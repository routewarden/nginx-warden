-- t/test_routewarden.lua
-- Comprehensive end-to-end simulation tests for RouteWarden

package.path = "lib/?.lua;lib/?/init.lua;" .. package.path

local routewarden = require("resty.routewarden")

print("Testing routewarden end-to-end inspection...")

-- Helper to simulate a request
local function simulate_request(rw, method, raw_uri, uri, headers, query_string, remote_addr)
    local headers_tbl = headers or {}
    local captured = {
        status = nil,
        content_type = nil,
        body = nil,
        headers = {},
        silent_dropped = false,
        redirected_to = nil
    }

    local req_ctx = {
        method = method,
        raw_uri = raw_uri,
        uri = uri or raw_uri,
        headers = headers_tbl,
        query_string = query_string or "",
        remote_addr = remote_addr or "127.0.0.1",
        set_header = function(k, v) captured.headers[k] = v end,
        respond = function(s, ct, b) captured.status = s; captured.content_type = ct; captured.body = b end,
        on_silent_drop = function() captured.silent_dropped = true end,
        redirect = function(t, c) captured.redirected_to = t end
    }

    local passed, block_info = rw:inspect(req_ctx)
    if not passed then
        rw.response_handler:serve(req_ctx)
    end

    return passed, captured, block_info
end

-- 1. Default inspection: GET /.env blocked with 403 JSON
do
    local rw = routewarden.new()
    local passed, cap, info = simulate_request(rw, "GET", "/.env")
    assert(passed == false, "GET /.env should be blocked")
    assert(cap.status == 403, "status should be 403")
    assert(cap.content_type == "application/json")
    assert(string.find(cap.body, '"Forbidden"'))
    print("  ✓ GET /.env blocked with 403 JSON")
end

-- 2. Methods filter: POST /.env allowed by default (GET only inspected)
do
    local rw = routewarden.new()
    local passed, cap, info = simulate_request(rw, "POST", "/.env")
    assert(passed == true, "POST /.env should pass by default")
    print("  ✓ POST /.env bypasses when inspect method is default GET")
end

-- 3. Methods filter: inspecting GET and POST
do
    local rw = routewarden.new({ methods = { "GET", "POST" } })
    local passed_get = simulate_request(rw, "GET", "/.env")
    assert(passed_get == false, "GET /.env should be blocked")

    local passed_post = simulate_request(rw, "POST", "/.env")
    assert(passed_post == false, "POST /.env should be blocked")

    local passed_delete = simulate_request(rw, "DELETE", "/.env")
    assert(passed_delete == true, "DELETE /.env should pass")
    print("  ✓ Custom methods {GET, POST} inspected properly")
end

-- 4. Anti-evasion: Double URL encoding (%252e%252e)
do
    local rw = routewarden.new()
    local passed = simulate_request(rw, "GET", "/static/%252e%252e/.env")
    assert(passed == false, "Double URL encoded path traversal should be blocked")
    print("  ✓ Multi-layer URL encoded traversal blocked")
end

-- 5. Anti-evasion: Semicolon matrix parameters (/;.env)
do
    local rw = routewarden.new()
    local passed = simulate_request(rw, "GET", "/;.env")
    assert(passed == false, "/;.env should be blocked")
    print("  ✓ Semicolon matrix parameter prefix blocked")
end

-- 6. Anti-evasion: Windows backslash (\..\.env)
do
    local rw = routewarden.new()
    local passed = simulate_request(rw, "GET", "/static\\..\\.env")
    assert(passed == false, "Backslash traversal should be blocked")
    print("  ✓ Windows backslash traversal blocked")
end

-- 7. Anti-evasion: Null byte in path
do
    local rw = routewarden.new()
    local passed = simulate_request(rw, "GET", "/.env\0.png")
    assert(passed == false, "Null byte evasion should be blocked")
    print("  ✓ Null byte path evasion blocked")
end

-- 8. Default allow patterns: /robots.txt & /.well-known/
do
    local rw = routewarden.new()
    local passed_robots = simulate_request(rw, "GET", "/robots.txt")
    assert(passed_robots == true, "/robots.txt should pass via default allowlist")

    local passed_wellknown = simulate_request(rw, "GET", "/.well-known/acme-challenge/token")
    assert(passed_wellknown == true, "/.well-known should pass via default allowlist")
    print("  ✓ Default allowlist exempts /robots.txt and /.well-known")
end

-- 9. Allow patterns overriding custom block patterns
do
    local rw = routewarden.new({
        block_patterns = { "^/api/.*$" },
        allow_patterns = { "^/api/public/.*%.env$" }
    })
    local passed_allowed = simulate_request(rw, "GET", "/api/public/demo.env")
    assert(passed_allowed == true, "custom allowlist should override blocklist")

    local passed_blocked = simulate_request(rw, "GET", "/api/private/demo.env")
    assert(passed_blocked == false, "non-allowed endpoint should be blocked")
    print("  ✓ Custom allowlist overrides custom block pattern")
end

-- 10. IP Whitelist bypass
do
    local rw = routewarden.new({
        allowed_ips = { "192.168.1.100", "10.0.0.0/8" }
    })

    -- Whitelisted exact IP
    local passed_exact = simulate_request(rw, "GET", "/.env", "/.env", {}, "", "192.168.1.100")
    assert(passed_exact == true, "192.168.1.100 should bypass blocklist")

    -- Whitelisted CIDR IP via X-Forwarded-For
    local passed_cidr = simulate_request(rw, "GET", "/.env", "/.env", { ["x-forwarded-for"] = "10.5.4.3, 1.2.3.4" }, "", "203.0.113.1")
    assert(passed_cidr == true, "10.5.4.3 should bypass blocklist via X-Forwarded-For")

    -- Non-whitelisted IP
    local passed_non = simulate_request(rw, "GET", "/.env", "/.env", {}, "", "203.0.113.50")
    assert(passed_non == false, "Non-whitelisted IP should be blocked")
    print("  ✓ IP and CIDR whitelist bypass verified")
end

-- 11. Query inspection (check_query = true)
do
    local rw = routewarden.new({ check_query = true })
    local passed_query = simulate_request(rw, "GET", "/download?file=.env", "/download", {}, "file=.env")
    assert(passed_query == false, "Sensitive query param should be blocked")

    local passed_clean_query = simulate_request(rw, "GET", "/search?q=openresty", "/search", {}, "q=openresty")
    assert(passed_clean_query == true, "Benign query should pass")
    print("  ✓ Query string inspection (check_query) verified")
end

-- 12. Security logging event format (CrowdSec compatible)
do
    local rw = routewarden.new({ security_log = true })
    local logged_json = nil
    local logged_payload = nil

    rw:set_log_sink(function(json_str, payload)
        logged_json = json_str
        logged_payload = payload
    end)

    local passed = simulate_request(rw, "GET", "/.git/config", "/.git/config", { ["user-agent"] = "ScannerBot/1.0" }, "", "198.51.100.25")
    assert(passed == false)
    assert(logged_payload ~= nil, "Security log event should be emitted")
    assert(logged_payload.type == "routewarden_block")
    assert(logged_payload.plugin == "nginx-warden")
    assert(logged_payload.client_ip == "198.51.100.25")
    assert(logged_payload.user_agent == "ScannerBot/1.0")
    assert(logged_payload.action == "json")
    print("  ✓ CrowdSec-compatible security log event emitted")
end

-- 13. Disabled module bypass
do
    local rw = routewarden.new({ enabled = false })
    local passed = simulate_request(rw, "GET", "/.env")
    assert(passed == true, "Disabled module should pass all requests")
    print("  ✓ Disabled module passes requests untouched")
end

-- 14. Expanded default block patterns (keys, container, ds_store, wp-config)
do
    local rw = routewarden.new()
    local sensitive_paths = {
        "/server.key",
        "/cert.pem",
        "/Dockerfile",
        "/docker-compose.yml",
        "/.DS_Store",
        "/wp-config.php"
    }
    for _, p in ipairs(sensitive_paths) do
        local passed = simulate_request(rw, "GET", p)
        assert(passed == false, "Expected " .. p .. " to be blocked by expanded default patterns")
    end
    print("  ✓ Expanded default patterns (keys, containers, wp-config, ds_store) verified")
end

-- 15. Header inspection (check_headers)
do
    local rw = routewarden.new({
        check_headers = { "X-Forwarded-Uri", "X-Rewrite-URL" }
    })
    -- Clean request with safe header
    local passed_clean = simulate_request(rw, "GET", "/app", "/app", { ["x-forwarded-uri"] = "/app" })
    assert(passed_clean == true, "Clean header should pass")

    -- Smuggled .env in header
    local passed_smuggled, cap, info = simulate_request(rw, "GET", "/app", "/app", { ["x-forwarded-uri"] = "/.env" })
    assert(passed_smuggled == false, "Smuggled .env in header should be blocked")
    assert(info.reason == "header_blocked")
    print("  ✓ Header injection inspection (check_headers) verified")
end

-- 16. Regex caching across multiple new() instances
do
    local rw1 = routewarden.new()
    local rw2 = routewarden.new()
    assert(#rw1.compiled_block == #rw2.compiled_block)
    assert(rw1.compiled_block[1] == rw2.compiled_block[1], "Compiled regex should be reused from cache")
    print("  ✓ Regex compilation caching verified")
end

print("All routewarden integration tests passed successfully!")

