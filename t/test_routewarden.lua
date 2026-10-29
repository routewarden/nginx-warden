-- t/test_routewarden.lua
-- Comprehensive end-to-end simulation tests for RouteWarden

package.path = "lib/?.lua;lib/?/init.lua;" .. package.path

local routewarden = require("resty.routewarden")

print("Testing routewarden end-to-end inspection...")

-- Helper to simulate a request
local function simulate_request(rw, method, raw_uri, uri, headers, query_string, remote_addr, req_body)
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
        body = req_body,
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

-- 17. Query parameter key blocking and traversal
do
    local rw = routewarden.new({ check_query = true })
    local passed_key = simulate_request(rw, "GET", "/search?foo=bar&.env=1", "/search", {}, "foo=bar&.env=1")
    assert(passed_key == false, "Query key .env should be blocked")

    local passed_traversal = simulate_request(rw, "GET", "/search?file=/images/../.env", "/search", {}, "file=/images/../.env")
    assert(passed_traversal == false, "Query traversal value /images/../.env should be blocked")
    print("  ✓ Query key and traversal inspection verified")
end

-- 18. Canonical directives configuration (block_patterns, allow_patterns, allowed_ips)
do
    local rw = routewarden.new({
        block_patterns = { "(?i)^/singular-path$", "(?i)^/singular-block$" },
        allow_patterns = { "(?i)^/singular-allow$" },
        allowed_ips = { "192.168.1.99" }
    })
    assert(simulate_request(rw, "GET", "/singular-path") == false, "block_patterns should be blocked")
    assert(simulate_request(rw, "GET", "/singular-block") == false, "block_patterns should be blocked")
    assert(simulate_request(rw, "GET", "/singular-allow") == true, "allow_patterns should pass")
    assert(simulate_request(rw, "GET", "/singular-path", "/singular-path", {}, "", "192.168.1.99") == true, "allowed_ips should bypass")
    print("  ✓ Canonical directives configuration verified")
end

-- 19. Action reporting for silent_drop
do
    local rw = routewarden.new({
        response = { mode = "silent_drop" },
        security_log = true
    })
    local logged_payload = nil
    rw:set_log_sink(function(json_str, payload)
        logged_payload = payload
    end)
    local passed = simulate_request(rw, "GET", "/.env")
    assert(passed == false)
    assert(logged_payload.action == "silentDrop", "expected action to be silentDrop, got: " .. tostring(logged_payload.action))
    print("  ✓ Action reported as silentDrop for mode silent_drop")
end

-- 20. Request body inspection (check_body & body_patterns)
do
    local rw = routewarden.new({
        enable_default_patterns = false,
        methods = { "POST" },
        check_body = true,
        check_body_patterns = { "(?i)grant_type=password" }
    })

    -- Login attempt with grant_type=password blocked
    local passed_login, cap_login, info_login = simulate_request(
        rw, "POST", "/identity/connect/token", "/identity/connect/token",
        { ["content-type"] = "application/x-www-form-urlencoded" }, "", "127.0.0.1",
        "grant_type=password&username=admin&password=secret"
    )
    assert(passed_login == false, "grant_type=password should be blocked")
    assert(info_login.reason == "body_blocked")

    -- Send access token grant with grant_type=send_access allowed
    local passed_send, cap_send, info_send = simulate_request(
        rw, "POST", "/identity/connect/token", "/identity/connect/token",
        { ["content-type"] = "application/x-www-form-urlencoded" }, "", "127.0.0.1",
        "grant_type=send_access&send_id=123&password=pass"
    )
    assert(passed_send == true, "grant_type=send_access should be allowed")
    print("  ✓ Request body inspection (check_body & body_patterns) verified")
end

-- 21. Custom response headers on block
do
    local rw = routewarden.new({
        response = {
            mode = "json",
            headers = {
                ["X-RouteWarden-Blocked"] = "true",
                ["X-Security-Policy"] = "strict"
            }
        }
    })
    local passed, cap = simulate_request(rw, "GET", "/.env")
    assert(passed == false, "GET /.env should be blocked")
    assert(cap.headers["X-RouteWarden-Blocked"] == "true", "expected custom header X-RouteWarden-Blocked")
    assert(cap.headers["X-Security-Policy"] == "strict", "expected custom header X-Security-Policy")
    print("  ✓ Custom response headers on blocked responses verified")
end

-- 22. Top-level mode, status_code, and custom_response_text aliases
do
    local rw = routewarden.new({
        mode = "text",
        status_code = 404,
        custom_response_text = "Resource not found on this server"
    })
    local passed, cap = simulate_request(rw, "GET", "/.env")
    assert(passed == false, "GET /.env should be blocked")
    assert(cap.status == 404, "expected top-level status_code 404, got: " .. tostring(cap.status))
    assert(cap.content_type == "text/plain; charset=utf-8", "expected text/plain content type")
    assert(cap.body == "Resource not found on this server", "expected custom response text")
    print("  ✓ Top-level mode, status_code, and custom_response_text aliases verified")
end

-- 23. Multiple HTTP methods filter (GET, HEAD, POST, PUT)
do
    local rw = routewarden.new({
        methods = { "GET", "HEAD", "POST", "PUT" }
    })
    assert(simulate_request(rw, "GET", "/.env") == false, "GET /.env should be blocked")
    assert(simulate_request(rw, "HEAD", "/.env") == false, "HEAD /.env should be blocked")
    assert(simulate_request(rw, "POST", "/.env") == false, "POST /.env should be blocked")
    assert(simulate_request(rw, "PUT", "/.env") == false, "PUT /.env should be blocked")
    assert(simulate_request(rw, "OPTIONS", "/.env") == true, "OPTIONS /.env should pass")
    assert(simulate_request(rw, "PATCH", "/.env") == true, "PATCH /.env should pass")
    print("  ✓ Multi-method filter {GET, HEAD, POST, PUT} verified")
end

-- 24. IPv6 CIDR allowlist matching
do
    local rw = routewarden.new({
        allowed_ips = { "2001:db8::/32" }
    })
    local passed_ipv6 = simulate_request(rw, "GET", "/.env", "/.env", {}, "", "[2001:db8::cafe]:54321")
    assert(passed_ipv6 == true, "2001:db8::cafe in 2001:db8::/32 should be allowed")

    local passed_outside = simulate_request(rw, "GET", "/.env", "/.env", {}, "", "[2001:db9::1]:54321")
    assert(passed_outside == false, "2001:db9::1 outside CIDR should be blocked")
    print("  ✓ IPv6 CIDR allowlist matching verified")
end

-- 25. Response neutrality on allowed requests
do
    local rw = routewarden.new({
        response = {
            headers = { ["X-Block-Header"] = "blocked" }
        }
    })
    local passed, cap = simulate_request(rw, "GET", "/normal/resource")
    assert(passed == true, "/normal/resource should be allowed")
    assert(cap.status == nil, "allowed request should not have status set by routewarden")
    assert(cap.headers["X-Block-Header"] == nil, "allowed request should not receive block headers")
    print("  ✓ Allowed request passes cleanly without block modifications")
end

-- 26. Comprehensive BlockPatterns and AllowPatterns verification matrix
do
    local rw = routewarden.new({
        enabled = true,
        enable_default_patterns = true,
        enable_default_allow_patterns = true,
        block_patterns = {
            "(?i)^/admin/.*$",
            "(?i)\\.(key|pem|conf|secret)$",
            "(?i)^/internal/debug$"
        },
        allow_patterns = {
            "(?i)^/admin/public/health$",
            "(?i)^/admin/assets/.*$",
            "(?i)^/public/sample\\.conf$",
            "(?i)^/\\.well-known/acme-challenge/.*$"
        },
        allowed_ips = { "192.168.100.50" },
        check_query = true
    })

    -- 1. BlockPatterns matches
    local passed1 = simulate_request(rw, "GET", "/admin/dashboard")
    assert(passed1 == false, "/admin/dashboard should be blocked by block_patterns")

    local passed2 = simulate_request(rw, "GET", "/ADMIN/Settings")
    assert(passed2 == false, "case insensitive /ADMIN/Settings should be blocked")

    local passed3 = simulate_request(rw, "GET", "/certs/server.key")
    assert(passed3 == false, "/certs/server.key should be blocked by extension pattern")

    local passed4 = simulate_request(rw, "GET", "/config/app.conf")
    assert(passed4 == false, "/config/app.conf should be blocked by extension pattern")

    local passed5 = simulate_request(rw, "GET", "/internal/debug")
    assert(passed5 == false, "/internal/debug should be blocked by exact endpoint pattern")

    -- 2. AllowPatterns overriding BlockPatterns
    local passed6 = simulate_request(rw, "GET", "/admin/public/health")
    assert(passed6 == true, "/admin/public/health should be allowed via allow_patterns")

    local passed7 = simulate_request(rw, "GET", "/admin/assets/app.js")
    assert(passed7 == true, "/admin/assets/app.js should be allowed via allow_patterns")

    local passed8 = simulate_request(rw, "GET", "/public/sample.conf")
    assert(passed8 == true, "/public/sample.conf should be allowed despite .conf extension")

    local passed9 = simulate_request(rw, "GET", "/.well-known/acme-challenge/abc-token")
    assert(passed9 == true, "/.well-known/acme-challenge should be allowed via allow_patterns")

    -- 3. Default block pattern still active
    local passed10 = simulate_request(rw, "GET", "/.env")
    assert(passed10 == false, "/.env should be blocked by default block pattern")

    -- 4. Clean routes pass
    local passed11 = simulate_request(rw, "GET", "/api/v1/products")
    assert(passed11 == true, "/api/v1/products should pass")

    local passed12 = simulate_request(rw, "GET", "/internal/debug/public")
    assert(passed12 == true, "/internal/debug/public should pass (not matching exact ^/internal/debug$)")

    -- 5. IP Whitelist bypass for blocked paths
    local passed13 = simulate_request(rw, "GET", "/admin/dashboard", "/admin/dashboard", {}, "", "192.168.100.50")
    assert(passed13 == true, "/admin/dashboard should pass from whitelisted IP")

    local passed14 = simulate_request(rw, "GET", "/admin/dashboard", "/admin/dashboard", {}, "", "10.0.0.1")
    assert(passed14 == false, "/admin/dashboard should be blocked from non-whitelisted IP")

    -- 6. Query string inspection with custom block_patterns
    local passed15 = simulate_request(rw, "GET", "/search?redirect=/admin/dashboard", "/search", {}, "redirect=/admin/dashboard")
    assert(passed15 == false, "query parameter matching block_patterns should be blocked")

    local passed16 = simulate_request(rw, "GET", "/search?q=normal-search-term", "/search", {}, "q=normal-search-term")
    assert(passed16 == true, "clean query parameter should pass")

    print("  ✓ Comprehensive BlockPatterns and AllowPatterns verification matrix passed")
end

-- 27. Request with empty URI (E-1)
do
    local rw = routewarden.new()
    local passed, cap = simulate_request(rw, "GET", "", "")
    assert(passed == true, "empty URI should default safely")
    print("  ✓ empty URI handled safely")
end

-- 28. check_body = true with nil body (E-2)
do
    local rw = routewarden.new({ check_body = true, check_body_patterns = { "(?i)secret" }, methods = { "POST" } })
    local passed = simulate_request(rw, "POST", "/submit", "/submit", {}, "", "127.0.0.1", nil)
    assert(passed == true, "nil body with check_body should pass")
    print("  ✓ check_body = true with nil body handled safely")
end

-- 29. check_headers with mixed-case header names (E-3)
do
    local rw = routewarden.new({ check_headers = { "X-Custom-Probe", "X-Target-URI" } })
    local passed_bad = simulate_request(rw, "GET", "/app", "/app", { ["x-custom-probe"] = "/.env" })
    assert(passed_bad == false, "mixed-case header name inspection should match")
    local passed_good = simulate_request(rw, "GET", "/app", "/app", { ["x-custom-probe"] = "/public/home" })
    assert(passed_good == true, "clean custom header should pass")
    print("  ✓ check_headers mixed-case header names verified")
end

-- 30. Multiple sequential requests on same instance (E-4)
do
    local rw = routewarden.new()
    for _ = 1, 20 do
        local passed1 = simulate_request(rw, "GET", "/.env")
        assert(passed1 == false)
        local passed2 = simulate_request(rw, "GET", "/api/v1/health")
        assert(passed2 == true)
    end
    print("  ✓ multiple sequential requests on same instance verified")
end

-- 31. security_log = true with nil log sink (E-5)
do
    local rw = routewarden.new({ security_log = true })
    rw:set_log_sink(nil)
    local passed = simulate_request(rw, "GET", "/.env")
    assert(passed == false)
    print("  ✓ security_log with nil log sink does not crash")
end

-- 32. enable_default_patterns = false and no custom block_patterns (E-6)
do
    local rw = routewarden.new({ enable_default_patterns = false, block_patterns = {} })
    local passed = simulate_request(rw, "GET", "/.env")
    assert(passed == true, "/.env should pass when default patterns are disabled and no block patterns")
    print("  ✓ disabling default patterns allows dotfiles")
end

-- 33. Request URI longer than 8KB (E-7)
do
    local rw = routewarden.new()
    local long_uri = "/" .. string.rep("x/", 1000) .. "resource"
    local passed = simulate_request(rw, "GET", long_uri)
    assert(passed == true)
    print("  ✓ request URI longer than 8KB inspected safely")
end

-- 34. Query string not inspected when check_query = false (E-8)
do
    local rw = routewarden.new({ check_query = false })
    local passed = simulate_request(rw, "GET", "/search?file=.env", "/search", {}, "file=.env")
    assert(passed == true, "query string must not be blocked when check_query = false")
    print("  ✓ check_query = false ignores query params")
end

-- 35. IPv6 address in allowed_ips bypassing dotfile block (E-9)
do
    local rw = routewarden.new({ allowed_ips = { "2001:db8:cafe::1" } })
    local passed_v6 = simulate_request(rw, "GET", "/.env", "/.env", {}, "", "[2001:db8:cafe::1]:12345")
    assert(passed_v6 == true, "allowed IPv6 must bypass block")
    local passed_other = simulate_request(rw, "GET", "/.env", "/.env", {}, "", "[2001:db8:beef::1]:12345")
    assert(passed_other == false, "other IPv6 must be blocked")
    print("  ✓ IPv6 whitelist bypass verified")
end

-- 36. Header value containing number or non-string (E-10)
do
    local rw = routewarden.new({ check_headers = { "X-Request-ID" } })
    local passed_num = simulate_request(rw, "GET", "/app", "/app", { ["x-request-id"] = 12345 })
    assert(passed_num == true, "numeric header value should not crash")
    print("  ✓ numeric header value handled safely")
end

-- 37. URI fragment anchor bypass prevented
do
    local rw = routewarden.new({ enable_default_patterns = true })
    local test_paths = {
        "/server-status#admin",
        "/server-status#section",
        "/server.key#frag",
        "/.env#local",
        "/phpinfo.php#info",
    }
    for _, p in ipairs(test_paths) do
        local passed = simulate_request(rw, "GET", p, p)
        assert(passed == false, "path with fragment " .. p .. " must be blocked")
    end
    print("  ✓ URI fragment anchor bypass prevented")
end

-- 38. Wildcard methods (* and ALL) inspect requests
do
    local rw_star = routewarden.new({ methods = { "*" } })
    assert(simulate_request(rw_star, "POST", "/.env", "/.env") == false, "wildcard * must inspect POST")
    assert(simulate_request(rw_star, "DELETE", "/.env", "/.env") == false, "wildcard * must inspect DELETE")

    local rw_all = routewarden.new({ methods = { "ALL" } })
    assert(simulate_request(rw_all, "POST", "/.env", "/.env") == false, "wildcard ALL must inspect POST")
    assert(simulate_request(rw_all, "PUT", "/.env", "/.env") == false, "wildcard ALL must inspect PUT")
    print("  ✓ wildcard methods (* and ALL) verified")
end

-- 39. Matrix parameter allowlist bypass prevented
do
    local rw = routewarden.new({
        enable_default_patterns = true,
        enable_default_allow_patterns = true,
    })
    local attack_paths = {
        "/.env;robots.txt",
        "/.env;sitemap.xml",
        "/backup.sql;robots.txt",
        "/.git/config;robots.txt",
    }
    for _, p in ipairs(attack_paths) do
        local passed = simulate_request(rw, "GET", p, p)
        assert(passed == false, "matrix attack path " .. p .. " must be blocked")
    end
    print("  ✓ matrix parameter allowlist bypass prevented")
end

-- 40. check_body auto-expands methods to inspect POST when methods is omitted
do
    local rw = routewarden.new({
        enable_default_patterns = false,
        check_body = true,
        check_body_patterns = { "(?i)password_leak" },
    })
    local passed, block_info = rw:inspect({
        method = "POST",
        uri = "/api/login",
        raw_uri = "/api/login",
        body = "user=admin&token=password_leak_123",
    })
    assert(passed == false, "POST body must be inspected when methods is omitted")
    print("  ✓ check_body auto-methods expansion verified")
end

-- 41. check_headers handles table headers and comma-delimited headers without crashing
do
    local rw = routewarden.new({
        check_headers = { "X-Rewrite-URL", "X-Custom-Path" },
        enable_default_patterns = true,
    })
    -- Table of headers (as returned by OpenResty for duplicate headers)
    local passed_tbl, block_info = rw:inspect({
        method = "GET",
        uri = "/index.html",
        raw_uri = "/index.html",
        headers = {
            ["x-rewrite-url"] = { "/safe/path", "/.env" },
        },
    })
    assert(passed_tbl == false, "duplicate header with sensitive path must be blocked")
    assert(block_info.reason == "header_blocked")

    -- Comma-delimited header
    local passed_comma, block_info2 = rw:inspect({
        method = "GET",
        uri = "/index.html",
        raw_uri = "/index.html",
        headers = {
            ["x-custom-path"] = "/safe/path, /.env",
        },
    })
    assert(passed_comma == false, "comma-delimited header with sensitive path must be blocked")
    print("  ✓ multi-value and table headers handled safely in check_headers")
end

-- 42. address_bytes strips IPv6 zone identifiers safely
do
    local ip_filter = require("resty.routewarden.ip_filter")
    local bytes = ip_filter.address_bytes("fe80::1%eth0")
    assert(bytes ~= nil and #bytes == 16, "address_bytes must parse scoped IPv6 address")
    local bytes_bracketed = ip_filter.address_bytes("[fe80::1%eth0]:443")
    assert(bytes_bracketed ~= nil and #bytes_bracketed == 16, "address_bytes must parse scoped bracketed IPv6 address")
    print("  ✓ IPv6 zone identifiers handled safely in address_bytes")
end

-- 43. captcha rendering handles percent characters and HTML special chars without crashing
do
    local response = require("resty.routewarden.response")
    local rh = response.new({
        mode = "captcha",
        captcha = {
            provider = "turnstile",
            site_key = '0x4AAAAAA"onmouseover="alert(1)',
            title = "100% Security <Check> & Verification",
        },
    })
    local captured_status, captured_ct, captured_body
    rh:serve({
        respond = function(status, ct, body)
            captured_status = status
            captured_ct = ct
            captured_body = body
        end
    })
    assert(captured_status == 403, "captcha must respond with status 403")
    assert(string.find(captured_body, "100% Security &lt;Check&gt; &amp; Verification", 1, true) ~= nil, "title must be HTML-escaped and percent signs preserved")
    assert(string.find(captured_body, "&quot;onmouseover=&quot;", 1, true) ~= nil, "site_key quotes must be attribute-escaped")
    print("  ✓ captcha rendering with percent signs and HTML injection characters verified")
end

-- 44. bracketed IPv6 CIDR and exact IP in allowed_ips
do
    local routewarden = require("resty.routewarden")
    local rw, err = routewarden.new({
        allowed_ips = { "[2001:db8::]/32", "[2001:db9::cafe]" }
    })
    assert(rw ~= nil, "routewarden.new must succeed with bracketed IPv6 CIDRs: " .. tostring(err))

    -- Allowed via bracketed CIDR
    local allowed_cidr = rw:inspect({
        method = "GET",
        uri = "/.env",
        raw_uri = "/.env",
        remote_addr = "2001:db8::1"
    })
    assert(allowed_cidr == true, "client IP in bracketed IPv6 CIDR must be allowed")

    -- Allowed via bracketed exact IP
    local allowed_exact = rw:inspect({
        method = "GET",
        uri = "/.env",
        raw_uri = "/.env",
        remote_addr = "2001:db9::cafe"
    })
    assert(allowed_exact == true, "client IP matching bracketed exact IPv6 must be allowed")

    -- Unallowed IP
    local denied = rw:inspect({
        method = "GET",
        uri = "/.env",
        raw_uri = "/.env",
        remote_addr = "2001:dba::1"
    })
    assert(denied == false, "client IP outside allowed_ips must be blocked")
    print("  ✓ bracketed IPv6 CIDR and exact IP supported in allowed_ips")
end

-- 45. check_query inspection on sensitive parameter keys
do
    local routewarden = require("resty.routewarden")
    local rw = routewarden.new({
        check_query = true
    })
    local passed, block_info = rw:inspect({
        method = "GET",
        uri = "/search",
        raw_uri = "/search?.env=1",
        query_string = ".env=1"
    })
    assert(passed == false, "query string with sensitive key .env must be blocked")
    assert(block_info.reason == "query_blocked", "reason must be query_blocked")
    print("  ✓ sensitive query parameter keys blocked when check_query enabled")
end

print("All routewarden integration tests passed successfully!")




