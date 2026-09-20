-- t/test_response.lua
-- Unit tests for all 13 RouteWarden response modes

package.path = "lib/?.lua;lib/?/init.lua;" .. package.path

local response = require("resty.routewarden.response")

print("Testing response handler modes...")

local function create_mock_ctx(uri)
    local headers = {}
    local captured = {
        headers = headers,
        status = nil,
        content_type = nil,
        body = nil,
        silent_dropped = false,
        redirected_to = nil,
        redirect_code = nil
    }

    local ctx = {
        uri = uri or "/test",
        set_header = function(k, v)
            headers[k] = v
        end,
        respond = function(status, ct, body)
            captured.status = status
            captured.content_type = ct
            captured.body = body
        end,
        on_silent_drop = function()
            captured.silent_dropped = true
        end,
        redirect = function(target, code)
            captured.redirected_to = target
            captured.redirect_code = code
        end
    }

    return ctx, captured
end

-- 1. JSON mode (default)
do
    local h = response.new({ mode = "json", status_code = 403 })
    local ctx, captured = create_mock_ctx()
    h:serve(ctx)
    assert(captured.status == 403)
    assert(captured.content_type == "application/json")
    assert(string.find(captured.body, '"Forbidden"'))
    assert(captured.headers["X-Content-Type-Options"] == "nosniff")
    print("  ✓ mode json passed")
end

-- 2. Text mode
do
    local h = response.new({ mode = "text", status_code = 403, body = "Custom text blocked" })
    local ctx, captured = create_mock_ctx()
    h:serve(ctx)
    assert(captured.status == 403)
    assert(captured.content_type == "text/plain; charset=utf-8")
    assert(captured.body == "Custom text blocked")
    print("  ✓ mode text passed")
end

-- 3. HTML mode
do
    local h = response.new({ mode = "html", status_code = 403 })
    local ctx, captured = create_mock_ctx()
    h:serve(ctx)
    assert(captured.status == 403)
    assert(captured.content_type == "text/html; charset=utf-8")
    assert(string.find(captured.body, "<h1>403 Forbidden</h1>"))
    print("  ✓ mode html passed")
end

-- 4. Captcha mode (Turnstile, hCaptcha, reCAPTCHA)
do
    local h = response.new({
        mode = "captcha",
        status_code = 403,
        captcha = {
            provider = "turnstile",
            site_key = "0x4AAAAAAABcdEFghIjK",
            title = "Verify Human"
        }
    })
    local ctx, captured = create_mock_ctx()
    h:serve(ctx)
    assert(captured.status == 403)
    assert(string.find(captured.body, "challenges.cloudflare.com/turnstile"))
    assert(string.find(captured.body, "0x4AAAAAAABcdEFghIjK"))
    assert(string.find(captured.body, "Verify Human"))
    print("  ✓ mode captcha passed")
end

-- 5. Redirect mode
do
    local h = response.new({ mode = "redirect", redirect_url = "/login", status_code = 302 })
    local ctx, captured = create_mock_ctx()
    h:serve(ctx)
    assert(captured.redirected_to == "/login")
    assert(captured.redirect_code == 302)
    assert(captured.headers["Location"] == "/login")
    print("  ✓ mode redirect passed")
end

-- 6. SilentDrop mode
do
    local h = response.new({ mode = "silentDrop" })
    local ctx, captured = create_mock_ctx()
    h:serve(ctx)
    assert(captured.silent_dropped == true)
    print("  ✓ mode silentDrop passed")
end

-- 7. GzipBomb mode
do
    local h = response.new({ mode = "gzipBomb", status_code = 403, gzip_bomb_mb = 10 })
    local ctx, captured = create_mock_ctx()
    h:serve(ctx)
    assert(captured.status == 403)
    assert(captured.headers["Content-Encoding"] == "gzip")
    assert(captured.headers["X-Content-Type-Options"] == "nosniff")
    print("  ✓ mode gzipBomb passed")
end

-- 8. Tarpit mode
do
    local h = response.new({ mode = "tarpit", status_code = 403, tarpit_delay_ms = 50, tarpit_max_duration_seconds = 1 })
    local ctx, captured = create_mock_ctx()
    h:serve(ctx)
    assert(captured.status == 403)
    assert(captured.headers["X-Content-Type-Options"] == "nosniff")
    print("  ✓ mode tarpit passed")
end

-- 9. FakeSuccess / Honeypot mode (.env, actuator, git, phpinfo)
do
    local h = response.new({ mode = "fakeSuccess" })

    -- Test .env decoy
    local ctx_env, cap_env = create_mock_ctx("/app/.env")
    h:serve(ctx_env)
    assert(cap_env.status == 200)
    assert(string.find(cap_env.body, "APP_NAME=Laravel"))
    assert(string.find(cap_env.body, "fake_honey_db_password"))

    -- Test actuator decoy
    local ctx_act, cap_act = create_mock_ctx("/actuator/health")
    h:serve(ctx_act)
    assert(cap_act.status == 200)
    assert(string.find(cap_act.body, '"UP"'))

    -- Test .git decoy
    local ctx_git, cap_git = create_mock_ctx("/.git/HEAD")
    h:serve(ctx_git)
    assert(cap_git.status == 200)
    assert(string.find(cap_git.body, "refs/heads/master"))

    -- Test phpinfo decoy
    local ctx_php, cap_php = create_mock_ctx("/phpinfo.php")
    h:serve(ctx_php)
    assert(cap_php.status == 200)
    assert(string.find(cap_php.body, "PHP Version"))

    print("  ✓ mode fakeSuccess / decoy passed")
end

-- 10. RateLimitChallenge mode
do
    local h = response.new({ mode = "rateLimitChallenge", status_code = 429, retry_after_seconds = 120 })
    local ctx, captured = create_mock_ctx()
    h:serve(ctx)
    assert(captured.status == 429)
    assert(captured.headers["Retry-After"] == "120")
    assert(string.find(captured.body, '"retryAfter":120'))
    print("  ✓ mode rateLimitChallenge passed")
end

-- 11. XML mode
do
    local h = response.new({ mode = "xml", status_code = 403 })
    local ctx, captured = create_mock_ctx()
    h:serve(ctx)
    assert(captured.status == 403)
    assert(captured.content_type == "application/xml; charset=utf-8")
    assert(string.find(captured.body, "<Error>"))
    print("  ✓ mode xml passed")
end

-- 12. InfiniteStream mode
do
    local h = response.new({ mode = "infiniteStream", status_code = 200 })
    local ctx, captured = create_mock_ctx()
    h:serve(ctx)
    assert(captured.status == 200)
    assert(captured.content_type == "application/octet-stream")
    print("  ✓ mode infiniteStream passed")
end

-- 13. Proxy fallback
do
    local h = response.new({ mode = "proxy", proxy_url = nil })
    local ctx, captured = create_mock_ctx()
    h:serve(ctx)
    assert(captured.status == 502)
    print("  ✓ mode proxy passed")
end

print("All response mode tests passed successfully!")
