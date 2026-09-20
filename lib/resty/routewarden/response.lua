-- lib/resty/routewarden/response.lua
-- Response handler executing all 13 RouteWarden response modes:
-- text, json, html, captcha, redirect, silentDrop, gzipBomb, tarpit,
-- fakeSuccess, rateLimitChallenge, proxy, infiniteStream, xml

local _M = {
    _VERSION = "1.1.0"
}

-- Default Captcha HTML template matching caddy-warden & traefik-warden exactly
local DEFAULT_CAPTCHA_HTML = [[<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{TITLE}}</title>
  <style>
    :root {
      --bg: #0f172a;
      --card: #1e293b;
      --text: #f8fafc;
      --subtext: #94a3b8;
      --accent: #3b82f6;
      --border: #334155;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 1.5rem;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 1rem;
      padding: 2.5rem;
      max-width: 480px;
      width: 100%;
      text-align: center;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5);
    }
    .shield-icon {
      width: 56px;
      height: 56px;
      margin: 0 auto 1.25rem;
      color: var(--accent);
    }
    h1 {
      font-size: 1.5rem;
      font-weight: 700;
      margin-bottom: 0.75rem;
      color: var(--text);
    }
    p {
      color: var(--subtext);
      font-size: 0.95rem;
      line-height: 1.5;
      margin-bottom: 2rem;
    }
    .captcha-container {
      display: flex;
      justify-content: center;
      margin-bottom: 1.5rem;
      min-height: 70px;
    }
    .footer {
      font-size: 0.8rem;
      color: var(--subtext);
      opacity: 0.75;
    }
  </style>
  {{SCRIPT}}
</head>
<body>
  <div class="card">
    <svg class="shield-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="M9 12l2 2 4-4"/>
    </svg>
    <h1>{{TITLE}}</h1>
    <p>Please complete the security challenge below to verify you are a human visitor before proceeding.</p>

    <form method="POST" action="">
      <div class="captcha-container">
        {{WIDGET}}
      </div>
    </form>
    <div class="footer">Protected by RouteWarden Security</div>
  </div>
</body>
</html>]]

-- Simple template renderer
local function render_captcha_html(template_str, provider, site_key, title)
    local tmpl = template_str or DEFAULT_CAPTCHA_HTML
    provider = string.lower(provider or "turnstile")
    site_key = site_key or ""
    title = title or "Security Check Required"

    local script = ""
    local widget = ""

    if provider == "turnstile" then
        script = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
        widget = '<div class="cf-turnstile" data-sitekey="' .. site_key .. '" data-theme="dark"></div>'
    elseif provider == "hcaptcha" then
        script = '<script src="https://js.hcaptcha.com/1/api.js" async defer></script>'
        widget = '<div class="h-captcha" data-sitekey="' .. site_key .. '" data-theme="dark"></div>'
    elseif provider == "recaptcha" then
        script = '<script src="https://www.google.com/recaptcha/api.js" async defer></script>'
        widget = '<div class="g-recaptcha" data-sitekey="' .. site_key .. '" data-theme="dark"></div>'
    else
        widget = '<div class="custom-captcha">' .. site_key .. '</div>'
    end

    local rendered = string.gsub(tmpl, "{{TITLE}}", title)
    rendered = string.gsub(rendered, "{{SCRIPT}}", script)
    rendered = string.gsub(rendered, "{{WIDGET}}", widget)
    return rendered
end

-- Generate pre-computed gzip payload that decompresses massively (zero-byte gzip)
-- A minimal valid gzip header + deflate block of zero bytes
local function generate_gzip_bomb_header()
    -- Gzip header: ID1=0x1f, ID2=0x8b, CM=8 (deflate), FLG=0, MTIME=0, XFL=2 (max compress), OS=255 (unknown)
    return "\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
end

-- Constructor
function _M.new(response_config)
    local cfg = response_config or {}
    local self = {
        mode = string.lower(cfg.mode or "json"),
        status_code = cfg.status_code or 403,
        body = cfg.body or "",
        content_type = cfg.content_type,
        headers = cfg.headers or {},
        redirect_url = cfg.redirect_url or "/",
        proxy_url = cfg.proxy_url,
        captcha = cfg.captcha or {},
        gzip_bomb_mb = cfg.gzip_bomb_mb or 10,
        retry_after_seconds = cfg.retry_after_seconds or 300,
        tarpit_delay_ms = cfg.tarpit_delay_ms or 1000,
        tarpit_max_duration_seconds = cfg.tarpit_max_duration_seconds or 60,
        stream_size_mb = cfg.stream_size_mb or 100,
        silent_drop = cfg.silent_drop or false
    }

    if self.mode == "silentdrop" or self.mode == "drop" then
        self.silent_drop = true
    end

    return setmetatable(self, { __index = _M })
end

-- Main response execution
function _M:serve(req_ctx)
    local mode = self.mode

    -- Silent Drop: abruptly terminate connection
    if self.silent_drop or mode == "silentdrop" or mode == "drop" then
        if req_ctx and req_ctx.on_silent_drop then
            req_ctx.on_silent_drop()
            return
        end

        if ngx then
            -- In OpenResty, close client connection immediately
            local sock, err = ngx.req.socket(true)
            if sock then
                sock:close()
                return ngx.exit(ngx.HTTP_CLOSE or 444)
            end
            return ngx.exit(ngx.HTTP_CLOSE or 444)
        end
        return
    end

    -- Header setter helper
    local function set_header(k, v)
        if req_ctx and req_ctx.set_header then
            req_ctx.set_header(k, v)
        elseif ngx and ngx.header then
            ngx.header[k] = v
        end
    end

    -- Set custom headers
    for k, v in pairs(self.headers) do
        set_header(k, v)
    end

    local function send_resp(status, content_type, body_content)
        if content_type then
            set_header("Content-Type", content_type)
        end
        if req_ctx and req_ctx.respond then
            req_ctx.respond(status, content_type, body_content)
            return
        end
        if ngx then
            ngx.status = status
            if body_content and #body_content > 0 then
                ngx.say(body_content)
            end
            return ngx.exit(status)
        end
    end

    if mode == "redirect" then
        local target = self.redirect_url
        if not target or target == "" then
            target = "/"
        end
        local code = self.status_code
        if code < 300 or code > 308 then
            code = 302
        end
        set_header("Location", target)
        if req_ctx and req_ctx.redirect then
            req_ctx.redirect(target, code)
            return
        end
        if ngx then
            return ngx.redirect(target, code)
        end
        return

    elseif mode == "json" then
        local ct = self.content_type or "application/json"
        set_header("X-Content-Type-Options", "nosniff")
        local body = self.body
        if not body or string.match(body, "^%s*$") then
            body = string.format('{"error":"Forbidden","status":%d,"message":"Access to sensitive endpoint is blocked"}', self.status_code)
        end
        return send_resp(self.status_code, ct, body)

    elseif mode == "html" then
        local ct = self.content_type or "text/html; charset=utf-8"
        local body = self.body
        if not body or string.match(body, "^%s*$") then
            body = string.format("<!DOCTYPE html><html><head><title>Access Denied</title></head><body><h1>%d Forbidden</h1><p>Access to this resource is denied.</p></body></html>", self.status_code)
        end
        return send_resp(self.status_code, ct, body)

    elseif mode == "captcha" then
        local ct = "text/html; charset=utf-8"
        local c = self.captcha or {}
        local html = render_captcha_html(c.template, c.provider, c.site_key, c.title)
        return send_resp(self.status_code, ct, html)

    elseif mode == "gzipbomb" or mode == "bomb" then
        local ct = self.content_type or "text/html; charset=UTF-8"
        set_header("Content-Encoding", "gzip")
        set_header("X-Content-Type-Options", "nosniff")
        local target_mb = self.gzip_bomb_mb > 0 and self.gzip_bomb_mb or 10

        -- Gzip header + raw deflate blocks
        local chunk = string.rep("\0", 32 * 1024)
        local total_chunks = math.floor((target_mb * 1024 * 1024) / #chunk)
        if total_chunks <= 0 then total_chunks = 32 end

        if req_ctx and req_ctx.respond then
            req_ctx.respond(self.status_code, ct, generate_gzip_bomb_header())
            return
        end

        if ngx then
            ngx.status = self.status_code
            ngx.print(generate_gzip_bomb_header())
            -- Stream zero chunks
            for _ = 1, total_chunks do
                local ok, err = ngx.print(chunk)
                if not ok then break end
                ngx.flush(true)
            end
            return ngx.exit(self.status_code)
        end
        return

    elseif mode == "tarpit" then
        set_header("Content-Type", "text/plain; charset=utf-8")
        set_header("X-Content-Type-Options", "nosniff")

        local delay_sec = (self.tarpit_delay_ms > 0 and self.tarpit_delay_ms or 1000) / 1000
        local max_sec = self.tarpit_max_duration_seconds > 0 and self.tarpit_max_duration_seconds or 60

        if req_ctx and req_ctx.respond then
            req_ctx.respond(self.status_code, "text/plain; charset=utf-8", " ")
            return
        end

        if ngx then
            ngx.status = self.status_code
            local iterations = math.floor(max_sec / delay_sec)
            for _ = 1, iterations do
                local ok, _ = ngx.print(" ")
                if not ok then break end
                ngx.flush(true)
                ngx.sleep(delay_sec)
            end
            return ngx.exit(self.status_code)
        end
        return

    elseif mode == "fakesuccess" or mode == "decoy" then
        local req_path = string.lower(req_ctx and req_ctx.uri or (ngx and ngx.var and ngx.var.uri) or "")
        local ct = "text/plain; charset=utf-8"
        local body = self.body

        if not body or body == "" then
            if string.find(req_path, ".env", 1, true) then
                ct = "text/plain; charset=utf-8"
                body = "APP_NAME=Laravel\nAPP_ENV=production\nAPP_KEY=base64:9a8f7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8=\nAPP_DEBUG=false\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=forge\nDB_USERNAME=forge\nDB_PASSWORD=fake_honey_db_password_77a9b\n"
            elseif string.find(req_path, "actuator", 1, true) then
                ct = "application/json"
                body = '{"status":"UP","components":{"diskSpace":{"status":"UP","details":{"total":10737418240,"free":8589934592,"threshold":10485760}},"ping":{"status":"UP"}}}'
            elseif string.find(req_path, ".git/head", 1, true) or string.find(req_path, ".git", 1, true) then
                ct = "text/plain; charset=utf-8"
                body = "ref: refs/heads/master\n"
            elseif string.find(req_path, "phpinfo", 1, true) or string.find(req_path, "info.php", 1, true) then
                ct = "text/html; charset=utf-8"
                body = "<!DOCTYPE html><html><head><title>PHP 8.2.14 - phpinfo()</title></head><body><h1>PHP Version 8.2.14</h1><p>System Linux 5.15.0-generic</p></body></html>"
            elseif string.find(req_path, "wp-login", 1, true) then
                ct = "text/html; charset=utf-8"
                body = "<!DOCTYPE html><html><head><title>Log In &lsaquo; WordPress</title></head><body><form name='loginform' id='loginform'><input type='text' name='log' /><input type='password' name='pwd' /></form></body></html>"
            else
                ct = "application/json"
                body = '{"status":"success","data":{"id":1,"active":true}}'
            end
        end

        if self.content_type then
            ct = self.content_type
        end

        local code = self.status_code
        if code < 200 or code > 299 then
            code = 200
        end
        return send_resp(code, ct, body)

    elseif mode == "ratelimit" or mode == "ratelimitchallenge" or mode == "backoff" then
        local retry_sec = self.retry_after_seconds > 0 and self.retry_after_seconds or 300
        set_header("Retry-After", tostring(retry_sec))
        local ct = self.content_type or "application/json"
        local code = self.status_code
        if code == 0 or code == 403 then
            code = 429
        end
        local body = self.body
        if not body or string.match(body, "^%s*$") then
            body = string.format('{"error":"Too Many Requests","status":%d,"retryAfter":%d,"message":"Rate limit exceeded. Please back off."}', code, retry_sec)
        end
        return send_resp(code, ct, body)

    elseif mode == "xml" then
        local ct = self.content_type or "application/xml; charset=utf-8"
        set_header("X-Content-Type-Options", "nosniff")
        local body = self.body
        if not body or string.match(body, "^%s*$") then
            body = string.format('<?xml version="1.0" encoding="UTF-8"?>\n<Error>\n  <Status>%d</Status>\n  <Message>Access to protected endpoint is denied</Message>\n</Error>', self.status_code)
        end
        return send_resp(self.status_code, ct, body)

    elseif mode == "proxy" or mode == "mirror" then
        if self.proxy_url and ngx then
            return ngx.exec(self.proxy_url)
        end
        return send_resp(502, "text/plain; charset=utf-8", "Honeypot proxy destination unavailable")

    elseif mode == "infinitestream" or mode == "garbagestream" then
        local ct = self.content_type or "application/octet-stream"
        set_header("X-Content-Type-Options", "nosniff")
        local stream_mb = self.stream_size_mb > 0 and self.stream_size_mb or 50

        local garbage_base = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+{}[]|:;<>?,./~`-=\n"
        local chunk = string.rep(garbage_base, math.floor((32 * 1024) / #garbage_base))
        local total_chunks = math.floor((stream_mb * 1024 * 1024) / #chunk)
        if total_chunks <= 0 then total_chunks = 16 end

        if req_ctx and req_ctx.respond then
            req_ctx.respond(self.status_code, ct, chunk)
            return
        end

        if ngx then
            ngx.status = self.status_code
            for _ = 1, total_chunks do
                local ok = ngx.print(chunk)
                if not ok then break end
                ngx.flush(true)
            end
            return ngx.exit(self.status_code)
        end
        return

    else -- "text"
        local ct = self.content_type or "text/plain; charset=utf-8"
        set_header("X-Content-Type-Options", "nosniff")
        local body = self.body
        if not body then body = "" end
        return send_resp(self.status_code, ct, body)
    end
end

return _M
