-- lib/resty/routewarden/init.lua
-- Main entrypoint for RouteWarden NGINX/OpenResty Lua module

local config = require("resty.routewarden.config")
local normalizer = require("resty.routewarden.normalizer")
local ip_filter = require("resty.routewarden.ip_filter")
local response = require("resty.routewarden.response")
local logger = require("resty.routewarden.logger")

local _M = {
    _VERSION = "1.6.0"
}

-- Check if ngx.re is available (OpenResty PCRE engine)
local has_ngx_re = (ngx and ngx.re and type(ngx.re.find) == "function")

-- Global / module-level regex cache to reuse compiled matchers across instances & requests
local regex_cache = {}

-- Compile regex or create matcher function (cached)
local function compile_regex(pattern)
    if not pattern or pattern == "" then
        return nil
    end

    if regex_cache[pattern] then
        return regex_cache[pattern]
    end

    -- Clean Go (?i) flag prefix if present, and track case-insensitivity
    local pcre_pattern = pattern
    local pcre_flags = "jo" -- compile once, PCRE JIT

    if string.sub(pcre_pattern, 1, 4) == "(?i)" then
        pcre_pattern = string.sub(pcre_pattern, 5)
        pcre_flags = "ijo"
    end

    local compiled
    if has_ngx_re then
        compiled = {
            pattern = pattern,
            raw_regex = pcre_pattern,
            flags = pcre_flags,
            match = function(self, target)
                local m, err = ngx.re.find(target, self.raw_regex, self.flags)
                return m ~= nil
            end
        }
    else
        -- Pure Lua fallback matcher for standalone testing without OpenResty
        compiled = {
            pattern = pattern,
            raw_regex = pcre_pattern,
            flags = pcre_flags,
            match = function(self, target)
                local lower_target = string.lower(target)
                local pat = self.raw_regex

                -- 1. Try direct Lua pattern matching first
                local lua_pat = string.lower(pat)
                lua_pat = string.gsub(lua_pat, "%(%?i%)", "")
                lua_pat = string.gsub(lua_pat, "\\%.", "%%.")
                local ok, res = pcall(function()
                    return string.find(lower_target, lua_pat)
                end)
                if ok and res ~= nil then
                    return true
                end

                -- 2. Clean PCRE groups e.g. (^|/) and escape literal hyphens outside character classes
                local clean_pcre = string.gsub(lua_pat, "%(%^|/%)", "")
                clean_pcre = string.gsub(clean_pcre, "%(%?i%)", "")
                local lua_escaped = string.gsub(clean_pcre, "([^%%%[])%-", "%1%%-")
                ok, res = pcall(function()
                    return string.find(lower_target, lua_escaped)
                end)
                if ok and res ~= nil then
                    return true
                end

                -- Match default patterns by pattern equality:
                if string.find(pat, "(\\.env.*|", 1, true) then
                    if string.find(lower_target, "%.env") then
                        return true
                    end
                    local exts = { "txt", "log", "bak", "backup", "sql", "conf", "config", "ini", "yaml", "yml" }
                    for _, ext in ipairs(exts) do
                        if string.find(lower_target, "%." .. ext .. "$") or string.find(lower_target, "%." .. ext .. "[%?#]") then
                            return true
                        end
                    end
                end

                -- 2. Sensitive archive / dump extensions (default pattern)
                if (string.find(pat, "tar|zip", 1) or string.find(pat, "tar|tar%.gz", 1) or string.find(pat, "sqlite", 1)) and not (string.find(pat, "^%(%?i%)%^/") or string.find(pat, "^%^/")) then
                    local exts = { "tar", "zip", "rar", "7z", "gz", "bz2", "iso", "dump", "sqlite", "sqlite3", "db" }
                    for _, ext in ipairs(exts) do
                        if string.find(lower_target, "%." .. ext .. "$") or string.find(lower_target, "%." .. ext .. "[%?#]") then
                            return true
                        end
                    end
                end

                -- 3. Hidden directory (.git, .svn, .aws, .ssh, .kube, .docker)
                local dirs = { "git", "svn", "hg", "bzr", "cvs", "aws", "ssh", "kube", "docker" }
                for _, d in ipairs(dirs) do
                    if string.find(pat, d, 1, true) then
                        if string.find(lower_target, "^%." .. d .. "/") or string.find(lower_target, "^%." .. d .. "$") or
                           string.find(lower_target, "/%." .. d .. "/") or string.find(lower_target, "/%." .. d .. "$") then
                            return true
                        end
                    end
                end

                -- 4. Admin endpoints
                local admin = { "phpinfo%.php", "info%.php", "server%-status", "server%-info", "actuator", "metrics", "heapdump", "trace" }
                for _, a in ipairs(admin) do
                    if string.find(pat, a, 1) then
                        if string.find(lower_target, a) then
                            return true
                        end
                    end
                end

                -- 5. Package managers
                local pkgs = { "composer%.json", "composer%.lock", "package%-lock%.json", "yarn%.lock", "pnpm%-lock%.yaml", "pipfile", "requirements%.txt" }
                for _, pkg in ipairs(pkgs) do
                    if string.find(pat, pkg, 1) then
                        if string.find(lower_target, pkg) then
                            return true
                        end
                    end
                end

                -- 6. TLS keys, certificates, keystores
                if string.find(pat, "pem|key|crt", 1, true) then
                    local key_exts = { "pem", "key", "crt", "pfx", "p12", "jks", "kdb" }
                    for _, ke in ipairs(key_exts) do
                        if string.find(lower_target, "%." .. ke .. "$") or string.find(lower_target, "%." .. ke .. "[%?#]") then
                            return true
                        end
                    end
                end

                -- 7. Container manifests
                if string.find(pat, "dockerfile", 1, true) then
                    if string.find(lower_target, "dockerfile") or string.find(lower_target, "docker%-compose") then
                        return true
                    end
                end

                -- 8. macOS metadata
                if string.find(pat, "ds_store", 1, true) then
                    if string.find(lower_target, "%.ds_store") then
                        return true
                    end
                end

                -- 9. CMS & framework configs
                if string.find(pat, "wp%-config", 1) or string.find(pat, "wp-config", 1, true) then
                    if string.find(lower_target, "wp%-config%.php") or string.find(lower_target, "configuration%.php") or
                       string.find(lower_target, "settings%.py") then
                        return true
                    end
                end

                -- 10. Default allow patterns
                if string.find(pat, "robots%.txt", 1) and (lower_target == "/robots.txt" or lower_target == "robots.txt") then
                    return true
                end
                if string.find(pat, "sitemap", 1) and string.find(lower_target, "^/sitemap.*%.xml$") then
                    return true
                end
                if string.find(pat, "ads%.txt", 1) and (lower_target == "/ads.txt" or lower_target == "ads.txt") then
                    return true
                end
                if string.find(pat, "security%.txt", 1) and (lower_target == "/security.txt" or lower_target == "security.txt") then
                    return true
                end
                if string.find(pat, "well%-known", 1) and string.find(lower_target, "^/%.well%-known") then
                    return true
                end

                return false
            end
        }
    end

    if compiled then
        regex_cache[pattern] = compiled
    end
    return compiled
end

-- Simple, robust JSON parser with OpenResty cjson support and pure-Lua fallback
local function parse_json(str)
    if not str or str == "" then
        return nil, "empty JSON string"
    end

    local ok, cjson = pcall(require, "cjson.safe")
    if ok and cjson and cjson.decode then
        local data, err = cjson.decode(str)
        if not data then
            return nil, err
        end
        return data
    end
    local ok2, cjson2 = pcall(require, "cjson")
    if ok2 and cjson2 and cjson2.decode then
        local ok_call, data = pcall(cjson2.decode, str)
        if ok_call then
            return data
        else
            return nil, data
        end
    end

    local idx = 1
    local len = #str

    local function skip_whitespace()
        while idx <= len do
            local c = string.byte(str, idx)
            if c == 32 or c == 9 or c == 10 or c == 13 then
                idx = idx + 1
            else
                break
            end
        end
    end

    local parse_value

    local function parse_string()
        idx = idx + 1 -- skip opening quote
        local start = idx
        local buf = {}
        while idx <= len do
            local c = string.byte(str, idx)
            if c == 34 then -- quote
                table.insert(buf, string.sub(str, start, idx - 1))
                idx = idx + 1
                return table.concat(buf)
            elseif c == 92 then -- backslash
                table.insert(buf, string.sub(str, start, idx - 1))
                idx = idx + 1
                if idx > len then
                    return nil, "unexpected EOF in escape sequence"
                end
                local esc = string.byte(str, idx)
                idx = idx + 1
                if esc == 34 then table.insert(buf, '"')
                elseif esc == 92 then table.insert(buf, '\\')
                elseif esc == 47 then table.insert(buf, '/')
                elseif esc == 98 then table.insert(buf, '\b')
                elseif esc == 102 then table.insert(buf, '\f')
                elseif esc == 110 then table.insert(buf, '\n')
                elseif esc == 114 then table.insert(buf, '\r')
                elseif esc == 116 then table.insert(buf, '\t')
                elseif esc == 117 then -- \uXXXX
                    if idx + 3 > len then
                        return nil, "invalid unicode escape sequence"
                    end
                    local hex = string.sub(str, idx, idx + 3)
                    idx = idx + 4
                    local code = tonumber(hex, 16)
                    if code then
                        if code < 128 then
                            table.insert(buf, string.char(code))
                        elseif code < 2048 then
                            table.insert(buf, string.char(192 + math.floor(code / 64), 128 + (code % 64)))
                        else
                            table.insert(buf, string.char(224 + math.floor(code / 4096), 128 + (math.floor(code / 64) % 64), 128 + (code % 64)))
                        end
                    end
                else
                    table.insert(buf, string.char(esc))
                end
                start = idx
            else
                idx = idx + 1
            end
        end
        return nil, "unterminated string"
    end

    local function parse_number()
        local s, e = string.find(str, "^%-?%d+%.?%d*[eE]?[%+%-]?%d*", idx)
        if s then
            local num_str = string.sub(str, s, e)
            local n = tonumber(num_str)
            idx = e + 1
            return n
        end
        return nil, "invalid number"
    end

    local function parse_array()
        idx = idx + 1 -- skip '['
        local arr = {}
        skip_whitespace()
        if idx <= len and string.byte(str, idx) == 93 then -- ']'
            idx = idx + 1
            return arr
        end
        while idx <= len do
            skip_whitespace()
            local val, err = parse_value()
            if err then return nil, err end
            table.insert(arr, val)
            skip_whitespace()
            if idx <= len and string.byte(str, idx) == 44 then -- ','
                idx = idx + 1
            elseif idx <= len and string.byte(str, idx) == 93 then -- ']'
                idx = idx + 1
                return arr
            else
                return nil, "expected ',' or ']' in array at position " .. idx
            end
        end
        return nil, "unterminated array"
    end

    local function parse_object()
        idx = idx + 1 -- skip '{'
        local obj = {}
        skip_whitespace()
        if idx <= len and string.byte(str, idx) == 125 then -- '}'
            idx = idx + 1
            return obj
        end
        while idx <= len do
            skip_whitespace()
            if idx > len or string.byte(str, idx) ~= 34 then
                return nil, "expected string key in object at position " .. idx
            end
            local key, err = parse_string()
            if err then return nil, err end
            skip_whitespace()
            if idx > len or string.byte(str, idx) ~= 58 then -- ':'
                return nil, "expected ':' after key in object at position " .. idx
            end
            idx = idx + 1
            skip_whitespace()
            local val, val_err = parse_value()
            if val_err then return nil, val_err end
            obj[key] = val
            skip_whitespace()
            if idx <= len and string.byte(str, idx) == 44 then -- ','
                idx = idx + 1
            elseif idx <= len and string.byte(str, idx) == 125 then -- '}'
                idx = idx + 1
                return obj
            else
                return nil, "expected ',' or '}' in object at position " .. idx
            end
        end
        return nil, "unterminated object"
    end

    function parse_value()
        skip_whitespace()
        if idx > len then
            return nil, "unexpected end of JSON input"
        end
        local c = string.byte(str, idx)
        if c == 34 then -- '"'
            return parse_string()
        elseif c == 123 then -- '{'
            return parse_object()
        elseif c == 91 then -- '['
            return parse_array()
        elseif c == 116 and string.sub(str, idx, idx + 3) == "true" then
            idx = idx + 4
            return true
        elseif c == 102 and string.sub(str, idx, idx + 4) == "false" then
            idx = idx + 5
            return false
        elseif c == 110 and string.sub(str, idx, idx + 3) == "null" then
            idx = idx + 4
            return nil
        elseif c == 45 or (c >= 48 and c <= 57) then -- '-' or '0'-'9'
            return parse_number()
        else
            return nil, "unexpected character '" .. string.char(c) .. "' at position " .. idx
        end
    end

    skip_whitespace()
    local result, err = parse_value()
    if err then return nil, err end
    skip_whitespace()
    if idx <= len then
        return nil, "trailing garbage after JSON at position " .. idx
    end
    return result
end

-- Normalize camelCase schema keys from routewarden.json into native snake_case
local function normalize_json_config(raw)
    if not raw or type(raw) ~= "table" then
        return {}
    end
    local t = {}

    if raw.enabled ~= nil then t.enabled = raw.enabled end
    if raw.enable_default_patterns ~= nil then t.enable_default_patterns = raw.enable_default_patterns
    elseif raw.enableDefaultPatterns ~= nil then t.enable_default_patterns = raw.enableDefaultPatterns end

    if raw.enable_default_allow_patterns ~= nil then t.enable_default_allow_patterns = raw.enable_default_allow_patterns
    elseif raw.enableDefaultAllowPatterns ~= nil then t.enable_default_allow_patterns = raw.enableDefaultAllowPatterns end

    if raw.check_query ~= nil then t.check_query = raw.check_query
    elseif raw.checkQuery ~= nil then t.check_query = raw.checkQuery end

    if raw.debug ~= nil then t.debug = raw.debug end

    if raw.security_log ~= nil then t.security_log = raw.security_log
    elseif raw.securityLog ~= nil then t.security_log = raw.securityLog end

    if raw.status_code ~= nil then t.status_code = raw.status_code
    elseif raw.statusCode ~= nil then t.status_code = raw.statusCode end

    if raw.custom_response_text ~= nil then t.custom_response_text = raw.custom_response_text
    elseif raw.customResponseText ~= nil then t.custom_response_text = raw.customResponseText end

    if raw.methods ~= nil then t.methods = raw.methods end

    if raw.check_headers ~= nil then t.check_headers = raw.check_headers
    elseif raw.checkHeaders ~= nil then t.check_headers = raw.checkHeaders end

    if raw.check_body ~= nil then t.check_body = raw.check_body
    elseif raw.checkBody ~= nil then t.check_body = raw.checkBody end

    if raw.check_body_max_bytes ~= nil then t.check_body_max_bytes = raw.check_body_max_bytes
    elseif raw.checkBodyMaxBytes ~= nil then t.check_body_max_bytes = raw.checkBodyMaxBytes end

    if raw.check_body_patterns ~= nil then t.check_body_patterns = raw.check_body_patterns
    elseif raw.checkBodyPatterns ~= nil then t.check_body_patterns = raw.checkBodyPatterns end

    if raw.block_patterns ~= nil then t.block_patterns = raw.block_patterns
    elseif raw.blockPatterns ~= nil then t.block_patterns = raw.blockPatterns end

    if raw.allow_patterns ~= nil then t.allow_patterns = raw.allow_patterns
    elseif raw.allowPatterns ~= nil then t.allow_patterns = raw.allowPatterns end

    if raw.allowed_ips ~= nil then t.allowed_ips = raw.allowed_ips
    elseif raw.allowedIps ~= nil then t.allowed_ips = raw.allowedIps end

    if raw.trusted_proxies ~= nil then t.trusted_proxies = raw.trusted_proxies
    elseif raw.trustedProxies ~= nil then t.trusted_proxies = raw.trustedProxies end

    if raw.mode ~= nil then t.mode = raw.mode end

    local resp_raw = raw.response
    if resp_raw and type(resp_raw) == "table" then
        local r = {}
        if resp_raw.mode ~= nil then r.mode = resp_raw.mode end
        if resp_raw.status_code ~= nil then r.status_code = resp_raw.status_code
        elseif resp_raw.statusCode ~= nil then r.status_code = resp_raw.statusCode end

        if resp_raw.body ~= nil then r.body = resp_raw.body end
        if resp_raw.content_type ~= nil then r.content_type = resp_raw.content_type
        elseif resp_raw.contentType ~= nil then r.content_type = resp_raw.contentType end

        if resp_raw.headers ~= nil then r.headers = resp_raw.headers end

        if resp_raw.redirect_url ~= nil then r.redirect_url = resp_raw.redirect_url
        elseif resp_raw.redirectUrl ~= nil then r.redirect_url = resp_raw.redirectUrl end

        if resp_raw.proxy_url ~= nil then r.proxy_url = resp_raw.proxy_url
        elseif resp_raw.proxyUrl ~= nil then r.proxy_url = resp_raw.proxyUrl end

        if resp_raw.gzip_bomb_mb ~= nil then r.gzip_bomb_mb = resp_raw.gzip_bomb_mb
        elseif resp_raw.gzipBombMb ~= nil then r.gzip_bomb_mb = resp_raw.gzipBombMb end

        if resp_raw.retry_after_seconds ~= nil then r.retry_after_seconds = resp_raw.retry_after_seconds
        elseif resp_raw.retryAfterSeconds ~= nil then r.retry_after_seconds = resp_raw.retryAfterSeconds end

        if resp_raw.tarpit_delay_ms ~= nil then r.tarpit_delay_ms = resp_raw.tarpit_delay_ms
        elseif resp_raw.tarpitDelayMs ~= nil then r.tarpit_delay_ms = resp_raw.tarpitDelayMs end

        if resp_raw.tarpit_max_duration_seconds ~= nil then r.tarpit_max_duration_seconds = resp_raw.tarpit_max_duration_seconds
        elseif resp_raw.tarpitMaxDurationSeconds ~= nil then r.tarpit_max_duration_seconds = resp_raw.tarpitMaxDurationSeconds end

        if resp_raw.stream_size_mb ~= nil then r.stream_size_mb = resp_raw.stream_size_mb
        elseif resp_raw.streamSizeMb ~= nil then r.stream_size_mb = resp_raw.streamSizeMb end

        local captcha_raw = resp_raw.captcha
        if captcha_raw and type(captcha_raw) == "table" then
            local c = {}
            if captcha_raw.provider ~= nil then c.provider = captcha_raw.provider end
            if captcha_raw.site_key ~= nil then c.site_key = captcha_raw.site_key
            elseif captcha_raw.siteKey ~= nil then c.site_key = captcha_raw.siteKey end
            if captcha_raw.title ~= nil then c.title = captcha_raw.title end
            if captcha_raw.template ~= nil then c.template = captcha_raw.template end
            r.captcha = c
        end

        t.response = r
    end

    return t
end

-- Constructor for RouteWarden instance
function _M.new(opts)
    local cfg = config.default_config()

    -- Support passing a file path directly as string: routewarden.new("/path/to/routewarden.json")
    if type(opts) == "string" then
        opts = { config_file = opts }
    end

    local file_opts = nil
    local config_file_path = nil
    if opts and type(opts) == "table" then
        config_file_path = opts.config_file or opts.configFile
    end

    if config_file_path and config_file_path ~= "" then
        local f, err = io.open(config_file_path, "r")
        if not f then
            error("[routewarden] cannot open config_file '" .. tostring(config_file_path) .. "': " .. tostring(err))
        end
        local content = f:read("*a")
        f:close()

        local raw_json, parse_err = parse_json(content)
        if parse_err then
            error("[routewarden] failed to parse JSON from config_file '" .. tostring(config_file_path) .. "': " .. tostring(parse_err))
        end
        file_opts = normalize_json_config(raw_json)
        cfg.config_file = config_file_path
    end

    local function apply_opts(source)
        if not source or type(source) ~= "table" then return end

        if source.enabled ~= nil then cfg.enabled = source.enabled end

        local edp = source.enable_default_patterns
        if edp == nil then edp = source.enableDefaultPatterns end
        if edp ~= nil then cfg.enable_default_patterns = edp end

        local edap = source.enable_default_allow_patterns
        if edap == nil then edap = source.enableDefaultAllowPatterns end
        if edap ~= nil then cfg.enable_default_allow_patterns = edap end

        local cq = source.check_query
        if cq == nil then cq = source.checkQuery end
        if cq ~= nil then cfg.check_query = cq end

        if source.debug ~= nil then cfg.debug = source.debug end

        local slog = source.security_log
        if slog == nil then slog = source.securityLog end
        if slog ~= nil then cfg.security_log = slog end

        local sc = source.status_code
        if sc == nil then sc = source.statusCode end
        if sc ~= nil then cfg.status_code = sc end

        local crt = source.custom_response_text
        if crt == nil then crt = source.customResponseText end
        if crt ~= nil then cfg.custom_response_text = crt end

        if source.methods then cfg.methods = source.methods end

        local ch = source.check_headers
        if ch == nil then ch = source.checkHeaders end
        if ch then cfg.check_headers = ch end

        local cb = source.check_body
        if cb == nil then cb = source.checkBody end
        if cb ~= nil then cfg.check_body = cb end

        local cbmb = source.check_body_max_bytes
        if cbmb == nil then cbmb = source.checkBodyMaxBytes end
        if cbmb then cfg.check_body_max_bytes = cbmb end

        local cbp = source.check_body_patterns
        if cbp == nil then cbp = source.checkBodyPatterns end
        if cbp then cfg.check_body_patterns = cbp end

        local bp = source.block_patterns
        if bp == nil then bp = source.blockPatterns end
        if bp then cfg.block_patterns = bp end

        local ap = source.allow_patterns
        if ap == nil then ap = source.allowPatterns end
        if ap then cfg.allow_patterns = ap end

        local aips = source.allowed_ips
        if aips == nil then aips = source.allowedIps end
        if aips then cfg.allowed_ips = aips end

        local tp = source.trusted_proxies
        if tp == nil then tp = source.trustedProxies end
        if tp then cfg.trusted_proxies = tp end

        if source.mode then
            cfg.response.mode = string.lower(source.mode)
        end

        if source.response then
            for k, v in pairs(source.response) do
                if k == "captcha" and type(v) == "table" then
                    cfg.response.captcha = cfg.response.captcha or {}
                    for ck, cv in pairs(v) do
                        cfg.response.captcha[ck] = cv
                    end
                else
                    cfg.response[k] = v
                end
            end
            if cfg.response.mode then
                cfg.response.mode = string.lower(cfg.response.mode)
            end
        end
    end

    -- 1. Apply file_opts as base configuration
    if file_opts then
        apply_opts(file_opts)
    end

    -- 2. Apply inline opts overriding file configuration
    if opts and type(opts) == "table" then
        apply_opts(opts)
    end

    -- Harmonize status_code and custom_response_text with response config
    if cfg.status_code then
        cfg.response.status_code = cfg.status_code
    end
    if cfg.custom_response_text and (not cfg.response.body or cfg.response.body == "") then
        cfg.response.body = cfg.custom_response_text
    end

    -- Process methods filter
    local methods_map = {}
    if cfg.methods and #cfg.methods > 0 then
        for _, m in ipairs(cfg.methods) do
            local trimmed = string.match(m, "^%s*(.-)%s*$")
            if trimmed ~= "" then
                methods_map[string.upper(trimmed)] = true
            end
        end
    end
    if not next(methods_map) then
        methods_map["GET"] = true
    end

    local function add_entries(target, entries)
        if not entries then return end
        if type(entries) == "string" then
            table.insert(target, entries)
        elseif type(entries) == "table" then
            for _, item in ipairs(entries) do
                table.insert(target, item)
            end
        end
    end

    -- Compile block patterns
    local all_block_patterns = {}
    if cfg.enable_default_patterns then
        for _, p in ipairs(config.default_block_patterns) do
            table.insert(all_block_patterns, p)
        end
    end
    add_entries(all_block_patterns, cfg.block_patterns)

    local compiled_block = {}
    for _, p in ipairs(all_block_patterns) do
        local trimmed = string.match(p, "^%s*(.-)%s*$")
        if trimmed ~= "" then
            local compiled = compile_regex(trimmed)
            if compiled then
                table.insert(compiled_block, compiled)
            end
        end
    end

    -- Compile allow patterns
    local all_allow_patterns = {}
    if cfg.enable_default_allow_patterns then
        for _, p in ipairs(config.default_allow_patterns) do
            table.insert(all_allow_patterns, p)
        end
    end
    add_entries(all_allow_patterns, cfg.allow_patterns)

    local compiled_allow = {}
    for _, p in ipairs(all_allow_patterns) do
        local trimmed = string.match(p, "^%s*(.-)%s*$")
        if trimmed ~= "" then
            local compiled = compile_regex(trimmed)
            if compiled then
                table.insert(compiled_allow, compiled)
            end
        end
    end

    -- Compile body patterns
    local all_body_patterns = {}
    add_entries(all_body_patterns, cfg.check_body_patterns)

    local compiled_body = {}
    for _, p in ipairs(all_body_patterns) do
        local trimmed = string.match(p, "^%s*(.-)%s*$")
        if trimmed ~= "" then
            local compiled = compile_regex(trimmed)
            if compiled then
                table.insert(compiled_body, compiled)
            end
        end
    end

    -- Initialize IP Filter
    local all_allowed_ips = {}
    add_entries(all_allowed_ips, cfg.allowed_ips)

    local all_trusted_proxies = {}
    add_entries(all_trusted_proxies, cfg.trusted_proxies)

    local ip_matcher, err
    if #all_allowed_ips > 0 or #all_trusted_proxies > 0 then
        ip_matcher, err = ip_filter.new(all_allowed_ips, all_trusted_proxies)
        if not ip_matcher then
            error("routewarden init error: " .. tostring(err))
        end
    end

    -- Initialize Response Handler
    local resp_handler = response.new(cfg.response)

    local self = {
        config = cfg,
        methods = methods_map,
        compiled_block = compiled_block,
        compiled_allow = compiled_allow,
        compiled_body = compiled_body,
        ip_matcher = ip_matcher,
        response_handler = resp_handler,
        custom_log_sink = nil
    }

    return setmetatable(self, { __index = _M })
end

local VALID_MODES = {
    json = true,
    text = true,
    html = true,
    captcha = true,
    redirect = true,
    silentdrop = true,
    silent_drop = true,
    drop = true,
    gzipbomb = true,
    gzip_bomb = true,
    tarpit = true,
    fakesuccess = true,
    fake_success = true,
    ratelimitchallenge = true,
    rate_limit_challenge = true,
    proxy = true,
    infinitestream = true,
    infinite_stream = true,
    xml = true
}

-- Validate configuration (returns true, or false, err)
function _M:validate()
    if self.config.status_code then
        local code = self.config.status_code
        if code < 100 or code > 599 then
            return false, string.format("routewarden: statusCode must be between 100 and 599, got %d", code)
        end
    end
    if self.config.response and self.config.response.status_code then
        local code = self.config.response.status_code
        if code < 100 or code > 599 then
            return false, string.format("routewarden: statusCode must be between 100 and 599, got %d", code)
        end
    end
    if self.config.response and self.config.response.mode then
        local m = string.lower(self.config.response.mode)
        if not VALID_MODES[m] then
            return false, string.format("routewarden: invalid response mode %q", tostring(self.config.response.mode))
        end
    end
    return true
end

-- Set custom log sink for testing
function _M:set_log_sink(sink)
    self.custom_log_sink = sink
end

-- Primary inspection routine
-- Returns true if passed, or false, block_info if blocked
function _M:inspect(req_ctx)
    if not self.config.enabled then
        return true
    end

    local method = string.upper(req_ctx.method or (ngx and ngx.req and ngx.req.get_method and ngx.req.get_method()) or "GET")
    if not self.methods[method] then
        return true
    end

    -- Stage 1: IP Whitelist Check
    local headers = req_ctx.headers or (ngx and ngx.req and ngx.req.get_headers and ngx.req.get_headers()) or {}
    local remote_addr = req_ctx.remote_addr or (ngx and ngx.var and ngx.var.remote_addr) or ""
    local client_ip = ip_filter.extract_client_ip(headers, remote_addr, self.ip_matcher)

    if self.ip_matcher then
        if self.ip_matcher:is_allowed(client_ip) then
            return true
        end
    end

    -- Stage 2: Path Normalization
    local raw_uri = req_ctx.raw_uri or (ngx and ngx.var and ngx.var.request_uri) or ""
    local uri = req_ctx.uri or (ngx and ngx.var and ngx.var.uri) or "/"
    local candidate_paths = normalizer.extract_candidate_paths(raw_uri, uri, raw_uri)

    -- Stage 3: Allow Patterns Match (Precedence over blocklist)
    for _, path_cand in ipairs(candidate_paths) do
        for _, allow_re in ipairs(self.compiled_allow) do
            if allow_re:match(path_cand) then
                return true
            end
        end
    end

    -- Stage 4: Block Patterns Match
    local is_blocked = false
    local blocked_pattern = ""
    local blocked_target = ""
    local blocked_reason = "path_blocked"

    for _, path_cand in ipairs(candidate_paths) do
        for _, block_re in ipairs(self.compiled_block) do
            if block_re:match(path_cand) then
                is_blocked = true
                blocked_pattern = block_re.pattern
                blocked_target = path_cand
                blocked_reason = "path_blocked"
                break
            end
        end
        if is_blocked then break end
    end

    -- Optional Query String Inspection
    if not is_blocked and self.config.check_query then
        local raw_query = req_ctx.query_string or (ngx and ngx.var and ngx.var.query_string) or ""
        if raw_query ~= "" then
            local query_candidates = normalizer.extract_query_candidates(raw_query)
            for _, qc in ipairs(query_candidates) do
                for _, block_re in ipairs(self.compiled_block) do
                    if block_re:match(qc) then
                        is_blocked = true
                        blocked_pattern = block_re.pattern
                        blocked_target = raw_query
                        blocked_reason = "query_blocked"
                        break
                    end
                end
                if is_blocked then break end
            end
        end
    end

    -- Optional Header Inspection
    if not is_blocked and self.config.check_headers and #self.config.check_headers > 0 then
        for _, hdr_name in ipairs(self.config.check_headers) do
            local hdr_val = headers[string.lower(hdr_name)] or headers[hdr_name]
            if hdr_val and hdr_val ~= "" then
                local header_candidates = { hdr_val }
                for _, hc in ipairs(normalizer.extract_candidate_paths(hdr_val, hdr_val, hdr_val)) do
                    table.insert(header_candidates, hc)
                end
                for _, hc in ipairs(header_candidates) do
                    for _, block_re in ipairs(self.compiled_block) do
                        if block_re:match(hc) then
                            is_blocked = true
                            blocked_pattern = block_re.pattern
                            blocked_target = hdr_val
                            blocked_reason = "header_blocked"
                            break
                        end
                    end
                    if is_blocked then break end
                end
            end
            if is_blocked then break end
        end
    end

    -- Optional Body Inspection (supports OpenResty ngx.req.read_body / ngx.req.get_body_data or mocked req_ctx.body)
    local should_check_body = (self.config.check_body or (self.compiled_body and #self.compiled_body > 0))
    if not is_blocked and should_check_body then
        local body_data = req_ctx.body
        if not body_data and ngx and ngx.req and type(ngx.req.read_body) == "function" then
            pcall(ngx.req.read_body)
            body_data = ngx.req.get_body_data()
            if not body_data and type(ngx.req.get_body_file) == "function" then
                local file_name = ngx.req.get_body_file()
                if file_name then
                    local f = io.open(file_name, "rb")
                    if f then
                        local max_bytes = self.config.check_body_max_bytes or 65536
                        body_data = f:read(max_bytes)
                        f:close()
                    end
                end
            end
        end

        if body_data and type(body_data) == "string" and body_data ~= "" then
            local max_bytes = self.config.check_body_max_bytes or 65536
            if string.len(body_data) > max_bytes then
                body_data = string.sub(body_data, 1, max_bytes)
            end

            local unescaped_body = normalizer.unescape_uri(body_data)
            local body_candidates = { body_data }
            if unescaped_body and unescaped_body ~= body_data then
                table.insert(body_candidates, unescaped_body)
            end

            local patterns_to_check = self.compiled_body
            if not patterns_to_check or #patterns_to_check == 0 then
                patterns_to_check = self.compiled_block
            end

            for _, bc in ipairs(body_candidates) do
                for _, re in ipairs(patterns_to_check) do
                    if re:match(bc) then
                        is_blocked = true
                        blocked_pattern = re.pattern
                        blocked_target = "[body payload]"
                        blocked_reason = "body_blocked"
                        break
                    end
                end
                if is_blocked then break end
            end
        end
    end

    if is_blocked then
        local action_mode = self.config.response.mode
        local status_code = 403
        if self.response_handler and self.response_handler.silent_drop then
            action_mode = "silentDrop"
            status_code = 0
        elseif self.response_handler and self.response_handler.status_code then
            status_code = self.response_handler.status_code
        elseif self.config.response and self.config.response.status_code then
            status_code = self.config.response.status_code
        end

        local block_info = {
            client_ip = client_ip,
            method = method,
            path = blocked_target,
            request_uri = raw_uri,
            pattern = blocked_pattern,
            action = action_mode,
            status_code = status_code,
            reason = blocked_reason,
            user_agent = (headers and (headers["user-agent"] or headers["User-Agent"])) or ""
        }

        if self.config.security_log then
            logger.log_security_event(block_info, true, self.custom_log_sink)
        end

        return false, block_info
    end

    return true
end

-- Top-level check function called from access_by_lua_block
function _M:check(req_ctx)
    -- If no req_ctx passed, build clean NGINX request context automatically
    local ctx = req_ctx or {}
    if not ctx.query_string and ngx and ngx.var then
        ctx.query_string = ngx.var.query_string or ""
    end
    if not ctx.raw_uri and ngx and ngx.var then
        ctx.raw_uri = ngx.var.request_uri or ""
    end
    if not ctx.uri and ngx and ngx.var then
        ctx.uri = ngx.var.uri or "/"
    end
    if not ctx.method and ngx and ngx.req and ngx.req.get_method then
        ctx.method = ngx.req.get_method()
    end
    if not ctx.headers and ngx and ngx.req and ngx.req.get_headers then
        ctx.headers = ngx.req.get_headers()
    end
    if not ctx.remote_addr and ngx and ngx.var then
        ctx.remote_addr = ngx.var.remote_addr or ""
    end

    local passed, block_info = self:inspect(ctx)
    if not passed then
        return self.response_handler:serve(ctx)
    end
end

return _M
