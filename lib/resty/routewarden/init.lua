-- lib/resty/routewarden/init.lua
-- Main entrypoint for RouteWarden NGINX/OpenResty Lua module

local config = require("resty.routewarden.config")
local normalizer = require("resty.routewarden.normalizer")
local ip_filter = require("resty.routewarden.ip_filter")
local response = require("resty.routewarden.response")
local logger = require("resty.routewarden.logger")

local _M = {
    _VERSION = "1.2.0"
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
                local ok, res = pcall(function()
                    return string.find(lower_target, lua_pat)
                end)
                if ok and res ~= nil then
                    return true
                end

                -- 2. Clean PCRE groups e.g. (^|/) and retry
                local clean_pcre = string.gsub(lua_pat, "%(%^|/%)", "")
                clean_pcre = string.gsub(clean_pcre, "%(%?i%)", "")
                ok, res = pcall(function()
                    return string.find(lower_target, clean_pcre)
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

                -- 2. Sensitive extensions
                local exts = { "txt", "log", "bak", "backup", "sql", "conf", "config", "ini", "yaml", "yml", "tar", "zip", "rar", "7z", "gz", "bz2", "iso", "dump", "sqlite", "sqlite3", "db" }
                for _, ext in ipairs(exts) do
                    if string.find(pat, ext, 1, true) then
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

-- Constructor for RouteWarden instance
function _M.new(opts)
    local cfg = config.default_config()

    if opts and type(opts) == "table" then
        if opts.enabled ~= nil then cfg.enabled = opts.enabled end
        if opts.enable_default_patterns ~= nil then cfg.enable_default_patterns = opts.enable_default_patterns end
        if opts.enable_default_allow_patterns ~= nil then cfg.enable_default_allow_patterns = opts.enable_default_allow_patterns end
        if opts.check_query ~= nil then cfg.check_query = opts.check_query end
        if opts.debug ~= nil then cfg.debug = opts.debug end
        if opts.security_log ~= nil then cfg.security_log = opts.security_log end
        if opts.status_code ~= nil then cfg.status_code = opts.status_code end
        if opts.custom_response_text ~= nil then cfg.custom_response_text = opts.custom_response_text end

        if opts.methods then cfg.methods = opts.methods end
        if opts.check_headers then cfg.check_headers = opts.check_headers end
        if opts.path_patterns then cfg.path_patterns = opts.path_patterns end
        if opts.block_patterns then cfg.block_patterns = opts.block_patterns end
        if opts.allow_patterns then cfg.allow_patterns = opts.allow_patterns end
        if opts.allowed_ips then cfg.allowed_ips = opts.allowed_ips end

        if opts.response then
            local resp_cfg = config.default_response_config()
            for k, v in pairs(opts.response) do
                resp_cfg[k] = v
            end
            if resp_cfg.mode then
                resp_cfg.mode = string.lower(resp_cfg.mode)
            end
            cfg.response = resp_cfg
        end
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

    -- Compile block patterns
    local all_block_patterns = {}
    if cfg.enable_default_patterns then
        for _, p in ipairs(config.default_block_patterns) do
            table.insert(all_block_patterns, p)
        end
    end
    if cfg.path_patterns then
        for _, p in ipairs(cfg.path_patterns) do
            table.insert(all_block_patterns, p)
        end
    end
    if cfg.block_patterns then
        for _, p in ipairs(cfg.block_patterns) do
            table.insert(all_block_patterns, p)
        end
    end

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
    if cfg.allow_patterns then
        for _, p in ipairs(cfg.allow_patterns) do
            table.insert(all_allow_patterns, p)
        end
    end

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

    -- Initialize IP Filter
    local ip_matcher, err
    if cfg.allowed_ips and #cfg.allowed_ips > 0 then
        ip_matcher, err = ip_filter.new(cfg.allowed_ips)
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
        ip_matcher = ip_matcher,
        response_handler = resp_handler,
        custom_log_sink = nil
    }

    return setmetatable(self, { __index = _M })
end

-- Validate configuration (returns true, or false, err)
function _M:validate()
    if self.config.response and self.config.response.status_code then
        local code = self.config.response.status_code
        if code < 100 or code > 599 then
            return false, string.format("routewarden: statusCode must be between 100 and 599, got %d", code)
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
    local client_ip = ip_filter.extract_client_ip(headers, remote_addr)

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
                local header_candidates = normalizer.extract_candidate_paths(hdr_val, hdr_val, hdr_val)
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

    if is_blocked then
        local block_info = {
            client_ip = client_ip,
            method = method,
            path = blocked_target,
            request_uri = raw_uri,
            pattern = blocked_pattern,
            action = self.config.response.mode,
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
