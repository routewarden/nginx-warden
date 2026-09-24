-- lib/resty/routewarden/config.lua
-- Configuration defaults and default sensitive/allow regex patterns

local _M = {
    _VERSION = "1.2.0"
}

-- Default block patterns for sensitive endpoints, files, and credentials
_M.default_block_patterns = {
    -- Sensitive extensions & environment files (e.g. .env, .env.local, .txt, .log, .bak, .backup, .sql, .conf, .config, .ini, .yaml, .yml)
    [[(?i)(^|/)(\.env.*|.*\.(txt|log|bak|backup|sql|conf|config|ini|yaml|yml))$]],
    -- Version control & sensitive hidden directories
    [[(?i)(^|/)\.(git|svn|hg|bzr|cvs)(/.*|$)]],
    -- Cloud & infra credentials
    [[(?i)(^|/)\.(aws|ssh|kube|docker)(/.*|$)]],
    -- Database & server dump files / archives
    [[(?i).*\.(tar|tar\.gz|tgz|zip|rar|7z|gz|bz2|iso|dump|sqlite|sqlite3|db)$]],
    -- Common sensitive admin & debug endpoints
    [[(?i)(^|/)(phpinfo\.php|info\.php|server-status|server-info|actuator(/.*)?|metrics|heapdump|trace|env)$]],
    -- Package manager files & lockfiles
    [[(?i)(^|/)(composer\.(json|lock)|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Pipfile|Pipfile\.lock|requirements\.txt)$]],
    -- TLS & cryptographic private keys, certificates, keystores
    [[(?i).*\.(pem|key|crt|pfx|p12|jks|kdb)$]],
    -- Container & orchestration manifests and configs
    [[(?i)(^|/)(dockerfile.*|docker-compose.*\.ya?ml)$]],
    -- System & macOS metadata files
    [[(?i)(^|/)\.ds_store$]],
    -- Web framework and CMS sensitive configuration files
    [[(?i)(^|/)(wp-config\.php.*|configuration\.php.*|settings\.py|local_settings\.py)$]]
}

-- Default allow patterns that exempt legitimate endpoints matching broad rules
_M.default_allow_patterns = {
    [[(?i)^/robots\.txt$]],
    [[(?i)^/sitemap.*\.xml$]],
    [[(?i)^/ads\.txt$]],
    [[(?i)^/security\.txt$]],
    [[(?i)^/\.well-known(/.*)?$]]
}

-- Return default response configuration
function _M.default_response_config()
    return {
        mode = "json",
        status_code = 403,
        body = "",
        content_type = nil,
        headers = {},
        redirect_url = "/",
        proxy_url = nil,
        captcha = {
            provider = "turnstile",
            site_key = "",
            title = "Security Check Required",
            template = nil
        },
        gzip_bomb_mb = 10,
        retry_after_seconds = 300,
        tarpit_delay_ms = 1000,
        tarpit_max_duration_seconds = 60,
        stream_size_mb = 100
    }
end

-- Return complete default module configuration
function _M.default_config()
    return {
        enabled = true,
        enable_default_patterns = true,
        enable_default_allow_patterns = true,
        path_patterns = {},
        block_patterns = {},
        allow_patterns = {},
        allowed_ips = {},
        methods = { "GET" },
        check_query = false,
        check_headers = {},
        status_code = nil,
        custom_response_text = nil,
        debug = false,
        security_log = true,
        response = _M.default_response_config()
    }
end

return _M
