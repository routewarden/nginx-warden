-- lib/resty/routewarden/logger.lua
-- Security logging emitting structured JSON records for CrowdSec and NGINX logs

local _M = {
    _VERSION = "1.2.1"
}

-- Simple, robust pure-Lua JSON serializer for logging
local function json_escape_string(s)
    if s == nil then return '""' end
    s = tostring(s)
    local escaped = s:gsub('\\', '\\\\')
                     :gsub('"', '\\"')
                     :gsub('\n', '\\n')
                     :gsub('\r', '\\r')
                     :gsub('\t', '\\t')
                     :gsub('%z', '\\u0000')
    return '"' .. escaped .. '"'
end

function _M.to_json(tbl)
    local parts = {}
    for k, v in pairs(tbl) do
        local key_str = json_escape_string(tostring(k))
        local val_str
        if type(v) == "string" then
            val_str = json_escape_string(v)
        elseif type(v) == "number" or type(v) == "boolean" then
            val_str = tostring(v)
        elseif type(v) == "nil" then
            val_str = "null"
        else
            val_str = json_escape_string(tostring(v))
        end
        table.insert(parts, key_str .. ":" .. val_str)
    end
    return "{" .. table.concat(parts, ",") .. "}"
end

-- ISO 8601 UTC timestamp generator
local function get_iso_timestamp()
    if ngx and ngx.time then
        return os.date("!%Y-%m-%dT%H:%M:%SZ", ngx.time())
    else
        return os.date("!%Y-%m-%dT%H:%M:%SZ")
    end
end

-- Emit security event
function _M.log_security_event(event_data, security_log_enabled, custom_sink)
    if not security_log_enabled then
        return
    end

    local timestamp = get_iso_timestamp()
    local payload = {
        type = "routewarden_block",
        timestamp = timestamp,
        plugin = "nginx-warden",
        client_ip = event_data.client_ip or "",
        method = event_data.method or "",
        path = event_data.path or "",
        request_uri = event_data.request_uri or "",
        pattern = event_data.pattern or "",
        action = event_data.action or "text",
        reason = event_data.reason or "path_blocked",
        user_agent = event_data.user_agent or ""
    }

    local json_str = _M.to_json(payload)

    if custom_sink and type(custom_sink) == "function" then
        custom_sink(json_str, payload)
        return
    end

    -- In OpenResty environment
    if ngx and ngx.log and ngx.WARN then
        ngx.log(ngx.WARN, "[routewarden_block] ", json_str)
    else
        io.stdout:write(json_str .. "\n")
        io.stdout:flush()
    end
end

return _M
