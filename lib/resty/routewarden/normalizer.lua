-- lib/resty/routewarden/normalizer.lua
-- Anti-evasion path normalizer neutralizing multi-layer URL encoding,
-- matrix parameters (;), backslash separators (\), null bytes, and dot traversals.

local _M = {
    _VERSION = "1.2.1"
}

-- Strip query string from a raw URI if present
local function strip_query(str)
    if not str then return "" end
    local idx = string.find(str, "?", 1, true)
    if idx then
        return string.sub(str, 1, idx - 1)
    end
    return str
end

-- Percent-unescape a string (%XX)
local function unescape_percent(str)
    if not str then return "" end
    return (string.gsub(str, "%%(%x%x)", function(h)
        local code = tonumber(h, 16)
        if code then
            return string.char(code)
        end
        return "%" .. h
    end))
end

-- Split string by delimiter
local function split(str, delimiter)
    local result = {}
    local pattern = "(.-)" .. delimiter
    local last_end = 1
    local s, e, cap = string.find(str, pattern, 1)
    while s do
        if s ~= 1 or cap ~= "" then
            table.insert(result, cap)
        end
        last_end = e + 1
        s, e, cap = string.find(str, pattern, last_end)
    end
    if last_end <= #str then
        table.insert(result, string.sub(str, last_end))
    end
    return result
end

-- Canonical path cleaner (equivalent to Go path.Clean)
-- Resolves ., .., redundant slashes, leading and trailing slashes
function _M.clean_path(p)
    if not p or p == "" then
        return "/"
    end

    local is_abs = string.sub(p, 1, 1) == "/"
    local segments = {}

    -- Split on slashes
    for seg in string.gmatch(p, "[^/]+") do
        if seg == "." or seg == "" then
            -- skip
        elseif seg == ".." then
            if #segments > 0 and segments[#segments] ~= ".." then
                table.remove(segments)
            elseif not is_abs then
                table.insert(segments, "..")
            end
        else
            table.insert(segments, seg)
        end
    end

    local cleaned = table.concat(segments, "/")
    if is_abs then
        cleaned = "/" .. cleaned
    end

    if cleaned == "" then
        return is_abs and "/" or "."
    end

    return cleaned
end

-- Extract candidate paths neutralizing common evasion tricks
function _M.extract_candidate_paths(raw_path, path_str, request_uri)
    local paths_to_check = {}

    local base_path = path_str or "/"
    table.insert(paths_to_check, _M.clean_path(base_path))

    -- 1. Add RequestURI path before query to catch gateway discrepancies
    if request_uri and request_uri ~= "" then
        local raw_uri_path = strip_query(request_uri)
        if raw_uri_path ~= "" then
            table.insert(paths_to_check, _M.clean_path(raw_uri_path))
        end
    end

    -- 2. Add RawPath if specified and different
    if raw_path and raw_path ~= "" and raw_path ~= base_path then
        table.insert(paths_to_check, _M.clean_path(raw_path))
    end

    -- 3. Perform iterative unescaping (up to 3 times) to prevent multi-layer URL encoding evasion (%252e%252e)
    local cur_path = base_path
    for _ = 1, 3 do
        local unescaped = unescape_percent(cur_path)
        if not unescaped or unescaped == cur_path then
            break
        end
        table.insert(paths_to_check, _M.clean_path(unescaped))
        cur_path = unescaped
    end

    -- 4. Check backslash-converted paths (Windows / IIS style path traversal / separator evasion)
    local count = #paths_to_check
    for i = 1, count do
        local p = paths_to_check[i]
        if string.find(p, "\\", 1, true) then
            local slash_converted = string.gsub(p, "\\", "/")
            table.insert(paths_to_check, _M.clean_path(slash_converted))
        end
    end

    -- 5. Semicolon matrix parameter handling (e.g. /;.env, /app;jsessionid=123/.env, /api;.env/config.json)
    count = #paths_to_check
    for i = 1, count do
        local p = paths_to_check[i]
        if string.find(p, ";", 1, true) then
            local parts = {}
            for part in string.gmatch(p, "[^/]+") do
                table.insert(parts, part)
            end

            local cleaned_segments = {}
            local param_segments = {}

            for _, seg in ipairs(parts) do
                local semi_idx = string.find(seg, ";", 1, true)
                if semi_idx then
                    table.insert(cleaned_segments, string.sub(seg, 1, semi_idx - 1))
                    local param = string.sub(seg, semi_idx + 1)
                    if param ~= "" then
                        table.insert(param_segments, param)
                    end
                else
                    table.insert(cleaned_segments, seg)
                end
            end

            local matrix_stripped = "/" .. table.concat(cleaned_segments, "/")
            table.insert(paths_to_check, _M.clean_path(matrix_stripped))

            for _, param in ipairs(param_segments) do
                if param ~= "" then
                    table.insert(paths_to_check, "/" .. param)
                    table.insert(paths_to_check, _M.clean_path("/" .. param))
                end
            end

            local semi_as_slash = string.gsub(p, ";", "/")
            table.insert(paths_to_check, _M.clean_path(semi_as_slash))
        end
    end

    -- 6. Strip null bytes
    count = #paths_to_check
    for i = 1, count do
        local p = paths_to_check[i]
        if string.find(p, "\0", 1, true) then
            local no_null = string.gsub(p, "%z", "")
            table.insert(paths_to_check, _M.clean_path(no_null))
        end
    end

    -- 7. Deduplicate candidates and maintain order
    local candidate_paths = {}
    local seen = {}
    for _, p in ipairs(paths_to_check) do
        if p ~= "" and not seen[p] then
            seen[p] = true
            table.insert(candidate_paths, p)
        end
    end

    return candidate_paths
end

-- Query candidate extraction for check_query
function _M.extract_query_candidates(raw_query)
    if not raw_query or raw_query == "" then
        return {}
    end

    local candidates = { raw_query }
    local unescaped = unescape_percent(raw_query)
    if unescaped ~= raw_query then
        table.insert(candidates, unescaped)
    end

    -- Parse query params
    for pair in string.gmatch(raw_query, "[^&;]+") do
        local eq_idx = string.find(pair, "=", 1, true)
        local val = pair
        if eq_idx then
            val = string.sub(pair, eq_idx + 1)
        end
        if val ~= "" then
            table.insert(candidates, val)
            local unescaped_val = unescape_percent(val)
            if unescaped_val ~= val then
                table.insert(candidates, unescaped_val)
            end

            -- Also test candidate paths for the parameter value
            local path_cands = _M.extract_candidate_paths(val, val, val)
            for _, pc in ipairs(path_cands) do
                table.insert(candidates, pc)
            end
        end
    end

    -- Deduplicate
    local result = {}
    local seen = {}
    for _, c in ipairs(candidates) do
        if c ~= "" and not seen[c] then
            seen[c] = true
            table.insert(result, c)
        end
    end

    return result
end

return _M
