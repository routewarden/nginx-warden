-- lib/resty/routewarden/normalizer.lua
-- Anti-evasion path normalizer neutralizing multi-layer URL encoding,
-- matrix parameters (;), backslash separators (\), null bytes, and dot traversals.

local _M = {
    _VERSION = "1.8.0"
}

-- Strip query string and fragment from a raw URI if present
local function strip_query(str)
    if not str then return "" end
    local q_idx = string.find(str, "?", 1, true)
    local h_idx = string.find(str, "#", 1, true)
    local idx
    if q_idx and h_idx then
        idx = math.min(q_idx, h_idx)
    else
        idx = q_idx or h_idx
    end
    if idx then
        return string.sub(str, 1, idx - 1)
    end
    return str
end

-- Percent-unescape a string (%XX) using OpenResty ngx.unescape_uri where available
local function unescape_percent(str)
    if not str then return "" end
    if ngx and ngx.unescape_uri then
        return ngx.unescape_uri(str)
    end
    return (string.gsub(str, "%%(%x%x)", function(h)
        local code = tonumber(h, 16)
        if code then
            return string.char(code)
        end
        return "%" .. h
    end))
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

local function strip_scheme_and_authority(s)
    if not s or s == "" then
        return s, false
    end
    local scheme_idx = string.find(s, "://", 1, true)
    if scheme_idx then
        local rest = string.sub(s, scheme_idx + 3)
        local slash_idx = string.find(rest, "[/\\]")
        if slash_idx then
            return string.sub(rest, slash_idx), true
        end
        return "/", true
    end
    return s, false
end

-- Extract candidate paths neutralizing common evasion tricks
function _M.extract_candidate_paths(raw_path, path_str, request_uri)
    local paths_to_check = {}

    local base_path = strip_query(path_str or "/")
    if base_path == "" then base_path = "/" end
    table.insert(paths_to_check, _M.clean_path(base_path))

    -- 1. Add RequestURI path before query to catch gateway discrepancies
    local raw_uri_path = nil
    if request_uri and request_uri ~= "" then
        raw_uri_path = strip_query(request_uri)
        if raw_uri_path ~= "" then
            table.insert(paths_to_check, _M.clean_path(raw_uri_path))
        end
    end

    -- 1a. Extract path from absolute URIs (e.g. http://example.com/path, http://example.com\path)
    local to_unescape = { base_path }
    if raw_uri_path and raw_uri_path ~= "" and raw_uri_path ~= base_path then
        table.insert(to_unescape, raw_uri_path)
    end
    if raw_path and raw_path ~= "" then
        local raw_clean = strip_query(raw_path)
        if raw_clean ~= "" and raw_clean ~= base_path and raw_clean ~= raw_uri_path then
            table.insert(to_unescape, raw_clean)
            table.insert(paths_to_check, _M.clean_path(raw_clean))
        end
    end

    for _, initial in ipairs({ path_str, raw_uri_path, raw_path }) do
        if initial and initial ~= "" then
            local extracted, ok = strip_scheme_and_authority(initial)
            if ok then
                table.insert(paths_to_check, _M.clean_path(extracted))
                table.insert(to_unescape, extracted)
            end
        end
    end

    -- 3. Perform iterative unescaping (up to 5 times) to prevent multi-layer URL encoding evasion (%25252e%25252e)
    for _, initial in ipairs(to_unescape) do
        local cur_path = initial
        for _ = 1, 5 do
            local unescaped = unescape_percent(cur_path)
            if not unescaped or unescaped == cur_path then
                break
            end
            table.insert(paths_to_check, _M.clean_path(unescaped))
            local extracted, ok = strip_scheme_and_authority(unescaped)
            if ok then
                table.insert(paths_to_check, _M.clean_path(extracted))
            end
            cur_path = unescaped
        end
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

            for _, seg in ipairs(parts) do
                local semi_idx = string.find(seg, ";", 1, true)
                if semi_idx then
                    table.insert(cleaned_segments, string.sub(seg, 1, semi_idx - 1))
                else
                    table.insert(cleaned_segments, seg)
                end
            end

            local matrix_stripped = "/" .. table.concat(cleaned_segments, "/")
            table.insert(paths_to_check, _M.clean_path(matrix_stripped))

            local semi_as_slash = string.gsub(p, ";", "/")
            table.insert(paths_to_check, _M.clean_path(semi_as_slash))
        end
    end

    -- 6. Strip and truncate null bytes (prevents C-string termination evasion on extension-anchored rules)
    count = #paths_to_check
    for i = 1, count do
        local p = paths_to_check[i]
        local null_idx = string.find(p, "\0", 1, true)
        if null_idx then
            local truncated = string.sub(p, 1, null_idx - 1)
            table.insert(paths_to_check, _M.clean_path(truncated))
            local no_null = string.gsub(p, "%z", "")
            table.insert(paths_to_check, _M.clean_path(no_null))
        end
    end

    -- 7. Strip embedded URI query (?) and fragments (#) to prevent regex anchor evasion
    count = #paths_to_check
    for i = 1, count do
        local p = paths_to_check[i]
        local q_idx = string.find(p, "?", 1, true)
        local h_idx = string.find(p, "#", 1, true)
        local idx = nil
        if q_idx and h_idx then
            idx = math.min(q_idx, h_idx)
        else
            idx = q_idx or h_idx
        end
        if idx then
            local before = string.sub(p, 1, idx - 1)
            if before ~= "" then
                table.insert(paths_to_check, _M.clean_path(before))
            end
        end
    end

    -- 8. Strip Windows NTFS Alternate Data Streams (::$DATA) evasion
    count = #paths_to_check
    for i = 1, count do
        local p = paths_to_check[i]
        if string.find(string.lower(p), "::$data", 1, true) then
            local stripped = string.gsub(p, "::%$[dD][aA][tT][aA]", "")
            table.insert(paths_to_check, _M.clean_path(stripped))
        end
    end

    -- 9. Strip trailing dots and spaces from path segments (Windows/IIS Win32 API evasion)
    count = #paths_to_check
    for i = 1, count do
        local p = paths_to_check[i]
        if string.find(p, "%.") or string.find(p, "%s") then
            local parts = {}
            for part in string.gmatch(p, "[^/]+") do
                table.insert(parts, part)
            end
            local modified = false
            local cleaned_segments = {}
            for _, seg in ipairs(parts) do
                if seg ~= "." and seg ~= ".." and seg ~= "" then
                    local trimmed = string.match(seg, "^(.-)[.%s]+$")
                    if trimmed and trimmed ~= "" then
                        table.insert(cleaned_segments, trimmed)
                        modified = true
                    else
                        table.insert(cleaned_segments, seg)
                    end
                else
                    table.insert(cleaned_segments, seg)
                end
            end
            if modified then
                local joined = "/" .. table.concat(cleaned_segments, "/")
                table.insert(paths_to_check, _M.clean_path(joined))
            end
        end
    end

    -- 10. Deduplicate candidates and maintain order
    local candidate_paths = {}
    local seen = {}
    for _, p in ipairs(paths_to_check) do
        if p ~= "" then
            local extracted, ok = strip_scheme_and_authority(p)
            if ok then
                p = extracted
            end
            if string.sub(p, 1, 1) ~= "/" then
                p = "/" .. p
            end
            p = _M.clean_path(p)
            if string.sub(p, 1, 7) == "/http:/" or string.sub(p, 1, 8) == "/https:/" then
                local second_slash = string.find(p, "/", 2, true)
                if second_slash then
                    local rest = string.sub(p, second_slash + 1)
                    local slash_idx = string.find(rest, "[/\\]")
                    if slash_idx then
                        p = _M.clean_path(string.sub(rest, slash_idx))
                    else
                        p = "/"
                    end
                end
            end
            if not seen[p] then
                seen[p] = true
                table.insert(candidate_paths, p)
            end
            if p ~= "/" and string.sub(p, -1) ~= "/" then
                local p_slash = p .. "/"
                if not seen[p_slash] then
                    seen[p_slash] = true
                    table.insert(candidate_paths, p_slash)
                end
            end
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

    -- Parse query params (extracting both keys and values from raw and unescaped queries)
    local queries_to_parse = { raw_query }
    if unescaped ~= raw_query then
        table.insert(queries_to_parse, unescaped)
    end

    for _, q in ipairs(queries_to_parse) do
        for pair in string.gmatch(q, "[^&;]+") do
            local eq_idx = string.find(pair, "=", 1, true)
            local key = pair
            local val = ""
            if eq_idx then
                key = string.sub(pair, 1, eq_idx - 1)
                val = string.sub(pair, eq_idx + 1)
            end

            if key ~= "" then
                table.insert(candidates, key)
                local unescaped_key = unescape_percent(key)
                if unescaped_key ~= key then
                    table.insert(candidates, unescaped_key)
                end
                local key_cands = _M.extract_candidate_paths(key, key, key)
                for _, kc in ipairs(key_cands) do
                    table.insert(candidates, kc)
                end
            end

            if val ~= "" then
                table.insert(candidates, val)
                local unescaped_val = unescape_percent(val)
                if unescaped_val ~= val then
                    table.insert(candidates, unescaped_val)
                end
                local val_cands = _M.extract_candidate_paths(val, val, val)
                for _, vc in ipairs(val_cands) do
                    table.insert(candidates, vc)
                end
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

_M.unescape_percent = unescape_percent
_M.unescape_uri = unescape_percent

return _M
