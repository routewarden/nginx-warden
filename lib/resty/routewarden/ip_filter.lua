-- lib/resty/routewarden/ip_filter.lua
-- IPv4/IPv6 address parsing and CIDR subnet evaluation for client IP whitelisting

local _M = {
    _VERSION = "1.0.0"
}

-- Convert an IPv4 dotted quad string to a 32-bit unsigned number
local function ipv4_to_num(ip_str)
    local o1, o2, o3, o4 = string.match(ip_str, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not o1 then return nil end
    o1, o2, o3, o4 = tonumber(o1), tonumber(o2), tonumber(o3), tonumber(o4)
    if o1 > 255 or o2 > 255 or o3 > 255 or o4 > 255 then
        return nil
    end
    return o1 * 16777216 + o2 * 65536 + o3 * 256 + o4
end

-- Convert 32-bit CIDR mask bits (0-32) to numeric mask
local function cidr_mask(bits)
    if bits == 0 then return 0 end
    local mask = 0
    local cur = 2147483648 -- 2^31
    for _ = 1, bits do
        mask = mask + cur
        cur = cur / 2
    end
    return mask
end

-- Bitwise AND for numbers within 32-bit integer range
local function bit_and(a, b)
    local res = 0
    local p = 1
    for _ = 1, 32 do
        local ra = a % 2
        local rb = b % 2
        if ra == 1 and rb == 1 then
            res = res + p
        end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        p = p * 2
        if a == 0 or b == 0 then break end
    end
    return res
end

-- Expand and parse IPv6 string to 16-byte array
local function ipv6_to_bytes(ip_str)
    -- Handle IPv4-mapped IPv6 (e.g. ::ffff:192.0.2.1)
    local v4_part = string.match(ip_str, ":(%d+%.%d+%.%d+%.%d+)$")
    if v4_part then
        local num = ipv4_to_num(v4_part)
        if not num then return nil end
        local o1, o2, o3, o4 = string.match(v4_part, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
        local hex_part = string.format("%02x%02x:%02x%02x", o1, o2, o3, o4)
        ip_str = string.sub(ip_str, 1, #ip_str - #v4_part) .. hex_part
    end

    local double_colon_idx = string.find(ip_str, "::", 1, true)
    local parts = {}

    if double_colon_idx then
        local left = string.sub(ip_str, 1, double_colon_idx - 1)
        local right = string.sub(ip_str, double_colon_idx + 2)

        local left_parts = {}
        for h in string.gmatch(left, "[^:]+") do
            table.insert(left_parts, tonumber(h, 16))
        end

        local right_parts = {}
        for h in string.gmatch(right, "[^:]+") do
            table.insert(right_parts, tonumber(h, 16))
        end

        local missing = 8 - (#left_parts + #right_parts)
        if missing < 0 then return nil end

        for _, v in ipairs(left_parts) do table.insert(parts, v) end
        for _ = 1, missing do table.insert(parts, 0) end
        for _, v in ipairs(right_parts) do table.insert(parts, v) end
    else
        for h in string.gmatch(ip_str, "[^:]+") do
            local val = tonumber(h, 16)
            if not val or val > 0xffff then return nil end
            table.insert(parts, val)
        end
        if #parts ~= 8 then return nil end
    end

    local bytes = {}
    for i = 1, 8 do
        local val = parts[i] or 0
        table.insert(bytes, math.floor(val / 256))
        table.insert(bytes, val % 256)
    end
    return bytes
end

-- Check if bytes match under CIDR mask
local function ipv6_match_cidr(ip_bytes, net_bytes, mask_bits)
    local full_bytes = math.floor(mask_bits / 8)
    local rem_bits = mask_bits % 8

    for i = 1, full_bytes do
        if ip_bytes[i] ~= net_bytes[i] then
            return false
        end
    end

    if rem_bits > 0 then
        local idx = full_bytes + 1
        local mask = 0
        local cur = 128
        for _ = 1, rem_bits do
            mask = mask + cur
            cur = cur / 2
        end
        if bit_and(ip_bytes[idx], mask) ~= bit_and(net_bytes[idx], mask) then
            return false
        end
    end

    return true
end

-- Constructor for IPFilter
function _M.new(allowed_ips_config)
    local self = {
        ipv4_exact = {},
        ipv4_nets = {},
        ipv6_exact = {},
        ipv6_nets = {}
    }

    if not allowed_ips_config or #allowed_ips_config == 0 then
        return setmetatable(self, { __index = _M })
    end

    for _, entry in ipairs(allowed_ips_config) do
        local trimmed = string.match(entry, "^%s*(.-)%s*$")
        if trimmed ~= "" then
            local slash_idx = string.find(trimmed, "/", 1, true)
            if slash_idx then
                local ip_part = string.sub(trimmed, 1, slash_idx - 1)
                local bits_str = string.sub(trimmed, slash_idx + 1)
                local bits = tonumber(bits_str)
                if not bits then
                    return nil, string.format("routewarden: invalid CIDR mask in %q", trimmed)
                end

                if string.find(ip_part, ":", 1, true) then
                    -- IPv6 CIDR
                    if bits < 0 or bits > 128 then
                        return nil, string.format("routewarden: invalid IPv6 CIDR bits in %q", trimmed)
                    end
                    local net_bytes = ipv6_to_bytes(ip_part)
                    if not net_bytes then
                        return nil, string.format("routewarden: invalid IPv6 address in %q", trimmed)
                    end
                    table.insert(self.ipv6_nets, { bytes = net_bytes, bits = bits })
                else
                    -- IPv4 CIDR
                    if bits < 0 or bits > 32 then
                        return nil, string.format("routewarden: invalid IPv4 CIDR bits in %q", trimmed)
                    end
                    local ip_num = ipv4_to_num(ip_part)
                    if not ip_num then
                        return nil, string.format("routewarden: invalid IPv4 address in %q", trimmed)
                    end
                    local mask = cidr_mask(bits)
                    table.insert(self.ipv4_nets, { net = bit_and(ip_num, mask), mask = mask })
                end
            else
                -- Exact IP
                if string.find(trimmed, ":", 1, true) then
                    local bytes = ipv6_to_bytes(trimmed)
                    if not bytes then
                        return nil, string.format("routewarden: invalid IPv6 address %q", trimmed)
                    end
                    local hex_key = ""
                    for _, b in ipairs(bytes) do
                        hex_key = hex_key .. string.format("%02x", b)
                    end
                    self.ipv6_exact[hex_key] = true
                else
                    local num = ipv4_to_num(trimmed)
                    if not num then
                        return nil, string.format("routewarden: invalid IPv4 address %q", trimmed)
                    end
                    self.ipv4_exact[num] = true
                end
            end
        end
    end

    return setmetatable(self, { __index = _M })
end

-- Is an IP allowed?
function _M:is_allowed(client_ip_str)
    if not client_ip_str or client_ip_str == "" then
        return false
    end

    -- Clean IP: strip port if host:port (e.g. 192.168.1.1:54321)
    local ip = client_ip_str
    if string.sub(ip, 1, 1) == "[" then
        -- [::1]:8080
        local bracket_end = string.find(ip, "]", 2, true)
        if bracket_end then
            ip = string.sub(ip, 2, bracket_end - 1)
        end
    elseif string.find(ip, "%.") then
        -- IPv4 with port
        local colon = string.find(ip, ":", 1, true)
        if colon then
            ip = string.sub(ip, 1, colon - 1)
        end
    end

    if string.find(ip, ":", 1, true) then
        -- IPv6 evaluation
        local bytes = ipv6_to_bytes(ip)
        if not bytes then return false end

        local hex_key = ""
        for _, b in ipairs(bytes) do
            hex_key = hex_key .. string.format("%02x", b)
        end
        if self.ipv6_exact[hex_key] then
            return true
        end

        for _, net in ipairs(self.ipv6_nets) do
            if ipv6_match_cidr(bytes, net.bytes, net.bits) then
                return true
            end
        end
    else
        -- IPv4 evaluation
        local num = ipv4_to_num(ip)
        if not num then return false end

        if self.ipv4_exact[num] then
            return true
        end

        for _, net in ipairs(self.ipv4_nets) do
            if bit_and(num, net.mask) == net.net then
                return true
            end
        end
    end

    return false
end

-- Extract Client IP from HTTP headers (X-Forwarded-For, X-Real-IP) or fallback to socket addr
function _M.extract_client_ip(headers, remote_addr)
    if headers then
        local xff = headers["x-forwarded-for"] or headers["X-Forwarded-For"]
        if xff and xff ~= "" then
            local first_ip = string.match(xff, "^([^,]+)")
            if first_ip then
                local trimmed = string.match(first_ip, "^%s*(.-)%s*$")
                if trimmed ~= "" then
                    return trimmed
                end
            end
        end

        local xrip = headers["x-real-ip"] or headers["X-Real-IP"]
        if xrip and xrip ~= "" then
            local trimmed = string.match(xrip, "^%s*(.-)%s*$")
            if trimmed ~= "" then
                return trimmed
            end
        end
    end

    if remote_addr then
        local colon = string.find(remote_addr, ":", 1, true)
        if colon and not string.find(remote_addr, "::", 1, true) then
            return string.sub(remote_addr, 1, colon - 1)
        end
        return remote_addr
    end

    return ""
end

return _M
