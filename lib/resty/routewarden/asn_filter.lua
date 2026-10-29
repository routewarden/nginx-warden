-- Immutable offline ASN routing lookup. Never trusts client-supplied ASN headers.
local ip_filter = require('resty.routewarden.ip_filter')
local M = {}

local function parse_asn(value)
    if type(value) ~= 'string' then return nil end
    value = value:match('^%s*(.-)%s*$'):upper():gsub('^AS', '')
    if not value:match('^%d+$') then return nil end
    local number = tonumber(value)
    if not number or number < 1 or number > 4294967295 then return nil end
    return number
end

function M.new(allowed, path, decode)
    local self = setmetatable({ allowed = {}, roots = {} }, { __index = M })
    if allowed == nil then return self end
    if type(allowed) ~= 'table' then return nil, 'allowed_asns must be an array' end
    if next(allowed) == nil then return self end
    for key, value in pairs(allowed) do
        if type(key) ~= 'number' or key % 1 ~= 0 or key < 1 or key > #allowed then
            return nil, 'allowed_asns must be an array'
        end
        local number = parse_asn(value)
        if not number then return nil, 'invalid ASN: ' .. tostring(value) end
        self.allowed[number] = true
    end
    if type(path) ~= 'string' or path == '' then return nil, 'asn_db required with allowed_asns' end
    local file, err = io.open(path, 'r')
    if not file then return nil, 'ASN database: ' .. tostring(err) end
    local content = file:read('*a')
    file:close()
    local data, decode_err = decode(content)
    if type(data) ~= 'table' then return nil, 'ASN database: ' .. tostring(decode_err or 'expected object') end
    local found = {}
    for key, prefixes in pairs(data) do
        local number = parse_asn(key)
        if not number or type(prefixes) ~= 'table' then return nil, 'invalid ASN database record' end
        for index, prefix in pairs(prefixes) do
            if type(index) ~= 'number' or index % 1 ~= 0 or index < 1 or index > #prefixes then
                return nil, 'ASN prefixes must be an array'
            end
            if type(prefix) ~= 'string' or not prefix:match('/%d+$') then return nil, 'ASN prefix must be a CIDR' end
            local matcher, match_err = ip_filter.new({ prefix }, {})
            if not matcher then return nil, 'ASN database: ' .. tostring(match_err) end
            local address, mask = prefix:match('^(.-)/(%d+)$')
            local bytes = ip_filter.address_bytes(address)
            local bits = tonumber(mask)
            if not bytes then return nil, 'invalid ASN prefix: ' .. prefix end
            if #bytes == 4 and address:find(':', 1, true) then bits = bits - 96 end
            if bits < 0 or bits > #bytes * 8 then return nil, 'invalid ASN mask: ' .. prefix end
            self.roots[#bytes] = self.roots[#bytes] or {}
            local node = self.roots[#bytes]
            for i = 0, bits - 1 do
                local byte = bytes[math.floor(i / 8) + 1]
                local bit = math.floor(byte / 2 ^ (7 - i % 8)) % 2
                node[bit] = node[bit] or {}
                node = node[bit]
            end
            if node.number and node.number ~= number then return nil, 'conflicting ASN prefix: ' .. prefix end
            node.number = number
            found[number] = true
        end
    end
    for number in pairs(self.allowed) do
        if not found[number] then return nil, 'ASN has no prefixes in database: ' .. tostring(number) end
    end
    return self
end

function M:is_allowed(ip)
    local bytes = ip_filter.address_bytes(ip)
    if not bytes then return false end
    local node = self.roots[#bytes]
    local number
    for i = 0, #bytes * 8 do
        if not node then break end
        if node.number then number = node.number end
        if i == #bytes * 8 then break end
        local byte = bytes[math.floor(i / 8) + 1]
        node = node[math.floor(byte / 2 ^ (7 - i % 8)) % 2]
    end
    return self.allowed[number] == true
end
return M
