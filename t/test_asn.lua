package.path = 'lib/?.lua;lib/?/init.lua;' .. package.path
local rw = require('resty.routewarden')
local ok, tmp = pcall(os.tmpname)
local path = (ok and tmp) or ("t/test_asn_" .. os.time() .. ".tmp")
local function write(content)
    local f = assert(io.open(path, 'w')); f:write(content); f:close()
end
write('{"AS64500":["8.0.0.0/8","2001:db8::/32"],"64501":["8.8.8.0/24","2001:db8:1::/48"]}')
local function create(extra)
    local opts = { allowed_asns = { 'as64500' }, asn_db = path, security_log = false }
    for k, v in pairs(extra or {}) do opts[k] = v end
    return assert(rw.new(opts))
end
local function inspect(instance, ip, headers)
    return instance:inspect({ method = 'GET', uri = '/.env', raw_uri = '/.env', remote_addr = ip, headers = headers or {} })
end
local instance = create()
assert(inspect(instance, '8.1.2.3'))
assert(inspect(instance, '::ffff:8.1.2.3'))
assert(inspect(instance, '[::ffff:8.1.2.3]:443'))
assert(inspect(instance, '2001:db8:2::1'))
assert(not inspect(instance, '8.8.8.8'))
assert(not inspect(instance, '2001:db8:1::1'))
assert(not inspect(instance, '9.1.2.3'))
assert(not inspect(instance, '127.0.0.1'))
assert(not inspect(instance, 'bad'))
for _, ip in ipairs({ '008.1.2.3', '::ffff:008.1.2.3', ':2001:db8::1', '2001:db8::1:', '2001:db8:zzzz::1', '2001:db8:10000::1', '2001:db8:::1', '2001:db8::1::2', '2001:db8:0:0:0:0:0:0::' }) do
 assert(not inspect(instance, ip), 'malformed address bypassed: ' .. ip)
end
assert(not inspect(instance, '9.1.2.3', { ['X-Forwarded-For'] = '8.1.2.3' }))
instance = create({ trusted_proxies = { '10.0.0.0/8' } })
assert(inspect(instance, '10.1.2.3', { ['X-Forwarded-For'] = '8.1.2.3' }))
assert(inspect(instance, '10.1.2.3', { ['X-Forwarded-For'] = '::ffff:8.1.2.3' }))
assert(not inspect(instance, '9.1.2.3', { ['X-Forwarded-For'] = '8.1.2.3' }))
instance = assert(rw.new({ allowedASNs = { '64500' }, asnDB = path, security_log = false }))
assert(inspect(instance, '8.1.2.3'))
for _, invalid in ipairs({ '0', '-1', '+64500', 'AS', '4294967296', '64502' }) do
    local result = rw.new({ allowed_asns = { invalid }, asn_db = path })
    assert(not result, 'accepted invalid ASN ' .. invalid)
end
assert(not rw.new({ allowed_asns = { '64500' } }))
assert(not rw.new({ allowed_asns = { '64500' }, asn_db = path .. 'missing' }))
write('{"64500":["2001:db8::/32"],"64501":["2001:0db8:0:0::/32"]}')
assert(not rw.new({ allowed_asns = { '64500' }, asn_db = path }))
for _, prefix in ipairs({ 'garbage::/0', '2001:db8:zzzz::/32', '2001:db8:10000::/32' }) do
 write('{"64500":["' .. prefix .. '"]}')
 assert(not rw.new({ allowed_asns = { '64500' }, asn_db = path }), 'accepted malformed prefix ' .. prefix)
end
write('{"64500":["invalid"]}')
assert(not rw.new({ allowed_asns = { '64500' }, asn_db = path }))
-- Existing instances retain their validated snapshot after the file changes.
assert(inspect(instance, '8.1.2.3'))
os.remove(path)
print('ASN lookup, validation, IPv4/IPv6, longest-prefix and trusted-proxy tests passed')
