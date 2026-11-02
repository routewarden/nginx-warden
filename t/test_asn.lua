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

-- Test blocked ASNs
write('{"AS64500":["8.0.0.0/8","2001:db8::/32"],"64501":["8.8.8.0/24","2001:db8:1::/48"]}')
local blocked_inst = assert(rw.new({ blocked_asns = { '64501' }, asn_db = path, security_log = false }))
local ok_pass, _ = blocked_inst:inspect({ method = 'GET', uri = '/safe.html', raw_uri = '/safe.html', remote_addr = '8.1.2.3' })
assert(ok_pass, 'safe IP in AS64500 should pass')
local ok_block, block_info = blocked_inst:inspect({ method = 'GET', uri = '/safe.html', raw_uri = '/safe.html', remote_addr = '8.8.8.8' })
assert(not ok_block, 'IP in AS64501 should be blocked')
assert(block_info and block_info.reason == 'asn_blocked', 'reason should be asn_blocked')
assert(block_info and block_info.pattern == 'AS64501', 'pattern should be AS64501')

-- Test cloud host blocking
write('{"16509":["54.240.196.0/24"],"24940":["136.243.0.0/16"]}')
local cloud_inst = assert(rw.new({
    block_cloud_hosts = true,
    asn_db = path,
    allow_patterns = { '^/api/webhook$' },
    allowed_ips = { '54.240.196.99' },
    security_log = false
}))

-- 1. Browser from AWS (AS16509) -> blocked (datacenter_browser_impersonation)
local ok_c1, info_c1 = cloud_inst:inspect({
    method = 'GET', uri = '/dashboard', raw_uri = '/dashboard', remote_addr = '54.240.196.10',
    headers = { ['user-agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36' }
})
assert(not ok_c1, 'browser from AWS should be blocked')
assert(info_c1.reason == 'datacenter_browser_impersonation', 'expected datacenter_browser_impersonation, got ' .. tostring(info_c1.reason))

-- 2. Non-browser from Hetzner (AS24940) -> blocked (cloud_host_blocked)
local ok_c2, info_c2 = cloud_inst:inspect({
    method = 'GET', uri = '/items', raw_uri = '/items', remote_addr = '136.243.1.2',
    headers = { ['user-agent'] = 'CustomCollector/2.0' }
})
assert(not ok_c2, 'scraper from Hetzner should be blocked')
assert(info_c2.reason == 'cloud_host_blocked', 'expected cloud_host_blocked, got ' .. tostring(info_c2.reason))

-- 3. AllowPattern exemption (/api/webhook) from AWS -> allowed
local ok_c3, _ = cloud_inst:inspect({
    method = 'GET', uri = '/api/webhook', raw_uri = '/api/webhook', remote_addr = '54.240.196.10',
    headers = { ['user-agent'] = 'GitHub-Hookshot/1.0' }
})
assert(ok_c3, 'allow pattern should exempt AWS IP')

-- 4. Whitelisted IP exemption from AWS -> allowed
local ok_c4, _ = cloud_inst:inspect({
    method = 'GET', uri = '/private', raw_uri = '/private', remote_addr = '54.240.196.99',
    headers = { ['user-agent'] = 'CustomApp/1.0' }
})
assert(ok_c4, 'allowed IP should exempt AWS IP')

os.remove(path)
print('ASN lookup, validation, IPv4/IPv6, longest-prefix and trusted-proxy tests passed')
