-- t/test_ip_filter.lua
-- Unit tests for IP and CIDR subnet evaluation

package.path = "lib/?.lua;lib/?/init.lua;" .. package.path

local ip_filter = require("resty.routewarden.ip_filter")

print("Testing ip_filter...")

-- Test constructor with invalid IP/CIDR
local bad_filter, err = ip_filter.new({ "not-an-ip" })
assert(bad_filter == nil, "expected error for invalid IP")
assert(string.find(err, "invalid IPv4 address"), "expected error message for invalid IP")

local bad_cidr, err_cidr = ip_filter.new({ "192.168.1.1/35" })
assert(bad_cidr == nil, "expected error for invalid CIDR bits")

-- Valid IP Filter
local filter, err = ip_filter.new({
    "127.0.0.1",
    "10.0.0.0/8",
    "192.168.1.0/24",
    "::1",
    "2001:db8::/32"
})
assert(filter ~= nil, "failed to initialize filter: " .. tostring(err))

-- IPv4 exact tests
assert(filter:is_allowed("127.0.0.1") == true, "127.0.0.1 should be allowed")
assert(filter:is_allowed("127.0.0.1:8080") == true, "127.0.0.1:8080 should be allowed")
assert(filter:is_allowed("127.0.0.2") == false, "127.0.0.2 should not be allowed")

-- IPv4 CIDR tests
assert(filter:is_allowed("10.1.2.3") == true, "10.1.2.3 in 10.0.0.0/8 should be allowed")
assert(filter:is_allowed("10.255.255.255") == true, "10.255.255.255 in 10.0.0.0/8 should be allowed")
assert(filter:is_allowed("11.0.0.1") == false, "11.0.0.1 should not be allowed")
assert(filter:is_allowed("192.168.1.55") == true, "192.168.1.55 in 192.168.1.0/24 should be allowed")
assert(filter:is_allowed("192.168.2.1") == false, "192.168.2.1 should not be allowed")

-- IPv6 exact tests
assert(filter:is_allowed("::1") == true, "::1 should be allowed")
assert(filter:is_allowed("[::1]:443") == true, "[::1]:443 should be allowed")
assert(filter:is_allowed("::2") == false, "::2 should not be allowed")

-- IPv6 CIDR tests
assert(filter:is_allowed("2001:db8::1") == true, "2001:db8::1 in 2001:db8::/32 should be allowed")
assert(filter:is_allowed("2001:db8:ffff::1") == true, "2001:db8:ffff::1 in 2001:db8::/32 should be allowed")
assert(filter:is_allowed("2001:db9::1") == false, "2001:db9::1 should not be allowed")

-- Client IP extraction from headers
local h1 = { ["x-forwarded-for"] = "203.0.113.195, 70.41.3.18, 150.172.238.178" }
assert(ip_filter.extract_client_ip(h1, "127.0.0.1") == "203.0.113.195")

local h2 = { ["x-real-ip"] = "198.51.100.1" }
assert(ip_filter.extract_client_ip(h2, "127.0.0.1") == "198.51.100.1")

local h3 = {}
assert(ip_filter.extract_client_ip(h3, "192.0.2.1:54321") == "192.0.2.1")

print("All ip_filter tests passed successfully!")
