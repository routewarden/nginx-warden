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
assert(ip_filter.extract_client_ip(h3, "[2001:db8::1]:12345") == "2001:db8::1")
assert(ip_filter.extract_client_ip(h3, "[::1]:8080") == "::1")

local h4 = { ["x-forwarded-for"] = "192.168.1.50:49200, 10.0.0.1" }
assert(ip_filter.extract_client_ip(h4, "127.0.0.1") == "192.168.1.50")

local h5 = { ["x-forwarded-for"] = "[2001:db8::99]:55432" }
assert(ip_filter.extract_client_ip(h5, "127.0.0.1") == "2001:db8::99")

local h6 = { ["x-real-ip"] = "[2001:db8::99]" }
assert(ip_filter.extract_client_ip(h6, "127.0.0.1") == "2001:db8::99")

-- Trusted proxies testing
local trusted_f = ip_filter.new({ "10.0.0.50" }, { "192.168.1.1", "10.100.0.0/16" })
assert(trusted_f.has_trusted_proxies == true)

-- Untrusted client connects with spoofed XFF
local h_spoof = { ["x-forwarded-for"] = "10.0.0.50" }
assert(ip_filter.extract_client_ip(h_spoof, "203.0.113.99:1234", trusted_f) == "203.0.113.99", "untrusted remote_addr must not spoof XFF")
assert(trusted_f:is_allowed(ip_filter.extract_client_ip(h_spoof, "203.0.113.99:1234", trusted_f)) == false, "spoofed IP must not be allowed")

-- Trusted proxy forwards whitelisted client IP
assert(ip_filter.extract_client_ip(h_spoof, "192.168.1.1:5432", trusted_f) == "10.0.0.50", "trusted proxy XFF must be honoured")
assert(trusted_f:is_allowed(ip_filter.extract_client_ip(h_spoof, "192.168.1.1:5432", trusted_f)) == true, "forwarded IP from trusted proxy must be allowed")

-- ─── Edge cases I-1 to I-10 ────────────────────────────────────────────────

-- I-1: 0.0.0.0/0 match-all IPv4 CIDR
local match_all_f, err_all = ip_filter.new({ "0.0.0.0/0" })
assert(match_all_f ~= nil, "failed to parse 0.0.0.0/0: " .. tostring(err_all))
assert(match_all_f:is_allowed("1.2.3.4") == true, "0.0.0.0/0 must match any IPv4")
assert(match_all_f:is_allowed("198.51.100.254") == true, "0.0.0.0/0 must match 198.51.100.254")
assert(match_all_f:is_allowed("2001:db8::1") == false, "0.0.0.0/0 must not match IPv6")

-- I-2: /32 single host CIDR
local single_host_f = ip_filter.new({ "192.168.5.10/32" })
assert(single_host_f:is_allowed("192.168.5.10") == true)
assert(single_host_f:is_allowed("192.168.5.11") == false)

-- I-3: X-Forwarded-For with whitespace-padded IPs
local h_ws = { ["x-forwarded-for"] = "   10.0.0.1   ,  192.168.1.1 " }
assert(ip_filter.extract_client_ip(h_ws, "127.0.0.1") == "10.0.0.1")

-- I-4: X-Forwarded-For with 10 IPs in chain
local chain = "10.1.1.1, 10.2.2.2, 10.3.3.3, 10.4.4.4, 10.5.5.5, 10.6.6.6, 10.7.7.7, 10.8.8.8, 10.9.9.9, 10.10.10.10"
local h_chain = { ["x-forwarded-for"] = chain }
assert(ip_filter.extract_client_ip(h_chain, "127.0.0.1") == "10.1.1.1")

-- I-5: X-Forwarded-For takes precedence, and X-Real-IP acts as fallback
local h_prec = {
    ["x-real-ip"] = "172.16.0.5",
    ["x-forwarded-for"] = "192.168.0.1, 10.0.0.1"
}
assert(ip_filter.extract_client_ip(h_prec, "127.0.0.1") == "192.168.0.1")

local h_real_only = {
    ["x-real-ip"] = "172.16.0.5"
}
assert(ip_filter.extract_client_ip(h_real_only, "127.0.0.1") == "172.16.0.5")

-- I-6: Empty or nil allowed_ips
local empty_filter = ip_filter.new({})
assert(empty_filter:is_allowed("127.0.0.1") == false)
assert(empty_filter:is_allowed("::1") == false)

local nil_filter = ip_filter.new(nil)
assert(nil_filter:is_allowed("127.0.0.1") == false)

-- I-7: Duplicate IPs in allowed_ips
local dup_filter, dup_err = ip_filter.new({ "10.0.0.1", "10.0.0.1", "192.168.1.0/24", "192.168.1.0/24" })
assert(dup_filter ~= nil and dup_err == nil)
assert(dup_filter:is_allowed("10.0.0.1") == true)
assert(dup_filter:is_allowed("192.168.1.5") == true)

-- I-8: IPv6 zone ID stripped from remote address
local h_zone = {}
assert(ip_filter.extract_client_ip(h_zone, "[fe80::1%eth0]:8080") == "fe80::1")

-- I-9: Trusted proxies with CIDR /0 trusts all proxies
local trust_all = ip_filter.new({ "10.5.5.5" }, { "0.0.0.0/0" })
local h_trust_all = { ["x-forwarded-for"] = "10.5.5.5" }
assert(trust_all:is_allowed(ip_filter.extract_client_ip(h_trust_all, "203.0.113.199:5432", trust_all)) == true)

-- I-10: is_allowed called with empty or nil IP
assert(filter:is_allowed("") == false)
assert(filter:is_allowed(nil) == false)
assert(filter:is_allowed("not-an-ip") == false)

print("All ip_filter tests passed successfully!")


