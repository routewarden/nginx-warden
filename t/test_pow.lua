-- t/test_pow.lua
-- Unit tests for Proof-of-Work (powChallenge) generation, verification, and end-to-end bypass

package.path = "./lib/?.lua;./lib/?/init.lua;" .. package.path

local pow = require("resty.routewarden.pow")
local rw_init = require("resty.routewarden")

print("Testing Proof-of-Work (powChallenge) module...")

-- 1. count_leading_zero_bits tests
assert(pow.count_leading_zero_bits(string.char(0x00, 0x00)) == 16, "leading zero bits for 0x0000 must be 16")
assert(pow.count_leading_zero_bits(string.char(0x00, 0x80)) == 8, "leading zero bits for 0x0080 must be 8")
assert(pow.count_leading_zero_bits(string.char(0x00, 0x40)) == 9, "leading zero bits for 0x0040 must be 9")
assert(pow.count_leading_zero_bits(string.char(0x80)) == 0, "leading zero bits for 0x80 must be 0")
assert(pow.count_leading_zero_bits(string.char(0x40)) == 1, "leading zero bits for 0x40 must be 1")
assert(pow.count_leading_zero_bits(string.char(0x01)) == 7, "leading zero bits for 0x01 must be 7")
assert(pow.count_leading_zero_bits("") == 0, "empty string must have 0 leading zero bits")
print("  ✓ count_leading_zero_bits passed")

-- 2. normalize_ip tests
assert(pow.normalize_ip("192.168.1.1") == "192.168.1.1", "plain IPv4")
assert(pow.normalize_ip("192.168.1.1:8080") == "192.168.1.1", "IPv4 with port")
assert(pow.normalize_ip("[2001:db8::1]") == "2001:db8::1", "IPv6 in brackets")
assert(pow.normalize_ip("[2001:db8::1]:443") == "2001:db8::1", "IPv6 with port")
assert(pow.normalize_ip("fe80::1%eth0") == "fe80::1", "IPv6 zone")
print("  ✓ normalize_ip passed")

-- 3. Challenge generation, solving, and stateless verification
local client_ip = "198.51.100.44"
local secret = "lua-pow-test-secret"
local difficulty = 10 -- Fast for test suite
local now = os.time()

local challenge = pow.generate_challenge(client_ip, secret, difficulty, now)
assert(challenge and #challenge > 0, "challenge must not be empty")

local parts = {}
for p in string.gmatch(challenge, "([^%.]+)") do
    parts[#parts + 1] = p
end
assert(#parts == 4, "challenge must contain 4 parts, got " .. #parts)

local nonce = pow.solve_pow(challenge, difficulty)
local solution = challenge .. "." .. tostring(nonce)

-- Valid verification
local ok, err = pow.verify_solution(client_ip, secret, solution, 300, now + 10)
assert(ok == true, "valid solution must verify, got err: " .. tostring(err))

-- IP mismatch
local bad_ip_ok, bad_ip_err = pow.verify_solution("203.0.113.1", secret, solution, 300, now + 10)
assert(bad_ip_ok == false, "IP mismatch must fail verification")
assert(bad_ip_err == "invalid_pow_signature", "reason must be invalid_pow_signature")

-- Secret mismatch
local bad_sec_ok, _ = pow.verify_solution(client_ip, "wrong-secret", solution, 300, now + 10)
assert(bad_sec_ok == false, "secret mismatch must fail verification")

-- Expired solution
local exp_ok, exp_err = pow.verify_solution(client_ip, secret, solution, 300, now + 305)
assert(exp_ok == false, "expired solution must fail verification")
assert(exp_err == "expired_pow", "reason must be expired_pow")

-- Bad nonce (insufficient work)
local bad_nonce_solution = challenge .. "." .. tostring(nonce + 1)
local work_ok, _ = pow.verify_solution(client_ip, secret, bad_nonce_solution, 300, now + 10)
assert(work_ok == false, "bad nonce must fail work verification")

-- Malformed format
local malformed_ok, _ = pow.verify_solution(client_ip, secret, "invalid.format", 300, now + 10)
assert(malformed_ok == false, "malformed format must fail")
print("  ✓ challenge generation and verification passed")

-- 4. HTML generation
local html = pow.generate_html(challenge, difficulty, 300)
assert(string.find(html, "<!DOCTYPE html>"), "html doctype")
assert(string.find(html, challenge, 1, true), "contains challenge")
assert(string.find(html, "__rw_pow"), "contains cookie name")
assert(string.find(html, "crypto.subtle"), "contains Web Crypto solver")
print("  ✓ generate_html passed")

-- 5. End-to-end RouteWarden inspect integration
local warden = rw_init.new({
    enabled = true,
    block_user_agents = { "^BadBot.*" },
    block_patterns = { "^/admin.*" },
    honeypot_trap_paths = { "/spider_trap" },
    response = {
        mode = "powChallenge",
        pow_difficulty = difficulty,
        pow_secret = secret,
        pow_timeout_seconds = 300
    }
})

-- Request 1: BadBot blocked without PoW
local req1 = {
    method = "GET",
    uri = "/index.html",
    raw_uri = "/index.html",
    remote_addr = client_ip,
    client_ip = client_ip,
    headers = {
        ["user-agent"] = "BadBot/1.0"
    }
}
local allowed1, info1 = warden:inspect(req1)
assert(allowed1 == false, "BadBot without PoW must be blocked")
assert(info1.reason == "user_agent_blocked", "reason must be user_agent_blocked")

-- Request 2: BadBot with valid __rw_pow cookie -> ALLOWED
local req2 = {
    method = "GET",
    uri = "/index.html",
    raw_uri = "/index.html",
    remote_addr = client_ip,
    client_ip = client_ip,
    headers = {
        ["user-agent"] = "BadBot/1.0",
        ["cookie"] = "__rw_pow=" .. solution
    }
}
local allowed2, info2 = warden:inspect(req2)
assert(allowed2 == true, "BadBot with valid PoW cookie must be allowed")

-- Request 3: Protected /admin path with X-RW-PoW header -> ALLOWED
local req3 = {
    method = "GET",
    uri = "/admin/settings",
    raw_uri = "/admin/settings",
    remote_addr = client_ip,
    client_ip = client_ip,
    headers = {
        ["user-agent"] = "BadBot/1.0",
        ["x-rw-pow"] = solution
    }
}
local allowed3, info3 = warden:inspect(req3)
assert(allowed3 == true, "/admin with valid PoW header must be allowed")
assert(info3.pow_verified == true, "pow_verified must be true")

-- Request 4: Honeypot spider trap MUST NOT be bypassed by PoW
local req4 = {
    method = "GET",
    uri = "/spider_trap/crawl",
    raw_uri = "/spider_trap/crawl",
    remote_addr = client_ip,
    client_ip = client_ip,
    headers = {
        ["user-agent"] = "BadBot/1.0",
        ["cookie"] = "__rw_pow=" .. solution
    }
}
local allowed4, info4 = warden:inspect(req4)
assert(allowed4 == false, "honeypot trap must block despite valid PoW")
assert(info4.reason == "honeypot_trap_triggered", "reason must be honeypot_trap_triggered")

print("  ✓ RouteWarden end-to-end PoW bypass and honeypot immutability verified")
print("All Proof-of-Work tests passed successfully!")
