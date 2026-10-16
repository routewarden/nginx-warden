-- t/test_normalizer.lua
-- Unit tests verifying multi-layer anti-evasion path normalization

package.path = "lib/?.lua;lib/?/init.lua;" .. package.path

local normalizer = require("resty.routewarden.normalizer")

local function assert_contains(candidates, expected, case_name)
    local found = false
    for _, c in ipairs(candidates) do
        if c == expected then
            found = true
            break
        end
    end
    if not found then
        error(string.format("FAILED [%s]: expected candidate %q in %s", case_name, expected, table.concat(candidates, ", ")))
    end
end

print("Testing normalizer: clean_path...")
assert(normalizer.clean_path("/a/b/c") == "/a/b/c")
assert(normalizer.clean_path("/a/../b") == "/b")
assert(normalizer.clean_path("/a/./b") == "/a/b")
assert(normalizer.clean_path("///a///b///") == "/a/b")
assert(normalizer.clean_path("/") == "/")
print("  ✓ clean_path passed")

print("Testing normalizer: extract_candidate_paths...")

local test_cases = {
    {
        name = "Standard path",
        path = "/api/v1/users",
        expected = { "/api/v1/users" }
    },
    {
        name = "Single URL encoded dot (%2eenv)",
        path = "/%2eenv",
        expected = { "/.env" }
    },
    {
        name = "Double URL encoded dot (%252eenv)",
        path = "/%252eenv",
        expected = { "/.env" }
    },
    {
        name = "Double URL encoded path traversal (%252e%252e)",
        path = "/static/%252e%252e/.env",
        expected = { "/.env" }
    },
    {
        name = "RawPath difference provided",
        raw_path = "/raw/%2eenv",
        path = "/raw/.env",
        expected = { "/raw/.env" }
    },
    {
        name = "Semicolon matrix parameter prefix (/;.env)",
        path = "/;.env",
        expected = { "/.env" }
    },
    {
        name = "Semicolon matrix parameter in segment (/app;jsessionid=123/.env)",
        path = "/app;jsessionid=123/.env",
        expected = { "/app/.env" }
    },
    {
        name = "Semicolon embedded within segment (/api;.env/config.json)",
        path = "/api;.env/config.json",
        expected = { "/api/.env/config.json" }
    },
    {
        name = "Windows backslash separator (\\..\\.env)",
        path = "/static\\..\\.env",
        expected = { "/.env" }
    },
    {
        name = "Direct backslash path (/\\.env)",
        path = "/\\.env",
        expected = { "/.env" }
    },
    {
        name = "Null byte in path",
        path = "/.env\0.png",
        expected = { "/.env.png" }
    },
    {
        name = "RequestURI query string stripped for candidate path",
        path = "/search",
        request_uri = "/search?file=.env",
        expected = { "/search" }
    },
    {
        name = "Dot slash canonical path (/./.env)",
        path = "/./.env",
        expected = { "/.env" }
    },
    {
        name = "Multi-layer encoded RequestURI when path differs",
        path = "/app",
        request_uri = "/app/%252e%252e/.env?test=1",
        expected = { "/.env" }
    },
    {
        name = "Triple URL encoded dot (%25252eenv)",
        path = "/%25252eenv",
        expected = { "/.env" }
    },
    {
        name = "Mixed slashes and backslashes (/app/..\\..//.env)",
        path = "/app/..\\..//.env",
        expected = { "/.env" }
    },
    {
        name = "50+ consecutive dot-dot traversals",
        path = "/" .. string.rep("../", 50) .. ".env",
        expected = { "/.env" }
    },
    {
        name = "Only dots /../../../.",
        path = "/../../../.",
        expected = { "/" }
    },
    {
        name = "Multiple matrix parameters in segment",
        path = "/service;p1=1;p2=2/.env",
        expected = { "/service/.env" }
    }
}

for _, tc in ipairs(test_cases) do
    local candidates = normalizer.extract_candidate_paths(tc.raw_path, tc.path, tc.request_uri)
    for _, exp in ipairs(tc.expected) do
        assert_contains(candidates, exp, tc.name)
    end
end
print("  ✓ extract_candidate_paths passed all test cases")

-- N-3: Very long path (>8192 chars) should not error or overflow
local very_long_path = "/" .. string.rep("abc/", 2000) .. "resource"
local long_cands = normalizer.extract_candidate_paths(nil, very_long_path, nil)
assert(#long_cands >= 1)
print("  ✓ very long path (>8KB) normalized safely")

-- N-6: Embedded null byte in segment
local null_byte_path = "/folder/item\0secret/.env"
local null_cands = normalizer.extract_candidate_paths(nil, null_byte_path, nil)
assert(#null_cands >= 1)
print("  ✓ embedded null byte in path handled")

-- N-9 & N-10: Boundary arguments for extract_candidate_paths
local empty_cands = normalizer.extract_candidate_paths("", "", "")
assert(#empty_cands >= 1 and empty_cands[1] == "/")
local nil_cands = normalizer.extract_candidate_paths(nil, nil, nil)
assert(#nil_cands >= 1 and nil_cands[1] == "/")
print("  ✓ empty and nil arguments handled cleanly")

print("Testing normalizer: extract_query_candidates...")
local query_cands = normalizer.extract_query_candidates("file=%2eenv&tag=test")
assert_contains(query_cands, "file=%2eenv&tag=test", "Raw query")
assert_contains(query_cands, ".env", "Param candidate path unescaped")

local query_key_cands = normalizer.extract_query_candidates("foo=bar&.env=1&file=/images/../.env")
assert_contains(query_key_cands, ".env", "Query key .env extracted")
assert_contains(query_key_cands, "/.env", "Query traversal value /images/../.env normalized to /.env")

-- N-8: Query string with encoded ampersand
local query_encoded_amp = normalizer.extract_query_candidates("search=hello%26file=.env")
assert_contains(query_encoded_amp, ".env", "Encoded ampersand param value extracted")

-- Query candidates with empty or nil input
local q_empty = normalizer.extract_query_candidates("")
assert(#q_empty == 0)
local q_nil = normalizer.extract_query_candidates(nil)
assert(#q_nil == 0)

print("  ✓ extract_query_candidates passed")

print("All normalizer tests passed successfully!")


