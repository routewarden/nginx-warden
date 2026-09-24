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
    }
}

for _, tc in ipairs(test_cases) do
    local candidates = normalizer.extract_candidate_paths(tc.raw_path, tc.path, tc.request_uri)
    for _, exp in ipairs(tc.expected) do
        assert_contains(candidates, exp, tc.name)
    end
end
print("  ✓ extract_candidate_paths passed all test cases")

print("Testing normalizer: extract_query_candidates...")
local query_cands = normalizer.extract_query_candidates("file=%2eenv&tag=test")
assert_contains(query_cands, "file=%2eenv&tag=test", "Raw query")
assert_contains(query_cands, ".env", "Param candidate path unescaped")

local query_key_cands = normalizer.extract_query_candidates("foo=bar&.env=1&file=/images/../.env")
assert_contains(query_key_cands, ".env", "Query key .env extracted")
assert_contains(query_key_cands, "/.env", "Query traversal value /images/../.env normalized to /.env")

print("  ✓ extract_query_candidates passed")

print("All normalizer tests passed successfully!")

