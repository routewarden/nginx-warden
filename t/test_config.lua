-- t/test_config.lua
-- Unit tests verifying default configuration and validations

package.path = "lib/?.lua;lib/?/init.lua;" .. package.path

local routewarden = require("resty.routewarden")
local config = require("resty.routewarden.config")

print("Testing config and init...")

-- Default configuration
local rw_default = routewarden.new()
assert(rw_default.config.enabled == true)
assert(rw_default.config.enable_default_patterns == true)
assert(rw_default.config.enable_default_allow_patterns == true)
assert(rw_default.methods["GET"] == true)
assert(rw_default.config.response.mode == "json")
assert(rw_default.config.response.status_code == 403)

local ok, err = rw_default:validate()
assert(ok == true, "validation should succeed")

-- Custom config
local rw_custom = routewarden.new({
    enabled = true,
    methods = { "GET", "POST", "PUT" },
    check_query = true,
    response = {
        mode = "silentDrop",
        retry_after_seconds = 600,
        status_code = 429
    }
})
assert(rw_custom.methods["GET"] == true)
assert(rw_custom.methods["POST"] == true)
assert(rw_custom.methods["PUT"] == true)
assert(rw_custom.methods["DELETE"] == nil)
assert(rw_custom.config.check_query == true)
assert(rw_custom.config.response.mode == "silentdrop")
assert(rw_custom.config.response.retry_after_seconds == 600)

-- Status code validation
local rw_bad_status = routewarden.new({
    response = { status_code = 99 }
})
local valid, val_err = rw_bad_status:validate()
assert(valid == false, "expected failure for status code < 100")

local rw_high_status = routewarden.new({
    response = { status_code = 600 }
})
local valid_high, val_err_high = rw_high_status:validate()
assert(valid_high == false, "expected failure for status code >= 600")

-- Block and allow patterns configuration verification
local rw_patterns = routewarden.new({
    block_patterns = { "(?i)^/admin/.*$", "(?i)\\.key$" },
    allow_patterns = { "(?i)^/admin/health$", "(?i)^/public/.*$" }
})
local patterns_ok, patterns_err = rw_patterns:validate()
assert(patterns_ok == true, "pattern configuration validation should succeed: " .. tostring(patterns_err))
assert(#rw_patterns.config.block_patterns == 2, "should have 2 custom block_patterns")
assert(#rw_patterns.config.allow_patterns == 2, "should have 2 custom allow_patterns")
assert(#rw_patterns.compiled_block >= 2, "compiled block patterns should be present")
assert(#rw_patterns.compiled_allow >= 2, "compiled allow patterns should be present")

-- ─── config_file tests ───────────────────────────────────────────────────────
local tmp_json_path = "t/tmp_test_routewarden_nginx.json"
local f = io.open(tmp_json_path, "w")
assert(f, "could not write temp json file")
f:write([[
{
  "enableDefaultPatterns": false,
  "enableDefaultAllowPatterns": true,
  "methods": ["GET", "POST"],
  "blockPatterns": [
    "(?i)^/file-probe$"
  ],
  "allowedIps": ["10.0.0.0/8"],
  "response": {
    "mode": "json",
    "statusCode": 404,
    "body": "{\"error\":\"File Blocked\"}"
  }
}
]])
f:close()

-- 1. Load config_file from table
local rw_file = routewarden.new({
    config_file = tmp_json_path
})
assert(rw_file.config.enable_default_patterns == false, "file should set enable_default_patterns")
assert(rw_file.config.enable_default_allow_patterns == true)
assert(#rw_file.config.block_patterns == 1)
assert(rw_file.config.block_patterns[1] == "(?i)^/file-probe$")
assert(#rw_file.config.allowed_ips == 1)
assert(rw_file.config.allowed_ips[1] == "10.0.0.0/8")
assert(rw_file.config.response.mode == "json")
assert(rw_file.config.response.status_code == 404)
assert(rw_file.config.response.body == "{\"error\":\"File Blocked\"}")

-- 2. Load directly via string filepath
local rw_str = routewarden.new(tmp_json_path)
assert(rw_str.config.response.status_code == 404)
assert(#rw_str.config.block_patterns == 1)

-- 3. Inline options override file options
local rw_override = routewarden.new({
    config_file = tmp_json_path,
    mode = "tarpit",
    status_code = 429,
    enable_default_patterns = true
})
assert(rw_override.config.response.mode == "tarpit", "inline mode should override file")
assert(rw_override.config.response.status_code == 429, "inline status_code should override file")
assert(rw_override.config.enable_default_patterns == true, "inline boolean should override file")
-- block_patterns from file should be preserved
assert(#rw_override.config.block_patterns == 1)
assert(rw_override.config.block_patterns[1] == "(?i)^/file-probe$")

os.remove(tmp_json_path)

-- 4. Missing file raises error
local ok_missing, err_missing = pcall(routewarden.new, { config_file = "/nonexistent/path/routewarden.json" })
assert(ok_missing == false, "missing config_file should raise error")
assert(string.find(tostring(err_missing), "cannot open config_file"), "error message should mention cannot open")

-- 5. Malformed JSON raises error
local bad_json_path = "t/tmp_test_bad_json.json"
local bf = io.open(bad_json_path, "w")
bf:write("{ this is not valid json }")
bf:close()
local ok_bad, err_bad = pcall(routewarden.new, { config_file = bad_json_path })
os.remove(bad_json_path)
assert(ok_bad == false, "malformed config_file should raise error")
assert(string.find(tostring(err_bad), "failed to parse JSON"), "error message should mention failed to parse JSON")

-- 6. config_file with all JSON keys present (C-1)
local full_json_path = "t/tmp_test_full_config.json"
local ff = io.open(full_json_path, "w")
ff:write([[
{
  "enabled": true,
  "enableDefaultPatterns": false,
  "enableDefaultAllowPatterns": false,
  "methods": ["GET", "POST", "PUT"],
  "checkQuery": true,
  "checkHeaders": ["X-Forwarded-Uri", "X-Custom-Auth"],
  "checkBody": true,
  "checkBodyPatterns": ["(?i)secret_payload"],
  "blockPatterns": ["(?i)^/admin/.*$"],
  "allowPatterns": ["(?i)^/admin/public$"],
  "allowedIps": ["192.168.1.0/24"],
  "trustedProxies": ["10.0.0.1"],
  "debug": true,
  "securityLog": false,
  "response": {
    "mode": "json",
    "statusCode": 403,
    "body": "{\"blocked\":true}",
    "headers": {
      "X-Custom-Deny": "1"
    },
    "redirectUrl": "/blocked",
    "retryAfterSeconds": 120,
    "gzipBombMb": 5,
    "tarpitDelayMs": 100,
    "tarpitMaxDurationSeconds": 5,
    "captcha": {
      "provider": "turnstile",
      "siteKey": "0x4AAAAAAABcdEFghIjK"
    }
  }
}
]])
ff:close()
local rw_full = routewarden.new({ config_file = full_json_path })
os.remove(full_json_path)
assert(rw_full.config.enabled == true)
assert(rw_full.config.enable_default_patterns == false)
assert(rw_full.config.enable_default_allow_patterns == false)
assert(rw_full.methods["GET"] == true and rw_full.methods["POST"] == true and rw_full.methods["PUT"] == true)
assert(rw_full.config.check_query == true)
assert(#rw_full.config.check_headers == 2)
assert(rw_full.config.check_body == true)
assert(#rw_full.config.check_body_patterns == 1)
assert(#rw_full.config.block_patterns == 1)
assert(#rw_full.config.allow_patterns == 1)
assert(#rw_full.config.allowed_ips == 1)
assert(#rw_full.config.trusted_proxies == 1)
assert(rw_full.config.debug == true)
assert(rw_full.config.security_log == false)
assert(rw_full.config.response.mode == "json")
assert(rw_full.config.response.status_code == 403)
assert(rw_full.config.response.retry_after_seconds == 120)
assert(rw_full.config.response.gzip_bomb_mb == 5)
assert(rw_full.config.response.tarpit_delay_ms == 100)
assert(rw_full.config.response.tarpit_max_duration_seconds == 5)
assert(rw_full.config.response.captcha.provider == "turnstile")

-- 7. config_file with unknown extra keys (C-2)
local extra_json_path = "t/tmp_test_extra_keys.json"
local ef = io.open(extra_json_path, "w")
ef:write([[{"unknownKey": "someValue", "fooBar": 123, "enableDefaultPatterns": false}]])
ef:close()
local rw_extra = routewarden.new({ config_file = extra_json_path })
os.remove(extra_json_path)
assert(rw_extra.config.enable_default_patterns == false)

-- 8. config_file with empty JSON object {} (C-3)
local empty_json_path = "t/tmp_test_empty.json"
local emf = io.open(empty_json_path, "w")
emf:write("{}")
emf:close()
local rw_empty = routewarden.new({ config_file = empty_json_path })
os.remove(empty_json_path)
assert(rw_empty.config.enabled == true)
assert(rw_empty.config.response.status_code == 403)

-- 9. config_file with empty strings in pattern array (C-4)
local empty_str_path = "t/tmp_test_empty_str.json"
local esf = io.open(empty_str_path, "w")
esf:write([[{"blockPatterns": ["", "(?i)^/admin$"]} ]])
esf:close()
local rw_empty_str = routewarden.new({ config_file = empty_str_path })
os.remove(empty_str_path)
assert(#rw_empty_str.config.block_patterns >= 1)

-- 10. config_file with unicode paths (C-5)
local unicode_json_path = "t/tmp_test_unicode.json"
local uf = io.open(unicode_json_path, "w")
uf:write([[{"blockPatterns": ["(?i)^/üñîçødé.*$"]} ]])
uf:close()
local rw_unicode = routewarden.new({ config_file = unicode_json_path })
os.remove(unicode_json_path)
assert(#rw_unicode.config.block_patterns == 1)

-- 11. Empty string config_file is a no-op (C-6)
local rw_empty_cfg = routewarden.new({ config_file = "" })
assert(rw_empty_cfg.config.enabled == true)

-- 12. Validate unknown response mode (C-7)
local rw_unknown_mode = routewarden.new({ response = { mode = "invalidMode123" } })
local ok_unknown, err_unknown = rw_unknown_mode:validate()
assert(ok_unknown == false, "expected failure for invalid response mode")

-- 13. Custom/unknown HTTP method accepted (C-8)
local rw_custom_method = routewarden.new({ methods = { "PROPFIND", "MKCOL" } })
assert(rw_custom_method.methods["PROPFIND"] == true)
assert(rw_custom_method.methods["MKCOL"] == true)

-- 14. Float retry_after_seconds handled safely (C-9)
local rw_float_retry = routewarden.new({ response = { retry_after_seconds = 60.5 } })
assert(rw_float_retry.config.response.retry_after_seconds == 60.5)

-- 15. Inline block_patterns override file blockPatterns (C-10)
local override_patterns_path = "t/tmp_test_override_pats.json"
local opf = io.open(override_patterns_path, "w")
opf:write([[{"blockPatterns": ["(?i)^/from-file$"]} ]])
opf:close()
local rw_pats_override = routewarden.new({
    config_file = override_patterns_path,
    block_patterns = { "(?i)^/from-inline$" }
})
os.remove(override_patterns_path)
assert(#rw_pats_override.config.block_patterns == 1)
assert(rw_pats_override.config.block_patterns[1] == "(?i)^/from-inline$")

print("All config tests passed successfully!")
