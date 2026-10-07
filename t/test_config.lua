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

print("All config tests passed successfully!")
