-- lib/resty/routewarden/robots_honeypot.lua
-- Deterministic edge robots.txt dynamic honeypot token derivation and injection

local _M = {
    _VERSION = "1.8.0",
    DEFAULT_SECRET = "routewarden-default-robots-trap-seed"
}

-- Bitwise operations supporting LuaJIT bit library, native Lua 5.3+ operators, and math fallback
local band, bor, bxor, bnot, rshift, rotr

local has_bit, bit = pcall(require, "bit")
if has_bit and bit and bit.band then
    band = bit.band
    bor = bit.bor
    bxor = bit.bxor
    bnot = bit.bnot
    rshift = bit.rshift
    rotr = bit.ror
else
    local ok, ops = pcall(load, [[
        return {
            band = function(a, b) return a & b end,
            bor = function(a, b) return a | b end,
            bxor = function(a, b) return a ~ b end,
            bnot = function(a) return (~a) & 0xffffffff end,
            rshift = function(a, n) return (a & 0xffffffff) >> n end,
            rotr = function(a, n)
                a = a & 0xffffffff
                return ((a >> n) | (a << (32 - n))) & 0xffffffff
            end
        }
    ]])
    if ok and type(ops) == "function" then
        local o = ops()
        band = o.band
        bor = o.bor
        bxor = o.bxor
        bnot = o.bnot
        rshift = o.rshift
        rotr = o.rotr
    else
        local function to_bits(n)
            local t = {}
            for i = 1, 32 do
                t[i] = n % 2
                n = math.floor(n / 2)
            end
            return t
        end
        local function from_bits(t)
            local n = 0
            local p = 1
            for i = 1, 32 do
                if t[i] == 1 then n = n + p end
                p = p * 2
            end
            return n
        end
        band = function(a, b)
            local ta, tb, tr = to_bits(a), to_bits(b), {}
            for i = 1, 32 do tr[i] = (ta[i] == 1 and tb[i] == 1) and 1 or 0 end
            return from_bits(tr)
        end
        bor = function(a, b)
            local ta, tb, tr = to_bits(a), to_bits(b), {}
            for i = 1, 32 do tr[i] = (ta[i] == 1 or tb[i] == 1) and 1 or 0 end
            return from_bits(tr)
        end
        bxor = function(a, b)
            local ta, tb, tr = to_bits(a), to_bits(b), {}
            for i = 1, 32 do tr[i] = (ta[i] ~= tb[i]) and 1 or 0 end
            return from_bits(tr)
        end
        bnot = function(a)
            local ta, tr = to_bits(a), {}
            for i = 1, 32 do tr[i] = (ta[i] == 1) and 0 or 1 end
            return from_bits(tr)
        end
        rshift = function(a, n)
            return math.floor((a % 4294967296) / (2 ^ n))
        end
        rotr = function(a, n)
            a = a % 4294967296
            local low = a % (2 ^ n)
            return math.floor(a / (2 ^ n)) + low * (2 ^ (32 - n))
        end
    end
end

local K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
}

local function add32(...)
    local sum = 0
    local args = {...}
    for i = 1, #args do
        sum = (sum + (args[i] or 0)) % 4294967296
    end
    return sum
end

local function sha256_raw(msg)
    local h0 = 0x6a09e667
    local h1 = 0xbb67ae85
    local h2 = 0x3c6ef372
    local h3 = 0xa54ff53a
    local h4 = 0x510e527f
    local h5 = 0x9b05688c
    local h6 = 0x1f83d9ab
    local h7 = 0x5be0cd19

    local msg_len = #msg
    local bit_len = msg_len * 8

    local pad_len = 64 - ((msg_len + 9) % 64)
    if pad_len == 64 then pad_len = 0 end

    local padded = msg .. string.char(0x80) .. string.rep(string.char(0), pad_len)
    local len_bytes = string.char(
        0, 0, 0, 0,
        band(rshift(bit_len, 24), 0xff),
        band(rshift(bit_len, 16), 0xff),
        band(rshift(bit_len, 8), 0xff),
        band(bit_len, 0xff)
    )
    padded = padded .. len_bytes

    local w = {}
    for block_start = 1, #padded, 64 do
        for t = 0, 15 do
            local idx = block_start + t * 4
            local b1, b2, b3, b4 = string.byte(padded, idx, idx + 3)
            w[t + 1] = bor(bor(bor(b1 * 16777216, b2 * 65536), b3 * 256), b4)
        end

        for t = 16, 63 do
            local s0 = bxor(bxor(rotr(w[t - 15 + 1], 7), rotr(w[t - 15 + 1], 18)), rshift(w[t - 15 + 1], 3))
            local s1 = bxor(bxor(rotr(w[t - 2 + 1], 17), rotr(w[t - 2 + 1], 19)), rshift(w[t - 2 + 1], 10))
            w[t + 1] = add32(w[t - 16 + 1], s0, w[t - 7 + 1], s1)
        end

        local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        for t = 0, 63 do
            local S1 = bxor(bxor(rotr(e, 6), rotr(e, 11)), rotr(e, 25))
            local ch = bxor(band(e, f), band(bnot(e), g))
            local temp1 = add32(h, S1, ch, K[t + 1], w[t + 1])
            local S0 = bxor(bxor(rotr(a, 2), rotr(a, 13)), rotr(a, 22))
            local maj = bxor(bxor(band(a, b), band(a, c)), band(b, c))
            local temp2 = add32(S0, maj)

            h = g
            g = f
            f = e
            e = add32(d, temp1)
            d = c
            c = b
            b = a
            a = add32(temp1, temp2)
        end

        h0 = add32(h0, a)
        h1 = add32(h1, b)
        h2 = add32(h2, c)
        h3 = add32(h3, d)
        h4 = add32(h4, e)
        h5 = add32(h5, f)
        h6 = add32(h6, g)
        h7 = add32(h7, h)
    end

    local function word_to_bytes(word)
        return string.char(
            band(rshift(word, 24), 0xff),
            band(rshift(word, 16), 0xff),
            band(rshift(word, 8), 0xff),
            band(word, 0xff)
        )
    end

    return word_to_bytes(h0) .. word_to_bytes(h1) .. word_to_bytes(h2) .. word_to_bytes(h3) ..
           word_to_bytes(h4) .. word_to_bytes(h5) .. word_to_bytes(h6) .. word_to_bytes(h7)
end

local function hmac_sha256(key, data)
    local block_size = 64
    if #key > block_size then
        key = sha256_raw(key)
    end
    if #key < block_size then
        key = key .. string.rep(string.char(0), block_size - #key)
    end

    local o_key_pad = {}
    local i_key_pad = {}
    for i = 1, block_size do
        local b = string.byte(key, i)
        o_key_pad[i] = string.char(bxor(b, 0x5c))
        i_key_pad[i] = string.char(bxor(b, 0x36))
    end
    local o_pad = table.concat(o_key_pad)
    local i_pad = table.concat(i_key_pad)

    local inner = sha256_raw(i_pad .. data)
    local outer = sha256_raw(o_pad .. inner)

    local hex_tbl = {}
    for i = 1, #outer do
        hex_tbl[#hex_tbl + 1] = string.format("%02x", string.byte(outer, i))
    end
    return table.concat(hex_tbl)
end

-- Generates a deterministic 12-hex-character token for a given timestamp.
function _M.get_robots_honeypot_token(secret, ts)
    local sec = secret
    if not sec or string.match(sec, "^%s*$") then
        sec = _M.DEFAULT_SECRET
    end
    local t = ts or os.time()
    local date_str = os.date("!%Y-%m-%d", t)
    local full_hex = hmac_sha256(sec, date_str)
    if #full_hex >= 12 then
        return string.sub(full_hex, 1, 12)
    end
    return full_hex
end

-- Returns the active trap path and today/yesterday prefixes for rollover tolerance.
function _M.get_active_robots_honeypot_traps(secret, ts)
    local t = ts or os.time()
    local today_token = _M.get_robots_honeypot_token(secret, t)
    local yesterday_token = _M.get_robots_honeypot_token(secret, t - 86400)

    local active_trap = "/_rw_trap_" .. today_token .. "/"
    local valid_prefixes = {
        "/_rw_trap_" .. today_token,
        "/_rw_trap_" .. yesterday_token
    }
    return active_trap, valid_prefixes
end

-- Checks whether a given path targets /robots.txt.
function _M.is_robots_txt_path(p)
    if not p then return false end
    local clean = string.lower(string.match(p, "^%s*(.-)%s*$"))
    clean = string.gsub(clean, "/+$", "")
    return clean == "/robots.txt"
end

-- Injects dynamic Disallow honeypot trap into existing robots.txt content.
function _M.inject_robots_txt_trap(body, active_trap_path)
    local content = body or ""
    local sb = { content }
    if #content > 0 and string.sub(content, -1) ~= "\n" then
        sb[#sb + 1] = "\n"
    end
    sb[#sb + 1] = "\n# RouteWarden Dynamic Honeypot Trap\n"
    sb[#sb + 1] = "User-agent: *\n"
    sb[#sb + 1] = "Disallow: "
    sb[#sb + 1] = active_trap_path
    sb[#sb + 1] = "\n"
    return table.concat(sb)
end

return _M
