-- lib/resty/routewarden/pow.lua
-- Proof-of-Work (powChallenge) generation, verification, and solver page

local _M = {
    _VERSION = "1.8.0",
    DEFAULT_DIFFICULTY = 16,
    DEFAULT_TIMEOUT_SECONDS = 300,
    DEFAULT_SECRET = "routewarden-pow-challenge-seed-secret"
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
    if ngx and ngx.hmac_sha256 and ngx.encode_hex then
        return ngx.encode_hex(ngx.hmac_sha256(key, data))
    end

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

-- Counts leading zero bits in raw binary string
function _M.count_leading_zero_bits(raw_bytes)
    if not raw_bytes or #raw_bytes == 0 then
        return 0
    end
    local zeros = 0
    for i = 1, #raw_bytes do
        local b = string.byte(raw_bytes, i)
        if b == 0 then
            zeros = zeros + 8
        else
            local z = 0
            if b >= 128 then z = 0
            elseif b >= 64 then z = 1
            elseif b >= 32 then z = 2
            elseif b >= 16 then z = 3
            elseif b >= 8 then z = 4
            elseif b >= 4 then z = 5
            elseif b >= 2 then z = 6
            elseif b >= 1 then z = 7
            else z = 8 end
            zeros = zeros + z
            break
        end
    end
    return zeros
end

-- Normalizes client IP by stripping port, brackets, and zone identifiers
function _M.normalize_ip(ip)
    if not ip then return "" end
    local s = string.match(ip, "^%s*(.-)%s*$")
    -- 1. [IPv6]:port -> IPv6
    local v6_port = string.match(s, "^%[([%x%:%a%.]+)%]:%d+$")
    if v6_port then
        s = v6_port
    else
        -- [IPv6] -> IPv6
        local v6 = string.match(s, "^%[([%x%:%a%.]+)%]$")
        if v6 then
            s = v6
        else
            -- IPv4:port -> IPv4
            local v4 = string.match(s, "^([%d%.]+):%d+$")
            if v4 then
                s = v4
            end
        end
    end
    -- Strip IPv6 zone identifier (%eth0)
    local idx = string.find(s, "%%")
    if idx then
        s = string.sub(s, 1, idx - 1)
    end
    return s
end

-- Generates signed challenge token: <timestamp>.<difficulty>.<salt>.<sig>
function _M.generate_challenge(client_ip, secret, difficulty, ts)
    local diff = difficulty or _M.DEFAULT_DIFFICULTY
    local sec = (secret and secret ~= "") and secret or _M.DEFAULT_SECRET
    local t = ts or os.time()
    local norm_ip = _M.normalize_ip(client_ip)

    local salt_bytes = {}
    for i = 1, 8 do
        salt_bytes[i] = string.format("%02x", math.random(0, 255))
    end
    local salt = table.concat(salt_bytes)

    local ts_str = tostring(t)
    local diff_str = tostring(diff)
    local payload = norm_ip .. ":" .. ts_str .. ":" .. diff_str .. ":" .. salt
    local sig = hmac_sha256(sec, payload)

    return ts_str .. "." .. diff_str .. "." .. salt .. "." .. sig
end

-- Verifies solved challenge: <timestamp>.<difficulty>.<salt>.<sig>.<nonce>
function _M.verify_solution(client_ip, secret, solution, timeout_seconds, ts)
    if not solution or solution == "" then
        return false, "invalid_pow_format"
    end
    local timeout = timeout_seconds or _M.DEFAULT_TIMEOUT_SECONDS
    local sec = (secret and secret ~= "") and secret or _M.DEFAULT_SECRET
    local now = ts or os.time()
    local norm_ip = _M.normalize_ip(client_ip)

    local parts = {}
    for part in string.gmatch(solution, "([^%.]+)") do
        parts[#parts + 1] = part
    end
    if #parts ~= 5 then
        return false, "invalid_pow_format"
    end

    local ts_str, diff_str, salt, sig, nonce_str = parts[1], parts[2], parts[3], parts[4], parts[5]
    local token_ts = tonumber(ts_str)
    if not token_ts then
        return false, "invalid_pow_timestamp"
    end

    local diff = tonumber(diff_str)
    if not diff or diff <= 0 or diff > 64 then
        return false, "invalid_pow_difficulty"
    end

    if not tonumber(nonce_str) then
        return false, "invalid_pow_nonce"
    end

    -- 1. Expiry check
    local elapsed = now - token_ts
    if elapsed < -10 or elapsed > timeout then
        return false, "expired_pow"
    end

    -- 2. HMAC signature check
    local payload = norm_ip .. ":" .. ts_str .. ":" .. diff_str .. ":" .. salt
    local expected_sig = hmac_sha256(sec, payload)
    if sig ~= expected_sig then
        return false, "invalid_pow_signature"
    end

    -- 3. Hashcash computation check: SHA-256(challenge + ":" + nonce) has >= difficulty leading zero bits
    local challenge = ts_str .. "." .. diff_str .. "." .. salt .. "." .. sig
    local check_payload = challenge .. ":" .. nonce_str
    local hash = sha256_raw(check_payload)
    local zeros = _M.count_leading_zero_bits(hash)

    if zeros < diff then
        return false, "insufficient_pow_work"
    end

    return true, ""
end

-- Solves challenge finding nonce with required leading zero bits
function _M.solve_pow(challenge, difficulty)
    local nonce = 0
    while true do
        local payload = challenge .. ":" .. tostring(nonce)
        local hash = sha256_raw(payload)
        if _M.count_leading_zero_bits(hash) >= difficulty then
            return nonce
        end
        nonce = nonce + 1
    end
end

-- Extracts PoW token from X-RW-PoW header or __rw_pow cookie
function _M.extract_pow_token(headers)
    if headers then
        if headers["x-rw-pow"] and headers["x-rw-pow"] ~= "" then
            return headers["x-rw-pow"]
        end
        if headers["cookie"] then
            local cookie_val = string.match(headers["cookie"], "__rw_pow=([^;%s]+)")
            if cookie_val and cookie_val ~= "" then
                return cookie_val
            end
        end
    end
    if ngx and ngx.var then
        if ngx.var.http_x_rw_pow and ngx.var.http_x_rw_pow ~= "" then
            return ngx.var.http_x_rw_pow
        end
        if ngx.var.cookie___rw_pow and ngx.var.cookie___rw_pow ~= "" then
            return ngx.var.cookie___rw_pow
        end
    end
    return nil
end

-- Generates inline HTML solver page
function _M.generate_html(challenge, difficulty, timeout_seconds)
    local diff = difficulty or _M.DEFAULT_DIFFICULTY
    local timeout = timeout_seconds or _M.DEFAULT_TIMEOUT_SECONDS

    return [[<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Verification &middot; RouteWarden</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(17, 24, 39, 0.85);
      --border: rgba(55, 65, 81, 0.6);
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: #3b82f6;
      --accent-glow: rgba(59, 130, 246, 0.35);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 1.5rem;
    }
    .card {
      background: var(--card-bg);
      backdrop-filter: blur(12px);
      border: 1px solid var(--border);
      border-radius: 1rem;
      padding: 2.25rem;
      max-width: 440px;
      width: 100%;
      text-align: center;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
    }
    .icon {
      width: 52px;
      height: 52px;
      margin: 0 auto 1.25rem;
      color: var(--accent);
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 50%;
      background: var(--accent-glow);
    }
    .icon svg {
      width: 28px;
      height: 28px;
      animation: spin 3s linear infinite;
    }
    @keyframes spin {
      100% { transform: rotate(360deg); }
    }
    h1 {
      font-size: 1.35rem;
      font-weight: 600;
      margin-bottom: 0.5rem;
    }
    p {
      color: var(--text-muted);
      font-size: 0.9rem;
      line-height: 1.5;
      margin-bottom: 1.5rem;
    }
    .progress-bar {
      width: 100%;
      height: 6px;
      background: rgba(55, 65, 81, 0.8);
      border-radius: 9999px;
      overflow: hidden;
      margin-bottom: 1rem;
      position: relative;
    }
    .progress-fill {
      height: 100%;
      width: 30%;
      background: linear-gradient(90deg, #3b82f6, #60a5fa);
      border-radius: 9999px;
      animation: indeterminate 1.5s infinite ease-in-out;
    }
    @keyframes indeterminate {
      0% { transform: translateX(-100%); width: 30%; }
      50% { width: 60%; }
      100% { transform: translateX(350%); width: 30%; }
    }
    .status {
      font-size: 0.8rem;
      color: var(--text-muted);
      font-mono: monospace;
    }
    .footer {
      margin-top: 1.5rem;
      font-size: 0.75rem;
      color: #6b7280;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">
      <svg fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
      </svg>
    </div>
    <h1>Checking your browser</h1>
    <p>Please wait a moment while we verify your connection security before proceeding.</p>
    <div class="progress-bar">
      <div class="progress-fill"></div>
    </div>
    <div id="status" class="status">Solving cryptographic challenge...</div>
    <div class="footer">Protected by RouteWarden &middot; Proof-of-Work Verification</div>
  </div>

  <script>
    (function() {
      const challenge = "]] .. challenge .. [[";
      const difficulty = ]] .. tostring(diff) .. [[;
      const timeout = ]] .. tostring(timeout) .. [[;

      function countLeadingZeroBits(buf) {
        const bytes = new Uint8Array(buf);
        let zeros = 0;
        for (let i = 0; i < bytes.length; i++) {
          const b = bytes[i];
          if (b === 0) {
            zeros += 8;
          } else {
            let z = 0;
            if (b >= 128) z = 0;
            else if (b >= 64) z = 1;
            else if (b >= 32) z = 2;
            else if (b >= 16) z = 3;
            else if (b >= 8) z = 4;
            else if (b >= 4) z = 5;
            else if (b >= 2) z = 6;
            else if (b >= 1) z = 7;
            else z = 8;
            zeros += z;
            break;
          }
        }
        return zeros;
      }

      async function solve() {
        const encoder = new TextEncoder();
        let nonce = 0;
        const batchSize = 2500;

        while (true) {
          const promises = [];
          for (let i = 0; i < batchSize; i++) {
            const currentNonce = nonce + i;
            const payload = challenge + ":" + currentNonce;
            const data = encoder.encode(payload);
            promises.push(
              crypto.subtle.digest("SHA-256", data).then(hash => ({
                nonce: currentNonce,
                zeros: countLeadingZeroBits(hash)
              }))
            );
          }

          const results = await Promise.all(promises);
          for (let res of results) {
            if (res.zeros >= difficulty) {
              const solution = challenge + "." + res.nonce;
              document.cookie = "__rw_pow=" + solution + "; Path=/; SameSite=Lax; Max-Age=" + timeout;
              document.getElementById("status").innerText = "Verification complete! Redirecting...";
              window.location.reload();
              return;
            }
          }
          nonce += batchSize;
          await new Promise(r => setTimeout(r, 0));
        }
      }

      if (window.crypto && window.crypto.subtle) {
        solve().catch(function(err) {
          document.getElementById("status").innerText = "Verification error. Please refresh.";
        });
      } else {
        document.getElementById("status").innerText = "Browser does not support Web Crypto. Please upgrade.";
      }
    })();
  </script>
</body>
</html>]]
end

return _M
