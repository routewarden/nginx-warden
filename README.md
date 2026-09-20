<div align="center">
  <img src="assets/icon.svg" alt="RouteWarden Logo" width="140" height="140" />
  <h1>RouteWarden for NGINX & OpenResty</h1>
  <p>A high-performance Lua security middleware for NGINX & OpenResty that blocks scanner probes for sensitive files (.env, .git, database dumps, cloud credentials) and neutralizes path-evasion tricks before requests hit your backend.</p>
</div>

<p align="center">
  <a href="https://github.com/routewarden/nginx-warden/actions/workflows/ci.yml"><img src="https://github.com/routewarden/nginx-warden/actions/workflows/ci.yml/badge.svg" alt="CI Status" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
  <a href="https://routewarden.github.io/docs/"><img src="https://img.shields.io/badge/Docs-Wiki-6366f1.svg" alt="Documentation Site" /></a>
</p>

---

- **Live Playground**: [Try RouteWarden in your browser](https://routewarden.github.io/docs/?playground=open)
- **Documentation & Guides**: [https://routewarden.github.io/docs/](https://routewarden.github.io/docs/)
- **Example Configurations**: [`examples/`](examples/)
- **Live Multi-Port Testing Suite**: [`samples/`](samples/)

---

## Why RouteWarden?

Web servers constantly receive automated requests searching for exposed secrets, such as `.env` files, `.git` directories, database backups, and private keys. Attackers often hide these probes using multi-layer URL encoding (`%252e%252e`), Windows backslashes (`\`), semicolon matrix parameters (`/;`), or null bytes to bypass basic path filters.

RouteWarden sits directly inside NGINX / OpenResty's `access_by_lua` phase to catch these requests early. It normalizes and decodes candidate paths, checks them against known sensitive patterns and your custom rules, and responds immediately with deceptive or defensive responses (such as honeypots, rate-limit challenges, tarpits, gzip bombs, or captchas) before your upstream application ever sees the request.

---

## Features

- 🛡️ **Zero Upstream Overhead**: Filters traffic in NGINX memory before proxying to your backend.
- 🧹 **Anti-Evasion Engine**: Neutralizes double-encoding (`%252e%252e`), Windows backslashes (`\`), semicolon matrix parameters (`/;`), null bytes, and path traversal tricks.
- 🎯 **13 Response Modes**:
  - `json` (default 403 JSON payload)
  - `text` (custom plaintext response)
  - `html` (custom HTML response)
  - `captcha` (Cloudflare Turnstile, hCaptcha, reCAPTCHA, custom)
  - `redirect` (configurable redirect URL & status code)
  - `silentDrop` (immediate TCP socket termination via HTTP 444 / close)
  - `gzipBomb` (highly compressible zero-byte streams to exhaust scanner memory)
  - `tarpit` (slow trickling byte response to tie up attacker connection pools)
  - `fakeSuccess` / `decoy` (realistic honeypot responses for `.env`, Spring actuator, `.git/HEAD`, `phpinfo`, WordPress)
  - `rateLimitChallenge` (HTTP 429 with `Retry-After` header)
  - `proxy` (internal honeypot backend forwarding)
  - `infiniteStream` (cyclic garbage data stream)
  - `xml` (structured XML error response)
- 🌐 **IP & CIDR Whitelisting**: Exact IPv4/IPv6 and subnet exemptions (`10.0.0.0/8`, `2001:db8::/32`) supporting `X-Forwarded-For` and `X-Real-IP`.
- 🔎 **Query Parameter Inspection**: Optional `check_query` mode inspecting unescaped parameters.
- 📊 **CrowdSec-Compatible Logging**: Generates standard JSON security logs for SIEM and CrowdSec parsers.

---

## Installation

### Option 1: OpenResty / Docker

Add RouteWarden to your OpenResty container:

```dockerfile
FROM openresty/openresty:alpine

# Copy RouteWarden into OpenResty Lua library search path
COPY lib/resty/routewarden /usr/local/openresty/site/lualib/resty/routewarden

# Copy your nginx.conf
COPY examples/nginx.conf /etc/nginx/conf.d/default.conf
```

Run with Docker:
```bash
docker run -d -p 80:80 -p 443:443 my-openresty-app
```

### Option 2: Existing NGINX with `lua-nginx-module`

1. Clone or copy `lib/resty/routewarden` to your server (e.g. `/etc/nginx/lua/lib/resty/routewarden`).
2. Add the path to `lua_package_path` inside `http {}` block in `nginx.conf`:

```nginx
http {
    lua_package_path "/etc/nginx/lua/lib/?.lua;/etc/nginx/lua/lib/?/init.lua;;";
    ...
}
```

---

## Quick Configuration

```nginx
http {
    lua_package_path "/etc/nginx/lua/lib/?.lua;/etc/nginx/lua/lib/?/init.lua;;";

    # Initialize RouteWarden in master/worker initialization phase
    init_by_lua_block {
        local routewarden = require("resty.routewarden")

        warden = routewarden.new({
            enabled = true,
            check_query = true,
            security_log = true,
            methods = { "GET", "HEAD" },
            allowed_ips = {
                "127.0.0.1",
                "10.0.0.0/8"
            },
            response = {
                mode = "json",
                status_code = 403
            }
        })
    }

    server {
        listen 80;
        server_name example.com;

        # Inspect all incoming requests
        access_by_lua_block {
            warden:check()
        }

        location / {
            proxy_pass http://backend_upstream;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
}
```

---

## Configuration Options

| Option | Type | Default | Description |
|---|---|---|---|
| `enabled` | `boolean` | `true` | Enable or disable RouteWarden inspection. |
| `enable_default_patterns` | `boolean` | `true` | Enable built-in sensitive file rules (`.env`, `.git`, `.aws`, database dumps, actuator, debug endpoints). |
| `enable_default_allow_patterns` | `boolean` | `true` | Enable exemptions for `/robots.txt`, `/sitemap*.xml`, `/.well-known/*`, etc. |
| `path_patterns` / `block_patterns` | `table` | `{}` | Custom regex patterns to block. |
| `allow_patterns` | `table` | `{}` | Custom regex patterns to allow (takes precedence over blocklists). |
| `allowed_ips` | `table` | `{}` | Whitelist of client IPs or CIDR blocks (`192.168.1.0/24`, `::1`). |
| `methods` | `table` | `{"GET"}` | HTTP methods to inspect (e.g. `{"GET", "POST"}`). |
| `check_query` | `boolean` | `false` | When true, inspects raw and decoded query string values. |
| `security_log` | `boolean` | `false` | Emits structured JSON events compatible with CrowdSec parsers. |
| `response` | `table` | `{ mode = "json", status_code = 403 }` | Response customization table. |

---

## Running Tests

Run the standalone unit test suite:

```bash
./t/run_tests.sh
```

---

## License

MIT License. Copyright (c) 2026 Aman.
