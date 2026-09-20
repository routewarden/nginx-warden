#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LUA_BIN="${LUA_BIN:-$(which lua || echo "/opt/homebrew/bin/lua")}"

echo "===================================================="
echo "🛡️  Running RouteWarden NGINX (Lua) Test Suite"
echo "Lua Binary: $LUA_BIN ($("$LUA_BIN" -v 2>&1))"
echo "===================================================="
echo ""

cd "$ROOT_DIR"

echo "▶ Running Path Normalizer Tests..."
"$LUA_BIN" t/test_normalizer.lua
echo ""

echo "▶ Running IP & CIDR Filter Tests..."
"$LUA_BIN" t/test_ip_filter.lua
echo ""

echo "▶ Running Configuration & Validation Tests..."
"$LUA_BIN" t/test_config.lua
echo ""

echo "▶ Running Response Modes Tests..."
"$LUA_BIN" t/test_response.lua
echo ""

echo "▶ Running End-to-End RouteWarden Inspection Tests..."
"$LUA_BIN" t/test_routewarden.lua
echo ""

echo "===================================================="
echo "🎉 ALL TESTS PASSED SUCCESSFULLY!"
echo "===================================================="
