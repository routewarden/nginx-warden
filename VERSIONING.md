# RouteWarden Plugin Versioning & Release Guide

This document explains how versioning is managed for the **RouteWarden** NGINX / OpenResty Lua plugin repository (`github.com/routewarden/nginx-warden`).

---

## 1. Single Source of Truth (`version.json`)

The canonical version of RouteWarden for NGINX is stored in [`version.json`](version.json) at the repository root:

```json
{
  "version": "v1.2.0"
}
```

Whenever you prepare a release, update this file or use the automated synchronization script.

---

## 2. Semantic Versioning Specification

RouteWarden follows standard [Semantic Versioning (SemVer 2.0.0)](https://semver.org/):

$$\text{v}\mathbf{MAJOR}.\mathbf{MINOR}.\mathbf{PATCH}$$

- **MAJOR** (`v1.0.0`): Breaking architectural changes or modified public API.
- **MINOR** (`v1.1.0`): Backwards-compatible features (e.g., new response modes, anti-evasion rules).
- **PATCH** (`v1.0.1`): Backwards-compatible bug fixes or performance optimizations.

---

## 3. Automated Version Synchronization

To synchronize versions across `version.json`, `README.md`, and Lua source files:

```bash
./scripts/update-version.sh v1.0.0
```

---

## 4. Step-by-Step Release Workflow

### Step 1: Run Tests
```bash
./t/run_tests.sh
```

### Step 2: Update Version Strings
```bash
./scripts/update-version.sh v1.0.0
```

### Step 3: Review Diff & Commit
```bash
git diff
git add -u
git commit -m "chore: release v1.0.0"
```

### Step 4: Tag & Push
```bash
git tag v0.1.1
git push origin main --tags
```
