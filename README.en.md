# Cassandra

**A black-box web vulnerability finder that works the way a human would: observe → attempt → discover.**

Python-based. It does not assume you know the target's credentials. It starts from what the target *itself* reveals (forms, API endpoints in JS bundles, error messages, hints in pages), then attempts to get in through paths that don't require prior knowledge — self-registration, password reset, SQLi login bypass, IDOR — and finally verifies each finding by reproducing it.

---

## Results (2026-11-16)

**Re-discovered vulnerabilities across 4 benchmarks using the "observe → attempt → discover" loop.** No credentials were known in advance (black-box); entry was made only from what the tool observed (forms, APIs, errors).

| Benchmark | Entry path (black-box) | Found & confirmed |
|-----------|------------------------|-------------------|
| **DVWA** | Unauthenticated scan → login-form **bruteforce** (dictionary) → `admin/password` | SQLi (UNION, extracted 5 credentials) · reflected XSS — verify **confirmed** |
| **Juice Shop** | API endpoints extracted from JS bundle → **self-registration** (`/api/Users/`) | **IDOR**: a customer token reads `authentication-details/` and returns all 51 users (incl. admin) — verify **confirmed** |
| **WebGoat** | Registration form → **self account creation** → traced RequireJS to lesson endpoints | Reflected XSS (`CrossSiteScripting/attack5a`) — verify **confirmed** |
| **bWAPP** | setup → `install.php` → login-form hint ("bee/bug") **bruted** | **SQLi** (error-based, `sqli_1.php?title=`) · **reflected XSS** (`htmli_get.php?firstname=`) — verify **confirmed** |

**Principle — no default credentials:** we do not search the web for "this app's default login" (that is reward hacking). Instead we (1) read only what the target **publicly exposes** (form hints, robots.txt, JS bundles, error messages) and (2) try a dictionary against the form and confirm by the target's **response** (redirect / status code).

**Tool = senses, agent = judgment:** the scanner only reports **observations** — "there is a form here", "this parameter errors when injected", "this API returns 200 without a token". The attack plan ("what to do with that") is decided by the agent, and `exploit` / `verify` execute it and leave evidence.

---

## How it works

It automates the **observe → attempt → discover** loop a human uses to find a vulnerability, starting from the assumption that you do not know the credentials.

```
① Observe (scan)        ② Judge (agent)         ③ Attempt (exploit)     ④ Verify
"there is a form/API/  →  "paths that open    →  "SQLi login bypass?   →  "reproduce and
 error here"            without credentials:   extract creds DB?        capture before/after
                       register? reset?       which payload?"          evidence;
                       SQLi? IDOR?"                                reproduced=true/false"
```

1. **Observe** — `scan` reports the unauthenticated surface (pages, forms, hidden fields, API endpoints inside JS bundles, headers, errors) and, after auth, the internals (modules, protected APIs). It **does not judge**.
2. **Judge** — the agent reads the observations and picks an attack path, in this order: (a) what is open without auth (APIs, public data) → (b) create your own account (registration flow) → (c) password reset (token leak / prediction) → (d) login-form injection (SQLi login bypass, credential DB extraction) → (e) after auth (IDOR, privilege escalation).
3. **Attempt** — `sqli` (auto probe: technique → columns → schema → data), `sqli-login` (inject into the login form), `bruteforce` (dictionary vs. the target's response), `exploit` (run a given instruction/payload).
4. **Verify** — `verify` **reproduces** the finding and captures the before (normal) vs. after (vulnerable) response diff, returning `reproduced: true/false` and a `verdict_hint`. A human makes the final call.

These four stages live in `scanner/` (①), `exploit/` (③), `verify/` (④); shared data models, config and logging are in `core/`.

---

## Scanner — what it actually catches

The **heart** of the project. Each module judges by **universal signals**, never by "this app is DVWA":

| Module | Catches |
|--------|---------|
| `sqli.py` | SQL injection (boolean / time-based blind / union / error) |
| `xss.py` | Reflected XSS, **DOM XSS** (JS bundle sink+source), **Stored XSS** (store→reflect) |
| `idor.py` | IDOR (access another user's resource by ID) |
| `ssrf.py` | SSRF |
| `auth.py` | Auth bypass (HTTP method override, etc.) |
| `fuzz.py` | Anomaly detection (status-code change) |
| `cve.py` | CVE matching (tech detection + NVD) |
| `api.py` | REST API (auth, rate limit, body injection) |
| `file.py` | File upload RCE, path traversal |
| `session.py` | **Weak Session**, **Insecure CAPTCHA**, **Password Reset** |
| `context.py` | API endpoint extraction from JS bundles (for SPAs) |
| `login.py` | Login / session handling (DVWA, Juice Shop, etc.) |
| `web.py` | **orchestrator** — calls all of the above |

---

## Install

```bash
# Python 3.11+ required
uv sync
```

Copy `.env.example` to `.env` and fill in keys (`.env` is gitignored). `config.yaml` holds scan options, LLM provider, scheduler and dashboard port.

## Usage

The CLI is `uv run python -m core.main <command>`.

```bash
# ① Observe — unauthenticated surface (pages, forms, JS APIs, headers, errors)
uv run python -m core.main scan http://localhost:8081 --max-pages 25

#    Also see the authenticated interior (only with credentials the target reveals)
uv run python -m core.main scan http://localhost:8081 \
    --login-url /login.php --login-user admin --login-pass password

# ③ Attempt — automatic SQLi probe (technique, columns, schema, credential DB)
uv run python -m core.main sqli "http://localhost:8081/vulnerabilities/sqli/?id=1" \
    --login-url /login.php --login-user admin --login-pass password

#    SQLi on the login form (bypass / extract without knowing credentials)
uv run python -m core.main sqli-login http://localhost:8081 --login-url /login.php

#    Login bruteforce (dictionary vs. the target's response)
uv run python -m core.main bruteforce http://localhost:8082 \
    --login-url /login.php --user-field login --pass-field password --max-attempts 200

#    Run an exploit instruction (POST body, custom headers)
uv run python -m core.main exploit "http://localhost:8082/htmli_get.php?firstname=%3Cscript%3Ealert(1)%3C%2Fscript%3E" \
    -i "XSS reflected in firstname" --expected "alert(1)"

# ④ Verify — reproduce + before/after evidence
uv run python -m core.main verify "http://localhost:8082/sqli_1.php?title=a%27&action=search" \
    -i "SQLi error-based: single quote breaks the query" \
    --expected "You have an error in your SQL" \
    --baseline-url "http://localhost:8082/sqli_1.php?title=a&action=search" \
    --login-url /login.php --login-user bee --login-pass bug
```

Every command prints JSON, so it pipes cleanly into `jq`.

## Running the benchmarks

```bash
cd demo && docker compose up -d
# DVWA: http://localhost:8081   Juice Shop: http://localhost:3000
# bWAPP: http://localhost:8082  WebGoat: http://localhost:8083/WebGoat
```

bWAPP needs its database installed on first use: hit `/install.php?install=yes`.

## Structure

```
cassandra/
├── core/          # models, config, db, scheduler, logger, main (CLI)
├── scanner/       # ① observe: sqli, xss, idor, ssrf, auth, fuzz, cve, api,
│                  #   file, session, infra, logic, nuclei, login, context + web.py
├── exploit/       # ③ attempt: executor (sqli_probe, sqli_login_probe), bruteforce, poc
├── verify/        # ④ verify: evidence (reproduce + before/after)
├── asset/         # asset discovery (CT, DNS, API crawl, CVE, rescan, scope)
├── triage/        # LLM (judge, severity, report, PoC), dedup
├── web/           # dashboard
├── demo/          # docker-compose (DVWA + Juice Shop + bWAPP + WebGoat)
├── tests/         # integration tests
└── docs/          # VULN_REPORT, walkthrough
```

## License

MIT
