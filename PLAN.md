# BugBounty Bot — 자동 버그바운티 탐색·리포트·제출 봇

**목표**: HackerOne 버그바운티에 버그를 자동으로 발견·리포트·제출해서 상금을 버는 실전 도구. GitHub에 공개해서 명성도 쌓는다.

**핵심 방향 (2026-11-11 결정)**: **과최적화하지 말고, 점진적으로 알려진 취약점을 모두 발견할 수 있는 범용 도구**로 발전시킨다.
- **과최적화 금지**: DVWA/Juice Shop에 맞춰서만 고치지 않는다. 일반화 가능한 방식으로 고친다.
- **점진적**: 한 번에 모든 취약점을 잡으려 하지 않는다. 단계별로 취약점 유형을 추가한다.
- **목표**: 알려진 취약점(DVWA ~13개, Juice Shop ~20+개)을 **모두** 자동 발견할 수 있는 도구.
- **측정**: `docs/VULN_REPORT.md`의 발견률(DVWA ~54%, Juice Shop ~10%)을 단계별로 높인다.

---

## 1. 범위

| 항목 | 결정 |
|------|------|
| 버그 종류 | 웹앱(SQLi/XSS/IDOR/SSRF/auth bypass) + 로직(race condition/payment bypass) + 인프라(DNS/TLS/subdomain takeover/cloud misconfig) |
| 킬체인 | 스캔 → PoC → 리포트 → HackerOne 제출 |
| 자산 소스 | 새 도메인(CT/DNS) + 새 API 엔드포인트 + CVE 매칭 + 기존 자산 재스캔 |
| 플랫폼 | HackerOne (API) |
| 스캔 | Nuclei + 자체 Python + LLM (판단·리포트) |
| 성격 | 실전 (교육용 아님, Nightjar와 무관) |

---

## 2. 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│  BugBounty Bot (Python daemon)                                  │
│                                                                 │
│  ┌────────────┐   ┌────────────┐   ┌────────────────────────┐  │
│  │ Asset      │   │ Scanner    │   │ Triage (LLM)           │  │
│  │ Discovery  │──►│            │──►│ - 진짜 버그?           │  │
│  │            │   │ - Nuclei   │   │ - 심각도 (low~crit)    │  │
│  │ - CT log   │   │ - Python   │   │ - 리포트 작성          │  │
│  │ - DNS      │   │   custom   │   │ - PoC (curl/스크린샷)  │  │
│  │ - API      │   │ - infra    │   │ - dedup               │  │
│  │ - CVE      │   │ - logic    │   └───────────┬────────────┘  │
│  │ - rescan   │   └────────────┘               │              │
│  └────────────┘                                 ▼              │
│                                    ┌──────────────────────┐    │
│                                    │ HackerOne Client     │    │
│                                    │ - report.create()    │    │
│                                    │ - triage track       │    │
│                                    │ - auto-respond (LLM) │    │
│                                    └──────────────────────┘    │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Web Dashboard (Flask)                                    │  │
│  │ - 파이프라인 실시간: 자산→스캔→버그→리포트→제출         │  │
│  │ - 리포트 리뷰/수정/제출 (반자동)                         │  │
│  │ - 수익: accepted/rejected/payout                         │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ SQLite: assets, findings, reports, submissions, earnings │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**데이터 흐름**:
1. Asset Discovery → `Asset` (domain, subdomains, endpoints, tech_stack, cves)
2. Scanner → `Finding` (asset, vuln_type, severity, evidence, poc_request)
3. Triage (LLM) → `Report` (title, summary, poc, impact, recommendation, rating)
4. HackerOne Client → `Submission` (report_id, status, payout)

---

## 3. 모듈

### 3.1 `core/` — 공통

| 파일 | 기능 |
|------|------|
| `config.py` | YAML 설정 로드 (API key, programs, scan interval, LLM) |
| `db.py` | SQLite (assets, findings, reports, submissions, earnings) |
| `models.py` | dataclass: Asset, Finding, Report, Submission |
| `scheduler.py` | APScheduler (CT poll, DNS, rescan, triage check) |
| `logger.py` | 로깅 (파일 + 대시보드) |

### 3.2 `asset/` — 자산 발견

| 파일 | 기능 |
|------|------|
| `ct.py` | crt.sh API 폴링 → 새 서브도메인 |
| `dns.py` | DNS brute-force (subfinder 또는 자체) + A/AAAA/CNAME/MX/TXT |
| `api_crawl.py` | robots.txt, sitemap, JS 분석, OpenAPI → 엔드포인트 |
| `cve_match.py` | Wappalyzer/httpx headers → 버전 → NVD CVE 매칭 |
| `rescan.py` | 기존 자산 정기 재스캔 |
| `scope.py` | HackerOne 프로그램 in-scope/out-of-scope (wildcard) |

### 3.3 `scanner/` — 스캔

| 파일 | 기능 |
|------|------|
| `nuclei.py` | Nuclei CLI (subprocess), YAML 템플릿, CVE별 |
| `web.py` | SQLi, XSS, IDOR, SSRF, auth bypass (httpx) |
| `infra.py` | DNS misconfig, TLS, subdomain takeover, S3/GCS |
| `api.py` | REST/GraphQL: auth, rate limit, injection, mass assignment |
| `logic.py` | race condition, payment bypass, workflow skip |
| `orchestrator.py` | 스캔 순서, rate limit, concurrent control |

### 3.4 `triage/` — LLM 판단 + 리포트

| 파일 | 기능 |
|------|------|
| `judge.py` | LLM: 진짜 버그? (false positive 제거) |
| `severity.py` | LLM: HackerOne rating (low/med/high/crit) |
| `report.py` | LLM: HackerOne 형식 (title, summary, PoC, impact, recommendation) |
| `poc.py` | 재현 curl/HTTP + 스크린샷 (Playwright) |
| `dedup.py` | 중복 제거 (asset + vuln_type + endpoint) |

**LLM**: OpenAI GPT-4o (기본) / Anthropic Claude / Ollama (로컬). API key는 `.env`.

### 3.5 `hackerone/` — 플랫폼

| 파일 | 기능 |
|------|------|
| `auth.py` | API key 인증 |
| `client.py` | REST API (hackerone-py 또는 직접) |
| `submit.py` | report.create + 파일 첨부 |
| `track.py` | triage 상태 (new→triaging→resolved→paid), 연구원 질문 LLM 자동 응답 |
| `programs.py` | 대상 프로그램 + scope |

### 3.6 `web/` — 대시보드

| 파일 | 기능 |
|------|------|
| `app.py` | Flask |
| `routes.py` | API + 페이지 |
| `templates/` | dashboard, reports, report_detail, assets, earnings, programs |
| `static/` | JS (polling 3s) + CSS |

**페이지**:
- `/` — 파이프라인 실시간 (자산→스캔→버그→리포트→제출)
- `/reports` — 목록 (draft/submitted/accepted/rejected)
- `/reports/<id>` — LLM 작성, 수정, 제출 버튼
- `/assets` — 자산 + 스캔 상태
- `/earnings` — accepted 수, payout, 프로그램별
- `/programs` — 대상 HackerOne 프로그램

---

## 4. 기술 스택

| 레이어 | 선택 |
|--------|------|
| 언어 | Python 3.11+ |
| HTTP | httpx (async, HTTP/2) |
| 스캔 | Nuclei (subprocess) + 자체 Python |
| LLM | OpenAI GPT-4o / Claude / Ollama |
| DB | SQLite |
| 웹 | Flask |
| 스케줄러 | APScheduler |
| 브라우저 | Playwright (스크린샷) |
| DNS | dnspython |
| CT | crt.sh API |
| 패키지 | uv (pyproject.toml + uv.lock) |

**외부 바이너리 (subprocess)**: Nuclei, subfinder (선택)

---

## 5. 운영

### 5.1 daemon

```bash
bugbounty-bot --config config.yaml
```

| 작업 | 주기 |
|------|------|
| CT poll (새 서브도메인) | 1h |
| DNS brute (새 자산) | 6h |
| 재스캔 (기존 자산) | 24h |
| Nuclei + Python 스캔 | 자산 발견 시 즉시 |
| LLM triage | Finding 발생 시 즉시 |
| HackerOne triage check | 1h |

### 5.2 반자동

- **자동**: 자산 → 스캔 → Finding → LLM 판단 → 리포트 작성
- **인간**: 대시보드에서 리포트 리뷰 → "제출" 클릭
- **`--auto-submit`**: high/crit만 자동 제출

### 5.3 config.yaml

```yaml
hackerone:
  api_key_env: H1_API_KEY   # .env에서
  programs: [google, github, shopify]

scan:
  nuclei_templates: [cves/, exposures/, misconfigurations/]
  custom: [sqli, xss, idor, ssrf, auth_bypass, race_condition]
  rate_limit: 10            # req/s
  concurrent: 5

llm:
  provider: openai          # openai | anthropic | ollama
  model: gpt-4o
  auto_submit_min: high     # high | crit

scheduler:
  ct_min: 60
  dns_min: 360
  rescan_min: 1440
  triage_min: 60

web:
  host: 0.0.0.0
  port: 8500
```

---

## 6. GitHub

- **README.md**: 아키텍처, 사용법, "Found X bugs, earned $Y" + HackerOne profile
- **demo/**: Docker Compose (DVWA + Juice Shop) + demo.sh
- **docs/walkthrough.md**: 코드 설명 (Nightjar 스타일)
- **LICENSE**: MIT
- **GitHub Actions**: lint + test

---

## 7. 구조

```
bugbounty/
├── PLAN.md
├── README.md
├── DEPLOY.md
├── config.yaml
├── pyproject.toml
├── .env.example
├── .venv/
├── core/          config, db, models, scheduler, logger
├── asset/         ct, dns, api_crawl, cve_match, rescan, scope
├── scanner/       nuclei, web, infra, api, logic, orchestrator
├── triage/        judge, severity, report, poc, dedup
├── hackerone/     auth, client, submit, track, programs
├── web/           app, routes, templates/, static/
├── demo/          docker-compose.yml, demo.sh
├── tests/         test_scanner, test_triage, test_hackerone, test_integration
└── docs/          walkthrough.md
```

---

## 8. 구현 순서

| 단계 | 내용 | 완료 기준 |
|------|------|----------|
| **1. MVP** | core + scanner(web: SQLi/XSS/IDOR) + triage(LLM) + hackerone(submit) + web | 1개 버그: 발견→리포트→제출 |
| **2. 자산** | asset(CT/DNS/api_crawl) + scheduler | 새 자산 자동 발견→스캔 |
| **3. 확장** | scanner(infra/api/logic) + nuclei + poc(스크린샷) | 전체 버그 종류 |
| **4. 자동화** | auto-submit + triage track + dedup + earnings | 완전 자동 |
| **5. 명성** | README + demo(Docker) + walkthrough + CI | GitHub 공개 |
| **6. 알려진 취약점 커버리지** | DVWA/Juice Shop 알려진 취약점 **모두** 자동 발견 (점진적, 과최적화 금지) | DVWA ~13/13, Juice Shop ~20/20 |

### 8.1 단계 6 — 알려진 취약점 커버리지 (점진적 로드맵)

**원칙**: 과최적화 금지. 각 항목은 **일반화 가능한 방식**(payload/시그니처/로직)으로 고친다. DVWA/Juice Shop은 **검증 벤치마크**일 뿐, 그 앱 전용 코드는 만들지 않는다.

**현재 발견률** (docs/VULN_REPORT.md): DVWA ~54% (7/13), Juice Shop ~10% (2/20)

| 서브단계 | 추가 취약점 | 일반화 방식 | 벤치마크 검증 |
|----------|-----------|-----------|--------------|
| **6a. API/NoSQL** | NoSQLi login, Admin Registration, Login Admin | API body injection: `$ne`/`$gt`/`$regex` operator + 200/201 응답 판별. OpenAPI/Swagger 자동 탐지(`/openapi.json`, `/swagger.json`)로 endpoint·method·body schema 자동 추출 | Juice Shop: NoSQLi login, Admin Registration, Login Admin |
| **6b. XSS 확장** | DOM XSS, Stored XSS(DVWA) | DOM: JS 번들에서 `innerHTML`/`document.write`/`location.hash` sink 탐지. Stored: POST/PUT body에 XSS payload → GET으로 반사 확인(기존 body scanner 확장) | Juice Shop: DOM XSS, DVWA: Stored XSS |
| **6c. 파일/업로드** | File Upload, File Download | 업로드 endpoint: multipart POST + 확장자/Content-Type 변형. 다운로드: path traversal(`../`) | Juice Shop: File Upload, File Download |
| **6d. 인증/세션** | Weak Session, CAPTCHA, Password Reset | 세션: cookie entropy/만료 분석. CAPTCHA: 자동 풀기(OCR) + 우회. Password Reset: token 예측/재사용 | Juice Shop: Weak Session, CAPTCHA, Password Reset |
| **6e. 로직/인프라** | Race Condition, Payment Bypass, DNS/TLS | race: 동시 요청 + 결과 대조. payment: 가격/수량 변형. infra: DNS misconfig, TLS weak cipher, subdomain takeover | Juice Shop: Race Condition, Payment Bypass + infra scanner |

**완료 기준**: 각 서브단계 후 `docs/VULN_REPORT.md` 갱신 + 발견률 측정. 최종: DVWA ~13/13, Juice Shop ~20/20.

---

## 9. 리스크

| 리스크 | 대응 |
|--------|------|
| LLM false positive | dedup + auto_submit_min(high) + 인간 승인 |
| HackerOne rate limit | rate_limit + exponential backoff |
| Nuclei false positive | LLM judge 2차 |
| API key 노출 | .env (gitignore) |
| 목표 사이트 장애 | rate limit + concurrent + scope 확인 |
| LLM 비용 | 캐싱 + Ollama 옵션 |
