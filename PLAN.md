# Cassandra — LLM 에이전트의 블랙박스 웹 취약점 탐색 도구

## ⭐ North Star (최종 목표)

**처음 보는(알지 못하는) 웹 애플리케이션에서 취약점을 찾아내는 블랙박스 보안 도구.** LLM 코딩 에이전트의 **도구(toolset)**로 설계된다.

- DVWA·Juice Shop·WebGoat·bWAPP은 **검증 벤치마크**일 뿐, 최종 목표가 아니다.
- **아키텍처 핵심**: Cassandra는 **판단하지 않는다**. HTTP 트래픽을 주고받아 **사실(관찰)만 JSON**으로 돌려준다. *판단*("credential을 모른 상태에서 열 수 있는 경로는?")은 **LLM 에이전트(뇌)**가 한다. 사람이 감독한다.
- 성공 지표: **본 적 없는 실제 사이트**에서 같은 "관찰→판단→시도→확인" 루프로 취약점을 재현.

**이 목표를 잊지 않기 위해**: 모든 단계는 "처음 보는 웹에서 취약점을 찾는다"로 수렴해야 한다. 벤치마크에서 발견률을 높이는 것은 **수단**이지 **목적**이 아니다.

---

**목표**: LLM 에이전트가 `python -m core.main <명령>`을 호출하면, Cassandra가 HTTP 트래픽을 주고받아 결과를 **JSON**으로 돌려주는 도구. 에이전트는 그 관찰을 읽고 판단·다음 명령을 결정한다.

**핵심 방향 (2026-11-11 결정)**:
- **과최적화 금지**: 특정 앱에 맞춰 전용 코드를 만들지 않는다. 보편적 신호(payload/시그니처/로직)로 고친다.
- **점진적**: 한 번에 수행할 수 있는 블록 단위로 나눠 단계적으로 추가한다.
- **Default Credential 금지**: "이 앱의 기본 계정은?"을 웹 검색해 답을 가져오는 보상해킹을 하지 않는다. 대상이 스스로 공개하는 것(폼 힌트, robots.txt, JS 번들, 에러)만 읽고, 사전(dictionary)을 대고 대상의 반응(리다이렉트·상태코드)으로 확인한다.
- **측정**: 알려진 취약점 **발견률** — 벤치마크에서 매 블록 후 `docs/VULN_REPORT.md` 갱신.

---

## 1. 범위

| 항목 | 결정 |
|------|------|
| 버그 종류 | 웹앱(SQLi/XSS/IDOR/SSRF/auth bypass) + 로직(race condition/payment bypass) + 인프라(DNS/TLS/subdomain takeover/cloud misconfig) |
| 킬체인 | 관찰(scan) → 판단(LLM) → 시도(sqli/exploit/bruteforce) → 확인(verify) |
| 자산 소스 | 새 도메인(CT/DNS) + 새 API 엔드포인트 + CVE 매칭 + 기존 자산 재스캔 |
| 판단 | **LLM 에이전트**(Cassandra 외부) — 도구 내부에 LLM 클라이언트를 두지 않는다 |
| 성격 | 실전 (교육용 아님, Nightjar와 무관) |

---

## 2. 아키텍처 — 두뇌(LLM) + 감각기관(Cassandra)

```
사람(감독) ── 지시 ──► LLM 에이전트(뇌: 판단)
                          │ run_shell: python -m core.main <명령>
                          ▼
                    Cassandra(감각기관)
                    ┌─────────────────────────────────────┐
                    │  scanner/  (① 관찰)                  │
                    │  exploit/  (③ 시도)                  │
                    │  verify/   (④ 확인)                  │
                    │  asset/    (자산 발견)               │
                    │  triage/   (dedup, poc)             │
                    │  core/     (CLI, models, config)    │
                    └──────────────────┬──────────────────┘
                                       │ HTTP 트래픽
                                       ▼
                                 대상 웹 서버
                                       │
                                       ▼  JSON(사실만)
                                 LLM이 읽고 다음 판단
```

**데이터 흐름**:
1. `scan` → 페이지·폼·JS API·헤더·에러 (JSON)
2. LLM 판단 → 공격 경로 선택
3. `sqli` / `sqli-login` / `bruteforce` / `exploit` → 실행 결과 (JSON)
4. `verify` → 재현 + before/after 차이 (`reproduced: true/false`)
5. LLM 최종 판단 → 리포트(`Report` 모델, status: draft/verified/reported/accepted/rejected)

**왜 이렇게 나누는가**:
- **Cassandra(도구)는 판단하지 않는다.** HTTP를 날리고, 받은 바이트를 분석해서 *사실*만 JSON으로 넘긴다. 판단을 넣으면 특정 앱에 맞춰 과최적화되고, 새 웹사이트에서 안 먹힌다.
- **LLM(에이전트)이 판단한다.** Cassandra의 JSON을 읽고, 사람 보안 전문가가 머릿속으로 하는 것과 똑같은 추론을 한다.
- **사람은 감독자이다.** LLM의 판단과 Cassandra의 증거를 보고 최종 승인한다.

---

## 3. 모듈

### 3.1 `core/` — 공통

| 파일 | 기능 |
|------|------|
| `config.py` | YAML 설정 로드 (`scan` + `db_path`) |
| `db.py` | SQLite (assets, findings, reports) |
| `models.py` | dataclass: Endpoint, Asset, Finding, Report |
| `scheduler.py` | APScheduler (재스캔 등) |
| `logger.py` | 로깅 |
| `main.py` | CLI: scan, sqli, sqli-login, bruteforce, exploit, verify |

### 3.2 `scanner/` — ① 관찰 (보편적 신호로 판별, 앱 이름 하드코딩 없음)

| 파일 | 관찰하는 것 |
|------|------------|
| `sqli.py` | SQL 인젝션 (boolean / time-based blind / union / error) |
| `xss.py` | Reflected XSS, DOM XSS(JS 번들 sink+source), Stored XSS |
| `idor.py` | IDOR (다른 사용자 ID로 접근) |
| `ssrf.py` | SSRF |
| `auth.py` | 인증 우회 (HTTP method override 등) |
| `fuzz.py` | 이상 탐지 (status code 변화) |
| `cve.py` | CVE 매칭 (tech detection + NVD) |
| `api.py` | REST API (auth, rate limit, body injection) |
| `file.py` | 파일 업로드 RCE, path traversal |
| `session.py` | Weak Session, Insecure CAPTCHA, Password Reset |
| `infra.py` | DNS misconfig, TLS, subdomain takeover |
| `logic.py` | Race condition, payment bypass, workflow skip |
| `nuclei.py` | Nuclei CLI (subprocess) |
| `context.py` | JS 번들에서 API 엔드포인트 추출 (SPA용) |
| `login.py` | 로그인/세션 처리 |
| `web.py` | **orchestrator** — 위 모듈들을 모두 호출 |

### 3.3 `exploit/` — ③ 시도

| 파일 | 기능 |
|------|------|
| `executor.py` | sqli_probe, sqli_login_probe (LLM이 지시한 payload 실행) |
| `bruteforce.py` | 로그인 브루트포스 (사전 vs 대상 반응) |
| `poc.py` | PoC 생성 (curl/HTTP) |

### 3.4 `verify/` — ④ 확인

| 파일 | 기능 |
|------|------|
| `evidence.py` | 재현 + before/after 응답 차이 캡처 → `reproduced: true/false` |

### 3.5 `asset/` — 자산 발견

| 파일 | 기능 |
|------|------|
| `ct.py` | crt.sh API 폴링 → 새 서브도메인 |
| `dns.py` | DNS brute-force + A/AAAA/CNAME/MX/TXT |
| `api_crawl.py` | robots.txt, sitemap, JS 분석, OpenAPI → 엔드포인트 |
| `cve_match.py` | Wappalyzer/httpx headers → 버전 → NVD CVE 매칭 |
| `rescan.py` | 기존 자산 정기 재스캔 |
| `scope.py` | in-scope/out-of-scope (wildcard) |
| `crawl.py` | 정적 crawl + robots.txt + JS 번들 라우트 추출 |

### 3.6 `triage/` — 중복 제거 + PoC

| 파일 | 기능 |
|------|------|
| `dedup.py` | 중복 제거 (asset + vuln_type + endpoint) |
| `poc.py` | 재현 curl/HTTP + 스크린샷 (Playwright) |

> **LLM 판단·리포트는 에이전트가 수행한다.** Cassandra 내부에 LLM 클라이언트를 두지 않는다. `Report` 모델(status: draft/verified/reported/accepted/rejected)은 에이전트가 리포트를 작성할 때 쓰는 데이터 구조로만 유지된다.

### 3.7 `web/` — 대시보드

| 파일 | 기능 |
|------|------|
| `app.py` | Flask 대시보드 |
| `templates/`, `static/` | UI |

---

## 4. 기술 스택

| 레이어 | 선택 |
|--------|------|
| 언어 | Python 3.11+ |
| HTTP | httpx (async, HTTP/2) |
| 스캔 | Nuclei (subprocess) + 자체 Python |
| DB | SQLite |
| 웹 | Flask |
| 스케줄러 | APScheduler |
| 브라우저 | Playwright (스크린샷, optional) |
| DNS | dnspython |
| CT | crt.sh API |
| 패키지 | uv (pyproject.toml + uv.lock) |

**외부 바이너리 (subprocess)**: Nuclei (optional)

---

## 5. CLI 명령

| 명령 | 역할 | 필수 옵션 |
|------|------|-----------|
| `scan` | ① 관찰 — 무인증 표면, 인증 후 내부 | `url` |
| `sqli` | ③ 시도 — SQLi 자동 탐사 | `url` |
| `sqli-login` | ③ 시도 — 로그인 폼 SQLi | `base_url`, `--login-url` |
| `bruteforce` | ③ 시도 — 로그인 브루트포스 | `base_url`, `--login-url` |
| `exploit` | ③ 시도 — LLM이 지시한 payload | `url`, `-i` |
| `verify` | ④ 확인 — 재현 + before/after | `url`, `-i` |

모든 명령은 **JSON**을 stdout으로 돌려준다.

---

## 6. config.yaml

코드가 실제로 읽는 섹션:

```yaml
scan:
  concurrent: 5
  timeout: 10
  user_agent: "Mozilla/5.0 ..."
  max_pages: 50
  follow_redirects: true

db_path: "cassandra.db"
```

`.env`(gitignore)에서 API 키 등을 관리한다.

---

## 7. GitHub

- **README.md / README.en.md**: 아키텍처, 사용법, 실측 결과
- **demo/**: Docker Compose (DVWA + Juice Shop + bWAPP + WebGoat) + demo.sh
- **docs/walkthrough.md**: 코드 설명 ("왜 이렇게 만들었나")
- **docs/VULN_REPORT.md**: 취약점 분석 (exploit 실측 + 발견률)
- **docs/agent_prompts.md**: LLM 에이전트가 Cassandra를 부를 때 쓰는 프롬프트
- **LICENSE**: MIT
- **GitHub Actions**: lint + test

---

## 8. 구조

```
cassandra/
├── PLAN.md
├── HANDOFF.md         # (gitignore, 내부)
├── README.md, README.en.md
├── LICENSE, config.yaml, pyproject.toml, uv.lock
├── core/              # models, config, db, scheduler, logger, main (CLI)
├── scanner/           # sqli, xss, idor, ssrf, auth, fuzz, cve, api, file,
│                      #   session, infra, logic, nuclei, context, login, web
├── exploit/           # executor, bruteforce, poc
├── verify/            # evidence
├── asset/             # ct, dns, api_crawl, cve_match, rescan, scope, crawl
├── triage/            # dedup, poc
├── web/               # app, templates/, static/
├── demo/              # docker-compose.yml, demo.sh
├── tests/             # test_mvp, test_asset, test_stage3, test_dvwa_login,
│                      #   test_8c_multistep, test_live
└── docs/              # logo, VULN_REPORT, walkthrough, agent_prompts, architecture.svg
```

---

## 9. 구현 순서

| 단계 | 내용 | 완료 기준 |
|------|------|----------|
| **1. MVP** | core + scanner(SQLi/XSS/IDOR) + triage + 대시보드 | 1개 버그: 관찰→실행→확인 |
| **2. 자산** | asset(CT/DNS/api_crawl) + scheduler | 새 자산 자동 발견→스캔 |
| **3. 확장** | scanner(infra/api/logic/nuclei/session/file) + poc | 전체 버그 종류 |
| **4. 자동화** | dedup + earnings + CI/demo | 완전 자동 |
| **5. 명성** | README + demo(Docker) + walkthrough + LICENSE | GitHub 공개 |
| **6. 알려진 취약점 커버리지** | DVWA/Juice Shop/WebGoat/bWAPP 알려진 취약점 **모두** 자동 발견 | 벤치마크 실측 confirmed |
| **7. 일반화 (범용성)** | 벤치마크 전용 코드 제거, **알지 못하는 웹**에서도 동작 | **알지 못하는 웹 앱**에서 동등한 findings |
| **8. 아키텍처 재정의** | 도구+에이전트 분리 확정, HackerOne/LLM 클라이언트 제거, CLI 6개 명령 | ✅ 완료 (2026-11-16) |
| **9. 실전** | **처음 보는 실제 사이트**에서 같은 루프 동작 | **North Star** |

### 9.1 단계 6 — 알려진 취약점 커버리지 (점진적 로드맵)

**원칙**: 과최적화 금지. 각 항목은 **일반화 가능한 방식**(payload/시그니처/로직)으로 고친다.

| 서브단계 | 추가 취약점 | 일반화 방식 |
|----------|-----------|-----------|
| **6a. API/NoSQL** | NoSQLi login, Admin Registration | API body injection: `$ne`/`$gt`/`$regex` operator + 200/201 판별. OpenAPI/Swagger 자동 탐지 |
| **6b. XSS 확장** | DOM XSS, Stored XSS | DOM: JS 번들에서 `innerHTML`/`document.write`/`location.hash` sink 탐지. Stored: POST body에 XSS payload → GET 반사 확인 |
| **6c. 파일/업로드** | File Upload, File Download | multipart POST + 확장자/Content-Type 변형. path traversal(`../`) |
| **6d. 인증/세션** | Weak Session, CAPTCHA, Password Reset | cookie 재생성→entropy/순차성/길이 분석, CAPTCHA sitekey/이미지 재사용, reset token 예측 |
| **6e. 로직/인프라** | Race Condition, Payment Bypass, DNS/TLS | 동시 요청+결과 대조, 가격/수량 변형, DNS misconfig/TLS weak cipher/subdomain takeover |

**완료 기준**: 각 서브단계 후 `docs/VULN_REPORT.md` 갱신 + 발견률 측정.

### 9.2 단계 7 — 일반화 (범용성)

- 벤치마크 전용 로직(경로 하드코딩, 앱 전용 payload) 제거 → generic 탐지(OpenAPI, form, JS sink, header)
- **새 벤치마크 추가**: bWAPP, WebGoat
- 완료 기준: **알지 못하는 웹 앱**에서 벤치마크와 동등한 findings + 오탐률 관리

### 9.3 단계 8 — 아키텍처 재정의 (✅ 완료 2026-11-16)

- **제거**: `hackerone/` 패키지, `H1_*` env, `Submission` 모델, payout, `scanner/llm.py`, `triage/llm.py`
- **유지**: `Report` 모델(에이전트 작성용)
- **확정**: CLI 6개 명령(scan/sqli/sqli-login/bruteforce/exploit/verify), JSON 출력
- **4개 벤치마크 실측**: DVWA, Juice Shop, WebGoat, bWAPP — 모두 confirmed

### 9.4 단계 9 — 실전 (North Star)

- **처음 보는 실제 사이트**에서, LLM 에이전트가 Cassandra를 도구로 써서 "관찰→판단→시도→확인" 루프를 돌린다.
- 성공 지표: **실제 사이트에서 confirmed 취약점 ≥ N**
- 리스크: 오탐 → verify(reproduced) + 사람 승인

---

## 10. 리스크

| 리스크 | 대응 |
|--------|------|
| LLM false positive | verify(재현) + 사람 승인 |
| 과최적화 | 보편적 신호만, 벤치마크 외 검증 |
| Default credential 의존 | 원칙: 대상이 공개하는 것만 + 사전 |
| API key 노출 | .env (gitignore) |
| 목표 사이트 장애 | rate limit + concurrent |
| LLM 비용 | 에이전트 측 문제(도구에는 LLM 클라이언트 없음) |
