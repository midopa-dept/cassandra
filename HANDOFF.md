# BugBounty Bot — Handoff

**마지막 업데이트**: 2026-11-11
**현재 단계**: **단계 6 (알려진 취약점 커버리지)** — 6a~6e 중 **6a(API/NoSQL) 시작 대기**
**현재 블록**: 6a — OpenAPI/Swagger 자동 탐지 + NoSQLi login + Admin Registration

---

## 1. 프로젝트 목표

**최종 목표**: HackerOne 버그바운티에 버그를 자동으로 발견·리포트·제출해서 상금을 버는 실전 도구.

**핵심 방향 (2026-11-11 결정, PLAN.md에도 저장)**:
- **과최적화 금지** — DVWA/Juice Shop에 맞춰 전용 코드를 만들지 않는다. 일반화 가능한 방식(payload/시그니처/로직)으로 고친다.
- **점진적** — 한 번에 모든 취약점을 잡지 않는다. **한 번에 수행할 수 있는 블록** 단위로 나눠 단계적으로 추가한다.
- **측정 기준** — 알려진 취약점 **발견률**: DVWA ~54% (7/13) → 100%, Juice Shop ~10% (2/20) → 100%. 매 블록 후 `docs/VULN_REPORT.md` 갱신.

---

## 2. 단계 개요 (거시)

| 단계 | 내용 | 상태 |
|------|------|------|
| 1. MVP | core + scanner(SQLi/XSS/IDOR) + triage(LLM) + hackerone + 대시보드 | ✅ 완료 (4/4 테스트) |
| 2. 자산 | CT/DNS/API crawl/CVE/rescan/scope | ✅ 완료 (6/6) |
| 3. 확장 | infra/api/logic/nuclei/PoC(Playwright)/daemon | ✅ 완료 (6/6) |
| 4. 자동화 | auto-submit/track/WebSocket/CI/demo | ✅ 완료 (3/3) |
| 5. 명성 | README/demo/walkthrough/LICENSE | ✅ 완료 |
| 재설계 | scanner 7개 분할(sqli/xss/idor/ssrf/auth/fuzz/cve) + login | ✅ 완료 |
| **6. 알려진 취약점 커버리지** | **DVWA 13개 + Juice Shop 20+개 알려진 취약점 모두 자동 발견** | 🔄 **진행 중** |

### 단계 6 — 블록 (서브단계)

각 블록은 **한 번에 수행할 수 있는 단위**다. 순서대로 진행, 각 블록 후 VULN_REPORT 갱신 + 발견률 측정.

| 블록 | 추가 취약점 | 일반화 방식 | 상태 |
|------|-----------|-----------|------|
| **6a. API/NoSQL** | NoSQLi login, Admin Registration, Login Admin | OpenAPI/Swagger 자동 탐지 → endpoint·method·body schema 자동 추출. NoSQL operator(`$ne`/`$gt`/`$regex`) + 200/201 판별 | ⬜ **다음** |
| **6b. XSS 확장** | DOM XSS, Stored XSS(DVWA) | DOM: JS 번들에서 `innerHTML`/`document.write`/`location.hash` sink 탐지. Stored: body에 XSS payload → GET 반사 확인 | ⬜ |
| **6c. 파일/업로드** | File Upload, File Download | multipart POST + 확장자/Content-Type 변형, path traversal(`../`) | ⬜ |
| **6d. 인증/세션** | Weak Session, CAPTCHA, Password Reset | cookie entropy/만료 분석, CAPTCHA OCR+우회, reset token 예측/재사용 | ⬜ |
| **6e. 로직/인프라** | Race Condition, Payment Bypass, DNS/TLS | 동시 요청+결과 대조, 가격/수량 변형, DNS misconfig/TLS weak cipher/subdomain takeover | ⬜ |

**완료 기준**: DVWA 13/13, Juice Shop 20/20 (VULN_REPORT.md 측정).

---

## 3. 현재 블록: 6a (API/NoSQL) — 세부

**목표**: Juice Shop의 NoSQLi login, Admin Registration, Login Admin을 자동 발견.

**알고 있는 것 (실측, 2026-11-11)**:
- Juice Shop **v20.2.0** (bkimminich/juice-shop:latest) — API는 **`/api/*`** (구버전의 `/rest/*`가 아님)
- `POST /api/users` → **201** (사용자 생성)
- `POST /rest/login` → 500 "Unexpected path" — **실제 로그인 경로 미확인** (JS 번들 lazy-load chunk에 있음)
- NoSQLi 신호: `{"$gt":""}` → 500 (현재 fuzz_anomaly 11개로 잡힘)
- 알려진 NoSQLi login payload: `{"username": {"$ne": null}, "password": {"$ne": null}}` → 200 (로그인 우회)
- Juice Shop 저장소에 `swagger.yml`(B2B API) + `SOLUTIONS.md`(모든 취약점) 있음

**할 일 (이 블록)**:
1. **실제 로그인 경로 발견** — JS 번들 분석 또는 API probe (`/api/users/login` 등)
2. **`scanner/api.py`**: NoSQLi operator payload 추가 (`$ne`/`$gt`/`$regex`/`$or`) + 200/201 성공 판별 → `vuln_type="nosql"` (fuzz_anomaly에서 승격)
3. **OpenAPI/Swagger 자동 탐지** — `/openapi.json`, `/swagger.json` GET → endpoint·method·body schema 추출 → `crawl_api`에 통합
4. **Admin Registration** — `POST /api/users`에 admin role/권한 필드 주입 → 201 + 권한 확인
5. **검증** — `tests/test_live.py` 재실행 + `docs/VULN_REPORT.md` 갱신 (Juice Shop 발견률 재측정)

**완료 기준**: Juice Shop findings에 `nosql`(login 우회) + admin registration 관련 finding 등장. VULN_REPORT 발견률 상승 확인.

**주의 (함정)**:
- Juice Shop은 SPA(Angular) — non-API 경로에 `index.html`(200 HTML) 반환. Content-Type 필터 필수(기존 구현 있음).
- DVWA는 MySQL, Juice Shop은 MongoDB. NoSQLi는 MongoDB 백엔드에만 해당.
- 과최적화 금지: `/api/users` 같은 Juice Shop 전용 경로를 하드코딩하지 않는다. OpenAPI 탐지 + generic operator payload로 잡는다.

---

## 4. 진행 기록

### 2026-11-11 (5~7차 세션) — 실전 테스트 + 분석

**실전 테스트 결과 (현재)**:
| 앱 | findings | 내용 |
|----|----------|------|
| DVWA | **40** | sqli 10, xss 19, idor 8, cve 3 |
| Juice Shop | **11** | fuzz_anomaly (NoSQL injection 신호) |

**해결한 것**:
1. **DVWA sqli/xss 0 findings** — sqli/xss/idor가 폼의 다른 필드(`Submit`)를 안 보내 DVWA 쿼리 미실행 + `scan_web` 비인증 클라이언트 → **완전 폼 전송** + **인증 클라이언트 전달**으로 해결
2. **Juice Shop 0 findings** — SPA가 non-API 경로에도 HTML(200) 반환 → 오탐 9개 + body injection 미테스트 → **Content-Type 필터** + **item endpoint 발견** + **body injection 스캐너**로 해결
3. **DVWA 로그인 비결정성** — admin DB 비밀번호가 빈 문자열(`md5('')`) → 로그인 실패 → DB reset 미트리거(치icken-and-egg) → **로그인 실패 시 DB reset + 재로그인 폴백**으로 해결

**취약점 분석** (`docs/VULN_REPORT.md`):
- **exploit 실측 9개**: DVWA 7 (boolean/time/length SQLi, IDOR, XSS, LFI, 명령 주입) + Juice Shop 2 (Stored XSS, IDOR)
- **모두 알려진 취약점** (새로운 것이 아님 — 의도적으로 취약한 학습용 앱)
- **발견률**: DVWA ~54% (7/13), Juice Shop ~10% (2/20) → **단계 6의 목표**

### 단계 1~5 + 재설계 (이전 세션)
- 19개 mock 테스트 전부 통과
- scanner 7개 분할 + login (DVWA/Juice Shop)
- 상세: git log 참고

---

## 5. 파일 구조

```
bugbounty/
├── PLAN.md            # 목표 + 아키텍처 + 단계 로드맵 (8.1: 단계 6 블록)
├── HANDOFF.md         # 이 파일 — 진행 상황 + 현재 블록
├── README.md, LICENSE, config.yaml, pyproject.toml, uv.lock
├── core/              # models, config, db, scheduler, logger, main
├── asset/             # ct, dns, crawl, cve_match, rescan, scope
├── scanner/           # web(orchestrator), sqli, xss, idor, ssrf, auth, fuzz, cve, api, infra, logic, nuclei, login
├── triage/            # llm, dedup, poc
├── hackerone/         # client, track, submit
├── web/               # app, templates, static
├── demo/              # docker-compose.yml, demo.sh
├── docs/
│   ├── walkthrough.md
│   └── VULN_REPORT.md # 취약점 분석 (exploit 실측 + 발견률)
└── tests/             # test_mvp, test_asset, test_stage3, test_stage4, test_live, test_dvwa_login
```

## 6. 테스트

| 테스트 | 내용 | 결과 |
|--------|------|------|
| test_mvp.py | scanner + triage + hackerone + web | ⚠️ `scan_web(rate_limit=)` 시그니처 불일치 (재설계 후 갱신 필요) |
| test_asset.py | CT + DNS + API + CVE + rescan + scope | ✓ |
| test_stage3.py | infra + api + logic + nuclei + poc + daemon | ✓ |
| test_stage4.py | track + submit + websocket | ✓ |
| test_live.py | **실전**: DVWA + Juice Shop (colima 필요) | ✓ 51 findings |

**실행**: `.venv/bin/python tests/test_live.py` (colima + docker 컨테이너 필요)

## 7. 환경

- **colima**: **Stopped** (2026-11-12) — 시작: `colima start` → 컨테이너: `DOCKER_HOST=unix:///Users/midopa/.colima/default/docker.sock docker start demo-dvwa-1 demo-juice-shop-1` (DVWA `:8081`, Juice Shop `:3000`)
- **Python**: `.venv` (uv, 3.13) — `python3` 또는 `.venv/bin/python`
- **DVWA**: MySQL (app/vulnerables), admin/password. 로그인 실패 시 자동 DB reset
- **Juice Shop**: v20.2.0, MongoDB, API `/api/*`
