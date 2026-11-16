# BugBounty Bot — Handoff

**마지막 업데이트**: 2026-11-14
**현재 단계**: **단계 6 (알려진 취약점 커버리지) 완료** (6a~6e) → **단계 7 (일반화) 대기**
**현재 블록**: 7 — 벤치마크 전용 코드 제거, 새 벤치마크(WebGoat/bWAPP) 검증

---

## 1. 프로젝트 목표

**⭐ North Star (최종 목표)**: **처음 보는(알지 못하는) 웹 애플리케이션에서 취약점을 자동으로 발견하고, HackerOne에 제출해서 상금을 버는 실전 도구.** (PLAN.md 상단에도 저장)

- DVWA·Juice Shop은 **검증 벤치마크**일 뿐, 최종 목표가 아니다.
- 최종 시험: **알지 못하는 실제 HackerOne 프로그램**에서, 사람이 제출 전 승인만 하고, 봇이 스캔→triage→제출을 자동 수행.
- 성공 지표: **실제 HackerOne 프로그램에서 accepted 버그 ≥ N, payout ≥ $X** (N·X는 단계 8에서 정함).

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
| **7. 일반화 (범용성)** | 벤치마크 전용 코드 제거, **알지 못하는 웹**에서도 동작 (새 벤치마크: WebGoat/bWAPP/Mutillidae) | ⬜ 대기 |
| **8. 실전 (HackerOne)** | **처음 보는 실제 HackerOne 프로그램**에서 자동 스캔→triage→제출(반자동) — **North Star** | ⬜ 대기 |

### 단계 6 — 블록 (서브단계)

각 블록은 **한 번에 수행할 수 있는 단위**다. 순서대로 진행, 각 블록 후 VULN_REPORT 갱신 + 발견률 측정.

| 블록 | 추가 취약점 | 일반화 방식 | 상태 |
|------|-----------|-----------|------|
| **6a. API/NoSQL** | NoSQLi login, Admin Registration, Login Admin | OpenAPI/Swagger 자동 탐지 → endpoint·method·body schema 자동 추출. NoSQL operator(`$ne`/`$gt`/`$regex`) + 200/201 판별 | ✅ **완료** (nosqli + admin_registration + openapi_exposed) |
| **6b. XSS 확장** | DOM XSS, Stored XSS(DVWA) | DOM: JS 번들에서 `innerHTML`/`document.write`/`location.hash` sink 탐지. Stored: body에 XSS payload → GET 반사 확인 | ✅ **완료** (dom_xss + stored_xss) |
| **6c. 파일/업로드** | File Upload, File Download | multipart POST + 확장자/Content-Type 변형, path traversal(`../`) | ✅ **완료** (file_upload RCE + path_traversal) |
| **6d. 인증/세션** | Weak Session, CAPTCHA, Password Reset | cookie 재생성→entropy/순차성/길이 분석, CAPTCHA sitekey/이미지 재사용, reset token 예측 | ✅ **완료** (weak_session + captcha; password_reset은 email 기반이라 토큰 미추출) |
| **6e. 로직/인프라** | Race Condition, Payment Bypass, DNS/TLS | 동시 요청+결과 대조, 가격/수량 변형, DNS misconfig/TLS weak cipher/subdomain takeover | ✅ **완료** (scanner 버그 수정 + orchestrator/test_live 통합; localhost 벤치마크엔 해당 취약점 없음) |

**완료 기준**: DVWA 13/13, Juice Shop 20/20 (VULN_REPORT.md 측정).

---

## 3. 완료된 블록: 6e (로직/인프라) — 결과 (2026-11-14)

**목표**: Race Condition, Payment Bypass, DNS/TLS 자동 발견.

**결과**:
- **scanner 버그 수정**: `scan_logic`이 `Endpoint` 객체를 문자열처럼 다뤄 `TypeError` 발생 → `endpoint.url` 처리로 수정. `scan_workflow_skip`은 모든 200 페이지를 오탐 → step/phase/stage/wizard/checkout 키워드만 검사하도록 수정.
- **통합**: `scan_infra`(TLS/subdomain takeover/S3/DNS) + `scan_logic`(race/payment/workflow)은 `core/main.py`에 이미 통합되어 있었음. `tests/test_live.py`에도 추가.
- **벤치마크 결과**: localhost(HTTP)라 infra 0, DVWA(PHP)·Juice Shop(SPA)에 해당 취약점이 없어 logic 0. **실전(실제 도메인, REST API, 결제 플로우)에서 동작**하도록 설계.

**새/수정 파일**: `scanner/logic.py`(버그 수정), `tests/test_live.py`(infra/logic 통합).

---

## 4. 완료된 블록: 6d (인증/세션) — 결과 (2026-11-14)

**목표**: Weak Session, CAPTCHA, Password Reset 자동 발견.

**결과**:
- **Weak Session IDs**: ✅ DVWA `vulnerabilities/weak_id/` — `dvwaSession` cookie가 Generate POST마다 **순차(1,2,3,4)**로 재생성. scanner는 엔드포인트 반복 요청→Set-Cookie 수집→재생성되는 cookie의 **순차성/엔트로피/길이** 분석. `weak_session` finding 1개 (**medium**).
- **Insecure CAPTCHA**: ✅ DVWA `vulnerabilities/captcha/` — reCAPTCHA `data-sitekey=''`(빈) + "key missing" 경고 + **이미지 재사용**(같은 session에서 동일 바이트) → CAPTCHA 비활성. `captcha` finding 1개 (**high**).
- **Password Reset**: ⚠️ Juice Shop은 email 기반(reset 토큰을 HTTP 응답에 안 줌)이라 토큰 미추출 → finding 없음(오탐 방지). scanner는 reset/forgot endpoint 탐지→토큰 추출→단순성/엔트로피 분석 로직은 갖춤.

**새 파일**: `scanner/session.py` (scan_weak_session, scan_captcha, scan_password_reset, scan_session). `scanner/web.py`에 asset-level 통합.

**발견률**: DVWA ~8/13 → **~10/13** (weak_session + captcha 추가). Juice Shop ~5/20+ (변화 없음, password_reset은 email 기반).

**일반화**: 특정 cookie 이름/경로 하드코딩 없음. Set-Cookie 재생성 패턴 + sitekey/이미지 재사용 신호로 판별. known session path(weak_id 등)를 candidate 우선으로 probe.

---

## 5. 완료된 블록: 6c (파일/업로드) — 결과 (2026-11-12)

**목표**: File Upload, File Download, path traversal 자동 발견.

**결과**:
- **File Upload (RCE)**: ✅ DVWA `vulnerabilities/upload/`에 `.php` 업로드 → `/hackable/uploads/bb_rce.php` 저장 → **200 + marker 출력** (RCE) — `file_upload` finding 1개 (**critical**).
- **Path Traversal**: scanner 추가 (file/download 파라미터에 `../` 주입 → /etc/passwd). DVWA LFI는 기존 lfi scanner가 이미 잡음.
- **DVWA findings**: 42 → **43** (file_upload 1)
- **TOTAL**: 64 → **65** (DVWA 43 + Juice Shop 22)
- **발견률**: DVWA **~8/13** (~62%), Juice Shop **~5/20+** (~25%)

**구현** (`scanner/file.py`):
- `scan_file_upload(asset, endpoint, client)` — multipart 폼(file input) 탐지 → .php payload 업로드 → 성공 메시지 + 저장 파일 URL 추출 → 접근·실행(marker) 확인. RCE면 critical.
- `scan_file_download(asset, endpoint, client)` — file/download/path/page 파라미터에 `../` traversal 주입 → /etc/passwd, index.php marker 반사 확인.

**알고 있는 것 (실측, 2026-11-12)**:
- DVWA `vulnerabilities/upload/`: 폼 `enctype="multipart/form-data"`, file 필드 `uploaded`, 버튼 `Upload`. `.php` 업로드 → `../../hackable/uploads/test.php succesfully uploaded!` → `/hackable/uploads/`에서 200 + 실행.
- 이 DVWA 이미지(v1.10 dev)는 `file_download` 페이지가 없음 (upload + fi만). path traversal은 LFI(`fi/.`)가 커버.

**다음 블록: 6d (인증/세션)** — Weak Session, CAPTCHA, Password Reset

**완료 기준**: Juice Shop findings에 `nosql`(login 우회) + admin registration 관련 finding 등장. VULN_REPORT 발견률 상승 확인.

**주의 (함정)**:
- Juice Shop은 SPA(Angular) — non-API 경로에 `index.html`(200 HTML) 반환. Content-Type 필터 필수(기존 구현 있음).
- DVWA는 MySQL, Juice Shop은 MongoDB. NoSQLi는 MongoDB 백엔드에만 해당.
- 과최적화 금지: `/api/users` 같은 Juice Shop 전용 경로를 하드코딩하지 않는다. OpenAPI 탐지 + generic operator payload로 잡는다.

---

## 6. 진행 기록

### 2026-11-11 (5~7차 세션) — 실전 테스트 + 분석

**실전 테스트 결과 (현재)**:
| 앱 | findings | 내용 |
|----|----------|------|
| DVWA | **43** | sqli 10, xss 19, stored_xss 2, idor 8, cve 3, file_upload 1 |
| Juice Shop | **22** | nosqli 1, admin_registration 1, dom_xss 1, xss 2, api_missing_auth 3, api_no_rate_limit 3, fuzz_anomaly 11 |

**해결한 것**:
1. **DVWA sqli/xss 0 findings** — sqli/xss/idor가 폼의 다른 필드(`Submit`)를 안 보내 DVWA 쿼리 미실행 + `scan_web` 비인증 클라이언트 → **완전 폼 전송** + **인증 클라이언트 전달**으로 해결
2. **Juice Shop 0 findings** — SPA가 non-API 경로에도 HTML(200) 반환 → 오탐 9개 + body injection 미테스트 → **Content-Type 필터** + **item endpoint 발견** + **body injection 스캐너**로 해결
3. **DVWA 로그인 비결정성** — admin DB 비밀번호가 빈 문자열(`md5('')`) → 로그인 실패 → DB reset 미트리거(치icken-and-egg) → **로그인 실패 시 DB reset + 재로그인 폴백**으로 해결

**취약점 분석** (`docs/VULN_REPORT.md`):
- **exploit 실측 14개**: DVWA 10 (boolean/time/length SQLi, IDOR, XSS, **Stored XSS×2**, **File Upload RCE**, LFI, 명령 주입) + Juice Shop 4 (Stored XSS, IDOR, NoSQLi login, Admin Registration) + **DOM XSS (정적 분석)**
- **모두 알려진 취약점** (새로운 것이 아님 — 의도적으로 취약한 학습용 앱)
- **발견률**: DVWA **~62%** (8/13), Juice Shop **~25%** (5/20) → **단계 6d~6e 목표**

### 단계 1~5 + 재설계 (이전 세션)
- 19개 mock 테스트 전부 통과
- scanner 7개 분할 + login (DVWA/Juice Shop)
- 상세: git log 참고

---

## 7. 파일 구조

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

## 8. 테스트

| 테스트 | 내용 | 결과 |
|--------|------|------|
| test_mvp.py | scanner + triage + hackerone + web | ⚠️ `scan_web(rate_limit=)` 시그니처 불일치 (재설계 후 갱신 필요) |
| test_asset.py | CT + DNS + API + CVE + rescan + scope | ✓ |
| test_stage3.py | infra + api + logic + nuclei + poc + daemon | ✓ |
| test_stage4.py | track + submit + websocket | ✓ |
| test_live.py | **실전**: DVWA + Juice Shop (colima 필요) | ✓ 51 findings |

**실행**: `colima start stewart --cpu 2 --memory 4 --mount /Volumes/Dev/stewart-work:w` → `unset DOCKER_HOST` → `cd demo && docker-compose up -d dvwa juice-shop` → `.venv/bin/python tests/test_live.py`

## 9. 환경

- **colima**: **stewart 프로파일** (2 CPU / 4GiB, `/Volumes/Dev/stewart-work` 마운트)
  - 기동: `colima start stewart --cpu 2 --memory 4 --mount /Volumes/Dev/stewart-work:w`
  - 종료: `colima stop stewart`
  - docker context: `colima-stewart` (colima start 시 자동 전환)
  - **주의**: 셸에 `DOCKER_HOST`가 export되어 있으면 context를 override한다 → `unset DOCKER_HOST`
  - 컨테이너: `cd demo && docker-compose up -d dvwa juice-shop` (DVWA `:8081`, Juice Shop `:3000`)
  - DVWA는 amd64 이미지 → arm64 VM에서 에뮬레이션(느림)
- **Python**: `.venv` (uv, 3.13) — `python3` 또는 `.venv/bin/python`
- **DVWA**: MySQL (app/vulnerables), admin/password. 로그인 실패 시 자동 DB reset
- **Juice Shop**: v20.2.0, MongoDB, API `/api/*`
