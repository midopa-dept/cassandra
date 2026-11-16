# BugBounty Bot — Handoff

**마지막 업데이트**: 2026-11-11
**현재 단계**: 실전 테스트 진행 중 — DVWA session 문제 분석 완료, 해결 방안 수립

## 완료된 작업

### MVP (단계 1) — 완료
- `core/` — models, config, db, scheduler, logger, main
- `scanner/web.py` — SQLi, XSS, IDOR (17줄 truncation)
- `triage/llm.py` — LLM (judge, severity, report, PoC)
- `triage/dedup.py` — 중복 제거
- `hackerone/client.py` — GraphQL API
- `web/app.py` + `dashboard.html` — Flask 대시보드
- `tests/test_mvp.py` — 통합 테스트 (4/4 통과)

### 단계 2: asset/ — 완료
- `asset/ct.py` — Certificate Transparency
- `asset/dns.py` — DNS brute-force
- `asset/api_crawl.py` — robots, sitemap, JS, OpenAPI
- `asset/cve_match.py` — Wappalyzer + NVD
- `asset/rescan.py` — 재스캔
- `asset/scope.py` — HackerOne scope
- `tests/test_asset.py` — 6/6 통과

### 단계 3: scanner/ 확장 — 완료
- `scanner/infra.py` — TLS, subdomain takeover, S3/GCS
- `scanner/api.py` — REST/GraphQL
- `scanner/logic.py` — race condition, payment bypass
- `scanner/nuclei.py` — Nuclei CLI
- `triage/poc.py` — Playwright 스크린샷
- `core/main.py` — daemon 모드
- `tests/test_stage3.py` — 6/6 통과

### 단계 4: 자동화 + 명성 — 완료
- `hackerone/track.py` — triage 상태 추적
- `hackerone/submit.py` — auto-submit
- `web/app.py` — WebSocket
- `README.md`, `LICENSE`, `docs/walkthrough.md`
- `demo/docker-compose.yml`, `demo/demo.sh`
- `.github/workflows/ci.yml`
- `tests/test_stage4.py` — 3/3 통과

### 재설계 — 완료
- `core/models.py` — `Asset.base_url` + `Endpoint` dataclass 추가 ✓
- `asset/crawl.py` — 웹 크롤러 (224줄) ✓
- `scanner/web.py` — orchestrator (39줄) ✓
- `scanner/sqli.py` — SQLi scanner (110줄) ✓
- `scanner/xss.py` — XSS scanner (81줄) ✓
- `scanner/idor.py` — IDOR scanner (76줄) ✓
- `scanner/ssrf.py` — SSRF scanner (92줄) ✓
- `scanner/auth.py` — Auth bypass scanner (98줄) ✓
- `scanner/fuzz.py` — Fuzzing/Anomaly scanner (144줄) ✓
- `scanner/cve.py` — CVE scanner (121줄) ✓
- `scanner/login.py` — Login/auth handler (148줄) ✓

## 현재 문제

### scanner/web.py truncation — 해결됨

`write_file` 로 14KB 파일 쓰려는데 17줄로 truncation.

**해결**: 파일 분할로 완료. `scanner/web.py` (39줄 orchestrator) + 7개 개별 scanner (sqli, xss, idor, ssrf, auth, fuzz, cve) + login.

### 실전 테스트 — 진행 중

Docker/colima 기동 완료. DVWA(:8081) + Juice Shop(:3000) 컨테이너 Running.

**1차 테스트 결과:**
- DVWA: 3 findings (CVE — Apache HTTP/2 rapid reset) — 실제 취약점 아님
- Juice Shop: 0 findings

**문제:**
1. DVWA: 로그인 POST 302→setup.php (성공)인데, 그 cookie 로 `/vulnerabilities/sqli/` GET 시 302→login.php (미인증). **원인: DB 미초기화** — setup.php 에서 "Create/Reset Database" 를 안 누르면 session 이 유지 안 됨.
2. Juice Shop: API endpoint 는 찾지만 params 가 비어서 scanner 가 payload 를 못 주입.

**해결 방안:**
1. DVWA: login 후 setup.php 로 가서 DB reset (POST `Reset=Reset` + `user_token`) → 그 다음 authenticated crawl
2. Juice Shop: API endpoint 에 기본 params (`?id=1`, `?name=test`) 주입해서 scanner 테스트

**2차 테스트 결과 (DB reset 후):**
- DVWA: login(302→setup.php) → setup.php GET(200) → DB reset POST(200, success) → `/` GET(302→login.php) → sqli GET(302→login.php)
- **문제**: DB reset 성공 후에도 session 이 유지 안 됨. reset 후 `/` 로 가면 302→login.php.
- **원인 (추측)**: DVWA 의 `session_regenerate_id()` 가 reset 시 호출되어 PHPSESSID 가 변경됨. reset 후 **다시 로그인**해야 함.
- **해결**: reset 후 login.php 로 다시 로그인 (2단계 로그인) 또는 reset 후 setup.php 의 "Continue" 링크를 따라감.

**Juice Shop:**
- API endpoint 는 찾지만 params 가 비어서 scanner 가 payload 를 못 주입.
- **해결**: API endpoint 에 기본 params (`?id=1`, `?name=test`) 주입해서 scanner 테스트.

**Colima**: 종료 완료. 다음 테스트 시 `colima start` 후 `docker-compose up -d dvwa juice-shop`.

## 다음 단계

1. ~~`scanner/web.py` 를 6개로 분할 (sqli, xss, idor, ssrf, auth, fuzz)~~ ✓
2. ~~각 파일 2~4KB 로 `write_file` 사용~~ ✓
3. ~~`scanner/fuzz.py` — unknown 버그 (fuzzing, anomaly)~~ ✓
4. ~~`scanner/cve.py` (NVD + Wappalyzer)~~ ✓
5. ~~`scanner/login.py` (DVWA 로그인)~~ ✓
6. 실전 테스트: DVWA + Juice Shop 에서 실제 findings (진행 중)
   - DVWA: DB 초기화 + authenticated crawl 수정 필요
   - Juice Shop: API params 탐지 보완 필요
7. HANDOFF.md 업데이트

## 파일 목록

```
bugbounty/
├── PLAN.md
├── HANDOFF.md
├── README.md
├── LICENSE
├── pyproject.toml
├── uv.lock
├── .env
├── .env.example
├── config.yaml
├── Dockerfile
├── .github/
│   └── workflows/
│       └── ci.yml
├── core/
│   ├── __init__.py
│   ├── models.py       # Asset, Endpoint, Finding, Report, Submission
│   ├── config.py
│   ├── db.py
│   ├── scheduler.py
│   ├── logger.py
│   └── main.py
├── asset/
│   ├── __init__.py
│   ├── ct.py
│   ├── dns.py
│   ├── api_crawl.py
│   ├── cve_match.py
│   ├── rescan.py
│   ├── scope.py
│   └── crawl.py        # 웹 크롤러 (224줄)
├── scanner/
│   ├── __init__.py
│   ├── web.py          # orchestrator (39줄)
│   ├── infra.py
│   ├── api.py
│   ├── logic.py
│   ├── nuclei.py
│   ├── sqli.py         # SQLi scanner (110줄)
│   ├── xss.py          # XSS scanner (81줄)
│   ├── idor.py         # IDOR scanner (76줄)
│   ├── ssrf.py         # SSRF scanner (92줄)
│   ├── auth.py         # Auth bypass scanner (98줄)
│   ├── fuzz.py         # Fuzzing/Anomaly scanner (144줄)
│   ├── cve.py          # CVE scanner (121줄)
│   └── login.py        # Login/auth handler (148줄)
├── triage/
│   ├── __init__.py
│   ├── llm.py
│   ├── dedup.py
│   └── poc.py
├── hackerone/
│   ├── __init__.py
│   ├── client.py
│   ├── track.py
│   └── submit.py
├── web/
│   ├── __init__.py
│   ├── app.py
│   ├── templates/
│   │   └── dashboard.html
│   └── static/
│       ├── css/
│       └── js/
├── demo/
│   ├── docker-compose.yml
│   └── demo.sh
├── docs/
│   └── walkthrough.md
└── tests/
    ├── test_mvp.py
    ├── test_asset.py
    ├── test_stage3.py
    └── test_stage4.py
```

## 테스트 결과

| 테스트 | 내용 | 결과 |
|--------|------|------|
| test_mvp.py | scanner + triage + hackerone + web | ✓ 4/4 |
| test_asset.py | CT + DNS + API + CVE + rescan + scope | ✓ 6/6 |
| test_stage3.py | infra + api + logic + nuclei + poc + daemon | ✓ 6/6 |
| test_stage4.py | track + submit + websocket | ✓ 3/3 |

**총 19개 테스트 모두 통과** (Mock 서버 기반)

## 실전 테스트

| 앱 | 상태 | 문제 |
|----|------|------|
| Juice Shop | `:3000` 200 OK | `/api/products` 만 200, scanner 0 findings — API params 미탐지 |
| DVWA | `:8081` 302→login.php | 로그인 성공(302→setup.php)인데 DB 미초기화로 session 유지 안 됨 |

**원인**: DVWA 는 setup.php 에서 DB reset 을 해야 session 이 유지됨. Juice Shop 은 API endpoint 에 params 가 없어서 scanner 가 payload 를 못 주입.

## 해결 방안

1. `Asset` 에 `base_url` 필드 추가 (완료)
2. `Endpoint` dataclass 추가 (완료)
3. `asset/crawl.py` 로 endpoint 자동 수집 (완료)
4. ~~`scanner/web.py` 를 6개로 분할~~ (완료)
5. 각 scanner (sqli, xss, idor, ssrf, auth) 가 `base_url + endpoint + param` 으로 실제 HTTP 요청 (완료)
6. ~~`scanner/fuzz.py` — unknown 버그 (fuzzing, anomaly)~~ (완료)
7. ~~`scanner/cve.py` — CVE 기반 (NVD + Wappalyzer)~~ (완료)
8. ~~`scanner/login.py` — 인증 처리 (DVWA 등)~~ (완료)
9. 실전 테스트: DVWA + Juice Shop 에서 실제 findings
