# BugBounty Bot — Handoff

**마지막 업데이트**: 2026-11-11
**현재 단계**: 실전 테스트 — DVWA 로그인 비결정성 해결 중 (재시도 로직 추가, 검증 대기)

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

**2차 테스트 결과 (DB reset 후):**
- DVWA: login(302→setup.php) → setup.php GET(200) → DB reset POST(200, success) → `/` GET(302→login.php) → sqli GET(302→login.php)
- **문제**: DB reset 성공 후에도 session 이 유지 안 됨. reset 후 `/` 로 가면 302→login.php.
- **원인 (추측)**: DVWA 의 `session_regenerate_id()` 가 reset 시 호출되어 PHPSESSID 가 변경됨. reset 후 **다시 로그인**해야 함.

**3차 세션 (2026-11-11) — DVWA 로그인 플로우 완전 분석:**

1. **setup.php 버튼 이름**: `create_db` (value="Create / Reset Database"). 기존 `Reset=Reset` 은 DB 생성 실패. → `_dvwa_db_reset()` 수정 완료.

2. **정상 플로우 (수동 검증 성공)**:
   ```
   GET /login.php (200, user_token)
   → POST /login.php (302 → setup.php, DB 미생성 시)
   → GET /setup.php (200, user_token)
   → POST /setup.php create_db (302, DB 생성)
   → GET /login.php (200, 새 user_token)
   → POST /login.php (302 → index.php, 성공)
   → GET / (200, /vulnerabilities/* 링크)
   → GET /vulnerabilities/sqli/ (200, id= param)
   ```

3. **비결정성 (미해결)**: 같은 플로우가 때로는 302(성공), 때로는 200(실패). 수동 재현 4/4 성공, `get_authenticated_client()` 5/5 실패. 재시도 로직 추가(200 시 토큰 재추출+재POST, 최대 3회) — 추가됨, 검증 대기.

4. **크롤러**: `crawl()` 에 301/302/303/307/308 수동 추적 추가 (인증 클라이언트 follow_redirects=False 대응).

5. **Juice Shop**: `/api/Products/1`(대문자)=JSON, `/REST/products/1`(소문자)=SPA HTML. `crawl_api()` 는 `/api/*` 사용 — 정상. 리스트에서 첫 ID 추출 → 개별 endpoint + path param(`id`) 추가 완료.

6. **sqli.py**: path parameter injection + URL encoding 추가.

**수정된 파일 (3차, 미커밋):**
- `scanner/login.py` — `create_db` 버튼, 재로그인, 재시도 로직, 불필요한 GET 제거
- `asset/crawl.py` — 302 수동 추적, 개별 API endpoint + path param
- `scanner/sqli.py` — path param injection

**3차 테스트 결과:** DVWA 3 findings(CVE만, sqli 미크롤), Juice Shop 0 findings(11 endpoint, path param 주입됨). **목표 미달.**

**Colima**: Running (다음 세션 stop 필요). **Git**: a7b003a push 완료, 3차 수정분 미커밋.

## 다음 단계

1. ~~`scanner/web.py` 를 6개로 분할 (sqli, xss, idor, ssrf, auth, fuzz)~~ ✓
2. ~~각 파일 2~4KB 로 `write_file` 사용~~ ✓
3. ~~`scanner/fuzz.py` — unknown 버그 (fuzzing, anomaly)~~ ✓
4. ~~`scanner/cve.py` (NVD + Wappalyzer)~~ ✓
5. ~~`scanner/login.py` (DVWA 로그인)~~ ✓
6. ~~DVWA setup.php `create_db` 버튼 수정 + 재로그인~~ ✓
7. ~~Juice Shop API 개별 endpoint + path param~~ ✓
8. **DVWA 로그인 비결정성 해결** — 재시도 로직이 200을 실제로 감지하는지 로그 확인. `find_login_form` 의 10개 404 GET 이 session 에 영향을 주는지 확인. 필요 시 `find_login_form` 을 DVWA 전용으로 단순화 (login.php 직접)
9. **실전 테스트 재실행** — DVWA sqli/xss 페이지 크롤링 + findings 확인, Juice Shop findings 확인
10. **범용성 보완** (장기 목표: 범용 해킹 툴)
    - OpenAPI/Swagger 자동 탐지 (`/openapi.json`, `/swagger.json`)
    - path parameter 일반화 (xss, ssrf, idor scanner)
    - DB reset 일반화 (asset별 설정, DVWA 전용 코드 분리)
11. HANDOFF.md 업데이트 + commit·push + colima stop

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
| Juice Shop | `:3000` 200 OK | 11개 API endpoint 발견, path param 주입됨, 0 findings |
| DVWA | `:8081` | 로그인 비결정성 (302/200) — sqli 페이지 미크롤, 3 findings(CVE만) |

**원인**: DVWA 는 setup.php `create_db` 로 DB 생성 후 재로그인 필요. 로그인 POST 가 비결정적으로 200(실패) 반환. Juice Shop 은 API endpoint 발견 + path param 주입 완료, findings 0.

## 해결 방안

1. `Asset` 에 `base_url` 필드 추가 (완료)
2. `Endpoint` dataclass 추가 (완료)
3. `asset/crawl.py` 로 endpoint 자동 수집 (완료)
4. ~~`scanner/web.py` 를 6개로 분할~~ (완료)
5. 각 scanner (sqli, xss, idor, ssrf, auth) 가 `base_url + endpoint + param` 으로 실제 HTTP 요청 (완료)
6. ~~`scanner/fuzz.py` — unknown 버그 (fuzzing, anomaly)~~ (완료)
7. ~~`scanner/cve.py` — CVE 기반 (NVD + Wappalyzer)~~ (완료)
8. ~~`scanner/login.py` — 인증 처리 (DVWA 등)~~ (완료)
9. ~~DVWA setup.php `create_db` + 재로그인~~ (완료)
10. ~~Juice Shop API 개별 endpoint + path param~~ (완료)
11. DVWA 로그인 비결정성 해결 (진행 중)
12. 실전 테스트: DVWA + Juice Shop 에서 실제 findings
13. 범용성 보완 (OpenAPI 탐지, path param 일반화, DB reset 일반화)
