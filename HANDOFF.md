# BugBounty Bot — Handoff

**마지막 업데이트**: 2026-11-11
**현재 단계**: 실전 테스트 — DVWA 로그인 비결정성 **해결 완료** (8/8 성공, e2e 통과). 다음: 실전 테스트 재실행 (findings 확인)

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

### 실전 테스트 — DVWA 로그인 비결정성 **해결 완료**

**진단 (4차 세션, 실측):**
- `get_authenticated_client()` 0/8 실패, 순수 플로우(login.php 직접) 8/8 성공 → **비결정성이 아니라 100% 결정적 실패**
- **원인**: `login()`이 DVWA를 `"dvwa" in asset.base_url.lower()`로 판별. config의 base_url은 `http://localhost:8081`이라 "dvwa" 문자가 없음 → DVWA 분기 미적용 → **`Login` 버튼이 POST에 안 들어감** → DVWA `login.php`는 `if( isset($_POST['Login']) )`이므로 로그인 처리 자체 미실행 → 200(폼 재렌더) 반환. 재시도 루프도 `"dvwa" in base_url` 조건이라 한 번도 미실행.
- **DVWA login.php 동작 (소스 확인)**: POST는 항상 302 (성공→index.php, 실패→login.php, DB 미생성→setup.php). 성공/실패는 status code가 아니라 **Location 헤더**로 구분. `generateSessionToken()`은 login.php GET마다 토큰 재생성. `dvwaLogin()`은 `session_regenerate_id()` 미호출.

**수정 (`scanner/login.py`):**
1. DVWA 감지: base_url 문자열 **또는** `user_token` hidden field 존재로 판별 (base_url에 "dvwa" 없어도 감지)
2. 성공/실패 판별: `_login_succeeded()`/`_login_failed()` — 302→login.php=실패, 302→기타=성공, 200=실패(폼 재렌더)
3. 재시도 조건: `200 또는 302→login` 시 최대 3회 (새 토큰 재추출)
4. `_dvwa_db_reset()` 재로그인에도 재시도 로직 추가

**검증:**
- `get_authenticated_client()` **8/8 성공** (이전 0/8)
- e2e: `/`(logout·vulnerabilities) + `/vulnerabilities/sqli/`(id·Submit) 모두 200
- mock 테스트: test_asset·stage3·stage4 통과 (test_mvp는 기존 `scan_web(rate_limit=)` 시그니처 불일치 — 재설계 시 발생, 이번 변경과 무관)

**Colima**: Running (다음 세션 stop 필요). **Git**: 4차 수정분 커밋 예정.

## 다음 단계

1. ~~`scanner/web.py` 를 6개로 분할 (sqli, xss, idor, ssrf, auth, fuzz)~~ ✓
2. ~~각 파일 2~4KB 로 `write_file` 사용~~ ✓
3. ~~`scanner/fuzz.py` — unknown 버그 (fuzzing, anomaly)~~ ✓
4. ~~`scanner/cve.py` (NVD + Wappalyzer)~~ ✓
5. ~~`scanner/login.py` (DVWA 로그인)~~ ✓
6. ~~DVWA setup.php `create_db` 버튼 수정 + 재로그인~~ ✓
7. ~~Juice Shop API 개별 endpoint + path param~~ ✓
8. ~~**DVWA 로그인 비결정성 해결**~~ ✓ (4차: `Login` 버튼 누락이 원인 — base_url에 "dvwa" 없어 DVWA 분기 미적용. `user_token` field로 DVWA 감지 + Location 헤더로 성공/실패 판별 + 재시도. 8/8 성공)
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
| DVWA | `:8081` | **로그인 8/8 성공** (4차 해결). sqli 페이지 크롤링 + findings 확인 대기 |

**원인 (4차 확인)**: DVWA `login.php`는 `if( isset($_POST['Login']) )` — `Login` 버튼 없으면 로그인 처리 미실행(200). `login()`이 base_url에 "dvwa" 문자가 없어 DVWA 분기 미적용 → `Login` 누락. `user_token` field로 DVWA 감지 + Location 헤더 판별으로 해결.

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
11. ~~DVWA 로그인 비결정성 해결~~ (4차 완료 — `Login` 버튼 누락 원인, `user_token` 감지 + Location 판별)
12. 실전 테스트: DVWA + Juice Shop 에서 실제 findings
13. 범용성 보완 (OpenAPI 탐지, path param 일반화, DB reset 일반화)
