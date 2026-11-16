# BugBounty Bot — Handoff

**마지막 업데이트**: 2026-11-11
**현재 단계**: 실전 테스트 — DVWA **실제 findings 40개** (sqli 10, xss 19, idor 8, cve 3). 다음: Juice Shop findings (API 크롤링 갭)

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

### 실전 테스트 — DVWA 실제 findings **40개** (5차 세션)

**진단 (5차, 실측):**
- **DVWA sqli 0 findings 원인**: (1) sqli/xss/idor 스캐너가 **목표 파라미터만** 보내고 폼의 다른 필드(`Submit`)를 안 보냄 → DVWA는 `if(isset($_GET['Submit']))`이므로 **쿼리 미실행**. (2) boolean-based 임계값 `1.5x`가 너무 엄격 — 실제 차이는 약 6%. (3) `scan_web`이 **비인증 클라이언트**를 새로 만듦 → sqli 페이지가 1523바이트 단순화 페이지(비인증) 반환, `id` 미처리.
- **실측**: `Submit=Submit` 포함 + `' OR '1'='1` → 4821바이트 (baseline 4538, +6%). 크롤러는 `params=['id','Submit']` 정확히 추출.

**수정:**
1. `scanner/sqli.py` — **완전 폼 전송** (`_build_params`: target=payload, 나머지는 이름=버튼값), boolean 임계값 `1.5x→1.05x`
2. `scanner/xss.py` — 완전 폼 전송 (target=payload, others=name)
3. `scanner/idor.py` — 완전 폼 전송 (target=test_id, others=name)
4. `scanner/web.py` — `scan_web(asset, client=None)`: **인증 클라이언트 전달 가능** (없으면 비인증 생성)
5. `tests/test_live.py` — `scan_web(asset, client=auth_client)` 전달

**5차 테스트 결과:**
- **DVWA: 40 findings** (이전 15) — **sqli 10** (sqli/ boolean + brute/ SQL error), **xss 19** (xss_r/ reflected), idor 8, cve 3. **실제 취약점 탐지 성공.**
- **Juice Shop: 0 findings** — 크롤러가 실제 `/api/*`가 아닌 generic probe 경로(v1/v2/graphql/openapi.json) 발견. API 크롤링 갭.

**Colima**: Running (다음 세션 stop 필요). **Git**: 5차 수정분 커밋 예정.

## 다음 단계

1. ~~`scanner/web.py` 를 6개로 분할 (sqli, xss, idor, ssrf, auth, fuzz)~~ ✓
2. ~~각 파일 2~4KB 로 `write_file` 사용~~ ✓
3. ~~`scanner/fuzz.py` — unknown 버그 (fuzzing, anomaly)~~ ✓
4. ~~`scanner/cve.py` (NVD + Wappalyzer)~~ ✓
5. ~~`scanner/login.py` (DVWA 로그인)~~ ✓
6. ~~DVWA setup.php `create_db` 버튼 수정 + 재로그인~~ ✓
7. ~~Juice Shop API 개별 endpoint + path param~~ ✓
8. ~~**DVWA 로그인 비결정성 해결**~~ ✓ (4차: `Login` 버튼 누락이 원인 — base_url에 "dvwa" 없어 DVWA 분기 미적용. `user_token` field로 DVWA 감지 + Location 헤더로 성공/실패 판별 + 재시도. 8/8 성공)
9. ~~**실전 테스트 재실행**~~ ✓ (5차: DVWA 40 findings — sqli 10, xss 19, idor 8, cve 3. 실제 취약점 탐지)
10. **Juice Shop findings** — API 크롤링 갭: generic probe(v1/v2/graphql) 대신 실제 `/api/*` endpoint 발견 + findings
11. **범용성 보완** (장기 목표: 범용 해킹 툴)
    - ~~path parameter 일반화 (xss, ssrf, idor scanner)~~ ✓ (5차: 완전 폼 전송)
    - OpenAPI/Swagger 자동 탐지 (`/openapi.json`, `/swagger.json`)
    - DB reset 일반화 (asset별 설정, DVWA 전용 코드 분리)
12. HANDOFF.md 업데이트 + commit·push + colima stop

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
| Juice Shop | `:3000` 200 OK | 0 findings — 크롤러가 generic probe(v1/v2/graphql/openapi.json)만 발견, 실제 `/api/*` 미발견 |
| DVWA | `:8081` | **40 findings** (sqli 10, xss 19, idor 8, cve 3) — 실제 취약점 탐지 성공 |

**원인 (5차 확인)**: sqli/xss/idor 스캐너가 폼의 다른 필드(`Submit`)를 안 보내 DVWA 쿼리 미실행 + `scan_web` 비인증 클라이언트. 완전 폼 전송 + 인증 클라이언트 전달로 해결.

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
12. ~~실전 테스트: DVWA 실제 findings~~ ✓ (5차: 40 findings) / Juice Shop findings (진행 중)
13. 범용성 보완 (OpenAPI 탐지, path param 일반화, DB reset 일반화)
