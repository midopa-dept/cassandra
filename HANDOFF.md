# BugBounty Bot — Handoff

**마지막 업데이트**: 2026-11-10
**현재 단계**: 재설계 중 (scanner 분할)

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

### 재설계 — 진행 중
- `core/models.py` — `Asset.base_url` + `Endpoint` dataclass 추가 ✓
- `asset/crawl.py` — 웹 크롤러 (224줄) ✓
- `scanner/web.py` — 17줄 truncation (14KB → 17줄) ✗

## 현재 문제

### scanner/web.py truncation

`write_file` 로 14KB 파일 쓰려는데 17줄로 truncation.

| 시도 | 방법 | 결과 |
|------|------|------|
| 1 | `write_file` (14KB) | 17줄 truncation |
| 2 | `cat > file << 'EOF'` | timeout (120초) |
| 3 | `python3 -c "..."` | syntax error (quote escaping) |
| 4 | `python3 << 'HEREDOC'` | timeout (30초) |
| 5 | `python3 -c '...'` | syntax error (line 15) |
| 6 | `python3 -c "..."` | syntax error (line 6) |

### 해결 방안

**파일 분할** — `scanner/web.py` 를 6개로 분할:

```
scanner/
├── web.py          # scan_web() orchestrator (2KB)
├── sqli.py         # SQLi scanner (4KB)
├── xss.py          # XSS scanner (3KB)
├── idor.py         # IDOR scanner (2KB)
├── ssrf.py         # SSRF scanner (2KB)
└── auth.py         # Auth bypass scanner (2KB)
```

각 파일 2~4KB → `write_file` truncation 회피.

## 다음 단계

1. `scanner/web.py` 를 6개로 분할 (sqli, xss, idor, ssrf, auth, fuzz)
2. 각 파일 2~4KB 로 `write_file` 사용
3. `scanner/cve.py` (NVD + Wappalyzer)
4. `scanner/login.py` (DVWA 로그인)
5. 실전 테스트: DVWA + Juice Shop 에서 실제 findings
6. HANDOFF.md 업데이트

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
│   ├── web.py          # 17줄 truncation (14KB → 17줄)
│   ├── infra.py
│   ├── api.py
│   ├── logic.py
│   ├── nuclei.py
│   ├── sqli.py         # 미작성
│   ├── xss.py          # 미작성
│   ├── idor.py         # 미작성
│   ├── ssrf.py         # 미작성
│   ├── auth.py         # 미작성
│   ├── fuzz.py         # 미작성 (unknown 버그)
│   ├── cve.py          # 미작성 (CVE 기반)
│   └── login.py        # 미작성 (DVWA 로그인)
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
| Juice Shop | `:3000` 200 OK | `/api/products` 만 200, scanner 0 findings |
| DVWA | `:8081` 302→login.php | 로그인 필요, scanner 0 findings |

**원인**: `scan_web(asset)` 는 `asset.endpoints` 를 순회하는데, endpoints 가 비어있거나, 쿼리 파라미터 (`?id=1`) 를 자동 탐지 안 함.

## 해결 방안

1. `Asset` 에 `base_url` 필드 추가 (완료)
2. `Endpoint` dataclass 추가 (완료)
3. `asset/crawl.py` 로 endpoint 자동 수집 (완료)
4. `scanner/web.py` 를 6개로 분할 (진행 중)
5. 각 scanner (sqli, xss, idor, ssrf, auth) 가 `base_url + endpoint + param` 으로 실제 HTTP 요청
6. `scanner/fuzz.py` — unknown 버그 (fuzzing, anomaly)
7. `scanner/cve.py` — CVE 기반 (NVD + Wappalyzer)
8. `scanner/login.py` — 인증 처리 (DVWA 등)
9. 실전 테스트: DVWA + Juice Shop 에서 실제 findings
