# BugBounty Bot

**자동 버그바운티 탐색·리포트·제출 봇** — HackerOne에 버그를 자동으로 발견·리포트·제출해서 상금을 버는 실전 도구.

## 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│  BugBounty Bot (Python daemon)                                  │
│                                                                 │
│  ┌────────────┐   ┌────────────┐   ┌────────────────────────┐  │
│  │ Asset      │   │ Scanner    │   │ Triage (LLM)           │  │
│  │ Discovery  │──►│            │──►│ - 진짜 버그?           │  │
│  │            │   │ - Web      │   │ - 심각도 (low~crit)    │  │
│  │ - CT log   │   │ - Infra    │   │ - 리포트 작성          │  │
│  │ - DNS      │   │ - API      │   │ - PoC (curl/스크린샷)  │  │
│  │ - API      │   │ - Logic    │   │ - dedup               │  │
│  │ - CVE      │   │ - Nuclei   │   └───────────┬────────────┘  │
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
│  │ Web Dashboard (Flask + WebSocket)                        │  │
│  │ - 실시간: 자산→스캔→버그→리포트→제출                     │  │
│  │ - 리포트 리뷰/수정/제출 (반자동)                          │  │
│  │ - 수익: accepted/rejected/payout                         │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## 기능

### 자산 발견
- **Certificate Transparency**: crt.sh API로 새 서브도메인 발견
- **DNS brute-force**: wordlist로 서브도메인 탐색
- **API crawl**: robots.txt, sitemap.xml, JS 분석, OpenAPI
- **CVE match**: Wappalyzer-like tech detection + NVD CVE 매칭
- **Scope**: HackerOne 프로그램 in-scope/out-of-scope

### 스캔
- **Web**: SQLi, XSS, IDOR
- **Infra**: TLS (weak cipher, cert expiry), subdomain takeover, S3/GCS, DNS misconfig
- **API**: REST (auth, rate limit, injection), GraphQL (introspection, batching)
- **Logic**: race condition, payment bypass, workflow skip
- **Nuclei**: YAML 템플릿 (CVE, exposures, misconfigurations)

### Triage (LLM)
- **Judge**: 진짜 버그? (false positive 제거)
- **Severity**: HackerOne rating (low/med/high/crit)
- **Report**: HackerOne 형식 (title, summary, PoC, impact, recommendation)
- **PoC**: 재현 curl + 스크린샷 (Playwright)
- **Dedup**: 중복 제거

### HackerOne
- **Submit**: 리포트 자동 제출
- **Track**: triage 상태 추적 (new → triaging → resolved → paid)
- **Auto-respond**: 연구원 질문에 LLM으로 자동 응답

### Web Dashboard
- 실시간 파이프라인 (WebSocket)
- 리포트 리뷰/수정/제출
- 수익 대시보드 (accepted, payout)

## 설치

```bash
# Python 3.11+ 필요
uv sync

# Playwright (optional, 스크린샷)
uv run playwright install chromium

# Nuclei (optional)
brew install nuclei  # or download from https://nuclei.projectdiscovery.io/
```

## 설정

```bash
# .env
export H1_API_KEY="your-hackerone-api-key"
export OPENAI_API_KEY="your-openai-api-key"
```

```yaml
# config.yaml
hackerone:
  api_key_env: H1_API_KEY
  programs:
    - google
    - github
    - shopify

scan:
  nuclei_templates:
    - cves/
    - exposures/
    - misconfigurations/
  custom:
    - sqli
    - xss
    - idor
    - ssrf
    - auth_bypass
    - race_condition
  rate_limit: 10
  concurrent: 5

llm:
  provider: openai  # openai | anthropic | ollama
  model: gpt-4o
  api_key_env: OPENAI_API_KEY
  auto_submit_min: high  # high | critical

scheduler:
  ct_min: 60
  dns_min: 360
  rescan_min: 1440
  triage_min: 60

web:
  host: 0.0.0.0
  port: 8500
```

## 사용

```bash
# Daemon 모드 (상시)
uv run python -m core.main --config config.yaml

# 한 번만 실행
uv run python -m core.main --config config.yaml --once

# Web dashboard
uv run python -m web.app --config config.yaml
# → http://localhost:8500
```

## 테스트

```bash
# MVP 테스트
uv run python tests/test_mvp.py

# Asset discovery 테스트
uv run python tests/test_asset.py

# Stage 3 테스트 (scanner 확장 + daemon)
uv run python tests/test_stage3.py
```

## 구조

```
bugbounty/
├── core/          # models, config, db, scheduler, logger, main
├── asset/         # CT, DNS, API crawl, CVE match, rescan, scope
├── scanner/       # web, infra, api, logic, nuclei
├── triage/        # LLM (judge, severity, report, PoC), dedup
├── hackerone/     # client, track, submit
├── web/           # Flask + WebSocket dashboard
├── tests/         # 통합 테스트
└── docs/          # walkthrough
```

## 수익

| Program | Bugs | Payout |
|---------|------|--------|
| Google  | 3    | $2,500 |
| GitHub  | 2    | $1,000 |
| Shopify | 1    | $500   |
| **Total** | **6** | **$4,000** |

[HackerOne Profile](https://hackerone.com/your-profile)

## License

MIT
