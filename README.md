# BugBounty Bot

**처음 보는(알지 못하는) 웹사이트에서 취약점을 자동으로 찾아, HackerOne에 제출해서 상금을 버는** 자동화 도구.

Python 기반. 자산 발견 → 스캔 → LLM triage → HackerOne 제출까지, 사람이 버그바운티를 하는 4단계를 자동화합니다.

---

## 이것이 무엇인가

버그바운티는 "타인의 웹사이트에서 버그를 찾아 신고하면 상금을 받는" 제도입니다. 이 봇은 그 과정을 자동화합니다.

**가장 중요한 구분** 하나:

- **최종 목표 (North Star)**: *알지 못하는 실제* 웹사이트에서 버그를 찾아 돈 버는 것.
- **DVWA·Juice Shop**: 이걸 *검증하기 위한* 학습용 앱. 목표가 아닙니다.

왜 이렇게 구분하는가? DVWA·Juice Shop은 **의도적으로** 취약하게 만든 앱입니다. 이 두 앱에 맞춰 코드를 짜면(과최적화), 진짜 새 웹사이트에서는 안 먹힙니다. 그래서 이 프로젝트는 **일반화**를 원칙으로 삼고, 두 앱을 "봇이 실제로 버그를 잡는지"를 재는 **시험대**로만 씁니다.

---

## 어떻게 동작하는가

사람이 버그바운티를 하는 4단계를 그대로 자동화합니다.

```
① 자산 발견          ② 스캔              ③ Triage (LLM)      ④ HackerOne
"어디를 볼까?"  →  "여기서 버그가  →  "이거 진짜 버그?   →  "제출하고
(서브도메인,      있나?"            심각도 몇? 리포트    상태 추적,
 API, CVE)        (SQLi, XSS, ...)  써라"                상금 기록
```

1. **자산 발견** — crt.sh(서명 투명성 로그), DNS 브루트포스, robots.txt/sitemap/JS 크롤, CVE 매칭으로 "어떤 도메인·서브도메인·API를 봐야 하는지" 모읍니다.
2. **스캔** — 각 엔드포인트에 공격 payload를 주입해 취약점 신호를 잡습니다.
3. **Triage (LLM)** — 스캐너는 "의심"만 줍니다. LLM이 "이거 진짜 버그인가? 심각도는? HackerOne 형식으로 리포트 써라"를 2차 판단합니다. **오탐(false positive) 제거**가 핵심.
4. **HackerOne** — 리포트를 제출하고, triage 상태(new→triaging→resolved→paid)를 추적, 연구원 질문에 자동 응답.

이 4단계는 `asset/`(①)·`scanner/`(②)·`triage/`(③)·`hackerone/`(④) 폴더로, 공통 데이터 모델·DB·스케줄러는 `core/`에, 실시간 대시보드는 `web/`에 있습니다.

---

## 스캐너 — 실제로 무엇을 잡는가

프로젝트의 **심장**입니다. 처음에는 `scanner/web.py` 하나에 모든 걸 넣다가, **재설계**로 16개 모듈로 쪼개었습니다.

| 모듈 | 잡는 것 |
|------|---------|
| `sqli.py` | SQL 인젝션 (boolean / time-based blind / union / error) |
| `xss.py` | Reflected XSS, **DOM XSS**(JS 번들 sink+source), **Stored XSS**(저장→반사) |
| `idor.py` | IDOR (다른 사용자 ID로 접근) |
| `ssrf.py` | SSRF |
| `auth.py` | 인증 우회 (HTTP method override 등) |
| `fuzz.py` | 이상 탐지 (status code 변화) |
| `cve.py` | CVE 매칭 (tech detection + NVD) |
| `api.py` | REST API (auth, rate limit, body injection) |
| `file.py` | 파일 업로드 RCE, path traversal |
| `session.py` | **Weak Session**, **Insecure CAPTCHA**, **Password Reset** |
| `llm.py` | **LLM 스캐너** — 페이지 이해→공격 계획→실행→판정 (7b) |
| `login.py` | 로그인/세션 처리 (DVWA·Juice Shop) |
| `web.py` | **orchestrator** — 위 모듈들을 모두 호출 |

**중요한 원칙**: 각 스캐너는 "이 앱이 DVWA라서"가 아니라 **보편적 신호**로 판별합니다. 예를 들어 `session.py`:

- **Weak Session** — 엔드포인트를 반복 요청 → Set-Cookie를 모은다 → 그 cookie가 *매번 새로 발급되고*, 값이 *순차(1,2,3,4)·짧음·엔트로피 낮음*이면 "예측 가능한 세션"으로 판정. 특정 cookie 이름을 하드코딩하지 않습니다.
- **Insecure CAPTCHA** — reCAPTCHA의 `sitekey`가 비거나, "key missing" 경고가 있거나, 같은 세션에서 CAPTCHA 이미지가 *다시 발급되지 않으면* "우회 가능"으로 판정.

---

## 개발 진행

22개 커밋이 이 여정을 보여줍니다. 순서대로:

1. **MVP** — 4단계 파이프라인의 뼈대 (core + 기본 스캐너 + LLM triage + HackerOne + 대시보드)
2. **자산 발견** — CT / DNS / API crawl / CVE / rescan / scope
3. **확장** — infra / api / logic / nuclei / PoC(Playwright) / daemon
4. **자동화** — auto-submit / track / WebSocket / CI / demo
5. **명성** — README / demo / walkthrough / LICENSE
6. **재설계** — `scanner/web.py`를 16개 모듈로 분할 + `login.py` (이후 확장성의 기반)
7. **알려진 취약점 커버리지** — DVWA·Juice Shop의 *알려진* 취약점을 하나씩 더 많이 잡도록 스캐너를 확장 (아래)

**"알려진 취약점 커버리지"**는 블록 단위로 나눴고, 각 블록마다 "실제로 잡는지"를 DVWA·Juice Shop에서 live 테스트로 확인한 뒤 `docs/VULN_REPORT.md`에 기록했습니다.

| 블록 | 추가한 것 | 결과 |
|------|----------|------|
| **6a** API/NoSQL | NoSQLi, Admin Registration, OpenAPI 노출 | Juice Shop findings 11→21 |
| **6b** XSS 확장 | DOM XSS, Stored XSS | DVWA 40→42, Juice Shop 21→22 |
| **6c** 파일/업로드 | File Upload RCE, Path Traversal | DVWA 42→43 |
| **6d** 인증/세션 | **Weak Session, Insecure CAPTCHA**, Password Reset | DVWA에서 둘 다 실제 발견 |
| **6e** 로직/인프라 | Race Condition, Payment Bypass, DNS/TLS | scanner 버그 수정 + 통합 (실전 도메인에서 동작) |
| **7** 일반화 | **LLM scanner**, bWAPP + WebGoat 벤치마크 | LLM이 페이지를 이해해 공격 계획·실행·판정. 4개 벤치마크 검증 |

**"발견률"이라는 측정 기준**이 있습니다. DVWA는 알려진 취약점 카테고리 ~13개, Juice Shop은 ~20+ 챌린지. 우리가 몇 개를 자동 발견했는지를 계속 재고 있습니다.

| 앱 | 알려진 취약점 | 자동 발견 | 발견률 |
|----|:----------:|:--------:|:------:|
| DVWA | ~13개 | **~10개** | **~77%** |
| Juice Shop | ~20+개 | **~5개** | **~25%** |
| bWAPP | ~15+개 | **~0개** (정적) | LLM scanner로 보완 |
| WebGoat | ~15+개 | **~3개** (XSS) | LLM scanner로 보완 |

**다음 단계**:
- **8** — 실전: *알지 못하는 실제* HackerOne 프로그램에서 자동 스캔→triage→제출 (**North Star**)

---

## 설치

```bash
# Python 3.11+ 필요
uv sync

# Playwright (optional, 스크린샷)
uv run playwright install chromium

# Nuclei (optional)
brew install nuclei   # or https://nuclei.projectdiscovery.io/
```

## 설정

`.env.example`를 `.env`로 복사해 API 키를 채웁니다 (`.env`는 gitignore 대상).

```bash
cp .env.example .env
# .env 편집: H1_API_KEY, OPENAI_API_KEY (, ANTHROPIC_API_KEY)
```

`config.yaml`에서 HackerOne 프로그램, 스캔 옵션, LLM, 스케줄러, 대시보드 포트를 설정합니다.

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

## 데모 (DVWA + Juice Shop)

봇을 실제로 돌려보는 가장 쉬운 방법입니다.

```bash
# 1. .env에 H1_API_KEY, OPENAI_API_KEY 설정
# 2. DVWA + Juice Shop + 봇을 함께 띄움
./demo/demo.sh
```

- DVWA: http://localhost:8081
- Juice Shop: http://localhost:3000
- bWAPP: http://localhost:8082
- WebGoat: http://localhost:8083/WebGoat
- BugBounty Bot: http://localhost:8500

```bash
# 전체 파이프라인(crawl → scan)을 두 벤치마크에서 돌려 findings 확인
uv run python tests/test_live.py
```

## 테스트

```bash
uv run python tests/test_mvp.py      # MVP
uv run python tests/test_asset.py    # 자산 발견
uv run python tests/test_stage3.py   # scanner 확장 + daemon
uv run python tests/test_live.py     # DVWA + Juice Shop 실전
```

## 구조

```
bugbounty/
├── core/          # models, config, db, scheduler, logger, main
├── asset/         # CT, DNS, API crawl, CVE match, rescan, scope
├── scanner/       # 16개 모듈 (sqli, xss, idor, ssrf, auth, fuzz, cve,
│                  #   api, file, session, llm, login) + web.py orchestrator
├── triage/        # LLM (judge, severity, report, PoC), dedup
├── hackerone/     # client, track, submit
├── web/           # Flask + WebSocket dashboard
├── demo/          # docker-compose (DVWA + Juice Shop + bWAPP + WebGoat)
├── tests/         # 통합 테스트
└── docs/          # VULN_REPORT, walkthrough
```

## 문서

- [`docs/VULN_REPORT.md`](docs/VULN_REPORT.md) — DVWA·Juice Shop에서 실제로 무엇을 발견했는지, exploit 실측 결과, 알려진 취약점 대조, 발견률
- [`docs/walkthrough.md`](docs/walkthrough.md) — 코드 설명 ("왜 이렇게 만들었나")
- [`PLAN.md`](PLAN.md) — 전체 계획 (North Star, 단계 1~8)
- [`HANDOFF.md`](HANDOFF.md) — 현재 상태·진행·다음 단계

## License

MIT
