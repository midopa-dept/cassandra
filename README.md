<p align="center"><img src="docs/logo.svg" width="96" alt="Cassandra"></p>

# Cassandra

**처음 보는(알지 못하는) 웹사이트에서 취약점을 자동으로 찾아내는** 블랙박스 보안 도구.

Python 기반. credential을 미리 알지 못한다는 전제에서, 대상이 스스로 드러내는 것(폼·API·에러)만으로 **관찰 → 시도 → 발견** 루프를 돌립니다.

---

## 성과 요약 (2026-11-16)

**4개 벤치마크에서 "관찰 → 시도 → 발견" 루프로 취약점을 재발견.** credential을 미리 알지 않고(블랙박스), 도구가 관찰한 것(폼·API·에러)만으로 진입한다.

| 벤치마크 | 진입 경로(블랙박스) | 발견·확인 |
|----------|---------------------|-----------|
| **DVWA** | 무인증 scan → 로그인 폼 **bruteforce**(사전) → `admin/password` | SQLi(UNION, 5명 credential 추출)·XSS reflected — verify **confirmed** |
| **Juice Shop** | JS 번들에서 API 엔드포인트 추출 → **자기 등록**(`/api/Users/`) | **IDOR**: customer 토큰으로 `authentication-details/`에서 51명 전체 목록(admin 포함) — verify **confirmed** |
| **WebGoat** | registration 폼 → **자기 계정 등록** → RequireJS 추적해 lesson endpoint | XSS reflected(`CrossSiteScripting/attack5a`) — verify **confirmed** |
| **bWAPP** | setup→install.php 설치 → login 폼 힌트("bee/bug")로 **브루트** | **SQLi**(error-based, `sqli_1.php?title=`)·**XSS reflected**(`htmli_get.php?firstname=`) — verify **confirmed** |

**원칙 — Default Credential 금지**: 웹에서 "이 앱의 기본 계정"을 검색해 답을 가져오는 보상해킹을 하지 않는다. 대신 (1) 대상이 **공개하는 것**(폼 힌트, robots.txt, JS 번들, 에러 메시지)만 읽고, (2) 사전(dictionary)을 대고 **대상의 반응**(리다이렉트·상태코드)으로 확인한다.

**도구 = 감각기관, 에이전트 = 판단**: 스캐너는 "여기에 폼이 있다", "이 파라미터가 주입되면 에러가 난다", "이 API가 토큰 없이도 200을 준다"는 **관찰**만 보고한다. "이걸로 뭘 하겠다"는 공격 계획은 에이전트가 세우고, `exploit`·`verify`가 실행·증거를 남긴다.

---

## 이것이 무엇인가

버그바운티는 "타인의 웹사이트에서 버그를 찾아 신고하면 상금을 받는" 제도입니다. 이 봇은 그 과정을 자동화합니다.

**가장 중요한 구분** 하나:

- **최종 목표 (North Star)**: *알지 못하는 실제* 웹사이트에서 버그를 찾아 돈 버는 것.
- **DVWA·Juice Shop**: 이걸 *검증하기 위한* 학습용 앱. 목표가 아닙니다.

왜 이렇게 구분하는가? DVWA·Juice Shop은 **의도적으로** 취약하게 만든 앱입니다. 이 두 앱에 맞춰 코드를 짜면(과최적화), 진짜 새 웹사이트에서는 안 먹힙니다. 그래서 이 프로젝트는 **일반화**를 원칙으로 삼고, 두 앱을 "봇이 실제로 버그를 잡는지"를 재는 **시험대**로만 씁니다.

---

## 어떻게 동작하는가

사람(에이전트)이 취약점을 찾는 **관찰 → 시도 → 발견** 루프를 자동화합니다. credential을 미리 알지 못한다는 전제에서 시작합니다.

```
① 관찰 (scan)          ② 판단 (에이전트)        ③ 시도 (exploit)      ④ 확인 (verify)
"여기에 폼·API·    →  "credential 없이 열   →  "SQLi로 로그인     →  "재현해서 before/
 에러가 있다"         수 있는 경로: 등록?   우회? credential      after 증거를 남기고
                      재설정? SQLi? IDOR?"  DB 추출? payload?"    reproduced=True/False"
```

1. **관찰** — `scan`이 무인증 표면(페이지, 폼, hidden 필드, JS 번들의 API 엔드포인트, 헤더, 에러)과, 인증 후 내부(모듈, protected API)를 보고합니다. **판단하지 않습니다.**
2. **판단** — 에이전트가 관찰을 읽고 공격 경로를 정합니다. 순서는: (a) 무인증으로 열려 있는 것(API, 공개 데이터) → (b) 자기 계정 만들기(등록 플로우) → (c) 비밀번호 재설정(토큰 유출/예측) → (d) 로그인 폼 주입(SQLi 로그인 우회, credential DB 추출) → (e) 인증 후(IDOR, 권한 상승).
3. **시도** — `sqli`(자동 탐사: 기법·컬럼·스키마·데이터), `sqli-login`(로그인 폼 주입), `bruteforce`(사전 대고 대상 반응으로 확인), `exploit`(지시대로 payload 실행).
4. **확인** — `verify`가 찾은 것을 **재현**하고 before(정상) vs after(취약) 응답 차이를 캡처해 `reproduced: true/false`와 `verdict_hint`를 줍니다. 사람이 최종 판단합니다.

이 4단계는 `scanner/`(①)·`exploit/`(③)·`verify/`(④) 폴더로, 공통 데이터 모델·설정·로거는 `core/`에 있습니다.

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
| `context.py` | JS 번들에서 API 엔드포인트 추출 (SPA용) |
| `login.py` | 로그인/세션 처리 (DVWA·Juice Shop 등) |
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
| **8** LLM 보완 | **POST body**, **multi-step**(로그인→protected), bWAPP/WebGoat 실측 | bWAPP static 0→LLM 16, WebGoat static 11+LLM 6. xss.py dict 필드 수정 |

**"발견률"이라는 측정 기준**이 있습니다. DVWA는 알려진 취약점 카테고리 ~13개, Juice Shop은 ~20+ 챌린지. 우리가 몇 개를 자동 발견했는지를 계속 재고 있습니다.

| 앱 | 알려진 취약점 | 자동 발견 | 발견률 |
|----|:----------:|:--------:|:------:|
| DVWA | ~13개 | **~10개** | **~77%** |
| Juice Shop | ~20+개 | **~5개** | **~25%** |
| bWAPP | ~15+개 | **~0개** (정적) | LLM scanner로 보완 |
| WebGoat | ~15+개 | **~3개** (XSS) | LLM scanner로 보완 |

**다음 단계**:
- **9** — 실전: *알지 못하는 실제* HackerOne 프로그램에서 자동 스캔→triage→제출 (**North Star**, API 키 필요)

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

CLI는 `uv run python -m core.main <명령>` 입니다.

```bash
# ① 관찰 — 무인증 표면(페이지·폼·JS API·헤더·에러)
uv run python -m core.main scan http://localhost:8081 --max-pages 25

#    인증 후 내부도 보려면 로그인 옵션 (대상이 공개하는 credential만)
uv run python -m core.main scan http://localhost:8081 \
    --login-url /login.php --login-user admin --login-pass password

# ③ 시도 — SQLi 자동 탐사 (기법·컬럼·스키마·credential DB)
uv run python -m core.main sqli "http://localhost:8081/vulnerabilities/sqli/?id=1" \
    --login-url /login.php --login-user admin --login-pass password

#    로그인 폼 SQLi (credential 없이 우회/추출)
uv run python -m core.main sqli-login http://localhost:8081 --login-url /login.php

#    로그인 브루트포스 (사전 대고 대상 반응으로 확인)
uv run python -m core.main bruteforce http://localhost:8082 \
    --login-url /login.php --user-field login --pass-field password --max-attempts 200

#    지시대로 exploit 실행 (POST body·커스텀 헤더)
uv run python -m core.main exploit "http://localhost:8082/htmli_get.php?firstname=%3Cscript%3Ealert(1)%3C%2Fscript%3E" \
    -i "XSS reflected in firstname" --expected "alert(1)"

# ④ 확인 — 재현 + before/after 증거
uv run python -m core.main verify "http://localhost:8082/sqli_1.php?title=a%27&action=search" \
    -i "SQLi error-based: single quote breaks query" \
    --expected "You have an error in your SQL" \
    --baseline-url "http://localhost:8082/sqli_1.php?title=a&action=search" \
    --login-url /login.php --login-user bee --login-pass bug
```

각 명령은 JSON을 돌려주므로 파이프(`| jq`)로 처리할 수 있습니다.

## 벤치마크 띄우기

```bash
cd demo && docker compose up -d
# DVWA: http://localhost:8081   Juice Shop: http://localhost:3000
# bWAPP: http://localhost:8082  WebGoat: http://localhost:8083/WebGoat
```

bWAPP는 첫 접속 시 `/install.php?install=yes`로 DB를 설치해야 합니다.

## 테스트

```bash
uv run python tests/test_mvp.py      # MVP
uv run python tests/test_asset.py    # 자산 발견
uv run python tests/test_stage3.py   # scanner 확장 + daemon
uv run python tests/test_live.py     # DVWA + Juice Shop 실전
```

## 구조

```
cassandra/
├── core/          # models, config, db, scheduler, logger, main (CLI)
├── scanner/       # ① 관찰: sqli, xss, idor, ssrf, auth, fuzz, cve, api,
│                  #   file, session, infra, logic, nuclei, login, context + web.py
├── exploit/       # ③ 시도: executor(sqli_probe, sqli_login_probe), bruteforce, poc
├── verify/        # ④ 확인: evidence (재현 + before/after)
├── asset/         # 자산 발견 (CT, DNS, API crawl, CVE, rescan, scope)
├── triage/        # LLM (judge, severity, report, PoC), dedup
├── web/           # 대시보드
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
