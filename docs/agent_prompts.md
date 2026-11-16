# Cassandra — 에이전트 사용 가이드

## 아키텍처: 도구 = 감각기관, 에이전트 = 뇌

Cassandra는 **판단하지 않는 도구**다. 도구는 오직 두 가지만 한다:

1. **관찰** — 대상의 HTML·폼·엔드포인트·헤더·에러를 구조화된 JSON으로 돌려준다
2. **실행** — 에이전트가 지시한 HTTP 요청을 보내고 결과를 캡처한다

**판단(이게 취약점인가? 어떤 전략인가? 다음에 뭘 시도할까?)은 전부 에이전트가 한다.**
도구에 LLM을 내장하지 않는다 — 에이전트 자체가 LLM이므로.

```
┌─────────────────────────────────────────────┐
│  에이전트 (뇌)                                │
│  - 관찰 데이터를 읽고 전략 세움                 │
│  - exploit 지시 생성                          │
│  - 결과 판단 (취약점? 0-day 후보?)            │
│  - 다음 걸음 결정                            │
└───────────────┬─────────────────────────────┘
                │ CLI 호출 (JSON in/out)
┌───────────────▼─────────────────────────────┐
│  도구 (감각기관)                              │
│  scan   → 관찰 (구조화 데이터)                 │
│  exploit→ 실행 (요청 보내고 결과 캡처)         │
│  verify → 재현 (before/after 증거)           │
└─────────────────────────────────────────────┘
```

---

## 명령

### 1. `scan` — 관찰

대상 URL을 크롤링하고, 각 페이지의 구조를 추출해 JSON으로 돌려준다.

```bash
python -m core.main scan <URL> [--max-pages N]
```

**출력 필드:**

| 필드 | 뜻 |
|------|-----|
| `pages[].forms` | `<form>`의 action/method/fields(name/type/autocomplete) |
| `pages[].links` | 동일 도메인 링크 목록 |
| `pages[].headers` | security 헤더(server, CSP, cookies, ...) |
| `pages[].scripts` | JS src + inline snippet |
| `pages[].meta` | title, generator, csrf-token 존재 여부 |
| `pages[].interesting_patterns` | 감지된 패턴 라벨(stack_trace, admin_path, file_disclosure, credential_hint, ...) |
| `endpoints` | JS/HTML에서 발견한 API 경로 |
| `errors` | 500+ 에러, connection error |
| `summary` | 전체 요약(페이지 수, 폼 수, unique 패턴, notable URL) |

**에이전트 활용:**
- `summary.unique_patterns`로 어디서 주목할 것이 있는지 빠르게 파악
- `forms`에서 입력 지점(attack surface) 식별
- `endpoints`에서 API 공격 표면 식별
- `interesting_patterns`의 `file_disclosure`·`credential_hint`·`admin_path`는 직접 확인 후보

### 2. `exploit` — 실행

에이전트의 지시로 HTTP 요청을 보내고 결과를 캡처한다.

```bash
python -m core.main exploit <URL> \
  -i "<자연어 지시>" \
  [--method GET|POST|PUT|DELETE|PATCH] \
  [--body '<request body>'] \
  [--header "Key: Value"] \
  [--compare-with <baseline URL>]
```

**출력 필드:**

| 필드 | 뜻 |
|------|-----|
| `request` | 실제로 보낸 method/url/headers/body |
| `response.status` | HTTP 상태 코드 |
| `response.body_snippet` | 응답 본문(첫 2000자) |
| `response.time_ms` | 응답 시간 |
| `signals` | 감지된 신호(server_error_500, stack_trace, sql_error, reflected_script, slow_response...) |
| `comparison` | baseline vs exploit 차이(status, size, diff_snippet) |

**에이전트 활용:**
- `-i`에 자연어로 쓰면 된다("id 파라미터에 `' OR 1=1--` 넣고 POST")
- `--compare-with`로 정상 요청과 비교 → 차이만 보면 취약점 여부를 빠르게 판단
- `signals`에서 `stack_trace`·`sql_error`·`reflected_script`는 강신호
- `comparison.status_differs=true`이면 뭔가 달라짐

### 3. `verify` — 재현 + 증거

발견된 것을 재현하고 before/after 증거를 캡처한다.

```bash
python -m core.main verify <URL> \
  -i "<재현 방법>" \
  [--expected "<기대 결과>"] \
  [--baseline-url <정상 URL>]
```

**출력 필드:**

| 필드 | 뜻 |
|------|-----|
| `reproduced` | 재현 성공(true/false) |
| `evidence.baseline` | 정상 요청 결과 |
| `evidence.exploit` | 취약 요청 결과 |
| `evidence.diff_snippet` | 차이 부분 |
| `verdict_hint` | confirmed / inconclusive / refuted (힌트, 최종 판단은 에이전트) |

---

## 에이전트 루프 (0-day 발견 목표)

```
1. scan → 관찰 데이터 확보
   ↓
2. 에이전트 분석: attack surface 식별
   - 어떤 입력 지점(form/param/header)이 있는가?
   - 어떤 패턴(file_disclosure, admin_path, credential_hint)이 있는가?
   - 어떤 엔드포인트가 노출되어 있는가?
   ↓
3. 가설 형성: "여기서 X 취약점이 있을 수 있다"
   ↓
4. exploit → 가설 검증 (baseline vs exploit 비교)
   ↓
5. 에이전트 판단: signals + comparison으로
   - 취약점 확인? → verify로 증거 고정
   - 불명확? → 다른 payload/방법으로 재시도
   - 반증? → 다음 가설로
   ↓
6. (반복) 더 깊은 탐사:
   - 다른 메서드(OPTIONS, PUT)
   - 다른 인코딩(URL-encoded, base64, hex)
   - race condition (동시 요청)
   - logic flaw (비즈니스 로직 우회)
   ↓
7. verify → 최종 증거 캡처 (before/after)
   ↓
8. 보고: 취약점 + 재현 절차 + 증거
```

**0-day를 위해:**
- 알려진 CVE 패턴에만 머물지 말고, `interesting_patterns`에서 비정형 신호를 읽는다
- `comparison`의 미묘한 차이(size, timing, header)도 신호
- 여러 가설을 병렬로 테스트하고, 가장 강한 신호를 따라 깊게 파고든다

---

## 기존 패턴 스캐너 (보조 센서)

`scanner/`에 개별 취약점 패턴 스캐너가 있다. `scan`(관찰) 이후
구체적으로 의심되는 취약점을 빠르게 확인하는 보조 수단.

| 모듈 | 함수 | 대상 |
|------|------|------|
| `scanner/sqli.py` | `scan_sqli` | SQL injection |
| `scanner/xss.py` | `scan_xss`, `scan_dom_xss`, `scan_stored_xss` | XSS |
| `scanner/idor.py` | `scan_idor` | IDOR |
| `scanner/ssrf.py` | `scan_ssrf` | SSRF |
| `scanner/auth.py` | `scan_auth_bypass` | 인증 우회 |
| `scanner/file.py` | `scan_file` | 파일 업로드/열거 |
| `scanner/fuzz.py` | `scan_fuzz` | 파라미터 fuzzing |
| `scanner/session.py` | `scan_session` | 세션/쿠키 |
| `scanner/cve.py` | `scan_cve` | CVE 매칭 |

이들은 `core/models.Finding`을 반환한다. 에이전트는 이 findings를
읽고 판단하며, 필요하면 `exploit`으로 직접 더 깊이 파고든다.
