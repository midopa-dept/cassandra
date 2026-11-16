# Cassandra — Code Walkthrough

IT/보안 담당자를 위한 코드 설명. "왜 이렇게 만들었나"에 초점을 둔다.

## 1. 아키텍처 — 두뇌(LLM) + 감각기관(Cassandra)

```
사람(감독) ── 지시 ──► LLM 에이전트(뇌: 판단)
                          │ run_shell: python -m core.main <명령>
                          ▼
                    Cassandra(감각기관)
                          │ HTTP 트래픽
                          ▼
                    대상 웹 서버
                          │
                          ▼  JSON(사실만)
                    LLM이 읽고 다음 판단
```

**Cassandra는 판단하지 않는다.** HTTP를 날리고, 받은 바이트를 분석해서 *사실*만 JSON으로 넘긴다. 판단("credential을 모른 상태에서 열 수 있는 경로는?")은 **LLM 에이전트**가 한다. 사람이 감독한다.

**데이터 흐름**:
1. `scan` → 페이지·폼·JS API·헤더·에러 (JSON)
2. LLM 판단 → 공격 경로 선택
3. `sqli` / `sqli-login` / `bruteforce` / `exploit` → 실행 결과 (JSON)
4. `verify` → 재현 + before/after 차이 (`reproduced: true/false`)
5. LLM 최종 판단 → 리포트(`Report` 모델)

**왜 이렇게 나누는가**: 판단을 도구 안에 넣으면 특정 앱에 맞춰 과최적화되고, 새 웹사이트에서 안 먹힌다. "관찰을 잘 보고하는 도구 + 판단하는 두뇌"라는 구조이기 때문에 본 적 없는 실제 사이트에서도 같은 루프로 돌릴 수 있다.

## 2. 왜 Python?

- **생태계**: httpx, Flask, APScheduler, dnspython
- **생산성**: 빠른 프로토타이핑, 읽기 쉬운 코드
- **보안 도구**: Nuclei 등 Go 바이너리를 subprocess로 호출

## 3. 왜 SQLite?

- **단일 파일**: 외부 DB 서버 불필요
- **충분한 성능**: 벤치마크·중소 규모 스캔
- **이동성**: USB로 복사해서 가져갈 수 있음

## 4. 판단은 누가 하나? — LLM 에이전트

**Cassandra 내부에 LLM 클라이언트를 두지 않는다.** 판단·리포트 작성은 **에이전트**(stewart, Claude Code 등)가 한다.

- **에이전트**: Cassandra의 JSON 출력을 읽고, 사람 보안 전문가처럼 추론해 다음 `run_shell` 명령을 결정한다.
- **Cassandra**: 관찰·실행·검증만. `Report` 모델(status: draft/verified/reported/accepted/rejected)은 에이전트가 리포트를 작성할 때 쓰는 데이터 구조로만 유지된다.

**이유**: 도구는 보편적이어야 한다. LLM 모델을 도구 안에 하드코딩하면 특정 모델에 맞춰져 일반화가 어렵다. 에이전트는 바꿀 수 있지만, 도구는 그대로 둔다.

## 5. CLI 설계

| 명령 | 역할 |
|------|------|
| `scan` | ① 관찰 — 무인증 표면(페이지·폼·JS API·헤더·에러), 인증 후 내부 |
| `sqli` | ③ 시도 — SQLi 자동 탐사(기법·컬럼·스키마·credential DB) |
| `sqli-login` | ③ 시도 — 로그인 폼 SQLi(credential 없이 우회/추출) |
| `bruteforce` | ③ 시도 — 로그인 브루트포스(사전 vs 대상 반응) |
| `exploit` | ③ 시도 — LLM이 지시한 payload 실행(POST body·커스텀 헤더) |
| `verify` | ④ 확인 — 재현 + before/after 응답 차이 |

모든 명령은 **JSON**을 stdout으로 돌려준다. LLM이 바로 읽을 수 있고, 사람도 `| jq`로 볼 수 있다.

## 6. 스캐너 설계 (scanner/)

각 모듈은 **보편적 신호**로 판별한다(특정 앱 이름을 하드코딩하지 않음).

### sqli.py
- **Boolean-based**: 참/거짓 payload로 행 수 변화 확인
- **Time-based blind**: `SLEEP(n)`로 지연 측정
- **Union**: 컬럼 수 탐지 → 스키마/credential DB 추출
- **Error-based**: 에러 메시지에서 DB 정보 반사

### xss.py
- **Reflected**: payload 주입 → HTML에 그대로 반사 확인
- **DOM XSS**: JS 번들에서 `innerHTML`/`document.write`/`location.hash` sink + source 탐지
- **Stored XSS**: POST body에 payload → GET으로 반사 확인

### session.py
- **Weak Session**: 엔드포인트 반복 요청 → Set-Cookie 수집 → 재생성되는 cookie의 순차성/엔트로피/길이 분석. 특정 cookie 이름을 하드코딩하지 않는다.
- **Insecure CAPTCHA**: reCAPTCHA sitekey 빈/미설정, 이미지 재사용(같은 session에서 동일 바이트)
- **Password Reset**: reset/forgot endpoint 탐지 → 토큰 추출 → 단순성/엔트로피 분석

### file.py
- **File Upload RCE**: multipart 폼(file input) 탐지 → .php payload 업로드 → 저장 파일 접근·실행(marker) 확인
- **Path Traversal**: file/download/path/page 파라미터에 `../` 주입 → /etc/passwd marker 반사

### infra.py
- **TLS**: weak cipher, cert expiry, protocol version
- **Subdomain takeover**: CNAME이 dangling (404 + known platform)
- **DNS misconfig**: TXT/MX/CNAME 이상

### logic.py
- **Race condition**: 동시 요청으로 상태 변경 확인
- **Payment bypass**: amount=0, negative amount

### context.py
- JS 번들/인라인 스크립트에서 API 엔드포인트(`/api/`, `/lessons/`, `/admin/`) 추출 (SPA용)

### web.py (orchestrator)
- 위 모듈들을 모두 호출. scan 명령의 백엔드.

## 7. verify (확인)

- **재현**: 같은 payload를 다시 보내서 동일한 결과를 얻는지 확인
- **before/after**: 정상 요청(baseline) vs 취약 요청의 응답 차이 캡처
- **출력**: `reproduced: true/false` + diff

이것은 LLM의 판단을 **근거**로 만든다. "반사됐다"는 주장이 아니라, 실제로 재현된 증거를 준다.

## 8. 대시보드 (web/)

- **Flask**: findings·reports 목록 표시
- **Dark theme**: 보안 도구 표준

## 9. 테스트

- **Mock server**: http.server로 취약점 시뮬레이션
- **Live test**: Docker 벤치마크(DVWA, Juice Shop, bWAPP, WebGoat) 실측
- **test_mvp / test_asset / test_stage3 / test_dvwa_login / test_8c_multistep / test_live**

## 10. 확장

- **새 벤치마크**: Mutillidae, Other Learning Apps
- **Mobile**: Android/iOS (reverse engineering)
- **Cloud**: AWS, Azure, GCP misconfig
- **CI/CD**: GitHub Actions, Jenkins
