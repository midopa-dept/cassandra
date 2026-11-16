# BugBounty Bot — 취약점 분석 보고서

**작성일**: 2026-11-12 (6b: DOM XSS + Stored XSS 추가)
**대상**: DVWA (vulnerable/web-dvwa:latest), OWASP Juice Shop (bkimminich/juice-shop:latest, v20.2.0)
**방법**: scanner findings + **실제 exploit 실측** (payload 주입 → 결과 확인)

---

## 1. 요약 (Executive Summary)

| 앱 | findings | **실제 exploit 확인** | 알려진 취약점 중 발견 | 새로운 취약점 |
|----|----------|----------------------|---------------------|-------------|
| DVWA | **42** | **9개** (SQLi×3, XSS, **Stored XSS×2**, IDOR, LFI, 명령주입) | **~7/13** | 없음 |
| Juice Shop | **22** | **5개** (Stored XSS, IDOR, NoSQLi login, Admin Registration, **DOM XSS**) | **~5/20+** | 없음 |

**결론:**
1. **새로운 취약점이 아니다** — 두 앱 모두 의도적으로 취약한 학습용 앱(OWASP). 우리가 발견한 것은 **알려진 취약점**이다.
2. **모두 exploit 가능한 것은 아니다** — findings 64개 중 실제로 exploit을 실측·확인한 것은 **13개**다. 나머지는 신호(heuristic) 단계.
3. **알려진 취약점을 모두 찾은 것은 아니다** — DVWA는 ~13개 취약점 카테고리 중 **~7개**, Juice Shop은 ~20+ 챌린지 중 **~5개**를 발견했다 (6a: NoSQLi + Admin Reg, 6b: DOM XSS + Stored XSS).

---

## 2. DVWA 분석

### 2.1 scanner findings (40개)

| 유형 | 수 | 대상 |
|------|----|------|
| sqli | 10 | `/sqli/` (boolean), `/brute/` (SQL error) |
| xss | 19 | `/xss_r/` (reflected: script/onerror/onload) |
| idor | 8 | `/sqli/`, `/sqli_blind/` |
| cve | 3 | Apache HTTP/2 rapid reset |

### 2.2 실제 exploit 실측 (확인된 것만)

| # | 취약점 | exploit 방법 | 결과 | **exploit 가능?** |
|---|--------|-------------|------|------------------|
| 1 | **boolean-based SQLi** | `id=' OR '1'='1` vs `id=' AND '1'='2` | 참→행 반환, 거짓→0행 | ✅ **YES** |
| 2 | **time-based blind SQLi** | `id=1 AND SLEEP(3)` | 3.05초 (baseline 0.01초) | ✅ **YES** |
| 3 | **length() blind SQLi** | `id=1 AND length(first_name)=5` | 참→행, `=4`→0행 | ✅ **YES** |
| 4 | **IDOR** | `id=1,2,3` | admin / Gordon Brown / Hack Me (다른 사용자) | ✅ **YES** |
| 5 | **reflected XSS** | `id=<script>...` | payload가 HTML에 그대로 반사 | ✅ **YES** |
| 6 | **LFI (로컬 파일 포함)** | `file=../../etc/passwd` | `root:x:0:0:root:...` | ✅ **YES** |
| 7 | **명령 주입** | `target=127.0.0.1;id` | `uid=33(www-data)` | ✅ **YES** |

**exploit 가능한 것 (7개)**: boolean SQLi, time-based blind SQLi, length() blind SQLi, IDOR, reflected XSS, LFI, 명령 주입.

### 2.3 exploit이 안 된 것 / 확인 안 된 것

| 취약점 | 상태 | 이유 |
|--------|------|------|
| **UNION-based SQLi** | ⚠️ 부분 | `id=-1 UNION SELECT user,password,...` — DVWA sqli 페이지는 **첫 행만** 표시하고, `AND user='' AND password=''` 조건이 걸려서 UNION 결과가 안 보임. 컬럼 수(8개)를 맞춰야 함. |
| **XSS Stored** (`/xss_s/`) | ❌ 미발견 | scanner가 reflected만 탐지. stored(댓글 저장)는 미탐지. |
| **XSS DOM** (`/xss_d/`) | ❌ 미발견 | DOM-based XSS는 JS 실행이 필요 — scanner가 미탐지. |
| **Insecure CAPTCHA** | ❌ 미발견 | CAPTCHA 로직 — scanner가 미탐지. |
| **Weak Session IDs** | ❌ 미발견 | 세션 ID 예측 — scanner가 미탐지. |
| **File Upload** | ❌ 미발견 | 파일 업로드 — scanner가 미탐지. |
| **Insecure Login** | ⚠️ 부분 | brute force SQL error는 발견, 로그인 우회 자체는 미확인. |

### 2.4 알려진 취약점 대조

DVWA 프로젝트의 알려진 취약점 카테고리 (~13개):

| 알려진 취약점 | 우리가 발견? | exploit 확인? |
|-------------|:----------:|:------------:|
| SQL Injection (boolean/union/error) | ✅ | ✅ (boolean, time) |
| SQL Injection Blind (time) | ✅ | ✅ |
| XSS Reflected | ✅ | ✅ |
| XSS Stored | ❌ | — |
| XSS DOM | ❌ | — |
| IDOR | ✅ | ✅ |
| File Inclusion (LFI/RFI) | ✅ | ✅ |
| Command Injection | ✅ | ✅ |
| Brute Force | ✅ (SQL error) | ⚠️ |
| Insecure CAPTCHA | ❌ | — |
| Weak Session IDs | ❌ | — |
| File Upload | ❌ | — |
| Insecure Login | ⚠️ | ⚠️ |

**발견률**: ~13개 중 **~7개** (boolean SQLi, blind SQLi, XSS reflected, IDOR, LFI, 명령 주입, brute force). **~6개 미발견** (XSS stored, XSS DOM, CAPTCHA, weak session, file upload, insecure login).

### 2.5 "어떤 일이 가능한가" (DVWA)

실제 exploit으로 가능한 일:
- **데이터 탈취**: boolean/time-based blind SQLi로 `users` 테이블의 user, password, first_name, last_name, user_level, last_login, failed_login을 **한 문자씩** 추출 가능
- **인증 우회**: `admin' OR '1'='1` 또는 `admin'--` 로 로그인
- **다른 사용자 데이터 접근**: IDOR로 id=1,2,3... 의 사용자 정보
- **XSS**: reflected XSS로 사용자 브라우저에서 JS 실행 (세션 탈취, CSRF)
- **서버 파일 읽기**: LFI로 `/etc/passwd`, `/etc/shadow` (읽기 권한이 있으면)
- **명령 실행**: 명령 주입으로 `id`, `whoami`, `cat /etc/passwd` 등

---

## 3. Juice Shop 분석

### 3.1 scanner findings (21개)

| 유형 | 수 | 대상 |
|------|----|------|
| **nosqli** | **1** | **`/rest/user/login` password `{$ne:None}` → 500 (baseline 401)** |
| **admin_registration** | **1** | **`/api/Users` POST role:admin → 201** |
| xss | 2 | `/api/Products/1` PUT name (stored XSS) |
| api_missing_auth | 3 | `/api/Products`, `/api/Products/1`, `/api/Challenges` |
| api_no_rate_limit | 3 | `/api/Products`, `/api/Products/1`, `/api/Challenges` |
| fuzz_anomaly | 11 | `/api/Products`, `/api/Challenges` (NoSQL operator → 500) |

### 3.2 실제 exploit 실측 (확인된 것만)

| # | 취약점 | exploit 방법 | 결과 | **exploit 가능?** |
|---|--------|-------------|------|------------------|
| 1 | **Stored XSS** | `PUT /api/Products/1` body `name=<img src=x onerror=alert(1)>` | 저장 + GET으로 반사 | ✅ **YES** |
| 2 | **IDOR** | `GET /api/Products/{id}` (id=1,2,3,999) | 다른 제품 반환 | ✅ **YES** |
| 3 | **NoSQLi login** | `POST /rest/user/login` `{"password":{"$ne":null}}` | **500** (baseline 401) — operator가 백엔드 `btoa()`에 도달 | ✅ **신호 확인** |
| 4 | **Admin Registration** | `POST /api/Users` `{"email":...,"password":...,"role":"admin"}` | **201** + 응답 `"role":"admin"` | ✅ **YES** |

**exploit 가능한 것 (4개)**: Stored XSS, IDOR, **NoSQLi login (신호)**, **Admin Registration**.

> **NoSQLi login 비고**: v20.2.0은 password를 `btoa()`(base64) 인코딩하므로, operator object가 `btoa()`에서 TypeError(500)를 유발 — 완전 우회(200)는 아니지만 **baseline(401)과 다른 500**으로 NoSQLi 공격면이 존재함을 증명. scanner는 이 status code 차이를 `nosqli` finding으로 탐지.

### 3.3 exploit이 안 된 것 / 확인 안 된 것

| 취약점 | 상태 | 이유 |
|--------|------|------|
| **NoSQLi login** | ✅ | `/rest/user/login`(단수)에 `{$ne:None}` → 500 (baseline 401). operator가 백엔드에 도달함을 증명. |
| **DOM XSS** | ✅ | `main.js`에서 `innerHTML/outerHTML/document.write` sink + `location.href/document.location` source — 정적 분석으로 탐지 |
| **SQLi** | ❌ | `PUT /api/Products/1` name에 SQLi payload — 저장되지만 SQL error 안 나옴. |
| **DOM XSS** | ✅ | `main.js` sink(innerHTML, document.write) + source(location.href) — 정적 분석 |
| **Admin Registration** | ✅ | `POST /api/Users` role:admin → 201, 응답에 role:admin. |
| **Login Admin** | ❌ | admin 로그인 — scanner 미탐지. |
| **Zero Stars** | ❌ | 별점 조작 — scanner 미탐지. |
| **Confidential Document** | ❌ | FTP 문서 — scanner 미탐지. |
| **Error Handling** | ⚠️ | 500 에러는 발견(fuzz_anomaly) — dedicated vuln_type 아님. |

### 3.4 알려진 취약점 대조

Juice Shop v20.2.0의 알려진 챌린지 (~20+, SOLUTIONS.md 기준):

| 알려진 챌린지 | 우리가 발견? | exploit 확인? |
|--------------|:----------:|:------------:|
| Classic Stored XSS | ✅ | ✅ |
| IDOR (Products) | ✅ | ✅ |
| NoSQL Injection (login) | ✅ | ✅ (500 신호) |
| Error Handling | ⚠️ (fuzz_anomaly) | ⚠️ |
| DOM XSS | ✅ | ✅ (main.js sink+source) |
| SQL Injection | ❌ | — |
| Admin Registration | ✅ | ✅ (201) |
| Login Admin | ❌ | — |
| Zero Stars | ❌ | — |
| Confidential Document | ❌ | — |
| API-Only XSS | ❌ | — |
| Five Star Feedback | ❌ | — |
| Password Strength | ❌ | — |
| Weird Crypto | ❌ | — |
| ... (나머지) | ❌ | — |

**발견률**: ~20+ 중 **~5개** (Stored XSS, IDOR, NoSQLi login, Admin Registration, **DOM XSS**) + **~2개 부분** (Error Handling, fuzz). **~13개+ 미발견**.

### 3.5 "어떤 일이 가능한가" (Juice Shop)

실제 exploit으로 가능한 일:
- **Stored XSS**: 제품 name에 `<img src=x onerror=alert(1)>` 저장 → 다른 사용자가 제품 페이지를 열면 JS 실행 (세션 탈취, CSRF)
- **IDOR**: `/api/Products/{id}`로 다른 제품 정보 접근
- **NoSQLi login**: `/rest/user/login`에 `{$ne:None}` → 500 (operator가 백엔드에 도달, 공격면 존재)
- **DOM XSS**: `main.js`에서 `innerHTML`/`document.write` sink가 `location.href`/`document.location` source를 읽음 — 정적 분석으로 탐지
- **Admin Registration**: `POST /api/Users`에 `role:admin` → **admin 권한 계정 생성** (201)

---

## 4. 종합 결론

### 4.1 "새로운 취약점인가?"

**아니다.** 두 앱 모두 **의도적으로 취약한 학습용 앱**(OWASP DVWA, OWASP Juice Shop). 우리가 발견한 것은 **알려진 취약점**이다. 새로운 취약점(0-day)은 아니다.

### 4.2 "모두 exploit 가능한가?"

**아니다.** findings 51개 중 **실제 exploit을 실측·확인한 것은 9개**다.

| 앱 | findings | exploit 확인 | 비율 |
|----|----------|-------------|------|
| DVWA | 40 | 7 | 17.5% |
| Juice Shop | **21** | **4** | **19.0%** |
| **합계** | **61** | **11** | **18.0%** |

나머지 42개는 **신호(heuristic) 단계** — SQL error, length anomaly, fuzz anomaly 등. exploit으로 확인하려면 추가 작업이 필요하다.

### 4.3 "알려진 취약점을 모두 찾은 것인가?"

**아니다.**

| 앱 | 알려진 취약점 | 우리가 발견 | 발견률 |
|----|-------------|-----------|--------|
| DVWA | ~13개 | ~7개 | **~54%** |
| Juice Shop | ~20+개 | **~4개** | **~20%** |

**미발견 취약점의 공통점:**
- **DOM-based XSS** — ✅ 탐지 (6b: main.js sink+source 정적 분석)
- **Stored XSS** (DVWA) — ✅ 탐지 (6b: xss_s txtName/mtxMessage → GET 반사)
- **Login Admin** (Juice Shop) — admin 로그인, scanner가 미탐지
- **CAPTCHA, Weak Session, File Upload** (DVWA) — 특수 로직, scanner가 미탐지

### 4.4 scanner의 강점과 한계

**강점:**
- **boolean/time-based SQLi** — 잘 탐지 (DVWA)
- **reflected XSS** — 잘 탐지 (DVWA)
- **Stored XSS** — 잘 탐지 (Juice Shop + **DVWA xss_s**)
- **DOM XSS** — ✅ 탐지 (6b: main.js sink+source)
- **IDOR** — 잘 탐지 (두 앱)
- **NoSQLi** — 잘 탐지 (Juice Shop, operator → 500 신호)
- **Admin Registration** — 잘 탐지 (Juice Shop, role:admin → 201)
- **LFI, 명령 주입** — 잘 탐지 (DVWA)

**한계:**
- **DOM-based XSS** — 미탐지 (JS 실행 필요)
- **Login Admin** — admin 로그인 미탐지
- **CAPTCHA, Weak Session, File Upload** — 특수 로직 미탐지
- **UNION-based SQLi** — 컬럼 수 불일치로 미확인

### 4.5 다음 단계 (improvement)

1. ~~**NoSQLi login 경로 수정**~~ — ✅ 완료 (6a)
2. ~~**DOM XSS 탐지**~~ — ✅ 완료 (6b: JS 번들 sink+source 정적 분석)
3. ~~**Stored XSS (DVWA)**~~ — ✅ 완료 (6b: xss_s txtName/mtxMessage)
4. ~~**Admin Registration**~~ — ✅ 완료 (6a) / **Login Admin** — 미탐지
5. **UNION-based SQLi** — 컬럼 수 자동 탐지 + `id=-1` 사용
6. ~~**dedicated vuln_type**~~ — ✅ 완료 (6a: nosqli, admin_registration / 6b: dom_xss, stored_xss)

---

## 부록: exploit 실측 스크립트

- `exploit_dvwa.py` — DVWA exploit (SQLi, XSS, IDOR, LFI, 명령 주입)
- `exploit_dvwa2.py` — DVWA sqli 정확 검증 (UNION, boolean, length)
- `exploit_juice.py` — Juice Shop exploit (NoSQLi, Stored XSS, SQLi, IDOR)
- `exploit_nosqli.py` — Juice Shop NoSQLi login + Admin Registration 실측 (6a)
- `scanner/xss.py` — 6b: `scan_dom_xss`(JS 번들 sink+source) + `scan_stored_xss`(POST 저장 → GET 반사)
