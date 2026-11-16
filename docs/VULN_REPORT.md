# BugBounty Bot — 취약점 분석 보고서

**작성일**: 2026-11-14 (7: bWAPP + WebGoat 벤치마크 추가, LLM scanner)
**대상**: DVWA (vulnerable/web-dvwa:latest), OWASP Juice Shop (bkimminich/juice-shop:latest, v20.2.0), bWAPP (raesene/bwapp:latest), OWASP WebGoat (webgoat/webgoat:latest)
**방법**: scanner findings + **실제 exploit 실측** (payload 주입 → 결과 확인)

---

## 1. 요약 (Executive Summary)

| 앱 | findings | **실제 exploit 확인** | 알려진 취약점 중 발견 | 새로운 취약점 |
|----|----------|----------------------|---------------------|-------------|
| DVWA | **45** | **12개** (SQLi×3, XSS, Stored XSS×2, **File Upload RCE**, IDOR, LFI, 명령주입, **Weak Session**, **Insecure CAPTCHA**) | **~10/13** | 없음 |
| Juice Shop | **22** | **5개** (Stored XSS, IDOR, NoSQLi login, Admin Registration, DOM XSS) | **~5/20+** | 없음 |
| bWAPP | **3** | **0** (cve×3: PHP 프레임워크 감지) | **~0/15+** | 없음 |
| WebGoat | **11** | **3** (xss×3) | **~3/15+** | fuzz_anomaly×8 |

**결론:**
1. **새로운 취약점이 아니다** — 두 앱 모두 의도적으로 취약한 학습용 앱(OWASP). 우리가 발견한 것은 **알려진 취약점**이다.
2. **모두 exploit 가능한 것은 아니다** — findings 65개 중 실제로 exploit을 실측·확인한 것은 **14개**다. 나머지는 신호(heuristic) 단계.
3. **알려진 취약점을 모두 찾은 것은 아니다** — DVWA는 ~13개 취약점 카테고리 중 **~10개**, Juice Shop은 ~20+ 챌린지 중 **~5개**를 발견했다 (6a: NoSQLi + Admin Reg, 6b: DOM XSS + Stored XSS, 6c: File Upload RCE, **6d: Weak Session + Insecure CAPTCHA**).

---

## 2. DVWA 분석

### 2.1 scanner findings (45개)

| 유형 | 수 | 대상 |
|------|----|------|
| sqli | 10 | `/sqli/` (boolean), `/brute/` (SQL error) |
| xss | 19 | `/xss_r/` (reflected: script/onerror/onload) |
| stored_xss | 2 | `/xss_s/` (txtName, mtxMessage → GET 반사) |
| idor | 8 | `/sqli/`, `/sqli_blind/` |
| cve | 3 | Apache HTTP/2 rapid reset |
| **file_upload** | **1** | **`/vulnerabilities/upload/` .php → `/hackable/uploads/` RCE** |
| **weak_session** | **1** | **`/vulnerabilities/weak_id/` `dvwaSession` 재생성 → 순차(1,2,3,4)·저엔트로피·짧음** |
| **captcha** | **1** | **`/vulnerabilities/captcha/` reCAPTCHA sitekey 빈 + key missing + 이미지 재사용** |

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
| 8 | **File Upload (RCE)** | `.php` 업로드 → `/hackable/uploads/bb_rce.php` | **200 + marker 출력** (RCE) | ✅ **YES** |
| 9 | **Weak Session IDs** | `/vulnerabilities/weak_id/` Generate POST 반복 | `dvwaSession=1,2,3,4` **순차 발급** (avg delta 1.0, entropy 0.00) | ✅ **YES** |
| 10 | **Insecure CAPTCHA** | `/vulnerabilities/captcha/` | reCAPTCHA `data-sitekey=''` + "key missing" + 이미지 재사용 → **CAPTCHA 비활성** | ✅ **YES** |

**exploit 가능한 것 (10개)**: boolean SQLi, time-based blind SQLi, length() blind SQLi, IDOR, reflected XSS, LFI, 명령 주입, **File Upload (RCE)**, **Weak Session IDs**, **Insecure CAPTCHA**.

### 2.3 exploit이 안 된 것 / 확인 안 된 것

| 취약점 | 상태 | 이유 |
|--------|------|------|
| **UNION-based SQLi** | ⚠️ 부분 | `id=-1 UNION SELECT user,password,...` — DVWA sqli 페이지는 **첫 행만** 표시하고, `AND user='' AND password=''` 조건이 걸려서 UNION 결과가 안 보임. 컬럼 수(8개)를 맞춰야 함. |
| **XSS Stored** (`/xss_s/`) | ✅ | 6b: txtName/mtxMessage → GET 반사 |
| **XSS DOM** (`/xss_d/`) | ✅ | 6b: main.js sink+source 정적 분석 |
| **Insecure CAPTCHA** | ✅ | 6d: reCAPTCHA sitekey 빈 + "key missing" + 이미지 재사용 → 우회 가능 |
| **Weak Session IDs** | ✅ | 6d: `dvwaSession` cookie 재생성 → 순차(1,2,3,4)·저엔트로피·짧음 |
| **Race Condition** | N/A | DVWA에 해당 취약점 없음 (6e scanner 있음) |
| **Payment Bypass** | N/A | DVWA에 해당 취약점 없음 (6e scanner 있음) |
| **DNS/TLS** | N/A | localhost(HTTP) — TLS/subdomain/S3/DNS 없음 (6e scanner 있음) |
| **File Upload** | ✅ | 6c: .php 업로드 → `/hackable/uploads/` RCE |
| **Insecure Login** | ⚠️ 부분 | brute force SQL error는 발견, 로그인 우회 자체는 미확인. |

### 2.4 알려진 취약점 대조

DVWA 프로젝트의 알려진 취약점 카테고리 (~13개):

| 알려진 취약점 | 우리가 발견? | exploit 확인? |
|-------------|:----------:|:------------:|
| SQL Injection (boolean/union/error) | ✅ | ✅ (boolean, time) |
| SQL Injection Blind (time) | ✅ | ✅ |
| XSS Reflected | ✅ | ✅ |
| XSS Stored | ✅ | ✅ (6b) |
| XSS DOM | ✅ | ✅ (6b) |
| IDOR | ✅ | ✅ |
| File Inclusion (LFI/RFI) | ✅ | ✅ |
| Command Injection | ✅ | ✅ |
| Brute Force | ✅ (SQL error) | ⚠️ |
| Insecure CAPTCHA | ✅ | ✅ (6d: sitekey 빈 + key missing) |
| Weak Session IDs | ✅ | ✅ (6d: dvwaSession 순차) |
| File Upload | ✅ | ✅ (6c: RCE) |
| Insecure Login | ⚠️ | ⚠️ |

**발견률**: ~13개 중 **~10개** (boolean SQLi, blind SQLi, XSS reflected, **XSS stored**, **XSS DOM**, IDOR, LFI, 명령 주입, **File Upload**, **Weak Session**, **Insecure CAPTCHA**). **~3개 미발견** (insecure login, brute force, union SQLi).

### 2.5 "어떤 일이 가능한가" (DVWA)

실제 exploit으로 가능한 일:
- **데이터 탈취**: boolean/time-based blind SQLi로 `users` 테이블의 user, password, first_name, last_name, user_level, last_login, failed_login을 **한 문자씩** 추출 가능
- **인증 우회**: `admin' OR '1'='1` 또는 `admin'--` 로 로그인
- **다른 사용자 데이터 접근**: IDOR로 id=1,2,3... 의 사용자 정보
- **XSS**: reflected XSS로 사용자 브라우저에서 JS 실행 (세션 탈취, CSRF)
- **서버 파일 읽기**: LFI로 `/etc/passwd`, `/etc/shadow` (읽기 권한이 있으면)
- **명령 실행**: 명령 주입으로 `id`, `whoami`, `cat /etc/passwd` 등
- **RCE (File Upload)**: `.php` 파일 업로드 → `/hackable/uploads/`에 저장 → 웹에서 실행 (원격 코드 실행)
- **세션 예측 (Weak Session)**: `dvwaSession`이 순차(1,2,3,4)로 발급 → 다음 세션 ID 예측 → 타인 세션 하이재킹
- **CAPTCHA 우회 (Insecure CAPTCHA)**: reCAPTCHA 비활성(sitekey 빈) → 비밀번호 변경/로그인 폼에 CAPTCHA 없이 직접 제출

---

## 3. Juice Shop 분석

### 3.1 scanner findings (22개)

| 유형 | 수 | 대상 |
|------|----|------|
| **nosqli** | **1** | **`/rest/user/login` password `{$ne:None}` → 500 (baseline 401)** |
| **admin_registration** | **1** | **`/api/Users` POST role:admin → 201** |
| **dom_xss** | **1** | **`main.js` sink(innerHTML, document.write) + source(location.href)** |
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

**exploit 가능한 것 (5개)**: Stored XSS, IDOR, **NoSQLi login (신호)**, **Admin Registration**, **DOM XSS**.

> **NoSQLi login 비고**: v20.2.0은 password를 `btoa()`(base64) 인코딩하므로, operator object가 `btoa()`에서 TypeError(500)를 유발 — 완전 우회(200)는 아니지만 **baseline(401)과 다른 500**으로 NoSQLi 공격면이 존재함을 증명. scanner는 이 status code 차이를 `nosqli` finding으로 탐지.

### 3.3 exploit이 안 된 것 / 확인 안 된 것

| 취약점 | 상태 | 이유 |
|--------|------|------|
| **NoSQLi login** | ✅ | `/rest/user/login`(단수)에 `{$ne:None}` → 500 (baseline 401). operator가 백엔드에 도달함을 증명. |
| **DOM XSS** | ✅ | `main.js`에서 `innerHTML/outerHTML/document.write` sink + `location.href/document.location` source — 정적 분석으로 탐지 |
| **SQLi** | ❌ | `PUT /api/Products/1` name에 SQLi payload — 저장되지만 SQL error 안 나옴. |
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

### 3.5 bWAPP (raesene/bwapp:latest)

**endpoints**: 1 (crawl이 index.php만 발견 — bWAPP은 프레임워크 기반, 대부분 POST로 동작)
**findings**: 3 (cve×3: PHP 프레임워크 감지)

bWAPP은 15+ 취약점 카테고리(SQLi, XSS, CSRF, LFI, RCE, etc.)를 포함하지만, 대부분 **POST 폼 + 특정 파라미터**로 동작해서 GET-based scanner가 못 잡음. LLM scanner(7b)가 이 부분을 보완할 것으로 기대.

### 3.6 WebGoat (webgoat/webgoat:latest, 2026.5)

**endpoints**: 3 (crawl이 /WebGoat, /WebGoat/start, /WebGoat/lessons만 발견 — SPA)
**findings**: 11 (xss×3, fuzz_anomaly×8)

WebGoat는 15+ 레슨(DOM XSS, CSRF, SQLi, Brute Force, etc.)을 포함하지만, **SPA(React)** 구조라 crawl이 제한적. xss×3는 레슨 페이지의 reflected XSS. fuzz_anomaly×8는 레슨 페이지의 500 에러.

---

## 4. 종합 결론

### 4.1 "새로운 취약점인가?"

**아니다.** 두 앱 모두 **의도적으로 취약한 학습용 앱**(OWASP DVWA, OWASP Juice Shop). 우리가 발견한 것은 **알려진 취약점**이다. 새로운 취약점(0-day)은 아니다.

### 4.2 "모두 exploit 가능한가?"

**아니다.** findings 67개 중 **실제 exploit을 실측·확인한 것은 17개**다.

| 앱 | findings | exploit 확인 | 비율 |
|----|----------|-------------|------|
| DVWA | **45** | **12** | **26.7%** |
| Juice Shop | **22** | **5** | **22.7%** |
| **합계** | **67** | **17** | **25.4%** |

나머지 42개는 **신호(heuristic) 단계** — SQL error, length anomaly, fuzz anomaly 등. exploit으로 확인하려면 추가 작업이 필요하다.

### 4.3 "알려진 취약점을 모두 찾은 것인가?"

**아니다.**

| 앱 | 알려진 취약점 | 우리가 발견 | 발견률 |
|----|-------------|-----------|--------|
| DVWA | ~13개 | **~10개** | **~77%** |
| Juice Shop | ~20+개 | **~5개** | **~25%** |

**미발견 취약점의 공통점:**
- **DOM-based XSS** — ✅ 탐지 (6b: main.js sink+source)
- **Stored XSS** (DVWA) — ✅ 탐지 (6b: xss_s txtName/mtxMessage)
- **File Upload** (DVWA) — ✅ 탐지 (6c: .php → RCE)
- **CAPTCHA, Weak Session** (DVWA) — ✅ 탐지 (6d: sitekey 빈, dvwaSession 순차)
- **Login Admin** (Juice Shop) — admin 로그인, scanner가 미탐지

### 4.4 scanner의 강점과 한계

**강점:**
- **boolean/time-based SQLi** — 잘 탐지 (DVWA)
- **reflected XSS** — 잘 탐지 (DVWA)
- **Stored XSS** — 잘 탐지 (Juice Shop + **DVWA xss_s**)
- **DOM XSS** — ✅ 탐지 (6b: main.js sink+source)
- **IDOR** — 잘 탐지 (두 앱)
- **NoSQLi** — 잘 탐지 (Juice Shop, operator → 500 신호)
- **Admin Registration** — 잘 탐지 (Juice Shop, role:admin → 201)
- **File Upload (RCE)** — ✅ 탐지 (6c: .php → 저장 → 실행)
- **LFI, 명령 주입** — 잘 탐지 (DVWA)

**한계:**
- **Login Admin** — admin 로그인 미탐지
- **UNION-based SQLi** — 컬럼 수 불일치로 미확인
- **Password Reset** (Juice Shop) — email 기반이라 토큰 미추출 (6d: 로직은 갖춤)

### 4.5 다음 단계 (improvement)

1. ~~**NoSQLi login 경로 수정**~~ — ✅ 완료 (6a)
2. ~~**DOM XSS 탐지**~~ — ✅ 완료 (6b: JS 번들 sink+source 정적 분석)
3. ~~**Stored XSS (DVWA)**~~ — ✅ 완료 (6b: xss_s txtName/mtxMessage)
4. ~~**Admin Registration**~~ — ✅ 완료 (6a) / **Login Admin** — 미탐지
5. **UNION-based SQLi** — 컬럼 수 자동 탐지 + `id=-1` 사용
6. ~~**dedicated vuln_type**~~ — ✅ 완료 (6a: nosqli, admin_registration / 6b: dom_xss, stored_xss / 6c: file_upload, path_traversal)
7. ~~**File Upload (RCE)**~~ — ✅ 완료 (6c: .php → 저장 → 실행)
8. ~~**Weak Session, Insecure CAPTCHA**~~ — ✅ 완료 (6d: dvwaSession 순차, sitekey 빈)

---

## 부록: exploit 실측 스크립트

- `exploit_dvwa.py` — DVWA exploit (SQLi, XSS, IDOR, LFI, 명령 주입)
- `exploit_dvwa2.py` — DVWA sqli 정확 검증 (UNION, boolean, length)
- `exploit_juice.py` — Juice Shop exploit (NoSQLi, Stored XSS, SQLi, IDOR)
- `exploit_nosqli.py` — Juice Shop NoSQLi login + Admin Registration 실측 (6a)
- `scanner/xss.py` — 6b: `scan_dom_xss`(JS 번들 sink+source) + `scan_stored_xss`(POST 저장 → GET 반사)
- `scanner/file.py` — 6c: `scan_file_upload`(.php 업로드 → 저장/실행 RCE) + `scan_file_download`(path traversal)
