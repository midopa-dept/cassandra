# BugBounty Bot — Code Walkthrough

IT/보안 담당자를 위한 코드 설명. "왜 이렇게 만들었나"에 초점을 둔다.

## 1. 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│  BugBounty Bot (Python daemon)                                  │
│                                                                 │
│  Asset Discovery → Scanner → Triage (LLM) → HackerOne           │
│                                                                 │
│  - Asset: CT, DNS, API crawl, CVE match                         │
│  - Scanner: Web, Infra, API, Logic, Nuclei                      │
│  - Triage: LLM (judge, severity, report, PoC)                   │
│  - HackerOne: submit, track, auto-respond                       │
└─────────────────────────────────────────────────────────────────┘
```

**데이터 흐름**:
1. `Asset` (domain, subdomains, endpoints, tech_stack, cves)
2. `Finding` (asset, vuln_type, severity, evidence, poc_request)
3. `Report` (title, summary, poc, impact, recommendation, rating)
4. `Submission` (report_id, hackerone_id, status, payout)

## 2. 왜 Python?

- **생태계**: httpx, Flask, APScheduler, dnspython, OpenAI, Anthropic
- **생산성**: 빠른 프로토타이핑, 읽기 쉬운 코드
- **보안 도구**: Nuclei, subfinder 등 Go 바이너리를 subprocess로 호출

## 3. 왜 SQLite?

- **단일 파일**: 외부 DB 서버 불필요
- **충분한 성능**: 버그바운티 규모 (수천~수만 findings)
- **이동성**: USB로 복사해서 가져갈 수 있음

## 4. 왜 LLM?

- **False positive 제거**: Nuclei/스캐너가 발견한 버그를 LLM이 2차 확인
- **리포트 작성**: HackerOne 형식 (title, summary, PoC, impact, recommendation) 자동 생성
- **심각도 평가**: CVSS-like rating (low/med/high/crit)

**LLM 선택**:
- OpenAI GPT-4o (기본): 가장 정확
- Anthropic Claude: 긴 컨텍스트
- Ollama (로컬): 프라이버시, 비용 절감

## 5. 왜 반자동?

- **인간 승인**: LLM이 리포트 작성, 사람이 대시보드에서 확인 후 제출
- **Auto-submit**: high/critical만 자동 제출 (config로 설정)
- **이유**: 버그바운티는 "질"이 중요. 잘못된 리포트가 많으면 연구원 신뢰도 하락

## 6. 스캐너 설계

### Web (SQLi, XSS, IDOR)
- **Payload-based**: 알려진 payload를 주입해서 응답 분석
- **Rate limit**: 목표 사이트 과부하 방지
- **Dedup**: 같은 asset + vuln_type + endpoint 중복 제거

### Infra (TLS, subdomain takeover, S3)
- **TLS**: weak cipher, cert expiry, protocol version
- **Subdomain takeover**: CNAME이 dangling (404 + known platform)
- **S3**: bucket listable, file readable

### API (REST, GraphQL)
- **Auth**: missing auth, auth bypass
- **Rate limit**: 10개 요청에 429 없으면 no rate limit
- **GraphQL**: introspection, batching

### Logic (race condition, payment bypass)
- **Race condition**: 동시 요청으로 상태 변경 확인
- **Payment bypass**: amount=0, negative amount

### Nuclei
- **YAML 템플릿**: CVE, exposures, misconfigurations
- **Subprocess**: Go 바이너리를 Python에서 호출

## 7. Triage (LLM)

### Judge
```python
prompt = f"""
Is this a real vulnerability or a false positive?
Consider:
- Is the evidence strong enough?
- Could this be a false positive?
- Is the endpoint in scope?
"""
```

### Severity
```python
prompt = f"""
Rate this vulnerability using HackerOne's rating scale:
- low: minor impact, difficult to exploit
- medium: moderate impact, requires some conditions
- high: significant impact, easy to exploit
- critical: severe impact, easy to exploit
"""
```

### Report
```python
prompt = f"""
Write a professional bug bounty report:
Title: [Concise, specific title]
Summary: [2-3 sentences]
PoC: [Step-by-step with curl]
Impact: [Business impact]
Recommendation: [How to fix]
"""
```

## 8. HackerOne API

- **GraphQL**: HackerOne은 REST가 아닌 GraphQL 사용
- **Auth**: Bearer token (API key)
- **Rate limit**: 100 requests/hour (free tier)

## 9. Web Dashboard

- **Flask + SocketIO**: 실시간 업데이트 (WebSocket)
- **Fallback**: WebSocket 실패 시 polling (5s)
- **Dark theme**: 보안 도구 표준

## 10. 운영

### Daemon
```bash
uv run python -m core.main --config config.yaml
```

- **Scheduler**: APScheduler (CT 1h, DNS 6h, rescan 24h, triage 1h)
- **Signal handling**: SIGINT, SIGTERM

### Config
```yaml
# .env
H1_API_KEY=xxx
OPENAI_API_KEY=xxx

# config.yaml
hackerone:
  programs: [google, github]
llm:
  provider: openai
  auto_submit_min: high
```

## 11. 테스트

- **Mock server**: http.server로 취약점 시뮬레이션
- **Mock LLM**: API key 없이 테스트
- **Mock HackerOne**: GraphQL mock

## 12. 확장

- **Bugcrowd, Intigriti**: 다른 플랫폼 지원
- **Mobile**: Android/iOS (reverse engineering)
- **Cloud**: AWS, Azure, GCP misconfig
- **CI/CD**: GitHub Actions, Jenkins
