"""BugBounty Bot — LLM triage (판단, 심각도, 리포트)."""
import json
from typing import Optional
from core.models import Finding, Report, Asset
from core.logger import get_logger

log = get_logger("triage")


class LLMClient:
    """LLM 클라이언트 (OpenAI, Anthropic, Ollama)."""

    def __init__(self, provider: str = "openai", model: str = "gpt-4o", api_key: str = ""):
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self._client = None

    def _get_client(self):
        if self._client:
            return self._client
        if self.provider == "openai":
            import openai
            self._client = openai.OpenAI(api_key=self.api_key)
        elif self.provider == "anthropic":
            import anthropic
            self._client = anthropic.Anthropic(api_key=self.api_key)
        elif self.provider == "ollama":
            import httpx
            self._client = httpx.Client(base_url="http://localhost:11434/api")
        return self._client

    def chat(self, messages: list[dict], temperature: float = 0.3) -> str:
        """LLM chat completion."""
        client = self._get_client()
        if self.provider == "openai":
            resp = client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
            )
            return resp.choices[0].message.content
        elif self.provider == "anthropic":
            resp = client.messages.create(
                model=self.model,
                max_tokens=4096,
                messages=messages,
                temperature=temperature,
            )
            return resp.content[0].text
        elif self.provider == "ollama":
            import httpx
            resp = httpx.post(
                "http://localhost:11434/api/generate",
                json={"model": self.model, "prompt": messages[-1]["content"], "stream": False},
                timeout=60,
            )
            return resp.json().get("response", "")
        return ""


def judge_finding(llm: LLMClient, finding: Finding, asset: Asset) -> dict:
    """LLM: 이 Finding이 진짜 버그인가?"""
    prompt = f"""You are a security researcher reviewing a potential vulnerability.

Asset: {asset.domain}
Vulnerability type: {finding.vuln_type}
Endpoint: {finding.endpoint}
Method: {finding.method}
Evidence: {finding.evidence}
PoC request: {json.dumps(finding.poc_request, indent=2)}

Is this a real vulnerability or a false positive?
Consider:
- Is the evidence strong enough?
- Could this be a false positive (e.g., reflected but not exploitable)?
- Is the endpoint in scope?

Respond with JSON:
{{"is_real": true/false, "confidence": 0.0-1.0, "reasoning": "..."}}
"""
    resp = llm.chat([{"role": "user", "content": prompt}])
    try:
        # Extract JSON from response
        start = resp.find("{")
        end = resp.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(resp[start:end])
    except json.JSONDecodeError:
        pass
    return {"is_real": True, "confidence": 0.5, "reasoning": "Default: assume real"}


def assess_severity(llm: LLMClient, finding: Finding, asset: Asset) -> str:
    """LLM: HackerOne rating (low, medium, high, critical)."""
    prompt = f"""You are a security researcher assessing vulnerability severity.

Asset: {asset.domain}
Vulnerability type: {finding.vuln_type}
Endpoint: {finding.endpoint}
Evidence: {finding.evidence}

Rate this vulnerability using HackerOne's rating scale:
- low: minor impact, difficult to exploit
- medium: moderate impact, requires some conditions
- high: significant impact, easy to exploit
- critical: severe impact, easy to exploit, affects many users

Respond with just the rating: low, medium, high, or critical
"""
    resp = llm.chat([{"role": "user", "content": prompt}])
    resp_lower = resp.lower().strip()
    for rating in ["critical", "high", "medium", "low"]:
        if rating in resp_lower:
            return rating
    return "medium"


def generate_report(llm: LLMClient, finding: Finding, asset: Asset, severity: str) -> Report:
    """LLM: HackerOne 형식 리포트 작성."""
    prompt = f"""You are a security researcher writing a bug bounty report for HackerOne.

Asset: {asset.domain}
Vulnerability type: {finding.vuln_type}
Endpoint: {finding.endpoint}
Method: {finding.method}
Evidence: {finding.evidence}
PoC request: {json.dumps(finding.poc_request, indent=2)}
Severity: {severity}

Write a professional bug bounty report in this format:

Title: [Concise, specific title]
Summary: [2-3 sentences describing the vulnerability]
PoC: [Step-by-step reproduction with curl commands or HTTP requests]
Impact: [Business impact, what data is exposed, who is affected]
Recommendation: [How to fix the vulnerability]

Be specific and technical. Include actual curl commands in the PoC section.
"""
    resp = llm.chat([{"role": "user", "content": prompt}])

    # Parse response into Report fields
    title = ""
    summary = ""
    poc = ""
    impact = ""
    recommendation = ""

    lines = resp.split("\n")
    current_section = ""
    sections = {}
    for line in lines:
        line_stripped = line.strip()
        if line_stripped.startswith("Title:"):
            current_section = "title"
            sections["title"] = line_stripped[6:].strip()
        elif line_stripped.startswith("Summary:"):
            current_section = "summary"
            sections["summary"] = line_stripped[8:].strip()
        elif line_stripped.startswith("PoC:"):
            current_section = "poc"
            sections["poc"] = line_stripped[4:].strip()
        elif line_stripped.startswith("Impact:"):
            current_section = "impact"
            sections["impact"] = line_stripped[7:].strip()
        elif line_stripped.startswith("Recommendation:"):
            current_section = "recommendation"
            sections["recommendation"] = line_stripped[15:].strip()
        elif current_section:
            sections[current_section] = sections.get(current_section, "") + "\n" + line

    title = sections.get("title", f"{finding.vuln_type} in {asset.domain}")
    summary = sections.get("summary", finding.evidence)
    poc = sections.get("poc", "")
    impact = sections.get("impact", "")
    recommendation = sections.get("recommendation", "")

    return Report(
        finding_id=finding.id,
        asset_id=asset.id,
        program=asset.program,
        title=title,
        summary=summary,
        poc=poc,
        impact=impact,
        recommendation=recommendation,
        rating=severity,
        status="draft",
    )


def generate_poc_curl(finding: Finding) -> str:
    """PoC: 재현 가능한 curl 명령 생성."""
    poc = finding.poc_request
    if not poc:
        return ""

    method = poc.get("method", "GET").upper()
    url = poc.get("url", "")
    headers = poc.get("headers", {})
    params = poc.get("params", {})
    body = poc.get("body", "")

    if params:
        query = "&".join(f"{k}={v}" for k, v in params.items())
        if "?" in url:
            url += f"&{query}"
        else:
            url += f"?{query}"

    cmd = f"curl -X {method} '{url}'"
    for k, v in headers.items():
        cmd += f" \\\n  -H '{k}: {v}'"
    if body:
        cmd += f" \\\n  -d '{body}'"

    return cmd
