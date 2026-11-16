"""BugBounty Bot — HackerOne GraphQL API 클라이언트.

Researcher(개인) API: https://hackerone.com/graphql
인증: X-Auth-Token: <api_token>
"""
import httpx
from typing import Optional
from core.models import Report
from core.logger import get_logger

log = get_logger("hackerone")

H1_BASE_URL = "https://hackerone.com/graphql"


class HackerOneClient:
    """HackerOne GraphQL API 클라이언트."""

    def __init__(self, api_key: str, username: str = "",
                 session_id: str = "", csrf_token: str = ""):
        import os
        self.api_key = api_key
        self.username = username
        # 비어 있으면 환경변수에서 (submit/track는 api_key만 전달)
        self.session_id = session_id or os.environ.get("H1_SESSION_ID", "")
        self.csrf_token = csrf_token or os.environ.get("H1_CSRF_TOKEN", "")
        headers = {
            "X-Auth-Token": api_key,
            "Content-Type": "application/json",
        }
        # 세션 쿠키 + CSRF 토큰: mutation(쓰기)에 필요
        if csrf_token:
            headers["X-CSRF-Token"] = csrf_token
        cookies = {}
        if session_id:
            cookies["_session_id"] = session_id
        self.client = httpx.Client(
            headers=headers,
            cookies=cookies,
            timeout=30,
        )

    def _graphql(self, query: str, variables: dict = None) -> dict:
        """GraphQL 요청."""
        resp = self.client.post(
            H1_BASE_URL,
            json={"query": query, "variables": variables or {}},
        )
        if resp.status_code == 401:
            log.error("H1 API 401: 인증 실패 (X-Auth-Token 확인)")
        elif resp.status_code >= 400:
            log.error(f"H1 API {resp.status_code}: {resp.text[:200]}")
        resp.raise_for_status()
        data = resp.json()
        if "errors" in data:
            log.error(f"GraphQL error: {data['errors']}")
        return data.get("data", {})

    def verify(self) -> dict:
        """API 토큰 검증: me 쿼리."""
        data = self._graphql("{ me { id username } }")
        me = data.get("me")
        if me:
            log.info(f"H1 API verified: {me.get('username', '?')}")
        else:
            log.warning("H1 API: me is null (토큰 활성 확인)")
        return data

    def list_programs(self) -> list[dict]:
        """참여 중인 프로그램 목록.

        X-Auth-Token은 public query 인증이라 me=null일 수 있음.
        collaboration_invitations로 참여 프로그램 조회.
        """
        query = """
        query {
          me {
            collaboration_invitations(first: 50) {
              edges {
                node {
                  id
                }
              }
            }
          }
        }
        """
        data = self._graphql(query)
        me = data.get("me") or {}
        edges = me.get("collaboration_invitations", {}).get("edges", [])
        return [edge["node"] for edge in edges]

    def get_program_id(self, handle: str) -> Optional[str]:
        """프로그램 handle → numeric ID (createReport에 필요)."""
        query = """
        query($handle: String!) {
          program(handle: $handle) {
            id
            handle
            name
            offersBounties
          }
        }
        """
        data = self._graphql(query, {"handle": handle})
        prog = data.get("program")
        return prog.get("id") if prog else None

    def create_report(self, report: Report, program_handle: str) -> Optional[str]:
        """리포트 제출."""
        query = """
        mutation($programId: ID!, $title: String!, $brief: String!, $desc: String!, $severity: String!) {
          createReport(
            input: {
              programId: $programId
              title: $title
              brief_description: $brief
              description: $desc
              severity: $severity
            }
          ) {
            report { id }
          }
        }
        """
        data = self._graphql(query, {
            "programId": program_handle,
            "title": report.title,
            "brief": report.summary,
            "desc": f"## PoC\n\n{report.poc}\n\n## Impact\n\n{report.impact}\n\n## Recommendation\n\n{report.recommendation}",
            "severity": report.rating,
        })
        report_id = data.get("createReport", {}).get("report", {}).get("id")
        if report_id:
            log.info(f"Report submitted to {program_handle}: {report.title} (ID: {report_id})")
        return report_id

    def get_report_status(self, report_id: str) -> dict:
        """리포트 상태 조회."""
        query = """
        query($id: ID!) {
          report(id: $id) {
            id
            state
            severity
            title
          }
        }
        """
        return self._graphql(query, {"id": report_id})

    def close(self):
        self.client.close()
