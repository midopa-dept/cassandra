"""BugBounty Bot — HackerOne API 클라이언트."""
import httpx
from typing import Optional
from core.models import Report
from core.logger import get_logger

log = get_logger("hackerone")

H1_BASE_URL = "https://hackerone.com/graphql"


class HackerOneClient:
    """HackerOne GraphQL API 클라이언트."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.client = httpx.Client(
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=30,
        )

    def _graphql(self, query: str, variables: dict = None) -> dict:
        """GraphQL 요청."""
        resp = self.client.post(
            H1_BASE_URL,
            json={"query": query, "variables": variables or {}},
        )
        resp.raise_for_status()
        data = resp.json()
        if "errors" in data:
            log.error(f"GraphQL error: {data['errors']}")
        return data.get("data", {})

    def list_programs(self) -> list[dict]:
        """대상 프로그램 목록."""
        query = """
        query {
          viewer {
            collaborations(first: 50) {
              edges {
                node {
                  id
                  name
                  handle
                  offersBounties
                }
              }
            }
          }
        }
        """
        data = self._graphql(query)
        edges = data.get("viewer", {}).get("collaborations", {}).get("edges", [])
        return [edge["node"] for edge in edges]

    def create_report(self, report: Report, program_handle: str) -> Optional[str]:
        """리포트 제출. HackerOne report ID 반환."""
        query = """
        mutation($programHandle: String!, $title: String!, $brief: String!, $description: String!, $severity: String!) {
          createSubmission(
            input: {
              programHandle: $programHandle,
              title: $title,
              brief: $brief,
              description: $description,
              severity: $severity
            }
          ) {
            submission {
              id
              url
            }
          }
        }
        """
        variables = {
            "programHandle": program_handle,
            "title": report.title,
            "brief": report.summary,
            "description": f"## PoC\n\n{report.poc}\n\n## Impact\n\n{report.impact}\n\n## Recommendation\n\n{report.recommendation}",
            "severity": report.rating,
        }
        data = self._graphql(query, variables)
        submission = data.get("createSubmission", {}).get("submission", {})
        report_id = submission.get("id")
        if report_id:
            log.info(f"Report submitted to {program_handle}: {report.title} (ID: {report_id})")
        return report_id

    def get_report_status(self, report_id: str) -> dict:
        """리포트 상태 조회."""
        query = """
        query($id: ID!) {
          submission(id: $id) {
            id
            state
            title
            bounty
            reward
          }
        }
        """
        data = self._graphql(query, {"id": report_id})
        return data.get("submission", {})

    def close(self):
        self.client.close()
