"""BugBounty Bot — 설정 로드."""
import os
import yaml
from dataclasses import dataclass, field
from typing import Optional
from dotenv import load_dotenv


@dataclass
class HackerOneConfig:
    api_key_env: str = "H1_API_KEY"
    programs: list[str] = field(default_factory=list)

    @property
    def api_key(self) -> str:
        return os.environ.get(self.api_key_env, "")


@dataclass
class ScanConfig:
    nuclei_templates: list[str] = field(default_factory=lambda: ["cves/", "exposures/", "misconfigurations/"])
    custom: list[str] = field(default_factory=lambda: ["sqli", "xss", "idor", "ssrf", "auth_bypass", "race_condition"])
    rate_limit: int = 10  # req/s per target
    concurrent: int = 5


@dataclass
class LLMConfig:
    provider: str = "openai"  # openai | anthropic | ollama
    model: str = "gpt-4o"
    api_key_env: str = "OPENAI_API_KEY"
    auto_submit_min: str = "high"  # low | medium | high | critical

    @property
    def api_key(self) -> str:
        return os.environ.get(self.api_key_env, "")


@dataclass
class SchedulerConfig:
    ct_min: int = 60
    dns_min: int = 360
    rescan_min: int = 1440
    triage_min: int = 60


@dataclass
class WebConfig:
    host: str = "0.0.0.0"
    port: int = 8500


@dataclass
class Config:
    hackerone: HackerOneConfig = field(default_factory=HackerOneConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    scheduler: SchedulerConfig = field(default_factory=SchedulerConfig)
    web: WebConfig = field(default_factory=WebConfig)
    db_path: str = "bugbounty.db"

    @classmethod
    def load(cls, path: str = "config.yaml") -> "Config":
        load_dotenv()
        if not os.path.exists(path):
            return cls()
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls(
            hackerone=HackerOneConfig(**data.get("hackerone", {})),
            scan=ScanConfig(**data.get("scan", {})),
            llm=LLMConfig(**data.get("llm", {})),
            scheduler=SchedulerConfig(**data.get("scheduler", {})),
            web=WebConfig(**data.get("web", {})),
            db_path=data.get("db_path", "bugbounty.db"),
        )
