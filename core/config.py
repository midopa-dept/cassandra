"""Cassandra — 설정 로드."""
import os
import yaml
from dataclasses import dataclass, field
from typing import Optional
from dotenv import load_dotenv


@dataclass
class ScanConfig:
    rate_limit: int = 10  # req/s per target
    concurrent: int = 5
    timeout: int = 10  # seconds
    user_agent: str = "Mozilla/5.0 (Cassandra)"
    max_pages: int = 100
    follow_redirects: bool = True


@dataclass
class Config:
    scan: ScanConfig = field(default_factory=ScanConfig)
    db_path: str = "cassandra.db"

    @classmethod
    def load(cls, path: str = "config.yaml") -> "Config":
        load_dotenv()
        if not os.path.exists(path):
            return cls()
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls(
            scan=ScanConfig(**data.get("scan", {})),
            db_path=data.get("db_path", "cassandra.db"),
        )
