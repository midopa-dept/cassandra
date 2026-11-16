"""BugBounty Bot — Nuclei CLI (subprocess)."""
import subprocess
import json
import os
import shutil
from typing import Optional
from core.models import Asset, Finding
from core.logger import get_logger

log = get_logger("scanner.nuclei")

NUCLEI_BIN = "nuclei"


def is_available() -> bool:
    """Nuclei 바이너리 존재 확인."""
    return shutil.which(NUCLEI_BIN) is not None


def scan_nuclei(asset: Asset, templates: list[str] = None, rate_limit: int = 10) -> list[Finding]:
    """Nuclei CLI: YAML 템플릿으로 스캔."""
    if not is_available():
        log.warning("Nuclei not found in PATH")
        return []

    findings = []
    targets = [asset.domain] + asset.subdomains

    # Build command
    cmd = [NUCLEI_BIN, "-json", "-rate-limit", str(rate_limit)]

    if templates:
        for template in templates:
            cmd.extend(["-t", template])
    else:
        # Default templates
        cmd.extend(["-t", "cves/", "-t", "exposures/", "-t", "misconfigurations/"])

    for target in targets:
        cmd.append(target)

    log.info(f"Nuclei: scanning {len(targets)} targets with {len(templates or [])} templates")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 min timeout
        )

        # Parse JSON output
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                if "type" in data and data["type"] == "default":
                    finding = Finding(
                        vuln_type=data.get("name", "nuclei"),
                        severity=data.get("severity", "info"),
                        endpoint=data.get("host", ""),
                        method=data.get("type", "GET"),
                        evidence=data.get("info", {}).get("description", "") or data.get("template", ""),
                        poc_request={
                            "method": data.get("type", "GET"),
                            "url": data.get("host", ""),
                        },
                        raw_data=data,
                    )
                    findings.append(finding)
            except json.JSONDecodeError:
                continue

    except subprocess.TimeoutExpired:
        log.warning("Nuclei timeout")
    except Exception as e:
        log.error(f"Nuclei error: {e}")

    log.info(f"Nuclei: {len(findings)} findings")
    return findings
