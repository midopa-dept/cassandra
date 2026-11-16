"""BugBounty Bot — 인프라 스캐너 (DNS, TLS, subdomain takeover, S3/GCS)."""
import ssl
import socket
import httpx
import dns.resolver
from datetime import datetime, timedelta
from typing import Optional
from core.models import Asset, Finding
from core.logger import get_logger

log = get_logger("scanner.infra")


# ── TLS ───────────────────────────────────────────────────────────────

WEAK_CIPHERS = [
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",  # CBC mode (not ideal)
    "TLS_RSA_WITH_AES_256_CBC_SHA",
]


def scan_tls(hostname: str, port: int = 443) -> list[Finding]:
    """TLS 스캔: weak cipher, cert expiry, protocol version."""
    findings = []

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Protocol version
                proto = ssock.version()
                if proto in ("TLSv1", "TLSv1.1"):
                    findings.append(Finding(
                        vuln_type="tls_weak_protocol",
                        severity="medium",
                        endpoint=f"https://{hostname}:{port}",
                        method="TLS",
                        evidence=f"Weak TLS protocol: {proto}",
                        poc_request={"method": "TLS", "url": f"https://{hostname}:{port}"},
                        raw_data={"protocol": proto},
                    ))

                # Cipher
                cipher = ssock.cipher()[0]
                if cipher in WEAK_CIPHERS:
                    findings.append(Finding(
                        vuln_type="tls_weak_cipher",
                        severity="medium",
                        endpoint=f"https://{hostname}:{port}",
                        method="TLS",
                        evidence=f"Weak TLS cipher: {cipher}",
                        poc_request={"method": "TLS", "url": f"https://{hostname}:{port}"},
                        raw_data={"cipher": cipher},
                    ))

                # Certificate expiry
                cert = ssock.getpeercert()
                if cert:
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (expiry - datetime.utcnow()).days
                            if days_left < 30:
                                findings.append(Finding(
                                    vuln_type="tls_cert_expiring",
                                    severity="low",
                                    endpoint=f"https://{hostname}:{port}",
                                    method="TLS",
                                    evidence=f"Certificate expires in {days_left} days ({not_after})",
                                    poc_request={"method": "TLS", "url": f"https://{hostname}:{port}"},
                                    raw_data={"not_after": not_after, "days_left": days_left},
                                ))
                        except ValueError:
                            pass

    except (ssl.SSLError, socket.error, OSError) as e:
        log.debug(f"TLS scan failed for {hostname}:{port}: {e}")

    return findings


# ── Subdomain Takeover ────────────────────────────────────────────────

TAKEOVER_SIGNATURES = {
    "github.io": ["404", "Not Found", "github.io"],
    "herokuapp.com": ["Application Error", "heroku", "A1234"],
    "s3.amazonaws.com": ["NoSuchBucket", "AccessDenied", "NoSuchKey"],
    "s3-*.amazonaws.com": ["NoSuchBucket", "AccessDenied"],
    "blob.core.windows.net": ["404", "Not Found", "The specified blob does not exist"],
    "pages.dev": ["404", "Not Found", "pages.dev"],
    "netlify.app": ["404", "Not Found", "netlify"],
    "cloudfront.net": ["404", "Not Found", "cloudfront"],
    "fastly.net": ["404", "Not Found", "fastly"],
    "akamaihd.net": ["404", "Not Found", "akamai"],
}


def scan_subdomain_takeover(hostname: str, cname: Optional[str] = None) -> list[Finding]:
    """Subdomain takeover: CNAME가 dangling (404 + known platform)."""
    findings = []

    # Get CNAME
    if cname is None:
        try:
            answers = dns.resolver.resolve(hostname, "CNAME")
            cname = answers[0].to_text().rstrip(".")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return findings
        except Exception:
            return findings

    if not cname:
        return findings

    # Check if CNAME points to a known platform
    for platform, signatures in TAKEOVER_SIGNATURES.items():
        if platform in cname or cname.endswith(platform):
            # Try to access the subdomain
            try:
                resp = httpx.get(f"https://{hostname}", timeout=10, follow_redirects=True)
                text = resp.text.lower()

                # If 404 and matches platform signature, potential takeover
                if resp.status_code == 404:
                    for sig in signatures:
                        if sig.lower() in text:
                            findings.append(Finding(
                                vuln_type="subdomain_takeover",
                                severity="high",
                                endpoint=f"https://{hostname}",
                                method="CNAME",
                                evidence=f"Subdomain takeover: {hostname} → {cname} (404 + {sig})",
                                poc_request={"method": "CNAME", "url": f"https://{hostname}", "cname": cname},
                                raw_data={"cname": cname, "status_code": resp.status_code},
                            ))
                            break
            except Exception:
                continue

    return findings


# ── S3/GCS Bucket ─────────────────────────────────────────────────────

def scan_s3_bucket(bucket_name: str) -> list[Finding]:
    """S3 bucket: list, read, write 권한 확인."""
    findings = []
    base_url = f"https://{bucket_name}.s3.amazonaws.com"

    try:
        # Try to list bucket
        resp = httpx.get(base_url, timeout=10)
        if resp.status_code == 200:
            findings.append(Finding(
                vuln_type="s3_bucket_listable",
                severity="medium",
                endpoint=base_url,
                method="GET",
                evidence=f"S3 bucket {bucket_name} is listable",
                poc_request={"method": "GET", "url": base_url},
                raw_data={"status_code": resp.status_code},
            ))
        elif resp.status_code == 403:
            # Access denied but bucket exists
            pass
        elif resp.status_code == 404:
            # Bucket doesn't exist
            pass

        # Try to read common files
        for path in ["/index.html", "/.env", "/config.json", "/backup.zip"]:
            resp = httpx.get(f"{base_url}{path}", timeout=10)
            if resp.status_code == 200 and len(resp.content) > 0:
                findings.append(Finding(
                    vuln_type="s3_file_readable",
                    severity="high" if path in ["/.env", "/config.json", "/backup.zip"] else "medium",
                    endpoint=f"{base_url}{path}",
                    method="GET",
                    evidence=f"S3 file {path} is readable ({len(resp.content)} bytes)",
                    poc_request={"method": "GET", "url": f"{base_url}{path}"},
                    raw_data={"status_code": resp.status_code, "size": len(resp.content)},
                ))

    except Exception as e:
        log.debug(f"S3 scan failed for {bucket_name}: {e}")

    return findings


# ── DNS Misconfig ─────────────────────────────────────────────────────

def scan_dns_misconfig(domain: str) -> list[Finding]:
    """DNS misconfig: open resolver, wildcard, etc."""
    findings = []

    # Check for wildcard DNS
    try:
        # Try a random subdomain
        import random
        random_sub = f"random{random.randint(10000, 99999)}.{domain}"
        answers = dns.resolver.resolve(random_sub, "A")
        if answers:
            findings.append(Finding(
                vuln_type="dns_wildcard",
                severity="low",
                endpoint=f"dns://{domain}",
                method="DNS",
                evidence=f"Wildcard DNS: {random_sub} resolves to {answers[0]}",
                poc_request={"method": "DNS", "url": f"dns://{domain}"},
                raw_data={"random_sub": random_sub, "resolved": str(answers[0])},
            ))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except Exception:
        pass

    return findings


# ── 메인 스캔 함수 ────────────────────────────────────────────────────

def scan_infra(asset: Asset) -> list[Finding]:
    """인프라 스캔: TLS, subdomain takeover, S3, DNS misconfig."""
    findings = []

    # TLS
    if asset.domain.startswith("http"):
        hostname = asset.domain.replace("https://", "").replace("http://", "").split(":")[0]
        port = 443 if "https" in asset.domain else 80
        if "https" in asset.domain:
            findings.extend(scan_tls(hostname, port))
    else:
        findings.extend(scan_tls(asset.domain, 443))

    # Subdomain takeover
    for sub in asset.subdomains:
        findings.extend(scan_subdomain_takeover(sub))

    # S3 (if domain looks like a bucket)
    if ".s3.amazonaws.com" in asset.domain or ".s3." in asset.domain:
        bucket = asset.domain.split(".s3.amazonaws.com")[0]
        findings.extend(scan_s3_bucket(bucket))

    # DNS misconfig
    findings.extend(scan_dns_misconfig(asset.domain))

    return findings
