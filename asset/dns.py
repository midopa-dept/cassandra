"""BugBounty Bot — DNS brute-force + recon."""
import dns.resolver
import dns.reversename
from typing import Optional
from core.models import Asset
from core.logger import get_logger

log = get_logger("asset.dns")

# Common subdomain wordlist (small, extendable)
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "dev", "staging", "test", "beta", "admin",
    "api", "app", "blog", "shop", "store", "cdn", "static", "assets",
    "img", "images", "files", "docs", "wiki", "help", "support",
    "portal", "dashboard", "login", "auth", "sso", "oauth",
    "db", "database", "mysql", "postgres", "mongo", "redis",
    "git", "github", "gitlab", "jenkins", "ci", "cd",
    "s3", "storage", "bucket", "oss", "blob",
    "vpn", "remote", "rdp", "ssh", "bastion",
    "internal", "intranet", "private", "corp",
    "dev1", "dev2", "staging1", "staging2", "test1", "test2",
    "prod", "production", "live", "main",
    "eu", "us", "uk", "de", "fr", "jp", "kr", "sg", "au", "ca",
    "n1", "n2", "n3", "node1", "node2", "node3",
    "web", "web1", "web2", "web3",
    "app1", "app2", "app3",
    "service", "services", "micro", "microservice",
    "gateway", "proxy", "lb", "loadbalancer",
    "monitor", "monitoring", "grafana", "prometheus", "kibana",
    "elastic", "elasticsearch", "log", "logging",
    "search", "solr", "meilisearch",
    "cache", "memcached", "varnish",
    "queue", "rabbitmq", "kafka", "nsq",
    "auth0", "cognito", "okta", "keycloak",
    "sentry", "bugsnag", "newrelic", "datadog",
    "heroku", "netlify", "vercel", "cloudflare",
    "aws", "azure", "gcp", "google", "amazon", "microsoft",
]


def dns_resolve(hostname: str, record_type: str = "A") -> list[str]:
    """DNS 조회: A, AAAA, CNAME, MX, TXT."""
    try:
        answers = dns.resolver.resolve(hostname, record_type)
        return [r.to_text() for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except Exception:
        return []


def dns_brute(domain: str) -> list[str]:
    """DNS brute-force: wordlist로 서브도메인 탐색."""
    found = []
    for word in SUBDOMAIN_WORDLIST:
        subdomain = f"{word}.{domain}"
        try:
            answers = dns.resolver.resolve(subdomain, "A")
            if answers:
                found.append(subdomain)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except Exception:
            continue

    log.info(f"DNS brute: {domain} → {len(found)} subdomains")
    return found


def dns_recon(domain: str) -> dict:
    """DNS recon: A, AAAA, CNAME, MX, TXT."""
    result = {
        "domain": domain,
        "a": dns_resolve(domain, "A"),
        "aaaa": dns_resolve(domain, "AAAA"),
        "cname": dns_resolve(domain, "CNAME"),
        "mx": dns_resolve(domain, "MX"),
        "txt": dns_resolve(domain, "TXT"),
    }
    return result


def discover_assets(domain: str, program: str = "") -> list[Asset]:
    """DNS brute + recon → Asset 객체."""
    subdomains = dns_brute(domain)
    recon = dns_recon(domain)

    assets = []
    for sub in subdomains:
        asset = Asset(
            domain=sub,
            subdomains=[sub],
            program=program,
            scope="in",
        )
        assets.append(asset)

    # Main domain
    main_asset = Asset(
        domain=domain,
        subdomains=subdomains,
        program=program,
        scope="in",
    )
    assets.append(main_asset)

    return assets
