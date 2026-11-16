"""Cassandra — CLI 엔트리포인트.

도구(감각기관) + 에이전트(뇌) 아키텍처:
  - scanner: 관찰(HTML/폼/엔드포인트/헤더/에러) → 구조화 JSON
  - exploit: 에이전트 지시대로 공격 실행 → 결과 캡처
  - verify: 재현 + before/after 증거

에이전트는 이 CLI를 호출하고, JSON 출력을 읽고 판단한다.
"""
import argparse
import json
import sys
from .config import Config


def main():
    parser = argparse.ArgumentParser(prog="cassandra", description="Vulnerability scanner, exploit generator, verifier")
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Observe target: pages, forms, endpoints, headers, errors")
    p_scan.add_argument("url", help="Target URL (http://...)")
    p_scan.add_argument("--max-pages", type=int, default=None, help="Max pages to crawl")
    p_scan.add_argument("--login-url", default=None, help="Login form URL (e.g. /login.php)")
    p_scan.add_argument("--login-user", default=None, help="Login username")
    p_scan.add_argument("--login-pass", default=None, help="Login password")
    p_scan.add_argument("--json", action="store_true", help="Output as JSON (default)")

    # exploit
    p_exploit = sub.add_parser("exploit", help="Execute exploit instruction against target")
    p_exploit.add_argument("url", help="Target URL or endpoint")
    p_exploit.add_argument("--instruction", "-i", required=True, help="Agent's exploit instruction (natural language or structured)")
    p_exploit.add_argument("--method", default=None, help="HTTP method override")
    p_exploit.add_argument("--body", default=None, help="Request body override")
    p_exploit.add_argument("--header", action="append", help="Extra header (Key: Value), repeatable")
    p_exploit.add_argument("--compare-with", default=None, help="Baseline URL for diff comparison")
    p_exploit.add_argument("--json", action="store_true", help="Output as JSON (default)")
    p_exploit.add_argument("--login-url", default=None, help="Login form URL")
    p_exploit.add_argument("--login-user", default=None, help="Login username")
    p_exploit.add_argument("--login-pass", default=None, help="Login password")

    # sqli (auto probe)
    p_sqli = sub.add_parser("sqli", help="Auto SQLi probe: injectable param → technique → schema → data")
    p_sqli.add_argument("url", help="Target URL with query params (e.g. .../sqli/?id=1)")
    p_sqli.add_argument("--param", default=None, help="Probe only this parameter")
    p_sqli.add_argument("--max-cols", type=int, default=20, help="Max UNION columns to try")
    p_sqli.add_argument("--login-url", default=None, help="Login form URL")
    p_sqli.add_argument("--login-user", default=None, help="Login username")
    p_sqli.add_argument("--login-pass", default=None, help="Login password")

    p_sqli_login = sub.add_parser("sqli-login", help="SQLi probe on login form: bypass or extract credentials")
    p_sqli_login.add_argument("base_url", help="Base URL (e.g. http://localhost:8081)")
    p_sqli_login.add_argument("--login-url", required=True, help="Login form URL (e.g. /login.php)")

    p_brute = sub.add_parser("bruteforce", help="Bruteforce login form with a dictionary (black-box)")
    p_brute.add_argument("base_url", help="Base URL (e.g. http://localhost:8081)")
    p_brute.add_argument("--login-url", required=True, help="Login form URL (e.g. /login.php)")
    p_brute.add_argument("--users", default=None, help="Comma-separated usernames (default: built-in list)")
    p_brute.add_argument("--passwords", default=None, help="Comma-separated passwords (default: built-in list)")
    p_brute.add_argument("--max-attempts", type=int, default=100)

    # verify
    p_verify = sub.add_parser("verify", help="Reproduce a finding and capture evidence")
    p_verify.add_argument("url", help="Target URL")
    p_verify.add_argument("--instruction", "-i", required=True, help="How to reproduce")
    p_verify.add_argument("--expected", default=None, help="What to expect (for pass/fail)")
    p_verify.add_argument("--method", default=None, help="HTTP method override")
    p_verify.add_argument("--body", default=None, help="Request body override")
    p_verify.add_argument("--baseline-url", default=None, help="Baseline URL for comparison (default: url itself)")
    p_verify.add_argument("--headers", default=None, help='Extra headers as JSON (e.g. \'{"Authorization":"Bearer ..."}\')')
    p_verify.add_argument("--baseline-headers", default=None, help='Baseline headers as JSON')
    p_verify.add_argument("--json", action="store_true", help="Output as JSON (default)")
    p_verify.add_argument("--login-url", default=None, help="Login form URL")
    p_verify.add_argument("--login-user", default=None, help="Login username")
    p_verify.add_argument("--login-pass", default=None, help="Login password")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    config = Config.load()

    if args.command == "scan":
        from scanner.context import ScannerContext
        ctx = ScannerContext(config)
        login = None
        if args.login_url and args.login_user:
            login = {"url": args.login_url, "username": args.login_user, "password": args.login_pass or ""}
        result = ctx.scan(args.url, max_pages=args.max_pages, login=login)
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.command == "exploit":
        from exploit.executor import ExploitExecutor
        headers = {}
        if args.header:
            for h in args.header:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        ex = ExploitExecutor(config)
        if args.login_url and args.login_user:
            from urllib.parse import urlparse
            u = urlparse(args.url)
            base = f"{u.scheme}://{u.netloc}"
            ex.login(base, args.login_url, args.login_user, args.login_pass or "")
        result = ex.execute(
            url=args.url,
            instruction=args.instruction,
            method=args.method,
            body=args.body,
            headers=headers,
            compare_with=args.compare_with,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.command == "sqli":
        from exploit.executor import ExploitExecutor
        ex = ExploitExecutor(config)
        if args.login_url and args.login_user:
            from urllib.parse import urlparse
            u = urlparse(args.url)
            base = f"{u.scheme}://{u.netloc}"
            ex.login(base, args.login_url, args.login_user, args.login_pass or "")
        result = ex.sqli_probe(args.url, param=args.param, max_cols=args.max_cols)
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.command == "sqli-login":
        from exploit.executor import ExploitExecutor
        ex = ExploitExecutor(config)
        result = ex.sqli_login_probe(args.base_url, args.login_url)
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.command == "bruteforce":
        from exploit.bruteforce import Bruteforcer, DEFAULT_USERNAMES, DEFAULT_PASSWORDS
        bf = Bruteforcer(config)
        users = args.users.split(",") if args.users else DEFAULT_USERNAMES
        pwds = args.passwords.split(",") if args.passwords else DEFAULT_PASSWORDS
        result = bf.run(args.base_url, args.login_url, users, pwds, max_attempts=args.max_attempts)
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.command == "verify":
        from verify.evidence import Verifier
        v = Verifier(config)
        if args.login_url and args.login_user:
            from urllib.parse import urlparse
            u = urlparse(args.url)
            base = f"{u.scheme}://{u.netloc}"
            v.login(base, args.login_url, args.login_user, args.login_pass or "")
        result = v.verify(
            url=args.url,
            instruction=args.instruction,
            expected=args.expected,
            baseline_url=args.baseline_url,
            method=args.method,
            body=args.body,
            headers=json.loads(args.headers) if args.headers else None,
            baseline_headers=json.loads(args.baseline_headers) if args.baseline_headers else None,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
