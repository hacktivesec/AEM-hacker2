from __future__ import annotations

import argparse
import sys
import textwrap

import urllib3
from urllib3.exceptions import InsecureRequestWarning

from .checks.base import check_selected
from .checks.registry import get_all_checks
from .coverage_matrix import markdown_matrix
from .engine import run_scan
from .models import ScanConfig
from .reporting import print_terminal_report, write_json, write_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Production-grade AEM pentest CLI with safe defaults and AEM-specific checks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              python3 aem_audit.py --target https://aem.example
              python3 aem_audit.py --target https://aem.example --profile deep --active-tests
              python3 aem_audit.py --target https://aem.example --username admin --password '***' --profile authenticated-deep
              python3 aem_audit.py --target https://aem.example --proxy http://127.0.0.1:8080 --insecure
              python3 aem_audit.py --target https://aem.example --active-tests --include-state-changing
            """
        ),
    )

    parser.add_argument("--target", required=True, help="AEM base URL, e.g. https://aem.example.com")
    parser.add_argument("--username", help="Username for authenticated checks")
    parser.add_argument("--password", help="Password for authenticated checks")

    parser.add_argument("--proxy", help="http(s)://host:port or socks5://host:port proxy")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")

    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds")
    parser.add_argument("--workers", type=int, default=8, help="Concurrent worker threads")
    parser.add_argument("--rate-limit", type=float, default=12.0, help="Max requests per second")
    parser.add_argument("--retries", type=int, default=2, help="Network retry attempts")
    parser.add_argument("--backoff", type=float, default=0.5, help="Retry exponential backoff base seconds")

    parser.add_argument(
        "--profile",
        choices=["quick", "standard", "deep", "authenticated-deep"],
        default="standard",
        help="Scan profile",
    )
    parser.add_argument("--include-check", action="append", default=[], help="Include specific check ID/name/tag")
    parser.add_argument("--exclude-check", action="append", default=[], help="Exclude specific check ID/name/tag")

    parser.add_argument(
        "--active-tests",
        action="store_true",
        help=(
            "Enable active (non-passive) checks that send exploit-like probes to the target. "
            "Includes: SSRF callback triggers, default credential brute-force, and CSRF token reads. "
            "Does NOT write or delete repository content — use --include-state-changing for that. "
            "Requires explicit written authorisation from the target owner before use."
        ),
    )
    parser.add_argument(
        "--include-state-changing",
        action="store_true",
        help=(
            "Enable checks that write, upload, or delete content on the target (requires --active-tests). "
            "Includes AEM-SLING-001 (Sling POST write), AEM-CVE25-003 (Package Manager ZIP upload), "
            "AEM-CVE25-004 (EL injection config write), AEM-DESER-001 (Java deser DAM probe — may cause OOM), "
            "AEM-ACT-100 (create/delete node probe). Cleanup is attempted but NOT guaranteed."
        ),
    )

    parser.add_argument("--json-out", help="Optional JSON output path")
    parser.add_argument("--md-out", help="Optional Markdown output path")

    parser.add_argument("--dry-run", action="store_true", help="Show planned behavior without network execution")
    parser.add_argument("--print-coverage-matrix", action="store_true", help="Print AEM Hacker coverage matrix")

    parser.add_argument(
        "--oob-collector",
        help=(
            "Out-of-band callback URL for active SSRF probes (e.g. https://<id>.oast.fun or Interactsh URL). "
            "When provided, LinkChecker SSRF checks will POST this URL and flag any response content match."
        ),
    )

    parser.add_argument(
        "--cookie",
        help=(
            "Raw Cookie header value sent with every request. "
            "Useful for BIG-IP APM session cookies (e.g. 'MRHSession=abc123; LastMRH_Session=xyz; F5_ST=abc') "
            "or any pre-authenticated session token that sits in front of AEM."
        ),
    )

    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        dest="yes",
        help="Skip interactive confirmation prompts (for use in CI / scripted pipelines).",
    )

    parser.add_argument(
        "--user-agent",
        dest="user_agent",
        default=None,
        help=(
            "Custom User-Agent string sent with every request. "
            "Defaults to 'AEM-Audit-Pro/2.0' when not specified. "
            "Useful for WAF bypass, blending with legitimate traffic, or impersonating a specific browser."
        ),
    )

    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def run(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.print_coverage_matrix:
        print(markdown_matrix())
        return 0

    if args.include_state_changing and not args.active_tests:
        print("[!] --include-state-changing requires --active-tests")
        return 2

    if args.profile == "authenticated-deep" and not (args.username and args.password):
        print("[!] authenticated-deep profile selected without credentials; authenticated checks will be skipped.")

    if args.insecure:
        urllib3.disable_warnings(InsecureRequestWarning)

    if args.active_tests:
        print()
        print("  ╔══ ACTIVE TESTS ENABLED ════════════════════════════════════════╗")
        print("  ║                                                                ║")
        print("  ║  --active-tests sends exploit-like probes to the target,       ║")
        print("  ║  including SSRF callback triggers and default credential       ║")
        print("  ║  brute-force against login endpoints.                          ║")
        print("  ║                                                                ║")
        print("  ║  These checks do NOT require credentials, but WILL generate    ║")
        print("  ║  auth failure log entries on the target server.                ║")
        print("  ║                                                                ║")
        print("  ║  Only proceed if you have EXPLICIT WRITTEN AUTHORISATION.      ║")
        print("  ╚════════════════════════════════════════════════════════════════╝")
        print()
        if not getattr(args, "yes", False):
            try:
                answer = input("  Confirm you have written authorisation to test this target [yes/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Aborted.")
                return 1
            if answer != "yes":
                print("[!] Aborted — re-run with explicit confirmation or remove --active-tests.")
                return 1

    if args.include_state_changing:
        print()
        print("  ╔══ STATE-CHANGING CHECKS ENABLED ═══════════════════════════════╗")
        print("  ║                                                                ║")
        print("  ║  The following checks WRITE TO or DELETE FROM the repository:  ║")
        print("  ║    AEM-SLING-001  Sling POST write probe (/content/, /etc/)    ║")
        print("  ║    AEM-CVE25-003  Package Manager malicious ZIP upload         ║")
        print("  ║    AEM-CVE25-004  EL injection payload written to JCR node     ║")
        print("  ║    AEM-DESER-001  Java deser probe — MAY CRASH AEM DAM (OOM)  ║")
        print("  ║    AEM-ACT-100    Create/delete node probe                     ║")
        print("  ║                                                                ║")
        print("  ║  Cleanup is attempted automatically but NOT guaranteed.        ║")
        print("  ║  Requires a change window and rollback plan.                   ║")
        print("  ╚════════════════════════════════════════════════════════════════╝")
        print()
        if not getattr(args, "yes", False):
            try:
                answer = input("  Confirm change window approved and rollback plan in place [yes/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Aborted.")
                return 1
            if answer != "yes":
                print("[!] Aborted — re-run with explicit confirmation or remove --include-state-changing.")
                return 1

    if getattr(args, "oob_collector", None):
        print(f"[*] OOB collector URL set: {args.oob_collector}")
        print("[!] Ensure you own or have explicit written permission to use this OOB endpoint.")

    if getattr(args, "cookie", None):
        cookie_names = [part.split("=")[0].strip() for part in args.cookie.split(";") if "=" in part]
        print(f"[*] Cookie header set — injecting into all requests. Names: {', '.join(cookie_names)}")

    if getattr(args, "user_agent", None):
        print(f"[*] User-Agent overridden: {args.user_agent}")

    config = ScanConfig(
        target=args.target,
        username=args.username,
        password=args.password,
        proxy=args.proxy,
        timeout=args.timeout,
        verify_ssl=not args.insecure,
        workers=max(1, args.workers),
        rate_limit=max(0.0, args.rate_limit),
        retries=max(0, args.retries),
        backoff=max(0.0, args.backoff),
        active_tests=args.active_tests,
        include_state_changing=args.include_state_changing,
        profile=args.profile,
        include_checks=args.include_check,
        exclude_checks=args.exclude_check,
        json_out=args.json_out,
        md_out=args.md_out,
        dry_run=args.dry_run,
        oob_collector=getattr(args, "oob_collector", None),
        cookie=getattr(args, "cookie", None),
        user_agent=getattr(args, "user_agent", None),
    )

    if args.dry_run:
        print("=== Dry Run ===")
        print(f"Target: {config.target}")
        print(f"Profile: {config.profile}")
        print(f"Workers: {config.workers}, Rate limit: {config.rate_limit} req/s")
        print(f"Active tests: {config.active_tests}, State-changing: {config.include_state_changing}")
        print(f"Include selectors: {config.include_checks or ['<all>']}")
        print(f"Exclude selectors: {config.exclude_checks or ['<none>']}")
        if config.cookie:
            cookie_names = [p.split("=")[0].strip() for p in config.cookie.split(";") if "=" in p]
            print(f"Cookie names injected: {', '.join(cookie_names)}")

        selected = []
        for check in get_all_checks():
            if not check_selected(check, config.profile, config.include_checks, config.exclude_checks):
                continue
            if check.requires_auth and not (config.username and config.password):
                continue
            if check.active and not config.active_tests:
                continue
            if check.name == "state-changing" and not config.include_state_changing:
                continue
            selected.append(f"{check.check_id}:{check.name}")

        print("Planned checks:")
        for item in selected:
            print(f"- {item}")
        return 0

    try:
        report = run_scan(config)
    except ValueError as exc:
        print(f"[!] Invalid configuration: {exc}")
        return 2

    print_terminal_report(report)

    if config.json_out:
        write_json(config.json_out, report)
        print(f"JSON written to: {config.json_out}")
    if config.md_out:
        write_markdown(config.md_out, report)
        print(f"Markdown written to: {config.md_out}")

    return 0


def main() -> None:
    code = run()
    raise SystemExit(code)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(130)
