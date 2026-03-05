# AEM Hacker

CLI tool for testing Adobe Experience Manager installations during a pentest.

---

## Install

```bash
pip install -r requirements.txt
```

---

## Quick start

```bash
# Basic scan
python3 aem_audit.py --target https://aem.example.com

# Deep scan through Burp
python3 aem_audit.py --target https://aem.example.com --profile deep \
  --proxy http://127.0.0.1:8080 --insecure

# Deep scan with SSRF OOB and saved reports
python3 aem_audit.py --target https://aem.example.com \
  --profile deep --active-tests \
  --oob-collector https://<id>.oast.fun \
  --json-out report.json --md-out report.md

# Behind BIG-IP APM — inject session cookies
python3 aem_audit.py --target https://aem.example.com --profile deep \
  --cookie 'MRHSession=abc123; LastMRH_Session=abc123; F5_ST=xyz'

# Authenticated scan
python3 aem_audit.py --target https://aem.example.com \
  --profile authenticated-deep --username admin --password 'pass'

# Enable write/delete probes (explicit authorisation required)
python3 aem_audit.py --target https://aem.example.com \
  --profile deep --active-tests --include-state-changing

# SOCKS5 via SSH tunnel
python3 aem_audit.py --target https://aem.example.com --proxy socks5://127.0.0.1:1080

# Run only specific checks
python3 aem_audit.py --target https://aem.example.com --include-check dispatcher
python3 aem_audit.py --target https://aem.example.com --exclude-check exposure

# Preview what would run — no network calls
python3 aem_audit.py --target https://aem.example.com --profile deep --dry-run

# Print coverage matrix
python3 aem_audit.py --print-coverage-matrix
```

---

## Checks

| Check ID | Name | Profile | Active? | Description |
|---|---|---|---|---|
| `AEM-FP-001` | `fingerprint` | all | — | AEM detection and version fingerprinting |
| `AEM-EDGE-001` | `edge-blocking-detection` | all | — | WAF / reverse-proxy detection (BIG-IP, Dispatcher) |
| `AEM-EXP-001` | `exposure` | all | — | 108+ endpoint probes (CRX, OSGi, PackageMgr, Replication, …) |
| `AEM-VCLASS-001` | `vuln-classes` | standard+ | — | Known vulnerable endpoint classes |
| `AEM-DISP-001` | `dispatcher-bypass` | deep+ | — | Basic Dispatcher bypass |
| `AEM-DISP-002` | `advanced-dispatcher-bypass` | standard+ | — | 14-technique bypass matrix (`..;/`, `//`, `%2f`, `%252f`, `%00`, tab, …) |
| `AEM-SEL-001` | `selector-bypass` | standard+ | — | Sling selector abuse (`.json`, `.infinity.json`, `.tidy.json`, `.-1.json`, …) |
| `AEM-QB-001` | `querybuilder-dump` | standard+ | — | QueryBuilder JCR dump (users, groups, OSGi, DAM, replication agents) |
| `AEM-SLING-001` | `sling-post` | deep+ | ✓ | Sling POST servlet write probe with cleanup |
| `AEM-SSRF-001` | `linkchecker-ssrf` | deep+ | ✓ | LinkChecker SSRF — cloud metadata (AWS, GCP, Azure, Alibaba) + OOB |
| `AEM-AUTH-001` | `authenticated-audit` | authenticated-deep | — | Post-auth surface checks |
| `AEM-ACT-001` | `active-safe` | standard+ | ✓ | CSRF token endpoint probe |
| `AEM-ACT-100` | `state-changing` | deep+ | ✓ | Node create/delete probe with cleanup |
| **CVE-2025 (APSB25-90)** | | | | |
| `AEM-CVE25-001` | `cve2025-querybuilder` | standard+ | — | QueryBuilder password-hash / writable-node disclosure (CVE-2025-54246..52) |
| `AEM-CVE25-002` | `cve2025-mstoken-ssrf` | deep+ | ✓ | SSRF via `/services/accesstoken/verify` (CVE-2025-54251) |
| `AEM-CVE25-003` | `cve2025-packmgr-xxe` | deep+ | ✓ | XXE via ZIP upload to Package Manager (CVE-2025-54249) |
| `AEM-CVE25-004` | `cve2025-el-injection` | deep+ | ✓ | EL injection via DAM cloud settings config (CVE-2025-54250) |
| **Legacy** | | | | |
| `AEM-CREDS-001` | `default-credentials` | standard+ | ✓ | Default credentials (admin:admin, author:author, …) |
| `AEM-XSS-001` | `wcmdebugfilter-xss` | standard+ | — | WCMDebugFilter reflected XSS `?debug=layout` (CVE-2016-7882) |
| `AEM-XSS-002` | `wcmsuggestions-xss` | standard+ | — | WCMSuggestionsServlet reflected XSS |
| `AEM-XSS-003` | `swf-xss` | standard+ | — | Legacy SWF served without Content-Disposition |
| `AEM-SSRF-002` | `salesforce-ssrf` | deep+ | ✓ | Salesforce OAuth servlet SSRF (CVE-2018-5006) |
| `AEM-SSRF-003` | `reportingservices-ssrf` | deep+ | ✓ | ContentInsight ReportingServices SSRF (CVE-2018-12809) |
| `AEM-SSRF-004` | `sitecatalyst-ssrf` | deep+ | ✓ | SiteCatalyst segments servlet SSRF |
| `AEM-SSRF-005` | `opensocial-ssrf` | deep+ | ✓ | OpenSocial (Shindig) proxy SSRF |
| `AEM-WEBDAV-001` | `webdav-exposure` | standard+ | — | WebDAV exposure on `/crx/repository/` — XXE risk (CVE-2015-1833) |
| `AEM-AUDIT-001` | `auditlog-servlet` | standard+ | — | Unauthenticated AuditLog servlet |
| `AEM-DESER-001` | `externaljob-deserialization` | deep+ | ✓ | ExternalJobServlet Java deserialization probe |

---

## Profiles

| Profile | Checks run | When to use |
|---|---|---|
| `quick` | ~25 endpoints | Fast baseline |
| `standard` | ~42 endpoints | Default |
| `deep` | ~108 endpoints | Full pentest |
| `authenticated-deep` | ~108 + auth checks | Post-auth / insider audit |

---

## CLI flags

| Flag | Default | Description |
|---|---|---|
| `--target` | required | AEM base URL |
| `--profile` | `standard` | Scan profile |
| `--active-tests` | off | Enable active probes (SSRF callbacks, credential brute-force, CSRF reads) |
| `--include-state-changing` | off | Enable write/delete probes — requires `--active-tests` |
| `--yes` / `-y` | off | Skip interactive consent prompts (for CI) |
| `--username` | — | Username for authenticated checks |
| `--password` | — | Password for authenticated checks |
| `--cookie` | — | Raw Cookie header (e.g. BIG-IP APM tokens) |
| `--user-agent` | `AEM-Audit-Pro/2.0` | Custom User-Agent |
| `--oob-collector` | — | OOB callback URL for SSRF checks (Interactsh, OAST) |
| `--proxy` | — | `http://host:port` or `socks5://host:port` |
| `--insecure` | off | Disable TLS verification |
| `--timeout` | `10.0` | Per-request timeout in seconds |
| `--workers` | `8` | Concurrent threads |
| `--rate-limit` | `12.0` | Max requests per second |
| `--retries` | `2` | Retry attempts on network error |
| `--backoff` | `0.5` | Retry backoff base (seconds) |
| `--include-check` | — | Run only this check ID / name / tag (repeatable) |
| `--exclude-check` | — | Skip this check ID / name / tag (repeatable) |
| `--json-out` | — | Write JSON report to file |
| `--md-out` | — | Write Markdown report to file |
| `--dry-run` | off | Show planned checks without making requests |
| `--print-coverage-matrix` | off | Print check coverage matrix |
