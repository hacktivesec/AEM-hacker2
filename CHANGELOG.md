# Changelog

## 2.1.0 - 2026-03-02

**Comprehensive AEM Endpoint Expansion (192x improvement)**
- Added comprehensive endpoint catalog (`aem_endpoints.py`) with 108+ AEM-specific endpoints organized into 23 functional categories derived from industry benchmark (https://gist.github.com/mrtouch93/AEM-list-paths).
- Endpoints now profile-aware:
  - **quick**: 25 critical endpoints (console, CRX, package manager) for baseline scans
  - **standard**: 42 endpoints (quick + replication, querybuilder, granite) for standard audits
  - **deep**: 108 endpoints (all categories: analytics, cloud services, DAM, reports, security, MCM, etc.) for comprehensive assessments
- Expanded coverage includes: OSGi console/bundles/config, CRX/CRXDE, Package Manager, Replication agents, QueryBuilder variants, Granite login/security, Sling endpoints, ACS Commons tools, Groovy Console, Analytics components, Cloud Services provisioning, OpenSocial proxy/makeRequest, MCM Salesforce integration, WCM workflows, DAM admin, Admin UI consoles, Reports surfaces, Repository paths, Security utilities.
- All endpoints tested concurrently with worker pool and rate limiting for performance.

## 2.0.0 - 2026-03-02

- Refactored from monolithic script to modular architecture under `aem_audit_tool/` with checker registry and profile-aware orchestration.
- Added AEM-focused checks for OSGi/Felix, CRX/DE, Package Manager, Granite/Sling, replication, ACS Commons, querybuilder, dispatcher bypass signals, and known vulnerability classes.
- Introduced AEM fingerprint confidence gating to reduce false positives on non-AEM targets.
- Added authenticated-only checks and split reporting between unauthenticated and authenticated findings.
- Added controlled active testing model with explicit flags and dedicated state-changing cleanup artifact tracking.
- Hardened proxy support (`http(s)` + `socks5`) with clearer root-cause TLS/proxy diagnostics.
- Added retry/backoff, rate limiting, timeout controls, and worker concurrency.
- Changed output behavior: terminal is default; JSON/Markdown files are only written when requested.
- Added dry-run mode and explicit scan profiles (`quick`, `standard`, `deep`, `authenticated-deep`).
- Added unit tests for CLI parsing, selector logic, summary reporting, and fingerprint checker behavior.
- Added AEM Hacker capability coverage benchmark matrix for implementation tracking.
