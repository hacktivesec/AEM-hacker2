# AEM Hacker Coverage Matrix

| Capability (AEM Hacker) | Status | Reason | Next Step |
|---|---|---|---|
| Exposed DefaultGetServlet | In progress | Implemented via selector-based DefaultGetServlet disclosure probes, not full historical path corpus | Add curated secret-path corpus with strict evidence thresholds |
| Exposed QueryBuilderJson/Feed | Implemented | QueryBuilder JSON reachability and abuse-signal checks included | Add feed servlet variant checks |
| Exposed GQLServlet | In progress | GQL reachability is checked via endpoint exposure probes only | Add dedicated GQL endpoint/probe set |
| Ability to create JCR nodes | Implemented | Explicit state-changing create/delete probe behind opt-in flags | Add additional repository path profiles |
| Exposed POSTServlet | Implemented | State-changing Sling POST probe with cleanup tracking | Add per-tier policy baseline diff |
| Exposed login/user info servlets | Implemented | Granite/Sling auth/user endpoints validated | Expand to custom app auth surfaces |
| Users with default password | Implemented | Default credential validation check is implemented and gated behind active-tests mode | Keep credential list and legal guardrails updated |
| Exposed Felix console | Implemented | Felix/OSGi admin surfaces checked | Add authenticated role-validation checks |
| WCMDebugFilter / WCMSuggestions | Implemented | Dedicated reflected-XSS checks for both servlets are implemented | Add additional safe reflection signatures |
| Exposed CRXDE/CRX | Implemented | CRXDE and CRX explorer checks included | Add deeper ACL behavior verification |
| Exposed reports | In progress | Report endpoints are covered and audit servlet exposure is checked; corpus is not exhaustive | Add report endpoint pack |
| SSRF: SalesforceSecretServlet | Implemented | Active OOB-capable Salesforce SSRF check is implemented | Add stronger callback confirmation telemetry |
| SSRF: ReportingServicesServlet | Implemented | Active OOB-capable ReportingServices SSRF check is implemented | Add stronger callback confirmation telemetry |
| SSRF: Sitecatalyst/Autoprovisioning | In progress | SiteCatalyst has active SSRF checks; autoprovisioning is currently surface/reachability coverage | Add dedicated autoprovisioning SSRF validation |
| SSRF: Opensocial proxy/makeRequest | Implemented | OpenSocial proxy and makeRequest SSRF checks are implemented | Add callback confirmation hardening |
| SWF XSS | Implemented | Dedicated SWF exposure/XSS-risk checks are implemented | Add SWF parameter reflection signatures |
| Deser ExternalJobServlet | Implemented | ExternalJobServlet deserialization probe is implemented (state-changing active mode) | Add safer non-OOM verification path |
| Exposed WebDAV | Implemented | WebDAV exposure check is implemented via auth challenge detection | Add WebDAV method/auth depth checks |
| Exposed Groovy Console | Implemented | Groovy console exposure explicitly checked | Add auth role and execution lock checks |
| Exposed ACS AEM Tools | Implemented | ACS admin surface exposure checked | Add ACS tool-specific endpoint expansion |
| Exposed GuideInternalSubmitServlet | Implemented | Vulnerability class endpoint presence checked | Add safe request-shape validation |
| Exposed MergeMetadataServlet / SetPreferences | Not implemented | No dedicated check currently exists in code | Add reflected input safety checks |
