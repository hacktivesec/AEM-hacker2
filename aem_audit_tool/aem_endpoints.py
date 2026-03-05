"""
Comprehensive AEM endpoint paths organized by category.
Derived from https://gist.github.com/mrtouch93/AEM-list-paths
"""

# Configuration: Map each profile to the categories it should include
PROFILE_CATEGORIES = {
    "quick": {"console", "crx", "packmgr"},
    "standard": {"console", "crx", "packmgr", "replication", "querybuilder", "granite"},
    "deep": "all",
    "authenticated-deep": "all",
}

# AEM endpoint categories and paths for comprehensive exposure detection
ENDPOINT_CATEGORIES = {
    "console": [
        "/system/console",
        "/system/console/bundles",
        "/system/console/configMgr",
        "/system/console/status-productinfo",
        "/system/console/depfinder",
        "/system/console/diskbenchmark",
        "/system/console/jmx/com.adobe.granite%3Atype%3DRepository",
        "/system/console/jmx/java.lang%3Atype%3DRuntime",
        "/system/console/licenses",
        "/system/console/memoryusage",
        "/system/console/mimetypes",
        "/system/console/profiler",
        "/system/console/vmstat",
        "/lc/system/console",
    ],
    "crx": [
        "/crx/de/index.jsp",
        "/crx/explorer/browser/index.jsp",
        "/crx/explorer/index.jsp",
        "/crx/explorer/nodetypes/index.jsp",
        "/crx/explorer/ui/namespace_editor.jsp",
        "/crx/explorer/ui/search.jsp",
        "/crx/repository/test",
        "/crx/repository/crx.default/content/dam/",
    ],
    "packmgr": [
        "/crx/packmgr/index.jsp",
        "/crx/packmgr/service.jsp",
        "/crx/packageshare",
    ],
    "replication": [
        "/etc/replication",
        "/etc/replication/agents.author.html",
        "/etc/replication/agents.publish.html",
        "/etc/replication/agents.publish/flush.html",
        "/etc/replication/treeactivation.html",
    ],
    "querybuilder": [
        "/bin/querybuilder.json",
        "/bin/querybuilder.feed",
        "/bin/querybuilder.json?path=/content&p.limit=10",
        "/bin/querybuilder.json?path=/home/users&p.limit=20",
        "/bin/querybuilder.json?path=/etc/replication&p.limit=50",
        "/bin/wcm/search/gql.json",
    ],
    "granite": [
        "/libs/granite/core/content/login.html",
        "/libs/granite/security/currentuser",
        "/libs/granite/security/currentuser.json",
        "/libs/granite/csrf/token.json",
        "/libs/granite/backup/content/admin.html",
        "/libs/granite/cluster/content/admin.html",
    ],
    "sling": [
        "/system/sling/cqform/defaultlogin.html",
        "/system/sling/info.sessionInfo.json",
        "/system/sling/info.sessionInfo.txt",
        "/system/sling/loginstatus",
        "/system/sling/loginstatus.json",
        "/libs/cq/core/content/login.html",
        "/libs/cq/core/content/login.json",
        "/libs/cq/core/content/welcome.html",
    ],
    "acs_commons": [
        "/apps/acs-commons/content/admin",
        "/etc/acs-tools/aem-fiddle/_jcr_content.run.html",
    ],
    "groovy_console": [
        "/etc/groovyconsole.html",
        "/etc/groovyconsole/_jcr_content.html",
        "/bin/groovyconsole/audit.servlet",
        "/bin/groovyconsole/post.servlet",
    ],
    "analytics": [
        "/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet",
        "/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json",
    ],
    "cloudservices": [
        "/etc/cloudservices",
        "/etc/cloudsettings.json",
        "/libs/cq/cloudservicesprovisioning/content/autoprovisioning",
        "/libs/cq/cloudservicesprovisioning/content/autoprovisioning.json",
        "/libs/cq/contentinsight/content/proxy.reportingservices.json",
        "/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet",
    ],
    "opensocial": [
        "/libs/opensocial/proxy",
        "/libs/opensocial/makeRequest",
    ],
    "mcm_salesforce": [
        "/libs/mcm/salesforce/customer.json",
    ],
    "wcm": [
        "/libs/cq/wcm/core/content/siteadmin.html",
        "/libs/cq/workflow/content/console.html",
        "/libs/cq/workflow/content/inbox.html",
        "/bin/wcm/contentfinder/connector/suggestions",
        "/bin/wcm/contentfinder/connector/suggestions.json",
    ],
    "dam": [
        "/libs/dam/cloud/proxy",
        "/libs/dam/cloud/proxy.json",
        "/damadmin",
        "/damadmin#/content/dam",
    ],
    "admin_ui": [
        "/admin",
        "/adminui",
        "/libs/granite/security/content/useradmin.html",
        "/miscadmin",
        "/miscadmin#/etc/blueprints",
        "/miscadmin#/etc/designs",
        "/miscadmin#/etc/importers",
        "/miscadmin#/etc/mobile",
        "/miscadmin#/etc/msm/rolloutconfigs",
        "/miscadmin#/etc/segmentation",
    ],
    "reports": [
        "/etc/reports/auditreport.html",
        "/etc/reports/diskusage.html",
        "/etc/reports/userreport.html",
    ],
    "content_paths": [
        "/content",
        "/content.json",
        "/content.xml",
        "/content.feed.xml",
    ],
    "repository": [
        "/bin/crxde/logs",
        "/jcr:system/jcr:versionStorage.json",
        "/var/classes.json",
        "/var/classes.xml",
    ],
    "security": [
        "/libs/cq/security/userinfo",
        "/libs/cq/tagging/content/debug.html",
        "/libs/cq/tagging/content/tagadmin.html",
        "/libs/cq/ui/content/dumplibs.html",
    ],
    "cq_search": [
        "/libs/cq/search/content/querydebug.html",
    ],
    "cq_forms": [
        "/libs/cq/forms/content/forms/af/guideInternalSubmitServlet",
    ],
    "cq_other": [
        "/libs/cq/contentsync/content/console.html",
        "/libs/cq/dialogconversion/content/console.html",
        "/libs/cq/i18n/translator.html",
        "/aem/inbox",
        "/aem/start.html",
    ],
}


def get_endpoints_for_profile(profile: str) -> dict[str, list[str]]:
    """Return endpoints to check based on profile."""
    if profile == "quick":
        selected_cats = PROFILE_CATEGORIES["quick"]
    elif profile == "standard":
        selected_cats = PROFILE_CATEGORIES["standard"]
    else:  # deep and authenticated-deep
        selected_cats = set(ENDPOINT_CATEGORIES.keys())

    return {cat: paths for cat, paths in ENDPOINT_CATEGORIES.items() if cat in selected_cats}
