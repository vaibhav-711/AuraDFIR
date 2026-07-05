"""Detection rule definitions — the single source of truth for both the
Elasticsearch-side analysis engine and the Python-side timeline tagger.

DIALECT CONTRACT (read before editing patterns)
------------------------------------------------
Every signature pattern must be valid in BOTH:
  * Lucene `regexp` (ES, flags=ALL), and
  * Python `re` (IGNORECASE).

Because Lucene regexp (flags=ALL) treats these as operators, they must NEVER
appear unescaped as literals:  <  >  #  &  @  ~  "  {  }  (  )  [  ]  $  +  *  .  ?  |
Escape any literal occurrence with a backslash, e.g.  \\<  \\#  \\{  \\$  \\.  \\(  \\"
Anchors (^ $) are NOT used — the engine wraps each pattern as `.*(<pattern>).*`,
so patterns match as infixes. Use [0-9] not \\d, and avoid \\b / lookarounds.

The test-suite in tests/ enforces this contract automatically.
"""
import re

# (name, severity, pattern, description)  severity: low | medium | high | critical
SIGNATURES = [
    # ---- Injection: SQL ----
    ("sqli", "high",
     r"(union[ +/*]*select|union[ +](all|distinct)[ +]select|information_schema|"
     r"table_schema|column_name|group_concat|load_file[ (]|into[ +]outfile|"
     r"into[ +]dumpfile|sleep[ (][ 0-9]|benchmark[ (]|pg_sleep[ (]|waitfor[ +]delay|"
     r"extractvalue[ (]|updatexml[ (]|' or '|\" or \"|%27[ +]?or|%22[ +]?or|"
     r"or[ +]1[ ]?=[ ]?1|and[ +]1[ ]?=[ ]?1|' and '|'--|'\#|;--|/\*!|xp_cmdshell|"
     r"sp_executesql|utl_http|dbms_lock|convert[ (]int|cast[ (]|concat[ (]0x|"
     r"char[ (][0-9]|0x[0-9a-f][0-9a-f][0-9a-f]|having[ +]1[ ]?=|%27%20or|%20or%201=1)",
     "SQL injection payloads or probes"),

    # ---- Injection: NoSQL ----
    ("nosqli", "high",
     r"(\[\$ne\]|\[\$gt\]|\[\$lt\]|\[\$gte\]|\[\$lte\]|\[\$regex\]|\[\$where\]|"
     r"\[\$exists\]|\[\$in\]|\[\$nin\]|\[\$or\]|\$where[ ]?[=:]|%5b%24ne%5d|"
     r"%24where|\{\$gt|\{\$ne|\{\$where|mapreduce\{)",
     "NoSQL / MongoDB operator injection"),

    # ---- Injection: OS command ----
    ("command_injection", "critical",
     r"(;[ +]?(id|whoami|uname|cat|ls|dir|ping|curl|wget|nc|bash|sh|powershell|cmd)[ +;/]|"
     r"\|[ +]?(id|whoami|uname|cat|ls|nc|bash|sh|curl|wget)|\$\([ ]?(id|whoami|uname|cat|ls)|"
     r"%24%28|%60|%0a(id|whoami|uname|cat|ls|ping)|/bin/(sh|bash|dash|zsh|busybox)|"
     r"bash[ +]-i|nc[ +]-e|/dev/tcp/|chmod[ +]+[0-9x]|%3b(id|whoami|uname)|"
     r"%7c(id|whoami)|\$\{ifs\}|\$ifs|/etc/cron)",
     "OS command injection"),

    # ---- Injection: Shellshock (CVE-2014-6271) ----
    ("shellshock", "critical",
     r"(\(\)[ +]*\{|%28%29[ +]*%7b|\(\)[ +]*\{[ +:;]|%28%29%20%7b)",
     "Shellshock / Bash function-definition injection"),

    # ---- Injection: Server-Side Template (SSTI) ----
    ("ssti", "high",
     r"(\{\{[ ]?[0-9*]|\{\{[ ]?(config|self|request|session|settings|g\.)|"
     r"\$\{[ ]?[0-9*]|\$\{[ ]?(t|java|runtime|class)|\#\{[ ]?[0-9]|\<%[ ]?=[ ]?[0-9]|"
     r"%7b%7b[0-9]|freemarker|velocity\.|\{\{7[ ]?\*[ ]?7|\$\{7[ ]?\*[ ]?7|"
     r"\{%[ ]?(if|for|import)|\{\{[ ]?['\"].*['\"]\.)",
     "Server-side template injection"),

    # ---- Injection: LDAP ----
    ("ldap_injection", "high",
     r"(\)\(uid=|\)\(cn=|\)\(userpassword=|\*\)\(|admin\*\)|\)\(objectclass=\*|"
     r"%29%28uid=|%2a%29%28|\)%00|\*\)%00)",
     "LDAP injection"),

    # ---- Injection: XPath ----
    ("xpath_injection", "medium",
     r"(' or '1'='1|' or count\(|/child::|::text\(\)|string-length\(|"
     r"' or name\(|\]\[position\(\)|substring\([ ]?/)",
     "XPath / XQuery injection"),

    # ---- Cross-Site Scripting ----
    ("xss", "medium",
     r"(\<script|%3cscript|\<img[ +/]|%3cimg|\<svg[ +/]|\<iframe|\<body[ +/]|"
     r"\<object[ +/]|\<embed[ +/]|\<details[ +/]|javascript:|vbscript:|"
     r"data:text/html|onerror[ ]?=|onload[ ]?=|onmouseover[ ]?=|onclick[ ]?=|"
     r"onfocus[ ]?=|onanimationstart|onerror%3d|onload%3d|alert[ (]|prompt[ (]|"
     r"confirm[ (]|document\.cookie|document\.domain|document\.location|"
     r"window\.location|eval[ (]|string\.fromcharcode|expression[ (]|"
     r"%3cscript%3e|\<svg/onload)",
     "Cross-site scripting payloads"),

    # ---- Local File Inclusion / Path Traversal ----
    ("lfi_traversal", "high",
     r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e/|%2e%2e%5c|\.\.%252f|"
     r"%252e%252e%252f|etc/passwd|etc%2fpasswd|/etc/shadow|/etc/hosts|"
     r"/etc/group|boot\.ini|win\.ini|windows/system32|/proc/self/|/proc/version|"
     r"/proc/cmdline|php://filter|php://input|php://fd|expect://|file:///|"
     r"data://text|zip://|phar://|/var/log/|/usr/local/|c:\\windows|"
     r"\.\.%c0%af|\.\.%c1%9c)",
     "Path traversal / local file inclusion"),

    # ---- Remote File Inclusion ----
    ("rfi", "high",
     r"(=[ ]?(https?|ftp|ftps|php|data|expect|dict|gopher)(://|%3a%2f%2f)|"
     r"=[ ]?%68%74%74%70|include=[ ]?https?|require=[ ]?https?)",
     "Remote file inclusion — URL passed as a parameter value"),

    # ---- Server-Side Request Forgery ----
    ("ssrf", "high",
     r"(169\.254\.169\.254|metadata\.google|metadata\.azure\.com|100\.100\.100\.200|"
     r"/latest/meta-data|/computemetadata|/metadata/instance|"
     r"=[ ]?(file|dict|gopher|ldap|tftp|sftp|netdoc)://|"
     r"=[ ]?https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|169\.254|"
     r"192\.168\.|10\.[0-9]|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)|"
     r"%6c%6f%63%61%6c%68%6f%73%74|burpcollaborator|oastify|interact\.sh|\.oast\.|"
     r"requestbin|\.canarytokens)",
     "Server-side request forgery / cloud-metadata access"),

    # ---- XML External Entity ----
    ("xxe", "high",
     r"(\<!entity|\<!doctype[ +]|%3c%21entity|%3c%21doctype|system[ +]%22file|"
     r"system[ +]%22http|\<\?xml[ +].*entity|/etc/passwd%22[ ]?%3e|"
     r"\<!\[cdata\[|expect://.*%3c)",
     "XML external entity injection"),

    # ---- Insecure Deserialization ----
    ("deserialization", "high",
     r"(java\.lang\.runtime|java\.lang\.processbuilder|rO0AB|aced0005|"
     r"__reduce__|__reduce_ex__|pickle\.loads|cpickle|subprocess\.popen|"
     r"os\.system|child_process|_\$\$nd_func|phar://|O:[0-9]+:%22|O:[0-9]+:\"|"
     r"a:[0-9]+:\{|commons-collections|ysoserial|readobject|marshal\.loads|"
     r"yaml\.load|__proto__|constructor\[)",
     "Insecure deserialization / object injection"),

    # ---- Webshells (files + tell-tale params) ----
    ("webshell", "critical",
     r"(c99\.php|c100\.php|r57\.php|wso\.php|wso[0-9]|alfa\.php|alfashell|"
     r"indoxploit|priv8|mini[ ]?shell|shell\.php|shell\.asp|shell\.jsp|shell\.aspx|"
     r"cmd\.php|cmd\.jsp|cmd\.asp|eval-stdin\.php|b374k|filesman|antsword|"
     r"weevely|regeorg|regeorge|behinder|godzilla|webadmin\.php|adminer\.php|"
     r"up\.php|upload\.php|gecko\.php|madspot|backdoor|/1\.php|/2\.php|/x\.php|"
     r"/a\.php|xx\.php|404\.php|radio\.php|wp-conf\.php|wp-cd\.php|"
     r"cmd=(whoami|id|dir|type|cat|net[ +]user)|(func|action|act)=(cmd|shell|command|exec))",
     "Known webshell filenames or command-execution parameters"),

    # ---- Log4Shell (CVE-2021-44228) ----
    ("log4shell", "critical",
     r"(\$\{jndi:|%24%7bjndi|\$\{jndi:(ldap|ldaps|rmi|dns|iiop|corba|nis|nds)|"
     r"\$\{\$\{|\$\{lower:|\$\{upper:|\$\{env:|\$\{sys:|\$\{::-j|\$\{base64:|"
     r"%24%7b%6a%6e%64%69|\$\{main:|\$\{date:)",
     "Log4Shell JNDI injection"),

    # ---- Spring4Shell (CVE-2022-22965) ----
    ("spring4shell", "critical",
     r"(class\.module\.classloader|class\.classloader|springframework.*classloader|"
     r"%63%6c%61%73%73%2e%6d%6f%64%75%6c%65|class%2emodule%2eclassloader|"
     r"getruntime\(\)\.exec)",
     "Spring4Shell class-loader manipulation"),

    # ---- Apache Struts2 OGNL ----
    ("struts_ognl", "critical",
     r"(%\{[ ]?\(|\$\{[ ]?\(|_memberaccess|ognl\.|\.getruntime|multipart/form-data.*%\{|"
     r"redirect:\$\{|\.action\?.*%\{|\#context\[|\#_memberaccess|\@java\.lang)",
     "Apache Struts2 OGNL injection"),

    # ---- HTTP response splitting / CRLF ----
    ("crlf_injection", "medium",
     r"(%0d%0a|%0a%0d|%250d%250a|%0d%0aset-cookie|%0aset-cookie|%0alocation:|"
     r"%0acontent-type|%0acontent-length|%3f%0d%0a|%23%0d%0a|%e5%98%8a%e5%98%8d)",
     "CRLF injection / HTTP response splitting"),

    # ---- Open redirect ----
    ("open_redirect", "medium",
     r"((redirect|redir|url|next|return|returnurl|return_url|goto|dest|destination|"
     r"continue|redirect_uri|redirect_url|callback|forward|image_url|go|out|link|"
     r"target|checkout_url)=[ ]?(https?:|//|/\\|%2f%2f|%5c%5c|%68%74%74%70|/%2f))",
     "Open redirect via user-controlled destination parameter"),

    # ---- Auth / access-control bypass tricks ----
    ("access_bypass", "high",
     r"(\.\.;/|%2e%2e;|/\.\.;|;/\.\.|/%2e%2e/|/\.;/|/;/|/\.%2e/|%2e%2e%2f%2e%2e|"
     r"/manager/\.\.;|/j_security_check|/\.%00|/\.\./\.\./;|/;jsessionid|"
     r"x-original-url|x-rewrite-url|/%2e/)",
     "Authentication / access-control bypass technique"),

    # ---- Sensitive file & config disclosure ----
    ("sensitive_file", "high",
     r"(/\.env|\.env\.bak|/\.git/|/\.git/config|/\.gitignore|/\.svn/|/\.hg/|/\.bzr/|"
     r"/\.ds_store|/web\.config|/\.htaccess|/\.htpasswd|/wp-config\.php|/config\.php|"
     r"/configuration\.php|/settings\.py|/database\.yml|/credentials|/id_rsa|/\.aws/|"
     r"/\.ssh/|/\.bash_history|/backup\.|/dump\.sql|/database\.sql|/\.npmrc|"
     r"/\.dockercfg|/docker-compose\.yml|/composer\.lock|/phpinfo\.php|/info\.php|"
     r"/server-status|/server-info|/\.well-known/security|/\.travis\.yml|"
     r"/config\.json\.bak|/\.env\.local|/\.env\.production|/secrets\.|/\.kube/config)",
     "Access to sensitive files, backups, secrets or config"),

    # ---- CRLF / null / encoding evasion ----
    ("null_byte", "medium",
     r"(%00|%2500|%c0%80|\.php%00|%00\.jpg|\.jsp%00|%252e%252e)",
     "Null-byte injection or double-encoding evasion"),

    # ---- Known component / CVE probing ----
    ("cve_probe", "medium",
     r"(/vendor/phpunit|/phpunit/src/util/php/eval-stdin|xmlrpc\.php|/wp-login\.php|"
     r"/wp-admin/|/wp-json/wp/|/wp-content/plugins/|/administrator/|/user/register\?|"
     r"\?author=[0-9]|/cgi-bin/|/manager/html|/host-manager|/actuator|/actuator/env|"
     r"/actuator/gateway|/solr/admin|/jenkins|/thinkphp|/tp/public|/index\.php\?s=|"
     r"/hnap1|/boaform|/setup\.cgi|/currentsetting\.htm|/goform/|/api/jsonws/invoke|"
     r"/druid/|/nacos/|/eureka/|/consul/|/_all_dbs|/owa/|/autodiscover|/ews/|"
     r"/remote/fgt_lang|/remote/login|/dana-na/|/global-protect|/vpn/|/citrix|"
     r"/vaadin|/wls-wsat|/_async/asyncresponseservice|/console/css|/adminer|/pma/|"
     r"/phpmyadmin|/dbadmin|/typo3|/joomla|/jsonws|/cfide|/geoserver|/zabbix|"
     r"/grafana/|/kibana|/_cat/|/telescope/requests|/debug/default/view|"
     r"/frontend/web|/graphql|/v2/api-docs|/swagger|/api-docs|/wsdl|/soap|"
     r"/\.vscode/|/actuator/heapdump|/wp-content/uploads/.*\.php|/mifs/|"
     r"/cgi-bin/luci|/ecp/|/rpc/|/portal/|/\+cscoe\+|/api/v1/totp)",
     "Probes for known-vulnerable components, panels or CVEs"),

    # ---- IIS / ASP.NET specific ----
    ("iis_aspnet", "medium",
     r"(/trace\.axd|/elmah\.axd|/\.axd|__viewstate=|/app_data/|/global\.asax|"
     r"/aspnet_client|/iisstart|/certsrv|/owa/auth|/scripts/.*\.asp|"
     r"/fckeditor|/ckeditor|web\.config|/bin/.*\.dll|%u002e%u002e)",
     "IIS / ASP.NET specific probe or misconfiguration access"),

    # ---- Mass scanner / recon signatures ----
    ("recon_probe", "low",
     r"(/robots\.txt.*\.\.|/\.env.*/|/\?rest_route=|/\?p=[0-9]+' |wp-json/oembed|"
     r"/sitemap\.xml.*\<|/\.aws/credentials|/api/\.\./|/v1/\.\./|/static/\.\./)",
     "Reconnaissance / fuzzing artefacts"),
]

# ---------------------------------------------------------------------------
# User-agent based detection
# ---------------------------------------------------------------------------
SCANNER_UAS = [
    # web app scanners / fuzzers
    "sqlmap", "nikto", "nuclei", "gobuster", "dirbuster", "dirb", "dirsearch",
    "wpscan", "joomscan", "droopescan", "cmsmap", "wfuzz", "ffuf", "feroxbuster",
    "arachni", "acunetix", "netsparker", "burpsuite", "burp", "owasp zap", "zaproxy",
    "vega", "skipfish", "w3af", "whatweb", "wappalyzer", "httprint", "commix",
    "xsstrike", "nosqlmap", "sqlninja", "jsql", "havij", "pangolin",
    # network / recon
    "nmap", "masscan", "zgrab", "zmap", "shodan", "censys", "netcraft",
    "fscan", "goby", "xray", "rustscan", "naabu",
    # exploit frameworks / libs commonly abused
    "metasploit", "hydra", "medusa", "patator", "crackmapexec", "impacket",
    "python-requests", "python-urllib", "go-http-client", "curl/", "wget/",
    "libwww-perl", "winhttp", "okhttp", "httpclient", "java/", "aiohttp",
    "node-fetch", "axios/", "guzzle", "mechanize", "scrapy", "phantomjs",
    "headlesschrome", "selenium",
    # misc malicious / iot bot markers
    "zgrab", "l9explore", "l9tcpid", "internetmeasurement", "custom-asynchttp",
    "hello world", "mozila", "morfeus", "zmeu", "muieblackcat", "jaws",
]

# Behaviour-based detection thresholds (used by the ES engine) -----------------
BRUTE_FORCE_WINDOW = "5m"
BRUTE_FORCE_THRESHOLD = 20        # 401/403 in one window
ENUM_404_THRESHOLD = 50           # 404 per IP
RARE_UA_MAX_COUNT = 5
SPIKE_ZSCORE = 3.0
EXFIL_MIN_BYTES = 10 * 1024 * 1024
DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "MKCOL",
                     "MOVE", "COPY", "LOCK", "UNLOCK", "SEARCH", "DEBUG", "TRACK", "PATCH"]

# Phase-classification tag sets (shared with the timeline correlator) ----------
EXPLOIT_TAGS = {
    "sqli", "nosqli", "command_injection", "shellshock", "ssti", "ldap_injection",
    "xpath_injection", "xss", "lfi_traversal", "rfi", "ssrf", "xxe",
    "deserialization", "log4shell", "spring4shell", "struts_ognl",
    "crlf_injection", "open_redirect", "access_bypass",
}
POSTEXPLOIT_TAGS = {"webshell"}
RECON_TAGS = {"cve_probe", "iis_aspnet", "sensitive_file", "recon_probe", "null_byte"}

COMPILED = [(name, sev, re.compile(pat, re.IGNORECASE), desc)
            for name, sev, pat, desc in SIGNATURES]


def tag_url(url: str) -> list[str]:
    """Return the names of every signature matching this URL (Python side)."""
    return [name for name, _sev, rx, _d in COMPILED if rx.search(url or "")]


def is_scanner_ua(ua: str) -> bool:
    low = (ua or "").lower()
    return any(s in low for s in SCANNER_UAS)
