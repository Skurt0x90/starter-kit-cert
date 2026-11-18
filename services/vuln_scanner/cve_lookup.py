import re
import requests
import logging
import time
import nmap
import dns.resolver
from vuln_scanner import utils

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 60   # NVD est lent, 15s ne suffit pas toujours
NVD_RETRIES = 3

INTERNETDB_URL = "https://internetdb.shodan.io"
MAX_IPS = 5        # nombre max d'IP interrogées par domaine (CDN = beaucoup d'IP)

# nom du produit (en minuscules, comme dans les headers / nmap) -> [(vendor, product)] CPE
# plusieurs entrées possibles : NVD a parfois changé de vendor selon les années (ex: nginx)
CPE_MAP = {
    "apache": [("apache", "http_server")],
    "apache httpd": [("apache", "http_server")],
    "php": [("php", "php")],
    "nginx": [("f5", "nginx"), ("nginx", "nginx")],
    "openssh": [("openbsd", "openssh")],
    "openssl": [("openssl", "openssl")],
    "mysql": [("oracle", "mysql")],
    "mariadb": [("mariadb", "mariadb")],
    "lighttpd": [("lighttpd", "lighttpd")],
    "microsoft-iis": [("microsoft", "internet_information_services")],
    "proftpd": [("proftpd", "proftpd")],
    "postfix": [("postfix", "postfix")],
}

# ports habituels par produit (vendor, product) : InternetDB ne dit pas quel port
# correspond à quel CPE, on déduit donc en croisant avec les ports ouverts de l'IP
PRODUCT_PORTS = {
    ("isc", "bind"): [53],
    ("openbsd", "openssh"): [22],
    ("apache", "http_server"): [80, 443, 8080, 8443],
    ("f5", "nginx"): [80, 443, 8080, 8443],
    ("nginx", "nginx"): [80, 443, 8080, 8443],
    ("php", "php"): [80, 443],
    ("lighttpd", "lighttpd"): [80, 443],
    ("microsoft", "internet_information_services"): [80, 443],
    ("haproxy", "haproxy"): [80, 443],
    ("oracle", "mysql"): [3306],
    ("mariadb", "mariadb"): [3306],
    ("postgresql", "postgresql"): [5432],
    ("postfix", "postfix"): [25, 465, 587],
    ("exim", "exim"): [25, 465, 587],
    ("dovecot", "dovecot"): [110, 143, 993, 995],
    ("proftpd", "proftpd"): [21],
}

# produits qui servent le site web lui-même, les autres sont des services de l'IP ("infra")
WEB_PRODUCTS = {
    ("apache", "http_server"),
    ("f5", "nginx"),
    ("nginx", "nginx"),
    ("php", "php"),
    ("lighttpd", "lighttpd"),
    ("microsoft", "internet_information_services"),
    ("haproxy", "haproxy"),
}

# produits dont la version complète n'a que deux nombres (ex: OpenSSH 9.2) : pas "partielle"
TWO_PART_VERSIONS = {("openbsd", "openssh")}


def get_stack_nmap(domain: str) -> list[dict]:
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError as e:
        logger.warning(f"{domain} -> nmap introuvable, scan actif impossible : {e}")
        return []

    # -Pn : pas de ping préalable (beaucoup d'hôtes bloquent l'ICMP)
    # --host-timeout : évite un scan qui dure des minutes sur un seul hôte
    nm.scan(domain, arguments="-sV -T4 -Pn --host-timeout 120s")
    
    # nmap indexe par IP résolue, pas par hostname
    host = nm.all_hosts()[0] if nm.all_hosts() else None
    if not host:
        return []
    
    ports = []
    for port, data in nm[host].get("tcp", {}).items():
        if data["state"] != "open":
            continue
        banner = f"{data['product']} {data['version']}".strip()
        ports.append({
            "port": port,
            "service": data["name"],
            "product": data["product"],
            "version": data["version"],
        })
    return ports


def get_stack(domain):
    url = f"http://{domain}"
    try:
        r = requests.get(url, timeout=utils.REQUEST_TIMEOUT, allow_redirects=True)
        server = r.headers.get("Server")
        powered_by = r.headers.get("X-Powered-By")
        logger.info(f"Get-stack succeed --> Server={server} X-Powered-By={powered_by}")

        return {
            "server": server,
            "x_powered_by": powered_by,
        }
    except requests.exceptions.RequestException as e:
        logger.info(f"Get-stack error --> {e}")
        return {
            "server": None,
            "x_powered_by": None,
        }


def get_internetdb(domain):
    # résout le domaine en IP puis interroge InternetDB (aucun paquet envoyé à la cible)
    try:
        answers = dns.resolver.resolve(domain, "A")
        ips = [a.to_text() for a in answers][:MAX_IPS]
    except Exception as e:
        logger.warning(f"{domain} -> résolution DNS impossible pour InternetDB : {e}")
        return None

    merged = {"ips": [], "ports": set(), "cpes": set(), "hostnames": set(), "tags": set(), "vulns": set()}
    found = False
    for ip in ips:
        time.sleep(1)  # InternetDB : ~1 requête/seconde
        try:
            r = requests.get(f"{INTERNETDB_URL}/{ip}", timeout=utils.REQUEST_TIMEOUT)
            if r.status_code == 404:
                logger.info(f"{domain} -> InternetDB : aucune donnée pour {ip}")
                continue
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            logger.warning(f"{domain} -> InternetDB failed for {ip}: {e}")
            continue

        found = True
        merged["ips"].append(ip)
        for key in ("ports", "cpes", "hostnames", "tags", "vulns"):
            merged[key].update(data.get(key, []))

    if not found:
        return None

    logger.info(f"{domain} -> InternetDB : {len(merged['cpes'])} CPE, {len(merged['vulns'])} CVE, {len(merged['ports'])} ports")
    return {k: (sorted(v) if isinstance(v, set) else v) for k, v in merged.items()}


def parse_idb_cpe(cpe):
    # "cpe:/a:apache:http_server:2.4.41" -> ("a", "apache", "http_server", "2.4.41")
    parts = cpe.split(":")
    if len(parts) < 4:
        return None
    if parts[1] == "2.3":  # au cas où le format 2.3 serait renvoyé
        parts = parts[2:]
        part, vendor, product = parts[0], parts[1], parts[2]
        version = parts[3] if len(parts) > 3 and parts[3] not in ("", "*", "-") else None
    else:
        part, vendor, product = parts[1].lstrip("/"), parts[2], parts[3]
        version = parts[4] if len(parts) > 4 and parts[4] else None
    return part, vendor, product, version

    
def parse_stack(header_value):
    if not header_value:
        return None, None
    parts = header_value.split("/")
    if len(parts) == 2:
        version = parts[1].split(" ")[0].strip()
        return parts[0].strip(), version
    return parts[0].strip(), None


def is_partial_version(version):
    # "8.2" -> partielle, "8.2.12" -> complète
    return version.count(".") < 2


def version_precision(vendor, product, version):
    # "exact" : CVE trouvée pour une version précise (ex: PHP 8.5.1)
    # "range" : version incomplète (ex: PHP 8.5), la CVE touche peut-être seulement certaines 8.5.x
    if (vendor, product) in TWO_PART_VERSIONS:
        return "exact"
    return "range" if is_partial_version(version) else "exact"


def normalize_version(version):
    # garde juste la partie numérique : "7.4p1" -> "7.4", "1.18.0-ubuntu" -> "1.18.0"
    m = re.match(r"\d+(\.\d+)*", version)
    return m.group(0) if m else None


def version_tuple(version):
    # "2.4.41" -> (2, 4, 41), pour comparer deux versions
    v = normalize_version(version) if version else None
    return tuple(int(x) for x in v.split(".")) if v else ()


def next_version(version):
    # "8.2" -> "8.3", "8" -> "9"
    parts = version.split(".")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


def build_cpe_params(vendor, product, version, part="a", exact=False):
    # exact=True : toujours la version exacte (utile quand elle vient d'un banner, ex: OpenSSH 9.2)
    if is_partial_version(version) and not exact:
        # version incomplète : on cherche sur la plage [8.2, 8.3[
        cpe = f"cpe:2.3:{part}:{vendor}:{product}:*:*:*:*:*:*:*:*"
        return {
            "virtualMatchString": cpe,
            "versionStart": version,
            "versionStartType": "including",
            "versionEnd": next_version(version),
            "versionEndType": "excluding",
        }
    cpe = f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    return {"virtualMatchString": cpe}


def build_cpe_queries(name, version):
    # renvoie la liste des paramètres NVD à interroger, ou None si le produit est inconnu
    products = CPE_MAP.get(name.lower())
    if not products:
        return None

    version = normalize_version(version)
    if not version:
        return None

    return [build_cpe_params(vendor, product, version) for vendor, product in products]


def query_nvd(params, domain, label):
    headers = {}
    if utils.NVD_API_KEY:
        headers["apiKey"] = utils.NVD_API_KEY
    else:
        time.sleep(6)

    data = None
    for attempt in range(1, NVD_RETRIES + 1):
        try:
            r = requests.get(NVD_URL, params=params, headers=headers, timeout=NVD_TIMEOUT)
            r.raise_for_status()
            data = r.json()
            break
        except Exception as e:
            logger.warning(f"{domain} -> NVD lookup failed for {label} (try {attempt}/{NVD_RETRIES}): {e}")
            if attempt < NVD_RETRIES:
                time.sleep(attempt * 10)  # 10s puis 20s
    if data is None:
        return []

    raw = data.get("vulnerabilities", [])
    logger.info(f"{domain} -> NVD returned {len(raw)} raw results for {label}")

    cves = []
    for item in raw:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
        metrics = cve.get("metrics", {})
        cvss_score = extract_cvss(metrics)
        if cve_id and cvss_score is not None:
            cves.append({
                "id": cve_id,
                "cvss": cvss_score,
                "description": description
            })

    logger.info(f"{domain} -> {len(cves)} CVE kept after filter for {label}")
    return cves


def lookup_cves(name, version, domain):
    if not name or not version:
        return []

    queries = build_cpe_queries(name, version)

    # produit absent de CPE_MAP : on retombe sur la recherche par mot-clé
    if queries is None:
        keyword = f"{name} {version}"
        logger.info(f"{domain} -> no CPE mapping for {name}, fallback keyword lookup for {keyword}")
        cves = query_nvd({"keywordSearch": keyword}, domain, keyword)
        for c in cves:
            c["match"] = "keyword"
        return cves

    vendor, product = CPE_MAP[name.lower()][0]
    match = version_precision(vendor, product, normalize_version(version) or version)

    cves = []
    for params in queries:
        label = params["virtualMatchString"]
        logger.info(f"{domain} -> CPE lookup for {label}")
        found = query_nvd(params, domain, label)
        for c in found:
            c["match"] = match
        cves.extend(found)
    return cves


def describe_component(vendor, product, version, idb_ports):
    # ports probables = ports habituels du produit qui sont réellement ouverts sur l'IP
    expected = PRODUCT_PORTS.get((vendor, product), [])
    ports = [p for p in expected if p in idb_ports]
    scope = "web" if (vendor, product) in WEB_PRODUCTS else "infra"
    return {"component": f"{vendor}:{product} {version}", "ports": ports, "scope": scope}


def lookup_cpe(part, vendor, product, version, domain, idb_ports):
    # recherche NVD directe à partir d'un CPE renvoyé par InternetDB
    version = normalize_version(version) if version else None
    if not version:
        return []
    exact = (vendor, product) in TWO_PART_VERSIONS
    params = build_cpe_params(vendor, product, version, part, exact=exact)
    label = params["virtualMatchString"]
    logger.info(f"{domain} -> CPE lookup (InternetDB) for {label}")
    cves = query_nvd(params, domain, label)
    info = describe_component(vendor, product, version, idb_ports)
    match = version_precision(vendor, product, version)
    for c in cves:
        c.update(info)
        c["match"] = match
    return cves


def extract_cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            return entries[0]["cvssData"]["baseScore"]
    return None


def find_idb_match(name, idb_products):
    # cherche le produit d'un header dans les CPE d'InternetDB
    # idb_products : liste de (part, vendor, product, version)
    candidates = CPE_MAP.get(name.lower(), [])
    for p in idb_products:
        if (p[1], p[2]) in candidates:
            return p
    return None


def header_is_newer(name, version, idb_products):
    # True si le header apporte une info plus récente que InternetDB
    match = find_idb_match(name, idb_products)
    if match is None:
        return True   # produit absent d'InternetDB : rien à comparer, on garde le header
    idb_version = match[3]
    if not version:
        return False  # header masqué, InternetDB en sait plus ou autant
    if not idb_version:
        return True   # InternetDB sans version, le header est plus précis
    return version_tuple(version) > version_tuple(idb_version)


def check(domain, scan_mode="passive"):
    result = {"server": None, "x_powered_by": None, "cves": [], "ports": [], "internetdb": None}

    # passif — headers HTTP
    stack = get_stack(domain)
    result["server"] = stack["server"]
    result["x_powered_by"] = stack["x_powered_by"]

    # passif — InternetDB (prioritaire sur les headers)
    idb = get_internetdb(domain)
    result["internetdb"] = idb

    idb_products = []
    if idb:
        for cpe in idb["cpes"]:
            parsed = parse_idb_cpe(cpe)
            if parsed:
                idb_products.append(parsed)

        for part, vendor, product, version in idb_products:
            if not version:
                continue
            for c in lookup_cpe(part, vendor, product, version, domain, idb["ports"]):
                c["source"] = "internetdb"
                result["cves"].append(c)

        # CVE signalées par InternetDB mais non retrouvées via NVD (cvss inconnu)
        known = {c["id"] for c in result["cves"] if c["id"]}
        for cve_id in idb["vulns"]:
            if cve_id not in known:
                result["cves"].append({
                    "id": cve_id,
                    "cvss": None,
                    "description": "Signalée par Shodan InternetDB, non confirmée via NVD",
                    "source": "internetdb",
                })

    # passif — headers HTTP : ignorés si InternetDB a identifié des logiciels, sauf s'ils sont plus récents
    for header in (stack["server"], stack["x_powered_by"]):
        name, version = parse_stack(header)
        if not name:
            continue
        if idb_products and not header_is_newer(name, version, idb_products):
            match = find_idb_match(name, idb_products)
            if not version and match and not match[3]:
                # ni le header ni InternetDB ne donnent la version : on garde la note
                result["cves"].append({"id": None, "cvss": None, "description": f"Version masquée pour {name}", "source": "headers", "scope": "web"})
            else:
                logger.info(f"{domain} -> header {header} ignoré (InternetDB prioritaire)")
            continue
        if not version:
            result["cves"].append({"id": None, "cvss": None, "description": f"Version masquée pour {name}", "source": "headers"})
            continue
        if is_partial_version(version):
            result["cves"].append({"id": None, "cvss": None, "description": f"Version partielle pour {name} ({version}), recherche sur la plage de versions, résultats indicatifs", "source": "headers"})
        for c in lookup_cves(name, version, domain):
            c["source"] = "headers"
            c["component"] = f"{name} {version}"
            c["scope"] = "web"
            result["cves"].append(c)

    # dédoublonnage par id (on garde les entrées sans id, ce sont des notes)
    seen = set()
    unique = []
    for c in result["cves"]:
        if c["id"] is not None:
            if c["id"] in seen:
                continue
            seen.add(c["id"])
        unique.append(c)
    result["cves"] = unique

    # actif — nmap
    if scan_mode == "active":
        try:
            ports = get_stack_nmap(domain)
            for p in ports:
                p["cves"] = lookup_cves(p["product"], p["version"], domain) if p["product"] and p["version"] else []
            result["ports"] = ports
        except Exception as e:
            logger.warning("nmap scan failed for %s: %s", domain, e)

    return result