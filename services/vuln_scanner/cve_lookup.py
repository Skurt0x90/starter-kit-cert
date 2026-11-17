import re
import requests
import logging
import time
import nmap
from vuln_scanner import utils

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 60   # NVD est lent, 15s ne suffit pas toujours
NVD_RETRIES = 3

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


def get_stack_nmap(domain: str) -> list[dict]:
    nm = nmap.PortScanner()
    nm.scan(domain, arguments="-sV -T4")
    
    # nmap indexe par IP résolue, pas par hostname
    host = nm.all_hosts()[0] if nm.all_hosts() else None
    if not host:
        return []
    
    ports = []
    for port, data in nm[host]["tcp"].items():
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
        logger.info(f"Get-stack succeed --> {r.headers}")

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


def normalize_version(version):
    # garde juste la partie numérique : "7.4p1" -> "7.4", "1.18.0-ubuntu" -> "1.18.0"
    m = re.match(r"\d+(\.\d+)*", version)
    return m.group(0) if m else None


def next_version(version):
    # "8.2" -> "8.3", "8" -> "9"
    parts = version.split(".")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


def build_cpe_queries(name, version):
    # renvoie la liste des paramètres NVD à interroger, ou None si le produit est inconnu
    products = CPE_MAP.get(name.lower())
    if not products:
        return None

    version = normalize_version(version)
    if not version:
        return None

    queries = []
    for vendor, product in products:
        if is_partial_version(version):
            # version incomplète : on cherche sur la plage [8.2, 8.3[
            cpe = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"
            queries.append({
                "virtualMatchString": cpe,
                "versionStart": version,
                "versionStartType": "including",
                "versionEnd": next_version(version),
                "versionEndType": "excluding",
            })
        else:
            cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
            queries.append({"virtualMatchString": cpe})
    return queries


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
        return query_nvd({"keywordSearch": keyword}, domain, keyword)

    cves = []
    for params in queries:
        label = params["virtualMatchString"]
        logger.info(f"{domain} -> CPE lookup for {label}")
        cves.extend(query_nvd(params, domain, label))
    return cves


def extract_cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            return entries[0]["cvssData"]["baseScore"]
    return None

def check(domain, scan_mode="passive"):
    result = {"server": None, "x_powered_by": None, "cves": [], "ports": []}

    # passif — headers HTTP
    stack = get_stack(domain)
    result["server"] = stack["server"]
    result["x_powered_by"] = stack["x_powered_by"]

    for header in (stack["server"], stack["x_powered_by"]):
        name, version = parse_stack(header)
        if not name:
            continue
        if not version:
            result["cves"].append({"id": None, "cvss": None, "description": f"Version masquée pour {name}"})
            continue
        if is_partial_version(version):
            result["cves"].append({"id": None, "cvss": None, "description": f"Version partielle pour {name} ({version}), recherche sur la plage de versions, résultats indicatifs"})
        result["cves"].extend(lookup_cves(name, version, domain))

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