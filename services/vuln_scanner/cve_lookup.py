import requests
import logging
import time
import nmap
from vuln_scanner import utils

logger = logging.getLogger(__name__)



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
        return {
            "server": server,
            "x_powered_by": powered_by,
        }
    except requests.exceptions.RequestException:
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


def lookup_cves(name, version):
    if not name or not version:
        return []
    
    keyword = f"{name} {version}"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword}
    
    headers = {}
    if utils.NVD_API_KEY:
        headers["apiKey"] = utils.NVD_API_KEY
    else:
        time.sleep(6)

    try:
        r = requests.get(url, params=params, headers=headers, timeout=utils.REQUEST_TIMEOUT)
        data = r.json()
    except Exception:
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
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

    return cves


def extract_cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            return entries[0]["cvssData"]["baseScore"]
    return None

def check(domain, scan_mode="passive"):
    logger.info(f"SCAN MODE={scan_mode}")
    result = {"server": None, "x_powered_by": None, "cves": [], "ports": []}

    # passif — headers HTTP
    stack = get_stack(domain)
    result["server"] = stack["server"]
    result["x_powered_by"] = stack["x_powered_by"]

    name, version = parse_stack(stack["server"])
    if name and not version:
        result["cves"].append({"id": None, "cvss": None, "description": f"Version masquée pour {name}"})
    elif name and version:
        result["cves"].extend(lookup_cves(name, version))

    name, version = parse_stack(stack["x_powered_by"])
    if name and not version:
        result["cves"].append({"id": None, "cvss": None, "description": f"Version masquée pour {name}"})
    elif name and version:
        result["cves"].extend(lookup_cves(name, version))

    # actif — nmap
    if scan_mode == "active":
        logger.info("ACTIVE MODE")
        try:
            ports = get_stack_nmap(domain)
            for p in ports:
                p["cves"] = lookup_cves(p["product"], p["version"]) if p["product"] and p["version"] else []
            result["ports"] = ports
        except Exception as e:
            logger.warning("nmap scan failed for %s: %s", domain, e)

    return result