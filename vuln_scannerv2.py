import argparse
import requests
import json
import csv
import logging
import concurrent.futures

#Logging
logging.basicConfig(filename="scan.log",
                    format="%(asctime)s - %(levelname)s - %(message)s",
                    level=logging.INFO)

stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(stream_handler)

logging.info("Enhanced Vulnerability Scanner w/ CVSS-based Risk Weighting")

# Map vulnerability types to CWE IDs for more precise NVD API querying
vuln_to_cve_query = {
    "sql": "CWE-89",
    "xss": "CWE-79",
    "misconfig": "CWE-16",
    "auth_weak": "CWE-287",
    "outdated_component": "CWE-1104",
    "broken_access": "CWE-284"
}
# Fetch CVSS scores dynamically from NVD based on CWE IDs
def fetch_cvss_score(vulnerability_type):
    query = vuln_to_cve_query.get(vulnerability_type)
    if not query:
        return 7.0  # fallback

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cweId={query}&resultsPerPage=5"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        scores = []

        for item in data.get('vulnerabilities', []):
            cvss = item.get('cve', {}).get('metrics', {}).get('cvssMetricV31') or item.get('cve', {}).get('metrics', {}).get('cvssMetricV2')
            if cvss:
                base_score = cvss[0].get('cvssData', {}).get('baseScore')
                if base_score:
                    scores.append(base_score)

        if scores:
            avg_score = sum(scores) / len(scores)
            return round(avg_score, 1)
        else:
            logging.warning(f"No CVSS scores found for {vulnerability_type}, using fallback score 7.0")
            return 7.0
    except Exception as e:
        logging.error(f"Error fetching CVSS data: {e}, using fallback score 7.0")
        return 7.0
# Wrapper function to safely handle HTTP requests with error handling

def safe_request(method, url, **kwargs):
    try:
        response = requests.request(method, url, timeout=5, **kwargs)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error for {url}: {e}")
        return None

# Calculate the chaining risk score using CVSS
def evaluate_chaining_risk(vulnerability_type):
    return fetch_cvss_score(vulnerability_type)

def scan_sql_injection(url):
    response = safe_request("post", url, data={"username": "' OR '1'='1", "password": "' OR '1'='1"})
    if response and "Welcome" in response.text:
        return "Potential SQL Injection detected!"
    return None

def scan_xss(url):
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    for payload in payloads:
        response = safe_request("get", url, params={"q": payload})
        if response and payload in response.text:
            return f"Potential XSS detected with payload: {payload}"
    return None

def scan_misconfig(url):
    paths = ["/admin/", "/phpinfo.php", "/.git/", "/.env"]
    for path in paths:
        full_url = url + path
        response = safe_request("get", full_url)
        if response and response.status_code == 200:
            return f"Potential misconfiguration detected: {full_url}"
    return None

def scan_broken_access_control(url):
    paths = ["/admin/", "/dashboard/"]
    for path in paths:
        full_url = url + path
        response = safe_request("get", full_url)
        if response and response.status_code == 200:
            return f"Broken Access Control detected! {full_url} is accessible without authentication."
    return None

def scan_auth_weak(url):
    creds = [("admin", "admin"), ("root", "root"), ("user", "password")]
    for username, password in creds:
        response = safe_request("post", url, data={"username": username, "password": password})
        if response and ("Welcome" in response.text or response.status_code == 200):
            return f"Weak Authentication detected! {username}:{password} works."
    return None

def scan_outdated_component(url):
    libs = ["jQuery 1.9.1", "Bootstrap 3.3.7", "AngularJS 1.2.0"]
    response = safe_request("get", url)
    if response:
        for lib in libs:
            if lib in response.text:
                return f"Outdated Component detected! {lib} is present on {url}"
    return None

'''
def log_to_csv(target_url, vulnerability, score):
    with open("scan_results.csv", mode="a", newline="") as file:
        writer = csv.writer(file)
        if file.tell() == 0:
            writer.writerow(["Target URL", "Vulnerability", "CVSS Score"])
        writer.writerow([target_url, vulnerability, score])
    print("Results logged to scan_results.csv")
'''
# Dispatch the scan based on scan type

def run_scan(scan_type, url):
    scan_functions = {
        "sql": scan_sql_injection,
        "xss": scan_xss,
        "misconfig": scan_misconfig,
        "broken_access": scan_broken_access_control,
        "auth_weak": scan_auth_weak,
        "outdated_component": scan_outdated_component
    }
    if scan_type in scan_functions:
        return scan_functions[scan_type](url)

# Main function to handle argument parsing and orchestrate scans
def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner with CVSS-based Risk Weighting")
    parser.add_argument("-u", "--url", required=True, help="Target URL for scanning")
    parser.add_argument("-s", "--scan", choices=["sql", "xss", "misconfig", "broken_access", "auth_weak", "outdated_component"], nargs="+", help="Select scan types")
    args = parser.parse_args()

    print(f"Scanning {args.url} for {', '.join(args.scan)} vulnerabilities...")

    detected_issues = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_results = {executor.submit(run_scan, scan_type, args.url): scan_type for scan_type in args.scan}

        for future in concurrent.futures.as_completed(future_results):
            scan_type = future_results[future]
            result = future.result()
            if result:
                detected_issues.append(scan_type)
                score = evaluate_chaining_risk(scan_type)
                if score >= 9:
                    risk = "[CRITICAL RISK]"
                elif score >= 7:
                    risk = "[HIGH RISK]"
                elif score >= 4:
                    risk = "[MEDIUM RISK]"
                else:
                    risk = "[LOW RISK]"
                print(f"✅ Detected: {scan_type.replace('_', ' ').title()}")
                print(f"➡️ {result}")
                print(f"CVSS Score: {score} {risk}\n")
                logging.info(f"Detected: {result} | CVSS Score: {score}")
                #log_to_csv(args.url, scan_type, score)

    if len(detected_issues) > 1:
        combined_score = sum(evaluate_chaining_risk(v) for v in detected_issues)
        print(f"⚠️ Attack Chain Identified!")
        print(f"➡️ Sequence: {detected_issues}")
        print(f"🔥 Combined CVSS Score Sum: {combined_score} [COMBINED RISK]\n")
        logging.info(f"Attack Chain Identified! Sequence: {detected_issues} | Combined CVSS Score: {combined_score}")

if __name__ == "__main__":
    main()

