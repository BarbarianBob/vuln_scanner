# vuln_scanner
# 🛡️ vuln_scanner.py – CVSS-Based Web Vulnerability Scanner

A multi-threaded Python vulnerability scanner that detects common web vulnerabilities and assesses risk using **real-time CVSS scores** from the NVD API. Instead of treating vulnerabilities in isolation, this tool evaluates the **chaining potential** of multiple weaknesses to model real-world attacker behavior.

---

## 🚀 Features

- Scans for:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Misconfigurations
  - Broken Access Control
  - Weak Authentication
  - Outdated Components

- Multi-threaded scanning using `concurrent.futures`
- Real-time CVSS score lookup via the [NVD API](https://nvd.nist.gov/)
- Dynamic **attack chain scoring** for compound vulnerabilities
- Logs to `scan.log` and CSV export to `scan_results.csv`
- Clean, modular codebase with clear comments and extensible scan logic

---

## 🛠 Requirements

- Python 3.7+
- Dependencies:
  - `requests`

Install dependencies:
```bash
pip install -r requirements.txt
Usage
python vuln_scanner.py -u <target_url> -s <scan_types>
Example
python vuln_scanner.py -u http://localhost:3000 -s sql xss auth_weak

