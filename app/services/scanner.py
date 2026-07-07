import requests
import time
import subprocess
import re

# NVD API Key maintained for vulnerability metric fetching
NVD_API_KEY = "f7c02005-a595-49ca-803f-af0b4056a262"

def get_severity_label(score):
    try:
        s = float(score)
        if s >= 9.0: return "Critical"
        if s >= 7.0: return "High"
        if s >= 4.0: return "Medium"
        return "Low"
    except:
        return "N/A"

def run_nmap_scan(target: str, port_selection: str = "1-1000"):
    start_time = time.time()
    command = ["nmap", "-T4", "-sV", "--open", "--script", "http-vuln,ssh-auth-methods", "-p", port_selection, target]
    result = subprocess.run(command, capture_output=True, text=True)
    
    vuln_pattern = re.compile(r"\(CVE-\d+-\d+|VULNERABLE\)")
    lines = result.stdout.split('\n')
    refined_findings = [line.strip() for line in lines if vuln_pattern.search(line)]
    
    duration = time.time() - start_time
    print(f"Optimized Nmap scan completed in {duration:.2f} seconds")
    return "\n".join(refined_findings) if refined_findings else "No specific vulnerabilities identified."

def get_cve_data(scan_output: str):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": "f7c02005-a595-49ca-803f-af0b4056a262"}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            parsed_results = []
            for vuln in vulnerabilities:
                cve_info = vuln.get('cve', {})
                metrics = cve_info.get('metrics', {}).get('cvssMetricV2', [{}])[0]
                score = metrics.get('cvssData', {}).get('baseScore', 'N/A')
                
                parsed_results.append({
                    "id": cve_info.get('id'),
                    "score": score,
                    "severity": get_severity_label(score),
                    "description": cve_info.get('descriptions', [{}])[0].get('value', 'No description')
                })
            
            # Truncate to top 10 for clean logs
            return parsed_results[:10]
        return []
    except Exception as e:
        print(f"Error fetching CVE data: {e}")
        return []
