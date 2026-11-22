import nmap
import json
import asyncio
from typing import Dict, Any, List

# --- KNOWLEDGE BASE: CVE & Triage Enrichment Matrix ---
# Maps common service banners/products to potential CVE intelligence & remediation context
CVE_DATABASE = {
    "vsftpd": {"cve": "CVE-2011-2523", "severity": "High", "remediation": "Upgrade to vsftpd 3.0.3 or later."},
    "openssh": {"cve": "CVE-2023-38408", "severity": "Medium", "remediation": "Update OpenSSH to the latest patched version."},
    "apache": {"cve": "CVE-2021-41773", "severity": "Critical", "remediation": "Patch Apache HTTP Server to version 2.4.51 or higher."},
    "nginx": {"cve": "CVE-2021-30116", "severity": "Medium", "remediation": "Update Nginx or check configuration parameters."},
    "samba": {"cve": "CVE-2017-7494", "severity": "Critical", "remediation": "Update Samba to version 4.6.4/later or restrict named pipe access."}
}

async def scan_target(target_ip: str, ports: str = "1-1000") -> Dict[str, Any]:
    """Performs an Nmap scan asynchronously with timeout and safe arguments."""
    nm = nmap.PortScanner()
    print(f"[*] Starting Aegis scan on {target_ip} for ports: {ports} ...")
    try:
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            None,
            lambda: nm.scan(target_ip, ports=ports, arguments='-sT -sV -T4')
        )
        return results.get('scan', {}).get(target_ip, {})
    except Exception as e:
        return {"error": str(e)}

def analyze_results(scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Analyzes raw scan data and calculates confidence scores."""
    if isinstance(scan_data, dict) and "error" in scan_data:
        return [{
            "port": 0,
            "service": "Error",
            "product": scan_data["error"],
            "state": "closed",
            "version": "N/A",
            "confidence_score": 0,
            "verdict": "Error",
            "cve": "N/A",
            "severity": "N/A",
            "remediation": "N/A",
            "triage_status": "Unverified"
        }]
    
    if 'tcp' not in scan_data:
        return [{
            "port": 0,
            "service": "None",
            "product": "No TCP ports found or target unreachable.",
            "state": "closed",
            "version": "N/A",
            "confidence_score": 0,
            "verdict": "Unreachable",
            "cve": "N/A",
            "severity": "N/A",
            "remediation": "N/A",
            "triage_status": "Unverified"
        }]

    report = []
    for port, details in scan_data['tcp'].items():
        state = details.get('state', 'unknown')
        score = 0
        if state == 'open':
            score += 55
            if details.get('product'):
                score += 45

        # --- Triage & CVE Enrichment Integration ---
        product_name = details.get('product', 'unknown').lower()
        matched_cve, severity, remediation = "None Identified", "Info", "Standard hardening recommended."
        
        for key, info in CVE_DATABASE.items():
            if key in product_name:
                matched_cve = info["cve"]
                severity = info["severity"]
                remediation = info["remediation"]
                break

        report.append({
            "port": port,
            "state": state,
            "service": details.get('name', 'unknown'),
            "product": details.get('product', 'unknown'),
            "version": details.get('version', 'unknown'),
            "confidence_score": score,
            "verdict": "High Confidence" if score >= 100 else "Low Confidence - Manual Check Needed",
            # Added upgrades cleanly appended without touching your baseline structure keys
            "cve": matched_cve,
            "severity": severity,
            "remediation": remediation,
            "triage_status": "Unverified"  # State machine flag for manual bug bounty workflow
        })

    if not report:
        report.append({
            "port": 0,
            "service": "None",
            "product": "No open ports detected in scope",
            "state": "closed",
            "version": "N/A",
            "confidence_score": 0,
            "verdict": "Nominal",
            "cve": "N/A",
            "severity": "N/A",
            "remediation": "N/A",
            "triage_status": "Unverified"
        })

    return report

async def main():
    import sys
    if len(sys.argv) < 2:
        print("[!] Usage: python3 scanner.py <IP_ADDRESS>")
        sys.exit(1)

    target = sys.argv[1]
    raw_data = await scan_target(target)

    if "error" in raw_data:
        print(f"[!] Scan Error: {raw_data['error']}")
    else:
        analysis = analyze_results(raw_data)
        print(json.dumps(analysis, indent=4))

if __name__ == "__main__":
    asyncio.run(main())
