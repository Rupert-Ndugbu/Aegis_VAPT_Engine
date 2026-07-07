import os
import datetime
import asyncio
from pathlib import Path

async def trigger_alerts_and_reports(target: str, cve_report: str):
    # Fixed: Used _file_ (with double underscores)
    base_dir = Path(__file__).resolve().parent.parent
    reports_dir = base_dir / 'reports'
    
    if not reports_dir.exists():
        reports_dir.mkdir(parents=True, exist_ok=True)
        
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    formatted_target = target.replace('.', '_')
    filename = reports_dir / f"report_{formatted_target}_{timestamp}.md"
    
    with open(filename, "w") as f:
        f.write(f"# Vulnerability Scan Report\n\n")
        f.write(f"*Target*: {target}\n\n")
        f.write(f"*Timestamp*: {timestamp}\n\n")
        f.write(f"## Findings\n{cve_report}\n")
    
    if "No specific vulnerabilities" not in cve_report:
        print(f"[ALERT] Vulnerability detected on {target}: {cve_report}")
