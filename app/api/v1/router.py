import asyncio
import io
from fastapi import APIRouter, Form, Header, HTTPException, Response
from weasyprint import HTML
from app.core.database import SessionLocal
from app.services.scanner import run_nmap_scan, get_cve_data
from app.services.reporter import trigger_alerts_and_reports
from app.models.scan_results import ScanResult

router = APIRouter()

def perform_scan_task(target: str, port_selection: str):
    # 1. Run Synchronous Nmap Scan
    scan_output = run_nmap_scan(target, port_selection=port_selection)
    
    # 2. Run Async services via a dedicated event loop wrapper
    async def run_services():
        try:
            cve_report = await get_cve_data(scan_output)
        except TypeError:
            cve_report = get_cve_data(scan_output)
            
        await trigger_alerts_and_reports(target, cve_report)
        return cve_report
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        cve_report = loop.run_until_complete(run_services())
        
        # 3. Database Persistence
        db = SessionLocal()
        new_result = ScanResult(
            target=target,
            output=str(scan_output),
            cve_report=str(cve_report),
            alerts=str(cve_report)
        )
        db.add(new_result)
        db.commit()
        db.close()
        return cve_report
    finally:
        loop.close()

@router.post("/scan")
def scan(target: str = Form(...), port_selection: str = Form(...)):
    cve_report = perform_scan_task(target, port_selection)
    return {"message": "Scan complete", "results": cve_report}

# PDF Export Endpoint
@router.get("/export-pdf/{target_ip}")
async def export_scan_to_pdf(target_ip: str):
    db = SessionLocal()
    scan_record = db.query(ScanResult).filter(ScanResult.target == target_ip).order_by(ScanResult.id.desc()).first()
    db.close()
    
    if not scan_record:
        raise HTTPException(status_code=404, detail="Scan record not found")
        
    html_content = f"<html><body><h1>Report for {scan_record.target}</h1><p>{scan_record.cve_report}</p></body></html>"
    pdf_file = io.BytesIO()
    HTML(string=html_content).write_pdf(pdf_file)
    
    return Response(content=pdf_file.getvalue(), media_type="application/pdf", 
                    headers={"Content-Disposition": f"attachment; filename=Aegis_Report_{target_ip}.pdf"})

# Admin History Endpoint
@router.get("/admin/history")
async def get_scan_history(api_key: str = Header(...)):
    if api_key != "YOUR_SECURE_ADMIN_KEY": # Ensure you update this key
        raise HTTPException(status_code=403, detail="Unauthorized access")
        
    db = SessionLocal()
    history = db.query(ScanResult).all()
    db.close()
    return {"status": "success", "data": history}
