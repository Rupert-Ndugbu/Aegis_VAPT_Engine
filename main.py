from fastapi import FastAPI
from fastapi.responses import FileResponse  # Added for dashboard serving
from app.api.v1.router import router as scanner_router
from app.core.database import engine, Base
from app.models.scan_results import ScanResult

# Create tables in the database
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Aegis VAPT Engine", version="1.0.0")

app.include_router(scanner_router, prefix="/api/v1")

# Serving the dashboard
@app.get("/")
async def root():
    return FileResponse("index.html")
