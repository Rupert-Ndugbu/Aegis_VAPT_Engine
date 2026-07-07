from app.core.database import engine, Base
from app.models.scan_results import ScanResult

Base.metadata.create_all(bind=engine)
print("Database initialized successfully.")
