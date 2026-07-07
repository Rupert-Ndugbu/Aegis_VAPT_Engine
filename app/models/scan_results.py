from sqlalchemy import Column, Integer, String, Text
from app.core.database import Base

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    target = Column(String)
    output = Column(Text)
    cve_report = Column(Text)
    alerts = Column(Text, nullable=True)
