from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime

from app.core.database import Base


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)

    indicator = Column(String(500), nullable=False, index=True)

    indicator_type = Column(String(50), nullable=False)

    source = Column(String(100), nullable=False)

    threat_type = Column(String(100), nullable=True)

    confidence = Column(Integer, nullable=True)

    description = Column(Text, nullable=True)

    first_seen = Column(DateTime, nullable=True)

    last_seen = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    