from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class IndicatorCreate(BaseModel):
    indicator: str
    indicator_type: str
    source: str
    threat_type: Optional[str] = None
    confidence: Optional[int] = None
    description: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class IndicatorResponse(BaseModel):
    id: int
    indicator: str
    indicator_type: str
    source: str
    threat_type: Optional[str] = None
    confidence: Optional[int] = None
    description: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    class Config:
        from_attributes = True