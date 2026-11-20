from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.indicator import Indicator
from app.schemas.indicator import IndicatorCreate, IndicatorResponse
from app.services.threatfox import get_recent_indicators


router = APIRouter(
    prefix="/indicators",
    tags=["Indicators"]
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Create an indicator
@router.post("/", response_model=IndicatorResponse)
def create_indicator(
    indicator_data: IndicatorCreate,
    db: Session = Depends(get_db)
):
    new_indicator = Indicator(
        indicator=indicator_data.indicator,
        indicator_type=indicator_data.indicator_type,
        source=indicator_data.source,
        threat_type=indicator_data.threat_type,
        confidence=indicator_data.confidence,
        description=indicator_data.description,
        first_seen=indicator_data.first_seen,
        last_seen=indicator_data.last_seen
    )

    db.add(new_indicator)
    db.commit()
    db.refresh(new_indicator)

    return new_indicator


# Get all indicators
@router.get("/", response_model=list[IndicatorResponse])
def get_indicators(db: Session = Depends(get_db)):
    return db.query(Indicator).all()


# Get recent indicators from ThreatFox
@router.get("/threatfox")
async def fetch_threatfox_indicators():
    try:
        data = await get_recent_indicators()
        return data
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch ThreatFox data: {str(e)}"
        )


# Get one indicator by ID
@router.get("/{indicator_id}", response_model=IndicatorResponse)
def get_indicator(
    indicator_id: int,
    db: Session = Depends(get_db)
):
    indicator = db.query(Indicator).filter(
        Indicator.id == indicator_id
    ).first()

    if indicator is None:
        raise HTTPException(
            status_code=404,
            detail="Indicator not found"
        )

    return indicator
