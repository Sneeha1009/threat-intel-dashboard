from fastapi import FastAPI

from app.core.database import engine, Base
from app.models.indicator import Indicator
from app.api.indicators import router as indicator_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Threat Intelligence Dashboard",
    description="Threat intelligence aggregation and analysis platform",
    version="1.0.0"
)

app.include_router(indicator_router)


@app.get("/")
def root():
    return {
        "message": "Threat Intelligence Dashboard API is running"
    }