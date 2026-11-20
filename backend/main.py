"""Threat Intelligence API - safe local demo and production-ready extension points."""
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Literal
from uuid import uuid4
import csv, io, os
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, func, or_, select, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./threatintel.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
class Base(DeclarativeBase): pass
class FeedSource(Base):
    __tablename__ = "feed_sources"; id: Mapped[int] = mapped_column(primary_key=True); name: Mapped[str] = mapped_column(String(100), unique=True); reliability: Mapped[float] = mapped_column(Float, default=.7)
class MalwareFamily(Base):
    __tablename__ = "malware_families"; id: Mapped[int] = mapped_column(primary_key=True); name: Mapped[str] = mapped_column(String(100), unique=True)
class Indicator(Base):
    __tablename__ = "indicators"
    id: Mapped[int] = mapped_column(primary_key=True); value: Mapped[str] = mapped_column(String(2048), unique=True, index=True); type: Mapped[str] = mapped_column(String(32), index=True); score: Mapped[int] = mapped_column(Integer, index=True); confidence: Mapped[int] = mapped_column(Integer, default=50)
    country: Mapped[str | None] = mapped_column(String(64), nullable=True); asn: Mapped[str | None] = mapped_column(String(64), nullable=True); detections: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("feed_sources.id")); malware_family_id: Mapped[int | None] = mapped_column(ForeignKey("malware_families.id"), nullable=True); stix: Mapped[dict] = mapped_column(JSON)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow); last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    source: Mapped[FeedSource] = relationship(); malware_family: Mapped[MalwareFamily | None] = relationship()
class Webhook(Base):
    __tablename__ = "webhooks"; id: Mapped[int] = mapped_column(primary_key=True); url: Mapped[str] = mapped_column(String(2048), unique=True); min_score: Mapped[int] = mapped_column(Integer, default=85); active: Mapped[bool] = mapped_column(Boolean, default=True)
class IndicatorIn(BaseModel):
    value: str = Field(min_length=3, max_length=2048); type: Literal["ipv4-addr", "domain-name", "url", "file"]; source: str = Field(default="Manual", max_length=100); confidence: int = Field(default=50, ge=0, le=100)
    malware_family: str | None = None; country: str | None = None; asn: str | None = None; detections: str | None = None
class WebhookIn(BaseModel): url: HttpUrl; min_score: int = Field(default=85, ge=0, le=100)
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()
def severity(score: int): return "critical" if score >= 85 else "high" if score >= 71 else "medium" if score >= 31 else "low"
def score_indicator(confidence: int, reliability: float, overlap: int = 0): return min(100, round(confidence*.65 + reliability*35 + min(overlap, 3)*5))
def stix_for(item: IndicatorIn):
    path={"ipv4-addr":"ipv4-addr:value","domain-name":"domain-name:value","url":"url:value","file":"file:hashes.'SHA-256'"}[item.type]
    now=datetime.utcnow().isoformat()+"Z"
    return {"type":"indicator","spec_version":"2.1","id":f"indicator--{uuid4()}","created":now,"modified":now,"pattern_type":"stix","pattern":f"[{path} = '{item.value}']","valid_from":now,"confidence":item.confidence,"labels":["malicious-activity",item.source.lower()]}
def serialize(i: Indicator): return {"id":i.id,"value":i.value,"type":i.type,"score":i.score,"severity":severity(i.score),"confidence":i.confidence,"country":i.country,"asn":i.asn,"detections":i.detections,"source":i.source.name,"malware_family":i.malware_family.name if i.malware_family else None,"first_seen":i.first_seen.isoformat(),"last_seen":i.last_seen.isoformat()}
def store_indicator(db: Session, item: IndicatorIn):
    existing=db.scalar(select(Indicator).where(Indicator.value == item.value))
    if existing:
        existing.last_seen=datetime.utcnow(); existing.confidence=max(existing.confidence,item.confidence); db.commit(); db.refresh(existing); return existing, False
    source=db.scalar(select(FeedSource).where(FeedSource.name == item.source))
    if not source: source=FeedSource(name=item.source,reliability=.75); db.add(source); db.flush()
    family=None
    if item.malware_family:
        family=db.scalar(select(MalwareFamily).where(MalwareFamily.name == item.malware_family))
        if not family: family=MalwareFamily(name=item.malware_family); db.add(family); db.flush()
    record=Indicator(value=item.value,type=item.type,score=score_indicator(item.confidence,source.reliability),confidence=item.confidence,country=item.country,asn=item.asn,detections=item.detections,source_id=source.id,malware_family_id=family.id if family else None,stix=stix_for(item))
    db.add(record); db.commit(); db.refresh(record); return record, True
DEMO=[IndicatorIn(value="198.51.100.42",type="ipv4-addr",source="ThreatFox",confidence=94,malware_family="RedLine",country="United States",asn="AS64500",detections="48/70"),IndicatorIn(value="login-check.example",type="domain-name",source="URLhaus",confidence=89,malware_family="Qakbot",country="Germany",asn="AS64501",detections="41/70"),IndicatorIn(value="https://cdn-updates.example/payload",type="url",source="URLhaus",confidence=77,malware_family="Emotet",country="Netherlands",asn="AS64502",detections="32/70"),IndicatorIn(value="a"*64,type="file",source="MalwareBazaar",confidence=98,malware_family="RedLine",country="United Kingdom",asn="AS64503",detections="66/70"),IndicatorIn(value="203.0.113.19",type="ipv4-addr",source="ThreatFox",confidence=56,malware_family="IcedID",country="Singapore",asn="AS64504",detections="17/70")]
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine); db=SessionLocal()
    if not db.scalar(select(func.count(Indicator.id))):
        for item in DEMO: store_indicator(db,item)
    db.close(); yield
app=FastAPI(title="Threat Intelligence Dashboard",version="1.0.0",description="STIX 2.1 IOC ingestion, enrichment, analytics and export API.",lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=os.getenv("CORS_ORIGINS","http://localhost:5173").split(","),allow_methods=["*"],allow_headers=["*"])
@app.get("/health")
def health(): return {"status":"ok","timestamp":datetime.utcnow().isoformat()+"Z"}
@app.get("/api/v1/iocs")
def list_iocs(search: str|None=None,severity_filter: str|None=Query(None,alias="severity"),limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0),db:Session=Depends(get_db)):
    stmt=select(Indicator).order_by(Indicator.last_seen.desc())
    if search: stmt=stmt.where(or_(Indicator.value.ilike(f"%{search}%"),Indicator.type.ilike(f"%{search}%")))
    ranges={"low":(0,30),"medium":(31,70),"high":(71,84),"critical":(85,100)}
    if severity_filter:
        if severity_filter not in ranges: raise HTTPException(422,"Invalid severity")
        stmt=stmt.where(Indicator.score.between(*ranges[severity_filter]))
    total=db.scalar(select(func.count()).select_from(stmt.subquery())) or 0; rows=db.scalars(stmt.offset(offset).limit(limit)).all()
    return {"items":[serialize(i) for i in rows],"total":total,"limit":limit,"offset":offset}
@app.post("/api/v1/iocs",status_code=201)
def create_ioc(item:IndicatorIn,db:Session=Depends(get_db)):
    record,created=store_indicator(db,item); return {**serialize(record),"created":created}
@app.post("/api/v1/iocs/ingest")
def ingest_demo(db:Session=Depends(get_db)):
    results=[store_indicator(db,item)[0] for item in DEMO]; return {"processed":len(results),"items":[serialize(i) for i in results]}
@app.get("/api/v1/iocs/{indicator_id}/stix")
def get_stix(indicator_id:int,db:Session=Depends(get_db)):
    item=db.get(Indicator,indicator_id)
    if not item: raise HTTPException(404,"Indicator not found")
    return item.stix
@app.get("/api/v1/analytics/summary")
def summary(db:Session=Depends(get_db)):
    rows=db.scalars(select(Indicator)).all(); by_type={t:sum(i.type==t for i in rows) for t in ["ipv4-addr","domain-name","url","file"]}; families={}; countries={}
    for i in rows:
        if i.malware_family: families[i.malware_family.name]=families.get(i.malware_family.name,0)+1
        if i.country: countries[i.country]=countries.get(i.country,0)+1
    return {"total":len(rows),"malicious":sum(i.score>=71 for i in rows),"critical":sum(i.score>=85 for i in rows),"active":sum(i.last_seen>=datetime.utcnow()-timedelta(days=1) for i in rows),"by_type":[{"name":k,"value":v} for k,v in by_type.items() if v],"families":[{"name":k,"value":v} for k,v in families.items()],"countries":[{"name":k,"value":v} for k,v in sorted(countries.items(),key=lambda x:x[1],reverse=True)],"trend":[{"day":(datetime.utcnow()-timedelta(days=n)).strftime("%a"),"value":sum(i.first_seen.date()==(datetime.utcnow()-timedelta(days=n)).date() for i in rows)} for n in reversed(range(7))]}
@app.get("/api/v1/export/csv")
def export_csv(db:Session=Depends(get_db)):
    out=io.StringIO(); writer=csv.writer(out); writer.writerow(["id","value","type","score","severity","source","family","first_seen"])
    for item in db.scalars(select(Indicator).order_by(Indicator.last_seen.desc())): writer.writerow([item.id,item.value,item.type,item.score,severity(item.score),item.source.name,item.malware_family.name if item.malware_family else "",item.first_seen.isoformat()])
    return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=threat-intel-iocs.csv"})
@app.post("/api/v1/webhooks",status_code=201)
def create_webhook(payload:WebhookIn,db:Session=Depends(get_db)):
    if db.scalar(select(Webhook).where(Webhook.url==str(payload.url))): raise HTTPException(409,"Webhook already exists")
    hook=Webhook(url=str(payload.url),min_score=payload.min_score); db.add(hook); db.commit(); db.refresh(hook); return {"id":hook.id,"url":hook.url,"min_score":hook.min_score,"active":hook.active}
