"""Scheduled-feed extension point. Configure authenticated adapters before production use."""
import os
from celery import Celery

celery_app = Celery("threatintel", broker=os.getenv("REDIS_URL", "redis://redis:6379/0"))
celery_app.conf.beat_schedule = {"poll-feeds": {"task": "worker.ingest_feeds", "schedule": 1800}}

@celery_app.task
def ingest_feeds():
    return {"status": "skipped", "reason": "Add authenticated source adapters before enabling production polling."}
