# Threat Intelligence Dashboard

End-to-end threat intelligence project: STIX 2.1 IOC normalization, deduplication, transparent scoring, REST APIs, dashboard charts, CSV export, and worker scaffolding.

## Start

```bash
cp .env.example .env
docker compose up --build
```

Open `http://localhost:5173`; API docs are at `http://localhost:8000/docs`.

### VS Code

Do **not** use the **Go Live** button: it only opens a static folder listing and cannot run React, FastAPI, PostgreSQL, or Redis. Open the project folder in VS Code, then choose **Terminal > Run Task > Start Threat Intelligence Dashboard**. Once the terminal says the services have started, open `http://localhost:5173` in your browser.

### Run without Docker

If Docker Desktop cannot download its images, use two VS Code tasks instead:

1. **Terminal > Run Task > Start API - No Docker**
2. **Terminal > Run Task > Start Dashboard UI - No Docker**

This starts the API with a local SQLite database. Open the Vite URL displayed in the second terminal - normally `http://localhost:5173`.

The first run seeds fictional indicators using documentation IP ranges and `.example` domains. The dashboard's demo ingestion is safe and repeatable; repeated items are deduplicated.

## Production checklist

Do not commit credentials. Add authentication, TLS, signed webhooks, licensed GeoIP enrichment, migrations, monitoring, and authenticated source adapters before connecting real feeds.
