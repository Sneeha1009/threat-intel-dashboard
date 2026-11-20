import os

import httpx
from dotenv import load_dotenv

load_dotenv()

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")


async def get_recent_indicators():
    payload = {
        "query": "get_iocs",
        "days": 1
    }

    headers = {
        "Auth-Key": THREATFOX_API_KEY,
        "User-Agent": "Threat-Intelligence-Dashboard/1.0"
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            THREATFOX_URL,
            json=payload,
            headers=headers
        )

        print("ThreatFox status:", response.status_code)
        print("ThreatFox response:", response.text[:500])

        response.raise_for_status()

        return response.json()
