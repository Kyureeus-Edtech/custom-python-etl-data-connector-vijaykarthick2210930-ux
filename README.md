# NVD CVE ETL Connector (Python → MongoDB)

This connector extracts CVE data from the NIST NVD v2.0 API, transforms the payload for MongoDB, and upserts documents into a collection.

## API
Base URL: `https://services.nvd.nist.gov/rest/json/cves/2.0`

### Key notes
- Optional API key can be passed via the `apiKey` header for higher rate limits.
- Pagination via `startIndex` and `resultsPerPage` (capped by the API).
- Time filters used here: `pubStartDate` and `pubEndDate` (ISO 8601, Zulu time).

## Setup

1. **Clone the repo** and create a new branch using the naming rule from your course guidelines.
2. **Create your `.env`** based on the provided `ENV_TEMPLATE`.
3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Run MongoDB** (local or cloud) and set `MONGO_URI` accordingly.

## Environment Variables

Copy `ENV_TEMPLATE` to `.env` and edit values.

```dotenv
NVD_BASE_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
NVD_API_KEY=your_api_key_or_leave_blank

MONGO_URI=mongodb://localhost:27017
MONGO_DB=security_feeds
MONGO_COLLECTION=nvd_cves_raw

# Optional tuning
RESULTS_PER_PAGE=200
MAX_PAGES=20
MAX_RETRIES=3
RETRY_SLEEP_SECONDS=3

# Optional time window (ISO 8601 Zulu). If omitted, defaults to last 24h:
# PUB_START=2025-08-12T00:00:00Z
# PUB_END=2025-08-13T00:00:00Z
```

## Run

```bash
python api_call.py
```

## Transform schema (per document)

```json
{
  "_id": "CVE-2025-XXXXX",
  "cveId": "CVE-2025-XXXXX",
  "published": "2025-08-12T15:00Z",
  "lastModified": "2025-08-12T18:00Z",
  "sourceIdentifier": "nvd@nist.gov",
  "description": "English description…",
  "cvssV3": {
    "baseScore": 7.5,
    "severity": "HIGH"
  },
  "affectedCPEs": ["cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*"],
  "raw": { /* original vulnerability object from NVD */ },
  "ingestionTimestamp": "2025-08-13T05:45:00Z"
}
```

## Testing & Validation

- Handles empty responses & pagination end
- Retries w/ simple backoff on request failures or 429
- Upserts by `cveId` to ensure idempotency
- Logs progress and counts of upserted/modified docs

## Git Hygiene

- Put secrets in `.env` (never commit them).
- Commit `ENV_TEMPLATE` to document required keys.
- Add `.env` to `.gitignore` before first commit.

## License

For educational use.
