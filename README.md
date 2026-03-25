# LLMSC Security — Offline Static Version

This is the **fully offline** version of [llmsc-security.github.io](https://llmsc-security.github.io/).  
All API calls to `llmscapi.wj2ai.com` have been replaced with local JSON cache files.

## Quick Start

```bash
# 1. Generate seed cache from bundled backend data (instant, no network)
python3 generate_seed_cache.py

# 2. Serve locally
python3 -m http.server 8080

# 3. Open http://localhost:8080 in your browser
```

## Full Cache (All 100 Repos)

To fetch live data for all 100 repositories from the API and cache everything:

```bash
# Install dependency
pip install aiohttp

# Fetch everything (takes ~2-5 minutes)
python3 fetch_cache.py

# Or fetch just one repo
python3 fetch_cache.py --only-repo "https://github.com/reworkd/AgentGPT"

# Skip CVE detail fetching (faster)
python3 fetch_cache.py --skip-cve
```

## Directory Structure

```
├── index.html              # Home page (offline)
├── potential.html           # Scan results page (offline)
├── cache/                   # ALL cached data lives here
│   ├── select_url.json      #    Candidate URL list
│   ├── potential/            #    Vulnerability results per repo
│   │   └── owner__repo.json
│   ├── architecture/         #    Architecture diagrams per repo
│   │   └── owner__repo.json
│   ├── dependencies/         #    Dependencies per repo (all in one file)
│   │   └── owner__repo.json
│   └── cve/                  #    CVE detail lookups
│       └── CVE-XXXX-YYYY.json
├── fetch_cache.py           # Fetches ALL data from live API into cache/
├── generate_seed_cache.py   # Creates cache from bundled backend data
└── backend/                 # Original backend code (reference only)
```

## What Changed

| File | Change |
|------|--------|
| `index.html` | `fetch(API_BASE_URL+...)` → `fetch("cache/...")` |
| `potential.html` | All 5 API endpoints replaced with local cache reads; dependencies use client-side filter/pagination |
| `fetch_cache.py` | **NEW** — async Python script to download all API data |
| `generate_seed_cache.py` | **NEW** — Generate starter cache from bundled backend data |
| `cache/` | **NEW** — Static JSON data directory |

### API Endpoints → Cache File Mapping

| Original API | Cache File |
|---|---|
| `GET /api/select_url.json` | `cache/select_url.json` |
| `GET /api/results/potential?url=REPO` | `cache/potential/{owner}__{repo}.json` |
| `GET /api/results/architecture?url=REPO` | `cache/architecture/{owner}__{repo}.json` |
| `GET /api/results/dependencies?url=REPO&layer=X&page=N` | `cache/dependencies/{owner}__{repo}.json` (filtered client-side) |
| `GET /api/cve/details?cve_id=ID` | `cache/cve/{CVE-ID}.json` |

## Deploying to GitHub Pages

Push the entire directory (including `cache/`) — no server needed.
