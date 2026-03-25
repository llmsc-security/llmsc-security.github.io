#!/usr/bin/env python3
"""
=================================================================
  LLMSC Static Cache Builder
  
  Fetches ALL data from the live API at https://llmscapi.wj2ai.com
  and saves it locally so the site can run 100% offline.
  
  Usage:
      python3 fetch_cache.py
      
  Optional flags:
      --api-base URL      Override API base (default: https://llmscapi.wj2ai.com)
      --output-dir DIR    Override output dir (default: ./cache)
      --concurrency N     Parallel requests  (default: 5)
      --skip-cve          Skip CVE detail fetching (fastest)
      --only-repo URL     Only fetch one specific repo
=================================================================
"""
import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path

try:
    import aiohttp
except ImportError:
    print("Installing aiohttp...")
    os.system(f"{sys.executable} -m pip install aiohttp -q")
    import aiohttp

# ─── Configuration ───────────────────────────────────────────────
API_BASE = "https://llmscapi.wj2ai.com"
OUTPUT_DIR = "cache"
CONCURRENCY = 5
DEP_PAGE_LIMIT = 20  # match backend default

# ─── Helpers ─────────────────────────────────────────────────────

def url_to_key(github_url: str) -> str:
    """Convert GitHub URL to safe filesystem key: 'owner__repo'"""
    clean = github_url.strip().rstrip("/")
    if "github.com" in clean:
        path_part = clean.split("github.com/")[-1]
        parts = path_part.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}__{parts[1]}"
    # Fallback: hash
    return hashlib.md5(clean.encode()).hexdigest()

def safe_filename(name: str) -> str:
    """Sanitize for filesystem"""
    return re.sub(r'[^\w\-.]', '_', name)

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def save_json(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(',', ':'))

# ─── Fetchers ────────────────────────────────────────────────────

async def fetch_json(session: aiohttp.ClientSession, url: str, label: str = "") -> dict | None:
    """Fetch JSON from URL with retry."""
    for attempt in range(3):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 404:
                    print(f"  [404] {label or url}")
                    return None
                else:
                    print(f"  [{resp.status}] {label or url} (attempt {attempt+1})")
        except Exception as e:
            print(f"  [ERR] {label or url}: {e} (attempt {attempt+1})")
        await asyncio.sleep(1 * (attempt + 1))
    return None


async def fetch_select_urls(session, output_dir):
    """Step 1: Fetch candidate URL list"""
    print("\n[1/5] Fetching candidate URLs...")
    url = f"{API_BASE}/api/select_url.json"
    data = await fetch_json(session, url, "select_url.json")
    if data:
        save_json(os.path.join(output_dir, "select_url.json"), data)
        candidates = data.get("candidates", [])
        print(f"  ✓ {len(candidates)} repositories found")
        return candidates
    else:
        # Fallback: read from local apps.txt
        print("  ⚠ API failed, trying local backend/data_dir/apps.txt...")
        apps_file = os.path.join(os.path.dirname(__file__), "backend", "data_dir", "apps.txt")
        if os.path.exists(apps_file):
            with open(apps_file) as f:
                candidates = [line.strip() for line in f if line.strip()]
            save_json(os.path.join(output_dir, "select_url.json"), {"candidates": candidates})
            print(f"  ✓ {len(candidates)} repositories from local file")
            return candidates
        print("  ✗ No candidates found!")
        return []


async def fetch_potential(session, output_dir, repo_url, key):
    """Step 2: Fetch vulnerability (potential) data for a repo"""
    encoded = urllib.parse.quote(repo_url, safe='')
    url = f"{API_BASE}/api/results/potential?url={encoded}"
    data = await fetch_json(session, url, f"potential/{key}")
    if data:
        save_json(os.path.join(output_dir, "potential", f"{key}.json"), data)
        return data
    return None


async def fetch_architecture(session, output_dir, repo_url, key):
    """Step 3: Fetch architecture diagram for a repo"""
    encoded = urllib.parse.quote(repo_url, safe='')
    url = f"{API_BASE}/api/results/architecture?url={encoded}"
    data = await fetch_json(session, url, f"architecture/{key}")
    if data:
        save_json(os.path.join(output_dir, "architecture", f"{key}.json"), data)
        return data
    return None


async def fetch_all_dependencies(session, output_dir, repo_url, key):
    """Step 4: Fetch ALL dependency pages for a repo (no layer filter = all deps)"""
    encoded = urllib.parse.quote(repo_url, safe='')
    all_items = []
    page = 1

    while True:
        url = f"{API_BASE}/api/results/dependencies?url={encoded}&page={page}&limit=100"
        data = await fetch_json(session, url, f"dependencies/{key}/page{page}")
        if not data:
            break
        items = data.get("items", [])
        all_items.extend(items)
        if not data.get("has_more", False):
            break
        page += 1
        if page > 100:  # safety limit
            break

    # Save the complete dependency list
    result = {
        "total": len(all_items),
        "items": all_items
    }
    save_json(os.path.join(output_dir, "dependencies", f"{key}.json"), result)
    return result


async def fetch_cve_detail(session, output_dir, cve_id):
    """Step 5: Fetch a single CVE detail"""
    safe_id = safe_filename(cve_id)
    out_path = os.path.join(output_dir, "cve", f"{safe_id}.json")
    
    # Skip if already fetched
    if os.path.exists(out_path):
        return True

    encoded = urllib.parse.quote(cve_id, safe='')
    url = f"{API_BASE}/api/cve/details?cve_id={encoded}"
    data = await fetch_json(session, url, f"cve/{cve_id}")
    if data:
        save_json(out_path, data)
        return True
    return False


# ─── Orchestrator ────────────────────────────────────────────────

async def process_repo(session, output_dir, repo_url, sem, skip_cve=False):
    """Process a single repo: potential + architecture + dependencies + CVE details"""
    key = url_to_key(repo_url)
    async with sem:
        print(f"\n── {repo_url}  →  {key}")

        # Potential (vulnerabilities)
        potential = await fetch_potential(session, output_dir, repo_url, key)
        vuln_count = 0
        cve_ids = set()
        if potential:
            vuln_data = potential.get("data", [])
            vuln_count = len(vuln_data)
            for v in vuln_data:
                if v.get("id"):
                    cve_ids.add(v["id"])
                if v.get("lookup_id"):
                    cve_ids.add(v["lookup_id"])
            print(f"  ✓ potential: {vuln_count} vulnerabilities, {len(cve_ids)} unique CVE IDs")
        else:
            print(f"  ✗ potential: no data")

        # Architecture
        arch = await fetch_architecture(session, output_dir, repo_url, key)
        if arch:
            nodes = arch.get("diagram", {})
            if nodes:
                node_count = len(nodes.get("nodes", []))
                print(f"  ✓ architecture: {node_count} nodes")
            else:
                print(f"  ✓ architecture: (no diagram)")
        else:
            print(f"  ✗ architecture: no data")

        # Dependencies
        deps = await fetch_all_dependencies(session, output_dir, repo_url, key)
        print(f"  ✓ dependencies: {deps['total']} items")

        # CVE Details
        if not skip_cve and cve_ids:
            print(f"  → Fetching {len(cve_ids)} CVE details...")
            cve_tasks = [fetch_cve_detail(session, output_dir, cid) for cid in cve_ids]
            results = await asyncio.gather(*cve_tasks, return_exceptions=True)
            ok = sum(1 for r in results if r is True)
            print(f"  ✓ cve details: {ok}/{len(cve_ids)} fetched")

        return vuln_count


async def main(args):
    t0 = time.time()

    output_dir = args.output_dir
    ensure_dir(output_dir)
    for sub in ["potential", "architecture", "dependencies", "cve"]:
        ensure_dir(os.path.join(output_dir, sub))

    print(f"╔══════════════════════════════════════════╗")
    print(f"║   LLMSC Static Cache Builder             ║")
    print(f"║   API: {args.api_base:<33s}║")
    print(f"║   Output: {args.output_dir:<30s}║")
    print(f"╚══════════════════════════════════════════╝")

    global API_BASE
    API_BASE = args.api_base

    async with aiohttp.ClientSession() as session:
        # Step 1: Get repo list
        candidates = await fetch_select_urls(session, output_dir)
        
        if args.only_repo:
            candidates = [c for c in candidates if args.only_repo in c]
            if not candidates:
                candidates = [args.only_repo]
            print(f"\n  Filtering to: {candidates}")

        if not candidates:
            print("No repositories to process. Exiting.")
            return

        # Step 2-5: Process all repos in parallel
        sem = asyncio.Semaphore(args.concurrency)
        tasks = [
            process_repo(session, output_dir, url, sem, skip_cve=args.skip_cve)
            for url in candidates
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    total_vulns = sum(r for r in results if isinstance(r, int))
    elapsed = time.time() - t0

    print(f"\n{'='*50}")
    print(f"Done! {len(candidates)} repos processed in {elapsed:.1f}s")
    print(f"Total vulnerabilities cached: {total_vulns}")
    print(f"Cache directory: {os.path.abspath(output_dir)}/")
    
    # Print cache stats
    total_files = 0
    total_size = 0
    for root, dirs, files in os.walk(output_dir):
        for f in files:
            fp = os.path.join(root, f)
            total_files += 1
            total_size += os.path.getsize(fp)
    print(f"Total files: {total_files} ({total_size/1024/1024:.1f} MB)")
    print(f"\nYour site is now fully offline! Open index.html in a browser.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLMSC Static Cache Builder")
    parser.add_argument("--api-base", default=API_BASE, help="API base URL")
    parser.add_argument("--output-dir", default=OUTPUT_DIR, help="Output cache directory")
    parser.add_argument("--concurrency", type=int, default=CONCURRENCY, help="Parallel requests")
    parser.add_argument("--skip-cve", action="store_true", help="Skip CVE detail fetching")
    parser.add_argument("--only-repo", default=None, help="Only fetch one repo URL")
    args = parser.parse_args()
    
    asyncio.run(main(args))
