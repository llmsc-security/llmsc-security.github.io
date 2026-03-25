#!/usr/bin/env python3
"""
Data extraction script for SecurityScan Hub.
Scrapes data from the backend APIs and saves to local JSON files.
"""

import json
import os
import time
import urllib.request
import urllib.error
import urllib.parse

API_BASE_URL = "https://llmscapi.wj2ai.com"
OUTPUT_DIR = "data"
CANDIDATES_ENDPOINT = "/api/select_url.json"
RESULTS_ENDPOINT = "/api/results/potential"
CVE_DETAILS_ENDPOINT = "/api/cve/details"
ARCHITECTURE_ENDPOINT = "/api/results/architecture"
DEPENDENCIES_ENDPOINT = "/api/results/dependencies"

# Create output directory
os.makedirs(OUTPUT_DIR, exist_ok=True)


def fetch_json(url, max_retries=3, delay=2):
    """Fetch JSON from URL with retry logic."""
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read().decode('utf-8')
                return json.loads(data)
        except urllib.error.URLError as e:
            print(f"  Error fetching {url}: {e}")
            if attempt < max_retries - 1:
                print(f"  Retrying ({attempt + 1}/{max_retries})...")
                time.sleep(delay)
            else:
                return None
        except json.JSONDecodeError as e:
            print(f"  JSON decode error for {url}: {e}")
            return None
        time.sleep(0.5)  # Small delay between requests
    return None


def extract_candidates():
    """Fetch all repository candidates."""
    print("Fetching repository candidates...")
    url = f"{API_BASE_URL}{CANDIDATES_ENDPOINT}"
    data = fetch_json(url)
    if data and 'candidates' in data:
        with open(f"{OUTPUT_DIR}/candidates.json", 'w') as f:
            json.dump(data, f, indent=2)
        print(f"  Saved {len(data['candidates'])} candidates")
        return data['candidates']
    return []


def extract_vulnerabilities(repo_url):
    """Fetch vulnerabilities for a repository."""
    url = f"{API_BASE_URL}{RESULTS_ENDPOINT}?url={urllib.parse.quote(repo_url)}"
    return fetch_json(url)


def extract_cve_details(cve_id):
    """Fetch CVE details."""
    url = f"{API_BASE_URL}{CVE_DETAILS_ENDPOINT}?cve_id={cve_id}"
    return fetch_json(url)


def extract_architecture(repo_url):
    """Fetch architecture data for a repository."""
    url = f"{API_BASE_URL}{ARCHITECTURE_ENDPOINT}?url={urllib.parse.quote(repo_url)}"
    return fetch_json(url)


def extract_dependencies(repo_url, layer, page=1, limit=20):
    """Fetch dependencies for a layer."""
    url = f"{API_BASE_URL}{DEPENDENCIES_ENDPOINT}?url={urllib.parse.quote(repo_url)}&layer={urllib.parse.quote(layer)}&page={page}&limit={limit}"
    return fetch_json(url)


def main():
    print("=" * 60)
    print("SecurityScan Hub Data Extraction")
    print("=" * 60)

    # Step 1: Get all candidates
    candidates = extract_candidates()
    if not candidates:
        print("No candidates found. Exiting.")
        return

    print(f"\nFound {len(candidates)} repositories to process")

    # Initialize data storage
    all_vulnerabilities = {}
    all_architectures = {}
    all_cve_details = {}
    all_dependencies = {}

    # Step 2: Extract data for each repository
    for i, repo_url in enumerate(candidates, 1):
        print(f"\n[{i}/{len(candidates)}] Processing: {repo_url}")

        # Extract vulnerabilities
        print("  - Vulnerabilities...", end=" ")
        vuln_data = extract_vulnerabilities(repo_url)
        if vuln_data:
            all_vulnerabilities[repo_url] = vuln_data
            print(f"OK ({len(vuln_data.get('data', []))} vulnerabilities)")
        else:
            print("FAILED")

        # Extract architecture
        print("  - Architecture...", end=" ")
        arch_data = extract_architecture(repo_url)
        if arch_data:
            all_architectures[repo_url] = arch_data
            print("OK")
        else:
            print("FAILED")

        # Extract CVE details from vulnerabilities
        if vuln_data and 'data' in vuln_data:
            for item in vuln_data['data']:
                cve_id = item.get('lookup_id') or item.get('id')
                if cve_id and cve_id not in all_cve_details:
                    print(f"    - {cve_id}...", end=" ")
                    cve_data = extract_cve_details(cve_id)
                    if cve_data:
                        all_cve_details[cve_id] = cve_data
                        print("OK")
                    else:
                        print("FAILED")

        # Rate limiting
        time.sleep(1)

    # Step 3: Save all extracted data
    print("\n" + "=" * 60)
    print("Saving data to JSON files...")
    print("=" * 60)

    with open(f"{OUTPUT_DIR}/vulnerabilities.json", 'w') as f:
        json.dump(all_vulnerabilities, f, indent=2)
    print(f"Saved vulnerabilities.json ({len(all_vulnerabilities)} repos)")

    with open(f"{OUTPUT_DIR}/architectures.json", 'w') as f:
        json.dump(all_architectures, f, indent=2)
    print(f"Saved architectures.json ({len(all_architectures)} repos)")

    with open(f"{OUTPUT_DIR}/cve_details.json", 'w') as f:
        json.dump(all_cve_details, f, indent=2)
    print(f"Saved cve_details.json ({len(all_cve_details)} CVEs)")

    # Extract dependencies for a few repos as sample
    print("\nExtracting dependency samples...")
    sample_repos = candidates[:3]  # Sample first 3 repos
    for repo_url in sample_repos:
        if repo_url in all_architectures:
            arch = all_architectures[repo_url]
            if arch.get('diagram', {}).get('nodes'):
                for node in arch['diagram']['nodes']:
                    layer = node.get('id')
                    if layer:
                        print(f"  - {repo_url} / {layer}...", end=" ")
                        dep_data = extract_dependencies(repo_url, layer, 1, 10)
                        if dep_data:
                            key = f"{repo_url}:{layer}"
                            all_dependencies[key] = dep_data
                            print("OK")
                        else:
                            print("FAILED")

    with open(f"{OUTPUT_DIR}/dependencies.json", 'w') as f:
        json.dump(all_dependencies, f, indent=2)
    print(f"Saved dependencies.json ({len(all_dependencies)} entries)")

    print("\n" + "=" * 60)
    print("Extraction complete!")
    print("=" * 60)
    print(f"\nData saved to {OUTPUT_DIR}/ directory:")
    print(f"  - candidates.json ({len(candidates)} repositories)")
    print(f"  - vulnerabilities.json ({len(all_vulnerabilities)} repos)")
    print(f"  - architectures.json ({len(all_architectures)} repos)")
    print(f"  - cve_details.json ({len(all_cve_details)} CVEs)")
    print(f"  - dependencies.json ({len(all_dependencies)} layer entries)")


if __name__ == "__main__":
    main()
