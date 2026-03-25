#!/usr/bin/env python3
"""
Static Data Extraction Script for SecurityScan Hub.
Extracts data from:
1. Local filesystem (architecture, vulnerabilities, dependencies)
2. HTTP service on port 6106 (CVE details)

Saves all data as combined JSON files for static offline usage.
"""

import json
import os
import time
import re
import urllib.request
import urllib.error
from typing import Dict, List, Any, Optional

# Configuration
HTTP_API_URL = "http://localhost:6106"
GRPC_HOST = "localhost:6008"
WORKSPACE_DIR = "/mnt/nvme/wj_code/dl_llmsc/SCA_workspace/lili_select_llm_app_100"
OUTPUT_DIR = "data"
APPS_LIST_FILE = "backend/data_dir/apps.txt"

# Patterns to clean sensitive data
AWS_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', '[AWS_ACCESS_KEY_REDACTED]'),
    (r'X-Amz-Credential=[^&]+', 'X-Amz-Credential=[REDACTED]'),
    (r'X-Amz-Signature=[0-9a-f]+', 'X-Amz-Signature=[REDACTED]'),
    (r'sk-proj-[0-9a-zA-Z]{20,}', '[OPENAI_KEY_REDACTED]'),
]


def clean_sensitive_data(text: str) -> str:
    """Remove sensitive data from text."""
    if not text:
        return text
    for pattern, replacement in AWS_PATTERNS:
        text = re.sub(pattern, replacement, text)
    return text


def fetch_http_json(endpoint: str, max_retries: int = 3) -> Optional[Dict]:
    """Fetch JSON from HTTP API with retry logic."""
    url = f"{HTTP_API_URL}{endpoint}"
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read().decode('utf-8')
                return json.loads(data)
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            print(f"  Error fetching {url}: {e}")
            if attempt < max_retries - 1:
                print(f"  Retrying ({attempt + 1}/{max_retries})...")
                time.sleep(2)
            else:
                return None
        except json.JSONDecodeError as e:
            print(f"  JSON decode error for {url}: {e}")
            return None
        time.sleep(0.3)
    return None


def get_repo_folder_path(url: str) -> Optional[str]:
    """Converts a GitHub URL to the local filesystem path."""
    if not url:
        return None
    try:
        clean_url = url.strip().rstrip('/')
        if "github.com" in clean_url:
            path_part = clean_url.split("github.com/")[-1]
            parts = path_part.split('/')
            if len(parts) >= 2:
                owner = parts[0]
                repo_name = parts[1]
                folder_name = f"{owner}__{repo_name}"
                return os.path.join(WORKSPACE_DIR, folder_name)
    except Exception:
        pass
    return None


def load_json_file(file_path: str) -> Optional[Dict]:
    """Load JSON from local file."""
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"  Error loading {file_path}: {e}")
        return None


def extract_candidates() -> List[str]:
    """Load repository candidates from apps.txt."""
    print("Loading repository candidates...")
    if os.path.exists(APPS_LIST_FILE):
        with open(APPS_LIST_FILE, 'r', encoding='utf-8') as f:
            candidates = [line.strip() for line in f if line.strip()]
        print(f"  Loaded {len(candidates)} candidates")
        return candidates
    return []


def extract_vulnerabilities_from_local(repo_url: str) -> Optional[Dict]:
    """Extract vulnerability data from local SCA result file."""
    repo_path = get_repo_folder_path(repo_url)
    if not repo_path:
        return None

    json_path = os.path.join(repo_path, "sca_result_enriched.json")
    data = load_json_file(json_path)
    if data:
        # Process results to match API format
        results = data.get("results", [])
        formatted_data = []
        seen_vulnerabilities = set()

        for item in results:
            if not item.get("vulnerable"):
                continue

            component_name = item.get("component")
            ecosystem = item.get("ecosystem")
            raw_version = item.get("parsed_constraint", "")
            clean_version = re.sub(r'[\^~>=<]', '', str(raw_version))

            for vuln in item.get("vulnerabilities", []):
                cve_list = vuln.get("cves", [])
                display_id = cve_list[0] if cve_list else vuln.get("id")

                unique_key = (component_name, display_id)
                if unique_key in seen_vulnerabilities:
                    continue
                seen_vulnerabilities.add(unique_key)

                # Calculate CVSS
                cvss_vector = vuln.get("cvss", "")
                score, severity_label = calculate_cvss_score(cvss_vector)

                formatted_data.append({
                    "component": component_name,
                    "ecosystem": ecosystem,
                    "version": clean_version,
                    "id": display_id,
                    "summary": vuln.get("summary"),
                    "severity": severity_label,
                    "score": score,
                    "cvss_version": "3.1" if cvss_vector and "CVSS:3.1" in cvss_vector else "3.0" if cvss_vector and "CVSS:3.0" in cvss_vector else "Unknown",
                    "cvss_vector": cvss_vector,
                    "lookup_id": vuln.get("id"),
                    "poc_video_url": None  # Will be mapped later
                })

        return {
            "meta": data.get("meta", {}),
            "total_vulnerabilities": len(formatted_data),
            "data": formatted_data
        }
    return None


def calculate_cvss_score(vector_str: str) -> tuple:
    """Calculate CVSS score from vector string."""
    if not vector_str or "CVSS:3" not in vector_str:
        return 0.0, "Medium"

    try:
        # CVSS 3.1 Calculator
        AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
        AC = {'L': 0.77, 'H': 0.44}
        PR_U = {'N': 0.85, 'L': 0.62, 'H': 0.27}
        PR_C = {'N': 0.85, 'L': 0.68, 'H': 0.50}
        UI = {'N': 0.85, 'R': 0.62}
        S = {'U': 6.42, 'C': 7.52}
        CIA = {'H': 0.56, 'L': 0.22, 'N': 0.0}

        def roundup(val):
            int_val = int(val * 100000)
            if int_val % 10000 == 0:
                return int_val / 100000.0
            return (int_val // 10000 + 1) / 10.0

        metrics = {}
        for part in vector_str.split('/'):
            if ':' in part:
                k, v = part.split(':')
                metrics[k] = v

        av = AV.get(metrics.get('AV'), 0.85)
        ac = AC.get(metrics.get('AC'), 0.77)
        ui = UI.get(metrics.get('UI'), 0.85)
        s_char = metrics.get('S', 'U')
        pr_val = metrics.get('PR', 'N')
        pr = PR_C.get(pr_val, 0.85) if s_char == 'C' else PR_U.get(pr_val, 0.85)
        c = CIA.get(metrics.get('C'), 0.0)
        i = CIA.get(metrics.get('I'), 0.0)
        a = CIA.get(metrics.get('A'), 0.0)

        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        impact = 6.42 * iss if s_char == 'U' else 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        if impact <= 0:
            base_score = 0.0
        else:
            exploitability = 8.22 * av * ac * pr * ui
            base_score = roundup(min((impact + exploitability), 10)) if s_char == 'U' else roundup(min(1.08 * (impact + exploitability), 10))

        if base_score == 0:
            severity = "None"
        elif base_score <= 3.9:
            severity = "Low"
        elif base_score <= 6.9:
            severity = "Medium"
        elif base_score <= 8.9:
            severity = "High"
        else:
            severity = "Critical"

        return base_score, severity
    except Exception:
        return 0.0, "Medium"


def extract_architecture_from_local(repo_url: str) -> Optional[Dict]:
    """Extract architecture data from local files."""
    repo_path = get_repo_folder_path(repo_url)
    if not repo_path:
        return None

    diagram_data = load_json_file(os.path.join(repo_path, "architecture_diagram.json"))
    layers_data = load_json_file(os.path.join(repo_path, "architecture_layers.json"))

    if diagram_data or layers_data:
        result = {}
        if diagram_data:
            result["diagram"] = diagram_data.get("diagram")
        if layers_data:
            result["layers"] = layers_data.get("layers")
        return result
    return None


def extract_dependencies_from_local(repo_url: str) -> List[Dict]:
    """Extract dependencies from local file."""
    repo_path = get_repo_folder_path(repo_url)
    if not repo_path:
        return []

    dep_path = os.path.join(repo_path, "dependency_architecture_mapping.json")
    data = load_json_file(dep_path)
    return data if data else []


def extract_cve_details_local(cve_id: str) -> Optional[Dict]:
    """Extract CVE details from local HTTP service on port 6106."""
    endpoint = f"/api/cve/details?cve_id={urllib.parse.quote(cve_id)}"
    return fetch_http_json(endpoint)


def extract_video_map(repo_path: str) -> Dict[str, str]:
    """Extract video mapping from local files."""
    combined_map = {}

    # Global map in backend directory
    global_map_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend", "cve_video_map.json")
    data = load_json_file(global_map_path)
    if data:
        combined_map.update(data)

    # Repo specific map
    if repo_path:
        repo_map_path = os.path.join(repo_path, "cve_video_map.json")
        data = load_json_file(repo_map_path)
        if data:
            combined_map.update(data)

    return combined_map


def main():
    print("=" * 70)
    print("SecurityScan Hub - Static Data Extraction")
    print("=" * 70)

    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Step 1: Load candidates
    candidates = extract_candidates()
    if not candidates:
        print("No candidates found. Exiting.")
        return

    print(f"\nFound {len(candidates)} repositories to process")
    print("-" * 70)

    # Data storage
    all_vulnerabilities = {}
    all_architectures = {}
    all_cve_details = {}
    all_dependencies = {}
    all_video_maps = {}

    # Step 2: Extract data from local filesystem for each repo
    for i, repo_url in enumerate(candidates, 1):
        print(f"\n[{i}/{len(candidates)}] Processing: {repo_url}")
        repo_path = get_repo_folder_path(repo_url)

        # Extract vulnerabilities
        print("  - Vulnerabilities...", end=" ")
        vuln_data = extract_vulnerabilities_from_local(repo_url)
        if vuln_data:
            all_vulnerabilities[repo_url] = vuln_data
            print(f"OK ({len(vuln_data.get('data', []))} vulnerabilities)")
        else:
            print("FAILED")

        # Extract architecture
        print("  - Architecture...", end=" ")
        arch_data = extract_architecture_from_local(repo_url)
        if arch_data:
            all_architectures[repo_url] = arch_data
            print("OK")
        else:
            print("FAILED")

        # Extract dependencies
        print("  - Dependencies...", end=" ")
        deps = extract_dependencies_from_local(repo_url)
        if deps:
            all_dependencies[repo_url] = deps
            print(f"OK ({len(deps)} dependencies)")
        else:
            print("FAILED")

        # Extract video map
        print("  - Video Map...", end=" ")
        video_map = extract_video_map(repo_path)
        if video_map:
            all_video_maps[repo_url] = video_map
            print(f"OK ({len(video_map)} mappings)")
        else:
            print("FAILED")

        # Collect CVE IDs from vulnerabilities
        if vuln_data and 'data' in vuln_data:
            for item in vuln_data['data']:
                cve_id = item.get('lookup_id') or item.get('id')
                if cve_id and cve_id not in all_cve_details:
                    print(f"    - CVE: {cve_id}...", end=" ")
                    cve_data = extract_cve_details_local(cve_id)
                    if cve_data:
                        # Clean sensitive data
                        if 'details' in cve_data:
                            cve_data['details'] = clean_sensitive_data(cve_data['details'])
                        if 'summary' in cve_data:
                            cve_data['summary'] = clean_sensitive_data(cve_data['summary'])
                        all_cve_details[cve_id] = cve_data
                        print("OK")
                    else:
                        print("FAILED (using placeholder)")

                        # Create placeholder entry
                        all_cve_details[cve_id] = {
                            "id": cve_id,
                            "summary": "Details not available - run local CVE service",
                            "details": f"Vulnerability {cve_id} details not found in local database.\n\nThis CVE was not found in the OSV database. To enable full CVE details, ensure the CVE lookup service is running on port 6106.",
                            "affected": [],
                            "references": []
                        }

        time.sleep(0.5)  # Rate limiting

    # Step 3: Save all data
    print("\n" + "=" * 70)
    print("Saving data to JSON files...")
    print("=" * 70)

    # Save vulnerabilities
    with open(f"{OUTPUT_DIR}/vulnerabilities.json", 'w') as f:
        json.dump(all_vulnerabilities, f, indent=2, ensure_ascii=False)
    print(f"\n✓ Saved vulnerabilities.json ({len(all_vulnerabilities)} repos)")

    # Save architectures
    with open(f"{OUTPUT_DIR}/architectures.json", 'w') as f:
        json.dump(all_architectures, f, indent=2, ensure_ascii=False)
    print(f"✓ Saved architectures.json ({len(all_architectures)} repos)")

    # Save CVE details
    with open(f"{OUTPUT_DIR}/cve_details.json", 'w') as f:
        json.dump(all_cve_details, f, indent=2, ensure_ascii=False)
    print(f"✓ Saved cve_details.json ({len(all_cve_details)} CVEs)")

    # Save dependencies
    with open(f"{OUTPUT_DIR}/dependencies.json", 'w') as f:
        json.dump(all_dependencies, f, indent=2, ensure_ascii=False)
    print(f"✓ Saved dependencies.json ({len(all_dependencies)} repos)")

    # Save video maps
    with open(f"{OUTPUT_DIR}/video_maps.json", 'w') as f:
        json.dump(all_video_maps, f, indent=2, ensure_ascii=False)
    print(f"✓ Saved video_maps.json ({len(all_video_maps)} repos)")

    # Save candidates list
    with open(f"{OUTPUT_DIR}/candidates.json", 'w') as f:
        json.dump({"candidates": candidates}, f, indent=2, ensure_ascii=False)
    print(f"✓ Saved candidates.json ({len(candidates)} repositories)")

    print("\n" + "=" * 70)
    print("Extraction complete!")
    print("=" * 70)
    print(f"\nData saved to {OUTPUT_DIR}/ directory:")
    print(f"  - candidates.json ({len(candidates)} repositories)")
    print(f"  - vulnerabilities.json ({len(all_vulnerabilities)} repos)")
    print(f"  - architectures.json ({len(all_architectures)} repos)")
    print(f"  - cve_details.json ({len(all_cve_details)} CVEs)")
    print(f"  - dependencies.json ({len(all_dependencies)} repos)")
    print(f"  - video_maps.json ({len(all_video_maps)} repos)")


if __name__ == "__main__":
    main()
