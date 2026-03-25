#!/usr/bin/env python3
"""
Generate seed cache from bundled backend data.
This creates a working cache/ directory from the existing
backend/sca_result_match_cve.json + backend/data_dir/apps.txt
so the site works immediately for the default repo (AgentGPT).

Usage: python3 generate_seed_cache.py
"""
import json
import math
import os
import re
import urllib.parse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(SCRIPT_DIR, "backend")
CACHE_DIR = os.path.join(SCRIPT_DIR, "cache")

# ─── CVSS 3.1 Calculator (ported from backend/main.py) ─────────

class CVSSCalculator:
    WEIGHTS = {
        "AV":  {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC":  {"L": 0.77, "H": 0.44},
        "PR_U":{"N": 0.85, "L": 0.62, "H": 0.27},
        "PR_C":{"N": 0.85, "L": 0.68, "H": 0.50},
        "UI":  {"N": 0.85, "R": 0.62},
        "C":   {"H": 0.56, "L": 0.22, "N": 0},
        "I":   {"H": 0.56, "L": 0.22, "N": 0},
        "A":   {"H": 0.56, "L": 0.22, "N": 0},
    }

    @staticmethod
    def roundup(x):
        return math.ceil(x * 10) / 10.0

    @classmethod
    def calculate_score(cls, vector_str):
        try:
            parts = {}
            for segment in vector_str.split("/"):
                if ":" in segment:
                    k, v = segment.split(":", 1)
                    parts[k] = v

            scope = parts.get("S", "U")
            av  = cls.WEIGHTS["AV"].get(parts.get("AV","N"), 0.85)
            ac  = cls.WEIGHTS["AC"].get(parts.get("AC","L"), 0.77)
            pr_key = "PR_C" if scope == "C" else "PR_U"
            pr  = cls.WEIGHTS[pr_key].get(parts.get("PR","N"), 0.85)
            ui  = cls.WEIGHTS["UI"].get(parts.get("UI","N"), 0.85)
            conf = cls.WEIGHTS["C"].get(parts.get("C","N"), 0)
            integ = cls.WEIGHTS["I"].get(parts.get("I","N"), 0)
            avail = cls.WEIGHTS["A"].get(parts.get("A","N"), 0)

            iss = 1 - ((1-conf) * (1-integ) * (1-avail))
            exploitability = 8.22 * av * ac * pr * ui

            if scope == "U":
                impact = 6.42 * iss
            else:
                impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02)**15)

            if impact <= 0:
                return (0.0, "None")

            if scope == "U":
                score = cls.roundup(min(impact + exploitability, 10))
            else:
                score = cls.roundup(min(1.08 * (impact + exploitability), 10))

            if score >= 9.0: label = "Critical"
            elif score >= 7.0: label = "High"
            elif score >= 4.0: label = "Medium"
            elif score > 0: label = "Low"
            else: label = "None"

            return (score, label)
        except Exception:
            return (0.0, "Medium")


def url_to_key(github_url):
    clean = github_url.strip().rstrip("/")
    if "github.com" in clean:
        path_part = clean.split("github.com/")[-1]
        parts = path_part.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}__{parts[1]}"
    return clean.replace("/", "__")


def process_potential(sca_data, video_map=None):
    """Replicate backend/main.py get_potential_results logic."""
    if video_map is None:
        video_map = {}

    results = sca_data.get("results", [])
    formatted = []
    seen = set()

    for item in results:
        if not item.get("vulnerable"):
            continue
        component = item.get("component")
        ecosystem = item.get("ecosystem")
        raw_ver = item.get("parsed_constraint", "")
        clean_ver = re.sub(r'[\^~>=<]', '', str(raw_ver))

        for vuln in item.get("vulnerabilities", []):
            cve_list = vuln.get("cves", [])
            display_id = cve_list[0] if cve_list else vuln.get("id")
            key = (component, display_id)
            if key in seen:
                continue
            seen.add(key)

            cvss_vector = vuln.get("cvss", "")
            cvss_version = "Unknown"
            if cvss_vector and "CVSS:3" in cvss_vector:
                score, severity_label = CVSSCalculator.calculate_score(cvss_vector)
                if "CVSS:3.1" in cvss_vector: cvss_version = "3.1"
                elif "CVSS:3.0" in cvss_vector: cvss_version = "3.0"
            else:
                score = 0
                severity_label = "Medium"

            mapped_val = video_map.get(display_id) or video_map.get(vuln.get("id"))
            poc_video_url = None
            if mapped_val and mapped_val.startswith("http"):
                poc_video_url = mapped_val

            formatted.append({
                "component": component,
                "ecosystem": ecosystem,
                "version": clean_ver,
                "id": display_id,
                "summary": vuln.get("summary"),
                "severity": severity_label,
                "score": score,
                "cvss_version": cvss_version,
                "cvss_vector": cvss_vector,
                "lookup_id": vuln.get("id"),
                "poc_video_url": poc_video_url,
            })

    return {
        "meta": sca_data.get("meta"),
        "total_vulnerabilities": len(formatted),
        "data": formatted,
    }


def main():
    os.makedirs(CACHE_DIR, exist_ok=True)
    for sub in ["potential", "architecture", "dependencies", "cve"]:
        os.makedirs(os.path.join(CACHE_DIR, sub), exist_ok=True)

    # 1. Candidate list
    apps_file = os.path.join(BACKEND_DIR, "data_dir", "apps.txt")
    candidates = []
    if os.path.exists(apps_file):
        with open(apps_file) as f:
            candidates = [line.strip() for line in f if line.strip()]
    select_data = {"candidates": candidates}
    with open(os.path.join(CACHE_DIR, "select_url.json"), "w") as f:
        json.dump(select_data, f, separators=(',', ':'))
    print(f"✓ select_url.json: {len(candidates)} candidates")

    # 2. Video map
    video_map = {}
    vmap_path = os.path.join(BACKEND_DIR, "cve_video_map.json")
    if os.path.exists(vmap_path):
        with open(vmap_path) as f:
            video_map = json.load(f)

    # 3. Process the bundled SCA data for the default repo
    sca_path = os.path.join(BACKEND_DIR, "sca_result_match_cve.json")
    if os.path.exists(sca_path):
        with open(sca_path) as f:
            sca_data = json.load(f)

        # The bundled file is for reworkd/AgentGPT
        default_key = "reworkd__AgentGPT"
        potential_result = process_potential(sca_data, video_map)
        out_path = os.path.join(CACHE_DIR, "potential", f"{default_key}.json")
        with open(out_path, "w") as f:
            json.dump(potential_result, f, separators=(',', ':'))
        print(f"✓ potential/{default_key}.json: {potential_result['total_vulnerabilities']} vulnerabilities")

        # Create empty architecture and dependencies placeholders
        arch_path = os.path.join(CACHE_DIR, "architecture", f"{default_key}.json")
        with open(arch_path, "w") as f:
            json.dump({"diagram": None, "layers": None}, f)
        print(f"✓ architecture/{default_key}.json (placeholder)")

        deps_path = os.path.join(CACHE_DIR, "dependencies", f"{default_key}.json")
        with open(deps_path, "w") as f:
            json.dump({"total": 0, "items": []}, f)
        print(f"✓ dependencies/{default_key}.json (placeholder)")
    else:
        print("⚠ No bundled SCA data found")

    print(f"\n✓ Seed cache created at: {CACHE_DIR}/")
    print(f"  The site now works offline for the default repo.")
    print(f"  Run 'python3 fetch_cache.py' to fetch data for ALL {len(candidates)} repos.")


if __name__ == "__main__":
    main()
