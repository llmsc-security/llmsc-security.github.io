import json
import asyncio
import os
import time
import math
import re
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# gRPC Imports
import grpc
from google.protobuf.json_format import MessageToDict

try:
    import osv_service_v1_pb2
    import osv_service_v1_pb2_grpc
except ImportError:
    print("Error: Could not import generated gRPC modules. Ensure osv_service_v1_pb2.py exists.")

app = FastAPI()

# --- Configuration ---
GRPC_HOST = "localhost:6008"
APPS_LIST_FILE = "data_dir/apps.txt"
WORKSPACE_DIR = "/mnt/nvme/wj_code/dl_llmsc/SCA_workspace/lili_select_llm_app_100"

# --- CORS Configuration ---
origins = [
    "http://143.198.205.199:9001",
    "http://143.198.205.199",
    "https://llmsc.wj2ai.com",
    "http://llmsc.wj2ai.com",
    "http://localhost:6007", 
    "http://127.0.0.1:6007"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Cache Configuration ---
SCA_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 Hours

# --- Startup Data Loading ---
APPS_CANDIDATES = []
if os.path.exists(APPS_LIST_FILE):
    try:
        with open(APPS_LIST_FILE, "r", encoding="utf-8") as f:
            APPS_CANDIDATES = [line.strip() for line in f if line.strip()]
        print(f"Loaded {len(APPS_CANDIDATES)} apps from {APPS_LIST_FILE}")
    except Exception as e:
        print(f"Error reading {APPS_LIST_FILE}: {e}")
        APPS_CANDIDATES = []
else:
    print(f"Warning: {APPS_LIST_FILE} not found. Candidate list will be empty.")


# --- CVSS 3.1 Calculator Logic ---
class CVSSCalculator:
    # Metric Values
    AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
    AC = {'L': 0.77, 'H': 0.44}
    PR_U = {'N': 0.85, 'L': 0.62, 'H': 0.27} # Scope Unchanged
    PR_C = {'N': 0.85, 'L': 0.68, 'H': 0.50} # Scope Changed
    UI = {'N': 0.85, 'R': 0.62}
    S =  {'U': 6.42, 'C': 7.52}
    CIA = {'H': 0.56, 'L': 0.22, 'N': 0.0}

    @staticmethod
    def roundup(input_val):
        int_input = int(input_val * 100000)
        if (int_input % 10000) == 0:
            return int_input / 100000.0
        else:
            return (math.floor(int_input / 10000) + 1) / 10.0

    @staticmethod
    def calculate_score(vector_str):
        if not vector_str or "CVSS:3" not in vector_str:
            return 0.0, "Medium" # Default fallback if no valid vector
        
        try:
            # Parse Vector
            metrics = {}
            parts = vector_str.split('/')
            for p in parts:
                if ':' in p:
                    k, v = p.split(':')
                    metrics[k] = v

            # Defaults
            av = CVSSCalculator.AV.get(metrics.get('AV'), 0.85)
            ac = CVSSCalculator.AC.get(metrics.get('AC'), 0.77)
            ui = CVSSCalculator.UI.get(metrics.get('UI'), 0.85)
            s_char = metrics.get('S', 'U')
            
            # PR depends on Scope
            pr_val = metrics.get('PR', 'N')
            if s_char == 'C':
                pr = CVSSCalculator.PR_C.get(pr_val, 0.85)
            else:
                pr = CVSSCalculator.PR_U.get(pr_val, 0.85)

            c = CVSSCalculator.CIA.get(metrics.get('C'), 0.0)
            i = CVSSCalculator.CIA.get(metrics.get('I'), 0.0)
            a = CVSSCalculator.CIA.get(metrics.get('A'), 0.0)

            # Impact Sub-score (ISS)
            iss = 1 - ((1 - c) * (1 - i) * (1 - a))

            # Impact
            if s_char == 'U':
                impact = 6.42 * iss
            else:
                impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

            if impact <= 0:
                base_score = 0.0
            else:
                # Exploitability
                exploitability = 8.22 * av * ac * pr * ui
                
                if s_char == 'U':
                    base_score = CVSSCalculator.roundup(min((impact + exploitability), 10))
                else:
                    base_score = CVSSCalculator.roundup(min(1.08 * (impact + exploitability), 10))

            # Severity Rating
            if base_score == 0: severity = "None"
            elif 0.1 <= base_score <= 3.9: severity = "Low"
            elif 4.0 <= base_score <= 6.9: severity = "Medium"
            elif 7.0 <= base_score <= 8.9: severity = "High"
            else: severity = "Critical"

            return base_score, severity

        except Exception:
            return 0.0, "Medium" 

# --- API Endpoints ---

@app.get("/api/select_url.json")
async def get_select_urls():
    return JSONResponse({
        "candidates": APPS_CANDIDATES
    })

@app.get("/api/results/potential")
async def get_potential_results(url: Optional[str] = Query(None)):
    sca_data = {"results": [], "meta": {}}

    # 1. Load Data Strategy (Disk + Cache)
    if url:
        try:
            clean_url = url.strip().rstrip('/')
            if "github.com" in clean_url:
                path_part = clean_url.split("github.com/")[-1]
                parts = path_part.split('/')
                
                if len(parts) >= 2:
                    owner = parts[0]
                    repo_name = parts[1]
                    folder_name = f"{owner}__{repo_name}"
                    json_path = os.path.join(WORKSPACE_DIR, folder_name, "sca_result_enriched.json")
                    
                    # Check Cache
                    current_time = time.time()
                    cached_entry = SCA_CACHE.get(json_path)
                    
                    if cached_entry and (current_time - cached_entry["timestamp"] < CACHE_TTL_SECONDS):
                        print(f"Cache HIT for {folder_name}")
                        sca_data = cached_entry["data"]
                    else:
                        if os.path.exists(json_path):
                            print(f"Cache MISS (Loading disk) for {folder_name}")
                            with open(json_path, "r", encoding="utf-8") as f:
                                sca_data = json.load(f)
                            SCA_CACHE[json_path] = {
                                "data": sca_data,
                                "timestamp": current_time
                            }
                        else:
                            print(f"SCA Result File not found: {json_path}")
            else:
                print(f"Invalid GitHub URL format provided: {url}")
            
        except Exception as e:
            print(f"Error loading SCA results for {url}: {e}")
            return JSONResponse({"error": str(e)}, status_code=500)

    # 2. Process & Deduplicate Logic
    results = sca_data.get("results", [])
    formatted_data = []
    seen_vulnerabilities = set() # Track unique (Component, CVE_ID) pairs

    for item in results:
        # Strict vulnerable check
        if not item.get("vulnerable"):
            continue

        component_name = item.get("component")
        ecosystem = item.get("ecosystem")
        
        # Clean Version (remove ^, ~, etc.)
        raw_version = item.get("parsed_constraint", "")
        clean_version = re.sub(r'[\^~>=<]', '', str(raw_version))

        for vuln in item.get("vulnerabilities", []):
            # Prioritize CVE ID
            cve_list = vuln.get("cves", [])
            display_id = cve_list[0] if cve_list else vuln.get("id")

            # Deduplication
            unique_key = (component_name, display_id)
            if unique_key in seen_vulnerabilities:
                continue
            seen_vulnerabilities.add(unique_key)

            # --- SEVERITY CALCULATION ---
            cvss_vector = vuln.get("cvss", "")
            cvss_version = "Unknown"
            
            # Determine Version
            if cvss_vector:
                if "CVSS:3.1" in cvss_vector: cvss_version = "3.1"
                elif "CVSS:3.0" in cvss_vector: cvss_version = "3.0"
                elif "CVSS:2" in cvss_vector: cvss_version = "2.0"

            # Calculate Score & Severity
            if cvss_vector and "CVSS:3" in cvss_vector:
                score, severity_label = CVSSCalculator.calculate_score(cvss_vector)
            else:
                score = 0
                severity_label = "Medium" # Default if no vector

            formatted_data.append({
                "component": component_name,
                "ecosystem": ecosystem,
                "version": clean_version,
                "id": display_id, # This is the CVE if available, or GHSA otherwise
                "summary": vuln.get("summary"),
                "severity": severity_label, 
                "score": score,
                "cvss_version": cvss_version,
                "cvss_vector": cvss_vector,
                "lookup_id": vuln.get("id") # Keep original ID (GHSA) for API lookups
            })
            
    return JSONResponse({
        "meta": sca_data.get("meta"),
        "total_vulnerabilities": len(formatted_data),
        "data": formatted_data
    })

@app.get("/api/cve/details")
async def get_cve_details(cve_id: str):
    if not cve_id:
        raise HTTPException(status_code=400, detail="Missing CVE ID")

    try:
        async with grpc.aio.insecure_channel(GRPC_HOST) as channel:
            stub = osv_service_v1_pb2_grpc.OSVStub(channel)
            request = osv_service_v1_pb2.GetVulnByIdParameters(id=cve_id)
            
            try:
                response = await stub.GetVulnById(request)
            except grpc.RpcError as e:
                if e.code() == grpc.StatusCode.NOT_FOUND:
                    return JSONResponse({
                        "id": cve_id,
                        "summary": "Not Found",
                        "details": f"Vulnerability {cve_id} not found in local database."
                    }, status_code=404)
                raise e

            data = MessageToDict(response, preserving_proto_field_name=True)
            return JSONResponse(data)

    except Exception as e:
        print(f"Error fetching CVE {cve_id}: {e}")
        return JSONResponse({"error": f"Failed to fetch vulnerability data: {str(e)}"}, status_code=500)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=6007)

