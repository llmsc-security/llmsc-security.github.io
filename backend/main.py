import json
import asyncio
import os
import time
import math
import re
import urllib.parse
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
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
VIDEO_MAP_FILENAME = "cve_video_map.json" 

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


# --- Helper: Get Repo Path ---
def get_repo_folder_path(url: str) -> Optional[str]:
    """Converts a GitHub URL to the local filesystem path."""
    if not url: return None
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

# --- Helper: Load Video Map (Combined) ---
def load_combined_video_map(repo_path: Optional[str]) -> Dict[str, str]:
    """
    Loads video mappings from:
    1. The 'backend' directory (global map)
    2. The specific repo directory (repo-specific map)
    Repo specific map overrides global map.
    """
    combined_map = {}
    
    # 1. Global Map (Relative to this main.py file)
    global_map_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), VIDEO_MAP_FILENAME)
    if os.path.exists(global_map_path):
        try:
            with open(global_map_path, "r", encoding="utf-8") as f:
                combined_map.update(json.load(f))
        except Exception as e:
            print(f"Warning: Failed to load global video map: {e}")

    # 2. Repo Specific Map
    if repo_path:
        repo_map_path = os.path.join(repo_path, VIDEO_MAP_FILENAME)
        if os.path.exists(repo_map_path):
            try:
                with open(repo_map_path, "r", encoding="utf-8") as f:
                    combined_map.update(json.load(f))
            except Exception as e:
                print(f"Warning: Failed to load repo video map: {e}")
                
    return combined_map


# --- API Endpoints ---

@app.get("/api/select_url.json")
async def get_select_urls():
    return JSONResponse({
        "candidates": APPS_CANDIDATES
    })

@app.get("/api/result/video")
async def get_poc_video(github_url: str = Query(...), cve_id: str = Query(...)):
    """
    Returns the PoC video content or Redirect.
    """
    repo_path = get_repo_folder_path(github_url)
    # Note: We continue even if repo_path is None, to check global map
    
    video_map = load_combined_video_map(repo_path)
    
    # Check if CVE exists in map
    mapped_value = video_map.get(cve_id)
    if not mapped_value:
        raise HTTPException(status_code=404, detail="No video mapped for this CVE")
        
    # CASE 1: External URL (Google Drive, etc.)
    if mapped_value.startswith("http"):
        return RedirectResponse(mapped_value)

    # CASE 2: Local File
    # Logic: If repo_path exists and file is there, use it.
    # If not, check if it's relative to main.py (Global fallback)
    
    # Try Repo Path first
    if repo_path:
        video_full_path = os.path.join(repo_path, mapped_value)
        if os.path.exists(video_full_path):
            return FileResponse(video_full_path, media_type="video/mp4")

    # Try Global Path (backend dir)
    global_dir = os.path.dirname(os.path.abspath(__file__))
    global_video_path = os.path.join(global_dir, mapped_value)
    
    if os.path.exists(global_video_path):
        return FileResponse(global_video_path, media_type="video/mp4")
        
    raise HTTPException(status_code=404, detail="Video file mapped but not found on disk")


@app.get("/api/results/architecture")
async def get_architecture_results(url: Optional[str] = Query(None)):
    response_data = {}
    repo_path = get_repo_folder_path(url)
    
    if repo_path:
        try:
            # Define paths
            diagram_path = os.path.join(repo_path, "architecture_diagram.json")
            layers_path = os.path.join(repo_path, "architecture_layers.json")
            
            # 1. Load Architecture Diagram
            if os.path.exists(diagram_path):
                with open(diagram_path, "r", encoding="utf-8") as f:
                    response_data.update(json.load(f))
            else:
                response_data["diagram"] = None

            # 2. Load Architecture Layers
            if os.path.exists(layers_path):
                with open(layers_path, "r", encoding="utf-8") as f:
                    response_data.update(json.load(f))
            else:
                response_data["layers"] = None
                
        except Exception as e:
            print(f"Error loading architecture results for {url}: {e}")
            return JSONResponse({"error": str(e)}, status_code=500)
    else:
        print(f"Invalid or missing URL: {url}")

    return JSONResponse(response_data)


@app.get("/api/results/potential")
async def get_potential_results(url: Optional[str] = Query(None)):
    sca_data = {"results": [], "meta": {}}
    
    repo_path = get_repo_folder_path(url)
    
    # Load Combined Map (Global + Repo)
    video_map = load_combined_video_map(repo_path)

    # 1. Load Data Strategy (Disk + Cache)
    if repo_path:
        try:
            json_path = os.path.join(repo_path, "sca_result_enriched.json")

            # Check Cache
            current_time = time.time()
            cached_entry = SCA_CACHE.get(json_path)
            
            if 1==2 and cached_entry and (current_time - cached_entry["timestamp"] < CACHE_TTL_SECONDS):
                print(f"Cache HIT for {json_path}")
                sca_data = cached_entry["data"]
            else:
                if os.path.exists(json_path):
                    with open(json_path, "r", encoding="utf-8") as f:
                        sca_data = json.load(f)
                    SCA_CACHE[json_path] = {
                        "data": sca_data,
                        "timestamp": current_time
                    }
                else:
                    print(f"SCA Result File not found: {json_path}")
        
        except Exception as e:
            print(f"Error loading SCA results for {url}: {e}")
            return JSONResponse({"error": str(e)}, status_code=500)
    else:
         print(f"Invalid GitHub URL format provided: {url}")

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
            
            if cvss_vector:
                if "CVSS:3.1" in cvss_vector: cvss_version = "3.1"
                elif "CVSS:3.0" in cvss_vector: cvss_version = "3.0"
                elif "CVSS:2" in cvss_vector: cvss_version = "2.0"

            if cvss_vector and "CVSS:3" in cvss_vector:
                score, severity_label = CVSSCalculator.calculate_score(cvss_vector)
            else:
                score = 0
                severity_label = "Medium"

            # --- VIDEO MAPPING LOGIC ---
            # Check for direct ID or Lookup ID in the combined map
            mapped_val = video_map.get(display_id) or video_map.get(vuln.get("id"))
            
            poc_video_url = None
            if mapped_val:
                if mapped_val.startswith("http"):
                    # Use external URL directly
                    poc_video_url = mapped_val
                else:
                    # Construct API URL for local file
                    if url and display_id:
                        safe_gh = urllib.parse.quote(url)
                        safe_cve = urllib.parse.quote(display_id)
                        poc_video_url = f"/api/result/video?github_url={safe_gh}&cve_id={safe_cve}"

            formatted_data.append({
                "component": component_name,
                "ecosystem": ecosystem,
                "version": clean_version,
                "id": display_id,
                "summary": vuln.get("summary"),
                "severity": severity_label, 
                "score": score,
                "cvss_version": cvss_version,
                "cvss_vector": cvss_vector,
                "lookup_id": vuln.get("id"),
                "poc_video_url": poc_video_url 
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

