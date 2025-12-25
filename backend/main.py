import json
import asyncio
import os
import time
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

# gRPC Imports
import grpc
from google.protobuf.json_format import MessageToDict

# Try to import the generated gRPC modules
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

# --- Cache Configuration ---
# Structure: { "full_file_path": { "data": dict, "timestamp": float } }
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


# --- Static Page Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open("index.html", "r", encoding='utf-8') as f: return f.read()

@app.get("/index.html", response_class=HTMLResponse)
async def read_index():
    with open("index.html", "r", encoding='utf-8') as f: return f.read()

@app.get("/scan-progress.html", response_class=HTMLResponse)
async def read_progress():
    with open("scan-progress.html", "r", encoding='utf-8') as f: return f.read()

@app.get("/tool-detail.html", response_class=HTMLResponse)
async def read_detail():
    with open("tool-detail.html", "r", encoding='utf-8') as f: return f.read()

@app.get("/sca_structure.html", response_class=HTMLResponse)
async def read_structure():
    with open("sca_structure.html", "r", encoding='utf-8') as f: return f.read()

@app.get("/potential.html", response_class=HTMLResponse)
async def read_potential():
    with open("potential.html", "r", encoding='utf-8') as f: return f.read()

# --- API Endpoints ---

@app.get("/api/select_url.json")
async def get_select_urls():
    """
    Returns the list of candidate URLs loaded at startup.
    """
    return JSONResponse({
        "candidates": APPS_CANDIDATES
    })

@app.get("/api/results/potential")
async def get_potential_results(url: Optional[str] = Query(None)):
    """
    Returns vulnerable components based on the provided Repo URL.
    Uses an in-memory cache to store results for 24 hours.
    """
    sca_data = {"results": [], "meta": {}}

    if url:
        try:
            # 1. Parse URL to get file path
            clean_url = url.strip().rstrip('/')
            if "github.com" in clean_url:
                path_part = clean_url.split("github.com/")[-1]
                parts = path_part.split('/')
                
                if len(parts) >= 2:
                    owner = parts[0]
                    repo_name = parts[1]
                    folder_name = f"{owner}__{repo_name}"
                    json_path = os.path.join(WORKSPACE_DIR, folder_name, "sca_result_enriched.json")
                    
                    # 2. Check Cache
                    current_time = time.time()
                    cached_entry = SCA_CACHE.get(json_path)
                    
                    # If valid cache exists (hit)
                    if cached_entry and (current_time - cached_entry["timestamp"] < CACHE_TTL_SECONDS):
                        print(f"Cache HIT for {folder_name}")
                        sca_data = cached_entry["data"]
                    
                    # If no cache or expired (miss)
                    else:
                        if os.path.exists(json_path):
                            print(f"Cache MISS (Loading disk) for {folder_name}")
                            with open(json_path, "r", encoding="utf-8") as f:
                                sca_data = json.load(f)
                            
                            # Update Cache
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

    # Process the loaded data
    results = sca_data.get("results", [])
    vulnerable_items = [item for item in results if item.get("vulnerable")]
    
    formatted_data = []
    for item in vulnerable_items:
        for vuln in item.get("vulnerabilities", []):
            formatted_data.append({
                "component": item.get("component"),
                "ecosystem": item.get("ecosystem"),
                "version": item.get("parsed_constraint"),
                "id": vuln.get("id"),
                "summary": vuln.get("summary"),
                "severity": "High" if "High" in str(vuln.get("cvss", "")) else "Medium",
                "cves": vuln.get("cves", []),
                "cvss": vuln.get("cvss")
            })
            
    return JSONResponse({
        "meta": sca_data.get("meta"),
        "total_vulnerabilities": len(formatted_data),
        "data": formatted_data
    })

@app.get("/api/cve/details")
async def get_cve_details(cve_id: str):
    """
    Fetches CVE details from the local gRPC OSV service.
    """
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


