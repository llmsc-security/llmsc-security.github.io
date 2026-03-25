## **Task: Transition System to Static/Offline Architecture**

### **Objective**

Convert the dynamic project into a **static offline version**. The project will serve HTML as static files, store data in JSON/JSONL format, and be hosted via **GitHub Pages**.
some jobs about converting already finish in deploy, static\*html and extract_\*.py, you can continue from them . 

### **Current Architecture**

* **Port 6006:** Primary application backend (General data).
* **Port 6106:** CVE lookup service (Maps CVE IDs to detailed descriptions).

### **Execution Strategy & Logic**

1. **Direct File System Extraction (Local Services):**
* For services such as `/api/` and `/architecture`, do **not** use HTTP requests.
* Trace the **realpath** on the local machine where these services are hosted.
* Extract the raw data directly from the source files stored on the PC to ensure data integrity and speed.


2. **HTTP Data Scraping (CVE Details):**
* For the **CVE detail pages**, perform recursive HTTP requests to the service on port 6106.
* Systematically map every CVE ID to its full description.
* *Note:* This will result in a high volume of requests, but it is a one-time operation to facilitate the migration.


3. **Data Persistence & Refactoring:**
* Consolidate all extracted data into **JSON** or **JSONL** files.
* Refactor the frontend JavaScript to replace all `fetch()` or `XHR` backend calls with logic that parses these local static files.


4. **Deployment:**
* Upload the entire static directory (including the new JSON database) to **GitHub Pages**.



---

### **Technical Summary Table**

| Data Source | Retrieval Method | Target Format |
| --- | --- | --- |
| `/api/` & `/architecture` | **Local File System (realpath)** | JSON / JSONL(read the backend/main.py ) |
| CVE Descriptions | **HTTP Request (Port 6106)** | JSON / JSONL |
| Frontend | **Static HTML/JS** | GitHub Pages |
cat only get from **HTTP Request** 
https://llmscapi.wj2ai.com/api/cve/details?cve_id=GHSA-9v9h-cgj8-h64p
cat get from **Local File System (realpath)** 
https://llmscapi.wj2ai.com/api/results/potential?url=https%3A%2F%2Fgithub.com%2Freworkd%2FAgentGPT
https://llmscapi.wj2ai.com/api/select_url.json
https://llmscapi.wj2ai.com/api/results/architecture?url=https%3A%2F%2Fgithub.com%2Freworkd%2FAgentGPT
https://llmscapi.wj2ai.com/api/results/dependencies?url=https%3A%2F%2Fgithub.com%2Freworkd%2FAgentGPT&layer=LLMs&page=1&limit=20

