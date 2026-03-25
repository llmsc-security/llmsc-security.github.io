
##  Test Case (Parameterized)

### Purpose

Validate the end-to-end flow:
**Connect GitHub → choose repo via autocomplete → Start Scan → open Vulnerabilities tab → click a vulnerability row → fetch and render vulnerability details for `<cve_id>`**

---

## Parameters (placeholders)

* `<repo_query>`: text typed into repo input (e.g., `gpt`)
* `<repo_url>`: selected repo URL from suggestions (e.g., `https://github.com/reworkd/AgentGPT`)
* `<encoded_repo_url>`: URL-encoded version of `<repo_url>`
* `<scan_page_path>`: `/potential.html`
* `<row_id>`: numeric row index used by UI (e.g., `36`)
* `<cve_id>`: vulnerability identifier passed to details API (e.g., `GHSA-5jqp-qgf6-3pvh`)
* `<details_api_base>`: `https://llmscapi.wj2ai.com/api/cve/details`
* `<details_api_url>`: `<details_api_base>?cve_id=<cve_id>`

---

## Preconditions

1. Landing page contains CTA button: `button.cta` with text `Connect GitHub`.
2. Autocomplete works for `<repo_query>` and contains `<repo_url>` as a selectable suggestion.
3. Scan results page shows Vulnerabilities table that includes at least one row with:

   * `id="row-<row_id>"`
   * row click triggers details for `<cve_id>` (ex: `onclick="toggleRow(<row_id>, '<cve_id>')"`)

---

## Test Steps + Expected Results (Assertions)

### Step 1 — Landing page

**Action**

* Open the landing page.

**Expected**

* `button.cta` is visible and contains text `Connect GitHub`.

---

### Step 2 — Autocomplete appears

**Action**

* Focus repo input.
* Type `<repo_query>`.

**Expected**

* Autocomplete dropdown appears.
* Dropdown contains `<repo_url>`.

---

### Step 3 — Start scan navigates correctly

**Action**

* Select suggestion `<repo_url>`.
* Click `Start Scan`.

**Expected**

* Browser navigates to `<scan_page_path>`.
* Current URL contains:

  * `url=<encoded_repo_url>`
  * (optional) `r=<timestamp_or_random>`

**Example assert**

* `currentUrl` contains `/potential.html?url=https%3A%2F%2Fgithub.com%2F...`

---

### Step 4 — Open Vulnerabilities tab

**Action**

* Click the Vulnerabilities tab button:

  * Selector: `#btn-tab-vuln` (or locate by text “Vulnerabilities”).

**Expected**

* Vulnerabilities tab content is visible.
* Vulnerability table contains at least 1 row: `tr.main-row`.

---

### Step 5 — Click a vulnerability row triggers details fetch

**Action**

* Click row `#row-<row_id>`.

**Expected (Network)**

* A request is made to:

  * `<details_api_url>` i.e. `.../api/cve/details?cve_id=<cve_id>`
* Response returns success (typically HTTP `200`).
* Response body is not empty (contains expected fields for detail rendering).

**Expected (UI)**

* Row expands or detail panel appears for that row.
* The UI displays detail information that corresponds to `<cve_id>` (or content returned by the API).

---

## Example (Concrete values)

Use this only as an illustration of what the placeholders look like in a real run:

* `<repo_query>` = `gpt`
* `<repo_url>` = `https://github.com/reworkd/AgentGPT`
* `<encoded_repo_url>` = `https%3A%2F%2Fgithub.com%2Freworkd%2FAgentGPT`
* `<row_id>` = `36`
* `<cve_id>` = `GHSA-5jqp-qgf6-3pvh`
* `<details_api_url>` =
  `https://llmscapi.wj2ai.com/api/cve/details?cve_id=GHSA-5jqp-qgf6-3pvh`

Example HTML row (illustrative):

```html
<tr class="main-row" onclick="toggleRow(36, 'GHSA-5jqp-qgf6-3pvh')" id="row-36">
  ...
</tr>
```




