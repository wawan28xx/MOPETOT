# DEBUGGING & FIXES SUMMARY

## Issues Fixed

### 1. HTTP 405 Error
- **Problem**: Endpoints tidak accessible (HTTP 405 Method Not Allowed)
- **Root Cause**: Multiple possible causes:
  - Duplicate endpoint handlers (especially `/api/scan/{scan_id}` endpoint)
  - Missing GET handler for some endpoints
  
- **Solution**: 
  - ✓ Checked app.py routes - all endpoints properly defined with correct HTTP methods
  - ✓ Added `/api/scan/{scan_id}` endpoint that was missing
  - ✓ Added `/api/scan/{scan_id}/source-context` endpoint
  - ✓ Verified all routes using test client - all passing

### 2. Popup Not Showing on Click
- **Problem**: Clicking hardcoded secret value didn't show modal
- **Root Cause**: 
  - Inline onclick attributes with HTML entity encoding (escHtml) breaking
  - Two duplicate click event listeners conflicting
  - window._secretsData not properly initialized
  
- **Solutions Applied**:
  - ✓ Changed from inline onclick to event delegation pattern
  - ✓ Store secret data in `window._secretsData` dictionary keyed by `secret-{idx}`
  - ✓ Use `data-secret-id` attribute instead of storing escaped data attributes
  - ✓ Merged two duplicate `document.addEventListener('click', ...)` handlers into one unified handler
  - ✓ Initialize `window._secretsData = {}` at top of script

### 3. Event Delegation Pattern
**Before (broken)**:
```html
<span class="secret-match-value" 
      data-file="${escHtml(fullFile)}"
      data-line="${escHtml(String(line))}"
      onclick="openSecretContext(this)">
```

**After (working)**:
```javascript
// In loadSecrets():
window._secretsData['secret-0'] = { file, line, match, context, rule, sev };

// In HTML:
<span class="secret-match-value clickable-secret" data-secret-id="secret-0">

// In event listener:
const secret = e.target.closest('.clickable-secret');
const secretId = secret.dataset.secretId;
openSecretContext(secretId);
```

## File Changes

### 1. `templates/results.html`
- **Complete rewrite of tab system**
  - Fixed tab switching logic (all tabs properly toggle display)
  - Added lazy-loading for tabs 2-6 (data only fetched when tab first clicked)
  
- **Tab 2 (Manifest & Komponen)**
  - Info grid: package, platform, version, SDK info
  - Permissions list with danger indicator for sensitive permissions
  - Components (activities, services, receivers, providers)
  - Deep links / URL schemes
  
- **Tab 3 (Hardcoded Secrets)**
  - Severity summary bar
  - Secrets table with: severity badge, rule, category, match value, file, line
  - ✓ Clickable secret values trigger modal popup
  - ✓ Data stored in `window._secretsData` for event delegation
  
- **Tab 4 (Findings)**
  - Severity summary bar
  - Grouped by category
  - Each group shows findings in table with severity, title, file, line
  
- **Tab 5 (Attack Surface)**
  - Endpoints table with: env badge, URL, host, port, path
  - Color-coded env badges (prod/dev/staging/unknown)
  
- **Tab 6 (Tech Stack & APKiD)**
  - Summary stat cards (findings count, secrets count, platform, file type)
  - Tech stack detection chips
  - RASP / Protection info
  - APKiD binary info
  
- **Tab 7 (Logs)**
  - Log container always visible (no toggle needed)
  - Log entry count badge
  
- **SOURCE CONTEXT MODAL**
  - Modal overlay with animation
  - Displays source code with ±5 line radius around target
  - Highlights the hardcoded secret value in yellow
  - Target line highlighted with orange left border
  - Close with Esc key, backdrop click, or X button
  
### 2. `app.py` (Python Backend)
- **Added endpoint**: `GET /api/scan/{scan_id}`
  - Returns full scan detail with manifest_info, findings array, secrets array
  
- **Added endpoint**: `GET /api/scan/{scan_id}/source-context`
  - Query params: file, line, match, radius (default=5)
  - Returns ±5 lines around the target line from corpus
  - Falls back to context field from findings.json if file not found
  - Response: `{lines: [{no, text}, ...], target_line, file}`

### 3. `static/css/style.css`
- **New CSS classes**:
  - `.tab-pane`: Tab content container (replaces old `.tab-content`)
  - `.tab-loading`: Loading spinner while fetching data
  - `.secrets-table`: Table styling for secrets/findings
  - `.sev-chip`: Severity badge styling (critical/high/medium/low/info)
  - `.hardcoded-highlight`: ✓ Yellow background with border (key differentiator for hardcoded values)
  - `.clickable-secret`: Cursor pointer, hover effect
  - `.ctx-modal-*`: Full modal styling with animation
  - `.ctx-line`: Source code line display
  - `.ctx-line-target`: Highlight target line (orange left border)
  - `.ctx-highlight`: Yellow highlight for matched value in code

## Testing

### Endpoint Tests (All Passing)
```
[OK] GET / — Status 200
[OK] GET /results/31 — Status 200  
[OK] GET /api/scan/31 — Status 200
[OK] GET /api/scan/31/secrets — Status 200 (List[2])
[OK] GET /api/scan/31/findings — Status 200 (List[1])
[OK] GET /api/scan/31/endpoints — Status 200 (List[2])
[OK] GET /api/scan/31/source-context — Status 200
```

### Test Data Created
- Scan ID 31 with 2 secrets:
  - Secret 1: "P@ssw0rd123" at MainActivity.java:42 (HIGH)
  - Secret 2: "AKIAIOSFODNN7EXAMPLE" at Config.java:100 (CRITICAL)
- 1 Finding: Potential SQL Injection
- 2 Endpoints: prod + staging
- Full manifest info with permissions and components

## How to Use

### View Results
1. Start server: `python app.py` (port 8089)
2. Navigate to: `http://localhost:8089/results/31`
3. Click tabs to view different sections

### Click Hardcoded Secret
1. Go to "Hardcoded Secrets" tab
2. Click on any yellow-highlighted secret value (e.g., "P@ssw0rd123")
3. Modal popup appears showing:
   - Source code context (±5 lines)
   - Target line highlighted in orange
   - Secret value highlighted in yellow
   - Rule ID and severity in footer
4. Close with Esc, click backdrop, or X button

## Known Limitations

- `/api/scan/{id}/source-context` tries to read from `results/{id}/work/corpus/` directory
  - If corpus files don't exist, falls back to `context` field stored in DB
  - For production scans, ensure corpus is preserved with `--keep` flag in mobile_audit.py

## Next Steps (Optional)

- Add ability to view full file from modal (with scroll)
- Add "Report this finding" button in modal
- Export secrets list to CSV/JSON
- Add filters for severity level in each tab
