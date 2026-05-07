# Credify Verify (GitHub Pages)

Static, scanner-only Credify verifier designed for GitHub Pages.

## Behavior

- Camera scan only (no upload, no paste)
- Cyber-style UI with matrix/falling-letter background effect
- Accepts Credify verification URLs containing:
  - `id` (required)
  - `qk` (required)
  - `qd` (optional)
  - `gt` (optional, used for 48-hour check)
- Verifies issuer JWS signature offline using trusted issuer public keys
- Shows full credential fields only when `qd` exists in the QR URL

## Run locally

Open `index.html` with a local static server (recommended):

- Python: `python -m http.server 8080`
- Node: `npx serve .`

Then open `http://localhost:8080`.

## Deploy to GitHub Pages

1. Push this folder to a repo branch.
2. In repository settings, enable GitHub Pages.
3. Set source to the branch/folder containing these static files.
4. Open the published URL and use `pages/scan.html` flow.

## Structure

- `index.html` at root as the deploy entry page
- `pages/scan.html`, `pages/result.html`, `pages/tampered.html` for scanner workflow pages
- `pages/info/privacy.html`, `pages/info/trust.html`, `pages/info/support.html` for footer pages
- `assets/css/style.css` for all styles
- `assets/js/app.js` for scan, verify, matrix rain, and UI behavior
- `assets/data/trusted_issuers.json` for trusted issuer key registry

## Trusted issuers

Issuer public keys are loaded from `assets/data/trusted_issuers.json`.
An embedded fallback is present in `assets/js/app.js` for resiliency.
