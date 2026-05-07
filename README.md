<div align="center">

# Credify Verify

**PDF academic transcript verifier for students and institutional verifiers.**

[![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)](.) [![Built with](https://img.shields.io/badge/HTML-CSS--JS-ff69b4?style=flat-square&logo=html5&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web)

Live → https://udaycodespace.github.io/credify-verify/ · Issues · Docs

</div>

---

## What this is

`Credify Verify` is a static verification client that lets verifiers check academic PDF credentials (transcripts/certificates) locally in the browser.

It verifies QR/proof data and credential anchors against a local trust list (`data/trusted_issuers.json`) without requiring a backend — built as an independent verification boundary for the Credify issuance platform.

---

## Stack

| Layer | Tech |
|---|---|
| Frontend | HTML, CSS, JavaScript (vanilla) |
| Backend | None (static client) |
| Storage | Local files; IPFS references in payloads |
| Auth | No authentication required (verifier access is public) |
| Deployment | GitHub Pages / any static host |

---

## Features

- Upload or scan a student PDF to extract QR or embedded proof data.
- Validate credential anchor and issuer against `data/trusted_issuers.json`.
- Show clear verification outcomes: verified (`pages/result.html`) or tampered (`pages/tampered.html`).
- Offline-capable verification flow — no backend dependency for basic checks.
- Simple informational pages: `pages/info/privacy.html`, `pages/info/support.html`, `pages/info/trust.html`.

---

## Screens

Screenshots of the main verification flows.

| Scan PDF | Verified result |
|:---:|:---:|
| ![Scan UI](./assets/screens/scan.png) | ![Verified result](./assets/screens/result.png) |

| Tampered result | Info pages |
|:---:|:---:|
| ![Tampered result](./assets/screens/tampered.png) | ![Info pages](./assets/screens/info.png) |

---

## Running locally

**Prerequisites**

- A modern browser (Chrome / Edge / Firefox)
- Optional: Python to serve files locally

```powershell
# From repository root
python -m http.server 8000
# Then open http://localhost:8000 in your browser
```

Opening `index.html` via `file://` may limit some browser APIs; prefer a local HTTP server.

No environment variables are required — the verifier is static and reads `data/trusted_issuers.json`.

---

## Project structure

```
.
├── index.html
├── README.md
├── TEMPLATE.md
├── assets/
│   ├── css/
│   └── screens/
├── data/
│   └── trusted_issuers.json
├── js/
│   └── app.js
├── pages/
│   ├── scan.html
│   ├── result.html
│   └── tampered.html
└── pages/info/
    ├── privacy.html
    ├── support.html
    └── trust.html
```

---

## Known gaps

- No client-side cryptographic signature verification of issuer keys (hash/anchor checks are performed; full signature validation is not implemented here).
- No automated test coverage for the static client.
- Basic responsive layout only; mobile UX can be improved.

---

## Roadmap

- Add client-side RSA signature verification using issuer public keys.
- Fetch trusted issuers from a signed, hosted endpoint and support key rotation.
- Add end-to-end tests and CI publishing to GitHub Pages.

---

## Status

![active](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)

---

## License

Proprietary — All rights reserved. See [LICENSE](./LICENSE) for details.

For permissions or licensing inquiries, contact the project owner:

- GitHub: https://github.com/udaycodespace
- LinkedIn: https://www.linkedin.com/in/somapuram-uday/

See [LICENSE-FAQ.md](./LICENSE-FAQ.md) for common questions about licensing and permissions.

---

<div align="center">
  <sub>Built by <a href="https://github.com/udaycodespace">udaycodespace</a> · 2026</sub>
</div>