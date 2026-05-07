<div align="center">

# Credify Verify

**PDF academic transcript verifier for students and institutional verifiers.**

<br/>

![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square) ![License](https://img.shields.io/badge/license-proprietary-red?style=flat-square) ![Last Commit](https://img.shields.io/github/last-commit/udaycodespace/credify-verify?style=flat-square) ![Built With](https://img.shields.io/badge/HTML--CSS--JS-ff69b4?style=flat-square&logo=html5&logoColor=white)

<br/>

[**Live Client →**](https://udaycodespace.github.io/credify-verify/) &emsp; [**Documentation →**](./docs) &emsp; [Report Issue](https://github.com/udaycodespace/credify-verify/issues/new)

</div>

<br/>

<div align="center">
  <img src="./assets/screens/preview.png" width="100%" alt="Credify Verify — dashboard preview" />
  <br/>
  <sub>Verifier dashboard · Scan and result engine</sub>
</div>

<br/>

## The Verification Protocol

Verification shouldn't depend on an issuer's uptime. A tool relying on an external server isn't an independent verifier; it is just an API call. Credify Verify shifts the trust boundary entirely to the client.

* **Execution:** Drop a PDF. The engine extracts embedded metadata or QR payloads directly in-browser.
* **Validation:** Cross-checks the credential anchor against a local registry (`trusted_issuers.json`) for a deterministic verdict.
* **Network Constraints:** Zero external network calls. Zero third-party dependencies.
* **Target Use Cases:** Offline institutional audits, student self-verification, and seamless integration into private blockchain architectures.

<br/>

## Technical Stack

| Layer | Technology | Architectural Decision |
| :--- | :--- | :--- |
| **Frontend** | HTML, CSS, Vanilla JS | Zero framework overhead. Absolute portability. |
| **Backend** | None | Total isolation from issuance infrastructure. |
| **Database** | None | Credential anchors map to a local trust list. Zero query latency. |
| **Auth** | None | Verifiers operate natively without accounts. |
| **Storage** | Local files + IPFS | Designed for offline-first verification. |
| **Deploy** | Static Host / GitHub Pages | Immutable frontend deployment. |

<br/>

## Core Mechanics

* **Client-Side Extraction:** Parses raw PDFs to extract embedded proof payloads or QR anchors entirely in-memory.
* **Deterministic Validation:** Validates the anchor and issuer identity against `data/trusted_issuers.json`.
* **Binary Output:** Returns an immediate, mathematically sound verdict—**Verified** or **Tampered**.
* **Air-Gapped Capability:** Works completely offline for all primary verification flows.

<br/>

## System Architecture

Built on three strict design principles:

* **Isolated Verification Boundary:** The engine is decoupled from the Credify issuance platform. If the issuing private blockchain or server goes dark, validation logic remains perfectly intact.
* **Zero Dependency Execution:** A static client running natively in the browser. No build pipelines, no package managers, no runtime dependencies.
* **Explicit Trust Mapping:** `trusted_issuers.json` acts as the human-readable trust anchor. Engineered to transition to a signed, remotely-fetched list with enforced key rotation for enterprise production.

<br/>

## Engineering Challenges

* **In-Browser PDF Parsing**
  * *Constraint:* The JS ecosystem for client-side PDF manipulation is bloated, with most libraries failing on edge-case document structures.
  * *Architecture:* Implemented a highly optimized, lightweight extraction path engineered specifically for academic documents.
* **Trust Model Tradeoffs**
  * *Constraint:* A local JSON trust list is functional but lacks cryptographic finality. 
  * *Architecture:* Acknowledged this limitation by explicitly designing the module to ingest signed remote lists for secure, production-grade environments.

<br/>

## Interface Overview

| Scan Interface | Verification Success |
| :---: | :---: |
| ![Scan UI](./assets/screens/scan.png) | ![Verified result](./assets/screens/result.png) |

| Tampered Detection | System Documentation |
| :---: | :---: |
| ![Tampered result](./assets/screens/tampered.png) | ![Info pages](./assets/screens/info.png) |

<br/>

## Deployment

Requires a modern browser (Chrome, Edge, Firefox). 
```bash
# Clone the repository
git clone [https://github.com/udaycodespace/credify-verify.git](https://github.com/udaycodespace/credify-verify.git)
cd credify-verify

# Spin up a local server (Bypasses browser file:// CORS restrictions)
python -m http.server 8000

# Access the client
http://localhost:8000
```

<br/>

## Directory Structure

```text
credify-verify/
├── index.html
├── data/
│   └── trusted_issuers.json      ← Core trust boundary
├── js/
│   └── app.js                    ← Extraction and validation logic
├── pages/
│   ├── scan.html
│   ├── result.html
│   └── tampered.html
└── assets/
```

<br/>

## Troubleshooting

> **"Unknown Issuer" Error on Valid Document**
> The issuer's public key is missing from `data/trusted_issuers.json`. Inject their metadata into the registry.

> **Browser Blocking File APIs**
> Never open `index.html` directly via the filesystem. Always route through a local HTTP server to clear security protocols.

<br/>

## Development Roadmap

* [ ] Implement client-side RSA signature verification against issuer public keys.
* [ ] Architect signed, hosted trust lists supporting dynamic key rotation.
* [ ] Establish end-to-end testing pipeline tied to GitHub Pages CI/CD.

<br/>

## Governance & Access

Contributions require strict architectural review. Review `CONTRIBUTING.md` and open a discussion before proposing structural modifications.

**System Architect:** [Somapuram Uday](https://github.com/udaycodespace) | [LinkedIn](https://www.linkedin.com/in/somapuram-uday/)

<br/>

## License

Proprietary — All rights reserved. See `LICENSE`.

<br/>

<div align="center">
  <sub>
    System Architect: <a href="https://github.com/udaycodespace">Somapuram Uday</a>
    &nbsp;·&nbsp;
    2026
    &nbsp;·&nbsp;
    Credify
  </sub>
</div>