<div align="center">

# Credify Verify

**Browser-native academic credential verifier. No backend. No accounts. No trust assumptions.**

<br/>

![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square) ![License](https://img.shields.io/badge/license-proprietary-red?style=flat-square) ![Last Commit](https://img.shields.io/github/last-commit/udaycodespace/credify-verify?style=flat-square) ![Built With](https://img.shields.io/badge/HTML--CSS--JS-ff69b4?style=flat-square&logo=html5&logoColor=white)

<br/>

[**Live →**](https://udaycodespace.github.io/credify-verify/) &emsp; [**Docs →**](./docs) &emsp; [Report a bug](https://github.com/udaycodespace/credify-verify/issues/new) &emsp; [Request a feature](https://github.com/udaycodespace/credify-verify/issues/new)

</div>

<div align="center">
  <img src="./assets/screens/preview.png" width="100%" alt="Credify Verify — dashboard preview" />
  <br/>
  <sub>Verifier dashboard · scan and result preview</sub>
</div>

---

## What this is

Most credential verification tools require you to ping an issuer's server, create an account, or trust a third-party service to tell you if a document is real.

**Credify Verify doesn't.**

Drop a PDF. The client extracts QR codes or embedded proof metadata directly in-browser, cross-checks the credential anchor against a local trust list (`data/trusted_issuers.json`), and returns a verdict — **verified** or **tampered** — without a single network call to an external service.

The verifier is intentionally decoupled from Credify's issuance platform. That's not a limitation — it's the design. A verification tool that depends on the issuer's uptime is not an independent verifier; it's just another API call dressed up.

Built for: students who need a self-contained proof check, institutions doing offline audits, and developers integrating verification into existing academic workflows.

---

## Stack

| Layer | Tech | Decision |
|:---|:---|:---|
| Frontend | HTML, CSS, Vanilla JS | Zero framework overhead. Runs anywhere. |
| Backend | None | Verifier stays independent of issuance infrastructure. |
| Database | None | Credential anchors + local trust list. No rows to query. |
| Auth | None | Verifiers should never need an account. |
| Storage | Local files + optional IPFS references | Offline-first by default. |
| Deployment | GitHub Pages / any static host | One push, live everywhere. |

---

## What it does

- **Upload or scan** a student PDF — extracts QR or embedded proof payload.
- **Validates** credential anchor and issuer identity against `data/trusted_issuers.json`.
- **Returns a clear verdict** — verified (`pages/result.html`) or tampered (`pages/tampered.html`).
- **Works offline** for all primary verification flows.
- Includes informational pages covering privacy, support, and trust model documentation.

---

## Architecture

Three decisions define this project:

**Independent verifier.** The verification boundary is separate from issuance. If the Credify platform goes down, verification still works. If the issuer's server moves, the trust list updates — not the client logic.

**No install, no dependencies.** A static client that runs in any modern browser. Nothing to build. Nothing to deploy except files.

**Explicit trust model.** The `trusted_issuers.json` file is human-readable and auditable. For production deployments, the README recommends replacing it with a signed, remotely-fetched trust list with key rotation — because a static local file is a starting point, not a security guarantee.

---

## What was hard

**PDF extraction and QR parsing** — the JS library ecosystem for in-browser PDF manipulation is messy. Most options either bloat the bundle or break on edge-case PDFs. Took iteration to find a lightweight path that handled real academic documents.

**The trust model tradeoff** — a locally curated trust list is usable but not cryptographically robust. The documented design acknowledges this explicitly and points toward the right production path (signed remote lists) rather than pretending the demo model is production-ready.

---

## Screens

| Scan PDF | Verified result |
|:---:|:---:|
| ![Scan UI](./assets/screens/scan.png) | ![Verified result](./assets/screens/result.png) |

| Tampered result | Info pages |
|:---:|:---:|
| ![Tampered result](./assets/screens/tampered.png) | ![Info pages](./assets/screens/info.png) |

---

## Getting started

**Prerequisites:** a modern browser (Chrome / Edge / Firefox). That's it.

```bash
# Clone the repo
git clone https://github.com/udaycodespace/credify-verify.git
cd credify-verify

# Serve locally (required — browser file:// restrictions apply)
python -m http.server 8000

# Open
# http://localhost:8000
```

No install step. No package manager. No build pipeline.

---

## Project structure

```
credify-verify/
├── index.html
├── README.md
├── TEMPLATE.md
├── LICENSE
├── LICENSE-FAQ.md
├── CONTRIBUTING.md
├── assets/
│   ├── css/
│   └── screens/
├── data/
│   └── trusted_issuers.json       ← trust boundary lives here
├── js/
│   └── app.js
└── pages/
    ├── scan.html
    ├── result.html
    └── tampered.html
```

---

## Troubleshooting

**"Unknown issuer" on a valid credential**
The issuer isn't in `data/trusted_issuers.json`. Add their public key and metadata, or contact the issuing institution's admin to get it added.

**Browser blocks file APIs**
Open the app through a local HTTP server, not by double-clicking `index.html`. See [Getting started](#getting-started).

---

## Known gaps

- RSA signature verification is not implemented — anchor/hash checks only. Planned for next milestone.
- No automated test suite for the static client.
- Mobile UX and accessibility are not fully optimised yet.

These are tracked openly. This is a verification client in active development, not a finished product.

---

## Roadmap

- [ ] Client-side RSA signature verification using issuer public keys
- [ ] Signed, hosted trust lists with key rotation support
- [ ] End-to-end test coverage + CI → GitHub Pages deployment pipeline

---

## Contributing

Contributions are controlled. Read `CONTRIBUTING.md` first, then reach out before submitting any code changes.

- GitHub: [udaycodespace](https://github.com/udaycodespace)
- LinkedIn: [somapuram-uday](https://www.linkedin.com/in/somapuram-uday/)

---

## Status

![active](https://img.shields.io/badge/status-active-brightgreen?style=flat-square) Actively maintained — demo and verification client for Credify v2.

---

## License

Proprietary — all rights reserved. See [LICENSE](./LICENSE).

For licensing or permission requests: [LinkedIn](https://www.linkedin.com/in/somapuram-uday/)

---

<div align="center">
  <sub>
    Built by <a href="https://github.com/udaycodespace">Somapuram Uday</a>
    &nbsp;·&nbsp;
    2026
    &nbsp;·&nbsp;
    Verification client for Credify v2
  </sub>
</div>