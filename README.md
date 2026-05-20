<div align="center">

<br/>

```txt
 ██████╗██████╗ ███████╗██████╗ ██╗███████╗██╗   ██╗
██╔════╝██╔══██╗██╔════╝██╔══██╗██║██╔════╝╚██╗ ██╔╝
██║     ██████╔╝█████╗  ██║  ██║██║█████╗   ╚████╔╝
██║     ██╔══██╗██╔══╝  ██║  ██║██║██╔══╝    ╚██╔╝
╚██████╗██║  ██║███████╗██████╔╝██║██║        ██║
 ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝        ╚═╝
```

```txt
██╗   ██╗███████╗██████╗ ██╗███████╗██╗   ██╗
██║   ██║██╔════╝██╔══██╗██║██╔════╝╚██╗ ██╔╝
██║   ██║█████╗  ██████╔╝██║█████╗   ╚████╔╝
╚██╗ ██╔╝██╔══╝  ██╔══██╗██║██╔══╝    ╚██╔╝
 ╚████╔╝ ███████╗██║  ██║██║██║        ██║
  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝
```

### Independent Offline Verification Client for Academic Credentials

<br/>

[![Status](https://img.shields.io/badge/status-active-brightgreen?style=for-the-badge)](https://github.com/udaycodespace/credify-verify)
[![License](https://img.shields.io/badge/license-proprietary-red?style=for-the-badge)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/udaycodespace/credify-verify?style=for-the-badge)](https://github.com/udaycodespace/credify-verify)

<br/>

[![HTML5](https://img.shields.io/badge/HTML5-Markup-E34F26?style=for-the-badge&logo=html5&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/HTML)
[![CSS3](https://img.shields.io/badge/CSS3-Styling-1572B6?style=for-the-badge&logo=css3&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/CSS)
[![JavaScript](https://img.shields.io/badge/JavaScript-Engine-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![GitHub Pages](https://img.shields.io/badge/Deploy-GitHub_Pages-222222?style=for-the-badge&logo=githubpages&logoColor=white)](https://pages.github.com/)

<br/>

> **Offline Verification · Deterministic Validation · Independent Trust Boundary**

> Browser-native academic credential verification engine designed for offline validation, tamper detection, and issuer trust verification without backend dependency.

<br/>

[Live Client](https://udaycodespace.github.io/credify-verify/) •
[Architecture](#-system-architecture) •
[Verification Workflow](#-verification-workflow) •
[Deployment](#-deployment) •
[Roadmap](#-development-roadmap)

---

</div>

# 📘 Overview

> [!NOTE]
> Credify Verify is an independent verification client engineered to validate academic credentials entirely inside the browser without relying on external APIs, centralized infrastructure, or runtime backend systems.

Traditional verification systems commonly fail under:
- backend downtime
- API dependency
- centralized verification bottlenecks
- institution-side availability issues
- network instability

Credify Verify removes those dependencies completely.

The verification engine:
- extracts credential proofs directly in-browser
- validates issuer trust locally
- checks credential integrity deterministically
- works offline for primary verification flows
- preserves an isolated trust boundary

---

# 🎯 Verification Philosophy

> [!IMPORTANT]
> A verifier that depends completely on an external server is not truly independent verification.
>
> Credify Verify shifts the verification trust boundary directly to the client runtime.

---

# ✨ Core Capabilities

<table>
<tr>

<td width="33%" valign="top">

## 🔍 Verification Engine

- Client-side PDF parsing
- QR payload extraction
- Deterministic proof validation
- Offline verification flows
- Tamper detection engine
- Browser-native execution

</td>

<td width="33%" valign="top">

## 🔐 Trust Model

- Local issuer trust registry
- Explicit trust boundaries
- Zero backend dependency
- No runtime authentication
- Independent validation logic
- Offline-first verification

</td>

<td width="33%" valign="top">

## ⚡ Runtime Design

- Zero framework overhead
- No package managers
- No external APIs
- Static deployment architecture
- Portable browser execution
- Minimal runtime complexity

</td>

</tr>
</table>

---

# 🏗️ System Architecture

> [!IMPORTANT]
> The verification engine is intentionally isolated from the credential issuance platform.
>
> Verification must remain operational even if the issuing infrastructure becomes unavailable.

---

## 🔄 Verification Workflow

```mermaid
flowchart TD

A[Upload Academic PDF]
--> B[Client-side Extraction]

B --> C[QR / Metadata Parsing]

C --> D[Issuer Trust Validation]

D --> E[Anchor Verification]

E --> F{Validation Result}

F -->|Valid| G[Verified]

F -->|Tampered| H[Tampered]
```

---

## 🌐 Trust Boundary Model

```mermaid
flowchart TD

User --> Browser

Browser --> PDFExtraction
Browser --> LocalRegistry

PDFExtraction --> ValidationEngine

LocalRegistry --> ValidationEngine

ValidationEngine --> VerificationResult
```

---

## 🔐 Verification Isolation Model

```mermaid
flowchart TD

A[Credify Issuance Platform]
B[Blockchain Network]
C[Credify Verify Client]

A -. Independent Boundary .-> C
B -. Independent Boundary .-> C

C --> D[Offline Verification Runtime]
```

---

# 🧠 Architecture Principles

<table>
<tr>
<th>Principle</th>
<th>Why It Exists</th>
</tr>

<tr>
<td><strong>Offline Verification</strong></td>
<td>Verification must continue functioning without internet or backend availability.</td>
</tr>

<tr>
<td><strong>Independent Trust Boundary</strong></td>
<td>Validation logic remains operational independently from issuance infrastructure.</td>
</tr>

<tr>
<td><strong>Deterministic Validation</strong></td>
<td>Verification results remain predictable, explainable, and reproducible.</td>
</tr>

<tr>
<td><strong>Zero Dependency Runtime</strong></td>
<td>Reducing runtime complexity improves portability and maintainability.</td>
</tr>

<tr>
<td><strong>Explicit Trust Mapping</strong></td>
<td>Issuer trust relationships remain human-readable and auditable.</td>
</tr>

</table>

---

# ⚙️ Verification Workflow

## 📌 End-to-End Validation Lifecycle

```mermaid
sequenceDiagram

participant User
participant Browser
participant Registry
participant Validator

User->>Browser: Upload PDF

Browser->>Validator: Extract proof payload

Validator->>Registry: Validate issuer trust

Validator-->>Browser: Verification verdict

Browser-->>User: Verified / Tampered
```

---

# 🔬 Core Mechanics

<table>
<tr>

<td width="50%" valign="top">

## 📄 Client-Side Extraction

- Parses academic PDFs directly in-memory
- Extracts embedded metadata
- Detects QR payloads
- Avoids external processing pipelines
- Preserves local-only execution

</td>

<td width="50%" valign="top">

## 🔐 Deterministic Validation

- Validates issuer identity
- Checks trust registry mappings
- Produces binary verification verdicts
- Detects tampered payloads
- Preserves audit-friendly verification

</td>

</tr>
</table>

---

# 🧩 Technical Stack

<div align="center">

## Frontend

| Technology | Purpose |
|---|---|
| HTML5 | Structure & rendering |
| CSS3 | Interface styling |
| Vanilla JavaScript | Verification engine |
| Browser APIs | File extraction & parsing |

---

## Runtime Architecture

| Layer | Decision |
|---|---|
| Backend | None |
| Database | None |
| Authentication | None |
| APIs | None |
| Deployment | Static hosting |

---

## Verification Infrastructure

| Component | Purpose |
|---|---|
| `trusted_issuers.json` | Local trust registry |
| QR Payloads | Verification anchors |
| Browser Memory Runtime | Local verification |
| Static Assets | Offline-first execution |

</div>

---

# ⚠️ Engineering Challenges

## 📄 In-Browser PDF Parsing

> [!WARNING]
> Most browser-side PDF tooling introduces unnecessary runtime weight and inconsistent parsing behavior across edge-case academic documents.

### Engineering Decisions

- lightweight extraction pipeline
- targeted academic document parsing
- reduced dependency footprint
- minimized runtime complexity
- browser-native execution

---

## 🔐 Trust Model Tradeoffs

> [!NOTE]
> A local trust registry is operationally simple but does not provide complete cryptographic trust finality.

### Future Direction

- signed trust registries
- issuer key rotation
- remote signature validation
- distributed trust synchronization
- enterprise-grade verification controls

---

# 🖼️ Interface Overview

## 📄 Scan Interface

<p align="center">
  <img src="./assets/screens/scan.png" width="100%" />
</p>

---

## ✅ Verification Success

<p align="center">
  <img src="./assets/screens/result.png" width="100%" />
</p>

---

## ⚠️ Tampered Detection

<p align="center">
  <img src="./assets/screens/tampered.png" width="100%" />
</p>

---

## 📘 Information & Documentation

<p align="center">
  <img src="./assets/screens/info.png" width="100%" />
</p>

---

# 🚀 Deployment

> [!TIP]
> Since the system is fully static and dependency-free, deployment can be performed on nearly any static hosting provider.

---

## Requirements

- Chrome
- Edge
- Firefox
- Modern browser with File API support

---

## Local Development

```bash
# Clone repository
git clone https://github.com/udaycodespace/credify-verify.git

cd credify-verify

# Start local server
python -m http.server 8000
```

---

## Application Endpoint

```txt
http://localhost:8000
```

---

# 📂 Project Structure

```text
credify-verify/
│
├── index.html
│
├── data/
│   └── trusted_issuers.json
│
├── js/
│   └── app.js
│
├── pages/
│   ├── scan.html
│   ├── result.html
│   └── tampered.html
│
└── assets/
```

---

# 🧪 Validation Scenarios

## Supported Flows

- Offline PDF verification
- QR proof validation
- Issuer trust matching
- Tampered credential detection
- Air-gapped institutional verification

---

## Failure Detection

- Unknown issuer
- Invalid proof payload
- Missing trust mapping
- Corrupted metadata
- Modified credential structure

---

# 🛠️ Troubleshooting

> [!WARNING]
> Browser security restrictions can block local file access if the project is opened directly through the filesystem.

---

## Common Issues

### Unknown Issuer

The issuer metadata or public key is missing from:

```txt
data/trusted_issuers.json
```

---

### Browser Blocking APIs

Never open:

```txt
index.html
```

directly through:

```txt
file://
```

Always use a local HTTP server.

---

# 🛣️ Development Roadmap

## Planned Enhancements

- Client-side RSA signature verification
- Signed issuer trust registries
- Dynamic issuer key rotation
- End-to-end testing pipeline
- GitHub Pages CI/CD integration
- Enhanced tamper heuristics
- Blockchain anchor synchronization

---

# 👥 Governance & Access

> [!IMPORTANT]
> Structural modifications affecting the trust model or validation engine require architectural review before integration.

---

## Contribution Model

- Architecture-first review process
- Validation-focused contributions
- Controlled trust-boundary modifications
- Deterministic verification guarantees

---

# 👨‍💻 System Architect

<div align="center">

<table>
<tr>

<td align="center">

<a href="https://github.com/udaycodespace">
<img src="https://github.com/udaycodespace.png" width="110px;" alt="udaycodespace"/>

### Somapuram Uday
</a>

`Architecture`
`Verification Engine`
`Frontend`
`Trust Model`

💻 ⚡ 🔐

</td>

</tr>
</table>

</div>

---

# 📜 License

> [!NOTE]
> Proprietary — All rights reserved.

See:

```txt
LICENSE
```

for usage restrictions and ownership details.

---

<div align="center">

<br/>

**Built as an independent verification boundary for the Credify ecosystem**

<br/>

*Offline-first · Deterministic · Dependency-free*

<br/>

</div>
