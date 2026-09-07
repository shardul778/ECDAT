# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool

**SIH PS26164** | Cryptographic Asset Discovery, Risk Scoring & Post-Quantum Readiness

🔗 **Live Demo:** [ecdat-eight.vercel.app](https://ecdat-eight.vercel.app)

ECDAT scans a codebase for weak or quantum-vulnerable cryptography, cross-validates every finding through two independent detection engines, and turns raw results into a prioritized, standards-compliant report — instead of a flat list of matches.

---

## The Problem

Most organizations have no visibility into where they use weak cryptography (MD5, SHA1, DES, RC4) or classically-secure-but-quantum-vulnerable cryptography (RSA, ECC). This matters today because of **"Harvest Now, Decrypt Later"** — encrypted data can be stolen now and decrypted later once quantum computers mature. Existing crypto-discovery tools (including official ones like IBM's CBOMKit and CycloneDX's own cdxgen) have been shown in recent research to disagree with each other on identical codebases and to treat every finding with the same flat severity, regardless of real-world exposure.

ECDAT is built to close both of those specific, documented gaps.

---

## Core Features

**1. Dual-Engine Cross-Validation**
Every file is scanned independently by Semgrep (pattern-based) and a Python AST checker (structure-based). A finding is only marked **High confidence** if both engines agree; if only one detects it, it's marked **Medium confidence**.

**2. Exposure-Aware Risk Scoring**
Findings are tagged by real-world exposure using file-path analysis (`auth/`, `login/`, `payment/`) and AST-based call-graph tracing to detect both direct and indirect exposure through route handlers (e.g. `@app.post`). A weak hash in a public login path is scored very differently from the same hash in an internal test file.

**3. Explainable Risk Engine**
Each finding gets a High/Medium/Low label, a continuous 0–100 numeric score with a visible formula breakdown, and a Mosca-style time-horizon tag (Immediate / PQC migration / Monitor). No black-box scoring.

**4. Standards-Compliant CBOM Export**
Findings are exported as a CycloneDX v1.6 Cryptography Bill of Materials, using the official `cryptographic-asset` component schema.

**5. Dependency (SCA) Scanning**
Parses dependency manifests (`requirements.txt`, `package.json`) and flags libraries with known weak-crypto issues (e.g. unmaintained `pycrypto`).

**6. Scan Any Public GitHub Repository**
Beyond the bundled sample repo, users can paste any public GitHub URL — ECDAT clones it, runs the full pipeline, and cleans up automatically afterward.

---

## Architecture / Pipeline

```
Source Code + Dependency Manifests (sample repo OR any public GitHub URL)
              │
              ▼
   ┌─────────────────────────────┐
   │      DISCOVERY LAYER         │
   │  Semgrep (YAML rules)        │
   │  Python AST checker          │
   │  SCA dependency scanner      │
   └──────────────┬───────────────┘
                  ▼
   ┌─────────────────────────────┐
   │   CONFIDENCE MATCHING        │
   │  Both engines agree → High   │
   │  One engine only    → Medium │
   └──────────────┬───────────────┘
                  ▼
   ┌─────────────────────────────┐
   │   EXPOSURE TAGGING           │
   │  Path keywords → Critical    │
   │  Direct/indirect route       │
   │  exposure → Externally       │
   │  Exposed (via AST call-graph)│
   │  Test files → Test-only      │
   │  Else → Internal-only        │
   └──────────────┬───────────────┘
                  ▼
   ┌─────────────────────────────┐
   │   RISK SCORING ENGINE        │
   │  High/Medium/Low label       │
   │  + 0-100 numeric score       │
   │  + Mosca time-horizon        │
   └──────────────┬───────────────┘
                  ▼
   ┌─────────────────────────────┐
   │   CBOM EXPORT (CycloneDX 1.6)│
   └──────────────┬───────────────┘
                  ▼
   ┌─────────────────────────────┐
   │   REACT DASHBOARD             │
   │  Findings table + risk chart │
   │  Filter by risk level        │
   │  Per-finding detail view     │
   │  with source code snippet    │
   └───────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Code scanner (primary) | Semgrep, custom YAML rules |
| Code scanner (cross-validator) | Python `ast` module |
| Dependency scanner | Custom SCA parser (requirements.txt / package.json) |
| Backend | FastAPI |
| Database | SQLite |
| Frontend | React (Vite) |
| CBOM export | CycloneDX v1.6 JSON (`cryptographic-asset` schema) |
| Deployment | Backend on Render, Frontend on Vercel |

---

## Known Limitations

This is a hackathon prototype, scoped deliberately:

- **Language coverage:** Python only — no Java/JavaScript/Go support yet
- **Live network/TLS scanning:** not implemented in this build
- **GitHub scanning:** limited to public repositories under 50MB, with a 60-second clone timeout
- **Exposure tagging:** relies on path-keyword and call-graph heuristics, not a full data-flow analysis
- **CBOM export:** structured to the CycloneDX v1.6 schema, but not validated against every optional field in the full spec

---

## Testing

The project has an automated `pytest` suite covering scanner accuracy, confidence matching, exposure tagging, risk scoring, the scan API, the GitHub-URL scan feature, and edge cases (engine disagreement, indirect route exposure, false-positive resistance, graceful handling of malformed/empty files). All tests currently pass.

---

## Running Locally

**Backend**
```
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

**Frontend**
```
cd frontend
npm install
npm run dev
```

---

## Why This Approach

Existing cryptographic discovery tools have two documented weaknesses: they rely on a single detection engine (shown to produce inconsistent results across tools), and they don't weight risk by real-world exposure. ECDAT's cross-validation and exposure-tagging layers exist specifically to address those two gaps.
