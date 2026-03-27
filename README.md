# secure-pm

A security-first package manager that audits source code with AI before installation to prevent supply chain attacks. Supports **pip**, **npm**, and **cargo**.

## How it works

1. **Download** — fetches the package and its full transitive dependency tree
2. **Verify** — checks upstream provenance (PyPI digests, npm signatures, crates.io checksums)
3. **Static scan** — fast regex prefilter catches 25+ known attack patterns (base64 eval, env exfiltration, shell injection, ctypes abuse, etc.)
4. **AI audit** — sends source code to an LLM for deep security review with prompt-injection resistance
5. **Pin** — locks versions with SHA-256 hashes (`requirements.txt`, `package-lock.secure.json`, `Cargo.lock.secure.json`)
6. **Install** — only installs code that passed all checks

Packages are **rejected by default** when no AI provider is configured (fail-closed).

## Install

```bash
bash install.sh
# or manually:
pip install -r requirements-secure.txt --require-hashes
pip install -e .
```

The bootstrap uses pre-audited, hash-pinned dependencies. Hash verification failures are treated as errors, not warnings.

## Setup

```bash
export AI_PROVIDER="grok"               # grok | openai | gemini | ollama
export XAI_API_KEY="your_key"           # or OPENAI_API_KEY, GEMINI_API_KEY
# Optional: export AI_MODEL="grok-4-1-fast-reasoning"
```

## Usage

```bash
# Install a package (audit → verify → pin → install)
secure-pm install pip requests
secure-pm install npm express
secure-pm install cargo serde

# Batch audit all dependencies in a project
secure-pm audit-all .

# Generate a CycloneDX SBOM from project manifests
secure-pm sbom . -o sbom.cdx.json

# Verify package provenance without installing
secure-pm verify pip requests
secure-pm verify cargo serde@1.0

# Manage the persistent audit cache
secure-pm cache stats
secure-pm cache prune
secure-pm cache clear
```

## Security features

| Layer | What it does |
|---|---|
| **Safe extraction** | Blocks path traversal, symlink escapes, and zip bombs in all archives |
| **Static prefilter** | 25+ regex patterns for known malicious indicators across `.py`, `.js`, `.sh`, `.rs`, `.ts` files |
| **AI audit** | Multi-provider LLM review (Grok, OpenAI, Gemini, Ollama) with prompt-injection hardening |
| **Provenance verification** | Validates SHA-256 against PyPI/crates.io; npm registry signature checks |
| **Hash pinning** | SHA-256 pinning for all three ecosystems |
| **Transitive auditing** | Full dependency tree downloaded and audited, including transitive deps for pip and cargo |
| **Fail-closed** | No API key = automatic rejection (not silent approval) |
| **Persistent cache** | SQLite cache at `~/.cache/secure-pm/` with 30-day expiry avoids redundant AI calls |
| **SBOM generation** | CycloneDX 1.5 JSON output with purl, hashes, and audit status |
| **NPM safety** | Uses `--ignore-scripts` during download to prevent pre-audit code execution |
| **Cargo safety** | Installs from local audited path (`cargo install --path`) instead of re-fetching from registry |

## Architecture

```
talkdoc_secure_pm/
├── cli.py                  # CLI entry point (install, audit-all, sbom, verify, cache)
├── sbom.py                 # CycloneDX SBOM generation
├── signature_verifier.py   # PyPI/npm/crates.io provenance checks
├── safe_extract.py         # Path traversal and zip bomb protection
├── batch_auditor.py        # Multi-ecosystem project scanning
├── auditor/
│   ├── ai_agent.py         # Static prefilter + AI audit engine
│   └── cache.py            # Persistent SQLite audit cache
└── managers/
    ├── base_manager.py     # Abstract install workflow
    ├── pip_manager.py      # Python packages
    ├── npm_manager.py      # Node.js packages
    └── cargo_manager.py    # Rust crates
```

## CI/CD

GitHub Actions runs on every push and PR:
- **Tests** — pytest on Python 3.12 and 3.13
- **Lint** — ruff across all source
- **Hash verify** — validates bootstrap dependency integrity

## License

[BSD 3-Clause License](LICENSE)
