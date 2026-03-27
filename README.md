# secure-pm

`secure-pm` replaces default package managers (`pip`, `npm`, `cargo`) to prevent supply chain attacks. It intercepts installations, runs the source code through an AI auditor (Grok, OpenAI, Gemini, or Ollama), and only installs if the code is safe.

## Installation
```bash
git clone https://github.com/TalkDocInc/secure-pm.git
cd secure-pm
pip install -e .
```

## Setup
By default, `secure-pm` uses Grok (`grok-4-1-fast-reasoning`). Set your key or change providers/models:
```bash
export AI_PROVIDER="grok" # Supports: openai, gemini, ollama
export AI_MODEL="grok-4-1-fast-reasoning" # Set to override the default model choice natively
export XAI_API_KEY="your_key"
```

## Usage
Audit and install securely:
- **Pip:** `secure-pm install pip <package>`
- **NPM:** `secure-pm install npm <package>`
- **Cargo:** `secure-pm install cargo <package>`

Audit an entire repository's lockfiles (batch security checks):
`secure-pm audit-all .`
