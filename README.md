# secure-pm

`secure-pm` audits package source code with AI before installation to mitigate supply chain attacks. Supports `pip`, `npm`, and `cargo`.

**Note:** This is an MVP with ongoing improvements to pinning and caching (v0.2.0+).

## Installation
```bash
cd /path/to/secure-pm
pip install -e .
# or use the secure-pm itself after initial setup
```

## Setup
Set your AI provider and key. Defaults updated for 2026:
```bash
export AI_PROVIDER="grok" # Supports: grok, openai, gemini, ollama
export AI_MODEL="grok-beta" 
export XAI_API_KEY="your_key"
# For OpenAI: export OPENAI_API_KEY=...
```
See `talkdoc_secure_pm/auditor/ai_agent.py` for provider details.

## Usage
```bash
secure-pm install pip <package>     # audits then installs
secure-pm install npm <package>
secure-pm install cargo <package>
secure-pm audit-all .               # batch audit of requirements/package.json/Cargo.toml
```

**Limitations (technical debt being addressed):** 
- Pinning is improved for pip but still MVP for npm/cargo.
- AI calls can be slow/expensive; caching planned.

## License
This project is open-source and available under the [BSD 3-Clause License](LICENSE).
