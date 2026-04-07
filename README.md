# secure-pm

`secure-pm` audits package source code with AI before installation to mitigate supply chain attacks. Supports `pip`, `npm`, and `cargo`.

**Note:** This is an MVP with ongoing improvements to pinning and caching (v0.2.0+).

## Installation (Bootstrap Security)
The initial install of secure-pm itself uses normal `pip` (chicken-and-egg problem). We mitigate this with pre-audited pinned hashes:

```bash
cd /path/to/secure-pm
pip install -r requirements-secure.txt --require-hashes
pip install -e .
```

`requirements-secure.txt` contains audited pins for core deps (requests, openai, rich, etc.). Regenerate with `python -c "from talkdoc_secure_pm.managers.pip_manager import PipManager; ..." ` if needed.

## Setup
Set your AI provider and key. Defaults for 2026:
```bash
export AI_PROVIDER="grok" # Supports: grok, openai, gemini, ollama
export AI_MODEL="grok-4-1-fast-reasoning" 
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
