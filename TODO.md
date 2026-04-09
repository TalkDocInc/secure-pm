# Task: Fix CI hash-verify failure for requirements-secure.txt (missing transitive dep pins)

## Approved Plan Steps:
1. [ ] Improve generate_secure_reqs.py / PipManager to download full transitive dep tree reliably.
2. [ ] Edit files as needed (generate_secure_reqs.py, pip_manager.py).
3. [ ] Run `python generate_secure_reqs.py` to regenerate complete requirements-secure.txt.
4. [ ] Verify: `pip install -r requirements-secure.txt --require-hashes --dry-run`.
5. [ ] Run tests: `python -m pytest tests/`.
6. [ ] Update .github/workflows/ci.yml if Python version mismatches found.
7. [ ] Commit changes to fix CI.

**Next: Implement step 1 - analyze and edit generate_secure_reqs.py for full dep download.**

