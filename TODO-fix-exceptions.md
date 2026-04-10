# TODO Steps: Fix broad except Exception clauses

## Plan Breakdown (Approved: All production files, commit to error-handling-akshat/PR #14):
1. [ ] Edit talkdoc_secure_pm/auditor/cache.py (sqlite3.Error, OSError)
2. [ ] Edit talkdoc_secure_pm/auditor/ai_agent.py (OSError, UnicodeDecodeError)
3. [ ] Edit talkdoc_secure_pm/managers/npm_manager.py (subprocess.CalledProcessError, OSError, shutil.Error)
4. [ ] Edit talkdoc_secure_pm/sbom.py (OSError/UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError)
5. [ ] Edit talkdoc_secure_pm/managers/pip_manager.py (subprocess.CalledProcessError, shutil.Error, OSError)
6. [ ] Edit talkdoc_secure_pm/managers/cargo_manager.py (requests.RequestException, OSError)
7. [ ] git add . && git commit -m "fix: replace broad except Exception with specific handlers"
8. [ ] git push
9. [ ] pytest
10. [ ] attempt_completion

**Status: Starting edits on current branch error-handling-akshat.**

