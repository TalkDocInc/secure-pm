# Secure-PM Technical Debt Refactoring TODO

Status: [0/18] Complete

## 1. GitHub Setup ✅
- [x] Init git repo, commit all files, push to https://github.com/TalkDocInc/secure-pm main
- [ ] Create GitHub issues for all debt items (10-15 issues)

## 2. Project Modernization [0/5]
- [ ] Create pyproject.toml (hatchling/PDM, dev deps: ruff/mypy/pytest-cov/pre-commit)
- [ ] Migrate from setup.py to pyproject.toml build-system
- [ ] Add ruff.toml (lint rules)
- [ ] Add .pre-commit-config.yaml + pre-commit install
- [ ] GitHub workflows: ci.yml (lint/test), dependabot.yml

## 3. Code Quality [0/6]
- [ ] Replace 100+ console.print/print with structured logging (loguru) + --verbose CLI flag
- [ ] Add full type hints (mypy --strict) to all .py files
- [ ] Fix broad except: → specific + propagate critical errors
- [ ] Extract shared utils for manager duplication (pin_dependency, extract logic)
- [ ] Update outdated docs (MD5 → SHA256 in tests)
- [ ] Add rate limiting to AI/cache calls

## 4. Testing [0/3]
- [ ] pyproject.toml [tool:pytest]: cov, markers; run pytest --cov=src --cov-report=html → 90%
- [ ] Add integration tests for full workflows (install/audit-all)
- [ ] Parametrize manager tests across ecosystems

## 5. Docs/Security/Polish [0/4]
- [ ] CONTRIBUTING.md, CHANGELOG.md, API docs (mkdocs)
- [ ] Improve AI prompt (few-shot examples)
- [ ] Add Dependabot/GHGHA
- [ ] Bootstrap script improvements (generate_secure_reqs.py → pinned + lockfile)

**Next Step:** After each completion, update this file and run `git commit -m 'TODO: step X' && git push`

