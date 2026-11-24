# CLAUDE.md

## Project
Python client library for x64dbg Automate — RPC-based automation of x64dbg debugger via ZMQ/msgpack.

## Commands
```powershell
poetry install --extras mcp --with dev   # install deps (mcp extra + dev tools)
python -m pytest --bitness 64   # run tests (live ones need x64dbg + plugin, see Test configuration)
python -m mkdocs serve      # docs dev server
```

## Test configuration
Machine-specific paths live in `tests/local.env` (gitignored; template `tests/local.env.example`), never in checked-in files. Precedence: pytest option > env var > `tests/local.env`.
- `--bitness 32|64` / `TEST_BITNESS` — debugger bitness (default: 64)
- `X64DBG_RELEASE_DIR` — x64dbg `release` dir; exe derived per bitness (`x64\x64dbg.exe` / `x32\x32dbg.exe`)
- `--x64dbg-path` / `X64DBG_PATH` — exact executable, overrides the release dir
- `REMOTE_HOST` / `REMOTE_REQ_PORT` / `REMOTE_PUB_PORT` — remote functional test (`tests/run_functional_tests.ps1`)

Live tests skip (not fail) when x64dbg isn't configured; the pytest header shows the resolved bitness and path.

## MCP Server
An MCP (Model Context Protocol) server is included, exposing x64dbg automation as MCP tools for LLM-based agents (e.g. Claude Code).

- **Module**: `x64dbg_automate.mcp_server` (`mcp_server.py`)
- **Entry point**: `x64dbg-automate-mcp` (console script)
- **Install**: `pip install x64dbg_automate[mcp]` (adds the `mcp` extra dependency)
- **Run**: `x64dbg-automate-mcp` (stdio transport by default)
- **Pattern**: Global `_client` managed via `start_session`/`connect_to_session`/`disconnect`/`terminate_session` tools; all other tools call `_require_client()`.

## Architecture
Mixin chain: `XAutoClientBase` → `XAutoCommandsMixin` (low-level RPC) → `XAutoHighLevelCommandAbstractionMixin` (convenience methods) → `X64DbgClient` (also mixes in `DebugEventQueueMixin`).

ZMQ REQ/REP for sync commands, PUB/SUB for async events. Msgpack serialization. Thread-safe via `_req_lock`.

## Releasing

Never `poetry publish` locally. PyPI uploads go through `.github/workflows/release.yml` (trusted publishing, `pypi` environment):

1. Bump `version` in `pyproject.toml`. If the wire protocol changed, bump `COMPAT_VERSION` in `x64dbg_automate/__init__.py` to match the plugin's `XAUTO_COMPAT_VERSION`.
2. Tag and push: `git tag v<version>-<codename>` then `git push origin v<version>-<codename>`. CI fails if the tag's version or codename doesn't match the code.
3. CI runs the offline tests, builds wheel + sdist, and creates a **draft** GitHub release with both attached. Edit the notes on the draft (auto-generated notes miss direct pushes to main).
4. Smoke test the draft's wheel with the plugin (see the plugin repo's CLAUDE.md).
5. **Publishing the draft release uploads its attached wheel + sdist to PyPI.** That's the only path to PyPI. PyPI versions are permanent (can't overwrite, only yank), so publish only after the smoke test.

Every push to main and every PR also runs the offline tests + build (live x64dbg tests skip in CI).

## Git

Keep all commits authored solely as the repo owner (Darius Houle) — do not add `Co-Authored-By` or other attribution trailers.

Do not add Claude/AI attribution to any GitHub text on this project — commit messages, PR titles and descriptions, PR/issue comments, and issue bodies. This includes the `🤖 Generated with Claude Code` footer and any `Co-Authored-By: Claude` line. All such text must read as authored solely by the repo owner.

## Conventions
- Type hints everywhere, modern union syntax (`X | None` not `Optional[X]`)
- Pydantic models for data structures (`models.py`)
- Google-style docstrings (Args/Returns/Raises)
- snake_case functions, PascalCase classes, UPPER_CASE constants
- Private methods prefixed with `_`
- Enums use `StrEnum`/`IntEnum`
- No unnecessary abstractions — keep it direct