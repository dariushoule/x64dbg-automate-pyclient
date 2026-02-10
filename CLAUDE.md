# CLAUDE.md

## Project
Python client library for x64dbg Automate — RPC-based automation of x64dbg debugger via ZMQ/msgpack.

## Commands
```powershell
poetry install              # install deps
python -m pytest            # run tests (requires running x64dbg with plugin)
python -m mkdocs serve      # docs dev server
```

## Test env vars
- `TEST_BITNESS` — 32 or 64 (default: 64)
- `X64DBG_PATH` — path to x64dbg executable

## Architecture
Mixin chain: `XAutoClientBase` → `XAutoCommandsMixin` (low-level RPC) → `XAutoHighLevelCommandAbstractionMixin` (convenience methods) → `X64DbgClient` (also mixes in `DebugEventQueueMixin`).

ZMQ REQ/REP for sync commands, PUB/SUB for async events. Msgpack serialization. Thread-safe via `_req_lock`.

## Conventions
- Type hints everywhere, modern union syntax (`X | None` not `Optional[X]`)
- Pydantic models for data structures (`models.py`)
- Google-style docstrings (Args/Returns/Raises)
- snake_case functions, PascalCase classes, UPPER_CASE constants
- Private methods prefixed with `_`
- Enums use `StrEnum`/`IntEnum`
- No unnecessary abstractions — keep it direct