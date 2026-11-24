"""Shared test configuration.

Machine-specific settings never live in this file. They resolve, highest
precedence first, from:

1. pytest options: ``--bitness 32|64`` and ``--x64dbg-path <exe>``
2. environment variables: ``TEST_BITNESS``, ``X64DBG_PATH``, ``X64DBG_RELEASE_DIR``
3. ``tests/local.env`` (gitignored; copy ``tests/local.env.example`` to start)

``X64DBG_RELEASE_DIR`` is the x64dbg ``release`` directory (the one holding
``x32/`` and ``x64/``); the debugger path is derived from it per bitness, so
switching legs is just ``pytest --bitness 32``. ``X64DBG_PATH`` pins an exact
executable instead.

Tests that need a live debugger are skipped, not failed, when no x64dbg is
configured, so the offline suites run on a fresh checkout.
"""
import os
from pathlib import Path

import pytest

from x64dbg_automate import X64DbgClient

LOCAL_ENV_FILE = Path(__file__).parent / "local.env"


def _read_local_env(path: Path) -> dict[str, str]:
    """Parse KEY=VALUE lines (``#`` comments allowed). Kept out of os.environ on purpose:
    some tests assert on X64DBG_PATH env handling and must not see local settings."""
    if not path.is_file():
        return {}
    settings = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        settings[key.strip()] = value.strip().strip('"').strip("'")
    return settings


_LOCAL = _read_local_env(LOCAL_ENV_FILE)


def _setting(key: str, override: str | None = None) -> str:
    """CLI override > real env var > tests/local.env > empty."""
    for value in (override, os.getenv(key), _LOCAL.get(key)):
        if value and value.strip():
            return value.strip()
    return ""


def _resolve(bitness_override: str | None = None, path_override: str | None = None) -> tuple[int, str | None]:
    bitness = int(_setting("TEST_BITNESS", bitness_override) or "64")
    if bitness not in (32, 64):
        raise pytest.UsageError(f"TEST_BITNESS must be 32 or 64, got {bitness}")
    explicit = _setting("X64DBG_PATH", path_override)
    if explicit:
        return bitness, explicit
    release_dir = _setting("X64DBG_RELEASE_DIR")
    if release_dir:
        return bitness, str(Path(release_dir) / f"x{bitness}" / f"x{bitness}dbg.exe")
    return bitness, None


TEST_BITNESS, X64DBG_PATH = _resolve()


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("x64dbg-automate")
    group.addoption("--bitness", choices=("32", "64"), help="Debugger bitness to test (overrides TEST_BITNESS)")
    group.addoption("--x64dbg-path", help="Exact x64dbg/x32dbg executable (overrides X64DBG_PATH / X64DBG_RELEASE_DIR)")


def pytest_configure(config: pytest.Config) -> None:
    # Runs before test modules are collected, so their `from tests.conftest import ...`
    # sees the CLI overrides.
    global TEST_BITNESS, X64DBG_PATH
    TEST_BITNESS, X64DBG_PATH = _resolve(config.getoption("bitness"), config.getoption("x64dbg_path"))


def pytest_report_header(config: pytest.Config) -> str:
    return f"x64dbg-automate: bitness={TEST_BITNESS} x64dbg={X64DBG_PATH or '<not configured: live tests will skip>'}"


@pytest.fixture
def x64dbg_path() -> str:
    """The configured debugger executable; skips the test when there isn't one."""
    if not X64DBG_PATH:
        pytest.skip("x64dbg not configured: copy tests/local.env.example to tests/local.env, or pass --x64dbg-path")
    if not Path(X64DBG_PATH).is_file():
        pytest.skip(f"x64dbg not found at {X64DBG_PATH}")
    return X64DBG_PATH


@pytest.fixture
def client(x64dbg_path: str):
    client = X64DbgClient(x64dbg_path=x64dbg_path)
    yield client
    client.terminate_session()
