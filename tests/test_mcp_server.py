"""Unit tests for the MCP server. Uses mocked X64DbgClient — no running x64dbg required."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from x64dbg_automate.mcp_server import (
    _format_address,
    _format_memory,
    _parse_address_or_expression,
    _pe_bitness,
    _resolve_debugger_path,
    _resolve_x64dbg_path_with_env,
    _require_client,
)
from x64dbg_automate.models import (
    Breakpoint,
    BreakpointType,
    Context64,
    Flags,
    FpuReg,
    Instruction,
    MemPage,
    MxcsrFields,
    RegDump64,
    Symbol,
    SymbolType,
    X87ControlWordFields,
    X87Fpu,
    X87StatusWordFields,
    DisasmInstrType,
)
from x64dbg_automate.events import EventType

# We need to import tool functions — they use the module-level _client global
import x64dbg_automate.mcp_server as mcp_mod


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------

class TestParseAddress:
    def test_hex_with_prefix(self):
        assert _parse_address_or_expression("0x7FF6A000") == 0x7FF6A000

    def test_hex_without_prefix(self):
        assert _parse_address_or_expression("7FF6A000") == 0x7FF6A000

    def test_hex_uppercase_prefix(self):
        assert _parse_address_or_expression("0X1234ABCD") == 0x1234ABCD

    def test_leading_trailing_spaces(self):
        assert _parse_address_or_expression("  0xDEAD  ") == 0xDEAD

    def test_zero(self):
        assert _parse_address_or_expression("0") == 0

    def test_plain_decimal_fallback(self):
        # "10" is valid hex, so it should parse as hex (16)
        assert _parse_address_or_expression("10") == 0x10

    def test_expression_fallback(self):
        """Non-hex strings fall back to eval_sync via the connected client."""
        mock_client = MagicMock()
        mock_client.eval_sync.return_value = (0x401000, True)
        original = mcp_mod._client
        mcp_mod._client = mock_client
        try:
            assert _parse_address_or_expression("RIP") == 0x401000
            mock_client.eval_sync.assert_called_once_with("RIP")
        finally:
            mcp_mod._client = original

    def test_expression_fallback_failure(self):
        """eval_sync failure raises ValueError."""
        mock_client = MagicMock()
        mock_client.eval_sync.return_value = (0, False)
        original = mcp_mod._client
        mcp_mod._client = mock_client
        try:
            with pytest.raises(ValueError, match="Cannot resolve"):
                _parse_address_or_expression("bad_symbol")
        finally:
            mcp_mod._client = original


class TestFormatAddress:
    def test_basic(self):
        assert _format_address(0x7FF6A000) == "0x7FF6A000"

    def test_zero(self):
        assert _format_address(0) == "0x0"


class TestFormatMemory:
    def test_single_line(self):
        data = bytes(range(16))
        result = _format_memory(data, 0x1000)
        assert "0x1000" in result
        assert "00 01 02" in result
        # ASCII sidebar should contain '.' for non-printable
        assert ".." in result

    def test_multiple_lines(self):
        data = bytes(range(32))
        result = _format_memory(data, 0x2000)
        lines = result.strip().split("\n")
        assert len(lines) == 2
        assert "0x2000" in lines[0]
        assert "0x2010" in lines[1]

    def test_partial_last_line(self):
        data = bytes(range(20))
        result = _format_memory(data, 0)
        lines = result.strip().split("\n")
        assert len(lines) == 2

    def test_empty(self):
        result = _format_memory(b"", 0)
        assert result == ""


class TestRequireClient:
    def test_raises_when_no_client(self):
        original = mcp_mod._client
        try:
            mcp_mod._client = None
            with pytest.raises(RuntimeError, match="Not connected"):
                _require_client()
        finally:
            mcp_mod._client = original


class TestPeBitness:
    def test_pe64(self, tmp_path):
        """Minimal PE with AMD64 machine type."""
        pe = _make_minimal_pe(0x8664)
        f = tmp_path / "test64.exe"
        f.write_bytes(pe)
        assert _pe_bitness(str(f)) == 64

    def test_pe32(self, tmp_path):
        """Minimal PE with i386 machine type."""
        pe = _make_minimal_pe(0x14C)
        f = tmp_path / "test32.exe"
        f.write_bytes(pe)
        assert _pe_bitness(str(f)) == 32

    def test_not_pe(self, tmp_path):
        f = tmp_path / "bad.exe"
        f.write_bytes(b"NOT_A_PE_FILE")
        with pytest.raises(ValueError, match="Not a valid PE"):
            _pe_bitness(str(f))


class TestResolveDebuggerPath:
    def test_passthrough_x64dbg(self, tmp_path):
        """x64dbg.exe is returned as-is."""
        p = tmp_path / "x64dbg.exe"
        p.write_bytes(b"")
        assert _resolve_debugger_path(str(p)) == str(p)

    def test_passthrough_x32dbg(self, tmp_path):
        p = tmp_path / "x32dbg.exe"
        p.write_bytes(b"")
        assert _resolve_debugger_path(str(p)) == str(p)

    def test_x96dbg_resolves_64(self, tmp_path):
        """x96dbg.exe + 64-bit target -> x64/x64dbg.exe (standard layout)."""
        launcher = tmp_path / "x96dbg.exe"
        launcher.write_bytes(b"")
        x64_dir = tmp_path / "x64"
        x64_dir.mkdir()
        dbg = x64_dir / "x64dbg.exe"
        dbg.write_bytes(b"")
        target = tmp_path / "target.exe"
        target.write_bytes(_make_minimal_pe(0x8664))
        result = _resolve_debugger_path(str(launcher), str(target))
        assert result == str(dbg)

    def test_x96dbg_resolves_32(self, tmp_path):
        """x96dbg.exe + 32-bit target -> x32/x32dbg.exe (standard layout)."""
        launcher = tmp_path / "x96dbg.exe"
        launcher.write_bytes(b"")
        x32_dir = tmp_path / "x32"
        x32_dir.mkdir()
        dbg = x32_dir / "x32dbg.exe"
        dbg.write_bytes(b"")
        target = tmp_path / "target.exe"
        target.write_bytes(_make_minimal_pe(0x14C))
        result = _resolve_debugger_path(str(launcher), str(target))
        assert result == str(dbg)

    def test_x96dbg_flat_layout(self, tmp_path):
        """Falls back to same-directory layout if x64/ doesn't exist."""
        launcher = tmp_path / "x96dbg.exe"
        launcher.write_bytes(b"")
        dbg = tmp_path / "x64dbg.exe"
        dbg.write_bytes(b"")
        target = tmp_path / "target.exe"
        target.write_bytes(_make_minimal_pe(0x8664))
        result = _resolve_debugger_path(str(launcher), str(target))
        assert result == str(dbg)

    def test_x96dbg_no_target_defaults_64(self, tmp_path):
        """No target exe defaults to 64-bit."""
        launcher = tmp_path / "x96dbg.exe"
        launcher.write_bytes(b"")
        x64_dir = tmp_path / "x64"
        x64_dir.mkdir()
        dbg = x64_dir / "x64dbg.exe"
        dbg.write_bytes(b"")
        result = _resolve_debugger_path(str(launcher))
        assert result == str(dbg)

    def test_x96dbg_not_found(self, tmp_path):
        launcher = tmp_path / "x96dbg.exe"
        launcher.write_bytes(b"")
        with pytest.raises(FileNotFoundError, match="Cannot find"):
            _resolve_debugger_path(str(launcher))


class TestResolveX64dbgPathWithEnv:
    def test_explicit_param_used(self):
        result = _resolve_x64dbg_path_with_env("C:\\x64dbg\\x64dbg.exe")
        assert result == "C:\\x64dbg\\x64dbg.exe"

    def test_explicit_param_overrides_env(self, monkeypatch):
        monkeypatch.setenv("X64DBG_PATH", "C:\\env\\x64dbg.exe")
        result = _resolve_x64dbg_path_with_env("C:\\param\\x64dbg.exe")
        assert result == "C:\\param\\x64dbg.exe"

    def test_env_fallback(self, monkeypatch):
        monkeypatch.setenv("X64DBG_PATH", "C:\\env\\x96dbg.exe")
        result = _resolve_x64dbg_path_with_env("")
        assert result == "C:\\env\\x96dbg.exe"

    def test_env_fallback_when_whitespace_only(self, monkeypatch):
        monkeypatch.setenv("X64DBG_PATH", "C:\\env\\x64dbg.exe")
        result = _resolve_x64dbg_path_with_env("   ")
        assert result == "C:\\env\\x64dbg.exe"

    def test_no_param_no_env_raises(self, monkeypatch):
        monkeypatch.delenv("X64DBG_PATH", raising=False)
        with pytest.raises(FileNotFoundError, match="X64DBG_PATH"):
            _resolve_x64dbg_path_with_env("")

    def test_env_whitespace_only_raises(self, monkeypatch):
        monkeypatch.setenv("X64DBG_PATH", "   ")
        with pytest.raises(FileNotFoundError, match="X64DBG_PATH"):
            _resolve_x64dbg_path_with_env("")


def _make_minimal_pe(machine: int) -> bytes:
    """Build the smallest valid PE stub with a given machine type."""
    import struct
    pe_offset = 0x80
    dos_header = b"MZ" + b"\x00" * (0x3C - 2) + struct.pack("<I", pe_offset) + b"\x00" * (pe_offset - 0x40)
    pe_sig = b"PE\x00\x00"
    machine_bytes = struct.pack("<H", machine)
    # Pad rest of COFF header (18 bytes remaining after machine)
    coff_rest = b"\x00" * 18
    return dos_header + pe_sig + machine_bytes + coff_rest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_client():
    """Provide a MagicMock client and patch it into the module global."""
    client = MagicMock()
    original = mcp_mod._client
    mcp_mod._client = client
    yield client
    mcp_mod._client = original


# ---------------------------------------------------------------------------
# Session tool tests
# ---------------------------------------------------------------------------

class TestListSessions:
    @patch.object(mcp_mod, "X64DbgClient")
    def test_no_sessions(self, mock_cls):
        mock_cls.list_sessions.return_value = []
        result = mcp_mod.list_sessions()
        assert "No active" in result

    @patch.object(mcp_mod, "X64DbgClient")
    def test_with_sessions(self, mock_cls):
        session = MagicMock()
        session.pid = 1234
        session.cmdline = ["C:\\x64dbg\\x64\\x64dbg.exe", "--arg"]
        session.window_title = "x64dbg"
        session.sess_req_rep_port = 5555
        session.sess_pub_sub_port = 5556
        mock_cls.list_sessions.return_value = [session]
        result = mcp_mod.list_sessions()
        assert "1234" in result
        assert "C:\\x64dbg\\x64\\x64dbg.exe" in result
        assert "x64dbg" in result

    @patch.object(mcp_mod, "X64DbgClient")
    def test_with_sessions_empty_cmdline(self, mock_cls):
        session = MagicMock()
        session.pid = 1234
        session.cmdline = []
        session.window_title = "x64dbg"
        session.sess_req_rep_port = 5555
        session.sess_pub_sub_port = 5556
        mock_cls.list_sessions.return_value = [session]
        result = mcp_mod.list_sessions()
        assert "1234" in result
        assert "unknown" in result

    @patch.object(mcp_mod, "X64DbgClient")
    def test_with_sessions_whitespace_cmdline(self, mock_cls):
        session = MagicMock()
        session.pid = 1234
        session.cmdline = ["   "]
        session.window_title = "x64dbg"
        session.sess_req_rep_port = 5555
        session.sess_pub_sub_port = 5556
        mock_cls.list_sessions.return_value = [session]
        result = mcp_mod.list_sessions()
        assert "1234" in result
        assert "unknown" in result

    @patch.object(mcp_mod, "X64DbgClient")
    def test_exception_returns_error(self, mock_cls):
        mock_cls.list_sessions.side_effect = NotImplementedError("Windows only")
        result = mcp_mod.list_sessions()
        assert "Error" in result
        assert "Windows only" in result


class TestStartSession:
    @patch.object(mcp_mod, "X64DbgClient")
    @patch.object(mcp_mod, "_resolve_debugger_path", return_value="C:\\x64dbg\\x64dbg.exe")
    def test_explicit_path(self, mock_resolve, mock_cls):
        mock_instance = MagicMock()
        mock_instance.start_session.return_value = 1234
        mock_cls.return_value = mock_instance
        result = mcp_mod.start_session(x64dbg_path="C:\\x64dbg\\x96dbg.exe")
        mock_resolve.assert_called_once_with("C:\\x64dbg\\x96dbg.exe", "")
        assert "1234" in result

    @patch.object(mcp_mod, "X64DbgClient")
    @patch.object(mcp_mod, "_resolve_debugger_path", return_value="C:\\env\\x64dbg.exe")
    def test_env_fallback(self, mock_resolve, mock_cls, monkeypatch):
        monkeypatch.setenv("X64DBG_PATH", "C:\\env\\x96dbg.exe")
        mock_instance = MagicMock()
        mock_instance.start_session.return_value = 5678
        mock_cls.return_value = mock_instance
        result = mcp_mod.start_session()
        mock_resolve.assert_called_once_with("C:\\env\\x96dbg.exe", "")
        assert "5678" in result

    def test_no_path_no_env_error(self, monkeypatch):
        monkeypatch.delenv("X64DBG_PATH", raising=False)
        result = mcp_mod.start_session()
        assert "Error" in result
        assert "X64DBG_PATH" in result


class TestConnectToSession:
    @patch.object(mcp_mod, "X64DbgClient")
    @patch.object(mcp_mod, "_resolve_debugger_path", return_value="C:\\x64dbg\\x64dbg.exe")
    def test_explicit_path(self, mock_resolve, mock_cls):
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance
        result = mcp_mod.connect_to_session(x64dbg_path="C:\\x64dbg\\x96dbg.exe", session_pid=1234)
        mock_resolve.assert_called_once_with("C:\\x64dbg\\x96dbg.exe")
        assert "1234" in result

    @patch.object(mcp_mod, "X64DbgClient")
    @patch.object(mcp_mod, "_resolve_debugger_path", return_value="C:\\env\\x64dbg.exe")
    def test_env_fallback(self, mock_resolve, mock_cls, monkeypatch):
        monkeypatch.setenv("X64DBG_PATH", "C:\\env\\x96dbg.exe")
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance
        result = mcp_mod.connect_to_session(session_pid=5678)
        mock_resolve.assert_called_once_with("C:\\env\\x96dbg.exe")
        assert "5678" in result

    def test_no_path_no_env_error(self, monkeypatch):
        monkeypatch.delenv("X64DBG_PATH", raising=False)
        result = mcp_mod.connect_to_session(session_pid=9999)
        assert "Error" in result
        assert "X64DBG_PATH" in result

    def test_missing_session_pid(self):
        result = mcp_mod.connect_to_session()
        assert "Error" in result
        assert "session_pid" in result


class TestDisconnect:
    def test_no_connection(self):
        original = mcp_mod._client
        mcp_mod._client = None
        result = mcp_mod.disconnect()
        assert "No active" in result
        mcp_mod._client = original

    def test_disconnect_success(self, mock_client):
        result = mcp_mod.disconnect()
        mock_client.detach_session.assert_called_once()
        assert "Disconnected" in result


# ---------------------------------------------------------------------------
# Debug Control tool tests
# ---------------------------------------------------------------------------

class TestGetDebuggerStatus:
    def test_status(self, mock_client):
        mock_client.is_debugging.return_value = True
        mock_client.is_running.return_value = False
        mock_client.debugee_pid.return_value = 4321
        mock_client.debugee_bitness.return_value = 64
        mock_client.debugger_is_elevated.return_value = False
        result = mcp_mod.get_debugger_status()
        assert "Has debuggee: True" in result
        assert "State: paused" in result
        assert "4321" in result
        assert "64" in result

    def test_running_when_debugging(self, mock_client):
        mock_client.is_debugging.return_value = True
        mock_client.is_running.return_value = True
        mock_client.debugee_pid.return_value = 4321
        mock_client.debugee_bitness.return_value = 64
        mock_client.debugger_is_elevated.return_value = False
        assert "State: running" in mcp_mod.get_debugger_status()

    def test_no_debuggee_does_not_report_running(self, mock_client):
        # DbgIsRunning() returns True once the debuggee exits; that must not surface
        # as "Running: True", which reads as a bridge fault.
        mock_client.is_debugging.return_value = False
        mock_client.is_running.return_value = True
        mock_client.debugger_is_elevated.return_value = False
        result = mcp_mod.get_debugger_status()
        assert "Has debuggee: False" in result
        assert "no debuggee" in result
        assert "running" not in result
        mock_client.debugee_pid.assert_not_called()


class TestEvalExpressionNoDebuggee:
    """x64dbg fabricates results with no debuggee, so nothing is evaluated without one."""

    # Every one of these returns (0, SUCCESS) with no debuggee attached, verified live.
    # The last four are why the expression is not inspected: they read debuggee state
    # without naming a register, a flag, or a dereference.
    @pytest.mark.parametrize("expr", [
        "[0x400000]",
        "eax",
        "_zf",
        "peb()",
        "$pid",
        "mod.main()",
        "arg.get(0)",
    ])
    def test_refused_without_debuggee(self, mock_client, expr):
        mock_client.is_debugging.return_value = False
        mock_client.eval_sync.return_value = (0, True)  # what x64dbg actually returns
        result = mcp_mod.eval_expression(expr)
        assert "no debuggee attached" in result
        mock_client.eval_sync.assert_not_called()

    def test_evaluated_normally_when_debugging(self, mock_client):
        mock_client.is_debugging.return_value = True
        mock_client.eval_sync.return_value = (0xDEAD, True)
        assert mcp_mod.eval_expression("[esi+0x10]") == "[esi+0x10] = 0xDEAD"

    def test_genuine_failure_still_reported(self, mock_client):
        mock_client.is_debugging.return_value = True
        mock_client.eval_sync.return_value = (0, False)
        assert "Evaluation failed" in mcp_mod.eval_expression("[0x1]")

    def test_address_resolution_refused_without_debuggee(self, mock_client):
        # Same guard covers every tool taking an address, via _parse_address_or_expression.
        mock_client.is_debugging.return_value = False
        mock_client.eval_sync.return_value = (0, True)
        assert "no debuggee attached" in mcp_mod.read_memory("rsp")
        mock_client.eval_sync.assert_not_called()

    def test_literal_address_does_not_consult_debuggee(self, mock_client):
        # Literals never reach the evaluator, so they cost no round trip.
        assert mcp_mod._parse_address_or_expression("0x400000") == 0x400000
        mock_client.is_debugging.assert_not_called()


class TestNoDebuggeeDisambiguation:
    """XERROR_READ_FAILED means both 'bad address' and 'dead debuggee' — disambiguate."""

    def test_memmap_refuses_stale_cache(self, mock_client):
        # DbgMemMap returns x64dbg's last-known memoryPages with no debuggee check,
        # so a detached session yields a plausible-looking but dead map.
        mock_client.is_debugging.return_value = False
        result = mcp_mod.get_memory_map()
        assert "No debuggee" in result
        mock_client.memmap.assert_not_called()

    def test_read_memory_failure_names_no_debuggee(self, mock_client):
        mock_client.is_debugging.return_value = False
        mock_client.read_memory.side_effect = RuntimeError("XERROR_READ_FAILED")
        result = mcp_mod.read_memory("0x10000", 16)
        assert "XERROR_READ_FAILED" in result
        assert "No debuggee" in result

    def test_read_memory_failure_with_debuggee_is_bad_address(self, mock_client):
        mock_client.is_debugging.return_value = True
        mock_client.read_memory.side_effect = RuntimeError("XERROR_READ_FAILED")
        result = mcp_mod.read_memory("0x1", 16)
        assert "XERROR_READ_FAILED" in result
        assert "No debuggee" not in result

    def test_successful_read_costs_no_extra_roundtrip(self, mock_client):
        mock_client.read_memory.return_value = b"\x90" * 4
        mcp_mod.read_memory("0x10000", 4)
        mock_client.is_debugging.assert_not_called()

    def test_read_many_failure_names_no_debuggee(self, mock_client):
        mock_client.is_debugging.return_value = False
        mock_client.read_memory.side_effect = RuntimeError("XERROR_READ_FAILED")
        result = mcp_mod.read_memory_many(["0x1000:4"])
        assert "XERROR_READ_FAILED" in result
        assert "No debuggee" in result

    def test_read_many_hint_is_appended_once_for_many_failures(self, mock_client):
        mock_client.is_debugging.return_value = False
        mock_client.read_memory.side_effect = RuntimeError("XERROR_READ_FAILED")
        result = mcp_mod.read_memory_many(["0x1000:4", "0x2000:4", "0x3000:4"])
        assert result.count("No debuggee") == 1
        mock_client.is_debugging.assert_called_once()

    def test_successful_batch_costs_no_extra_roundtrip(self, mock_client):
        mock_client.read_memory.return_value = b"\x90" * 4
        mcp_mod.read_memory_many(["0x1000:4", "0x2000:4"])
        mock_client.is_debugging.assert_not_called()

    def test_read_many_failure_with_debuggee_is_bad_address(self, mock_client):
        mock_client.is_debugging.return_value = True
        mock_client.read_memory.side_effect = RuntimeError("XERROR_READ_FAILED")
        result = mcp_mod.read_memory_many(["0x1:4"])
        assert "XERROR_READ_FAILED" in result
        assert "No debuggee" not in result

    def test_memmap_reports_absence_before_complaining_about_filters(self, mock_client):
        # A detached session must say so rather than rejecting the filter arguments.
        mock_client.is_debugging.return_value = False
        result = mcp_mod.get_memory_map(state="bogus")
        assert "No debuggee" in result
        mock_client.memmap.assert_not_called()


class TestGo:
    def test_go_success(self, mock_client):
        mock_client.go.return_value = True
        result = mcp_mod.go()
        assert "Resumed" in result

    def test_go_failure(self, mock_client):
        mock_client.go.return_value = False
        result = mcp_mod.go()
        assert "Failed" in result


class TestPause:
    def test_pause_success(self, mock_client):
        mock_client.pause.return_value = True
        result = mcp_mod.pause()
        assert "Paused" in result


class TestStepInto:
    def test_step_into(self, mock_client):
        mock_client.stepi.return_value = True
        result = mcp_mod.step_into(count=3)
        mock_client.stepi.assert_called_once_with(step_count=3)
        assert "3" in result


class TestStepOver:
    def test_step_over(self, mock_client):
        mock_client.stepo.return_value = True
        result = mcp_mod.step_over(count=2)
        mock_client.stepo.assert_called_once_with(step_count=2)
        assert "2" in result


class TestSkipInstruction:
    def test_skip(self, mock_client):
        mock_client.skip.return_value = True
        result = mcp_mod.skip_instruction(count=1)
        assert "Skipped" in result


class TestRunToReturn:
    def test_rtr(self, mock_client):
        mock_client.ret.return_value = True
        result = mcp_mod.run_to_return()
        assert "return" in result.lower()


# ---------------------------------------------------------------------------
# Memory tool tests
# ---------------------------------------------------------------------------

class TestReadMemory:
    def test_read_memory(self, mock_client):
        mock_client.read_memory.return_value = b"\x90" * 16
        result = mcp_mod.read_memory("0x1000", 16)
        assert "0x1000" in result
        assert "90" in result

    def test_oversized_refused_without_reading(self, mock_client):
        """Too large to encode is refused up front — never truncated, never issued."""
        result = mcp_mod.read_memory("0x1000", 99_999_999)
        assert "would exceed the response limit" in result
        assert "Read at most" in result
        mock_client.read_memory.assert_not_called()

    def test_oversized_suggests_base64(self, mock_client):
        result = mcp_mod.read_memory("0x1000", 99_999_999, format="hex")
        assert "format='base64'" in result

    def test_oversized_in_base64_does_not_suggest_itself(self, mock_client):
        result = mcp_mod.read_memory("0x1000", 99_999_999, format="base64")
        assert "format='base64'" not in result

    def test_size_below_cap_passed_through(self, mock_client):
        mock_client.read_memory.return_value = b"\x00" * 9999
        mcp_mod.read_memory("0x1000", 9999, format="base64")
        mock_client.read_memory.assert_called_once_with(0x1000, 9999)

    def test_size_zero_reads_the_most_that_fits(self, mock_client):
        mock_client.read_memory.return_value = b"\x00"
        mcp_mod.read_memory("0x1000", 0, format="base64")
        expected = mcp_mod._max_bytes_for("base64", 0x1000)
        mock_client.read_memory.assert_called_once_with(0x1000, expected)

    def test_size_zero_result_fits_budget(self, mock_client):
        for fmt in ("dump", "hex", "base64"):
            cap = mcp_mod._max_bytes_for(fmt, 0x7FFEF0E9D7BE)
            mock_client.read_memory.return_value = b"\xAB" * cap
            out = mcp_mod.read_memory("0x7FFEF0E9D7BE", 0, format=fmt)
            assert len(out) <= mcp_mod.MAX_RESPONSE_CHARS, f"{fmt} overflowed: {len(out)}"


class TestResponseBudget:
    """Encoded size is exact, so the budget can be enforced before the read happens."""

    @pytest.mark.parametrize("fmt", ["dump", "hex", "base64"])
    @pytest.mark.parametrize("nbytes", [0, 1, 2, 3, 15, 16, 17, 255, 4096])
    @pytest.mark.parametrize("addr", [0x401000, 0x7FFEF0E9D7BE])
    def test_predicted_length_is_exact(self, fmt, nbytes, addr):
        predicted = mcp_mod._encoded_len(nbytes, addr, fmt)
        actual = len(mcp_mod._encode_memory(bytes(nbytes), addr, fmt))
        assert predicted == actual

    @pytest.mark.parametrize("fmt", ["dump", "hex", "base64"])
    @pytest.mark.parametrize("addr", [0x401000, 0x7FFEF0E9D7BE])
    def test_max_bytes_fits_and_is_maximal(self, fmt, addr):
        cap = mcp_mod._max_bytes_for(fmt, addr)
        assert mcp_mod._encoded_len(cap, addr, fmt) <= mcp_mod.MAX_RESPONSE_CHARS
        # One more line/unit must not fit, or the cap is leaving room on the table.
        step = 16 if fmt == "dump" else 3
        assert mcp_mod._encoded_len(cap + step, addr, fmt) > mcp_mod.MAX_RESPONSE_CHARS

    def test_invalid_format_rejected(self):
        with pytest.raises(ValueError, match="Invalid format"):
            mcp_mod._encoded_len(16, 0x1000, "rot13")


class TestReadableSpan:
    """size=0 must stop at the region edge: DbgMemRead is all-or-nothing across one."""

    @staticmethod
    def _page(base, size, protect=0x04, state=None):
        from x64dbg_automate.models import MEM_COMMIT
        p = MagicMock()
        p.base_address, p.region_size = base, size
        p.protect, p.state = protect, MEM_COMMIT if state is None else state
        return p

    def test_span_stops_at_region_end(self, mock_client):
        mock_client.memmap.return_value = [self._page(0x1000, 0x2000)]
        assert mcp_mod._readable_span(mock_client, 0x1800) == 0x1800

    def test_unmapped_address_reports_unknown(self, mock_client):
        mock_client.memmap.return_value = [self._page(0x1000, 0x1000)]
        assert mcp_mod._readable_span(mock_client, 0x9999) == 0

    def test_noaccess_region_is_not_readable(self, mock_client):
        mock_client.memmap.return_value = [self._page(0x1000, 0x1000, protect=0x01)]
        assert mcp_mod._readable_span(mock_client, 0x1000) == 0

    def test_guarded_stack_still_readable(self, mock_client):
        """x64dbg folds a stack's guard page into the region; excluding it broke stacks."""
        from x64dbg_automate.models import PAGE_GUARD
        mock_client.memmap.return_value = [self._page(0x1000, 0x8000, protect=0x04 | PAGE_GUARD)]
        assert mcp_mod._readable_span(mock_client, 0x1000) == 0x8000

    def test_reserved_region_is_not_readable(self, mock_client):
        from x64dbg_automate.models import MEM_RESERVE
        mock_client.memmap.return_value = [self._page(0x1000, 0x1000, state=MEM_RESERVE)]
        assert mcp_mod._readable_span(mock_client, 0x1000) == 0

    def test_size_zero_clamps_to_region(self, mock_client):
        """A region smaller than the budget must not produce an over-long request."""
        mock_client.memmap.return_value = [self._page(0x1000, 0x1000)]
        mock_client.read_memory.return_value = b"\x00" * 0x800
        mcp_mod.read_memory("0x1800", 0, format="base64")
        mock_client.read_memory.assert_called_once_with(0x1800, 0x800)

    def test_size_zero_uses_budget_when_span_unknown(self, mock_client):
        mock_client.memmap.side_effect = RuntimeError("no map")
        mock_client.read_memory.return_value = b"\x00"
        mcp_mod.read_memory("0x1000", 0, format="base64")
        expected = mcp_mod._max_bytes_for("base64", 0x1000)
        mock_client.read_memory.assert_called_once_with(0x1000, expected)

    def test_format_hex(self, mock_client):
        mock_client.read_memory.return_value = b"\xde\xad\xbe\xef"
        assert mcp_mod.read_memory("0x1000", 4, format="hex") == "DEADBEEF"

    def test_format_base64(self, mock_client):
        mock_client.read_memory.return_value = b"\xde\xad\xbe\xef"
        assert mcp_mod.read_memory("0x1000", 4, format="base64") == "3q2+7w=="

    def test_format_dump_is_default(self, mock_client):
        mock_client.read_memory.return_value = b"\xde\xad\xbe\xef"
        assert mcp_mod.read_memory("0x1000", 4) == mcp_mod.read_memory("0x1000", 4, format="dump")

    def test_invalid_format(self, mock_client):
        mock_client.read_memory.return_value = b"\x00"
        assert "Error" in mcp_mod.read_memory("0x1000", 1, format="yaml")


class TestReadMemoryMany:
    def test_batch(self, mock_client):
        mock_client.read_memory.side_effect = [b"\xaa\xbb", b"\xcc"]
        result = mcp_mod.read_memory_many(["0x1000:2", "0x2000:1"])
        assert "0x1000:2 @0x1000 = AABB" in result
        assert "0x2000:1 @0x2000 = CC" in result

    def test_one_failure_does_not_abort_others(self, mock_client):
        mock_client.read_memory.side_effect = [RuntimeError("XERROR_READ_FAILED"), b"\xcc"]
        result = mcp_mod.read_memory_many(["0x1000:2", "0x2000:1"])
        assert "0x1000:2 ERROR: XERROR_READ_FAILED" in result
        assert "0x2000:1 @0x2000 = CC" in result

    def test_malformed_spec(self, mock_client):
        result = mcp_mod.read_memory_many(["garbage"])
        assert "ERROR" in result

    def test_empty(self, mock_client):
        assert "No reads requested" in mcp_mod.read_memory_many([])

    def test_batch_shares_one_budget(self, mock_client):
        """Earlier reads complete; the one that no longer fits is skipped, not cut."""
        cap = mcp_mod._max_bytes_for("hex", 0x1000)
        mock_client.read_memory.side_effect = [b"\xAA" * cap, b"\xBB"]
        result = mcp_mod.read_memory_many([f"0x1000:{cap}", "0x2000:1"])
        assert result.startswith("0x1000:%d @0x1000 = AA" % cap)
        assert "0x2000:1 SKIPPED" in result
        # The skipped read must not have been issued.
        assert mock_client.read_memory.call_count == 1

    def test_batch_stays_within_budget(self, mock_client):
        cap = mcp_mod._max_bytes_for("base64", 0x1000)
        mock_client.read_memory.return_value = b"\xAB" * cap
        result = mcp_mod.read_memory_many([f"0x{i}000:{cap}" for i in range(1, 6)],
                                          format="base64")
        assert len(result) <= mcp_mod.MAX_RESPONSE_CHARS * 1.1  # + skip notices
        assert "SKIPPED" in result

    def test_oversized_single_read_skipped_not_truncated(self, mock_client):
        result = mcp_mod.read_memory_many(["0x1000:99999999"])
        assert "SKIPPED" in result
        mock_client.read_memory.assert_not_called()


class TestWriteMemory:
    def test_write(self, mock_client):
        mock_client.write_memory.return_value = True
        result = mcp_mod.write_memory("0x1000", "90 90 90")
        mock_client.write_memory.assert_called_once_with(0x1000, b"\x90\x90\x90")
        assert "Wrote 3 bytes" in result


class TestAllocateMemory:
    def test_alloc(self, mock_client):
        mock_client.virt_alloc.return_value = 0xDEAD0000
        result = mcp_mod.allocate_memory(4096)
        assert "0xDEAD0000" in result


class TestFreeMemory:
    def test_free(self, mock_client):
        mock_client.virt_free.return_value = True
        result = mcp_mod.free_memory("0xDEAD0000")
        assert "Freed" in result


def _page(base, *, size=0x1000, state=0x1000, protect=0x20, type=0x20000, info="mapped"):
    return MemPage(
        base_address=base, allocation_base=base, allocation_protect=0x40,
        partition_id=0, region_size=size, state=state, protect=protect, type=type, info=info,
    )


class TestGetMemoryMap:
    def test_memmap(self, mock_client):
        mock_client.memmap.return_value = [_page(0x10000)]
        result = mcp_mod.get_memory_map()
        assert "0x10000" in result
        assert "mapped" in result

    def test_defaults_to_committed_only(self, mock_client):
        mock_client.memmap.return_value = [
            _page(0x10000, state=mcp_mod.MEM_COMMIT),
            _page(0x20000, state=mcp_mod.MEM_FREE),
            _page(0x30000, state=mcp_mod.MEM_RESERVE),
        ]
        result = mcp_mod.get_memory_map()
        assert "0x10000" in result
        assert "0x20000" not in result
        assert "1/3 regions matched, 2 hidden by filters" in result

    def test_empty_state_includes_all(self, mock_client):
        mock_client.memmap.return_value = [
            _page(0x10000, state=mcp_mod.MEM_COMMIT),
            _page(0x20000, state=mcp_mod.MEM_FREE),
        ]
        result = mcp_mod.get_memory_map(state="")
        assert "0x10000" in result and "0x20000" in result

    def test_committed_private_rw(self, mock_client):
        """The motivating case: ~27 committed private RW regions out of ~1000."""
        mock_client.memmap.return_value = [
            _page(0x10000, protect=0x04, type=mcp_mod.MEM_PRIVATE),   # RW- private -> match
            _page(0x20000, protect=0x20, type=mcp_mod.MEM_PRIVATE),   # R-X private -> no
            _page(0x30000, protect=0x04, type=mcp_mod.MEM_IMAGE),     # RW- image   -> no
            _page(0x40000, protect=0x40, type=mcp_mod.MEM_PRIVATE),   # RWX private -> match
        ]
        result = mcp_mod.get_memory_map(protect="rw", mem_type="private")
        assert "0x10000" in result and "0x40000" in result
        assert "0x20000" not in result and "0x30000" not in result

    def test_min_size(self, mock_client):
        mock_client.memmap.return_value = [_page(0xAAA000, size=0x100), _page(0xBBB000, size=0x9000)]
        result = mcp_mod.get_memory_map(min_size=0x1000)
        assert "0xBBB000" in result and "0xAAA000" not in result

    def test_pagination(self, mock_client):
        mock_client.memmap.return_value = [_page(0x10000 * i) for i in range(1, 6)]
        result = mcp_mod.get_memory_map(offset=1, limit=2)
        assert "0x20000" in result and "0x30000" in result
        assert "0x10000" not in result and "0x40000" not in result
        assert "2 more — call again with offset=3" in result

    def test_limit_zero_is_unlimited(self, mock_client):
        mock_client.memmap.return_value = [_page(0x10000 * i) for i in range(1, 6)]
        result = mcp_mod.get_memory_map(limit=0)
        assert "more" not in result

    def test_as_json(self, mock_client):
        import json as _json
        mock_client.memmap.return_value = [_page(0x10000, protect=0x04, type=mcp_mod.MEM_PRIVATE)]
        result = mcp_mod.get_memory_map(as_json=True)
        payload = _json.loads(result[:result.rindex("\n[")])
        assert payload[0]["base_address"] == "0x10000"
        assert payload[0]["protect"] == "RW-"
        assert payload[0]["state"] == "commit"
        assert payload[0]["type"] == "private"

    def test_no_matches(self, mock_client):
        mock_client.memmap.return_value = [_page(0x10000, protect=0x02)]
        assert "No regions matched" in mcp_mod.get_memory_map(protect="x")

    def test_invalid_state_filter(self, mock_client):
        mock_client.memmap.return_value = [_page(0x10000)]
        assert "Error" in mcp_mod.get_memory_map(state="bogus")


class TestProtectDecoding:
    @pytest.mark.parametrize("protect,expected", [
        (0x01, "---"), (0x02, "R--"), (0x04, "RW-"), (0x08, "RC-"),
        (0x10, "--X"), (0x20, "R-X"), (0x40, "RWX"), (0x80, "RCX"),
        (0x00, "---"),
    ])
    def test_decode(self, protect, expected):
        assert mcp_mod._decode_protect(protect) == expected

    def test_guard_flag(self):
        assert mcp_mod._decode_protect(0x104) == "RW-+G"

    @pytest.mark.parametrize("protect,filt,expected", [
        (0x04, "rw", True),
        (0x04, "x", False),
        (0x40, "rwx", True),
        (0x08, "w", True),      # copy-on-write counts as writable
        (0x10, "r", False),     # execute-only is not readable
        (0x02, "", True),       # empty filter matches everything
        (0x04, "0x04", True),   # exact hex match
        (0x04, "0x20", False),
    ])
    def test_matches(self, protect, filt, expected):
        assert mcp_mod._protect_matches(protect, filt) is expected


# ---------------------------------------------------------------------------
# Register tool tests
# ---------------------------------------------------------------------------

class TestGetRegister:
    def test_get_reg(self, mock_client):
        mock_client.get_reg.return_value = 0xDEADBEEF
        result = mcp_mod.get_register("rax")
        assert "0xDEADBEEF" in result


class TestSetRegister:
    def test_set_reg(self, mock_client):
        mock_client.set_reg.return_value = True
        result = mcp_mod.set_register("rax", "0xCAFE")
        mock_client.set_reg.assert_called_once_with("rax", 0xCAFE)
        assert "Set rax" in result


class TestGetAllRegisters:
    def test_get_all(self, mock_client):
        ctx = Context64(
            rax=1, rbx=2, rcx=3, rdx=4, rbp=5, rsp=6, rsi=7, rdi=8,
            r8=9, r9=10, r10=11, r11=12, r12=13, r13=14, r14=15, r15=16,
            rip=0x1000, eflags=0x246, cs=0x33, ds=0x2B, es=0x2B, fs=0x53, gs=0x2B, ss=0x2B,
            dr0=0, dr1=0, dr2=0, dr3=0, dr6=0, dr7=0,
            reg_area=b"\x00" * 80,
            x87_fpu=X87Fpu(ControlWord=0, StatusWord=0, TagWord=0, ErrorOffset=0,
                           ErrorSelector=0, DataOffset=0, DataSelector=0, Cr0NpxState=0),
            mxcsr=0, zmm_regs=[b"\x00" * 64] * 32,
        )
        flags = Flags(c=False, p=True, a=False, z=True, s=False, t=False, i=True, d=False, o=False)
        fpu = [FpuReg(data=b"\x00" * 10, st_value=0, tag=0)] * 8
        mxcsr_f = MxcsrFields(FZ=False, PM=False, UM=False, OM=False, ZM=False, IM=False,
                               DM=False, DAZ=False, PE=False, UE=False, OE=False, ZE=False,
                               DE=False, IE=False, RC=0)
        x87sw = X87StatusWordFields(B=False, C3=False, C2=False, C1=False, C0=False,
                                     ES=False, SF=False, P=False, U=False, O=False,
                                     Z=False, D=False, I=False, TOP=0)
        x87cw = X87ControlWordFields(IC=False, IEM=False, PM=False, UM=False, OM=False,
                                      ZM=False, DM=False, IM=False, RC=0, PC=0)
        regdump = RegDump64(
            context=ctx, flags=flags, fpu=fpu, mmx=[0] * 8,
            mxcsr_fields=mxcsr_f, x87_status_word_fields=x87sw,
            x87_control_word_fields=x87cw, last_error=(0, ""), last_status=(0, ""),
        )
        mock_client.get_regs.return_value = regdump
        result = mcp_mod.get_all_registers()
        assert "rax" in result
        assert "rip" in result
        assert "flags" in result


# ---------------------------------------------------------------------------
# Expression & Command tool tests
# ---------------------------------------------------------------------------

class TestEvalExpression:
    def test_eval_success(self, mock_client):
        mock_client.eval_sync.return_value = (0xBEEF, True)
        result = mcp_mod.eval_expression("kernel32:CreateFileA")
        assert "0xBEEF" in result

    def test_eval_failure(self, mock_client):
        mock_client.eval_sync.return_value = (0, False)
        result = mcp_mod.eval_expression("bad_expr")
        assert "failed" in result.lower()


class TestExecuteCommand:
    def test_cmd(self, mock_client):
        mock_client.cmd_sync.return_value = True
        result = mcp_mod.execute_command("msg hello")
        assert "True" in result


# ---------------------------------------------------------------------------
# Breakpoint tool tests
# ---------------------------------------------------------------------------

class TestSetBreakpoint:
    def test_software_bp(self, mock_client):
        mock_client.set_breakpoint.return_value = True
        result = mcp_mod.set_breakpoint("0x401000")
        assert "set" in result.lower()

    def test_hardware_bp(self, mock_client):
        mock_client.set_hardware_breakpoint.return_value = True
        result = mcp_mod.set_breakpoint("0x401000", bp_type="hardware", hardware_mode="x")
        mock_client.set_hardware_breakpoint.assert_called_once()
        assert "set" in result.lower()

    def test_memory_bp(self, mock_client):
        mock_client.set_memory_breakpoint.return_value = True
        result = mcp_mod.set_breakpoint("0x401000", bp_type="memory")
        mock_client.set_memory_breakpoint.assert_called_once()
        assert "set" in result.lower()

    def test_symbol_name(self, mock_client):
        mock_client.set_breakpoint.return_value = True
        result = mcp_mod.set_breakpoint("kernel32:CreateFileA")
        assert "set" in result.lower()


class TestClearBreakpoint:
    def test_clear_all_software(self, mock_client):
        mock_client.clear_breakpoint.return_value = True
        result = mcp_mod.clear_breakpoint()
        mock_client.clear_breakpoint.assert_called_once_with(None)
        assert "cleared" in result.lower()

    def test_clear_hardware(self, mock_client):
        mock_client.clear_hardware_breakpoint.return_value = True
        result = mcp_mod.clear_breakpoint("0x401000", bp_type="hardware")
        mock_client.clear_hardware_breakpoint.assert_called_once_with(0x401000)
        assert "cleared" in result.lower()


class TestToggleBreakpoint:
    def test_enable(self, mock_client):
        mock_client.toggle_breakpoint.return_value = True
        result = mcp_mod.toggle_breakpoint("0x401000", enable=True)
        assert "Enabled" in result

    def test_disable(self, mock_client):
        mock_client.toggle_breakpoint.return_value = True
        result = mcp_mod.toggle_breakpoint("0x401000", enable=False)
        assert "Disabled" in result


class TestListBreakpoints:
    def test_list_empty(self, mock_client):
        mock_client.get_breakpoints.return_value = []
        result = mcp_mod.list_breakpoints()
        assert "No" in result

    def test_list_with_bps(self, mock_client):
        bp = Breakpoint(
            type=BreakpointType.BpNormal, addr=0x401000, enabled=True, singleshoot=False,
            active=True, name="test_bp", mod="test.exe", slot=0, typeEx=0, hwSize=0,
            hitCount=5, fastResume=False, silent=False, breakCondition="", logText="",
            logCondition="", commandText="", commandCondition="",
        )
        mock_client.get_breakpoints.return_value = [bp]
        result = mcp_mod.list_breakpoints()
        assert "0x401000" in result
        assert "test_bp" in result
        assert "5" in result


# ---------------------------------------------------------------------------
# Assembly tool tests
# ---------------------------------------------------------------------------

class TestDisassemble:
    def test_disassemble(self, mock_client):
        ins1 = Instruction(
            instruction="nop", symbolized_instruction="nop", argcount=0, instr_size=1,
            type=DisasmInstrType.Normal, arg=[],
        )
        ins2 = Instruction(
            instruction="ret", symbolized_instruction="ret", argcount=0, instr_size=1,
            type=DisasmInstrType.Normal, arg=[],
        )
        mock_client.disassemble_at.side_effect = [ins1, ins2]
        result = mcp_mod.disassemble("0x1000", count=2)
        assert "nop" in result
        assert "ret" in result
        assert "0x1000" in result
        assert "0x1001" in result

    def test_disassemble_failure(self, mock_client):
        mock_client.disassemble_at.return_value = None
        result = mcp_mod.disassemble("0x1000", count=1)
        assert "???" in result


class TestAssemble:
    def test_assemble(self, mock_client):
        mock_client.assemble_at.return_value = 1
        result = mcp_mod.assemble("0x1000", "nop")
        assert "nop" in result
        assert "1 bytes" in result


# ---------------------------------------------------------------------------
# Annotation & Symbol tool tests
# ---------------------------------------------------------------------------

class TestLabels:
    def test_set_label(self, mock_client):
        mock_client.set_label_at.return_value = True
        result = mcp_mod.set_label("0x1000", "my_func")
        assert "Label set" in result

    def test_get_label(self, mock_client):
        mock_client.get_label_at.return_value = "my_func"
        result = mcp_mod.get_label("0x1000")
        assert "my_func" in result

    def test_get_label_empty(self, mock_client):
        mock_client.get_label_at.return_value = ""
        result = mcp_mod.get_label("0x1000")
        assert "No label" in result


class TestComments:
    def test_set_comment(self, mock_client):
        mock_client.set_comment_at.return_value = True
        result = mcp_mod.set_comment("0x1000", "interesting")
        assert "Comment set" in result

    def test_get_comment(self, mock_client):
        mock_client.get_comment_at.return_value = "interesting"
        result = mcp_mod.get_comment("0x1000")
        assert "interesting" in result


class TestGetSymbol:
    def test_found(self, mock_client):
        sym = Symbol(addr=0x1000, decoratedSymbol="_func", undecoratedSymbol="func",
                     type=SymbolType.SymExport, ordinal=1)
        mock_client.get_symbol_at.return_value = sym
        result = mcp_mod.get_symbol("0x1000")
        assert "func" in result
        assert "0x1000" in result

    def test_not_found(self, mock_client):
        mock_client.get_symbol_at.return_value = None
        result = mcp_mod.get_symbol("0x1000")
        assert "No symbol" in result


# ---------------------------------------------------------------------------
# Thread tool tests
# ---------------------------------------------------------------------------

class TestThreads:
    def test_create_thread(self, mock_client):
        mock_client.thread_create.return_value = 42
        result = mcp_mod.create_thread("0x1000", "0")
        assert "42" in result

    def test_terminate_thread(self, mock_client):
        mock_client.thread_terminate.return_value = True
        result = mcp_mod.terminate_thread(42)
        assert "terminated" in result.lower()

    def test_pause_thread(self, mock_client):
        mock_client.thread_pause.return_value = True
        result = mcp_mod.pause_resume_thread(42, "pause")
        assert "paused" in result.lower()

    def test_resume_thread(self, mock_client):
        mock_client.thread_resume.return_value = True
        result = mcp_mod.pause_resume_thread(42, "resume")
        assert "resumed" in result.lower()

    def test_switch_thread(self, mock_client):
        mock_client.switch_thread.return_value = True
        result = mcp_mod.switch_thread(42)
        assert "Switched" in result


# ---------------------------------------------------------------------------
# Event tool tests
# ---------------------------------------------------------------------------

class TestEvents:
    def test_get_latest_event_empty(self, mock_client):
        mock_client.get_latest_debug_event.return_value = None
        result = mcp_mod.get_latest_event()
        assert "No events" in result

    def test_get_latest_event(self, mock_client):
        event = MagicMock()
        event.event_type = EventType.EVENT_BREAKPOINT
        event.event_data = MagicMock()
        event.event_data.model_dump.return_value = {"addr": 0x1000, "name": "test"}
        mock_client.get_latest_debug_event.return_value = event
        result = mcp_mod.get_latest_event()
        assert "EVENT_BREAKPOINT" in result

    def test_wait_for_event_timeout(self, mock_client):
        mock_client.wait_for_debug_event.return_value = None
        result = mcp_mod.wait_for_event("EVENT_BREAKPOINT", timeout=1)
        assert "Timed out" in result


# ---------------------------------------------------------------------------
# Settings tool tests
# ---------------------------------------------------------------------------

class TestSettings:
    def test_get_string_setting(self, mock_client):
        mock_client.get_setting_str.return_value = "value"
        result = mcp_mod.get_setting("Gui", "Theme")
        assert "value" in result

    def test_get_int_setting(self, mock_client):
        mock_client.get_setting_int.return_value = 42
        result = mcp_mod.get_setting("Gui", "FontSize", type="int")
        assert "42" in result

    def test_set_setting(self, mock_client):
        mock_client.set_setting_str.return_value = True
        result = mcp_mod.set_setting("Gui", "Theme", "dark")
        assert "updated" in result.lower()


# ---------------------------------------------------------------------------
# GUI tool tests
# ---------------------------------------------------------------------------

class TestGui:
    def test_log_message(self, mock_client):
        mock_client.log.return_value = True
        result = mcp_mod.log_message("hello")
        assert "logged" in result.lower()

    def test_refresh_gui(self, mock_client):
        mock_client.gui_refresh_views.return_value = True
        result = mcp_mod.refresh_gui()
        assert "refreshed" in result.lower()


# ---------------------------------------------------------------------------
# Error path tests
# ---------------------------------------------------------------------------

class TestErrorPaths:
    def test_no_connection_raises(self):
        original = mcp_mod._client
        mcp_mod._client = None
        try:
            result = mcp_mod.go()
            assert "Error" in result
            assert "Not connected" in result
        finally:
            mcp_mod._client = original

    def test_invalid_address(self, mock_client):
        mock_client.read_memory.side_effect = RuntimeError("invalid address")
        result = mcp_mod.read_memory("0xBAD", 16)
        assert "Error" in result

    def test_exception_in_eval(self, mock_client):
        mock_client.eval_sync.side_effect = Exception("eval failed")
        result = mcp_mod.eval_expression("bad")
        assert "Error" in result
