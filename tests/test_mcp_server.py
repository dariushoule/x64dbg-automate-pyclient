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
        session.window_title = "x64dbg"
        session.sess_req_rep_port = 5555
        session.sess_pub_sub_port = 5556
        mock_cls.list_sessions.return_value = [session]
        result = mcp_mod.list_sessions()
        assert "1234" in result
        assert "x64dbg" in result


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
        assert "True" in result
        assert "4321" in result
        assert "64" in result


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

    def test_size_capped(self, mock_client):
        mock_client.read_memory.return_value = b"\x00"
        mcp_mod.read_memory("0x1000", 9999)
        mock_client.read_memory.assert_called_once_with(0x1000, 4096)


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


class TestGetMemoryMap:
    def test_memmap(self, mock_client):
        page = MemPage(
            base_address=0x10000, allocation_base=0x10000, allocation_protect=0x40,
            partition_id=0, region_size=0x1000, state=0x1000, protect=0x20, type=0x20000, info="mapped"
        )
        mock_client.memmap.return_value = [page]
        result = mcp_mod.get_memory_map()
        assert "0x10000" in result
        assert "mapped" in result


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
            instruction="nop", argcount=0, instr_size=1,
            type=DisasmInstrType.Normal, arg=[],
        )
        ins2 = Instruction(
            instruction="ret", argcount=0, instr_size=1,
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
