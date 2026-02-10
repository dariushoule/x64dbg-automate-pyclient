"""MCP server for x64dbg-automate. Exposes x64dbg automation as MCP tools."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("MCP dependency not installed. Install with: pip install x64dbg_automate[mcp]", file=sys.stderr)
    sys.exit(1)

from x64dbg_automate import X64DbgClient
from x64dbg_automate.events import EventType
from x64dbg_automate.models import (
    BreakpointType,
    HardwareBreakpointType,
    MemoryBreakpointType,
)

mcp = FastMCP(
    "x64dbg-automate",
    instructions=(
        "MCP server for controlling the x64dbg debugger via x64dbg-automate. "
        "Use list_sessions or start_session first, then connect before using other tools. "
        "Addresses are hex strings (e.g. '0x7FF6A0001000'). Memory reads return hex dumps."
    ),
)

_client: X64DbgClient | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_client() -> X64DbgClient:
    """Return the active client or raise a clear error."""
    if _client is None:
        raise RuntimeError("Not connected to x64dbg. Use connect_to_session or start_session first.")
    return _client


def _parse_address_or_expression(s: str) -> int:
    """Parse an address string to int.

    Accepts hex literals ('0x7FF6...', '7FF6...'), and falls back to
    x64dbg's expression evaluator so registers ('RIP'), symbols
    ('kernel32:CreateFileA'), and arithmetic ('rsp+0x20') all work.
    """
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    try:
        return int(s, 16)
    except ValueError:
        pass
    # Fall back to x64dbg expression evaluator
    client = _require_client()
    val, success = client.eval_sync(s)
    if not success:
        raise ValueError(f"Cannot resolve address: {s}")
    return val


def _format_address(addr: int) -> str:
    """Format an integer address as a hex string."""
    return f"0x{addr:X}"


def _format_memory(data: bytes, base: int) -> str:
    """Format bytes as a standard hex dump with ASCII sidebar."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{_format_address(base + offset)}  {hex_part:<48s}  {ascii_part}")
    return "\n".join(lines)


def _pe_bitness(exe_path: str) -> int:
    """Read the PE Machine field to determine if an executable is 32-bit or 64-bit."""
    with open(exe_path, "rb") as f:
        mz = f.read(2)
        if mz != b"MZ":
            raise ValueError(f"Not a valid PE file: {exe_path}")
        f.seek(0x3C)
        pe_offset = struct.unpack("<I", f.read(4))[0]
        f.seek(pe_offset)
        sig = f.read(4)
        if sig != b"PE\x00\x00":
            raise ValueError(f"Invalid PE signature in: {exe_path}")
        machine = struct.unpack("<H", f.read(2))[0]
    if machine == 0x8664:
        return 64
    if machine == 0x14C:
        return 32
    raise ValueError(f"Unknown PE machine type 0x{machine:X} in: {exe_path}")


def _resolve_debugger_path(x64dbg_path: str, target_exe: str = "") -> str:
    """Resolve x96dbg.exe to the correct x64dbg.exe or x32dbg.exe based on target bitness.

    If the path already points to x64dbg.exe or x32dbg.exe, it is returned as-is.
    """
    p = Path(x64dbg_path)
    name_lower = p.name.lower()
    if name_lower not in ("x96dbg.exe", "x96dbg"):
        return x64dbg_path
    # x96dbg launcher — resolve to the correct binary
    if target_exe.strip():
        bitness = _pe_bitness(target_exe.strip())
    else:
        bitness = 64  # default when no target specified
    arch_dir = "x64" if bitness == 64 else "x32"
    dbg_name = "x64dbg.exe" if bitness == 64 else "x32dbg.exe"
    candidates = [
        p.parent / arch_dir / dbg_name,        # release/x64/x64dbg.exe (standard layout)
        p.parent / dbg_name,                    # release/x64dbg.exe (flat layout)
        p.parent / "release" / dbg_name,        # alongside release/ folder
        p.parent / "release" / arch_dir / dbg_name,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise FileNotFoundError(
        f"Cannot find {dbg_name} relative to {x64dbg_path}. "
        f"Pass the path to {dbg_name} directly instead of x96dbg.exe."
    )


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------

@mcp.tool()
def list_sessions() -> str:
    """List all active x64dbg debugger instances. Does not require an active connection."""
    sessions = X64DbgClient.list_sessions()
    if not sessions:
        return "No active x64dbg sessions found."
    lines = []
    for s in sessions:
        lines.append(
            f"PID: {s.pid}  |  Window: {s.window_title}  |  "
            f"REQ port: {s.sess_req_rep_port}  |  SUB port: {s.sess_pub_sub_port}"
        )
    return "\n".join(lines)


@mcp.tool()
def start_session(x64dbg_path: str, target_exe: str = "", cmdline: str = "", current_dir: str = "") -> str:
    """Launch a new x64dbg instance and optionally load an executable.

    If x96dbg.exe (the launcher) is given, the correct x64dbg.exe or x32dbg.exe is
    selected automatically based on the target executable's PE bitness.

    Args:
        x64dbg_path: Path to x64dbg installation (x96dbg.exe, x64dbg.exe, or x32dbg.exe)
        target_exe: Path to executable to debug (optional)
        cmdline: Command-line arguments for the target (optional)
        current_dir: Working directory for the target (optional)
    """
    global _client
    try:
        resolved = _resolve_debugger_path(x64dbg_path, target_exe)
        _client = X64DbgClient(resolved)
        pid = _client.start_session(target_exe, cmdline, current_dir)
        return f"Session started with {Path(resolved).name}. Debugger PID: {pid}"
    except Exception as e:
        _client = None
        return f"Error: {e}"


@mcp.tool()
def connect_to_session(x64dbg_path: str, session_pid: int) -> str:
    """Connect to an already-running x64dbg instance.

    If x96dbg.exe is given, it is resolved to x64dbg.exe (default).
    The actual debugger binary must already be running.

    Args:
        x64dbg_path: Path to x64dbg installation (x96dbg.exe, x64dbg.exe, or x32dbg.exe)
        session_pid: PID of the x64dbg process to attach to
    """
    global _client
    try:
        resolved = _resolve_debugger_path(x64dbg_path)
        _client = X64DbgClient(resolved)
        _client.attach_session(session_pid)
        return f"Connected to session PID {session_pid}."
    except Exception as e:
        _client = None
        return f"Error: {e}"


@mcp.tool()
def disconnect() -> str:
    """Disconnect from the current x64dbg session without terminating the debugger."""
    global _client
    if _client is None:
        return "No active connection."
    try:
        _client.detach_session()
        _client = None
        return "Disconnected."
    except Exception as e:
        _client = None
        return f"Error: {e}"


@mcp.tool()
def terminate_session() -> str:
    """Terminate the connected x64dbg debugger process."""
    global _client
    try:
        client = _require_client()
        client.terminate_session()
        _client = None
        return "Session terminated."
    except Exception as e:
        _client = None
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Debug Control
# ---------------------------------------------------------------------------

@mcp.tool()
def get_debugger_status() -> str:
    """Get consolidated debugger status: debugging state, running state, PID, bitness, elevated."""
    try:
        client = _require_client()
        debugging = client.is_debugging()
        running = client.is_running()
        pid = client.debugee_pid() if debugging else None
        bitness = client.debugee_bitness() if debugging else None
        elevated = client.debugger_is_elevated()
        parts = [
            f"Debugging: {debugging}",
            f"Running: {running}",
            f"Debuggee PID: {pid}",
            f"Bitness: {bitness}",
            f"Elevated: {elevated}",
        ]
        return "\n".join(parts)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def go(pass_exceptions: bool = False, swallow_exceptions: bool = False) -> str:
    """Resume debuggee execution.

    Args:
        pass_exceptions: Pass exceptions to the debuggee
        swallow_exceptions: Swallow exceptions
    """
    try:
        client = _require_client()
        result = client.go(pass_exceptions=pass_exceptions, swallow_exceptions=swallow_exceptions)
        return "Resumed." if result else "Failed to resume."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def pause() -> str:
    """Pause the debuggee."""
    try:
        client = _require_client()
        result = client.pause()
        return "Paused." if result else "Failed to pause."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def step_into(count: int = 1) -> str:
    """Step into one or more instructions.

    Args:
        count: Number of instructions to step into
    """
    try:
        client = _require_client()
        result = client.stepi(step_count=count)
        return f"Stepped into {count} instruction(s)." if result else "Step into failed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def step_over(count: int = 1) -> str:
    """Step over one or more instructions.

    Args:
        count: Number of instructions to step over
    """
    try:
        client = _require_client()
        result = client.stepo(step_count=count)
        return f"Stepped over {count} instruction(s)." if result else "Step over failed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def skip_instruction(count: int = 1) -> str:
    """Skip instructions without executing them.

    Args:
        count: Number of instructions to skip
    """
    try:
        client = _require_client()
        result = client.skip(skip_count=count)
        return f"Skipped {count} instruction(s)." if result else "Skip failed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def run_to_return(frames: int = 1) -> str:
    """Run until a return instruction is encountered.

    Args:
        frames: Number of return frames to seek
    """
    try:
        client = _require_client()
        result = client.ret(frames=frames)
        return "Ran to return." if result else "Run to return failed."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------

@mcp.tool()
def read_memory(address: str, size: int = 256) -> str:
    """Read memory from the debuggee. Returns hex dump with ASCII sidebar.

    Args:
        address: Address — hex ('0x7FF6A0001000'), register ('RSP'), symbol, or expression ('rsp+0x20')
        size: Number of bytes to read (max 4096)
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        size = min(size, 4096)
        data = client.read_memory(addr, size)
        return _format_memory(data, addr)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def write_memory(address: str, hex_data: str) -> str:
    """Write bytes to debuggee memory.

    Args:
        address: Hex address to write to
        hex_data: Hex string of bytes to write (e.g. '90 90 90' or '909090')
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        cleaned = hex_data.replace(" ", "").replace("\n", "")
        data = bytes.fromhex(cleaned)
        result = client.write_memory(addr, data)
        return f"Wrote {len(data)} bytes to {_format_address(addr)}." if result else "Write failed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def allocate_memory(size: int = 4096, address: str = "0") -> str:
    """Allocate memory in the debuggee's address space (VirtualAlloc).

    Args:
        size: Number of bytes to allocate
        address: Preferred address (0 for any)
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        result = client.virt_alloc(n=size, addr=addr)
        return f"Allocated {size} bytes at {_format_address(result)}."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def free_memory(address: str) -> str:
    """Free memory in the debuggee's address space (VirtualFree).

    Args:
        address: Address of memory to free
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        client.virt_free(addr)
        return f"Freed memory at {_format_address(addr)}."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_memory_map() -> str:
    """List all memory regions in the debuggee's address space."""
    try:
        client = _require_client()
        pages = client.memmap()
        if not pages:
            return "No memory regions found."
        lines = []
        for p in pages:
            lines.append(
                f"{_format_address(p.base_address)}  Size: {_format_address(p.region_size)}  "
                f"Protect: 0x{p.protect:X}  State: 0x{p.state:X}  Info: {p.info}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Registers
# ---------------------------------------------------------------------------

@mcp.tool()
def get_register(register: str) -> str:
    """Read a single register value.

    Args:
        register: Register name (e.g. 'rax', 'eip', 'rsp', 'eflags')
    """
    try:
        client = _require_client()
        val = client.get_reg(register)
        return f"{register} = {_format_address(val)}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def set_register(register: str, value: str) -> str:
    """Write a value to a register.

    Args:
        register: Register name (e.g. 'rax', 'eip')
        value: Hex value to set
    """
    try:
        client = _require_client()
        val = _parse_address_or_expression(value)
        result = client.set_reg(register, val)
        return f"Set {register} = {_format_address(val)}." if result else "Failed to set register."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_all_registers() -> str:
    """Dump all general-purpose registers and flags."""
    try:
        client = _require_client()
        regs = client.get_regs()
        ctx = regs.context
        lines = []
        for field_name in type(ctx).model_fields:
            val = getattr(ctx, field_name)
            if isinstance(val, int):
                lines.append(f"{field_name:8s} = {_format_address(val)}")
        flags = regs.flags
        flag_strs = [f"{k}={int(v)}" for k, v in flags.model_dump().items()]
        lines.append(f"flags    = {' '.join(flag_strs)}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Expressions & Commands
# ---------------------------------------------------------------------------

@mcp.tool()
def eval_expression(expression: str) -> str:
    """Evaluate an x64dbg expression. Supports symbols, registers, arithmetic.

    Args:
        expression: Expression to evaluate (e.g. 'kernel32:CreateFileA', 'rax+0x10')
    """
    try:
        client = _require_client()
        val, success = client.eval_sync(expression)
        if not success:
            return f"Evaluation failed for: {expression}"
        return f"{expression} = {_format_address(val)}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def execute_command(command: str) -> str:
    """Execute a raw x64dbg command.

    See https://help.x64dbg.com/en/latest/commands/ for available commands.

    Args:
        command: x64dbg command string
    """
    try:
        client = _require_client()
        result = client.cmd_sync(command)
        return f"Command executed. Success: {result}"
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Breakpoints
# ---------------------------------------------------------------------------

@mcp.tool()
def set_breakpoint(
    address_or_symbol: str,
    bp_type: str = "software",
    name: str | None = None,
    hardware_mode: str = "x",
    memory_mode: str = "a",
    singleshot: bool = False,
) -> str:
    """Set a breakpoint (software, hardware, or memory).

    Args:
        address_or_symbol: Hex address or symbol name
        bp_type: 'software', 'hardware', or 'memory'
        name: Optional breakpoint name (software only)
        hardware_mode: Hardware BP mode: 'r' (read), 'w' (write), 'x' (execute)
        memory_mode: Memory BP mode: 'r', 'w', 'x', 'a' (access)
        singleshot: Single-shot breakpoint
    """
    try:
        client = _require_client()
        # Parse address; if it fails, treat as symbol name
        try:
            addr: int | str = _parse_address_or_expression(address_or_symbol)
        except (ValueError, TypeError):
            addr = address_or_symbol

        if bp_type == "hardware":
            hw = HardwareBreakpointType(hardware_mode)
            result = client.set_hardware_breakpoint(addr, bp_type=hw)
        elif bp_type == "memory":
            mm = MemoryBreakpointType(memory_mode)
            result = client.set_memory_breakpoint(addr, bp_type=mm, singleshoot=singleshot)
        else:
            result = client.set_breakpoint(addr, name=name, singleshoot=singleshot)

        return f"Breakpoint set at {address_or_symbol}." if result else "Failed to set breakpoint."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def clear_breakpoint(address: str | None = None, bp_type: str = "software") -> str:
    """Clear breakpoint(s).

    Args:
        address: Hex address or symbol (None clears all of this type)
        bp_type: 'software', 'hardware', or 'memory'
    """
    try:
        client = _require_client()
        target: int | str | None = None
        if address is not None:
            try:
                target = _parse_address_or_expression(address)
            except (ValueError, TypeError):
                target = address

        if bp_type == "hardware":
            result = client.clear_hardware_breakpoint(target)
        elif bp_type == "memory":
            result = client.clear_memory_breakpoint(target)
        else:
            result = client.clear_breakpoint(target)

        return "Breakpoint(s) cleared." if result else "Failed to clear breakpoint(s)."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def toggle_breakpoint(address: str | None = None, bp_type: str = "software", enable: bool = True) -> str:
    """Enable or disable breakpoint(s).

    Args:
        address: Hex address or symbol (None toggles all of this type)
        bp_type: 'software', 'hardware', or 'memory'
        enable: True to enable, False to disable
    """
    try:
        client = _require_client()
        target: int | str | None = None
        if address is not None:
            try:
                target = _parse_address_or_expression(address)
            except (ValueError, TypeError):
                target = address

        if bp_type == "hardware":
            result = client.toggle_hardware_breakpoint(target, on=enable)
        elif bp_type == "memory":
            result = client.toggle_memory_breakpoint(target, on=enable)
        else:
            result = client.toggle_breakpoint(target, on=enable)

        action = "Enabled" if enable else "Disabled"
        return f"{action} breakpoint(s)." if result else f"Failed to {action.lower()} breakpoint(s)."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def list_breakpoints(bp_type: str = "software") -> str:
    """List all breakpoints of a given type.

    Args:
        bp_type: 'software', 'hardware', or 'memory'
    """
    try:
        client = _require_client()
        type_map = {
            "software": BreakpointType.BpNormal,
            "hardware": BreakpointType.BpHardware,
            "memory": BreakpointType.BpMemory,
        }
        bt = type_map.get(bp_type, BreakpointType.BpNormal)
        bps = client.get_breakpoints(bt)
        if not bps:
            return f"No {bp_type} breakpoints set."
        lines = []
        for bp in bps:
            status = "ON" if bp.enabled else "OFF"
            lines.append(
                f"{_format_address(bp.addr)}  [{status}]  Name: {bp.name}  "
                f"Module: {bp.mod}  Hits: {bp.hitCount}  Singleshot: {bp.singleshoot}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

@mcp.tool()
def disassemble(address: str, count: int = 10) -> str:
    """Disassemble instructions at an address.

    Args:
        address: Address — hex ('0x401000'), register ('RIP'), symbol, or expression
        count: Number of instructions to disassemble (max 100)
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        count = min(count, 100)
        lines = []
        current = addr
        for _ in range(count):
            ins = client.disassemble_at(current)
            if ins is None:
                lines.append(f"{_format_address(current)}  ???")
                break
            lines.append(f"{_format_address(current)}  {ins.instruction}")
            current += ins.instr_size
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def assemble(address: str, instruction: str) -> str:
    """Assemble a single instruction at an address.

    Args:
        address: Hex address to assemble at
        instruction: Assembly instruction (e.g. 'nop', 'mov eax, 1')
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        size = client.assemble_at(addr, instruction)
        if size is None:
            return f"Failed to assemble '{instruction}' at {_format_address(addr)}."
        return f"Assembled '{instruction}' at {_format_address(addr)} ({size} bytes)."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Annotations & Symbols
# ---------------------------------------------------------------------------

@mcp.tool()
def set_label(address: str, text: str) -> str:
    """Set a label at an address.

    Args:
        address: Hex address
        text: Label text
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        result = client.set_label_at(addr, text)
        return f"Label set at {_format_address(addr)}." if result else "Failed to set label."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_label(address: str) -> str:
    """Get the label at an address.

    Args:
        address: Hex address
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        label = client.get_label_at(addr)
        if not label:
            return f"No label at {_format_address(addr)}."
        return f"{_format_address(addr)}: {label}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def set_comment(address: str, text: str) -> str:
    """Set a comment at an address.

    Args:
        address: Hex address
        text: Comment text
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        result = client.set_comment_at(addr, text)
        return f"Comment set at {_format_address(addr)}." if result else "Failed to set comment."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_comment(address: str) -> str:
    """Get the comment at an address.

    Args:
        address: Hex address
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        comment = client.get_comment_at(addr)
        if not comment:
            return f"No comment at {_format_address(addr)}."
        return f"{_format_address(addr)}: {comment}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_symbol(address: str) -> str:
    """Look up the symbol at an address.

    Args:
        address: Hex address
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        sym = client.get_symbol_at(addr)
        if sym is None:
            return f"No symbol at {_format_address(addr)}."
        return (
            f"Address: {_format_address(sym.addr)}\n"
            f"Decorated: {sym.decoratedSymbol}\n"
            f"Undecorated: {sym.undecoratedSymbol}\n"
            f"Type: {sym.type}  Ordinal: {sym.ordinal}"
        )
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Threads
# ---------------------------------------------------------------------------

@mcp.tool()
def create_thread(entry_address: str, argument: str = "0") -> str:
    """Create a new thread in the debuggee.

    Args:
        entry_address: Hex address of the thread entry point
        argument: Hex value passed as thread argument
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(entry_address)
        arg = _parse_address_or_expression(argument)
        tid = client.thread_create(addr, arg)
        if tid is None:
            return "Failed to create thread."
        return f"Thread created. TID: {tid}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def terminate_thread(tid: int) -> str:
    """Terminate a thread in the debuggee.

    Args:
        tid: Thread ID to terminate
    """
    try:
        client = _require_client()
        result = client.thread_terminate(tid)
        return f"Thread {tid} terminated." if result else f"Failed to terminate thread {tid}."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def pause_resume_thread(tid: int, action: str = "pause") -> str:
    """Pause or resume a thread.

    Args:
        tid: Thread ID
        action: 'pause' or 'resume'
    """
    try:
        client = _require_client()
        if action == "resume":
            result = client.thread_resume(tid)
            return f"Thread {tid} resumed." if result else f"Failed to resume thread {tid}."
        else:
            result = client.thread_pause(tid)
            return f"Thread {tid} paused." if result else f"Failed to pause thread {tid}."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def switch_thread(tid: int) -> str:
    """Switch the debugger's active thread context.

    Args:
        tid: Thread ID to switch to
    """
    try:
        client = _require_client()
        result = client.switch_thread(tid)
        return f"Switched to thread {tid}." if result else f"Failed to switch to thread {tid}."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@mcp.tool()
def get_latest_event() -> str:
    """Pop the latest debug event from the event queue."""
    try:
        client = _require_client()
        event = client.get_latest_debug_event()
        if event is None:
            return "No events in queue."
        data_str = ""
        if event.event_data is not None:
            data_str = "\n" + "\n".join(
                f"  {k}: {v}" for k, v in event.event_data.model_dump().items()
            )
        return f"Event: {event.event_type}{data_str}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def wait_for_event(event_type: str, timeout: int = 5) -> str:
    """Wait for a specific debug event type.

    Args:
        event_type: Event type name (e.g. 'EVENT_BREAKPOINT', 'EVENT_LOAD_DLL')
        timeout: Max seconds to wait
    """
    try:
        client = _require_client()
        et = EventType(event_type)
        event = client.wait_for_debug_event(et, timeout=timeout)
        if event is None:
            return f"Timed out waiting for {event_type}."
        data_str = ""
        if event.event_data is not None:
            data_str = "\n" + "\n".join(
                f"  {k}: {v}" for k, v in event.event_data.model_dump().items()
            )
        return f"Event: {event.event_type}{data_str}"
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@mcp.tool()
def get_setting(section: str, name: str, type: str = "string") -> str:
    """Read an x64dbg setting.

    Args:
        section: Settings section name
        name: Setting name
        type: 'string' or 'int'
    """
    try:
        client = _require_client()
        if type == "int":
            val = client.get_setting_int(section, name)
        else:
            val = client.get_setting_str(section, name)
        if val is None:
            return f"Setting [{section}]{name} not found."
        return f"[{section}]{name} = {val}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def set_setting(section: str, name: str, value: str, type: str = "string") -> str:
    """Write an x64dbg setting.

    Args:
        section: Settings section name
        name: Setting name
        value: Setting value
        type: 'string' or 'int'
    """
    try:
        client = _require_client()
        if type == "int":
            result = client.set_setting_int(section, name, int(value))
        else:
            result = client.set_setting_str(section, name, value)
        return f"Setting [{section}]{name} updated." if result else "Failed to update setting."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

@mcp.tool()
def log_message(message: str) -> str:
    """Log a message to the x64dbg log window.

    Args:
        message: Message text to log
    """
    try:
        client = _require_client()
        result = client.log(message)
        return "Message logged." if result else "Failed to log message."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def refresh_gui() -> str:
    """Refresh all x64dbg GUI views."""
    try:
        client = _require_client()
        result = client.gui_refresh_views()
        return "GUI refreshed." if result else "Failed to refresh GUI."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Run the MCP server with stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
