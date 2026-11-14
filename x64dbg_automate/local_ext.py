"""Local extensions for the x64dbg-automate MCP server.

Upgraded from the old ``mcp_server_local.py`` monkey-patch layer (0.9.2+local.p2)
into real source. What changed vs p2:

* No more runtime rebinding of ``base._parse_address_or_expression`` — that fix now
  lives in ``mcp_server.py`` itself;
* No more ``X64DbgClient.pause = _pause_with_fallback`` — that fix now lives in
  ``hla_xauto.py``;
* ``xref`` rewritten: p2 put the ModRM index on the opcode for the ``FF 15/FF 25``
  branch (so ``call/jmp qword [rip+d]`` could never match) and measured ``0xC7``
  as 7 bytes instead of 11 (missing the imm32);
* ``exec_command_out`` fetches only the log tail instead of the whole buffer;
* ``find_bytes`` reports when the 64 MB scan cap truncated the range;
* ``parse_addr`` helper honours the same expression fallback as the MCP tools.

Patch set: local.3 → local.9. The authoritative current value is the ``PATCH``
constant below — version numbers written in prose drift, this one did.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

MEM_IMAGE = 0x1000000
_MAX_SCAN = 64 * 1024 * 1024

PATCH = "0.9.2+local.9"
LOCAL_TOOLS: list[str] = []


def _base():
    """Late import so this module can be imported before mcp_server finishes."""
    from x64dbg_automate import mcp_server as base
    return base


def _client():
    return _base()._require_client()


def _fmt(addr: int) -> str:
    return f"0x{addr:X}"


def _addr(spec: str) -> int:
    b = _base()
    return b._parse_address_or_expression(spec)


# ---------------------------------------------------------------------------
# Memory range helpers
# ---------------------------------------------------------------------------

def _image_pages(client, exe_only: bool = False):
    pages = []
    for p in client.memmap():
        if p.type != MEM_IMAGE or not p.info:
            continue
        if exe_only and not p.info.lower().endswith(".exe"):
            continue
        pages.append(p)
    return pages


def _default_range(client, start: str, size: int):
    """Resolve the scan range; defaults to the main module's image pages.

    A module's section pages do not all end in ``.exe`` in ``info``, so an
    ``.exe`` page is used only to discover the ``allocation_base``.
    """
    if start:
        lo = _addr(start)
        if size:
            return lo, size
        for p in client.memmap():
            if p.base_address <= lo < p.base_address + p.region_size:
                return lo, p.base_address + p.region_size - lo
        raise ValueError(f"start={start} 不在任何已映射内存区，请显式给 size")
    pages = _image_pages(client)
    if not pages:
        raise ValueError("无法确定主模块范围，请显式传 start/size")
    bases = {p.allocation_base for p in pages if ".exe" in p.info.lower()}
    if not bases:
        bases = {p.allocation_base for p in pages}
    sel = [p for p in pages if p.allocation_base in bases]
    lo = min(p.base_address for p in sel)
    hi = max(p.base_address + p.region_size for p in sel)
    return lo, (size or (hi - lo))


def _parse_pattern(pattern: str):
    """'48 8D 05 ?? ?? ?? ??' / '488D05??????' -> (vals, masks)"""
    compact = re.sub(r"\s+", "", pattern)
    if not compact or len(compact) % 2 != 0:
        raise ValueError("pattern 必须是偶数长度的十六进制，支持 ?? 通配")
    vals, masks = [], []
    for i in range(0, len(compact), 2):
        tok = compact[i:i + 2]
        if tok in ("??", "**"):
            vals.append(0)
            masks.append(0)
        else:
            vals.append(int(tok, 16))
            masks.append(0xFF)
    return vals, masks


def _scan_bytes(client, start: int, size: int, vals, masks, max_hits: int):
    """Chunked scan. Returns (hits, bytes_covered, truncated)."""
    plen = len(vals)
    hits = []
    chunk = 0x10000
    addr = start
    capped = min(size, _MAX_SCAN)
    truncated = size > _MAX_SCAN
    end = start + capped
    covered = 0
    prev_end = None
    first_byte = None
    fixed = all(masks)
    if fixed:
        first_byte = bytes([vals[0]]) if plen else None
    while addr < end and len(hits) < max_hits:
        n = min(chunk + plen - 1, end - addr)
        if n < plen:
            break
        try:
            buf = client.read_memory(addr, n)
        except Exception:
            addr += chunk
            continue
        # chunks overlap by plen-1 bytes so a match spanning the boundary is not
        # missed; count only the newly covered part (p2 counted the overlap too,
        # so a 6.4 MB module reported 6,400,388 bytes scanned).
        overlap = 0 if prev_end is None else max(0, prev_end - addr)
        covered += len(buf) - overlap
        prev_end = addr + len(buf)
        limit = len(buf) - plen
        pos = 0
        while pos <= limit:
            if first_byte is not None:
                found = buf.find(first_byte, pos, limit + 1)
                if found == -1:
                    break
                pos = found
            ok = True
            for k in range(plen):
                if masks[k] and buf[pos + k] != vals[k]:
                    ok = False
                    break
            if ok:
                hits.append(addr + pos)
                if len(hits) >= max_hits:
                    break
            pos += 1
        addr += limit + 1
    return hits, covered, truncated


# ---------------------------------------------------------------------------
# Console channel (console debuggee only)
# ---------------------------------------------------------------------------

_CONSOLE_HELPER = r"""
import ctypes, json, sys
from ctypes import wintypes as W

GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
FILE_SHARE_RW, OPEN_EXISTING = 3, 3

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.FreeConsole.argtypes = []
k32.AttachConsole.argtypes = [W.DWORD]
k32.AttachConsole.restype = W.BOOL
k32.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE]
k32.CreateFileW.restype = ctypes.c_void_p
k32.CloseHandle.argtypes = [ctypes.c_void_p]

class COORD(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

class SMALL_RECT(ctypes.Structure):
    _fields_ = [("Left", ctypes.c_short), ("Top", ctypes.c_short),
                ("Right", ctypes.c_short), ("Bottom", ctypes.c_short)]

class CSBI(ctypes.Structure):
    _fields_ = [("dwSize", COORD), ("dwCursorPosition", COORD),
                ("wAttributes", W.WORD), ("srWindow", SMALL_RECT),
                ("dwMaximumWindowSize", COORD)]

class KEY_EVENT_RECORD(ctypes.Structure):
    _fields_ = [("bKeyDown", W.BOOL), ("wRepeatCount", W.WORD),
                ("wVirtualKeyCode", W.WORD), ("wVirtualScanCode", W.WORD),
                ("UnicodeChar", W.WCHAR), ("dwControlKeyState", W.DWORD)]

class _EVENT(ctypes.Union):
    _fields_ = [("KeyEvent", KEY_EVENT_RECORD), ("_pad", ctypes.c_byte * 16)]

class INPUT_RECORD(ctypes.Structure):
    _fields_ = [("EventType", W.WORD), ("Event", _EVENT)]

k32.WriteConsoleInputW.argtypes = [W.HANDLE, ctypes.c_void_p, W.DWORD, ctypes.POINTER(W.DWORD)]
k32.WriteConsoleInputW.restype = W.BOOL
k32.GetConsoleScreenBufferInfo.argtypes = [W.HANDLE, ctypes.POINTER(CSBI)]
k32.ReadConsoleOutputCharacterW.argtypes = [W.HANDLE, W.LPWSTR, W.DWORD, COORD, ctypes.POINTER(W.DWORD)]

def done(**kw):
    print(json.dumps(kw))
    sys.exit(0)

payload = sys.stdin.buffer.read().decode("utf-8", "replace")
pid = int(sys.argv[1])
mode = sys.argv[2]

k32.FreeConsole()
if not k32.AttachConsole(pid):
    done(ok=False, err="AttachConsole failed (%d)；目标可能无控制台（GUI 程序）" % ctypes.get_last_error())

if mode == "write":
    h = k32.CreateFileW("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_RW, None, OPEN_EXISTING, 0, None)
    if not h or h == 0xFFFFFFFFFFFFFFFF:
        done(ok=False, err="打开 CONIN$ 失败 (%d)" % ctypes.get_last_error())
    recs = []
    for ch in payload:
        r = INPUT_RECORD()
        r.EventType = 1
        ke = r.Event.KeyEvent
        ke.bKeyDown = True
        ke.wRepeatCount = 1
        if ch in "\r\n":
            ke.wVirtualKeyCode, ke.wVirtualScanCode, ke.UnicodeChar = 0x0D, 0x1C, "\r"
        else:
            ke.wVirtualKeyCode, ke.wVirtualScanCode = 0, 0
            ke.UnicodeChar = ch
        recs.append(r)
    arr = (INPUT_RECORD * len(recs))(*recs)
    written = W.DWORD(0)
    ok = k32.WriteConsoleInputW(h, ctypes.cast(arr, ctypes.c_void_p), len(recs), ctypes.byref(written))
    err = ctypes.get_last_error()
    k32.CloseHandle(h)
    done(ok=bool(ok), written=written.value, err=("" if ok else "WriteConsoleInputW failed (%d)" % err))

h = k32.CreateFileW("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_RW, None, OPEN_EXISTING, 0, None)
if not h or h == 0xFFFFFFFFFFFFFFFF:
    done(ok=False, err="打开 CONOUT$ 失败 (%d)" % ctypes.get_last_error())
info = CSBI()
if not k32.GetConsoleScreenBufferInfo(h, ctypes.byref(info)):
    done(ok=False, err="GetConsoleScreenBufferInfo failed (%d)" % ctypes.get_last_error())
total = max(1, info.dwSize.X * info.dwSize.Y)
buf = ctypes.create_unicode_buffer(total + 1)
read = W.DWORD(0)
ok = k32.ReadConsoleOutputCharacterW(h, buf, total, COORD(0, 0), ctypes.byref(read))
k32.CloseHandle(h)
if not ok:
    done(ok=False, err="ReadConsoleOutputCharacterW failed (%d)" % ctypes.get_last_error())
width = max(1, info.dwSize.X)
chars = buf[:read.value].replace("\r", "").replace("\n", "")
rows = [chars[i:i + width].rstrip() for i in range(0, len(chars), width)]
while rows and not rows[0]:
    rows.pop(0)
while rows and not rows[-1]:
    rows.pop()
done(ok=True, text="\n".join(rows))
"""


def _console_call(pid: int, mode: str, payload: str = "") -> dict:
    proc = subprocess.run(
        [sys.executable, "-c", _CONSOLE_HELPER, str(pid), mode],
        input=payload.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=25,
    )
    out = proc.stdout.decode("utf-8", "replace").strip()
    if not out:
        return {"ok": False, "err": proc.stderr.decode("utf-8", "replace").strip() or "helper 无输出"}
    try:
        return json.loads(out.splitlines()[-1])
    except Exception:
        return {"ok": False, "err": out}


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

def skip_call(return_value: int = 0, mode: str = "call", force: bool = False) -> str:
    """
    跳过当前 call 并写入返回值（x64 写 rax / x86 写 eax）。

    mode="call"（默认）：断在 call 指令上，ip 前进、sp 不变。
    mode="return"：断在被调函数入口，弹出返回地址再跳。
    非 call 指令默认拒绝；确需跳过传 force=True。
    """
    if mode not in ("call", "return"):
        return f"Error: mode 只能是 'call' 或 'return'，收到 {mode!r}"
    try:
        client = _client()
        if client.is_running():
            return "Error: 调试对象正在运行，先 pause 或下断点"
        is64 = client.debugee_bitness() != 32
        ip_reg, sp_reg, ax_reg = ("rip", "rsp", "rax") if is64 else ("eip", "esp", "eax")
        ptr = 8 if is64 else 4
        mask = (1 << (ptr * 8)) - 1
        ip = client.get_reg(ip_reg)
        sp = client.get_reg(sp_reg)
        value = return_value & mask
        if mode == "return":
            ret = client.read_qword(sp) if is64 else client.read_dword(sp)
            client.set_reg(ip_reg, ret)
            client.set_reg(sp_reg, sp + ptr)
            client.set_reg(ax_reg, value)
            return (f"Returned from call: {_fmt(ip)} -> {_fmt(ret)}, "
                    f"{sp_reg}={_fmt(sp + ptr)}, {ax_reg}={_fmt(value)}")
        ins = client.disassemble_at(ip)
        if ins is None:
            return f"Error: 无法反汇编 {_fmt(ip)}"
        if not ins.instruction.lower().startswith("call") and not force:
            return (f"Error: {_fmt(ip)} 不是 call 指令（{ins.symbolized_instruction}）；"
                    f"确实要跳过请传 force=True")
        new_ip = ip + ins.instr_size
        client.set_reg(ip_reg, new_ip)
        client.set_reg(ax_reg, value)
        return (f"Skipped {ins.symbolized_instruction} at {_fmt(ip)} -> {_fmt(new_ip)}, "
                f"{ax_reg}={_fmt(value)}")
    except Exception as e:
        return f"Error: {e}"


def send_stdin(text: str, newline: bool = True) -> str:
    """
    向调试对象的控制台注入键盘输入（仅控制台程序）。

    newline=True 时末尾自动补回车（fgets/scanf 需要）。
    """
    try:
        pid = _client().debugee_pid()
        if not pid:
            return "Error: 当前没有调试对象"
        payload = text + ("\n" if newline else "")
        r = _console_call(pid, "write", payload)
        if r.get("ok"):
            return f"Sent {r.get('written', 0)} input records to console of pid {pid}"
        return f"Error: {r.get('err')}"
    except Exception as e:
        return f"Error: {e}"


def read_console(max_chars: int = 6000) -> str:
    """
    读调试对象控制台的当前屏内容（不含回滚历史）。
    """
    try:
        pid = _client().debugee_pid()
        if not pid:
            return "Error: 当前没有调试对象"
        r = _console_call(pid, "read")
        if not r.get("ok"):
            return f"Error: {r.get('err')}"
        lines = [ln.rstrip() for ln in r.get("text", "").replace("\r", "").split("\n")]
        while lines and not lines[0]:
            lines.pop(0)
        text = "\n".join(lines).rstrip()
        if max_chars > 0:
            text = text[-max_chars:]
        return text if text else "(console empty)"
    except Exception as e:
        return f"Error: {e}"


def find_bytes(pattern: str, start: str = "", size: int = 0, max_hits: int = 16) -> str:
    """
    在内存里搜字节模式，支持 ?? 通配（如 "48 8B ?? 05"）。

    留空 start/size 扫主模块；单次上限 64 MB，超出时返回会标 truncated。
    """
    try:
        vals, masks = _parse_pattern(pattern)
        lo, length = _default_range(_client(), start, size)
        hits, covered, truncated = _scan_bytes(_client(), lo, length, vals, masks, max_hits)
        note = f" [truncated at 64 MB of {length:,}]" if truncated else ""
        if not hits:
            return f"No match in {_fmt(lo)}+{length:,}{note}"
        lines = [f"{len(hits)} hit(s), {covered:,} bytes covered{note}:"]
        lines += [f"  {_fmt(h)}" for h in hits]
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


def find_string(text: str, encoding: str = "utf-8", start: str = "",
                size: int = 0, max_hits: int = 16) -> str:
    """
    按编码（ascii / utf16le）在内存里搜字符串。
    """
    enc = {"ascii": "ascii", "utf-8": "utf-8", "utf8": "utf-8",
           "utf-16le": "utf-16le", "utf16": "utf-16le"}.get(encoding.lower())
    if enc is None:
        return "Error: encoding 仅支持 ascii / utf-8 / utf-16le"
    if not text:
        return "Error: text 不能为空"
    try:
        data = text.encode(enc)
    except Exception as e:
        return f"Error: {e}"
    return find_bytes(data.hex(" "), start=start, size=size, max_hits=max_hits)


# opcode -> imm 长度（mod=00/rm=101，即 RIP 相对时用于算指令总长）
_RIP_OP_IMM = {
    0x01: 0, 0x03: 0, 0x29: 0, 0x2B: 0, 0x38: 0, 0x39: 0, 0x3B: 0,
    0x85: 0, 0x87: 0, 0x88: 0, 0x89: 0, 0x8B: 0, 0x8D: 0,
    0x81: 4, 0x83: 1, 0xC6: 1, 0xC7: 4,
}
_RIP_FIRST = bytes(sorted(set(list(_RIP_OP_IMM) + [0xFF] + list(range(0x40, 0x50)))))

# 反汇编文本里的绝对内存操作数：[0x140000117] / [7FF6C2E30250] / 32 位 [00404040]
# 不匹配 [rsp+0x20]、[rax+8] 这类寄存器相对寻址（那不是静态引用，本来就不算 xref）
_ABS_MEM_RE = re.compile(r"\[\s*(?:0x)?([0-9A-Fa-f]{8,16})\s*\]")


def _xref_deep(client, lo: int, length: int, tgt: int, max_hits: int):
    """流式反汇编找引用：覆盖所有 opcode（含 0F 系），代价是每指令一次 IPC。

    判定依据优先用 ``Instruction.arg`` 里 type=Memory 的解析值（x64dbg 已把
    RIP 相对算成绝对地址），取不到再回退正则解析 symbolized_instruction。
    """
    from x64dbg_automate.models import DisasmArgType

    hits = []
    cur = lo
    end = lo + min(length, _MAX_SCAN)
    while cur < end and len(hits) < max_hits:
        try:
            ins = client.disassemble_at(cur)
        except Exception:
            cur += 1
            continue
        if ins is None:
            cur += 1
            continue
        matched = False
        for a in (ins.arg or []):
            if a.type == DisasmArgType.Memory and a.value == tgt:
                matched = True
                break
        if not matched:
            for m in _ABS_MEM_RE.finditer(ins.symbolized_instruction or ""):
                if int(m.group(1), 16) == tgt:
                    matched = True
                    break
        if matched:
            hits.append(cur)
        cur += max(1, ins.instr_size)
    return hits


def xref(target: str, start: str = "", size: int = 0, max_hits: int = 32,
         deep: bool = False) -> str:
    """
    查找引用某地址的指令（x64 的 RIP 相对寻址）。

    deep=False：快路径，只认单字节 opcode + FF 15/FF 25，秒级。
    deep=True：流式反汇编，覆盖 0F 系（movzx/movaps 等），32 位目标的绝对地址也能匹配；
        慢 10~70 倍，务必用 start/size 限定区间，别对全模块开。
    """
    try:
        client = _client()
        tgt = _addr(target)
        # 快路径依赖 RIP 相对编码，x86 下算出的目标是错的 → 明说，别给假结论
        if not deep:
            try:
                if client.debugee_bitness() == 32:
                    return ("xref 快路径只解析 x64 的 RIP 相对寻址；当前调试对象是 32 位。"
                            "32 位请用 deep=True（按反汇编结果匹配绝对地址操作数），"
                            f"或 find_bytes 搜 {tgt & 0xFFFFFFFF:08X} 的小端字节。")
            except Exception:
                pass
        lo, length = _default_range(client, start, size)
        if deep:
            import time
            _t0 = time.time()
            hits = _xref_deep(client, lo, length, tgt, max_hits)
            _elapsed = time.time() - _t0
            # 慢的时候别只给结果，顺手教一次怎么变快（这类提示不该写进 docstring）
            _hint = ""
            if _elapsed >= 10:
                _hint = (f"\n[deep 扫了 {_elapsed:.0f}s / {length:,} 字节 —— 下次用 "
                         f"start+size 限定区间，或先 find_bytes 定位候选段]")
            if not hits:
                return f"No xref to {_fmt(tgt)} in {_fmt(lo)}+{length:,} (deep){_hint}"
            lines = [f"{len(hits)} xref(s) to {_fmt(tgt)} (deep):"]
            for va in hits:
                ins = client.disassemble_at(va)
                lines.append(f"  {_fmt(va)}  {ins.symbolized_instruction if ins else '???'}")
            return "\n".join(lines) + _hint
        hits, seen = [], set()
        chunk = 0x10000
        addr = lo
        end = lo + min(length, _MAX_SCAN)
        while addr < end and len(hits) < max_hits:
            n = min(chunk + 16, end - addr)
            if n < 16:
                break
            try:
                buf = client.read_memory(addr, n)
            except Exception:
                addr += chunk
                continue
            pos = 0
            while True:
                idx = -1
                for b in _RIP_FIRST:
                    k = buf.find(bytes((b,)), pos)
                    if k != -1 and (idx == -1 or k < idx):
                        idx = k
                if idx == -1 or idx > len(buf) - 8:
                    break
                i, j = idx, idx
                if 0x40 <= buf[j] <= 0x4F:      # REX
                    j += 1
                if j >= len(buf):
                    break
                op = buf[j]
                if op == 0xFF:                  # call/jmp r/m64 -> /2, /4
                    modrm_pos = j + 1
                    if modrm_pos >= len(buf) or buf[modrm_pos] not in (0x15, 0x25):
                        pos = i + 1
                        continue
                    imm = 0
                elif op in _RIP_OP_IMM:
                    modrm_pos = j + 1
                    if modrm_pos >= len(buf):
                        pos = i + 1
                        continue
                    imm = _RIP_OP_IMM[op]
                else:
                    pos = i + 1
                    continue
                if (buf[modrm_pos] & 0xC7) != 0x05:   # mod=00, rm=101
                    pos = i + 1
                    continue
                if modrm_pos + 5 > len(buf):
                    break
                insn_len = (modrm_pos - i) + 1 + 4 + imm
                disp = int.from_bytes(buf[modrm_pos + 1:modrm_pos + 5], "little", signed=True)
                insn_va = addr + i
                if insn_va + insn_len + disp == tgt and insn_va not in seen:
                    seen.add(insn_va)
                    hits.append(insn_va)
                    if len(hits) >= max_hits:
                        break
                pos = i + insn_len
            addr += max(1, len(buf) - 16)
        if not hits:
            return f"No xref to {_fmt(tgt)} in {_fmt(lo)}+{length:,}"
        lines = [f"{len(hits)} xref(s) to {_fmt(tgt)}:"]
        for va in hits:
            ins = client.disassemble_at(va)
            lines.append(f"  {_fmt(va)}  {ins.symbolized_instruction if ins else '???'}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


def modules() -> str:
    """
    列出已加载模块（基址 / 大小 / 名称）。
    """
    try:
        client = _client()
        groups: dict[int, dict] = {}

        def _mod_name(info: str) -> str:
            # memmap 的 info 在模块首页是模块名，其余页是节名（形如 ' ".text"'）
            s = (info or "").strip()
            if not s or s[0] in ('"', "'"):
                return ""
            return s

        for p in _image_pages(client):
            cand = _mod_name(p.info)
            g = groups.setdefault(p.allocation_base,
                                  {"name": "", "lo": p.base_address,
                                   "hi": p.base_address + p.region_size})
            g["lo"] = min(g["lo"], p.base_address)
            g["hi"] = max(g["hi"], p.base_address + p.region_size)
            if not cand:
                continue
            at_base = p.base_address == p.allocation_base
            looks_mod = cand.lower().endswith((".exe", ".dll", ".sys", ".drv"))
            if at_base or looks_mod or not g["name"]:
                g["name"] = cand
        if not groups:
            return "No image pages (未调试或在系统空间暂停)"
        lines = [f"{len(groups)} module(s):"]
        for base_addr, g in sorted(groups.items()):
            raw = g["name"].strip().strip('"')
            name = os.path.basename(raw) or f"<unknown {_fmt(base_addr)}>"
            lines.append(f"  {_fmt(base_addr)}-{_fmt(g['hi'])}  {name}  ({g['hi'] - base_addr:,} bytes)")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


def disasm_json(address: str, count: int = 25, skip: int = 0) -> str:
    """
    反汇编 N 条指令，返回结构化 JSON（每条含 addr/size/text，另有 next 指针）。
    """
    try:
        client = _client()
        addr = _addr(address)
        count = max(1, min(count, 200))
        cur = addr
        for _ in range(max(0, skip)):
            ins = client.disassemble_at(cur)
            if ins is None:
                return json.dumps({"start": _fmt(addr), "instructions": [], "next": None,
                                   "error": f"反汇编失败于 {_fmt(cur)}"})
            cur += ins.instr_size
        items = []
        for _ in range(count):
            ins = client.disassemble_at(cur)
            if ins is None:
                break
            items.append({"addr": _fmt(cur), "size": ins.instr_size,
                          "text": ins.symbolized_instruction})
            cur += ins.instr_size
        return json.dumps({"start": items[0]["addr"] if items else _fmt(cur),
                           "instructions": items, "next": _fmt(cur) if items else None})
    except Exception as e:
        return f"Error: {e}"


def exec_command_out(command: str, log_lines: int = 8) -> str:
    """
    执行 x64dbg 命令；失败时附带最近 log_lines 行日志，便于定位原因。
    """
    try:
        client = _client()
        ok = client.cmd_sync(command)
        if ok:
            return f"OK: {command}"
        tail: list[str] = []
        want = max(1, log_lines)
        try:
            _, first, remaining, _ = client.get_log(0, 1, "")
            total = len(first) + max(0, remaining)
            _, msgs, _, _ = client.get_log(max(0, total - want), 0, "")
        except Exception:
            _, msgs, _, _ = client.get_log(0, 0, "")
        lines = [ln for m in msgs for ln in m.splitlines() if ln.strip()]
        tail = lines[-want:]
        out = [f"FAILED: {command}"]
        out += tail if tail else ["(无日志可查；可尝试 get_log 或 GUI 日志窗口)"]
        return "\n".join(out)
    except Exception as e:
        return f"Error: {e}"


def local_patch_info() -> str:
    """
    返回本地补丁版本、包路径与已注册的本地扩展工具（确认补丁是否加载）。
    """
    import x64dbg_automate
    return "\n".join([
        f"patch: {PATCH}",
        f"mcp layer: {_base()._XAUTO_MCP_PATCH}",
        f"package: {os.path.dirname(x64dbg_automate.__file__)}",
        f"python: {sys.version.split()[0]}",
        f"local tools ({len(LOCAL_TOOLS)}): {', '.join(LOCAL_TOOLS)}",
    ])


def register(mcp) -> None:
    """Register every local tool on the given FastMCP instance."""
    for fn in (skip_call, send_stdin, read_console, find_bytes, find_string,
               xref, modules, disasm_json, exec_command_out, local_patch_info):
        mcp.tool()(fn)
        LOCAL_TOOLS.append(fn.__name__)
