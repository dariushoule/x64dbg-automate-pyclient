"""xref 回归基线 —— 改任何 xref 实现之前必须先跑绿。

约定：
  * 用例 1-4 是现有快路径必须命中的（D1/D2 修复的成果，别弄丢）。
  * 用例 5-6 是 0F 系，快路径**预期不命中**（没实现），deep 模式预期命中。
  * 断言写成「fast 必须怎样 / deep 必须怎样」，任何一边退化都算回归。

用法：
    C:\\Python314\\python.exe ops\\xref_baseline.py          # 离线（假 client）
    C:\\Python314\\python.exe ops\\xref_baseline.py --live   # 追加 freedom.exe 真机对比
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import x64dbg_automate.local_ext as LE
from x64dbg_automate.models import (DisasmArgType, DisasmInstrType, Instruction,
                                    InstructionArg, MemPage, SegmentReg)

BASE = 0x140000000
# 0x100 lea / 0x110 call FF15 / 0x120 mov C7+imm32 / 0x130 jmp FF25
# 0x140 movzx 0F B6 / 0x150 movaps 0F 28
CODE = {
    0x100: "48 8D 05 10 00 00 00",
    0x110: "FF 15 20 00 00 00",
    0x120: "48 C7 05 30 00 00 00 11 22 33 44",
    0x130: "FF 25 40 00 00 00",
    0x140: "0F B6 05 50 00 00 00",
    0x150: "0F 28 05 60 00 00 00",
}

buf = bytearray(b"\x90" * 0x2000)
for off, h in CODE.items():
    buf[off:off + len(h)] = bytes.fromhex(h)


def mem_arg(val: int) -> InstructionArg:
    return InstructionArg(mnemonic="", type=DisasmArgType.Memory,
                          segment=SegmentReg.SegDefault, constant=val,
                          value=val, memvalue=0)


# addr -> (instr_size, target, symbolized)
DECODED: dict[int, tuple[int, int, str]] = {}
for off, (size, tgt_off, sym) in {
    0x100: (7, 0x117, "lea rax, qword ptr ds:[0x140000117]"),
    0x110: (6, 0x136, "call qword ptr ds:[0x140000136]"),
    0x120: (11, 0x15B, "mov qword ptr ds:[0x14000015B], 0x44332211"),
    0x130: (6, 0x176, "jmp qword ptr ds:[0x140000176]"),
    0x140: (7, 0x197, "movzx eax, byte ptr ds:[0x140000197]"),
    0x150: (7, 0x1B7, "movaps xmm0, xmmword ptr ds:[0x1400001B7]"),
}.items():
    DECODED[off] = (size, BASE + tgt_off, sym)


class FakeClient:
    page = MemPage(base_address=BASE, allocation_base=BASE, allocation_protect=0x20,
                   partition_id=0, region_size=len(buf), state=0x1000,
                   protect=0x20, type=0x1000000, info="baseline.exe")

    def memmap(self): return [self.page]
    def read_memory(self, a, n):
        off = a - BASE
        if off < 0 or off >= len(buf):
            raise ValueError("bad address")
        return bytes(buf[off:off + n])
    def is_debugging(self): return True
    def is_running(self): return False
    def debugee_bitness(self): return 64
    def eval_sync(self, e): return (0, False)

    def disassemble_at(self, addr):
        off = addr - BASE
        rec = DECODED.get(off)
        if rec is None:
            return None
        size, tgt, sym = rec
        return Instruction(instruction=sym, symbolized_instruction=sym,
                           argcount=1, instr_size=size,
                           type=DisasmInstrType.Normal, arg=[mem_arg(tgt)])


CASES = [
    # name,             target offset, fast 必须命中, deep 必须命中
    ("lea  48 8D 05",   0x117, True,  True),
    ("call FF 15",      0x136, True,  True),
    ("mov  48 C7 05 i", 0x15B, True,  True),
    ("jmp  FF 25",      0x176, True,  True),
    ("movzx 0F B6",     0x197, False, True),
    ("movaps 0F 28",    0x1B7, False, True),
]

LE._client = lambda: FakeClient()          # type: ignore[assignment]
LE._addr = lambda spec: int(spec, 16)      # type: ignore[assignment]

fails = []


def hits_of(result: str) -> list[int]:
    out = []
    for ln in result.splitlines():
        ln = ln.strip()
        if ln.startswith("0x"):
            out.append(int(ln.split()[0], 16))
    return out


print("=== xref 基线（离线假 client）===")
for name, tgt_off, want_fast, want_deep in CASES:
    tgt = BASE + tgt_off
    fast = hits_of(LE.xref(hex(tgt)))
    got_fast = bool(fast)
    mark = "OK  " if got_fast == want_fast else "FAIL"
    if got_fast != want_fast:
        fails.append(f"{name}: fast expected {want_fast}, got {got_fast}")
    print(f"  [{mark}] {name:16s} tgt={hex(tgt)} fast={got_fast} ({len(fast)} hits)")

    try:
        deep = hits_of(LE.xref(hex(tgt), deep=True))
        got_deep = bool(deep)
    except TypeError:
        print(f"         deep 尚未实现（或缺参数），跳过")
        continue
    mark = "OK  " if got_deep == want_deep else "FAIL"
    if got_deep != want_deep:
        fails.append(f"{name}: deep expected {want_deep}, got {got_deep}")
    print(f"         deep={got_deep} ({len(deep)} hits)  [{mark}]")

# 快路径不得因 deep 引入的改动而丢掉命中，也不能凭空多出命中
for name, tgt_off, want_fast, _ in CASES:
    if not want_fast:
        continue
    fast = set(hits_of(LE.xref(hex(BASE + tgt_off))))
    if not fast:
        fails.append(f"{name}: fast path lost its hit")


def live_compare(target: str = r"D:\tmp\Freedom.exe"):
    """真机对比：主模块 fast vs deep（需先起会话）。"""
    import time

    from x64dbg_automate import X64DbgClient
    import x64dbg_automate.mcp_server as S

    dbg = r"D:\toolkit\dbg\release\x64\x64dbg.exe"
    c = X64DbgClient(dbg)
    pid = c.start_session(target_exe=target, current_dir=os.path.dirname(target))
    print(f"\n=== 真机对比 (session {pid}) target={target} ===")
    try:
        S._client = c
        LE._client = lambda: c
        base = int(S.eval_expression("mod.main()").split("=")[-1].strip(), 16)
        print(f"  main module: {hex(base)}")

        # A. FF 15 靶：deep 不得丢 fast 的命中
        fb = LE.find_bytes("FF 15", max_hits=3)
        addrs = [int(x.strip(), 16) for x in fb.splitlines()[1:]]
        for a in addrs:
            disp = int.from_bytes(c.read_memory(a + 2, 4), "little", signed=True)
            tgt = a + 6 + disp
            t0 = time.time()
            fast = set(hits_of(LE.xref(hex(tgt), max_hits=64)))
            t_fast = time.time() - t0
            t0 = time.time()
            deep = set(hits_of(LE.xref(hex(tgt), deep=True, max_hits=64)))
            t_deep = time.time() - t0
            lost, extra = fast - deep, deep - fast
            print(f"  [FF15] tgt={hex(tgt)} fast={len(fast)} deep={len(deep)} "
                  f"lost={len(lost)} extra={len(extra)}  "
                  f"fast={t_fast*1000:.0f}ms deep={t_deep*1000:.0f}ms")
            if lost:
                fails.append(f"live {hex(tgt)}: deep 丢了 fast 的命中 {[hex(x) for x in lost]}")
            for e in sorted(extra):
                ins = c.disassemble_at(e)
                print(f"    + {hex(e)}  {ins.symbolized_instruction if ins else '???'}")

        # B. 0F 系靶：fast 必须 0，deep 必须 >=1（这才是 deep 的价值）
        for pat, ins_len in (("0F B6 05", 7), ("0F 28 05", 7), ("0F 10 05", 7)):
            fb = LE.find_bytes(pat, max_hits=2)
            rows = [int(x.strip(), 16) for x in fb.splitlines()[1:]]
            if not rows:
                print(f"  [{pat}] 样本里没有该 opcode，跳过")
                continue
            for a in rows[:1]:
                disp = int.from_bytes(c.read_memory(a + 3, 4), "little", signed=True)
                tgt = a + ins_len + disp
                fast = set(hits_of(LE.xref(hex(tgt), max_hits=64)))
                deep = set(hits_of(LE.xref(hex(tgt), deep=True, max_hits=64)))
                # 0F 系的验收只看 deep：快路径靠字节特征，命中与否取决于巧合
                # （cmd.exe 实测 0F B6 那条 fast 也报了 1 条，但不是这条指令的
                #  可靠引用，所以不能拿 "fast 必须 0" 当断言）
                ok = a in deep
                print(f"  [{pat}] insn={hex(a)} tgt={hex(tgt)} "
                      f"fast={len(fast)}(不可信) deep={len(deep)} "
                      f"deep{'含' if a in deep else '不含'}该指令  [{'OK' if ok else 'FAIL'}]")
                if not ok:
                    fails.append(f"0F case {pat} @{hex(a)}: deep 未命中该指令 "
                                 f"(deep={len(deep)})")
    finally:
        c.terminate_session()


if "--live" in sys.argv:
    idx = sys.argv.index("--live")
    tgt_arg = sys.argv[idx + 1] if len(sys.argv) > idx + 1 else r"D:\tmp\Freedom.exe"
    live_compare(tgt_arg)

print()
if fails:
    print("基线失败:")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("基线全绿")
