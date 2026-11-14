"""验证 fork 的三个修 + 本地工具在新结构下仍工作。

cd D:\\od\\x64dbg-automate-fork && C:\\Python314\\python.exe <本文件>
"""
import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.disable(logging.CRITICAL)   # 静音 mcp 的 INFO 请求日志，保持输出可 diff

import x64dbg_automate.mcp_server as S
import x64dbg_automate.local_ext as LE
import x64dbg_automate.mcp_server_local as _entry  # noqa: F401  触发 register()
from x64dbg_automate.models import MemPage
from mcp.shared.memory import create_connected_server_and_client_session as cc

print("=== 1. 工具总数（上游 + 本地）===")
async def tools():
    async with cc(S.mcp._mcp_server) as c:
        names = [t.name for t in (await c.list_tools()).tools]
        print("  total:", len(names), "| local present:",
              all(n in names for n in LE.LOCAL_TOOLS))
        print("  local:", ", ".join(LE.LOCAL_TOOLS))

print("=== 2. A1: toggle_breakpoint 参数别名 ===")
async def a1():
    async with cc(S.mcp._mcp_server) as c:
        for args in ({"address": "0x1000", "on": False},
                     {"address": "0x1000", "enable": False},
                     {"address": "0x1000", "enable": True, "on": False}):
            r = await c.call_tool("toggle_breakpoint", args)
            print(f"  {args} -> {[x.text for x in r.content][0][:70]}")

print("=== 3. A2: wait_for_event 新参数在 schema 里 ===")
async def a2():
    async with cc(S.mcp._mcp_server) as c:
        for t in (await c.list_tools()).tools:
            if t.name == "wait_for_event":
                props = t.inputSchema.get("properties", {})
                default = props.get("drain_first", {}).get("default")
                print("  props:", sorted(props), "| drain_first default:", default)
                assert default is False, (
                    "drain_first must default to False: with True, a go->wait call "
                    f"drops the breakpoint that hit while it was in flight (measured "
                    f"on freedom.exe 2026-11-14). got {default!r}")

print("=== 4. local_patch_info ===")
print("  " + LE.local_patch_info().replace("\n", "\n  "))

print("=== 5. xref 修好的实现（假 client，三类 RIP 相对）===")
BASE = 0x140000000
buf = bytearray(b"\x90" * 0x2000)
def put(o, h): buf[o:o + len(h)] = bytes.fromhex(h)
put(0x100, "48 8D 05 10 00 00 00")
put(0x110, "FF 15 20 00 00 00")
put(0x120, "48 C7 05 30 00 00 00 11 22 33 44")

class Fake:
    page = MemPage(base_address=BASE, allocation_base=BASE, allocation_protect=0x20,
                   partition_id=0, region_size=len(buf), state=0x1000,
                   protect=0x20, type=0x1000000, info="t.exe")
    def memmap(self): return [self.page]
    def read_memory(self, a, n): return bytes(buf[a - BASE:a - BASE + n])
    def disassemble_at(self, a): return None
    def is_debugging(self): return True
    def is_running(self): return False
    def eval_sync(self, e): return (0, False)
    def toggle_breakpoint(self, target, on=True):
        print(f"      -> client.toggle_breakpoint(target={target}, on={on})")
        return True

S._client = Fake()
for name, tgt in [("lea 48 8D 05", 0x117), ("call FF 15", 0x136), ("mov 48 C7 05 imm", 0x15B)]:
    print(f"  {name:18s} -> " + LE.xref(hex(BASE + tgt)).replace("\n", "\n" + " " * 22))

print("=== 6. 地址解析：算式修复 ===")
class ExprFake(Fake):
    def eval_sync(self, e): return (BASE + 0x10, True) if e == "0x140000000+0x10" else (0, False)
S._client = ExprFake()
print("  0x140000000+0x10 ->", hex(S._parse_address_or_expression("0x140000000+0x10")))

asyncio.run(tools())
asyncio.run(a1())
asyncio.run(a2())

print("=== 7. pause 不再假成功：无 debuggee 时必须 False ===")
from x64dbg_automate import X64DbgClient

class NoDebuggee:
    def is_debugging(self): return False
    def is_running(self): return False
    def cmd_sync(self, cmd):
        raise AssertionError(f"pause must not send a command without a debuggee, got {cmd!r}")

r = X64DbgClient.pause(NoDebuggee())
print("  is_debugging=False ->", r)
assert r is False, f"pause returned {r!r}, p2 returned True here (false success)"

