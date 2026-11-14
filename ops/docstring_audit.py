"""MCP 工具描述体积审计 —— 改 docstring 后跑一遍对账。

用法:
    C:\\Python314\\python.exe ops\\docstring_audit.py            # 全量清单
    C:\\Python314\\python.exe ops\\docstring_audit.py --assert 200 # 任一超限即失败

设计依据：description 是唯一无条件进入调用方上下文的文本，但它只该回答
「调用时会不会传错参数 / 选错模式」。历史数据、性能实测、变更记录属于
SKILL.md §8.1，不该塞在这里。
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logging.disable(logging.CRITICAL)

import x64dbg_automate.mcp_server as S
import x64dbg_automate.mcp_server_local  # noqa: F401  register local tools
from mcp.shared.memory import create_connected_server_and_client_session as cc

# 本轮收缩的 15 个（本地新增 + 我们改过描述的），改前字符数作为基线
TARGETS = {
    "skip_call": 418, "send_stdin": 103, "read_console": 84,
    "find_bytes": 205, "find_string": 56, "xref": 858, "modules": 41,
    "disasm_json": 126, "exec_command_out": 131, "local_patch_info": 104,
    "run_python": 1184, "wait_for_event": 997, "toggle_breakpoint": 622,
    "trace_into": 855, "trace_over": 854,
}


async def main() -> int:
    async with cc(S.mcp._mcp_server) as c:
        tools = (await c.list_tools()).tools
    sizes = {t.name: len((t.description or "").strip()) for t in tools}

    limit = None
    if "--assert" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--assert") + 1])
    limit_all = None
    if "--assert-all" in sys.argv:
        limit_all = int(sys.argv[sys.argv.index("--assert-all") + 1])

    print(f"{'tool':24s} {'before':>7s} {'after':>6s} {'drop':>7s}  lines")
    before_total = after_total = 0
    rows = []
    for name, before in TARGETS.items():
        after = sizes.get(name, -1)
        before_total += before
        after_total += max(after, 0)
        rows.append((name, before, after))
    for name, before, after in sorted(rows, key=lambda r: -(r[1] - r[2])):
        pct = (before - after) / before * 100 if before else 0
        print(f"{name:24s} {before:7d} {after:6d} {pct:6.1f}%")
    pct = (before_total - after_total) / before_total * 100
    print(f"{'15 个合计':24s} {before_total:7d} {after_total:6d} {pct:6.1f}%")

    all_total = sum(sizes.values())
    print(f"\n全部 {len(sizes)} 个工具描述合计 {all_total:,} 字符"
          f"（≈{all_total/2.2:.0f} tokens）")

    worst = sorted(sizes.items(), key=lambda kv: -kv[1])[:8]
    print("最长 8 个：" + "  ".join(f"{n}={v}" for n, v in worst))

    rc = 0
    if pct < 75:
        print(f"FAIL: 降幅 {pct:.1f}% < 75%")
        rc = 1
    # --assert 只看本轮约定的 15 个；纯上游工具按设计不动（压它们只会扩大
    # upgrade_upstream 的 rebase 冲突面），要查全量用 --assert-all。
    if limit is not None:
        over = [(n, sizes.get(n, 0)) for n in TARGETS if sizes.get(n, 0) > limit]
        if over:
            print(f"FAIL: 约定的 15 个里有超过 {limit} 字符的: {over}")
            rc = 1
    if limit_all is not None:
        over = [(n, v) for n, v in sizes.items() if v > limit_all]
        if over:
            print(f"WARN: 全量里超过 {limit_all} 字符的（多为纯上游工具，未动）: {over}")
            rc = 1
    print("PASS" if rc == 0 else "FAILED")
    return rc


raise SystemExit(asyncio.run(main()))
