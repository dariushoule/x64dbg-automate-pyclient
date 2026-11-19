"""MCP 工具描述体积审计 —— 以 token 为主指标。

为什么用 token 而不是字符：描述统一英文后字符数会翻倍，但 token 反而更少
（中文 51 字 ≈ 43 tok，同义英文 116 字 ≈ 25 tok）。所以字符数只能参考，
判据必须落在 token 上。

用法:
    C:\\Python314\\python.exe ops\\docstring_audit.py                # 清单
    C:\\Python314\\python.exe ops\\docstring_audit.py --assert 60    # 约定 15 个超限即失败
    C:\\Python314\\python.exe ops\\docstring_audit.py --assert-all 200

度量口径：优先 tiktoken(cl100k_base)；没有 tiktoken 时按 en≈len/4、zh≈len/1.2 估算。
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

try:
    import tiktoken
    _ENC = tiktoken.get_encoding("cl100k_base")
    def tokens(text: str) -> int:
        return len(_ENC.encode(text))
    UNIT = "tok(tiktoken)"
except Exception:                                    # pragma: no cover
    def tokens(text: str) -> int:
        ascii_n = sum(1 for c in text if ord(c) < 128)
        return round(ascii_n / 4 + (len(text) - ascii_n) / 1.2)
    UNIT = "tok(est)"

# 本轮收缩的 15 个：值为「中文小作文版」的 token 数（git 46524b4 量得）
TARGETS = {
    "skip_call": 238, "send_stdin": 72, "read_console": 62, "find_bytes": 124,
    "find_string": 28, "xref": 544, "modules": 32, "disasm_json": 84,
    "exec_command_out": 105, "local_patch_info": 83, "run_python": 311,
    "wait_for_event": 226, "toggle_breakpoint": 146, "trace_into": 197,
    "trace_over": 197,
}


async def main() -> int:
    async with cc(S.mcp._mcp_server) as c:
        tools = (await c.list_tools()).tools
    desc = {t.name: (t.description or "").strip() for t in tools}
    tok = {n: tokens(d) for n, d in desc.items()}

    limit = int(sys.argv[sys.argv.index("--assert") + 1]) if "--assert" in sys.argv else None
    limit_all = (int(sys.argv[sys.argv.index("--assert-all") + 1])
                 if "--assert-all" in sys.argv else None)

    print(f"unit: {UNIT}   tools: {len(tools)}\n")
    print(f"{'tool':22s} {'before':>7s} {'after':>6s} {'drop':>7s}")
    before_total = after_total = 0
    rows = []
    for name, before in TARGETS.items():
        after = tok.get(name, -1)
        before_total += before
        after_total += max(after, 0)
        rows.append((name, before, after))
    for name, before, after in sorted(rows, key=lambda r: -(r[1] - r[2])):
        pct = (before - after) / before * 100 if before else 0
        print(f"{name:22s} {before:7d} {after:6d} {pct:6.1f}%")
    pct = (before_total - after_total) / before_total * 100
    print(f"{'15 个合计':22s} {before_total:7d} {after_total:6d} {pct:6.1f}%")

    total_all = sum(tok.values())
    print(f"\n全部 {len(tools)} 个工具描述合计 {total_all:,} {UNIT}")
    worst = sorted(tok.items(), key=lambda kv: -kv[1])[:8]
    print("最长 8 个：" + "  ".join(f"{n}={v}" for n, v in worst))

    rc = 0
    if pct < 75:
        print(f"FAIL: token 降幅 {pct:.1f}% < 75%")
        rc = 1
    if limit is not None:
        over = [(n, tok.get(n, 0)) for n in TARGETS if tok.get(n, 0) > limit]
        if over:
            print(f"FAIL: 约定的 15 个里有超过 {limit} tok 的: {over}")
            rc = 1
    if limit_all is not None:
        over = [(n, v) for n, v in tok.items() if v > limit_all]
        if over:
            print(f"WARN: 全量里超过 {limit_all} tok 的（多为纯上游工具，未动）: {over}")
            rc = 1
    print("PASS" if rc == 0 else "FAILED")
    return rc


raise SystemExit(asyncio.run(main()))
