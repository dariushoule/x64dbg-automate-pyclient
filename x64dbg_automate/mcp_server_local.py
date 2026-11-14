"""MCP server entry point: upstream tools + local extensions.

    python -m x64dbg_automate.mcp_server_local

Since 0.9.2+local.3 this module is a thin registrar — the tools themselves live in
``local_ext.py`` and every former monkey-patch now lives in the source it belongs to:

* address/expression parsing fix -> ``mcp_server._parse_address_or_expression``
* blocking-state pause fallback  -> ``X64DbgClient.pause`` (``hla_xauto.py``)
* ``toggle_breakpoint(on=...)`` alias / ``wait_for_event(drain_first=...)``
  -> ``mcp_server.py``

Nothing is rebound at import time any more, so a stale ``site-packages`` copy can no
longer shadow the real implementation.
"""

from __future__ import annotations

from x64dbg_automate import local_ext
from x64dbg_automate.mcp_server import mcp

local_ext.register(mcp)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
