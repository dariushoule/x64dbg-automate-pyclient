"""Protocol-level tests for the MCP server.

test_mcp_server.py calls the tool functions directly; these drive the server through a
real MCP client instead, so tool registration, schemas, result encoding and the stdio
transport are covered too. No running x64dbg required.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters

import x64dbg_automate.mcp_server as mcp_mod

pytestmark = pytest.mark.anyio

CORE_TOOLS = {
    "list_sessions", "start_session", "connect_to_session", "connect_remote",
    "terminate_session", "read_memory", "eval_expression",
}
STDIO_SERVER = StdioServerParameters(command=sys.executable, args=["-m", "x64dbg_automate.mcp_server"])


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def test_tools_register_with_schemas():
    async with Client(mcp_mod.mcp) as client:
        tools = (await client.list_tools()).tools

    names = {t.name for t in tools}
    assert CORE_TOOLS <= names, f"missing: {CORE_TOOLS - names}"
    for tool in tools:
        assert tool.description, f"{tool.name} has no description"
        assert tool.input_schema.get("type") == "object", f"{tool.name} has no object input schema"


async def test_tool_call_round_trips():
    with patch.object(mcp_mod.X64DbgClient, "list_sessions", return_value=[]):
        async with Client(mcp_mod.mcp) as client:
            result = await client.call_tool("list_sessions", {})

    assert not result.is_error
    assert result.content[0].text == "No active x64dbg sessions found."


async def test_tool_failure_is_an_mcp_error_result():
    """A failing tool returns is_error=True carrying its own message, which the SDK prefixes
    with the tool name (a non-ToolError would arrive with the message stripped), and the
    session survives for the next call."""
    with patch.object(mcp_mod, "_client", None):
        async with Client(mcp_mod.mcp) as client:
            result = await client.call_tool("read_memory", {"address": "0x1000", "size": 16})
            with patch.object(mcp_mod.X64DbgClient, "list_sessions", return_value=[]):
                followup = await client.call_tool("list_sessions", {})

    assert result.is_error
    assert result.content[0].text.startswith("Error executing tool read_memory: Not connected to x64dbg")
    assert not followup.is_error


async def test_operation_reporting_failure_is_an_mcp_error_result():
    """A debugger call that returns False (not an exception) is an error result too."""
    debugger = MagicMock()
    debugger.go.return_value = False
    with patch.object(mcp_mod, "_client", debugger):
        async with Client(mcp_mod.mcp) as client:
            result = await client.call_tool("go", {})

    assert result.is_error
    assert result.content[0].text == "Error executing tool go: Failed to resume."


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_stdio_server(mode: str):
    """The installed entry point serves both the 2026-07-28 protocol and the 2025-era
    (legacy, initialize-handshake) protocol that older clients speak."""
    async with Client(STDIO_SERVER, mode=mode) as client:
        tools = (await client.list_tools()).tools
        version = client.protocol_version

    assert CORE_TOOLS <= {t.name for t in tools}
    if mode == "legacy":
        assert not version.startswith("2026"), f"legacy mode negotiated {version}"
