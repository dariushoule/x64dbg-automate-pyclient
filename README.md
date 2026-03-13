# x64dbg Automate: Reference Python Client

This is the reference client of x64dbg Automate. The library builds on x64dbg's command execution engine and plugin API to provide an expressive, modern, and easy to use Python client. x64dbg Automate is useful in a wide variety of malware analysis, reverse engineering, and vulnerability hunting tasks. 

The client implements the full RPC protocol provided by [x64dbg-automate](https://github.com/dariushoule/x64dbg-automate). 

## Documentation

Full project documentation is published on: [https://dariushoule.github.io/x64dbg-automate-pyclient/](https://dariushoule.github.io/x64dbg-automate-pyclient/)

See: [Installation](https://dariushoule.github.io/x64dbg-automate-pyclient/installation/) and [Quickstart](https://dariushoule.github.io/x64dbg-automate-pyclient/quickstart/)

🔔 _All examples and sample code assume x64dbg is configured to stop on entry and system breakpoints, skipping TLS breakpoints._

## MCP Server (Claude Code Integration)

The MCP server exposes x64dbg automation as [Model Context Protocol](https://modelcontextprotocol.io/) tools for LLM clients like Claude Code.

### Installation

```sh
pip install x64dbg_automate[mcp] --upgrade
```

### Configuration

Add to your `.mcp.json` (project or user level):

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "x64dbg-automate-mcp",
      "env": {
        "X64DBG_PATH": "C:\\path\\to\\x96dbg.exe"
      }
    }
  }
}
```

Setting `X64DBG_PATH` lets the MCP tools resolve x64dbg automatically — no need to pass the path on every `start_session` or `connect_to_session` call.

**For local development**, use `uv` to run from source:

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "uv",
      "args": [
        "run",
        "--directory", "C:\\path\\to\\x64dbg-automate-pyclient",
        "--extra", "mcp",
        "x64dbg-automate-mcp"
      ],
      "env": {
        "X64DBG_PATH": "C:\\path\\to\\x96dbg.exe"
      }
    }
  }
}
```

See the [MCP Server documentation](https://dariushoule.github.io/x64dbg-automate-pyclient/mcp-server/) for the full tool reference and usage walkthrough.

## Development and Testing

The client's environment is managed with [poetry](https://python-poetry.org/docs/).

Update `tests/conftest.py` or provide the requisite environment to allow tests to pass.

```powershell
poetry install
poetry env activate
python -m pytest # Test
python .\examples\assemble_and_disassemble.py C:\<you>\x64dbg\release\x64\x64dbg.exe # Run an example
```

**Documentation is built using mkdocs**

```powershell
python -m mkdocs serve # dev
python -m mkdocs build # publish
```

# Contributing

Issues, feature-requests, and pull-requests are welcome on this project ❤️🐛

My commitment to the community will be to be a responsive maintainer. Discuss with me before implementing major breaking changes or feature additions.