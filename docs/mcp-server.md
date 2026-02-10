# MCP Server

### What is the MCP Server?

The x64dbg Automate MCP server exposes the debugger's capabilities as [Model Context Protocol](https://modelcontextprotocol.io/) tools. This allows LLM clients like Claude Code to directly control x64dbg for reverse engineering, malware analysis, and debugging tasks.

The MCP server wraps the same Python API documented in the Client Reference sections, so all the same functionality is available.

### Installation

Install the client library with the `mcp` extra:

```sh
pip install x64dbg_automate[mcp] --upgrade
```

### Claude Code Configuration

Add the following to your Claude Code MCP settings. You can do this via the CLI:

```sh
claude mcp add x64dbg -- x64dbg-automate-mcp
```

Or manually create/edit `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "x64dbg-automate-mcp"
    }
  }
}
```

Restart Claude Code after adding the configuration. You will be prompted to approve the MCP server on first use.

### Available Tools

The MCP server provides ~40 tools organized into the following groups:

| Group | Tools | Description |
|-------|-------|-------------|
| Session | `list_sessions`, `start_session`, `connect_to_session`, `disconnect`, `terminate_session` | Manage debugger instances |
| Debug Control | `go`, `pause`, `step_into`, `step_over`, `skip_instruction`, `run_to_return`, `get_debugger_status` | Control execution |
| Memory | `read_memory`, `write_memory`, `allocate_memory`, `free_memory`, `get_memory_map` | Read/write debuggee memory |
| Registers | `get_register`, `set_register`, `get_all_registers` | Register access |
| Expressions | `eval_expression`, `execute_command` | x64dbg expression evaluator and raw commands |
| Breakpoints | `set_breakpoint`, `clear_breakpoint`, `toggle_breakpoint`, `list_breakpoints` | Software, hardware, and memory breakpoints |
| Assembly | `disassemble`, `assemble` | Disassemble and assemble instructions |
| Annotations | `set_label`, `get_label`, `set_comment`, `get_comment`, `get_symbol` | Labels, comments, and symbol lookup |
| Threads | `create_thread`, `terminate_thread`, `pause_resume_thread`, `switch_thread` | Thread management |
| Events | `get_latest_event`, `wait_for_event` | Debug event queue |
| Settings | `get_setting`, `set_setting` | x64dbg configuration |
| GUI | `log_message`, `refresh_gui` | Debugger UI interaction |

### Walkthrough: Debugging with Claude

This walkthrough demonstrates a typical analysis session using the MCP server from Claude Code. The x64dbg plugin must be installed and the MCP server configured as described above.

**Step 1: Start a session**

Ask Claude to start a debug session:

```
Launch x64dbg from C:\x64dbg\release and debug C:\targets\to_analyze.exe
```

Claude will call `start_session` with your x64dbg path and target executable. 

**Step 2: Explore the target**

Ask Claude to look around:

```
Disassemble the first 20 instructions at the entry point
```

Claude will call `disassemble` with `RIP` as the address (resolved via x64dbg's expression evaluator), giving you annotated disassembly output.

```
Show me the memory map and read 256 bytes at RSP
```

Claude will call `get_memory_map` and `read_memory`, returning a hex dump with ASCII sidebar.

**Step 3: Set breakpoints and run**

```
Set a breakpoint on MessageBoxA and resume execution
```

Claude will call `set_breakpoint` with the symbol name and then `go` to resume.

**Step 4: Inspect state at a breakpoint**

```
Show me all registers and disassemble 10 instructions at the current position
```

Claude will call `get_all_registers` and `disassemble` with `RIP`, giving you a full picture of the current state.

**Step 5: Modify and continue**

```
Write 0x90 0x90 (NOPs) at 0x401032 and step over 5 instructions
```

Claude will call `write_memory` to patch the bytes and `step_over` to advance.

**Step 6: Clean up**

```
Disconnect from the debugger
```

Claude will call `disconnect`, leaving x64dbg running for manual inspection, or `terminate_session` to close it entirely.

### Tips

- **Let Claude drive**: Describe your analysis goal in plain language. Claude can chain multiple tools together to investigate, set breakpoints, read memory, and modify state.
- **Expressions work everywhere**: Any tool that takes an address also accepts registers, symbols, and arithmetic expressions — just like the x64dbg command bar.
- **Memory reads are capped**: `read_memory` is limited to 4096 bytes per call and `disassemble` to 100 instructions. Ask for multiple reads if you need more.
- **Events for synchronization**: Use `wait_for_event` to wait for breakpoints, DLL loads, or other debug events before inspecting state.
- **Raw commands**: If a feature isn't exposed as a dedicated tool, `execute_command` passes any command directly to x64dbg's command interpreter. See the [x64dbg command reference](https://help.x64dbg.com/en/latest/commands/).
