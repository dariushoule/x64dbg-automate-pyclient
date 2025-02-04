# Session Control

### Sessions

A session refers to an automation-enabled running instance of x64dbg.

Each instance of the debugger you launch or attach to has a session ID allocated to it. The automation client relies on sessions 
to know which debugger instance to communicate with. 

After launching x64dbg with the plugin installed its session ID can be seen in the debug log:
```
[x64dbg-automate] Allocated session id: 1
```

### Example: Sessions

```python
"""
Example: Session Control (32/64 bit)
"""
...

```


### API Reference

::: x64dbg_automate.X64DbgClient.start_session
    options:
        show_root_heading: true


::: x64dbg_automate.X64DbgClient.attach_session
    options:
        show_root_heading: true


::: x64dbg_automate.X64DbgClient.detach_session
    options:
        show_root_heading: true


::: x64dbg_automate.X64DbgClient.terminate_session
    options:
        show_root_heading: true


::: x64dbg_automate.X64DbgClient.list_sessions
    options:
        show_root_heading: true