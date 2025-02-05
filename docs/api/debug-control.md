# Debug Control

### What is Debug Control?

Debug control refers to performing actions that change the state of the running debugger. 

Examples include:

- Loading/unloading a debugee
- Transitioning from stopped to running or visa-versa
- Switching thread contexts
- Single-stepping
- Running until return

It's helpful to think of changing the debuggers state as two-steps:

1. Requesting the change in state
2. Waiting for the expected state

Without explicit waits its easy to end up with race conditions and poor repeatability in scripts. 

```
# Good
client.set_breakpoint(0x00401000, singleshoot=True)
client.go()
client.wait_for_debug_event(EventType.EVENT_BREAKPOINT)
    # Retrieved RIP after debugger reached target state
print(client.get_reg('eip'))

# Bad
client.set_breakpoint(0x00401000, singleshoot=True)
client.go()
    # Retrieved RIP without wait. It's possible to read an unintended value before the breakpoint is hit
print(client.get_reg('eip'))
```

### Example: Debug Control

```python
"""
Example: Debug Control (32/64 bit)
"""
import sys
from x64dbg_automate import X64DbgClient

if len(sys.argv) != 2:
    print("Usage: python sessions.py <x64dbg_path>")
    quit(1)

print('[+] Creating the x64dbg Automate session')
client = X64DbgClient(x64dbg_path=sys.argv[1])
client.start_session()

print('[+] Loading notepad and asking it to open a file')
client.load_executable('C:\\Windows\\System32\\notepad.exe', 'C:\\Users\\desktop.ini')

print('[+] Resuming from system breakpoint')
client.go()

print('[+] Waiting until the debugee is stopped at the entrypoint')
client.wait_until_stopped()

print('[+] Stepping-in 3 times')
client.stepi(3)

print('[+] Resuming from entrypoint + 3 step-ins')
client.go()

print('[+] Pausing the debugee')
client.pause()

print('[+] Resuming the debugee')
client.go()

print('[+] Unloading notepad')
client.unload_executable()

print('[+] Detaching the session')
client.detach_session()
```

```
[+] Creating the x64dbg Automate session
[+] Loading notepad and asking it to open a file
[+] Resuming from system breakpoint
[+] Waiting until the debugee is stopped at the entrypoint
[+] Stepping-in 3 times
[+] Resuming from entrypoint + 3 step-ins
[+] Pausing the debugee
[+] Resuming the debugee
[+] Unloading notepad
[+] Detaching the session
```

### API Method Reference

::: x64dbg_automate.X64DbgClient.load_executable
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.unload_executable
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.go
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.pause
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.stepi
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.stepo
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.skip
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.ret
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.thread_create
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.thread_terminate
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.thread_pause
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.thread_resume
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.switch_thread
    options:
        show_root_heading: true
        show_root_full_path: false
