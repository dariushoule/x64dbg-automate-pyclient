# Breakpoints

Management of breakpoints are supported nearly completely by x64dbg Automate. 

Software, hardware, and memory breakpoints are usable, but their condition and log components are not yet exposed.


### Example: Breakpoints

```python
"""
Example: Breakpoints (64 bit)
"""
"""
Example: Breakpoints (64 bit)
"""
import sys
from x64dbg_automate import X64DbgClient
from x64dbg_automate.events import EventType

if len(sys.argv) != 2:
    print("Usage: python sessions.py <x64dbg_path>")
    quit(1)

print('[+] Creating the x64dbg Automate session')
client = X64DbgClient(x64dbg_path=sys.argv[1])
client.start_session(r'c:\Windows\system32\winver.exe')

print('[+] Writing shellcode to demonstrate breakpoint features')
sys_entry, _ = client.eval_sync('rip')
i = sys_entry
i = i + client.assemble_at(i, 'mov rax, GetCurrentProcessId')
i = i + client.assemble_at(i, 'call rax')

print('[+] Setting a standard breakpoint at GetCurrentProcessId')
client.set_breakpoint('GetCurrentProcessId', singleshoot=True)
client.go()

print('[+] Waiting until the debugee is stopped at the software breakpoint')
bp = client.wait_for_debug_event(EventType.EVENT_BREAKPOINT)
client.clear_debug_events()
print(f'[+] Breakpoint "{bp.event_data.name}" hit at {bp.event_data.addr:X} with singleshoot={bp.event_data.singleshoot}')

print('[+] Resetting and setting a hardware breakpoint at GetCurrentProcessId')
client.set_reg('rip', sys_entry)
client.set_hardware_breakpoint('GetCurrentProcessId')
client.go()

print('[+] Waiting until the debugee is stopped at the hardware breakpoint')
client.wait_for_debug_event(EventType.EVENT_BREAKPOINT)
client.clear_debug_events()

print('[+] Clearing hardware breakpoint')
client.clear_hardware_breakpoint('GetCurrentProcessId')

print('[+] Resetting and setting a memory breakpoint at GetCurrentProcessId')
client.set_reg('rip', sys_entry)
client.set_memory_breakpoint('GetCurrentProcessId', restore=False)
client.go()

print('[+] Waiting until the debugee is stopped at the memory breakpoint')
client.wait_for_debug_event(EventType.EVENT_BREAKPOINT)
client.clear_debug_events()

print('[+] Cleaning up')
client.terminate_session()
```

```
[+] Creating the x64dbg Automate session
[+] Writing shellcode to demonstrate breakpoint features
[+] Setting a standard breakpoint at GetCurrentProcessId
[+] Waiting until the debugee is stopped at the software breakpoint
[+] Breakpoint "bpx_GetCurrentProcessId" hit at 7FFC973A36E0 with singleshoot=True
[+] Resetting and setting a hardware breakpoint at GetCurrentProcessId
[+] Waiting until the debugee is stopped at the hardware breakpoint
[+] Clearing hardware breakpoint
[+] Resetting and setting a memory breakpoint at GetCurrentProcessId
[+] Waiting until the debugee is stopped at the memory breakpoint
[+] Cleaning up
```


### API Method Reference


::: x64dbg_automate.X64DbgClient.get_breakpoints
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.set_breakpoint
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.set_hardware_breakpoint
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.set_memory_breakpoint
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.clear_breakpoint
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.clear_hardware_breakpoint
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.clear_memory_breakpoint
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.toggle_breakpoint
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.toggle_hardware_breakpoint
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.toggle_memory_breakpoint
    options:
        show_root_heading: true
        show_root_full_path: false


### API Model Reference

::: x64dbg_automate.models.Breakpoint
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false

::: x64dbg_automate.models.BreakpointType
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false

::: x64dbg_automate.models.StandardBreakpointType
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false

::: x64dbg_automate.models.HardwareBreakpointType
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false

::: x64dbg_automate.models.MemoryBreakpointType
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false