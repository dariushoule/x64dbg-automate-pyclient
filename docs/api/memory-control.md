# Memory Control

### What is Memory Control?

Memory control refers to reading, writing, inspecting, allocating, freeing, and protecting memory. 

### Example: Memory Control

```python
"""
Example: Memory Control (64 bit)
"""
import queue
import sys
from x64dbg_automate import X64DbgClient
from x64dbg_automate.events import DbgEvent, EventType
from x64dbg_automate.models import MemPage, PageRightsConfiguration

if len(sys.argv) != 2:
    print("Usage: python hello64.py <x64dbg_path>")
    quit(1)

print('[+] Creating a new x64dbg Automate session')
client = X64DbgClient(x64dbg_path=sys.argv[1])
client.start_session(r'c:\Windows\system32\winver.exe')
client.go() # Continue from system breakpoint
client.wait_until_stopped()
client.go() # Continue from entrypoint

print('[+] Registering a callback for debug string events')
received: queue.Queue[DbgEvent] = queue.Queue()
callback = lambda x: received.put(x)
client.watch_debug_event(EventType.EVENT_OUTPUT_DEBUG_STRING, callback)

print('[+] Allocating memory for shellcode and debug string')
shellcode = client.virt_alloc()
debug_string = client.virt_alloc()

print('[+] Retrieving memory protection on debug string memory')
mem: MemPage = client.virt_query(debug_string)
print(f'\tMemory Protection: 0x{mem.allocation_protect:X}')

print('[+] Setting memory protection on debug string memory to readonly')
client.virt_protect(debug_string, PageRightsConfiguration.ReadOnly)

print('[+] Writing debug string to debugee memory')
client.write_memory(debug_string, b'https://www.youtube.com/watch?v=FKROYzWRiQ0')

print('[+] Writing shellcode to debugee memory')
i = shellcode
i = i + client.assemble_at(i, 'push rcx')
i = i + client.assemble_at(i, 'push rcx')
i = i + client.assemble_at(i, 'push rcx')
i = i + client.assemble_at(i, 'mov rax, OutputDebugStringA')
i = i + client.assemble_at(i, 'call rax')
i = i + client.assemble_at(i, 'pop rcx')
i = i + client.assemble_at(i, 'pop rcx')
i = i + client.assemble_at(i, 'pop rcx')
i = i + client.assemble_at(i, 'ret')

print('[+] Executing shellcode')
client.thread_create(shellcode, debug_string)

ev = received.get(timeout=4)
print('[+] Received debug string event')
print('\tEvent Type:', ev.event_type)
print('\tlpDebugStringData:', ev.event_data.lpDebugStringData.decode('utf-8').strip('\0'))

print('[+] Freeing memory')
client.virt_free(shellcode)
client.virt_free(debug_string)

print('[+] Retrieving full memory map and finding all *.DLL references')
pages: list[MemPage] = client.memmap()
for page in pages:
    if '.dll' in page.info.lower():
        print(f'\t{page.allocation_base:X} - {page.region_size:X} {page.protect} {page.info}')

print('[+] Terminating the session')
client.terminate_session()
```

```
[+] Creating a new x64dbg Automate session
[+] Registering a callback for debug string events
[+] Allocating memory for shellcode and debug string
[+] Retrieving memory protection on debug string memory
        Memory Protection: 0x40
[+] Setting memory protection on debug string memory to readonly
[+] Writing debug string to debugee memory
[+] Writing shellcode to debugee memory
[+] Executing shellcode
[+] Received debug string event
        Event Type: EVENT_OUTPUT_DEBUG_STRING
        lpDebugStringData: https://www.youtube.com/watch?v=FKROYzWRiQ0
[+] Freeing memory
[+] Retrieving full memory map and finding all *.DLL references
        13B701B0000 - 63000 2 \Device\HarddiskVolume3\Windows\System32\en-US\shell32.dll.mui
        13B70250000 - 3000 2 \Device\HarddiskVolume3\Windows\WinSxS\amd64_microsoft.windows.c..-controls.resources_6595b64144ccf1df_6.0.26100.1591_en-us_541af4fe0fd3faf0\comctl32.dll.mui
        13B70270000 - 3000 2 \Device\HarddiskVolume3\Windows\System32\oleaccrc.dll
        7FFC726F0000 - 1000 2 oleacc.dll
        7FFC77140000 - 1000 2 comctl32.dll
        7FFC80AD0000 - 1000 2 textshaping.dll
        7FFC82A30000 - 1000 2 textinputframework.dll
        7FFC84210000 - 1000 2 winbrand.dll
        7FFC8DA80000 - 1000 2 coreuicomponents.dll
        7FFC903D0000 - 1000 2 coremessaging.dll
        7FFC910D0000 - 1000 2 wintypes.dll
        7FFC92380000 - 1000 2 uxtheme.dll
        7FFC93F10000 - 1000 2 kernel.appcore.dll
        7FFC94620000 - 1000 2 cryptbase.dll
        7FFC95290000 - 1000 2 ucrtbase.dll
        7FFC95470000 - 1000 2 gdi32full.dll
        7FFC955A0000 - 1000 2 win32u.dll
        7FFC955D0000 - 1000 2 kernelbase.dll
        7FFC95990000 - 1000 2 msvcp_win.dll
        7FFC95A40000 - 1000 2 bcryptprimitives.dll
        7FFC95D40000 - 1000 2 shcore.dll
        7FFC95E30000 - 1000 2 gdi32.dll
        7FFC95FD0000 - 1000 2 user32.dll
        7FFC96260000 - 1000 2 combase.dll
        7FFC96A80000 - 1000 2 oleaut32.dll
        7FFC96BB0000 - 1000 2 shell32.dll
        7FFC972C0000 - 1000 2 advapi32.dll
        7FFC97380000 - 1000 2 kernel32.dll
        7FFC97450000 - 1000 2 msctf.dll
        7FFC975B0000 - 1000 2 sechost.dll
        7FFC976D0000 - 1000 2 shlwapi.dll
        7FFC97730000 - 1000 2 clbcatq.dll
        7FFC97860000 - 1000 2 msvcrt.dll
        7FFC97930000 - 1000 2 imm32.dll
        7FFC97970000 - 1000 2 rpcrt4.dll
        7FFC97D40000 - 1000 2 ntdll.dll
[+] Terminating the session
```

### API Method Reference


::: x64dbg_automate.X64DbgClient.write_memory
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.read_memory
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.memmap
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.virt_alloc
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.virt_protect
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.virt_query
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.virt_free
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.memset
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.check_valid_read_ptr
    options:
        show_root_heading: true
        show_root_full_path: false


### API Model Reference

::: x64dbg_automate.models.MemPage
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false

::: x64dbg_automate.models.PageRightsConfiguration
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false