"""
Example: Memory Control (64 bit)
"""
import queue
import sys
from x64dbg_automate import X64DbgClient
from x64dbg_automate.events import DbgEvent, EventType
from x64dbg_automate.models import MemPage, PageRightsConfiguration

if len(sys.argv) != 2:
    print("Usage: python memory_control.py <x64dbg_path>")
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