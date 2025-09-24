"""
Example: Breakpoints (64 bit)
"""
import sys
from x64dbg_automate import X64DbgClient
from x64dbg_automate.events import EventType

if len(sys.argv) != 2:
    print("Usage: python breakpoints.py <x64dbg_path>")
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
client.set_memory_breakpoint('GetCurrentProcessId', singleshoot=True)
client.go()

print('[+] Waiting until the debugee is stopped at the memory breakpoint')
client.wait_for_debug_event(EventType.EVENT_BREAKPOINT)
client.clear_debug_events()

print('[+] Cleaning up')
client.terminate_session()