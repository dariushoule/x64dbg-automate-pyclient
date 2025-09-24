"""
Example: Debug Control (32/64 bit)
"""
import sys
from x64dbg_automate import X64DbgClient

if len(sys.argv) != 2:
    print("Usage: python debug_control.py <x64dbg_path>")
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