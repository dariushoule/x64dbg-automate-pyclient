"""
Example: Session Control (32/64 bit)
"""
import subprocess
import sys
from x64dbg_automate import X64DbgClient

if len(sys.argv) != 2:
    print("Usage: python sessions.py <x64dbg_path>")
    quit(1)

print('[+] Creating an x64dbg Automate session using start_session')
client1 = X64DbgClient(x64dbg_path=sys.argv[1])
client1.start_session(r'c:\Windows\system32\winver.exe')

print('[+] Starting an unconnected session using subprocess.Popen')
client2 = X64DbgClient(x64dbg_path=sys.argv[1])
proc = subprocess.Popen([sys.argv[1]], executable=sys.argv[1])

print('[+] Waiting for the unconnected session to start')
X64DbgClient.wait_for_session(proc.pid)

print('[+] Listing running sessions')
sessions = X64DbgClient.list_sessions()
print(sessions)

print('[+] Terminating the first session')
client1.terminate_session()

print('[+] Listing running sessions')
sessions = X64DbgClient.list_sessions()
print(sessions)

print('[+] Attaching to the second session')
client2.attach_session(sessions[0].pid)

print('[+] Detaching from the second session')
client2.detach_session()

print('[+] Re-attaching to the second session')
client2.attach_session(sessions[0].pid)

print('[+] Terminating the second session')
client2.terminate_session()
