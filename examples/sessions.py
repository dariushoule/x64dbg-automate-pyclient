"""
Example: Session Control (32/64 bit)
"""
import subprocess
import sys
import time
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

time.sleep(3) # High-tech synchronization to make sure both sessions are up

print('[+] Listing active sessions')
sessions = X64DbgClient.list_sessions()
print(sessions)

print('[+] Terminating the first session')
client1.terminate_session()

print('[+] Listing active sessions')
sessions = X64DbgClient.list_sessions()
print(sessions)

print('[+] Attaching to the second session')
client2.attach_session(sessions[1])

print('[+] Detaching from the second session')
client2.detach_session()

print('[+] Cleaning up example')
proc.kill()
