"""
Example: Attach to a Running Process with x64dbg
"""
import subprocess
import sys
from x64dbg_automate import X64DbgClient

if len(sys.argv) != 2:
    print("Usage: python attach.py <x64dbg_path>")
    quit(1)

x64dbg_path = sys.argv[1]

print("[+] Spawning winver.exe")
proc = subprocess.Popen([r"c:\Windows\system32\winver.exe"], executable=r"c:\Windows\system32\winver.exe")

print(f"[+] winver.exe started with PID: {proc.pid}")

print("[+] Starting x64dbg session")
client = X64DbgClient(x64dbg_path=x64dbg_path)
client.start_session()

print("[+] Attaching to winver.exe")
if client.attach(proc.pid):
    print("[+] Successfully attached to winver.exe")
else:
    print("[-] Failed to attach to winver.exe")
    quit(1)

print("[+] Listing running x64dbg sessions")
sessions = X64DbgClient.list_sessions()
print(sessions)

print("[+] Detaching from winver.exe")
client.detach()

print("[+] Terminating x64dbg session")
client.terminate_session()

print("[+] Done")
