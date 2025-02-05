# Session Control

### What are Sessions?

A session refers to an automation-enabled running instance of x64dbg.

Each instance of the debugger you launch or attach to has a session ID allocated to it. The automation client relies on sessions 
to know which debugger instance to communicate with. For all intents and purposes the session ID is equivalent to the debugger PID.

After launching x64dbg with the plugin installed its session ID and port binds can be seen in the startup log:
```
[x64dbg-automate] Allocated session ID: 12584
[x64dbg-automate] Allocated PUB/SUB port: 49759
[x64dbg-automate] Allocated REQ/REP port: 52085
```

Sessions can also be discovered programmatically - with PIDs, command lines, working directories, and window titles provided for disambiguation.

### Example: Sessions

```python
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
```

```
[+] Creating an x64dbg Automate session using start_session
[+] Starting an unconnected session using subprocess.Popen
[+] Waiting for the unconnected session to start
[+] Listing running sessions
[DebugSession(pid=11396, lockfile_path='C:\\Users\\dariu\\AppData\\Local\\Temp\\xauto_session.11396.lock', cmdline=['C:\\re\\x64dbg_dev\\release\\x64\\x64dbg.exe'], cwd='C:\\re\\x64dbg_dev\\release\\x64', window_title='winver.exe - PID: 30944 - Module: ntdll.dll - Thread: Main Thread 20648 - x64dbg', sess_req_rep_port=54561, sess_pub_sub_port=60710), DebugSession(pid=26000, lockfile_path='C:\\Users\\dariu\\AppData\\Local\\Temp\\xauto_session.26000.lock', cmdline=['C:\\re\\x64dbg_dev\\release\\x64\\x64dbg.exe'], cwd='C:\\re\\x64dbg_dev\\release\\x64', window_title='x64dbg', sess_req_rep_port=53337, sess_pub_sub_port=61219)]
[+] Terminating the first session
[+] Listing running sessions
[DebugSession(pid=26000, lockfile_path='C:\\Users\\dariu\\AppData\\Local\\Temp\\xauto_session.26000.lock', cmdline=['C:\\re\\x64dbg_dev\\release\\x64\\x64dbg.exe'], cwd='C:\\re\\x64dbg_dev\\release\\x64', window_title='x64dbg', sess_req_rep_port=53337, sess_pub_sub_port=61219)]   
[+] Attaching to the second session
[+] Detaching from the second session
[+] Re-attaching to the second session
[+] Terminating the second session
```

### API Method Reference

::: x64dbg_automate.X64DbgClient.start_session
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.attach_session
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.detach_session
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.terminate_session
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.list_sessions
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.wait_for_session
    options:
        show_root_heading: true
        show_root_full_path: false


### API Model Reference

::: x64dbg_automate.models.DebugSession
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false