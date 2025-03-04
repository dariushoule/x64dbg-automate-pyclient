"""
Example: Populate Reference View (32/64 bit)
"""
import sys
from x64dbg_automate import X64DbgClient
from x64dbg_automate.models import ReferenceViewRef

if len(sys.argv) != 2:
    print("Usage: python sessions.py <x64dbg_path>")
    quit(1)

client = X64DbgClient(x64dbg_path=sys.argv[1])
client.start_session(r'c:\Windows\system32\winver.exe')

print('[+] Creating a reference view')
client.gui_show_reference_view(
    'Example Reference View', [
        ReferenceViewRef(
            address=client.eval_sync('cip')[0],
            text='Example Reference 1: "Current Instruction Pointer"'
        ),
        ReferenceViewRef(
            address=client.eval_sync('IsDebuggerPresent')[0],
            text='Example Reference 2: "IsDebuggerPresent"'
        )
    ]
)

print('[+] Cleaning up')
client.detach_session()
