# GUI Control

User interface control is partially implemented at this point. There exists the ability to trigger a refresh and populate a reference view.

### Example: Populate a Reference View

```python
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
```


### API Method Reference

::: x64dbg_automate.X64DbgClient.log
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.gui_refresh_views
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.gui_show_reference_view
    options:
        show_root_heading: true
        show_root_full_path: false


### API Model Reference

::: x64dbg_automate.models.ReferenceViewRef
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false
