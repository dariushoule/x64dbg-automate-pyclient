# Installation

### Step 1: Dependencies

Ensure you have the latest Visual C++ Runtime Redistributable. 

Available from Microsoft at: [vc_redist.x64.exe](https://aka.ms/vs/17/release/vc_redist.x64.exe) and [vc_redist.x86.exe](https://aka.ms/vs/17/release/vc_redist.x86.exe) (64 and 32 bit respectively).

### Step 2: Plugin

Download the latest plugin release from [https://github.com/dariushoule/x64dbg-automate/releases](https://github.com/dariushoule/x64dbg-automate/releases)

Extract the entire contents of the archive into your debugger's `plugins` directory, creating it as needed.

| Install directory | Bitness |
| ----------------- | ------- |
| x64dbg\release\x64\plugins | 64-bit |
| x64dbg\release\x32\plugins | 32-bit |

### Step 3: Client Library

```sh
pip install x64dbg_automate --upgrade
```

🔔 Important: The Microsoft Store builds of Python are restricted such that the client library may not function well. Use them at your own risk.


### Troubleshooting

If you receive an error like the following:
```
AssertionError: Incompatible x64dbg plugin and client versions abc != xyz
```

Either your client or plugin is out of date, update them to resolve. 