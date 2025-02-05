# Installation

### Step 1: Plugin

Download the latest plugin release from [https://github.com/dariushoule/x64dbg-automate/releases](https://github.com/dariushoule/x64dbg-automate/releases)

Extract the contents of the archive into your debugger's plugin directory, creating it as needed.

| Install directory | Bitness |
| ----------------- | ------- |
| x64dbg\release\x64\plugins | 64-bit |
| x64dbg\release\x32\plugins | 32-bit |

### Step 2: Client Library

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