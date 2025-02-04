# x64dbg Automate Home

x64dbg Automate is a plugin + client library that adds enhanced scripting and automation capabilities to x64dbg.

<p align="center">
<img src="art.png" alt="Python + x64dbg homepage graphic"/>
</p>

The heart of this project is the native plugin that externalizes the bridge and scripting interfaces of x64dbg. This allows high-level languages a programatic
interface for debug interaction, which is the foundation on which the Python reference client for x64dbg Automate is built.

## Core Principles

- **First-class Python Support**: Bring your own interpreter to automate debug and analysis tasks.
- **Expanded and Enhanced**: The project provides abstractions on top of debugger functionality to make common tasks easy, and pitfalls rare. 
- **Maintained and Modern**: The project aims to target both the latest x64dbg and Python versions.
- **Clearly Documented**: The features of the software are easy to use and well documented.
- **Extensible**: Build your own client on the plugin's RPC interface and extend x64dbg Automate beyond Python.

## Getting Started

To get started with x64dbg Automate, it's recommended to visit [Installation](installation.md) and [Quickstart](quickstart.md). For ambitious users a 
Hello World may be sufficient to get started.

**Hello World**
```python
"""
Hello x64dbg Automate (64 bit)
"""
import sys
from x64dbg_automate import X64DbgClient

if len(sys.argv) != 2:
    print("Usage: python hello.py <x64dbg_path>")
    quit(1)

print('[+] Creating a new x64dbg Automate session')
client = X64DbgClient(x64dbg_path=sys.argv[1])
client.start_session(r'c:\Windows\system32\winver.exe')

print('[+] Allocating memory in the debugee and writing a string to it')
mem = client.virt_alloc()
client.write_memory(mem, 'x64dbg Automate Rocks!'.encode('utf-16le'))

print('[+] Breakpointing ShellAboutW and running until we hit it')
client.set_breakpoint('ShellAboutW', singleshoot=True)
client.go() # Entrypoint breakpoint
client.wait_until_stopped()
client.go() # ShellAboutW
client.wait_until_stopped()

print('[+] Replacing the ShellAboutW App name with our string')
client.set_reg('rdx', mem)
client.go()

print('[+] Bye bye! Go check out the title bar of the winver window! 🥳')
client.deattach_session()
```

**Output**
```
[+] Creating a new x64dbg Automate session
[+] Allocating memory in the debugee and writing a string to it
[+] Breakpointing ShellAboutW and running until we hit it
[+] Replacing the ShellAboutW App name with our string
[+] Bye bye! Go check out the title bar of the winver window! 🥳
```

![Output in Winver](rocks.png)


## Source

- Plugin Repository: [https://github.com/dariushoule/x64dbg-automate](https://github.com/dariushoule/x64dbg-automate)
- Python Reference Client Repository: [https://github.com/dariushoule/x64dbg-automate-pyclient](https://github.com/dariushoule/x64dbg-automate-pyclient)

## Contributing

I welcome contributions from the community! Please leave issues or suggest features on the GitHub repositories for the project.

## Support

You can reach out to me at darius[at]x64.ooo