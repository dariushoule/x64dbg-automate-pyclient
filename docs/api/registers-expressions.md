# Registers and Expressions

### What is an Expression?

An expression is a statement evaluated in the context of the debugger. It can be as simple as 2+2, or a complex calculation involving symbols, scales, and segments. 
x64dbg Automate provides the debugger's full evaluation capabilities, and adds some convenience methods.

When you request a register in x64dbg Automate it's really just shorthand for evaluating an expression where the only value is your register. This is true unless
a full register dump is requested. This is the exception to the above rule - instead providing a full thread context dump in the format the debugger uses internally. 

The full register dump can be useful for accessing more nuanced parts of thread state, but is generally overkill for common tasks like retrieving a common register value.

### Example: Expressions and Registers

```python
"""
Example: Expressions and Registers (64 bit)
"""
import sys
from x64dbg_automate import X64DbgClient
from x64dbg_automate.models import RegDump64

if len(sys.argv) != 2:
    print("Usage: python expressions_and_registers.py <x64dbg_path>")
    quit(1)

print('[+] Creating a new x64dbg Automate session')
client = X64DbgClient(x64dbg_path=sys.argv[1])
client.start_session(r'c:\Windows\system32\winver.exe')

print('[+] Getting the value of RIP')
rip = client.get_reg('rip')
print(f'\tRIP: 0x{rip:X}')

print('[+] Setting the value of RIP')
client.set_reg('rip', 0x1234)

print('[+] Setting the value of RIP to an expression')
value, _ = client.eval_sync('LoadLibraryA + 0x20')
client.set_reg('rip', value)

print('[+] Setting the value of a subregister')
client.set_reg('rax', 0)
client.set_reg('ah', 0x99)

print('[+] Performing a full register dump')
dump: RegDump64 = client.get_regs()
print(f'\tRIP: 0x{dump.context.rip:X}')
print(f'\tRAX: 0x{dump.context.rax:X}')

print('[+] Cleaning up')
client.terminate_session()
```

```
[+] Creating a new x64dbg Automate session
[+] Getting the value of RIP
        RIP: 0x7FFC97E6142A
[+] Setting the value of RIP
[+] Setting the value of RIP to an expression
[+] Setting the value of a subregister
[+] Performing a full register dump
        RIP: 0x7FFC973C2DA0
        RAX: 0x9900
[+] Cleaning up
```

### API Method Reference

::: x64dbg_automate.X64DbgClient.get_reg
    options:
        show_root_heading: true
        show_root_full_path: false

::: x64dbg_automate.X64DbgClient.get_regs
    options:
        show_root_heading: true
        show_root_full_path: false

::: x64dbg_automate.X64DbgClient.set_reg
    options:
        show_root_heading: true
        show_root_full_path: false

::: x64dbg_automate.X64DbgClient.eval_sync
    options:
        show_root_heading: true
        show_root_full_path: false

::: x64dbg_automate.X64DbgClient.get_symbol_at
    options:
        show_root_heading: true
        show_root_full_path: false


### API Model Reference

::: x64dbg_automate.models.RegDump
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: true

::: x64dbg_automate.models.RegDump64
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: true

::: x64dbg_automate.models.RegDump32
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: true

::: x64dbg_automate.models.Context64
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: true

::: x64dbg_automate.models.Context32
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: true

::: x64dbg_automate.models.X87Fpu
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: true

::: x64dbg_automate.models.Flags
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: true

::: x64dbg_automate.models.FpuReg
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: true

::: x64dbg_automate.models.MxcsrFields
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: true

::: x64dbg_automate.models.X87StatusWordFields
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: true

::: x64dbg_automate.models.X87ControlWordFields
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: true

::: x64dbg_automate.models.Symbol
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: true

::: x64dbg_automate.models.SymbolType
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: true

::: x64dbg_automate.models.MutableRegister
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: true