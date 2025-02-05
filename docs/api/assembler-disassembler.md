# Assembling and Disassembling

The Assembler and Disassembler features of x64dbg are supported in Automate. Symbols and expressions are supported in the assembler as they are in the UI.


### Example: Assemble and Disassemble

```python
"""
Example: Assemble and Disassemble (64 bit)
"""
import sys
from x64dbg_automate import X64DbgClient

if len(sys.argv) != 2:
    print("Usage: python hello64.py <x64dbg_path>")
    quit(1)

print('[+] Creating a new x64dbg Automate session')
client = X64DbgClient(x64dbg_path=sys.argv[1])
client.start_session(r'c:\Windows\system32\winver.exe')

print('[+] Getting the value of RIP')
rip = client.get_reg('rip')
print(f'\tRIP: 0x{rip:X}')

print('[+] Assembling instructions')
k32_base, _ = client.eval_sync('kernel32')
client.set_label_at(k32_base, 'my_cool_label')

i = rip
i = i + client.assemble_at(i, 'mov rax, OutputDebugStringA') # Symbol
i = i + client.assemble_at(i, 'mov rdx, 0x401000') # Constant
i = i + client.assemble_at(i, 'mov rcx, my_cool_label') # Label
i = i + client.assemble_at(i, 'lea rcx, [rcx * 2 + 4]') # Scale
i = i + client.assemble_at(i, 'mov rbx, gs:[0]') # Segmentation
i = i + client.assemble_at(i, f'mov rdi, 0x{client.virt_alloc():x}') # Interpolation

print('[+] Disassembling instructions')
i = rip
for _ in range(6):
    ins = client.disassemble_at(i)
    print(f'\t{i:016X}: {ins.instruction}')
    i = i + ins.instr_size

print('[+] Cleaning up')
client.terminate_session()
```

```
[+] Creating a new x64dbg Automate session
[+] Getting the value of RIP
        RIP: 0x7FF962D4C135
[+] Assembling instructions
[+] Disassembling instructions
        00007FF962D4C135: mov rax, 0x7FF961A698C0
        00007FF962D4C13F: mov rdx, 0x401000
        00007FF962D4C146: mov rcx, 0x7FF961A50000
        00007FF962D4C150: lea rcx, ds:[rcx*2+0x04]
        00007FF962D4C158: mov rbx, qword ptr gs:[0x0000000000000000]
        00007FF962D4C161: mov rdi, 0x21CBEDC0000
[+] Cleaning up
```

### API Method Reference


::: x64dbg_automate.X64DbgClient.assemble_at
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.disassemble_at
    options:
        show_root_heading: true
        show_root_full_path: false


### API Model Reference

::: x64dbg_automate.models.Instruction
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false


::: x64dbg_automate.models.DisasmInstrType
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false


::: x64dbg_automate.models.DisasmArgType
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false


::: x64dbg_automate.models.InstructionArg
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false

::: x64dbg_automate.models.SegmentReg
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false