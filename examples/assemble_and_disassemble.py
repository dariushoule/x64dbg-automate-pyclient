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
