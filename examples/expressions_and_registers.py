"""
Example: Expressions and Registers (64 bit)
"""
import sys
from x64dbg_automate import X64DbgClient
from x64dbg_automate.models import RegDump64

if len(sys.argv) != 2:
    print("Usage: python hello64.py <x64dbg_path>")
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
