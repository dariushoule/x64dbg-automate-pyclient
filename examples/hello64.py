"""
Example: Hello x64dbg Automate (64 bit)
"""
import sys
from x64dbg_automate import X64DbgClient

if len(sys.argv) != 2:
    print("Usage: python hello64.py <x64dbg_path>")
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
client.detach_session()
