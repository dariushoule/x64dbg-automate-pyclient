from x64dbg_automate_pyclient import X64DbgClient
from x64dbg_automate_pyclient.models import BreakpointType, DisasmArgType, DisasmInstrType, SegmentReg


def test_dbg_eval_not_debugging(client: X64DbgClient):
    client.start_session()
    assert client.dbg_eval_sync('9*9') == [81, True]
    assert client.dbg_eval_sync('9*') == [0, False]


def test_dbg_eval_debugging(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.dbg_eval_sync('9*9') == [81, True]
    assert client.dbg_eval_sync('9*') == [0, False]
    addr, success = client.dbg_eval_sync('GetModuleHandleA+1')
    assert success
    assert addr > 0


def test_dbg_command_exec_sync(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.dbg_cmd_sync('sto') == True
    assert client.wait_cmd_ready() == True
    assert client.dbg_cmd_sync('bad_command') == False


def test_dbg_memmap(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    mm = client.get_memmap()
    assert len(mm) > 1
    assert mm[0].base_address > 0
    assert mm[0].region_size > 0
    assert isinstance(mm[0].info, str)


def test_gui_refresh_views(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.gui_refresh_views() == True


def test_valid_read_ptr(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    addr, success = client.dbg_eval_sync('GetModuleHandleA')
    assert success
    assert client.check_valid_read_ptr(addr)
    assert client.check_valid_read_ptr(0) == False


def test_disassemble(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    rip = client.get_reg('rip')
    assert client.write_memory(rip, b'\x90\xeb\xfe')
    instr = client.disassemble_at(rip)
    assert instr.instruction == 'nop'
    instr = client.disassemble_at(rip+1)
    assert instr.instruction == f'jmp 0x{rip+1:016X}'
    assert instr.type == DisasmInstrType.Branch
    assert instr.argcount == 1
    assert instr.instr_size == 2
    assert instr.arg[0].mnemonic == f'{rip+1:X}'
    assert instr.arg[0].constant == rip+1
    assert instr.arg[0].value == rip+1
    assert instr.arg[0].type == SegmentReg.SegDefault
    assert instr.arg[1].mnemonic == f''


def test_assemble(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    rip = client.get_reg('rip')
    assert client.assemble_at(rip, 'mov rax, 0x45678ABCDEF54321')
    assert client.read_memory(rip, 10) == bytes.fromhex('48 B8 21 43 F5 DE BC 8A 67 45')


def test_get_breakpoints(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.clear_breakpoint()
    rip = client.get_reg('rip')
    assert client.write_memory(rip, b'\x90\x90\x90\x90')
    assert client.set_breakpoint(rip+3)
    bps = client.get_breakpoints(BreakpointType.BpNormal)
    assert len(bps) == 1
    assert bps[0].type == BreakpointType.BpNormal
    assert bps[0].addr == rip+3
