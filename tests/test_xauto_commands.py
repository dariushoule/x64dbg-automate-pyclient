from tests.conftest import TEST_BITNESS
from x64dbg_automate_pyclient import X64DbgClient
from x64dbg_automate_pyclient.models import BreakpointType, DisasmInstrType, SegmentReg


def test_dbg_eval_not_debugging(client: X64DbgClient):
    client.start_session()
    assert client.eval_sync('9*9') == [81, True]
    assert client.eval_sync('9*') == [0, False]


def test_dbg_eval_debugging(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.eval_sync('9*9') == [81, True]
    assert client.eval_sync('9*') == [0, False]
    addr, success = client.eval_sync('GetModuleHandleA+1')
    assert success
    assert addr > 0


def test_dbg_command_exec_sync(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.cmd_sync('sto') == True
    assert client.wait_cmd_ready() == True
    assert client.cmd_sync('bad_command') == False


def test_dbg_memmap(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    mm = client.memmap()
    assert len(mm) > 1
    assert mm[0].base_address > 0
    assert mm[0].region_size > 0
    assert isinstance(mm[0].info, str)


def test_gui_refresh_views(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.gui_refresh_views() == True


def test_valid_read_ptr(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    addr, success = client.eval_sync('GetModuleHandleA')
    assert success
    assert client.check_valid_read_ptr(addr)
    assert client.check_valid_read_ptr(0) == False


def test_disassemble(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    ip_reg = 'rip' if TEST_BITNESS == 64 else 'eip'
    ip = client.get_reg(ip_reg)
    assert client.write_memory(ip, b'\x90\xeb\xfe')
    instr = client.disassemble_at(ip)
    assert instr.instruction == 'nop'
    instr = client.disassemble_at(ip+1)
    if TEST_BITNESS == 64:
        assert instr.instruction == f'jmp 0x{ip+1:016X}'
    else:
        assert instr.instruction == f'jmp 0x{ip+1:08X}'
    assert instr.type == DisasmInstrType.Branch
    assert instr.argcount == 1
    assert instr.instr_size == 2
    assert instr.arg[0].mnemonic == f'{ip+1:X}'
    assert instr.arg[0].constant == ip+1
    assert instr.arg[0].value == ip+1
    assert instr.arg[0].type == SegmentReg.SegDefault
    assert instr.arg[1].mnemonic == f''


def test_breakpoints_normal(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    ip_reg = 'rip' if TEST_BITNESS == 64 else 'eip'
    assert client.clear_breakpoint()
    assert client.clear_hardware_breakpoint()
    assert client.clear_memory_breakpoint()
    ip = client.get_reg(ip_reg)
    assert client.write_memory(ip, b'\x90\x90\x90\x90')
    assert client.set_breakpoint(ip+3)
    bps = client.get_breakpoints(BreakpointType.BpNormal)
    assert len(bps) == 1
    assert bps[0].type == BreakpointType.BpNormal
    assert bps[0].addr == ip+3
    assert client.toggle_breakpoint(ip+3, False)
    bps = client.get_breakpoints(BreakpointType.BpNormal)
    assert not bps[0].enabled
    assert client.clear_breakpoint()


def test_breakpoints_hardware(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    ip_reg = 'rip' if TEST_BITNESS == 64 else 'eip'
    assert client.clear_breakpoint()
    assert client.clear_hardware_breakpoint()
    assert client.clear_memory_breakpoint()
    ip = client.get_reg(ip_reg)
    assert client.write_memory(ip, b'\x90\x90\x90\x90')
    assert client.set_hardware_breakpoint(ip+3)
    bps = client.get_breakpoints(BreakpointType.BpHardware)
    assert len(bps) == 1
    assert bps[0].type == BreakpointType.BpHardware
    assert bps[0].addr == ip+3
    assert bps[0].enabled
    assert client.toggle_hardware_breakpoint(ip+3, False)
    bps = client.get_breakpoints(BreakpointType.BpHardware)
    assert not bps[0].enabled
    assert client.clear_hardware_breakpoint()


def test_breakpoints_memory(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    ip_reg = 'rip' if TEST_BITNESS == 64 else 'eip'
    assert client.clear_breakpoint()
    assert client.clear_hardware_breakpoint()
    assert client.clear_memory_breakpoint()
    ip = client.get_reg(ip_reg)
    assert client.write_memory(ip, b'\x90\x90\x90\x90')
    assert client.set_memory_breakpoint(ip+3)
    bps = client.get_breakpoints(BreakpointType.BpMemory)
    assert len(bps) == 1
    assert bps[0].type == BreakpointType.BpMemory
    mem = client.virt_query(ip+3)
    assert bps[0].addr == mem.base_address
    assert bps[0].enabled
    assert client.toggle_memory_breakpoint(mem.base_address, False)
    bps = client.get_breakpoints(BreakpointType.BpMemory)
    assert not bps[0].enabled
    assert client.clear_memory_breakpoint()


def test_rw_memory(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    ip_reg = 'rip' if TEST_BITNESS == 64 else 'eip'
    ip = client.get_reg(ip_reg)
    assert client.write_memory(ip, b'\x90\x90\x90\x90')
    assert client.read_memory(ip, 16).startswith(b'\x90\x90\x90\x90')


def test_get_symbol_at(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    x, _ = client.eval_sync('NtQueryInformationProcess')
    assert client.get_symbol_at(x).decoratedSymbol in ('NtQueryInformationProcess', 'ZwQueryInformationProcess')
