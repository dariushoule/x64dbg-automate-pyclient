import queue
import time
import pytest
from tests.conftest import TEST_BITNESS
from x64dbg_automate import X64DbgClient
from x64dbg_automate.events import CreateThreadEventData, DbgEvent, EventType, ExceptionEventData
from x64dbg_automate.models import BreakpointType, HardwareBreakpointType, MemoryBreakpointType, PageRightsConfiguration, StandardBreakpointType
from x64dbg_automate.win32 import OpenProcess, CreateRemoteThread, WaitForSingleObject, CloseHandle


def test_stepi(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.stepi(2)
    assert client.stepi(swallow_exceptions=True)
    assert client.stepi(pass_exceptions=True)
    with pytest.raises(ValueError):
        assert client.stepi(pass_exceptions=True, swallow_exceptions=True)


def test_stepo(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.stepo(2)
    assert client.stepo(swallow_exceptions=True)
    assert client.stepo(pass_exceptions=True)
    with pytest.raises(ValueError):
        assert client.stepo(pass_exceptions=True, swallow_exceptions=True)


def test_go_and_pause(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.set_setting_int('Events', 'TlsCallbacks', 0)
    assert client.set_setting_int('Events', 'TlsCallbacksSystem', 0)
    assert client.go()
    assert client.wait_until_stopped()
    assert client.go()
    assert client.pause()


def test_skip(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.skip(2)


def test_ret(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.ret(1)
    assert client.ret(1)


def test_rw_regs(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    ip_reg = 'rip' if TEST_BITNESS == 64 else 'eip'
    if TEST_BITNESS == 64:
        client.set_reg('rax', 0x1234567812345678)
        assert client.get_regs().context.rax == 0x1234567812345678
    else:
        client.set_reg('eax', 0x12345678)
        assert client.get_regs().context.eax == 0x12345678
    client.set_reg('di', 0xB33F)
    assert client.get_reg('di') == 0xB33F
    if TEST_BITNESS == 64:
        assert client.get_regs().context.rdi & 0xFFFF == 0xB33F
    else:
        assert client.get_regs().context.edi & 0xFFFF == 0xB33F
    client.set_reg(ip_reg, 0x1000)
    assert client.get_reg(ip_reg) == 0x1000


def test_memset(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    addr = client.virt_alloc()
    assert addr > 0
    assert client.memset(addr, ord('Z'), 16)
    assert client.read_memory(addr, 16) == b'Z' * 16


def test_virt_query(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    rip = client.get_reg('rip' if TEST_BITNESS == 64 else 'eip')
    page = client.virt_query(rip)
    assert page
    assert page.allocation_base != rip
    assert page.allocation_base % 0x1000 == 0
    assert page.protect == 0x20


def test_virt_protect(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    addr = client.virt_alloc()
    page = client.virt_query(addr)
    assert page
    assert page.protect == 0x40
    assert client.virt_protect(addr, PageRightsConfiguration.NoAccess)
    page = client.virt_query(addr)
    assert page
    assert page.protect == 0x1


def test_breakpoint(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    ip_reg = 'rip' if TEST_BITNESS == 64 else 'eip'
    assert client.clear_breakpoint()
    ip = client.get_reg(ip_reg)
    assert client.write_memory(ip, b'\x90\x90\x90\x90')
    assert client.set_breakpoint(ip+3)
    assert client.go()
    assert client.wait_until_stopped()
    assert client.get_reg(ip_reg) == ip+3
    assert client.clear_breakpoint(ip+3)


def test_breakpoint_ss(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    ip_reg = 'rip' if TEST_BITNESS == 64 else 'eip'
    assert client.clear_breakpoint()
    ip = client.get_reg(ip_reg)
    assert client.write_memory(ip, b'\x90\x90\x90\x90')
    assert client.set_breakpoint(ip+3, singleshoot=True)
    assert client.go()
    assert client.wait_until_stopped()
    assert client.get_reg(ip_reg) == ip+3


def test_label(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    ip_reg = 'rip' if TEST_BITNESS == 64 else 'eip'
    ip = client.get_reg(ip_reg)
    client.del_label_at(ip)
    assert client.get_label_at(ip) == ""
    assert client.set_label_at(ip, "https://www.youtube.com/watch?v=tJ94VwZ51Wo")
    assert client.get_label_at(ip) == "https://www.youtube.com/watch?v=tJ94VwZ51Wo"
    assert client.del_label_at(ip)
    assert client.get_label_at(ip) == ""


def test_comment(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    ip_reg = 'rip' if TEST_BITNESS == 64 else 'eip'
    rip = client.get_reg(ip_reg)
    client.del_comment_at(rip)
    assert client.get_comment_at(rip) == ""
    assert client.set_comment_at(rip, "https://www.youtube.com/watch?v=mNjmGuJY5OE")
    assert client.get_comment_at(rip) == "https://www.youtube.com/watch?v=mNjmGuJY5OE"
    assert client.del_comment_at(rip)
    assert client.get_comment_at(rip) == ""


def test_start_stop(client: X64DbgClient):
    client.start_session()
    assert client.load_executable(r'c:\Windows\system32\winver.exe')
    assert client.unload_executable()


def test_event_queue_inline(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    ip_reg = 'rip' if TEST_BITNESS == 64 else 'eip'
    ip = client.get_reg(ip_reg)
    assert client.write_memory(ip, b'\x90\x90\x90\x90')
    assert client.set_breakpoint(ip+3, singleshoot=True)
    assert client.go()
    assert client.wait_for_debug_event(EventType.EVENT_BREAKPOINT)
    assert client.get_reg(ip_reg) == ip+3
    assert client.clear_breakpoint()


def test_event_queue_callback(client: X64DbgClient):
    received: queue.Queue[DbgEvent] = queue.Queue()
    callback = lambda x: received.put(x)
    client.watch_debug_event(EventType.EVENT_SYSTEMBREAKPOINT, callback)
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert received.get().event_type == EventType.EVENT_SYSTEMBREAKPOINT
    assert received.empty()
    client.unload_executable()
    client.unwatch_debug_event(EventType.EVENT_SYSTEMBREAKPOINT, callback)
    client.load_executable(r'c:\Windows\system32\winver.exe')
    assert received.empty()


def test_event_create_thread(client: X64DbgClient):
    received: queue.Queue[DbgEvent] = queue.Queue()
    callback = lambda x: received.put(x)
    client.watch_debug_event(EventType.EVENT_CREATE_THREAD, callback)
    client.start_session(r'c:\Windows\system32\winver.exe')
    ev = received.get()
    tev: CreateThreadEventData = ev.event_data
    assert ev.event_type == EventType.EVENT_CREATE_THREAD
    assert tev.dwThreadId > 0
    assert tev.lpStartAddress > 0


def test_assemble(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    ip_reg = 'rip' if TEST_BITNESS == 64 else 'eip'
    ip = client.get_reg(ip_reg)
    if TEST_BITNESS == 64:
        assert client.assemble_at(ip, 'mov rax, 0x45678ABCDEF54321') == 10
        assert client.read_memory(ip, 10) == bytes.fromhex('48 B8 21 43 F5 DE BC 8A 67 45')
    else:
        assert client.assemble_at(ip, 'mov eax, 0x45678ABC') == 5
        assert client.read_memory(ip, 5) == bytes.fromhex('B8 BC 8A 67 45')


def test_event_exit_thread(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.set_setting_int('Events', 'TlsCallbacks', 0)
    assert client.set_setting_int('Events', 'TlsCallbacksSystem', 0)
    
    page = client.virt_alloc()
    if TEST_BITNESS == 64:
        mov_siz = client.assemble_at(page, 'mov rax, 0x10101010')
        assert mov_siz == 7
    else:
        mov_siz = client.assemble_at(page, 'mov eax, 0x10101010')
        assert mov_siz == 5
    assert client.assemble_at(page + mov_siz, 'ret') == 1

    client.go()
    client.wait_until_stopped()
    client.go()
    client.wait_until_running()
    client.clear_debug_events(EventType.EVENT_EXIT_THREAD)

    hProc = OpenProcess(0x1fffff, False, client.debugee_pid())
    hThread = CreateRemoteThread(hProc, None, 0, page, None, 0, None)
    WaitForSingleObject(hThread, -1)
    CloseHandle(hThread)
    CloseHandle(hProc)

    ev = client.wait_for_debug_event(EventType.EVENT_EXIT_THREAD, 3)
    assert ev
    assert ev.event_type == EventType.EVENT_EXIT_THREAD
    assert ev.event_data.dwThreadId > 0
    assert ev.event_data.dwExitCode == 0x10101010


def test_event_load_unload_dll(client: X64DbgClient):
    received: queue.Queue[DbgEvent] = queue.Queue()
    callback = lambda x: received.put(x)
    client.watch_debug_event(EventType.EVENT_LOAD_DLL, callback)
    client.watch_debug_event(EventType.EVENT_UNLOAD_DLL, callback)
    client.start_session(r'c:\Windows\system32\winver.exe')
    client.wait_for_debug_event(EventType.EVENT_SYSTEMBREAKPOINT)
    client.go()
    client.wait_until_stopped()
    client.go()

    shellcode = client.virt_alloc()
    sz_dll = client.virt_alloc()
    client.write_memory(sz_dll, r'c:\Windows\system32\lz32.dll'.encode() + b'\0')

    if TEST_BITNESS == 64:
        i = shellcode
        i = i + client.assemble_at(i, f'mov rcx, 0x{sz_dll:x}')
        i = i + client.assemble_at(i, 'mov rax, LoadLibraryA')
        i = i + client.assemble_at(i, 'push rcx')
        i = i + client.assemble_at(i, 'push rcx')
        i = i + client.assemble_at(i, 'push rcx')
        i = i + client.assemble_at(i, 'call rax')
        i = i + client.assemble_at(i, 'mov rdx, FreeLibrary')
        i = i + client.assemble_at(i, 'mov rcx, rax')
        i = i + client.assemble_at(i, 'call rdx')
        i = i + client.assemble_at(i, 'pop rcx')
        i = i + client.assemble_at(i, 'pop rcx')
        i = i + client.assemble_at(i, 'pop rcx')
        i = i + client.assemble_at(i, 'ret')
    else:
        i = shellcode
        i = i + client.assemble_at(i, f'push 0x{sz_dll:x}')
        i = i + client.assemble_at(i, f'push LoadLibraryA')
        i = i + client.assemble_at(i, f'pop eax')
        i = i + client.assemble_at(i, f'call eax')
        i = i + client.assemble_at(i, f'push eax')
        i = i + client.assemble_at(i, f'push FreeLibrary')
        i = i + client.assemble_at(i, f'pop eax')
        i = i + client.assemble_at(i, f'call eax')
        i = i + client.assemble_at(i, 'ret')

    hProc = OpenProcess(0x1fffff, False, client.debugee_pid())
    hThread = CreateRemoteThread(hProc, None, 0, shellcode, None, 0, None)
    WaitForSingleObject(hThread, -1)
    CloseHandle(hThread)
    CloseHandle(hProc)

    modbase = 0
    while True:
        mod = received.get(timeout=3)
        if mod.event_type == EventType.EVENT_LOAD_DLL and mod.event_data.modname == r'lz32.dll':
            assert mod.event_data.lpBaseOfDll > 0
            modbase = mod.event_data.lpBaseOfDll
        elif mod.event_type == EventType.EVENT_UNLOAD_DLL and mod.event_data.lpBaseOfDll == modbase:
            break


def test_event_output_dbg_str(client: X64DbgClient):
    received: queue.Queue[DbgEvent] = queue.Queue()
    callback = lambda x: received.put(x)
    client.watch_debug_event(EventType.EVENT_OUTPUT_DEBUG_STRING, callback)
    client.start_session(r'c:\Windows\system32\winver.exe')
    client.wait_for_debug_event(EventType.EVENT_SYSTEMBREAKPOINT)
    client.go()
    client.wait_until_stopped()
    client.go()

    shellcode = client.virt_alloc()
    sz_str = client.virt_alloc()
    client.write_memory(sz_str, b'duck duck goose')

    if TEST_BITNESS == 64:
        i = shellcode
        i = i + client.assemble_at(i, f'mov rcx, 0x{sz_str:x}')
        i = i + client.assemble_at(i, 'mov rax, OutputDebugStringA')
        i = i + client.assemble_at(i, 'push rcx')
        i = i + client.assemble_at(i, 'push rcx')
        i = i + client.assemble_at(i, 'push rcx')
        i = i + client.assemble_at(i, 'call rax')
        i = i + client.assemble_at(i, 'pop rcx')
        i = i + client.assemble_at(i, 'pop rcx')
        i = i + client.assemble_at(i, 'pop rcx')
        i = i + client.assemble_at(i, 'ret')
    else:
        i = shellcode
        i = i + client.assemble_at(i, f'push 0x{sz_str:x}')
        i = i + client.assemble_at(i, 'push OutputDebugStringA')
        i = i + client.assemble_at(i, 'pop eax')
        i = i + client.assemble_at(i, 'call eax')
        i = i + client.assemble_at(i, 'ret')

    hProc = OpenProcess(0x1fffff, False, client.debugee_pid())
    hThread = CreateRemoteThread(hProc, None, 0, shellcode, None, 0, None)
    WaitForSingleObject(hThread, -1)
    CloseHandle(hThread)
    CloseHandle(hProc)

    ev = received.get(timeout=3)
    assert ev.event_type == EventType.EVENT_OUTPUT_DEBUG_STRING
    assert ev.event_data.lpDebugStringData == b'duck duck goose\0'


def test_event_exception(client: X64DbgClient):
    received: queue.Queue[DbgEvent] = queue.Queue()
    callback = lambda x: received.put(x)
    client.watch_debug_event(EventType.EVENT_EXCEPTION, callback)
    client.start_session(r'c:\Windows\system32\winver.exe')
    client.wait_for_debug_event(EventType.EVENT_SYSTEMBREAKPOINT)

    if TEST_BITNESS == 64:
        i = client.get_reg('rip')
        i = i + client.assemble_at(i, 'mov rcx, 0x1234')
        i = i + client.assemble_at(i, 'call rcx')
    else:
        i = client.get_reg('eip')
        i = i + client.assemble_at(i, 'mov ecx, 0x1234')
        i = i + client.assemble_at(i, 'call ecx')
    client.go()

    ev = received.get(timeout=3)
    xcpt_data: ExceptionEventData = ev.event_data
    assert ev.event_type == EventType.EVENT_EXCEPTION
    assert xcpt_data.ExceptionCode == 0xC0000005
    assert xcpt_data.dwFirstChance == True
    assert xcpt_data.ExceptionAddress == 0x1234
    assert xcpt_data.NumberParameters == 2
    assert xcpt_data.ExceptionInformation == [8, 4660]


def test_debug_hide_peb(client: X64DbgClient):
    received: queue.Queue[DbgEvent] = queue.Queue()
    callback = lambda x: received.put(x)
    client.watch_debug_event(EventType.EVENT_EXCEPTION, callback)
    client.start_session(r'c:\Windows\system32\winver.exe')
    client.wait_for_debug_event(EventType.EVENT_SYSTEMBREAKPOINT)
    assert client.hide_debugger_peb()


def test_thread_control(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    client.wait_for_debug_event(EventType.EVENT_SYSTEMBREAKPOINT)
    client.go()
    client.wait_until_stopped()
    client.go()

    shellcode = client.virt_alloc()
    client.write_memory(shellcode, b'\xeb\xfe') # jmp $-2

    tid = client.thread_create(shellcode)
    time.sleep(.2) # todo: method to check if thread is running?
    assert tid > 0
    assert client.thread_pause(tid)
    assert client.switch_thread(tid)
    assert client.thread_resume(tid)
    assert client.thread_terminate(tid)
    assert client.thread_resume(tid) == False


def test_breakpoint_toggle_and_clear_standard_with_name_and_symbols(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.clear_breakpoint()
    assert client.clear_hardware_breakpoint()
    assert client.clear_memory_breakpoint()

    addr, _ = client.eval_sync('GetCurrentProcessId')
    assert client.set_breakpoint(addr, "charlie", StandardBreakpointType.Short, True)
    bps = client.get_breakpoints(BreakpointType.BpNormal)
    assert len(bps) == 1
    assert bps[0].name == "charlie"
    assert bps[0].type == BreakpointType.BpNormal
    assert bps[0].enabled == True
    assert bps[0].singleshoot == True
    assert bps[0].active == True
    assert bps[0].addr == addr  
    assert bps[0].mod == 'kernel32.dll'
    # TODO: investigate, this may be an issue in x64dbg
    # assert client.toggle_breakpoint("charlie") 
    # assert client.get_breakpoints(BreakpointType.BpNormal)[0].enabled == False
    assert client.toggle_breakpoint("GetCurrentProcessId", False)
    assert client.get_breakpoints(BreakpointType.BpNormal)[0].enabled == False
    assert client.toggle_breakpoint(addr, True)
    assert client.get_breakpoints(BreakpointType.BpNormal)[0].enabled == True
    # TODO: investigate, this may be an issue in x64dbg
    # assert client.clear_breakpoint("charlie")
    assert client.clear_breakpoint("GetCurrentProcessId")
    assert len(client.get_breakpoints(BreakpointType.BpNormal)) == 0
    assert client.set_breakpoint('GetCurrentProcessId', bp_type=StandardBreakpointType.Ud2)
    bps = client.get_breakpoints(BreakpointType.BpNormal)
    assert len(bps) == 1
    assert bps[0].name == "bpx_GetCurrentProcessId"
    assert bps[0].type == BreakpointType.BpNormal
    assert bps[0].enabled == True
    assert client.clear_breakpoint(addr)
    assert len(client.get_breakpoints(BreakpointType.BpNormal)) == 0


def test_breakpoint_toggle_and_clear_hardware_with_name_and_symbols(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.clear_breakpoint()
    assert client.clear_hardware_breakpoint()
    assert client.clear_memory_breakpoint()

    addr, _ = client.eval_sync('GetCurrentProcessId')
    assert client.set_hardware_breakpoint(addr, HardwareBreakpointType.r, 4)
    bps = client.get_breakpoints(BreakpointType.BpHardware)
    assert len(bps) == 1
    assert bps[0].type == BreakpointType.BpHardware
    assert bps[0].enabled == True
    assert bps[0].singleshoot == False
    assert bps[0].active == True
    assert bps[0].addr == addr  
    assert bps[0].hwSize == 2  
    assert bps[0].mod == 'kernel32.dll'

    assert client.toggle_hardware_breakpoint("GetCurrentProcessId", False)
    assert client.get_breakpoints(BreakpointType.BpHardware)[0].enabled == False
    assert client.toggle_hardware_breakpoint(addr, True)
    assert client.get_breakpoints(BreakpointType.BpHardware)[0].enabled == True
    assert client.clear_hardware_breakpoint("GetCurrentProcessId")
    assert len(client.get_breakpoints(BreakpointType.BpHardware)) == 0
    assert client.set_hardware_breakpoint('GetCurrentProcessId', bp_type=HardwareBreakpointType.x)
    bps = client.get_breakpoints(BreakpointType.BpHardware)
    assert len(bps) == 1
    assert bps[0].type == BreakpointType.BpHardware
    assert bps[0].enabled == True
    assert client.clear_hardware_breakpoint(addr)
    assert len(client.get_breakpoints(BreakpointType.BpHardware)) == 0


def test_breakpoint_toggle_and_clear_memory_with_name_and_symbols(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.clear_breakpoint()
    assert client.clear_hardware_breakpoint()
    assert client.clear_memory_breakpoint()

    addr, _ = client.eval_sync('GetCurrentProcessId')
    mem = client.virt_query(addr)
    addr_base = mem.base_address
    assert client.set_memory_breakpoint(addr, MemoryBreakpointType.a, 4)
    bps = client.get_breakpoints(BreakpointType.BpMemory)
    assert len(bps) == 1
    assert bps[0].type == BreakpointType.BpMemory
    assert bps[0].enabled == True
    assert bps[0].singleshoot == True
    assert bps[0].active == True
    assert bps[0].addr == addr_base
    assert bps[0].mod == 'kernel32.dll'

    # TODO: Symbols can't be toggled, only their memory bases (do we try to do this automatically for people?)
    assert client.toggle_memory_breakpoint("GetCurrentProcessId", False) == False
    assert client.get_breakpoints(BreakpointType.BpMemory)[0].enabled == True

    assert client.toggle_memory_breakpoint(addr_base, True)
    assert client.get_breakpoints(BreakpointType.BpMemory)[0].enabled == True

    assert client.clear_memory_breakpoint("GetCurrentProcessId") == False
    assert len(client.get_breakpoints(BreakpointType.BpMemory)) == 1
    assert client.set_memory_breakpoint('GetCurrentProcessId', bp_type=MemoryBreakpointType.x)
    bps = client.get_breakpoints(BreakpointType.BpMemory)
    assert len(bps) == 1
    assert bps[0].type == BreakpointType.BpMemory
    assert bps[0].enabled == True
    client.clear_memory_breakpoint(addr_base)
    assert len(client.get_breakpoints(BreakpointType.BpMemory)) == 0
