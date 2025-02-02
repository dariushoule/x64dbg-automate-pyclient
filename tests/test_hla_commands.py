import pytest
from x64dbg_automate_pyclient import X64DbgClient


def test_stepi(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.stepi(2) == True
    assert client.stepi(swallow_exceptions=True) == True
    assert client.stepi(pass_exceptions=True) == True
    with pytest.raises(ValueError):
        assert client.stepi(pass_exceptions=True, swallow_exceptions=True)


def test_stepo(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.stepo(2) == True
    assert client.stepo(swallow_exceptions=True) == True
    assert client.stepo(pass_exceptions=True) == True
    with pytest.raises(ValueError):
        assert client.stepo(pass_exceptions=True, swallow_exceptions=True)


def test_go_and_pause(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.set_setting_int('Events', 'TlsCallbacks', 0) == True
    assert client.set_setting_int('Events', 'TlsCallbacksSystem', 0) == True
    assert client.go() == True
    assert client.wait_until_stopped() == True
    assert client.go() == True
    assert client.pause() == True
    assert client.wait_until_stopped() == True


def test_skip(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.skip(2) == True


def test_ret(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.ret(1) == True
    assert client.ret(1) == True


def test_rw_regs(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    client.set_reg('rax', 0x1234567812345678)
    assert client.get_regs().context.rax == 0x1234567812345678
    client.set_reg('di', 0xB33F)
    assert client.get_reg('di') == 0xB33F
    assert client.get_regs().context.rdi & 0xFFFF == 0xB33F


def test_rw_memory(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    rip = client.get_reg('rip')
    assert client.write_memory(rip, b'\x90\x90\x90\x90')
    assert client.read_memory(rip, 16).startswith(b'\x90\x90\x90\x90')


def test_memset(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    addr = client.virt_alloc()
    assert addr > 0
    assert client.memset(addr, ord('Z'), 16)
    assert client.read_memory(addr, 16) == b'Z' * 16
