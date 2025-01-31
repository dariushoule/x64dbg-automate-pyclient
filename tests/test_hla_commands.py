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
