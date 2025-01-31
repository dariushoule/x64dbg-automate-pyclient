from x64dbg_automate_pyclient import X64DbgClient


def test_dbg_eval_not_debugging(client: X64DbgClient):
    client.start_session()
    assert client.dbg_eval('9*9') == [81, True]
    assert client.dbg_eval('9*') == [0, False]


def test_dbg_eval_debugging(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.wait_cmd_ready() == True
    assert client.dbg_eval('9*9') == [81, True]
    assert client.dbg_eval('9*') == [0, False]
    addr, succ = client.dbg_eval('GetModuleHandleA+1')
    assert addr > 0
    assert succ


def test_dbg_command_exec_sync(client: X64DbgClient):
    client.start_session()
    assert client.dbg_cmd_sync(r'init c:\Windows\system32\winver.exe') == True
    assert client.wait_cmd_ready() == True
    assert client.dbg_cmd_sync(r'sto') == True
    assert client.dbg_cmd_sync(r'bad_command') == False


def test_dbg_is_elevated(client: X64DbgClient):
    client.start_session()
    assert client.get_dbg_is_elevated() == False
