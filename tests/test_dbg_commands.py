from x64dbg_automate_pyclient import X64DbgClient


def test_dbg_eval(client: X64DbgClient):
    client.start_session()
    assert client.dbg_eval('9*9') == [81, True]
    assert client.dbg_eval('9*') == [0, False]


def test_dbg_command_exec_sync(client: X64DbgClient):
    client.start_session()
    assert client.dbg_cmd_sync(r'init c:\Windows\system32\winver.exe') == True
    assert client.wait_cmd_ready() == True
    assert client.dbg_cmd_sync(r'sto') == True
    assert client.dbg_cmd_sync(r'bad_command') == False
