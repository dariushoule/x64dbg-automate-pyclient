from x64dbg_automate_pyclient import X64DbgClient


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
