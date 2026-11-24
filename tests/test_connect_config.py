import os
import subprocess
import sys
from pathlib import Path

import psutil
import pytest

import x64dbg_automate
from tests.conftest import TEST_BITNESS, X64DBG_PATH
from x64dbg_automate import X64DbgClient
import time

BOGUS_COMPAT_VERSION = "not_a_real_codename"

# Run in a child interpreter so the test observes what a user script does after a
# rejected handshake: whether the process can exit at all. A leaked non-daemon
# thread shows up here as a hang, which an in-process test can't see.
REJECTED_HANDSHAKE_SCRIPT = f"""
import sys
import x64dbg_automate
from x64dbg_automate import X64DbgClient

x64dbg_automate.COMPAT_VERSION = {BOGUS_COMPAT_VERSION!r}
client = X64DbgClient(x64dbg_path=sys.argv[1])
try:
    client.start_session()
except AssertionError as e:
    print(e)
    sys.exit(0)
print("start_session unexpectedly succeeded")
sys.exit(1)
"""


def _debugger_pids(exe: str) -> set[int]:
    target = os.path.normcase(os.path.abspath(exe))
    pids = set()
    for p in psutil.process_iter(["pid", "exe"]):
        if p.info["exe"] and os.path.normcase(p.info["exe"]) == target:
            pids.add(p.info["pid"])
    return pids


def _kill_all(pids: set[int]) -> None:
    for pid in pids:
        try:
            psutil.Process(pid).kill()
        except psutil.NoSuchProcess:
            pass


def test_connect(client: X64DbgClient):
    client.start_session()


def test_reconnect(client: X64DbgClient):
    sid = client.start_session()
    client.detach_session()
    client.attach_session(sid)


def test_compat_version(client: X64DbgClient):
    client.start_session()
    client._assert_connection_compat()


def test_rejected_handshake_exits_cleanly(x64dbg_path: str):
    """start_session() against an incompatible plugin raises, lets the interpreter exit,
    and doesn't leave the x64dbg it launched running."""
    before = _debugger_pids(x64dbg_path)
    leaked: set[int] = set()
    try:
        result = subprocess.run(
            [sys.executable, "-c", REJECTED_HANDSHAKE_SCRIPT, x64dbg_path],
            cwd=Path(__file__).parent.parent, capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("client process hung after the rejected compat handshake")
    finally:
        leaked = _debugger_pids(x64dbg_path) - before
        _kill_all(leaked)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Incompatible x64dbg plugin and client versions" in result.stdout
    assert not leaked, f"launched x64dbg left running after rejection: {leaked}"


def test_rejected_handshake_on_attach_leaves_debugger_running(client: X64DbgClient, monkeypatch):
    """Attaching to an x64dbg the caller already had running: a rejected handshake tears down
    the connection but must not kill that debugger, and the client stays reusable."""
    proc = subprocess.Popen([X64DBG_PATH])
    try:
        client.wait_for_session(proc.pid)
        monkeypatch.setattr(x64dbg_automate, "COMPAT_VERSION", BOGUS_COMPAT_VERSION)
        with pytest.raises(AssertionError, match="Incompatible x64dbg plugin and client versions"):
            client.attach_session(proc.pid)

        assert client.req_socket is None and client.sub_socket is None
        assert not client.sub_thread.is_alive()
        time.sleep(1)
        assert proc.poll() is None, "an x64dbg the client didn't launch must not be terminated"

        monkeypatch.undo()
        client.attach_session(proc.pid)  # fixture teardown terminates it
        assert not client.is_debugging()
    except BaseException:
        proc.kill()
        raise


def test_bitness(client: X64DbgClient):
    client.start_session()
    assert client.debugee_bitness() == TEST_BITNESS


def test_debugger_version(client: X64DbgClient):
    client.start_session()
    assert client.get_debugger_version() > 18 # TODO: what is the lowest version we support?


def test_dbg_is_elevated(client: X64DbgClient):
    client.start_session()
    assert client.debugger_is_elevated() == False


def test_dbg_is_debugging(client: X64DbgClient):
    client.start_session()
    assert client.is_debugging() == False
    assert client.load_executable(r'c:\Windows\system32\winver.exe') == True
    assert client.is_debugging() == True


def test_dbg_is_running(client: X64DbgClient):
    client.start_session(r'c:\Windows\system32\winver.exe')
    assert client.is_running() == False
    assert client.cmd_sync('g') == True
    assert client.is_running() == True


def test_dbg_load_cwd(client: X64DbgClient):
    client.start_session(r'winver.exe', "", r'c:\Windows\system32')
    assert client.is_running() == False
    assert client.cmd_sync('g') == True
    assert client.is_running() == True


def test_dbg_load_shortpath(client: X64DbgClient):
    os.chdir(r'c:\Windows\system32')
    client.start_session(r'winver.exe')
    assert client.is_running() == False
    assert client.cmd_sync('g') == True
    assert client.is_running() == True


def test_config_get_set(client: X64DbgClient):
    client.start_session()
    assert client.get_setting_str('Shortcuts', 'ActionFind') == 'Ctrl+F'
    assert client.set_setting_str('Shortcuts', 'ActionFind', 'Ctrl+G') == True
    assert client.get_setting_str('Shortcuts', 'ActionFind') == 'Ctrl+G'
    assert client.set_setting_int('Deleted Tabs', 'BreakpointsTab', 9000) == True
    assert client.get_setting_int('Deleted Tabs', 'BreakpointsTab') == 9000


def test_attach_session(client: X64DbgClient):
    proc = subprocess.Popen([X64DBG_PATH])
    client.wait_for_session(proc.pid)
    client.attach_session(proc.pid)
    assert client.is_debugging() == False


def test_attach_debugee_1(client: X64DbgClient):
    if TEST_BITNESS == 32:
        debugee_proc = subprocess.Popen([r"c:\Windows\SysWOW64\winver.exe"], executable=r"c:\Windows\SysWOW64\winver.exe")
    else:
        debugee_proc = subprocess.Popen([r"c:\Windows\system32\winver.exe"], executable=r"c:\Windows\system32\winver.exe")
    client.start_session_attach(debugee_proc.pid)
    assert client.is_debugging() == True
    assert client.is_running() == True
    time.sleep(1.2) # High-tech synchronization primitive
    assert client.eval_sync('winver')[0] > 0
    assert client.detach() == True
    assert client.wait_until_not_debugging() == True
    debugee_proc.terminate()
    debugee_proc.wait()


def test_attach_debugee_2(client: X64DbgClient):
    if TEST_BITNESS == 32:
        debugee_proc = subprocess.Popen([r"c:\Windows\SysWOW64\winver.exe"], executable=r"c:\Windows\SysWOW64\winver.exe")
    else:
        debugee_proc = subprocess.Popen([r"c:\Windows\system32\winver.exe"], executable=r"c:\Windows\system32\winver.exe")
    client.start_session()
    client.attach(debugee_proc.pid)
    assert client.is_debugging() == True
    assert client.is_running() == True
    time.sleep(1.2) # High-tech synchronization primitive
    assert client.eval_sync('winver')[0] > 0
    assert client.detach() == True
    assert client.wait_until_not_debugging() == True
    debugee_proc.terminate()
    debugee_proc.wait()
