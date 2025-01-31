import subprocess
from tests.conftest import X64DBG_PATH
from x64dbg_automate_pyclient import X64DbgClient


def test_connect(client: X64DbgClient):
    client.start_session()


def test_compat_version(client: X64DbgClient):
    client.start_session()
    client._assert_connection_compat()


def test_debugger(client: X64DbgClient):
    client.start_session()
    assert client.get_debugger_version() > 18 # TODO: what is the lowest version we support?


def test_attach(client: X64DbgClient):
    subprocess.Popen([X64DBG_PATH])
    client.attach_session(1)
