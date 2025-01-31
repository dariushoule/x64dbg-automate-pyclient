import subprocess
from tests.conftest import X64DBG_PATH
from x64dbg_automate_pyclient import X64DbgClient


def test_connect(client: X64DbgClient):
    client.start_session()


def test_attach(client: X64DbgClient):
    subprocess.Popen([X64DBG_PATH])
    client.attach_session(1)
