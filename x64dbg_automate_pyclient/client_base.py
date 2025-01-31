import subprocess
import zmq

from abc import ABC, abstractmethod


class XAutoClientBase(ABC):
    proc: subprocess.Popen | None
    socket: zmq.SyncSocket
    x64dbg_path: str | None
    xauto_session_id: int | None

    @abstractmethod
    def _send_request(self, request_type: str, *args):
        pass
