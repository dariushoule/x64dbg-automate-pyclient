import subprocess
import threading
import zmq

from abc import ABC, abstractmethod


class XAutoClientBase(ABC):
    proc: subprocess.Popen | None
    context: zmq.Context | None
    req_socket: zmq.SyncSocket | None
    sub_socket: zmq.SyncSocket | None
    sub_thread: threading.Thread
    x64dbg_path: str | None
    xauto_session_id: int | None

    @abstractmethod
    def _send_request(self, request_type: str, *args):
        pass
