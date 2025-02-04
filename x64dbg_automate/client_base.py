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
    session_pid: int | None
    sess_req_rep_port = 0
    sess_pub_sub_port = 0

    @abstractmethod
    def _send_request(self, request_type: str, *args):
        pass
