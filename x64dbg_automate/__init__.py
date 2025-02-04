import ctypes
import logging
import subprocess
import threading
import time
import msgpack
import zmq

from x64dbg_automate.events import DebugEventQueueMixin
from x64dbg_automate.hla_xauto import XAutoHighLevelCommandAbstractionMixin
from x64dbg_automate.win32 import OpenMutexW, CloseHandle, SYNCHRONIZE, SetConsoleCtrlHandler


COMPAT_VERSION = "bitter_oyster" # TODO: externalize
logger = logging.getLogger(__name__)
all_instances: list['X64DbgClient'] = []


def ctrl_c_handler(sig_t: int) -> bool:
    print(f'Received exit signal {sig_t}, detaching and exiting', flush=True)
    for i in all_instances:
        i.deattach_session()
    import sys
    sys.exit(0)
    return True
ctrl_c_handler = SetConsoleCtrlHandler.argtypes[0](ctrl_c_handler)
SetConsoleCtrlHandler(ctrl_c_handler, True)


class ClientConnectionFailedError(Exception):
    pass

class X64DbgClient(XAutoHighLevelCommandAbstractionMixin, DebugEventQueueMixin):
    def __init__(self, x64dbg_path: str):
        self.x64dbg_path = x64dbg_path
        self.xauto_session_id = None
        self.context = None
        self.req_socket = None
        self.sub_socket = None
        all_instances.append(self)

    def __del__(self):
        all_instances.remove(self)
    
    @property
    def SESS_REQ_REP_PORT(self) -> int:
        return 41600 + self.xauto_session_id
    
    @property
    def SESS_PUB_SUB_PORT(self) -> int:
        return 51600 + self.xauto_session_id
    
    def _sub_thread(self):
        while True:
            try:
                if self.context is None:
                    break
                msg = msgpack.unpackb(self.sub_socket.recv())
                self.debug_event_publish(msg)
            except zmq.error.ContextTerminated:
                # This session has been detached, exit thread
                break
            except zmq.error.ZMQError:
                if self.context is None:
                    logger.exception("Socket terminated, exiting thread")
                    break
                else:
                    logger.exception("Unhandled ZMQError, retrying")

    
    def _init_connection(self):
        if self.context is not None:
            self._close_connection()

        self.context = zmq.Context()
        self.req_socket = self.context.socket(zmq.REQ)
        self.req_socket.setsockopt(zmq.SNDTIMEO, 5000)
        self.req_socket.setsockopt(zmq.RCVTIMEO, 10000)
        self.req_socket.connect(f"tcp://localhost:{self.SESS_REQ_REP_PORT}")
        self.req_socket.send(msgpack.packb("PING"))
        if msgpack.unpackb(self.req_socket.recv()) != "PONG":
            raise ClientConnectionFailedError(f"Connection to x64dbg failed on port {self.SESS_REQ_REP_PORT}")
        
        self.sub_socket = self.context.socket(zmq.SUB)
        self.req_socket.setsockopt(zmq.RCVTIMEO, 6000)
        self.sub_socket.connect(f"tcp://localhost:{self.SESS_PUB_SUB_PORT}")
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, "")
        self.sub_thread = threading.Thread(target=self._sub_thread)
        self.sub_thread.start()

    def _close_connection(self):
        if self.context is None:
            return
        self.context.destroy()
        self.context = None
        self.req_socket = None
        self.sub_socket = None
        self.sub_thread.join()
        self.xauto_session_id = None
        self.proc = None

    def _send_request(self, request_type: str, *args) -> tuple:
        self.req_socket.send(msgpack.packb((request_type, *args)))
        msg = msgpack.unpackb(self.req_socket.recv())
        if msg is None:
            raise RuntimeError("Empty response from x64dbg")
        if isinstance(msg, list) and len(msg) == 2 and isinstance(msg[0], str) and msg[0].startswith("XERROR_"):
            raise RuntimeError(msg)
        return msg

    def _assert_connection_compat(self):
        v = self.get_xauto_compat_version()
        assert v == COMPAT_VERSION, f"Incompatible x64dbg plugin and client versions {v} != {COMPAT_VERSION}"
        
    def start_session(self, target_exe: str = "", cmdline: str = "", current_dir: str = "") -> int:
        """
        Start a new x64dbg session and optionally load an executable into it.
        """
        if len(target_exe.strip()) == 0 and (len(cmdline) > 0 or len(current_dir) > 0):
            raise ValueError("cmdline and current_dir cannot be provided without target_exe")
        
        visited_sessions = set(self.list_sessions())
        self.proc = subprocess.Popen([self.x64dbg_path], executable=self.x64dbg_path)

        for _ in range(100):
            if self.xauto_session_id is not None:
                break

            time.sleep(0.2)
            sessions = self.list_sessions()

            for s in sessions:
                if s not in visited_sessions:
                    self.xauto_session_id = s
                    self._init_connection()
                    # Race prevention, ensure session we connected to is the expected PID
                    if self.get_debugger_pid() != self.proc.pid:
                        visited_sessions.add(s)
                        self._close_connection()
                        continue
                    break
        if self.xauto_session_id is None:
            raise TimeoutError("Session did not start in a reasonable amount of time")
        self._assert_connection_compat()

        if target_exe.strip() != "":
            self.load_executable(target_exe.strip(), cmdline, current_dir)
            self.wait_cmd_ready()
        return self.xauto_session_id
    
    def attach_session(self, xauto_session_id: int):
        for _ in range(100):
            time.sleep(0.2)
            self.xauto_session_id = xauto_session_id
            sessions = self.list_sessions()
            if xauto_session_id in sessions:
                self._init_connection()
                self._assert_connection_compat()
                return self.xauto_session_id
        raise TimeoutError("Session did not start in a reasonable amount of time")
    
    def deattach_session(self):
        self._close_connection()

    def terminate_session(self):
        sid = self.xauto_session_id
        self.xauto_terminate_session()
        self._close_connection()
        for _ in range(100):
            time.sleep(0.2)
            if sid not in self.list_sessions():
                return
        raise TimeoutError("Session did not terminate in a reasonable amount of time")

    @staticmethod
    def list_sessions() -> list[int]:
        sessions = []
        sid = 1
        while True:
            handle = OpenMutexW(SYNCHRONIZE, False, ctypes.create_unicode_buffer(f"x64dbg_automate_mutex_s_{sid}"))
            if handle:
                sessions.append(sid)
                sid += 1
                CloseHandle(handle)
                continue
            break
        return sessions
    