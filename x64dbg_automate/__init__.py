import ctypes
import glob
import logging
from os import unlink
import subprocess
import threading
import time
import msgpack
import psutil
import zmq

from x64dbg_automate.events import DebugEventQueueMixin
from x64dbg_automate.hla_xauto import XAutoHighLevelCommandAbstractionMixin
from x64dbg_automate.models import DebugSession
from x64dbg_automate.win32 import GetTempPathW, SetConsoleCtrlHandler, EnumWindows, GetWindowTextW, GetWindowThreadProcessId


COMPAT_VERSION = "bitter_oyster" # TODO: externalize
logger = logging.getLogger(__name__)
all_instances: list['X64DbgClient'] = []


def ctrl_c_handler(sig_t: int) -> bool:
    print(f'Received exit signal {sig_t}, detaching and exiting', flush=True)
    for i in all_instances:
        i.detach_session()
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
        self.session_pid = None
        self.context = None
        self.req_socket = None
        self.sub_socket = None
        self.sess_req_rep_port = 0
        self.sess_pub_sub_port = 0
        all_instances.append(self)

    def __del__(self):
        all_instances.remove(self)
    
    def _sub_thread(self) -> None:
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

    
    def _init_connection(self) -> None:
        if self.context is not None:
            self._close_connection()

        self.context = zmq.Context()
        self.req_socket = self.context.socket(zmq.REQ)
        self.req_socket.setsockopt(zmq.SNDTIMEO, 5000)
        self.req_socket.setsockopt(zmq.RCVTIMEO, 10000)
        self.req_socket.connect(f"tcp://localhost:{self.sess_req_rep_port}")
        self.req_socket.send(msgpack.packb("PING"))
        if msgpack.unpackb(self.req_socket.recv()) != "PONG":
            raise ClientConnectionFailedError(f"Connection to x64dbg failed on port {self.sess_req_rep_port}")
        
        self.sub_socket = self.context.socket(zmq.SUB)
        self.req_socket.setsockopt(zmq.RCVTIMEO, 6000)
        self.sub_socket.connect(f"tcp://localhost:{self.sess_pub_sub_port}")
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, "")
        self.sub_thread = threading.Thread(target=self._sub_thread)
        self.sub_thread.start()

    def _close_connection(self) -> None:
        if self.context is None:
            return
        self.context.destroy()
        self.context = None
        self.req_socket = None
        self.sub_socket = None
        self.sub_thread.join()
        self.session_pid = None
        self.proc = None
        self.sess_req_rep_port = 0
        self.sess_pub_sub_port = 0

    def _send_request(self, request_type: str, *args) -> tuple:
        self.req_socket.send(msgpack.packb((request_type, *args)))
        msg = msgpack.unpackb(self.req_socket.recv())
        if msg is None:
            raise RuntimeError("Empty response from x64dbg")
        if isinstance(msg, list) and len(msg) == 2 and isinstance(msg[0], str) and msg[0].startswith("XERROR_"):
            raise RuntimeError(msg)
        return msg

    def _assert_connection_compat(self) -> None:
        v = self.get_xauto_compat_version()
        assert v == COMPAT_VERSION, f"Incompatible x64dbg plugin and client versions {v} != {COMPAT_VERSION}"
        
    def start_session(self, target_exe: str = "", cmdline: str = "", current_dir: str = "") -> int:
        """
        Start a new x64dbg session and optionally load an executable into it. If target_exe is not provided, 
        the debugger starts without any executable. This is useful for performing configuration before the debuggee is loaded.

        Args:
            target_exe: The path to the target executable (optional)
            cmdline: The command line arguments to pass to the executable (optional)
            current_dir: The current working directory to set for the executable (optional)

        Returns:
            The debug session ID
        """
        if len(target_exe.strip()) == 0 and (len(cmdline) > 0 or len(current_dir) > 0):
            raise ValueError("cmdline and current_dir cannot be provided without target_exe")
        
        self.proc = subprocess.Popen([self.x64dbg_path], executable=self.x64dbg_path)
        self.session_pid = self.proc.pid
        self.attach_session(self.session_pid)

        if target_exe.strip() != "":
            self.load_executable(target_exe.strip(), cmdline, current_dir)
            self.wait_cmd_ready()
        return self.session_pid
    
    @staticmethod
    def wait_for_session(session_pid: int, timeout = 10) -> DebugSession:
        """
        Wait for an x64dbg session to start

        Args:
            session_pid: The session ID to wait for (debugger PID)
        """
        while timeout > 0:
            sessions = X64DbgClient.list_sessions()
            sessions = [s for s in sessions if s.pid == session_pid]
            if session_pid in [s.pid for s in sessions]:
                return sessions[0]
            time.sleep(0.2)
            timeout -= 0.2
        raise TimeoutError("Session did not appear in a reasonable amount of time")
    
    def attach_session(self, session_pid: int) -> None:
        """
        Attach to an existing x64dbg session

        Args:
            session_pid: The session ID to wait for (debugger PID)
        """
        session = X64DbgClient.wait_for_session(session_pid)
        self.sess_req_rep_port = session.sess_req_rep_port
        self.sess_pub_sub_port = session.sess_pub_sub_port
        self._init_connection()
        self._assert_connection_compat()
    
    def detach_session(self) -> None:
        """
        Detach from the current x64dbg session, leaving the debugger process running.
        """
        self._close_connection()

    def terminate_session(self) -> None:
        """
        End the current x64dbg session, terminating the debugger process.
        """
        sid = self.session_pid
        self.xauto_terminate_session()
        self._close_connection()
        for _ in range(100):
            time.sleep(0.2)
            if sid not in [p.pid for p in self.list_sessions()]:
                return
        raise TimeoutError("Session did not terminate in a reasonable amount of time")
    
    @staticmethod
    def _window_title_for_pid(pid: int) -> str:
        wnd_title = ctypes.create_unicode_buffer(1024)
        found_title = ''
        def EnumWindowsCb(hwnd, pid):
            nonlocal found_title
            enum_process_id = ctypes.c_ulong()
            GetWindowThreadProcessId(hwnd, ctypes.byref(enum_process_id))
            if enum_process_id.value == pid:
                GetWindowTextW(hwnd, wnd_title, 1024)
                if 'x64dbg' in wnd_title.value.lower() or 'x32dbg' in wnd_title.value.lower():
                    found_title = wnd_title.value if len(wnd_title.value) > len(found_title) else found_title
            return True
        EnumWindowsCb = EnumWindows.argtypes[0](EnumWindowsCb)
        EnumWindows(EnumWindowsCb, pid)
        return found_title

    @staticmethod
    def list_sessions() -> list[DebugSession]:
        """
        Lists all active x64dbg sessions

        Returns:
            A list of session IDs
        """
        sessions: list[DebugSession] = []
        temp_path_cstr = ctypes.create_unicode_buffer(1024)
        if GetTempPathW(1024, temp_path_cstr) == 0:
            temp_path = "c:\\windows\\temp\\"
        else:
            temp_path = temp_path_cstr.value
        
        # Find the first live x64dbg Automate session active and ask it to list all sessions
        locks = glob.glob(f'{temp_path}xauto_session.*.lock')
        for lock in locks:
            try:
                with open(lock, 'r') as f:
                    sess_req_rep_port = int(f.readline().strip())
                    sess_pub_sub_port = int(f.readline().strip())

                pid = int(lock.split('.')[-2])
                process = psutil.Process(pid)
                if process.is_running():
                    sessions.append(DebugSession(
                        pid=pid,
                        lockfile_path=lock,
                        cmdline=process.cmdline(),
                        cwd=process.cwd(),
                        window_title=X64DbgClient._window_title_for_pid(pid),
                        sess_req_rep_port=sess_req_rep_port,
                        sess_pub_sub_port=sess_pub_sub_port
                    ))
            except psutil.NoSuchProcess:
                # Stale session didn't get cleaned up properly
                try:
                    unlink(lock)
                except:
                    pass

        return sessions
    