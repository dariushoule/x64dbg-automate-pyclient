import ctypes
import glob
import logging
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import msgpack
import psutil
import shutil
import zmq

from x64dbg_automate.events import DebugEventQueueMixin
from x64dbg_automate.hla_xauto import XAutoHighLevelCommandAbstractionMixin
from x64dbg_automate.models import DebugSession

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    from x64dbg_automate.win32 import GetTempPathW, SetConsoleCtrlHandler, EnumWindows, GetWindowTextW, GetWindowThreadProcessId


COMPAT_VERSION = "green_pepe" # TODO: externalize
logger = logging.getLogger(__name__)
all_instances: list['X64DbgClient'] = []


if _IS_WINDOWS:
    def ctrl_c_handler(sig_t: int) -> bool:
        logger.warning(f'Received exit signal {sig_t}, detaching and exiting')
        for i in all_instances:
            i.detach_session()
        import psutil
        psutil.Process().terminate()
        return True
    ctrl_c_handler = SetConsoleCtrlHandler.argtypes[0](ctrl_c_handler)
    SetConsoleCtrlHandler(ctrl_c_handler, True)


class ClientConnectionFailedError(Exception):
    pass

class X64DbgClient(XAutoHighLevelCommandAbstractionMixin, DebugEventQueueMixin):
    def _init_fields(self, x64dbg_path: str | None = None, remote_host: str = "localhost",
                     req_rep_port: int = 0, pub_sub_port: int = 0):
        self.x64dbg_path = x64dbg_path
        self.proc = None
        self.session_pid = None
        self.context = zmq.Context()
        self.req_socket = None
        self.sub_socket = None
        self.sess_req_rep_port = req_rep_port
        self.sess_pub_sub_port = pub_sub_port
        self.remote_host = remote_host
        self._req_lock = threading.Lock()
        all_instances.append(self)

    def __init__(self, x64dbg_path: str = "x64dbg"):
        resolved = x64dbg_path
        if not Path(resolved).is_file():
            resolved = shutil.which(x64dbg_path)
        if resolved is None or not Path(resolved).is_file():
            raise FileNotFoundError(f"x64dbg executable not found at {x64dbg_path} or in PATH")
        self._init_fields(x64dbg_path=resolved)

    @classmethod
    def connect_remote(cls, host: str, req_rep_port: int, pub_sub_port: int) -> 'X64DbgClient':
        """Connect to a remote x64dbg instance by host and port pair.

        This bypasses local session discovery (lockfiles) and connects directly
        to a remote x64dbg plugin configured to bind on an accessible address.

        Args:
            host: Remote hostname or IP address (e.g. '192.168.1.100')
            req_rep_port: The REQ/REP port the plugin is listening on
            pub_sub_port: The PUB/SUB port the plugin is listening on

        Returns:
            A connected X64DbgClient instance
        """
        client = cls.__new__(cls)
        client._init_fields(remote_host=host, req_rep_port=req_rep_port, pub_sub_port=pub_sub_port)
        client._init_connection()
        client._assert_connection_compat()
        return client

    def __del__(self):
        all_instances.remove(self)
    
    def _sub_thread(self) -> None:
        while True:
            try:
                if self.sub_socket is None:
                    break
                msg = msgpack.unpackb(self.sub_socket.recv(zmq.DONTWAIT))
                self.debug_event_publish(msg)
            except zmq.error.Again:
                # No messages on socket
                time.sleep(0.2)
                pass
            except KeyboardInterrupt:
                # Quitting, expected exit
                break
            except zmq.error.ZMQError:
                logger.exception("Unhandled ZMQError, retrying")

    
    def _init_connection(self) -> None:
        if self.req_socket is not None:
            self._close_connection()

        self.req_socket = self.context.socket(zmq.REQ)
        self.req_socket.setsockopt(zmq.CONNECT_TIMEOUT, 6000)
        self.req_socket.setsockopt(zmq.SNDTIMEO, 6000)
        self.req_socket.setsockopt(zmq.RCVTIMEO, 10000)
        self.req_socket.connect(f"tcp://{self.remote_host}:{self.sess_req_rep_port}")
        self.req_socket.send(msgpack.packb("PING"))
        if msgpack.unpackb(self.req_socket.recv()) != "PONG":
            raise ClientConnectionFailedError(f"Connection to x64dbg failed on port {self.sess_req_rep_port}")
        
        self.sub_socket = self.context.socket(zmq.SUB)
        self.sub_socket.setsockopt(zmq.CONNECT_TIMEOUT, 6000)
        self.sub_socket.setsockopt(zmq.SNDTIMEO, 6000)
        self.sub_socket.setsockopt(zmq.RCVTIMEO, 10000)
        self.sub_socket.connect(f"tcp://{self.remote_host}:{self.sess_pub_sub_port}")
        self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, "")
        self.sub_thread = threading.Thread(target=self._sub_thread)
        self.sub_thread.start()

    def _close_connection(self) -> None:
        if self.req_socket is None:
            return
        self.req_socket.close()
        self.sub_socket.close()
        self.req_socket = None
        self.sub_socket = None
        self.sub_thread.join()
        self.session_pid = None
        self.proc = None
        self.sess_req_rep_port = 0
        self.sess_pub_sub_port = 0

    def _send_request(self, request_type: str, *args) -> tuple:
        with self._req_lock:
            self.req_socket.send(msgpack.packb((request_type, *args)))
            msg = msgpack.unpackb(self.req_socket.recv(), use_list=False)
        if msg is None:
            raise RuntimeError("Empty response from x64dbg")
        if isinstance(msg, tuple) and len(msg) == 2 and isinstance(msg[0], str) and msg[0].startswith("XERROR_"):
            raise RuntimeError(msg)
        return msg

    def _assert_connection_compat(self) -> None:
        v = self._get_xauto_compat_version()
        assert v == COMPAT_VERSION, f"Incompatible x64dbg plugin and client versions {v} != {COMPAT_VERSION}"
        
    def _launch_x64dbg(self) -> int:
        if self.x64dbg_path is None:
            raise RuntimeError("Cannot launch x64dbg in remote mode — no x64dbg_path configured")
        self.proc = subprocess.Popen([self.x64dbg_path], executable=self.x64dbg_path)
        self.session_pid = self.proc.pid
        self.attach_session(self.session_pid)

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

        self._launch_x64dbg()

        if target_exe.strip() != "":
            if not self.load_executable(target_exe.strip(), cmdline, current_dir):
                self.terminate_session()
                raise RuntimeError("Failed to load executable")
            self.wait_cmd_ready()
        return self.session_pid

    def start_session_attach(self, pid: int) -> int:
        """
        Start a new x64dbg session and attach to an existing process identified by pid.

        Args:
            pid (int): Process Identifier (PID) of the process to attach to.

        Returns:
            int: The debug session ID (the PID of the x64dbg process).

        Raises:
            RuntimeError: If attaching to the process fails.
        """
        self._launch_x64dbg()

        if not self.attach(pid):
            self.terminate_session()
            raise RuntimeError("Failed to attach to process")

        self.wait_until_debugging()
        return self.session_pid
    
    @staticmethod
    def wait_for_session(session_pid: int, timeout: int = 10) -> DebugSession:
        """
        Wait for an x64dbg session to start

        Args:
            session_pid: The session ID to wait for (debugger PID)
            timeout: The maximum time to wait in seconds

        Returns:
            The awaited debug session object
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
            session_pid: The session ID to attach to (debugger PID)
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
        self._xauto_terminate_session()
        self._close_connection()
        if not _IS_WINDOWS or self.x64dbg_path is None:
            # Remote mode — cannot poll local lockfiles for confirmation
            return
        for _ in range(100):
            time.sleep(0.2)
            if sid not in [p.pid for p in self.list_sessions()]:
                return
        raise TimeoutError("Session did not terminate in a reasonable amount of time")
    
    @staticmethod
    def _window_title_for_pid(pid: int) -> str:
        if not _IS_WINDOWS:
            return ''
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
        Lists all active x64dbg sessions (local only, requires Windows).

        Returns:
            A list of sessions
        """
        if not _IS_WINDOWS:
            raise NotImplementedError("Local session discovery is only available on Windows. Use connect_remote() for remote connections.")

        sessions: list[DebugSession] = []
        temp_path_cstr = ctypes.create_unicode_buffer(1024)
        if GetTempPathW(1024, temp_path_cstr) == 0:
            temp_path = "c:\\windows\\temp\\"
        else:
            temp_path = temp_path_cstr.value

        locks = glob.glob(f'{temp_path}xauto_session.*.lock')
        for lock in locks:
            while True:
                try:
                    with open(lock, 'r') as f:
                        sess_req_rep_port = int(f.readline().strip())
                        sess_pub_sub_port = int(f.readline().strip())
                        host_line = f.readline().strip()
                        host = host_line if host_line else "localhost"
                        # For local discovery, 0.0.0.0 means connect via localhost
                        if host == "0.0.0.0":
                            host = "localhost"

                    pid = int(lock.split('.')[-2])
                    if psutil.pid_exists(pid):
                        process = psutil.Process(pid)
                        try:
                            cmdline = process.cmdline()
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            cmdline = []
                        try:
                            cwd = process.cwd()
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            cwd = ""
                        sessions.append(DebugSession(
                            pid=pid,
                            lockfile_path=lock,
                            cmdline=cmdline,
                            cwd=cwd,
                            window_title=X64DbgClient._window_title_for_pid(pid),
                            sess_req_rep_port=sess_req_rep_port,
                            sess_pub_sub_port=sess_pub_sub_port,
                            host=host
                        ))
                        break
                    else:
                        if time.time() - os.path.getctime(lock) > 10.0:
                            logger.warning(f"Stale lockfile {lock}, removing")
                            os.unlink(lock)
                            break
                except (FileNotFoundError, psutil.AccessDenied, psutil.NoSuchProcess):
                    # The process exited or is inaccessible
                    break

        return sessions
    
