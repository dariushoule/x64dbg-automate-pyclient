from enum import StrEnum
import time

from x64dbg_automate_pyclient.client_base import XAutoClientBase
from x64dbg_automate_pyclient.models import MemPage


class XAutoCommand(StrEnum):
    XAUTO_REQ_DEBUGGER_PID = "XAUTO_REQ_DEBUGGER_PID"
    XAUTO_REQ_COMPAT_VERSION = "XAUTO_REQ_COMPAT_VERSION"
    XAUTO_REQ_QUIT = "XAUTO_REQ_QUIT"
    XAUTO_REQ_DBG_EVAL = "XAUTO_REQ_DBG_EVAL"
    XAUTO_REQ_DBG_CMD_EXEC_DIRECT = "XAUTO_REQ_DBG_CMD_EXEC_DIRECT"
    XAUTO_REQ_DBG_IS_RUNNING = "XAUTO_REQ_DBG_IS_RUNNING"
    XAUTO_REQ_DBG_IS_DEBUGGING = "XAUTO_REQ_DBG_IS_DEBUGGING"
    XAUTO_REQ_DBG_IS_ELEVATED = "XAUTO_REQ_DBG_IS_ELEVATED"
    XAUTO_REQ_DEBUGGER_VERSION = "XAUTO_REQ_DEBUGGER_VERSION"
    XAUTO_REQ_DBG_GET_BITNESS = "XAUTO_REQ_DBG_GET_BITNESS"
    XAUTO_REQ_DBG_MEMMAP = "XAUTO_REQ_DBG_MEMMAP",
    XAUTO_REQ_GUI_REFRESH_VIEWS = "XAUTO_REQ_GUI_REFRESH_VIEWS"


class XAutoCommandsMixin(XAutoClientBase):
    def get_debugger_pid(self) -> int:
        return self._send_request(XAutoCommand.XAUTO_REQ_DEBUGGER_PID)
    
    def get_xauto_compat_version(self) -> str:
        return self._send_request(XAutoCommand.XAUTO_REQ_COMPAT_VERSION)
    
    def get_debugger_version(self) -> int:
        return self._send_request(XAutoCommand.XAUTO_REQ_DEBUGGER_VERSION)
    
    def xauto_terminate_session(self):
        assert self._send_request(XAutoCommand.XAUTO_REQ_QUIT) == "OK_QUITTING", "Failed to terminate x64dbg session"
    
    def dbg_eval_sync(self, eval_str) -> list[int, bool]:
        """
        Evaluates an expression that results in a numerical output
        Returns:
            list[int, bool], a list containing:
                - int: Evaluation result
                - bool: Success or failure
        """
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_EVAL, eval_str)
    
    def dbg_cmd_sync(self, cmd_str) -> bool:
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_CMD_EXEC_DIRECT, cmd_str)
    
    def get_is_running(self) -> bool:
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_IS_RUNNING)
    
    def get_is_debugging(self) -> bool:
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_IS_DEBUGGING)
    
    def debugger_is_elevated(self) -> bool:
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_IS_ELEVATED)
    
    def get_bitness(self) -> bool:
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_GET_BITNESS)
    
    def get_memmap(self) -> list[MemPage]:
        resp = self._send_request(XAutoCommand.XAUTO_REQ_DBG_MEMMAP)
        pages = []
        for page in resp:
            pages.append(MemPage(**{k: v for k, v in zip(MemPage.model_fields.keys(), page)}))
        return pages
    
    def gui_refresh_views(self) -> list[MemPage]:
        return self._send_request(XAutoCommand.XAUTO_REQ_GUI_REFRESH_VIEWS)
    
    def wait_until_debugging(self, timeout = 10) -> bool:
        slept = 0
        while True:
            if self.get_is_debugging():
                return True
            time.sleep(0.2)
            slept += 0.2
            if slept >= timeout:
                return False
    
    def wait_until_stopped(self, timeout = 10) -> bool:
        slept = 0
        while True:
            if not self.get_is_running():
                return True
            time.sleep(0.1)
            slept += 0.1
            if slept >= timeout:
                return False
    
    def wait_cmd_ready(self, timeout = 10) -> bool:
        return self.wait_until_debugging(timeout) and self.wait_until_stopped(timeout)
