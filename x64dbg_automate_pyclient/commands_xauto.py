from enum import StrEnum
import time

from x64dbg_automate_pyclient.client_base import XAutoClientBase


class XAutoCommand(StrEnum):
    XAUTO_REQ_DEBUGGER_PID = "XAUTO_REQ_DEBUGGER_PID"
    XAUTO_REQ_COMPAT_VERSION = "XAUTO_REQ_COMPAT_VERSION"
    XAUTO_REQ_QUIT = "XAUTO_REQ_QUIT"
    XAUTO_REQ_DBG_EVAL = "XAUTO_REQ_DBG_EVAL"
    XAUTO_REQ_DBG_CMD_EXEC_DIRECT = "XAUTO_REQ_DBG_CMD_EXEC_DIRECT"
    XAUTO_REQ_DBG_IS_RUNNING = "XAUTO_REQ_DBG_IS_RUNNING"
    XAUTO_REQ_DBG_IS_DEBUGGING = "XAUTO_REQ_DBG_IS_DEBUGGING"


class XAutoCommandsMixin(XAutoClientBase):
    def get_debugger_pid(self) -> int:
        return self._send_request(XAutoCommand.XAUTO_REQ_DEBUGGER_PID)[0]
    
    def get_xauto_compat_version(self) -> str:
        return self._send_request(XAutoCommand.XAUTO_REQ_COMPAT_VERSION)[0]
    
    def dbg_terminate_session(self):
        assert self._send_request(XAutoCommand.XAUTO_REQ_QUIT) == "OK_QUITTING", "Failed to terminate x64dbg session"
    
    def dbg_eval(self, eval_str) -> list[int, bool]:
        """
        Evaluates an expression that results in a numerical output
        Returns:
            list[int, bool], a list containing:
                - int: Evaluation result
                - bool: Success or failure
        """
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_EVAL, eval_str)
    
    def dbg_cmd_sync(self, cmd_str) -> bool:
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_CMD_EXEC_DIRECT, cmd_str)[0]
    
    def get_dbg_is_running(self) -> bool:
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_IS_RUNNING)[0]
    
    def get_dbg_is_debugging(self) -> bool:
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_IS_DEBUGGING)[0]
    
    def wait_until_debugging(self, timeout = 10) -> bool:
        slept = 0
        while True:
            if self.get_dbg_is_debugging():
                return True
            time.sleep(0.3)
            slept += 0.3
            if slept >= timeout:
                return False
    
    def wait_until_not_running(self, timeout = 10) -> bool:
        slept = 0
        while True:
            if not self.get_dbg_is_running():
                return True
            time.sleep(0.3)
            slept += 0.3
            if slept >= timeout:
                return False
    
    def wait_cmd_ready(self, timeout = 10) -> bool:
        return self.wait_until_debugging(timeout) and self.wait_until_not_running(timeout)
