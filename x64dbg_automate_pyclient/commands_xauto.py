from enum import StrEnum
import time

from x64dbg_automate_pyclient.client_base import XAutoClientBase
from x64dbg_automate_pyclient.models import Context64, Context32, Flags, FpuReg, MemPage, MutableRegister, \
    MxcsrFields, RegDump32, RegDump64, X87ControlWordFields, X87Fpu, X87StatusWordFields


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
    XAUTO_REQ_DBG_READ_REGISTERS = "XAUTO_REQ_DBG_READ_REGISTERS"


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
    
    def get_regs(self) -> list[MemPage]:
        raw_regs = self._send_request(XAutoCommand.XAUTO_REQ_DBG_READ_REGISTERS)
        bitness = raw_regs[0]
        raw_regs = raw_regs[1:]
        if bitness == 64:
            ctx = {k: v for k, v in zip(Context64.model_fields.keys(), raw_regs[0])}
            ctx['x87_fpu'] = X87Fpu(**{k: v for k, v in zip(X87Fpu.model_fields.keys(), ctx['x87_fpu'])})
            ctx['xmm_regs'] = [ctx['xmm_regs'][i:i+16] for i in range(0, len(ctx['xmm_regs']), 16)]
            ctx['ymm_regs'] = [ctx['ymm_regs'][i:i+32] for i in range(0, len(ctx['ymm_regs']), 32)]
            return RegDump64(
                context=Context64(**ctx),
                flags=Flags(**{k: v for k, v in zip(Flags.model_fields.keys(), raw_regs[1])}),
                fpu=[FpuReg(data=raw_regs[2][i][0], st_value=raw_regs[2][i][1], tag=raw_regs[2][i][2]) for i in range(len(raw_regs[2]))],
                mmx=raw_regs[3],
                mxcsr_fields=MxcsrFields(**{k: v for k, v in zip(MxcsrFields.model_fields.keys(), raw_regs[4])}),
                x87_status_word_fields=X87StatusWordFields(**{k: v for k, v in zip(X87StatusWordFields.model_fields.keys(), raw_regs[5])}),
                x87_control_word_fields=X87ControlWordFields(**{k: v for k, v in zip(X87ControlWordFields.model_fields.keys(), raw_regs[6])}),
                last_error=(raw_regs[7][0], raw_regs[7][1].decode().strip('\0')),
                last_status=(raw_regs[8][0], raw_regs[8][1].decode().strip('\0'))
            )
        else:
            ctx = {k: v for k, v in zip(Context64.model_fields.keys(), raw_regs[0])}
            ctx['x87_fpu'] = X87Fpu(**{k: v for k, v in zip(X87Fpu.model_fields.keys(), ctx['x87_fpu'])})
            ctx['xmm_regs'] = [ctx['xmm_regs'][i:i+16] for i in range(0, len(ctx['xmm_regs']), 16)]
            ctx['ymm_regs'] = [ctx['ymm_regs'][i:i+32] for i in range(0, len(ctx['ymm_regs']), 32)]
            return RegDump32(
                context=Context32(**ctx),
                flags=Flags(**{k: v for k, v in zip(Flags.model_fields.keys(), raw_regs[1])}),
                fpu=[FpuReg(data=raw_regs[2][i][0], st_value=raw_regs[2][i][1], tag=raw_regs[2][i][2]) for i in range(len(raw_regs[2]))],
                mmx=raw_regs[3],
                mxcsr_fields=MxcsrFields(**{k: v for k, v in zip(MxcsrFields.model_fields.keys(), raw_regs[4])}),
                x87_status_word_fields=X87StatusWordFields(**{k: v for k, v in zip(X87StatusWordFields.model_fields.keys(), raw_regs[5])}),
                x87_control_word_fields=X87ControlWordFields(**{k: v for k, v in zip(X87ControlWordFields.model_fields.keys(), raw_regs[6])}),
                last_error=(raw_regs[7][0], raw_regs[7][1]),
                last_status=(raw_regs[8][0], raw_regs[8][1])
            )
    
    def set_reg(self, reg: MutableRegister | str, val: int) -> bool:
        reg = MutableRegister(str(reg).lower())
        if not isinstance(val, int):
            raise TypeError("val must be an integer")
        return self.dbg_cmd_sync(f'{reg}=0x{val:X}')
    
    def get_reg(self, reg: MutableRegister | str) -> int:
        reg = MutableRegister(str(reg).lower())
        res, success = self.dbg_eval_sync(f'{reg}')
        if not success:
            raise ValueError(f"Failed to evaluate register {reg}")
        return res
    
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
