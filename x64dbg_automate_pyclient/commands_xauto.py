from enum import StrEnum
import time

from x64dbg_automate_pyclient.client_base import XAutoClientBase
from x64dbg_automate_pyclient.models import Breakpoint, BreakpointType, Context64, Context32, DisasmArgType, \
    DisasmInstrType, Flags, FpuReg, Instruction, InstructionArg, MemPage, MxcsrFields, RegDump32, RegDump64, \
    SegmentReg, Symbol, SymbolType, X87ControlWordFields, X87Fpu, X87StatusWordFields


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
    XAUTO_REQ_DBG_READ_MEMORY = "XAUTO_REQ_DBG_READ_MEMORY"
    XAUTO_REQ_DBG_WRITE_MEMORY = "XAUTO_REQ_DBG_WRITE_MEMORY"
    XAUTO_REQ_DBG_READ_SETTING_SZ = "XAUTO_REQ_DBG_READ_SETTING_SZ"
    XAUTO_REQ_DBG_WRITE_SETTING_SZ = "XAUTO_REQ_DBG_WRITE_SETTING_SZ"
    XAUTO_REQ_DBG_READ_SETTING_UINT = "XAUTO_REQ_DBG_READ_SETTING_UINT"
    XAUTO_REQ_DBG_WRITE_SETTING_UINT = "XAUTO_REQ_DBG_WRITE_SETTING_UINT"
    XAUTO_REQ_DBG_IS_VALID_READ_PTR = "XAUTO_REQ_DBG_IS_VALID_READ_PTR"
    XAUTO_REQ_DISASSEMBLE = "XAUTO_REQ_DISASSEMBLE"
    XAUTO_REQ_ASSEMBLE = "XAUTO_REQ_ASSEMBLE"
    XAUTO_REQ_GET_BREAKPOINTS = "XAUTO_REQ_GET_BREAKPOINTS"
    XAUTO_REQ_GET_LABEL = "XAUTO_REQ_GET_LABEL"
    XAUTO_REQ_GET_COMMENT = "XAUTO_REQ_GET_COMMENT"
    XAUTO_REQ_GET_SYMBOL = "XAUTO_REQ_GET_SYMBOL"


class XAutoCommandsMixin(XAutoClientBase):
    def get_debugger_pid(self) -> int:
        return self._send_request(XAutoCommand.XAUTO_REQ_DEBUGGER_PID)
    
    def get_xauto_compat_version(self) -> str:
        return self._send_request(XAutoCommand.XAUTO_REQ_COMPAT_VERSION)
    
    def get_debugger_version(self) -> int:
        return self._send_request(XAutoCommand.XAUTO_REQ_DEBUGGER_VERSION)
    
    def xauto_terminate_session(self):
        assert self._send_request(XAutoCommand.XAUTO_REQ_QUIT) == "OK_QUITTING", "Failed to terminate x64dbg session"
    
    def eval_sync(self, eval_str) -> list[int, bool]:
        """
        Evaluates an expression that results in a numerical output
        Returns:
            list[int, bool], a list containing:
                - int: Evaluation result
                - bool: Success or failure
        """
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_EVAL, eval_str)
    
    def cmd_sync(self, cmd_str: str) -> bool:
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
    
    def read_memory(self, addr: int, size: int) -> bytes:
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_READ_MEMORY, addr, size)
     
    def write_memory(self, addr: int, data: bytes) -> bool:
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_WRITE_MEMORY, addr, data)
    
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
        
    def get_is_running(self) -> bool:
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_IS_RUNNING)
    
    def get_setting_str(self, section: str, setting_name: str) -> str | None:
        res, setting = self._send_request(XAutoCommand.XAUTO_REQ_DBG_READ_SETTING_SZ, section, setting_name)
        if not res:
            return None
        return setting
    
    def set_setting_str(self, section: str, setting_name: str, setting_val: str) -> bool:
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_WRITE_SETTING_SZ, section, setting_name, setting_val)
    
    def get_setting_int(self, section: str, setting_name: str) -> int | None:
        res, setting = self._send_request(XAutoCommand.XAUTO_REQ_DBG_READ_SETTING_UINT, section, setting_name)
        if not res:
            return None
        return setting
    
    def set_setting_int(self, section: str, setting_name: str, setting_val: int) -> bool:
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_WRITE_SETTING_UINT, section, setting_name, setting_val)
    
    def check_valid_read_ptr(self, addr: int) -> bool:
        return self._send_request(XAutoCommand.XAUTO_REQ_DBG_IS_VALID_READ_PTR, addr)
    
    def disassemble_at(self, addr: int) -> Instruction:
        res = self._send_request(XAutoCommand.XAUTO_REQ_DISASSEMBLE, addr)
        return Instruction(
            instruction=res[0],
            argcount=res[1],
            instr_size=res[2],
            type=DisasmInstrType(res[3]),
            arg=[InstructionArg(
                    mnemonic=arg[0],
                    type=DisasmArgType(arg[1]),
                    segment=SegmentReg(arg[2]),
                    constant=arg[3],
                    value=arg[4],
                    memvalue=arg[5],
            ) for arg in res[4]]
        )
    
    def assemble_at(self, addr: int, instr: str) -> bool:
        return self._send_request(XAutoCommand.XAUTO_REQ_ASSEMBLE, addr, instr)
    
    def get_breakpoints(self, bp_type: BreakpointType) -> list[Breakpoint]:
        resp = self._send_request(XAutoCommand.XAUTO_REQ_GET_BREAKPOINTS, bp_type)
        return [Breakpoint(
            type=BreakpointType(bp[0]),
            addr=bp[1],
            enabled=bp[2],
            singleshoot=bp[3],
            active=bp[4],
            name=bp[5],
            mod=bp[6],
            slot=bp[7],
            typeEx=bp[8],
            hwSize=bp[9],
            hitCount=bp[10],
            fastResume=bp[11],
            silent=bp[12],
            breakCondition=bp[13],
            logText=bp[14],
            logCondition=bp[15],
            commandText=bp[16],
            commandCondition=bp[17]
        ) for bp in resp]
    
    def get_label_at(self, addr: int, segment_reg: SegmentReg = SegmentReg.SegDefault) -> str:
        res, label = self._send_request(XAutoCommand.XAUTO_REQ_GET_LABEL, addr, segment_reg)
        if not res:
            return ""
        return label
    
    def get_comment_at(self, addr: int) -> str:
        res, comment = self._send_request(XAutoCommand.XAUTO_REQ_GET_COMMENT, addr)
        if not res:
            return ""
        return comment
    
    def get_symbol_at(self, addr: int) -> Symbol | None:
        res = self._send_request(XAutoCommand.XAUTO_REQ_GET_SYMBOL, addr)
        if not res[0]:
            return ""
        return Symbol(
            addr=res[1],
            decoratedSymbol=res[2],
            undecoratedSymbol=res[3],
            type=SymbolType(res[4]),
            ordinal=res[5]
        )
    
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
