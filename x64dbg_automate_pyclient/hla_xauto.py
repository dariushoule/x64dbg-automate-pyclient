
from x64dbg_automate_pyclient.commands_xauto import XAutoCommandsMixin
from x64dbg_automate_pyclient.models import MemPage, MutableRegister, PageRightsConfiguration, StandardBreakpointType


class XAutoHighLevelCommandAbstractionMixin(XAutoCommandsMixin):
    """
    Higher-level abstractions built on top of raw XAuto command primitives
    """

    def load_executable(self, target_exe: str, wait_timeout=10) -> bool:
        if not self.cmd_sync(f'init {target_exe}'):
            return False
        return self.wait_cmd_ready(wait_timeout)

    def stepi(self, step_count = 1, pass_exceptions = False, swallow_exceptions = False, wait_for_ready=True, wait_timeout=2) -> bool:
        if pass_exceptions == True and swallow_exceptions == True:
            raise ValueError("Cannot pass and swallow exceptions at the same time")
        prefix = 'e' if pass_exceptions else 'se'
        res = self.cmd_sync(f"{prefix}sti 0x{step_count:x}")
        if res and wait_for_ready:
            self.wait_until_stopped(wait_timeout)
        return res
    
    def stepo(self, step_count = 1, pass_exceptions = False, swallow_exceptions = False, wait_for_ready=True, wait_timeout=2) -> bool:
        if pass_exceptions == True and swallow_exceptions == True:
            raise ValueError("Cannot pass and swallow exceptions at the same time")
        prefix = 'e' if pass_exceptions else 'se'
        res = self.cmd_sync(f"{prefix}sto 0x{step_count:x}")
        if res and wait_for_ready:
            self.wait_until_stopped(wait_timeout)
        return res
    
    def skip(self, skip_count = 1, wait_for_ready=True, wait_timeout=2) -> bool:
        res = self.cmd_sync(f"skip {skip_count}")
        if res and wait_for_ready:
            self.wait_until_stopped(wait_timeout)
        return res
    
    def ret(self, frames = 1, wait_timeout=10) -> bool:
        if not self.cmd_sync(f"rtr {frames}"):
            return False
        return self.wait_cmd_ready(wait_timeout)
    
    def go(self, pass_exceptions = False, swallow_exceptions = False) -> bool:
        if pass_exceptions == True and swallow_exceptions == True:
            raise ValueError("Cannot pass and swallow exceptions at the same time")
        prefix = 'e' if pass_exceptions else 'se'
        return self.cmd_sync(f"{prefix}go")
    
    def virt_alloc(self, n: int = 0x1000, addr: int = 0) -> int:
        if not self.cmd_sync(f"alloc 0x{n:x}, 0x{addr:x}"):
            raise ValueError("Failed to allocate memory")
        addr, success = self.eval_sync("$result")
        if not success:
            raise ValueError("Failed to evaluate result")
        return addr
    
    def virt_free(self, addr: int) -> bool:
        if not self.cmd_sync(f"free 0x{addr:x}"):
            raise ValueError("Failed to free memory")
        return True
    
    def virt_protect(self, addr: int, page_rights: PageRightsConfiguration, guard = False) -> bool:
        rights_str = str(page_rights)
        if guard:
            rights_str = f'G{rights_str}'
        if not self.cmd_sync(f"setpagerights 0x{addr:x}, {rights_str}"):
            raise ValueError("Failed to set memory protection")
        return True
    
    def virt_query(self, addr: int) -> MemPage | None:
        map = self.get_memmap()
        for m in map:
            if m.base_address <= addr < m.base_address + m.region_size:
                return m
        return None
    
    def memset(self, addr: int, byte_val: int, size: int) -> bool:
        if not self.cmd_sync(f"memset 0x{addr:x}, 0x{byte_val:x}, 0x{size:x}"):
            raise ValueError("Failed to set memory")
        return True
    
    def set_reg(self, reg: MutableRegister | str, val: int) -> bool:
        reg = MutableRegister(str(reg).lower())
        if not isinstance(val, int):
            raise TypeError("val must be an integer")
        return self.cmd_sync(f'{reg}=0x{val:X}')
    
    def get_reg(self, reg: MutableRegister | str) -> int:
        reg = MutableRegister(str(reg).lower())
        res, success = self.eval_sync(f'{reg}')
        if not success:
            raise ValueError(f"Failed to evaluate register {reg}")
        return res
    
    def pause(self) -> bool:
        return self.cmd_sync(f"pause")
    
    def set_breakpoint(self, address: int, name: str | None = None, bp_type: StandardBreakpointType = StandardBreakpointType.Short, singleshoot = False) -> bool:
        name = name or f"bpx_{address:x}"
        bp_type_str = str(bp_type).lower()
        if singleshoot and bp_type_str != "ss":
            bp_type_str = f'ss{bp_type_str}'
        if '"' in name:
            raise ValueError("Name cannot contain double quotes")
        return self.cmd_sync(f'bpx 0x{address:x}, "{name}", {bp_type_str}')

    def clear_breakpoint(self, address_name_or_none: int | str | None = None) -> bool:
        if address_name_or_none is None:
            return self.cmd_sync('bpc')
        if isinstance(address_name_or_none, int):
            return self.cmd_sync(f'bpc 0x{address_name_or_none:x}')
        return self.cmd_sync(f'bpc {address_name_or_none}')

    def set_label_at(self, address: int, text: str):
        if '"' in text:
            raise ValueError("Text cannot contain double quotes")
        return self.cmd_sync(f'lblset 0x{address:x}, "{text}"')

    def del_label_at(self, address: int):
        return self.cmd_sync(f'lbldel 0x{address:x}')

    def set_comment_at(self, address: int, text: str):
        if '"' in text:
            raise ValueError("Text cannot contain double quotes")
        return self.cmd_sync(f'cmtset 0x{address:x}, "{text}"')

    def del_comment_at(self, address: int):
        return self.cmd_sync(f'cmtdel 0x{address:x}')