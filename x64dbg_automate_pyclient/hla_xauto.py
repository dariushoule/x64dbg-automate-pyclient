
from x64dbg_automate_pyclient.commands_xauto import XAutoCommandsMixin


class XAutoHighLevelCommandAbstractionMixin(XAutoCommandsMixin):
    """
    Higher-level abstractions built on top of raw XAuto command primitives
    """

    def load_executable(self, wait_timeout=10) -> bool:
        if not self.dbg_cmd_sync(r'init c:\Windows\system32\winver.exe'):
            return False
        return self.wait_cmd_ready(wait_timeout)

    def stepi(self, step_count = 1, pass_exceptions = False, swallow_exceptions = False, wait_for_ready=True, wait_timeout=2) -> bool:
        if pass_exceptions == True and swallow_exceptions == True:
            raise ValueError("Cannot pass and swallow exceptions at the same time")
        prefix = 'e' if pass_exceptions else 'se'
        res = self.dbg_cmd_sync(f"{prefix}sti {step_count}")
        if res and wait_for_ready:
            self.wait_until_stopped(wait_timeout)
        return res
    
    def stepo(self, step_count = 1, pass_exceptions = False, swallow_exceptions = False, wait_for_ready=True, wait_timeout=2) -> bool:
        if pass_exceptions == True and swallow_exceptions == True:
            raise ValueError("Cannot pass and swallow exceptions at the same time")
        prefix = 'e' if pass_exceptions else 'se'
        res = self.dbg_cmd_sync(f"{prefix}sto {step_count}")
        if res and wait_for_ready:
            self.wait_until_stopped(wait_timeout)
        return res
    
    def skip(self, skip_count = 1, wait_for_ready=True, wait_timeout=2) -> bool:
        res = self.dbg_cmd_sync(f"skip {skip_count}")
        if res and wait_for_ready:
            self.wait_until_stopped(wait_timeout)
        return res
    
    def ret(self, frames = 1) -> bool:
        return self.dbg_cmd_sync(f"rtr {frames}")
    
    def go(self, pass_exceptions = False, swallow_exceptions = False) -> bool:
        if pass_exceptions == True and swallow_exceptions == True:
            raise ValueError("Cannot pass and swallow exceptions at the same time")
        prefix = 'e' if pass_exceptions else 'se'
        return self.dbg_cmd_sync(f"{prefix}go")
    
    def pause(self) -> bool:
        return self.dbg_cmd_sync(f"pause")
