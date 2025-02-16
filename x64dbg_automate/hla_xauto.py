import os
from x64dbg_automate.commands_xauto import XAutoCommandsMixin
from x64dbg_automate.models import HardwareBreakpointType, MemPage, \
    MemoryBreakpointType, MutableRegister, PageRightsConfiguration, StandardBreakpointType


class XAutoHighLevelCommandAbstractionMixin(XAutoCommandsMixin):
    """
    Higher-level abstractions built on top of raw XAuto command primitives
    """

    def load_executable(self, target_exe: str, cmdline: str = "", current_dir: str = "", wait_timeout: int = 10) -> bool:
        """
        Loads a new executable into the debugger. This method will block until the debugee is ready to receive a command.

        Args:
            target_exe: Path to the executable to load
            cmdline: Command line arguments to pass to the executable
            current_dir: Current working directory for the executable
            wait_timeout: Max time to wait for the debugee to be ready

        Returns:
            True if successful, False otherwise
        """
        cmdline = cmdline.replace('"', r'\"')
        current_dir = current_dir.replace('"', r'\"')
        if len(current_dir) == 0:
            current_dir = "."
        if current_dir == "." or current_dir == "":
            target_exe = os.path.abspath(target_exe)
        else:
            target_exe = os.path.abspath(os.path.join(current_dir, target_exe))
        if not self.cmd_sync(f'init {target_exe}, "{cmdline}", "{current_dir}"'):
            return False
        return self.wait_cmd_ready(wait_timeout)

    def unload_executable(self, wait_timeout: int = 10) -> bool:
        """
        Unloads the currently loaded executable. This method will block until the debugger is no longer debugging.

        Args:
            wait_timeout: Max time to wait for the debugger finish unloading

        Returns:
            True if successful, False otherwise
        """
        if not self.cmd_sync(f'stop'):
            return False
        return self.wait_until_not_debugging(wait_timeout)

    def stepi(self, step_count: int = 1, pass_exceptions: bool = False, swallow_exceptions: bool = False, wait_for_ready: bool = True, wait_timeout: int = 2) -> bool:
        """
        Steps into N instructions.
        
        Args:
            step_count: Number of instructions to step through
            pass_exceptions: Pass exceptions to the debugee during step
            swallow_exceptions: Swallow exceptions during step
            wait_for_ready: Block until debugger is stopped
            wait_timeout: Maximum time in seconds to wait for debugger to stop
        Returns:
            bool: True if stepping operation was successful, False otherwise.
        Raises:
            ValueError: If both pass_exceptions and swallow_exceptions are True.
        """
        if pass_exceptions == True and swallow_exceptions == True:
            raise ValueError("Cannot pass and swallow exceptions at the same time")
        if pass_exceptions:
            prefix = 'e'
        elif swallow_exceptions:
            prefix = 'se'
        else:
            prefix = ''
        res = self.cmd_sync(f"{prefix}sti 0x{step_count:x}")
        if res and wait_for_ready:
            self.wait_until_stopped(wait_timeout)
        return res
    
    def stepo(self, step_count: int = 1, pass_exceptions: bool = False, swallow_exceptions: bool = False, wait_for_ready: bool = True, wait_timeout: int = 2) -> bool:
        """
        Steps over N instructions.
        
        Args:
            step_count: Number of instructions to step through
            pass_exceptions: Pass exceptions to the debugee during step
            swallow_exceptions: Swallow exceptions during step
            wait_for_ready: Block until debugger is stopped
            wait_timeout: Maximum time in seconds to wait for debugger to stop
        Returns:
            bool: True if stepping operation was successful, False otherwise.
        Raises:
            ValueError: If both pass_exceptions and swallow_exceptions are True.
        """
        if pass_exceptions == True and swallow_exceptions == True:
            raise ValueError("Cannot pass and swallow exceptions at the same time")
        if pass_exceptions:
            prefix = 'e'
        elif swallow_exceptions:
            prefix = 'se'
        else:
            prefix = ''
        res = self.cmd_sync(f"{prefix}sto 0x{step_count:x}")
        if res and wait_for_ready:
            self.wait_until_stopped(wait_timeout)
        return res
    
    def skip(self, skip_count: int = 1, wait_for_ready: bool = True, wait_timeout: int = 2) -> bool:
        """
        Skips over N instructions.
        
        Args:
            skip_count: Number of instructions to skip
            wait_for_ready: Block until debugger is stopped
            wait_timeout: Maximum time in seconds to wait for debugger to stop
        Returns:
            bool: True if stepping operation was successful, False otherwise.
        """
        res = self.cmd_sync(f"skip {skip_count}")
        if res and wait_for_ready:
            self.wait_until_stopped(wait_timeout)
        return res
    
    def ret(self, frames: int = 1, wait_timeout: int = 10) -> bool:
        """
        Steps until a ret instruction is encountered.
        
        Args:
            frames: Number of ret instructions to seek
            wait_timeout: Maximum time in seconds to wait for debugger to stop
        Returns:
            bool: True if stepping operation was successful, False otherwise.
        """
        if not self.cmd_sync(f"rtr {frames}"):
            return False
        return self.wait_cmd_ready(wait_timeout)
    
    def go(self, pass_exceptions: bool = False, swallow_exceptions: bool = False) -> bool:
        """
        Resumes the debugee. This method will block until the debugee is in the running state.

        Args:
            pass_exceptions: Pass exceptions to the debugee
            swallow_exceptions: Swallow exceptions

        Returns:
            True if successful, False otherwise
        """
        if pass_exceptions == True and swallow_exceptions == True:
            raise ValueError("Cannot pass and swallow exceptions at the same time")
        if pass_exceptions:
            prefix = 'e'
        elif swallow_exceptions:
            prefix = 'se'
        else:
            prefix = ''
        if not self.cmd_sync(f"{prefix}go"):
            return False
        self.wait_until_running(timeout=1)
        return True

    
    def virt_alloc(self, n: int = 0x1000, addr: int = 0) -> int:
        """
        Allocates memory in the debugee's address space

        Args:
            n: Size of memory to allocate
            addr: Address to allocate memory at

        Returns:
            Address of the allocated memory
        """
        if not self.cmd_sync(f"alloc 0x{n:x}, 0x{addr:x}"):
            raise ValueError("Failed to allocate memory")
        addr, success = self.eval_sync("$result")
        if not success:
            raise ValueError("Failed to evaluate result")
        return addr
    
    def virt_free(self, addr: int) -> bool:
        """
        Frees memory in the debugee's address space

        Args:
            addr: Address to free memory at

        Returns:
            Success
        """
        if not self.cmd_sync(f"free 0x{addr:x}"):
            raise ValueError("Failed to free memory")
        return True
    
    def virt_protect(self, addr: int, page_rights: PageRightsConfiguration, guard: bool = False) -> bool:
        """
        Changes a pages memory protection in the debugee's address space, optionally setting a page guard.

        Args:
            addr: Address to operate on
            page_rights: New memory protection configuration
            guard: page guard toggle

        Returns:
            Success
        """
        rights_str = str(page_rights)
        if guard:
            rights_str = f'G{rights_str}'
        if not self.cmd_sync(f"setpagerights 0x{addr:x}, {rights_str}"):
            raise ValueError("Failed to set memory protection")
        return True
    
    def virt_query(self, addr: int) -> MemPage | None:
        """
        Retrieves information about a memory region.

        Args:
            addr: Address to query

        Returns:
            MemPage on success, None on failure
        """
        map = self.memmap()
        for m in map:
            if m.base_address <= addr < m.base_address + m.region_size:
                return m
        return None
    
    def memset(self, addr: int, byte_val: int, size: int) -> bool:
        """
        Sets memory in the debugee's address space to the specified value

        Args:
            addr: Address to set memory at
            byte_val: Value to set memory to
            size: Number of bytes to set

        Returns:
            Success
        """
        if not self.cmd_sync(f"memset 0x{addr:x}, 0x{byte_val:x}, 0x{size:x}"):
            raise ValueError("Failed to set memory")
        return True
    
    def set_reg(self, reg: MutableRegister | str, val: int) -> bool:
        """
        Set a single register or subregister to a value

        Args:
            reg: Register to set
            val: Value to set

        Returns:
            Success
        """
        reg = MutableRegister(str(reg).lower())
        if not isinstance(val, int):
            raise TypeError("val must be an integer")
        return self.cmd_sync(f'{reg}=0x{val:X}')
    
    def get_reg(self, reg: MutableRegister | str) -> int:
        """
        Get a single register or subregister

        Args:
            reg: Register to get

        Returns:
            Success
        """
        reg = MutableRegister(str(reg).lower())
        res, success = self.eval_sync(f'{reg}')
        if not success:
            raise ValueError(f"Failed to evaluate register {reg}")
        return res
    
    def pause(self) -> bool:
        """
        Pauses the debugee. This method will block until the debugee is in the stopped state.

        Returns:
            True if successful, False otherwise
        """
        if not self.cmd_sync(f"pause"):
            return False
        return self.wait_until_stopped()
    
    def set_breakpoint(self, address_or_symbol: int | str, name: str | None = None, bp_type: StandardBreakpointType = StandardBreakpointType.Short, singleshoot: bool = False) -> bool:
        """
        Sets a software breakpoint at the specified address or symbol.

        Args:
            address_or_symbol: Address or symbol to set the breakpoint at
            name: Optional name for the breakpoint
            bp_type: Type of software breakpoint to set
            singleshoot: Set a single-shot breakpoint

        Returns:
            Success
        """
        bp_type_str = str(bp_type).lower()
        if singleshoot and bp_type_str != "ss":
            bp_type_str = f'ss{bp_type_str}'
        if isinstance(address_or_symbol, int):
            name = name or f"bpx_{address_or_symbol:x}"
            return self.cmd_sync(f'bpx 0x{address_or_symbol:x}, "{name}", {bp_type_str}')
        else:
            name = name or f"bpx_{address_or_symbol.replace(' ', '_')}"
            if '"' in name:
                raise ValueError("Name cannot contain double quotes")
            return self.cmd_sync(f'bpx {address_or_symbol}, "{name}", {bp_type_str}')
    
    def set_hardware_breakpoint(self, address_or_symbol: int | str, bp_type: HardwareBreakpointType = HardwareBreakpointType.x, size: int = 1) -> bool:
        """
        Sets a hardware breakpoint at the specified address or symbol.

        Args:
            address_or_symbol: Address or symbol to set the breakpoint at
            bp_type: Type of software breakpoint to set
            size: breakpoint size, one of [1, 2, 4, 8]

        Returns:
            Success
        """
        if size not in [1, 2, 4, 8]:
            raise ValueError("Invalid size")
        if isinstance(address_or_symbol, int):
            return self.cmd_sync(f'bph 0x{address_or_symbol:x}, {bp_type}, {size}')
        else:
            return self.cmd_sync(f'bph {address_or_symbol}, {bp_type}, {size}')
    
    def set_memory_breakpoint(self, address_or_symbol: int | str, bp_type: MemoryBreakpointType = MemoryBreakpointType.a, restore: bool = True) -> bool:
        """
        Sets a memory breakpoint at the specified address or symbol.

        Args:
            address_or_symbol: Address or symbol to set the breakpoint at
            bp_type: Type of software breakpoint to set
            restore: Restore the original memory protection

        Returns:
            Success
        """
        if isinstance(address_or_symbol, int):
            return self.cmd_sync(f'bpm 0x{address_or_symbol:x}, {int(restore)}, {bp_type}')
        else:
            return self.cmd_sync(f'bpm {address_or_symbol}, {int(restore)}, {bp_type}')

    def clear_breakpoint(self, address_name_symbol_or_none: int | str | None = None) -> bool:
        """
        Clears software breakpoint at the specified address, name, or symbol.

        Args:
            address_name_symbol_or_none: Address or symbol to remove the breakpoint at (None removes all breakpoints of this type)

        Returns:
            Success
        """
        if address_name_symbol_or_none is None:
            return self.cmd_sync('bpc')
        if isinstance(address_name_symbol_or_none, int):
            return self.cmd_sync(f'bpc 0x{address_name_symbol_or_none:x}')
        return self.cmd_sync(f'bpc "{address_name_symbol_or_none}"')
    
    def clear_hardware_breakpoint(self, address_symbol_or_none: int | str | None = None) -> bool:
        """
        Clears hardware breakpoint at the specified address or symbol.

        Args:
            address_symbol_or_none: Address or symbol to remove the breakpoint at (None removes all breakpoints of this type)
            
        Returns:
            Success
        """
        if address_symbol_or_none is None:
            return self.cmd_sync('bphc')
        if isinstance(address_symbol_or_none, int):
            return self.cmd_sync(f'bphc 0x{address_symbol_or_none:x}')
        return self.cmd_sync(f'bphc {address_symbol_or_none}')
    
    def clear_memory_breakpoint(self, address_symbol_or_none: int | str | None = None) -> bool:
        """
        Clears memory breakpoint at the specified address or symbol.

        Args:
            address_symbol_or_none: Address or symbol to remove the breakpoint at (None removes all breakpoints of this type)
            
        Returns:
            Success
        """
        if address_symbol_or_none is None:
            return self.cmd_sync('bpmc')
        if isinstance(address_symbol_or_none, int):
            return self.cmd_sync(f'bpmc 0x{address_symbol_or_none:x}')
        return self.cmd_sync(f'bpmc {address_symbol_or_none}')
    
    def toggle_breakpoint(self, address_name_symbol_or_none: int | str | None = None, on: bool = True) -> bool:
        """
        Toggles software breakpoint at the specified address or symbol.

        Args:
            address_name_symbol_or_none: Address, name, or symbol to toggle the breakpoint at
            on: Enable or disable the breakpoint
            
        Returns:
            Success
        """
        toggle_cmd = 'bpe' if on else 'bpd'
        if isinstance(address_name_symbol_or_none, int):
            return self.cmd_sync(f'{toggle_cmd} 0x{address_name_symbol_or_none:x}')
        elif address_name_symbol_or_none is None:
            return self.cmd_sync(f'{toggle_cmd}')
        else:
            return self.cmd_sync(f'{toggle_cmd} {address_name_symbol_or_none}')
    
    def toggle_hardware_breakpoint(self, address_symbol_or_none: int | str | None = None, on: bool = True) -> bool:
        """
        Toggles hardware breakpoint at the specified address or symbol.

        Args:
            address_symbol_or_none: Address or symbol to toggle the breakpoint at
            on: Enable or disable the breakpoint
            
        Returns:
            Success
        """
        toggle_cmd = 'bphe' if on else 'bphd'
        if isinstance(address_symbol_or_none, int):
            return self.cmd_sync(f'{toggle_cmd} 0x{address_symbol_or_none:x}')
        elif address_symbol_or_none is None:
            return self.cmd_sync(f'{toggle_cmd}')
        else:
            return self.cmd_sync(f'{toggle_cmd} {address_symbol_or_none}')
    
    def toggle_memory_breakpoint(self, address_symbol_or_none: int | str | None = None, on: bool = True) -> bool:
        """
        Toggles memory breakpoint at the specified address or symbol.

        Args:
            address_symbol_or_none: Address or symbol to toggle the breakpoint at
            on: Enable or disable the breakpoint
            
        Returns:
            Success
        """
        toggle_cmd = 'bpme' if on else 'bpmd'
        if isinstance(address_symbol_or_none, int):
            return self.cmd_sync(f'{toggle_cmd} 0x{address_symbol_or_none:x}')
        elif address_symbol_or_none is None:
            return self.cmd_sync(f'{toggle_cmd}')
        else:
            return self.cmd_sync(f'{toggle_cmd} {address_symbol_or_none}')

    def set_label_at(self, address: int, text: str) -> bool:
        """
        Sets a label at the specified address

        Args:
            address: Address to set the label at
            text: Label text

        Returns:
            Success
        """
        if '"' in text:
            raise ValueError("Text cannot contain double quotes")
        return self.cmd_sync(f'lblset 0x{address:x}, "{text}"')

    def del_label_at(self, address: int) -> bool:
        """
        Deletes a label at the specified address

        Args:
            address: Address to clear the label at

        Returns:
            Success
        """
        return self.cmd_sync(f'lbldel 0x{address:x}')

    def set_comment_at(self, address: int, text: str) -> bool:
        """
        Sets a comment at the specified address

        Args:
            address: Address to set the comment at
            text: comment text

        Returns:
            Success
        """
        if '"' in text:
            raise ValueError("Text cannot contain double quotes")
        return self.cmd_sync(f'cmtset 0x{address:x}, "{text}"')

    def del_comment_at(self, address: int) -> bool:
        """
        Deletes a comment at the specified address

        Args:
            address: Address to clear the comment at

        Returns:
            Success
        """
        return self.cmd_sync(f'cmtdel 0x{address:x}')

    def hide_debugger_peb(self) -> bool:
        """
        Hides the debugger in the debugee's PEB

        Returns:
            Success
        """
        return self.cmd_sync(f'hide')

    def debugee_pid(self) -> int | None:
        """
        Retrieves the PID of the debugee

        Returns:
            PID of the debugee, or None if the debugger is not debugging
        """
        if self.is_debugging():
            pid, res = self.eval_sync(f'pid')
            if res:
                return pid
        return None

    def thread_create(self, addr: int, arg: int = 0) -> int | None:
        """
        Create a new thread in the debugee.

        Args:
            addr: Address of the thread entry point
            arg: Argument to pass to the thread
        """
        success = self.cmd_sync(f'createthread 0x{addr:x}, 0x{arg:x}')
        if not success:
            return None
        tid, success = self.eval_sync('$result')
        if not success:
            return None
        return tid

    def thread_terminate(self, tid: int):
        """
        Kills a thread in the debugee.

        Args:
            tid: Thread ID to kill
        """
        return self.cmd_sync(f'killthread 0x{tid:x}')

    def thread_pause(self, tid: int):
        """
        Pauses a thread in the debugee.

        Args:
            tid: Thread ID to kill
        """
        return self.cmd_sync(f'suspendthread 0x{tid:x}')

    def thread_resume(self, tid: int):
        """
        Resumes a thread in the debugee.

        Args:
            tid: Thread ID to kill
        """
        return self.cmd_sync(f'resumethread 0x{tid:x}')

    def switch_thread(self, tid: int):
        """
        Switches the currently observed debugger thread.

        Args:
            tid: Thread ID to kill
        """
        return self.cmd_sync(f'switchthread 0x{tid:x}')
    
    def assemble_at(self, addr: int, instr: str) -> int | None:
        """
        Assembles a single instruction at the specified address

        Args:
            addr: Address to assemble at
            instr: Instruction to assemble

        Returns:
            The size of the assembled instruction, or None on failure
        """
        res = self._assemble_at(addr, instr)
        if not res:
            return None
        ins = self.disassemble_at(addr)
        if not ins:
            return None
        return ins.instr_size
