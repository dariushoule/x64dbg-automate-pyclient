from enum import IntEnum, StrEnum
from pydantic import BaseModel


class MemPage(BaseModel):
    base_address: int
    allocation_base: int
    allocation_protect: int
    partition_id: int
    region_size: int
    state: int
    protect: int
    type: int
    info: str


class X87Fpu(BaseModel):
    ControlWord: int
    StatusWord: int
    TagWord: int
    ErrorOffset: int
    ErrorSelector: int
    DataOffset: int
    DataSelector: int
    Cr0NpxState: int


class X87StatusWordFields(BaseModel):
    B: bool
    C3: bool
    C2: bool
    C1: bool
    C0: bool
    ES: bool
    SF: bool
    P: bool
    U: bool
    O: bool
    Z: bool
    D: bool
    I: bool
    TOP: int


class X87ControlWordFields(BaseModel):
    IC: bool
    IEM: bool
    PM: bool
    UM: bool
    OM: bool
    ZM: bool
    DM: bool
    IM: bool
    RC: int
    PC: int


class Context64(BaseModel):
    rax: int
    rbx: int
    rcx: int
    rdx: int
    rbp: int
    rsp: int
    rsi: int
    rdi: int
    r8: int
    r9: int
    r10: int
    r11: int
    r12: int
    r13: int
    r14: int
    r15: int
    rip: int
    eflags: int
    cs: int
    ds: int
    es: int
    fs: int
    gs: int
    ss: int
    dr0: int
    dr1: int
    dr2: int
    dr3: int
    dr6: int
    dr7: int
    reg_area: bytes
    x87_fpu: X87Fpu
    mxcsr: int
    xmm_regs: list[bytes]
    ymm_regs: list[bytes]


class Context32(BaseModel):
    eax: int
    ebx: int
    ecx: int
    edx: int
    ebp: int
    esp: int
    esi: int
    edi: int
    eflags: int
    cs: int
    ds: int
    es: int
    fs: int
    gs: int
    ss: int
    dr0: int
    dr1: int
    dr2: int
    dr3: int
    dr6: int
    dr7: int
    reg_area: bytes
    x87_fpu: X87Fpu
    mxcsr: int
    xmm_regs: list[bytes]
    ymm_regs: list[bytes]


class Flags(BaseModel):
    c: bool
    p: bool
    a: bool
    z: bool
    s: bool
    t: bool
    i: bool
    d: bool
    o: bool


class MxcsrFields(BaseModel):
    FZ: bool
    PM: bool
    UM: bool
    OM: bool
    ZM: bool
    IM: bool
    DM: bool
    DAZ: bool
    PE: bool
    UE: bool
    OE: bool
    ZE: bool
    DE: bool
    IE: bool
    RC: int


class FpuReg(BaseModel):
    data: bytes
    st_value: int
    tag: int


class RegDump(BaseModel):
    flags: Flags
    fpu: list[FpuReg]
    mmx: list[int]
    mxcsr_fields: MxcsrFields
    x87_status_word_fields: X87StatusWordFields
    x87_control_word_fields: X87ControlWordFields
    last_error: tuple[int, str]
    last_status: tuple[int, str]


class RegDump64(RegDump):
    context: Context64


class RegDump32(RegDump):
    context: Context32


class MutableRegister(StrEnum):
    rax = 'rax'
    rbx = 'rbx'
    rcx = 'rcx'
    rdx = 'rdx'
    rbp = 'rbp'
    rsp = 'rsp'
    rsi = 'rsi'
    rdi = 'rdi'
    r8 = 'r8'
    r9 = 'r9'
    r10 = 'r10'
    r11 = 'r11'
    r12 = 'r12'
    r13 = 'r13'
    r14 = 'r14'
    r15 = 'r15'
    rip = 'rip'
    eflags = 'eflags'
    rflags = 'rflags'
    cs = 'cs'
    ds = 'ds'
    es = 'es'
    fs = 'fs'
    gs = 'gs'
    ss = 'ss'
    dr0 = 'dr0'
    dr1 = 'dr1'
    dr2 = 'dr2'
    dr3 = 'dr3'
    dr6 = 'dr6'
    dr7 = 'dr7'
    eax = 'eax'
    ebx = 'ebx'
    ecx = 'ecx'
    edx = 'edx'
    ebp = 'ebp'
    esp = 'esp'
    esi = 'esi'
    edi = 'edi'
    ax = 'ax'
    bx = 'bx'
    cx = 'cx'
    dx = 'dx'
    si = 'si'
    di = 'di'
    bp = 'bp'
    sp = 'sp'
    al = 'al'
    bl = 'bl'
    cl = 'cl'
    dl = 'dl'
    ah = 'ah'
    bh = 'bh'
    ch = 'ch'
    dh = 'dh'
    sil = 'sil'
    dil = 'dil'
    bpl = 'bpl'
    spl = 'spl'
    r8d = 'r8d'
    r9d = 'r9d'
    r10d = 'r10d'
    r11d = 'r11d'
    r12d = 'r12d'
    r13d = 'r13d'
    r14d = 'r14d'
    r15d = 'r15d'
    r8w = 'r8w'
    r9w = 'r9w'
    r10w = 'r10w'
    r11w = 'r11w'
    r12w = 'r12w'
    r13w = 'r13w'
    r14w = 'r14w'
    r15w = 'r15w'
    r8b = 'r8b'
    r9b = 'r9b'
    r10b = 'r10b'
    r11b = 'r11b'
    r12b = 'r12b'
    r13b = 'r13b'
    r14b = 'r14b'
    r15b = 'r15b'
    # TODO: MM registers, these are tricker because they need to get loaded via something like: https://help.x64dbg.com/en/latest/commands/general-purpose/movdqu.html


class PageRightsConfiguration(StrEnum):
    Execute = "Execute"
    ExecuteRead = "ExecuteRead"
    ExecuteReadWrite = "ExecuteReadWrite"
    ExecuteWriteCopy = "ExecuteWriteCopy"
    NoAccess = "NoAccess"
    ReadOnly = "ReadOnly"
    ReadWrite = "ReadWrite"
    WriteCopy = "WriteCopy"


class StandardBreakpointType(StrEnum):
    SingleShotInt3 = 'ss' # CC (SingleShoot)
    Long = 'long' # CD03
    Ud2 = 'ud2' # 0F0B
    Short = 'short' # CC


class DisasmInstrType(IntEnum):
    Normal = 0
    Branch = 1
    Stack = 2


class DisasmArgType(IntEnum):
    Normal = 0
    Memory = 1


class SegmentReg(IntEnum):
    SegDefault = 0
    SegEs = 1
    SegDs = 2
    SegFs = 3
    SegGs = 4
    SegCs = 5
    SegSs = 6


class InstructionArg(BaseModel):
    mnemonic: str
    type: DisasmArgType
    segment: SegmentReg
    constant: int
    value: int
    memvalue: int


class Instruction(BaseModel):
    instruction: str
    argcount: int
    instr_size: int
    type: DisasmInstrType
    arg: list[InstructionArg]


class BreakpointType(IntEnum):
    BpNone = 0,
    BpNormal = 1,
    BpHardware = 2,
    BpMemory = 4,
    BpDll = 8,
    BpException = 16


class Breakpoint(BaseModel):
    type: BreakpointType
    addr: int
    enabled: bool
    singleshoot: bool
    active: bool
    name: str
    mod: str
    slot: int
    typeEx: int
    hwSize: int
    hitCount: int
    fastResume: bool
    silent: bool
    breakCondition: str
    logText: str
    logCondition: str
    commandText: str
    commandCondition: str


class SymbolType(IntEnum):
    SymImport = 0
    SymExport = 1
    SymSymbol = 2


class Symbol(BaseModel):
    addr: int
    decoratedSymbol: str
    undecoratedSymbol: str
    type: int
    ordinal: int
