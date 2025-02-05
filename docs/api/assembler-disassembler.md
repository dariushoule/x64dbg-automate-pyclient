# Assembling and Disassembling

The Assembler and Disassembler features of x64dbg are supported in Automate. Symbols and expressions are supported in the assembler as they are in the UI.


### API Method Reference


::: x64dbg_automate.X64DbgClient.assemble_at
    options:
        show_root_heading: true
        show_root_full_path: false


::: x64dbg_automate.X64DbgClient.disassemble_at
    options:
        show_root_heading: true
        show_root_full_path: false


### API Model Reference

::: x64dbg_automate.models.Instruction
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false


::: x64dbg_automate.models.DisasmInstrType
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false


::: x64dbg_automate.models.DisasmArgType
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false


::: x64dbg_automate.models.InstructionArg
    options:
        show_root_heading: true
        show_root_full_path: false
        show_bases: false