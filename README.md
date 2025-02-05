# x64dbg Automate: Reference Python Client

This repository contains the source code for the reference client of x64dbg Automate.

The client implements the full RPC protocol provided by [x64dbg-automate](https://github.com/dariushoule/x64dbg-automate), as well as builds on it for enhanced functionality. 

## Documentation

Full documentation is published on: TODO

[Installation](todo) and [Quickstart](todo)

🔔 _All examples and sample code assume x64dbg is configured to stop on entry and system breakpoints, skipping TLS breakpoints._

## Development and Testing

The client's environment is managed with [poetry](https://python-poetry.org/docs/). 

Update `tests/conftest.py` or provide the requisite environment to allow tests to pass. 

```powershell
poetry install
poetry env activate
python -m pytest # Test
python .\examples\assemble_and_disassemble.py C:\<you>\x64dbg\release\x64\x64dbg.exe # Run an example
```

**Documentation is built using mkdocs**

```powershell
python -m mkdocs serve # dev
python -m mkdocs build # publish
```