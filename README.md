# x64dbg Automate: Reference Python Client

This is the reference client of x64dbg Automate. The library builds on x64dbg's command execution engine and plugin API to provide an expressive, modern, and easy to use Python client. x64dbg Automate is useful in a wide variety of malware analysis, reverse engineering, and vulnerability hunting tasks. 

The client implements the full RPC protocol provided by [x64dbg-automate](https://github.com/dariushoule/x64dbg-automate). 

## Documentation

Full project documentation is published on: [https://dariushoule.github.io/x64dbg-automate-pyclient/](https://dariushoule.github.io/x64dbg-automate-pyclient/)

See: [Installation](https://dariushoule.github.io/x64dbg-automate-pyclient/installation/) and [Quickstart](https://dariushoule.github.io/x64dbg-automate-pyclient/quickstart/)

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

# Contributing

Issues, feature-requests, and pull-requests are welcome on this project ❤️🐛

My commitment to the community will be to be a responsive maintainer. Discuss with me before implementing major breaking changes or feature additions.