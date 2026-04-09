![Undertaker](https://github.com/user-attachments/assets/699f7243-1bd8-46b7-aa68-b7fb6ca25f14)

# Undertaker

Undertaker is a static malware analysis tool that triages a sample and produces a structured report you hand to Claude alongside Ghidra MCP.

Point it at a binary. Get hashes, packing detection, suspicious imports, IOCs, strings of interest, capability tags, and YARA matches — in one command:

```
undertaker analyze sample.dll
```

No execution. No dynamic analysis. Just fast, structured static triage that gives Claude the map before it navigates the binary through Ghidra.

Planning documents:

- [Product plan](docs/PRODUCT_PLAN_V2.md)

Current status: planning stage.
