# CFG recovery with Ghidra

Export the control flow graph (functions, basic blocks, edges, indirect call sites) from a binary to JSON using Ghidra headless. The output is intended for use by the remill lifter pipeline.

## Prerequisites

- [Ghidra](https://ghidra-sre.org/) installed; `analyzeHeadless` must be on your `PATH` or run from Ghidra’s support directory (e.g. `Ghidra/support`).

## Usage

1. **Point headless at your script directory**  
   Use `-scriptPath` so Ghidra can find `ExportCFG.java`.

2. **Import and analyze the binary**  
   Use `-import <path_to_binary>` so the program is imported and analyzed before the postScript runs.

3. **Run the CFG export postScript**  
   Use `-postScript ExportCFG.java <output.json>` and pass the desired output JSON path as the first (and only) script argument.

### Example (Unix)

```bash
analyzeHeadless /tmp/ghidra_proj MyProject \
  -import /path/to/game.exe \
  -postScript ExportCFG.java /path/to/cfg_output.json \
  -scriptPath /path/to/levo/ghidra_cfg
```

### Example (Windows)

```powershell
analyzeHeadless C:\ghidra_proj MyProject `
  -import C:\path\to\game.exe `
  -postScript ExportCFG.java C:\path\to\cfg_output.json `
  -scriptPath C:\path\to\levo\ghidra_cfg
```

To run on an already-imported program (no import, no analysis):

```bash
analyzeHeadless /tmp/ghidra_proj MyProject \
  -process existing_binary.exe \
  -postScript ExportCFG.java cfg_output.json \
  -scriptPath /path/to/levo/ghidra_cfg
```

## Output JSON format

- **program_name** – Domain file name of the program.
- **image_base** – Program image base address (hex string).
- **functions** – Array of function CFGs:
  - **name** – Function symbol name.
  - **address** – Entry point (hex string).
  - **blocks** – Basic blocks: `start` and `end` addresses (hex strings). The range is **[start, end)** (inclusive start, exclusive end; `end` is the first address after the last byte of the block).
  - **edges** – Control flow edges: `from`, `to` (block start addresses), `type` (`"call"`, `"branch"`, `"fallthrough"`), and optional `indirect: true`.
  - **indirect_call_sites** – Addresses of instructions that perform indirect calls (for `call_indirect` table generation).

All addresses are hex strings with a `0x` prefix (e.g. `"0x401000"`).
