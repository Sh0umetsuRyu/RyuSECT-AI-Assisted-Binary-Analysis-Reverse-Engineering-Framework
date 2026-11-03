# RyuSECT™

### AI-Assisted Binary Analysis & Reverse Engineering Framework

**Developed by RyujinWARE™**

**Current version: v0.2 | Early Development**

RyuSECT is an evolving reverse-engineering application designed to bring binary disassembly, decompilation, firmware investigation, and eventually AI-assisted analysis together in a unified interface.

Built around established analysis technology, beginning with Rizin, RyuSECT aims to make complex binary investigations more accessible, organized, and repeatable.

The long-term goal is not simply to display assembly instructions, but to help investigators understand what software does, how its components interact, and where important behavior originates.

## Current Development Status

**IMPORTANT: AI functionality is NOT incorporated into RyuSECT v0.2.**

RyuKORE Mini, our planned local AI analysis component, is currently in the development roadmap. The existing release is a functional, non-AI disassembly prototype.

### Working Features in v0.2

- PySide6 graphical interface
- Rizin-powered MIPS32 little-endian disassembly
- Configurable raw binary base address
- Virtual address and file-offset navigation
- 4 KiB paginated disassembly viewing
- Hexadecimal preview
- First nonzero-region detection
- Raw whole-file disassembly export
- Basic background export progress and navigation controls

Whole-file export currently decodes raw byte ranges. It does not yet distinguish all executable code from embedded data, recover every function, or provide complete semantic analysis.

## AI Integration Roadmap

RyuSECT will eventually incorporate **RyuKORE Mini**, a lightweight local AI analysis system.

Its intended capabilities include:

- Interpreting recovered assembly and pseudocode
- Suggesting function names and descriptions
- Investigating cross-references and call chains
- Finding potentially important conditional branches
- Tracking analysis evidence and confidence
- Suggesting follow-up investigations
- Reducing repeated manual analysis work

AI findings will be treated as hypotheses until supported by verifiable evidence.

### Development Timeline

| Target period | Milestone |
|---|---|
| October 29 – November 4, 2026 | v0.2 foundation, Rizin integration, GUI navigation |
| November 5 – 11, 2026 | Function analysis, cross-references, indexing, decompilation integration |
| November 12 – 18, 2026 | Initial local RyuKORE Mini AI integration |
| November 19 – 26, 2026 | First real-world AI-assisted firmware investigation |

**These dates are development targets and may change.** AI-assisted functionality is not available in the current release.

## Initial Research Target

RyuSECT is being developed and tested using firmware from the HiChip HC16xx embedded platform, associated with the RyujinWARE RyuSPARK Cinder research project.

Current research focuses on MIPS firmware, Linux and HCRtos components, USB controller behavior, firmware initialization, and binary function discovery.

Proprietary firmware images are not distributed with RyuSECT.

## Requirements

- Linux development environment
- Python 3
- PySide6
- Rizin
- rzpipe

## Running the Development Version

Install Rizin using your distribution's package manager.

Create a Python virtual environment and install the Python dependencies:

```bash
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Launch RyuSECT:

```bash
.venv/bin/python ryuhex.py
```

A packaged standalone release and desktop integration are planned but are not part of the current source distribution.

## Project Direction

RyuSECT is intended to operate as a standalone reverse-engineering application.

Future releases will add broader architecture support, function analysis, decompilation, structured investigation reports, and integration with RyuKORE.

RyuFORGE is a separate RyujinWARE project focused on binary and software creation and build tooling.

## Credits

**Shoumetsu Ryū (Reshii)**  
RyujinWARE Founder, Project Lead & Lead Co-Developer

**Echo Fox**  
AI R&D Head & Co-Developer

RyuSECT uses and builds upon independent open-source software, including Rizin and PySide6. These tools are not developed or owned by RyujinWARE.

---

**RyujinWARE™ | RyuSECT v0.2**

*Understand the binary. Trace the logic. Discover the unknown.*
