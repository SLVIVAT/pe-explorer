# PE Explorer Professional

A modern Windows Portable Executable (PE) analysis and reverse engineering tool written in Python and PySide6.

## Overview

PE Explorer Professional is a desktop application for inspecting and analyzing Windows PE (Portable Executable) files without relying on external PE parsing libraries. The project focuses on correctness, performance, and a modern user interface suitable for reverse engineering and malware analysis workflows.

## Features

### PE Analysis
- DOS Header
- COFF Header
- Optional Header (PE32 / PE32+)
- Section Table
- Data Directories
- Import Table
- Export Table
- Resources
- VERSIONINFO
- Digital Signature (WIN_CERTIFICATE)

### Analysis
- Security Analysis
- Entropy Analysis
- Overlay Detection
- Strings Extraction
- Hash Calculation (MD5, SHA-1, SHA-256, SHA-512)

### Reverse Engineering Tools
- Virtualized Hex Viewer
- ASCII / UTF-16 / Hex Search
- RVA / VA / File Offset Navigation
- Background Analysis
- HTML / JSON / Markdown Reports

## Technologies

- Python
- PySide6 (Qt)
- Qt Model/View Architecture
- Manual PE parsing (no external PE parsing libraries)

## Performance

- Optimized for large executable files
- Virtualized Hex Viewer (supports very large files)
- Background parsing and search
- Asynchronous operations
- Low memory usage

## Testing

- 160 automated tests
- Successfully validated on thousands of real PE files
- PE32 and PE32+ support

## Screenshots

*(Screenshots will be added soon.)*

## Future Development

- Additional reverse engineering capabilities
- Extended certificate analysis
- Plugin architecture

## Author

Created by **SLVIVAT**.
