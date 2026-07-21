# PE Explorer

PE Explorer is a PySide6 desktop application for inspecting Windows Portable
Executable (PE) files. It parses the format directly with Python and `struct`;
no external PE parsing library is used.

## Features

- Opens EXE, DLL, SYS, OCX, CPL, PYD, MUI, and other PE images
- Manually parses complete PE32 and PE32+ headers and section tables
- Parses all data directories and reports whether each range is present,
  absent, file-backed, virtual-only, truncated, or invalid
- Parses imports by name and ordinal, including lookup/IAT locations and bound
  address fallbacks
- Parses export names, aliases, ordinals, RVAs, unused EAT slots, and forwarded
  exports
- Parses the complete resource hierarchy, including named and language nodes,
  and decodes icons, version data, manifests, dialogs, string tables, and bitmap
  metadata
- Explains architecture, image type, ASLR, DEP, CFG, signature presence,
  suspicious sections, writable/executable sections, packing indicators, and
  the aggregate Low/Medium/High risk rating
- Presents a virtualized Hex view with file-offset, RVA, and VA navigation,
  byte-range selection, highlighting, and copying
- Searches asynchronously by ASCII, UTF-16LE, hexadecimal bytes, RVA, VA, or
  file offset and links results directly to the Hex view
- Extracts, sorts, filters, copies, and navigates ASCII and UTF-16LE strings;
  the document pipeline applies a clearly disclosed 250,000-row safety cap
  while Global Search always scans the complete file
- Calculates section entropy, MD5/SHA hashes, overlay regions, digital-signature
  metadata, and version information
- Exports deterministic HTML, JSON, and Markdown reports
- Loads and analyzes files on a worker thread so the interface remains
  responsive
- Uses virtual Qt models, lazy ordered string extraction, typed in-model
  sorting, and stale-result guards to keep large-file workflows responsive
- Supports drag-and-drop, recent files, keyboard shortcuts, sortable Qt views,
  and a consistent professional dark theme
- Rejects malformed or truncated structures with contextual errors

The main workspace contains 12 tabs: Overview, Optional Header, Sections,
Imports, Exports, Resources, Data Directories, Analysis, Hex, Search, Strings,
and File Analysis.

## Run

```powershell
python -m pip install -r requirements.txt
python main.py
```

Open a file with the toolbar, drag it onto the window, or select it from the
Recent menu. Useful shortcuts are:

| Shortcut | Action |
|---|---|
| `Ctrl+O` | Open a PE file |
| `Ctrl+F` | Activate global search |
| `Ctrl+G` | Activate the Hex address control |
| `Ctrl+Shift+S` | Generate a report |

Double-click a Search result to open and highlight its bytes in the Hex tab.
Selections throughout the structural, resource, string, entropy, and overlay
views are synchronized with the same Hex data source.

## Reports

After loading a file, choose **Generate Report** and select HTML, JSON, or
Markdown. Reports include the structural parser results, security findings,
entropy and overlay analysis, hashes, digital-signature details, and version
information. Raw executable bytes and the potentially large extracted-string
collection are not embedded in reports.

## Test

The test suite generates deterministic PE32 and PE32+ images in temporary
directories, covers malformed and truncated inputs, and exercises the GUI with
Qt's offscreen platform. Integrated validation also covers representative real
PE32 and PE32+ executables when they are available in the project environment.

```powershell
python -m unittest discover -s tests -v
```

## Requirements

- Python 3.10 or newer
- PySide6 6.9 or newer
