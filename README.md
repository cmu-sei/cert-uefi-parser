CERT UEFI Parser
================

The CERT UEFI Parser is a Python-based tool for inspecting firmware ROM
images, installers, and related files, especially those associated with UEFI.
It combines information from the UEFI specifications with insights from
independent firmware research (for example, Igor Skochinsky’s Intel ME work).

Written for Python 3 and built on the Construct parsing framework, the parser
is more flexible than the EDK2 reference implementation and is easier to extend
to proprietary or experimental data structures.  CERT UEFI Parser aims to
support all data formats commonly found inside UEFI ROMs, including Portable
Executables (PEs) and image structures.  The project is free of NDAs or other
restrictions; all proprietary formats have been reverse engineered from public
information and original analysis.

Installation
------------

The parser depends on the **cert-uefi-support** package, which provides
lower-level decompression and binary utilities.  Both packages are now
available on PyPI.

Basic installation:

```
  $ python3 -m venv cert-venv
  $ source cert-venv/bin/activate
  $ pip install cert-uefi-support cert-uefi-parser
```

### Optional GUI Support (Qt)

GUI support is optional and provided via the PySide6 package.  It is a
large dependency, so it is not installed by default.  To install with the GUI
extras:

```
  $ pip install cert-uefi-support cert-uefi-parser[qt]
```


### Installing from the Official Git Repositories


```
  $ python3 -m venv cert-venv
  $ git clone https://github.com/cmu-sei/cert-uefi-support.git
  $ cd cert-uefi-support
  $ git submodule update --init --recursive
  $ ../cert-venv/bin/pip install .
  $ cd ..
  
  $ git clone https://github.com/cmu-sei/cert-uefi-parser.git
  $ cd cert-uefi-parser
  $ ../cert-venv/bin/pip install .
  $ cd ..
```


Usage
-----

CERT UEFI Parser provides four primary output modes: a graphical interface, an
ASCII text display (with ANSI color output enabled by default), a full JSON
representation, and a filtered JSON representation containing fields that are
useful for generating a Software Bill of Materials (SBOM).


```
  $ ./cert-venv/bin/cert-uefi-parser --gui {firmware-related-file}
  $ ./cert-venv/bin/cert-uefi-parser --text {firmware-related-file} | less
  $ ./cert-venv/bin/cert-uefi-parser --json {firmware-related-file} >output.json
  $ ./cert-venv/bin/cert-uefi-parser --sbom {firmware-related-file} >output.json
```


Sample firmware files can typically be obtained by downloading the BIOS or
UEFI update tools from your system vendor’s support site.  While not all
models are guaranteed to be fully supported, many common vendor formats parse
successfully, and examining these update files is a good way to begin exploring
the parser’s capabilities.

