CERT UEFI Parser
================

The CERT UEFI Parser is a tool for inspecting firmware ROM images,
installers, and related files, especially those related to UEFI.  It
pulls together information from the UEFI standards and a variety of
independent research (e.g. Igor Skochinsky's Intel ME work).

Written in Python version 3 and using the Construct module, it's less
rigid than the EDK2 UEFI reference implementation and more easily
extended to support proprietary and experimental data structure
parsing.  CERT UEFI Parser is intended to parse all related data
formats including standard file formats commonly found inside UEFI
ROMs such as Portable Executables (PEs) and images. CERT UEFI Parser
is free from NDAs or other restrictions on proprietary formats, having
been reverse engineered from widely available public information and
original work.

Installation
------------

To install CERT UEFI Parser, you'll need a Python virtual environment
containing not only this repository, but also a related support
library, CERT UEFI support.   The commands to install everything are:

```
  $ python3 -m venv cert-venv

  $ git clone https://github.com/cmu-sei/cert-uefi-support
  $ cd cert-uefi-support
  $ git submodule update --init --recursive
  $ ../cert-venv/bin/pip install .
  $ cd ..
  
  $ git clone https://github.com/cmu-sei/cert-uefi-parser
  $ cd cert-uefi-parser
  $ ../cert-venv/bin/pip install .
  $ cd ..
```

Usage
-----

CERT UEFI Parser has four primary modes: a GUI display, an ASCII text
display (including ANSI color codes by default), a JSON format, and a
filtered JSON format containing fields that might be interest for
generating an SBOM.

```
  $ ./cert-venv/bin/cert-uefi-parser --gui {firmware-related-file}
  $ ./cert-venv/bin/cert-uefi-parser --text {firmware-related-file} | less
  $ ./cert-venv/bin/cert-uefi-parser --json {firmware-related-file} >output.json
  $ ./cert-venv/bin/cert-uefi-parser --sbom {firmware-related-file} >output.json
```

For sample input files, we recommend downloading the BIOS updater
executable that your hardware vendor ships through their normal
support channels.  While not all models are guaranteed to be
supported, many of the popular vendors are, and examining a ROM update
is a good place to get started exploring on exploring the capabilities
of CERT UEFI Parser.
