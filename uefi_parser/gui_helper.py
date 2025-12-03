#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# CERT UEFI Parser
#
# Copyright 2025 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL
# IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY
# KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO,
# WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED
# FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY
# KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a BSD (SEI)-style license, please see license.txt or contact
# permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public release and
# unlimited distribution.  Please see Copyright notice for non-US Government use and
# distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject to its own
# license.
#
# DM25-1401
"""
Cross-platform environment checker for GUI (PySide6).
Use before importing Qt modules or creating QApplication.

Example:
    from cert_uefi_parser.environment import ensure_gui_environment
    ensure_gui_environment(require_gui=True)
"""

import sys
import os
import ctypes.util
from argparse import ArgumentParser

# ----------------------------
# Helper: check if PySide6 exists
# ----------------------------
def _pyside6_installed() -> bool:
    try:
        import PySide6  # noqa [F401]
        return True
    except ImportError:
        return False


# ----------------------------
# Linux-specific checks
# ----------------------------
def _check_linux_graphics(argparser: ArgumentParser) -> bool:
    # 1. Check for a graphical environment
    display = os.environ.get("DISPLAY")
    wayland = os.environ.get("WAYLAND_DISPLAY")

    if not display and not wayland:
        argparser.error(
            "No graphical environment detected.\n\n"
            "This GUI requires one of the following:\n"
            " - X11 (DISPLAY)\n"
            " - Wayland (WAYLAND_DISPLAY)\n\n"
            "If running over SSH, use:  ssh -X  or  ssh -Y\n"
            "If running on a server, you may need:  xvfb-run python yourapp.py"
        )
        return False

    # 2. Check for required XCB libraries used by Qt
    required_xcb = [
        "xcb", "xcb-render", "xcb-shm", "xcb-cursor", "xcb-icccm",
        "xcb-keysyms", "xcb-randr", "xcb-xinerama", "xcb-xfixes"
    ]

    missing = [lib for lib in required_xcb if ctypes.util.find_library(lib) is None]

    if missing:
        argparser.error(
            "Missing required system libraries for Qt (XCB backend):\n"
            + "".join(f" - {lib}\n" for lib in missing)
            + "\nInstall them using your system package manager.\n\n"
            "Ubuntu/Debian example:\n"
            "  sudo apt install libxcb-cursor0 libxcb-icccm4 "
            "libxcb-keysyms1 libxcb-shape0 libxcb-xinerama0 "
            "libxcb-render-util0"
        )
        return False
    return True

# ----------------------------
# Main cross-platform entry point
# ----------------------------
def ensure_gui_environment(argparser: ArgumentParser) -> bool:
    """
    Verifies that the runtime environment supports GUI operations.
    """
    # Check if PySide6 is installed at all.
    if True or not _pyside6_installed():
        argparser.error(
            "GUI support requested but PySide6 is not installed.\n\n"
            "Install with:  pip install cert-uefi-parser[qt]")
        return False

    # Per-OS behavior
    if sys.platform.startswith("win"):
        # Windows always works — Qt uses native backend.
        return True

    if sys.platform == "darwin":
        # macOS also always works — uses Cocoa backend.
        return True

    if sys.platform.startswith("linux"):
        if _check_linux_graphics(argparser):
            return True
        return False

    # Unsupported OS
    argparser.error(f"Unsupported OS for GUI: {sys.platform}")
    return False
