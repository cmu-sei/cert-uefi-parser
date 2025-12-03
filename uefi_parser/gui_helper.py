"""
Cross-platform environment checker for GUI (PySide6).
Use before importing Qt modules or creating QApplication.

Example:
    from cert_uefi_parser.environment import ensure_gui_environment
    ensure_gui_environment(require_gui=True)
"""

import sys
import os
import ctypes
import ctypes.util


# ----------------------------
# Helper: check if PySide6 exists
# ----------------------------
def _pyside6_installed():
    try:
        import PySide6  # noqa
        return True
    except ImportError:
        return False


# ----------------------------
# Linux-specific checks
# ----------------------------
def _check_linux_graphics():
    # 1. Check for a graphical environment
    display = os.environ.get("DISPLAY")
    wayland = os.environ.get("WAYLAND_DISPLAY")

    if not display and not wayland:
        print(
            "No graphical environment detected.\n\n"
            "This GUI requires one of the following:\n"
            " - X11 (DISPLAY)\n"
            " - Wayland (WAYLAND_DISPLAY)\n\n"
            "If running over SSH, use:  ssh -X  or  ssh -Y\n"
            "If running on a server, you may need:  xvfb-run python yourapp.py\n"
        )
        return False

    # 2. Check for required XCB libraries used by Qt
    required_xcb = [
        "xcb", "xcb-render", "xcb-shm", "xcb-cursor", "xcb-icccm",
        "xcb-keysyms", "xcb-randr", "xcb-xinerama", "xcb-xfixes"
    ]

    missing = [lib for lib in required_xcb if ctypes.util.find_library(lib) is None]

    if missing:
        print(
            "Missing required system libraries for Qt (XCB backend):\n"
            + "".join(f" - {lib}\n" for lib in missing)
            + "\nInstall them using your system package manager.\n\n"
            "Ubuntu/Debian example:\n"
            "  sudo apt install libxcb-cursor0 libxcb-icccm4 "
            "libxcb-keysyms1 libxcb-shape0 libxcb-xinerama0 "
            "libxcb-render-util0\n"
        )
        return False
    return True

# ----------------------------
# Main cross-platform entry point
# ----------------------------
def ensure_gui_environment(require_gui: bool = False):
    """
    Verifies that the runtime environment supports GUI operations.

    Parameters
    ----------
    require_gui : bool
        If True -> GUI is required and PySide6 must exist.
        If False ->  Return silently if GUI is not needed.
    """

    # If GUI is not required, we skip everything.
    if not require_gui:
        return False

    # Check if PySide6 is installed at all.
    if not _pyside6_installed():
        print(
            "GUI support requested but PySide6 is not installed.\n\n"
            "Install with:\n"
            "    pip install cert-uefi-parser[qt]\n"
        )
        return False

    # Per-OS behavior
    if sys.platform.startswith("win"):
        # Windows always works — Qt uses native backend.
        return True

    if sys.platform == "darwin":
        # macOS also always works — uses Cocoa backend.
        return True

    if sys.platform.startswith("linux") and _check_linux_graphics():
        return True

    # Unsupported OS
    print(f"Unsupported OS for GUI: {sys.platform}")
