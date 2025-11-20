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
Support for PLF firmware.

Use for Parrot drones.

Thanks to: https://embedded-software.blogspot.com/2010/12/plf-file-format.html
"""

import math
import gzip
from typing import Optional

from construct import (
    Int16ul, Int32ul, Const, Bytes, GreedyBytes, GreedyRange, Array, this)

from .base import (
    FirmwareStructure, Struct, Class, CString, PaddedString, EnumAdapter, Context)
from .mystery import MysteryBytes, HexDump
from .uenum import UEnum
from .pfs import TextFile
from .exes import ELFExecutable
from .vendor import PNGImage, GIFImage, TIFFImage, JPGImage, OpenTypeFont

# ----------------------------------------------------------------------------------------
class PLFSectionType(UEnum):
    Unknown = 0
    BootLoader = 3
    Section7 = 7
    Filesystem = 9
    Configuration = 11
    Installer = 12

# ----------------------------------------------------------------------------------------
def lazy_plf_firmware(ctx: Context) -> Class:
    return Class(PLFFirmware)

# ----------------------------------------------------------------------------------------
class UBX8Firmware(FirmwareStructure):
    """
    A fake structure that recognizes the magic of a UBX8 U-Blox GPS Firmware.
    """

    label = "UBX8 U-Blox GPS Firmware"

    definition = Struct(
        "magic" / Const(b"UBX8"),
        "_data" / Class(MysteryBytes),
    )

    reporting = [["magic"], ["_data"]]

# ----------------------------------------------------------------------------------------
class PLFConfigEntry(FirmwareStructure):
    """
    A PLF configuration entry.
    """

    label = "PLF Config Entry"

    definition = Struct(
        "device" / Int16ul,
        "voltype" / Int16ul,
        "volume" / Int16ul,
        "u1" / Int16ul,
        "volume_size" / Int32ul,
        "volume_action" / Int32ul,
        "volume_name" / PaddedString(32),
        "mount_name" / PaddedString(32),
    )

    reporting = [
        ["device"], ["voltype"], ["volume"],
        ["u1"], ["volume_size"], ["volume_action"], ["volume_name"], ["mount_name"],
    ]

    def instance_name(self) -> str:
        return str(self.volume_name)

# ----------------------------------------------------------------------------------------
class PLFSection7(FirmwareStructure):
    """
    A PLF section that sometimes contains boot parameters.
    """

    label = "PLF Section 7 (Boot Params?)"

    definition = Struct(
        "_data" / GreedyBytes,
    )

    reporting = [["interpretation"]]

    def analyze(self) -> None:
        self.interpretation = None
        try:
            self.interpretation = self._data.decode('utf-8')
        except UnicodeDecodeError:
            self.interpretation = self.subparse(HexDump, "_data")

# ----------------------------------------------------------------------------------------
class PLFConfigSection(FirmwareStructure):
    """
    A PLF configuration section.
    """

    label = "PLF Config Section"

    definition = Struct(
        "tbl_version" / Int32ul,
        "version_major" / Int32ul,
        "version_minor" / Int32ul,
        "version_bugfix" / Int32ul,
        "u1" / Int32ul,
        "u2" / Int32ul,
        "u3" / Int32ul,
        "u4" / Int32ul,
        "u5" / Int32ul,
        "num_entries" / Int32ul,
        "entries" / Array(this.num_entries, Class(PLFConfigEntry)),
    )

    reporting = [
        ["tbl_version"], ["version_major"], ["version_minor"], ["version_bugfix"],
        ["u1"], ["u2"], ["u3"], ["u4"], ["u5"], ["num_entries"],
        [], ["entries"],
    ]

# ----------------------------------------------------------------------------------------
class PLFFile(FirmwareStructure):
    """
    A PLF file.
    """

    label = "PLF File"

    definition = Struct(
        "name" / CString(),
        "_flags" / Int32ul,
        "uid" / Int32ul,
        "gid" / Int32ul,
        "_data" / GreedyBytes,
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    _flags: int
    data: Optional[FirmwareStructure]

    @property
    def perms(self) -> str:
        return "0o%o" % (self._flags & 0x0FFF)

    @property
    def ftype(self) -> int:
        return (self._flags & 0xF000) >> 12

    reporting = [["name"], ["perms"], ["ftype"], ["uid"], ["gid"], ["data"]]

    def analyze(self) -> None:
        self.data = None

        # If the file is a softlink, the "data" is the name of the file it links to.
        self.softlink = None
        if self.ftype == 10:
            self.softlink = self._data[:-1].decode()
            # Return since there can't be data in soft link files.
            return

        # If there's truly no data, we're done.
        if len(self._data) == 0:
            return

        # Maybe I should just defer to AutoObject here?
        self.data = self.subparse(ELFExecutable, "_data")
        if self.data is not None:
            return

        self.data = self.subparse(PNGImage, "_data")
        if self.data is not None:
            return
        self.data = self.subparse(GIFImage, "_data")
        if self.data is not None:
            return
        self.data = self.subparse(TIFFImage, "_data")
        if self.data is not None:
            return
        self.data = self.subparse(JPGImage, "_data")
        if self.data is not None:
            return
        self.data = self.subparse(OpenTypeFont, "_data")
        if self.data is not None:
            return
        self.data = self.subparse(UBX8Firmware, "_data")
        if self.data is not None:
            return

        # NO OTF support!

        self.data = self.subparse(TextFile, "_data")
        if self.data is not None and not isinstance(self.data.lines, bytes):
            return

        self.data = self.subparse(HexDump, "_data")

    def instance_name(self) -> str:
        if self.ftype == 10:
            return f"{self.name} -> {self.softlink}"
        if self.ftype == 4:
            return f"{self.name} (Directory)"
        if self.data is None:
            return f"{self.name} (Empty)"
        return f"{self.name} ({self.data.__class__.__name__})"

# ----------------------------------------------------------------------------------------
class PLFSection(FirmwareStructure):
    """
    A PLF Section.
    """

    label = "PLF Section"

    definition = Struct(
        "stype" / EnumAdapter(Int32ul, PLFSectionType),
        "size" / Int32ul,
        "crc32" / Int32ul,
        "u1" / Int32ul,
        "uncompressed_size" / Int32ul,
        "_data" / Bytes(this.size),
        # Consume bytes ntil we reach the next multiple of 4.
        "padding" / Bytes(lambda ctx: (math.ceil(ctx.size / 4) * 4) - ctx.size),
    )

    data: Optional[FirmwareStructure]

    reporting = [
        ["stype"], ["size"], ["crc32", "0x%08x"], ["u1", "0x%08x"], ["uncompressed_size"],
        ["padding"],
        [], ["data"],
    ]

    def instance_name(self) -> str:
        if isinstance(self.data, PLFFile):
            return self.data.instance_name()
        return str(self.stype)

    def analyze(self) -> None:
        self.data = None
        # BUG! Nasty duplication of code here, but if we don't we'll lose file offsets for
        # the uncompressed blobs.  Hmm, what should we do about this?
        if self.uncompressed_size == 0:
            if self.stype == PLFSectionType.Configuration:
                self.data = self.subparse(PLFConfigSection, "_data")
            elif self.stype == PLFSectionType.BootLoader:
                self.data = self.subparse(PLFFirmware, "_data")
            elif self.stype == PLFSectionType.Installer:
                self.data = self.subparse(PLFFirmware, "_data")
            elif self.stype == PLFSectionType.Section7:
                self.data = self.subparse(PLFSection7, "_data")
            elif self.stype == PLFSectionType.Filesystem:
                self.data = self.subparse(PLFFile, "_data")
            return

        uncompressed = self._data
        if self.uncompressed_size != 0:
            uncompressed = gzip.decompress(self._data)

        if self.stype == PLFSectionType.Configuration:
            self.data = PLFConfigSection.parse(uncompressed, 0)
        elif self.stype == PLFSectionType.BootLoader:
            self.data = PLFFirmware.parse(uncompressed, 0)
        elif self.stype == PLFSectionType.Installer:
            self.data = PLFFirmware.parse(uncompressed, 0)
        elif self.stype == PLFSectionType.Section7:
            self.data = PLFSection7.parse(uncompressed, 0)
        elif self.stype == PLFSectionType.Filesystem:
            self.data = PLFFile.parse(uncompressed, 0)
        return

# ----------------------------------------------------------------------------------------
class PLFFirmware(FirmwareStructure):
    """
    A PLF firmware.
    """

    label = "PLF Firmware"

    definition = Struct(
        "magic" / Const(0x21464C50, Int32ul),
        "header_version" / Int32ul,
        "header_size" / Int32ul,
        "entry_header_size" / Int32ul,
        "u1" / Int32ul,
        "u2" / Int32ul,
        "u3" / Int32ul,
        "u4" / Int32ul,
        "u5" / Int32ul,
        "version_major" / Int32ul,
        "version_minor" / Int32ul,
        "version_bugfix" / Int32ul,
        "u6" / Int32ul,
        "filesize" / Int32ul,
        "sections" / GreedyRange(Class(PLFSection)),
        "more" / Class(MysteryBytes),
    )

    reporting = [
        ["magic", "0x%08x"], ["header_version"], ["header_size"],
        ["entry_header_size"],
        ["u1"], ["u2", "0x%08x"], ["u3"], ["u4"], ["u5", "0x%08x"],
        [], ["version_major"], ["version_minor"], ["version_bugfix"],
        ["u6"], ["filesize"], ["sections"],
    ]

    def instance_name(self) -> str:
        return (f"version={self.version_major}.{self.version_minor}.{self.version_bugfix}"
                f" size={self.filesize}")

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
