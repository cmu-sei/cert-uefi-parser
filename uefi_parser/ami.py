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
Structures relating to AMI specific ROMs.
"""

from typing import Optional

from construct import (
    Bytes, Select, Computed, Const, GreedyRange, GreedyBytes, Int8ul, Int32ul, Peek, this)

from .base import FirmwareStructure, FixedLength, Class, Struct, SafeFixedLength, Until
from .mystery import MysteryBytes, CommitMystery
from .finder import FirmwareVolumeFinder
from .pfs import TextFile, IntelBIOSGuardHeader, IntelBIOSGuardSignature
from .fit import FITable

# ----------------------------------------------------------------------------------------
class AMI_PFAT_Config(FirmwareStructure):
    """
    AMI BIOS Guard Flash Configurations

    Parsing a text file with Construct.  Ick.
    """

    label = "AMI PFAT Config"

    definition = Struct(
        "_flag" / Until(b' ', GreedyBytes),
        "flag" / Computed(lambda ctx: int(ctx._flag)),
        "_space1" / Bytes(1),
        "param" / Until(b' ', GreedyBytes),
        "_space2" / Bytes(1),
        "_blocks" / Until(b' ;', GreedyBytes),
        "blocks" / Computed(lambda ctx: int(ctx._blocks)),
        "_space3" / Bytes(2),
        "name" / Until(b'\x0d\x0a', GreedyBytes),
        "_space4" / Bytes(2),
    )

# ----------------------------------------------------------------------------------------
class AMI_PFAT_Header(FirmwareStructure):
    """
    AMI PFAT Header
    """

    label = "AMI PFAT Header"

    definition = Struct(
        "size" / Int32ul,
        "checksum" / Int32ul,
        "magic1" / Const(b'_AMIPFAT'),
        "failure" / CommitMystery,
        "flags" / Int8ul,
        # Peek the bytes once to present it as it actually is (a text file).
        "text" / Peek(FixedLength(this.size - 17, Class(TextFile))),
        # And then parse it again in a more structured way.
        "magic2" / Const(b'AMI_BIOS_GUARD_FLASH_CONFIGURATIONS\x0d\x0a'),
        # There might be an "II" and an array of Int16ul indexes here?
        "configs" / SafeFixedLength(this.size - 17 - 37,
                                    GreedyRange(Class(AMI_PFAT_Config))),
        "skipped" / Computed(this.extra),
    )

    reporting = [
        ["magic1"], ["magic2"], ["size"], ["checksum"], ["flags"], ["skipped"],
        ["text"], ["configs"],
    ]

# ----------------------------------------------------------------------------------------
class AMI_BIOSGuard_Block(FirmwareStructure):
    """
    AMI BIOSGuard Block (Header & Signature)
    """

    label = "AMI BIOS Guard Block"

    definition = Struct(
        "header" / Class(IntelBIOSGuardHeader),
        "sig" / Class(IntelBIOSGuardSignature),
    )

# ----------------------------------------------------------------------------------------
class AMI_PFAT_File(FirmwareStructure):
    """
    AMI PFAT File
    """

    label = "AMI PFAT File"

    definition = Struct(
        "data" / Select(
            Class(FITable),
            Class(FirmwareVolumeFinder),
            Class(MysteryBytes),
        )
    )

    name: Optional[str]
    size: int

    reporting = [["name"], ["size"], ["data"]]

# ----------------------------------------------------------------------------------------
class AMI_PFAT_Firmware(FirmwareStructure):
    """
    AMI PFAT Firmware
    """

    label = "AMI PFAT Firmware"

    definition = Struct(
        "header" / Class(AMI_PFAT_Header),
        "failure" / CommitMystery,

        # Using Array is the more correct approach, but if there's a problem it recovers
        # poorly, with Construct discarding the entire array because it wasn't the correct
        # length.  We'll either need a less picky Array construct, or we can just use
        # GreedyRange which is fine so long as there aren't extra btyes after the blocks
        # (which there isn't presently).
        # "_num_blocks" / Computed(lambda ctx: sum(cfg.blocks for cfg in ctx.header.configs)),
        # "blocks" / Array(this._num_blocks, Class(AMI_BIOSGuard_Block)),
        "blocks" / GreedyRange(Class(AMI_BIOSGuard_Block)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["header"], ["blocks"], ["files"],
    ]

    def analyze(self) -> None:
        self.files = []
        # If we didn't find the blocks we expected, we have to abort.
        if self.blocks is None:
            return
        current_block = 0
        missing_block = None
        for config in self.header.configs:
            file_bytes = b''
            for bn in range(config.blocks):
                # If we didn't find the block we need, just skip the remaining blocks,
                # which will result in truncated file.
                if current_block >= len(self.blocks):
                    if missing_block is None:
                        msg = "missing AMI PFAT block %s, files are truncated."
                        self.warn(msg % current_block)
                    # Prevent warning from being emitted repeatedly.
                    missing_block = current_block
                    continue
                file_bytes += self.blocks[current_block].header.data
                current_block += 1
            interpretation = AMI_PFAT_File.parse(file_bytes, 0)
            if interpretation is None:
                return

            interpretation.name = None
            interpretation.size = len(file_bytes)
            try:
                interpretation.name = config.name.decode('utf8')
            except UnicodeError:
                pass
            self.files.append(interpretation)


# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
