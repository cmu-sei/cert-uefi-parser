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
Intel Firmware Interface Table (FIT)
"""

from construct import (
    Computed, Array, GreedyRange, Const, Int8ul, Int16ul, Int24ul, Int64ul, this)

from .base import FirmwareStructure, Class, Struct
from .uenum import UEnum
from .mystery import MysteryBytes, CommitMystery

# ----------------------------------------------------------------------------------------
# This 17 page standard documents the format briefly but intelligbly:
# https://www.intel.com/content/dam/develop/external/us/en/documents/firmware-interface-table-bios-specification-r1p2p1.pdf

# A less formal analysis of FIT hacking:
# https://www.win-raid.com/t4032f47-GUIDE-Update-CPU-Microcode-Fix-FIT-Using-UEFITool-Hex.html

class FITType(UEnum):
    FITHeader = 0x0
    CpuMicrocodeUpdate = 0x1
    StartupACM = 0x2
    DiagnosticACM = 0x3
    IntelReserved1 = 0x4
    IntelReserved2 = 0x5
    IntelReserved3 = 0x6
    BIOSStartupModule = 0x7
    TPMPolicyRecord = 0x8
    BIOSPolicyRecord = 0x9
    TXTPolicyRecord = 0xA
    KeyManifest = 0xB
    BootPolicyManifest = 0xC
    IntelReserved4 = 0xD
    IntelReserved5 = 0xE
    IntelReserved6 = 0xF
    CSESecureBoot = 0x10
    FeaturePolicy = 0x2D
    JMPDebugPolicy = 0x2F
    Unused = 0x7F
    # All other byte values are also "Intel reserved".

# ----------------------------------------------------------------------------------------
class FITEntry(FirmwareStructure):

    label = "Intel Firmware Interface Table (FIT) Entry"

    definition = Struct(
        # Must be aligned on a 16 byte boundary.
        "address" / Int64ul,
        # Size is measured in 16-byte increments (in addition to this structure)
        "size" / Int24ul,
        # Reserved in that "It's used for various things" kind of way.
        "reserved" / Int8ul,
        "version" / Int16ul,
        "_type_cv" / Int8ul,
        "type" / Computed(lambda ctx: FITType(ctx["_type_cv"] & 0x7F)),
        "checksum_valid" / Computed(lambda ctx: bool(ctx["_type_cv"] & 0x80)),
        # Checksum is only valid if the high bit is set.
        "checksum" / Int8ul,
    )

    reporting = [
        ["address", "0x%x"], ["size"], ["version", "0x%x"], ["type"], ["checksum"],
    ]

    def instance_name(self) -> str:
        return "%s 0x%x" % (str(self.type), self.address)

# ----------------------------------------------------------------------------------------
class FITable(FirmwareStructure):
    """
    Intel Firmware Interface Table

    This version is self-sizing, and will only consume the bytes indicated by the header.
    It is used when parsing a FIT that is less clearly bounded.
    """

    label = "Intel Firmware Interface Table (FIT)"

    definition = Struct(
        # The header is actually a FITEntry itself, but because the of the "magic"
        # address, I've chosen to encode it as separate data structure.  This was NOT
        # witty Intel. :-(
        "_magic" / Const(b'_FIT_   '),
        "failure" / CommitMystery,
        "entries" / Int24ul,
        "_reserved" / Int8ul,
        "version" / Int16ul,
        "_type_cv" / Int8ul,
        "type" / Computed(lambda ctx: FITType(ctx["_type_cv"] & 0x7F)),
        "checksum_valid" / Computed(lambda ctx: bool(ctx["_type_cv"] & 0x80)),
        "checksum" / Int8ul,
        "data" / Array(this.entries - 1, Class(FITEntry)),
    )

    reporting = [
        ["entries"], ["version", "0x%x"], ["type"], ["checksum"], ["checksum_valid"]
    ]

# ----------------------------------------------------------------------------------------
class FITablePlus(FirmwareStructure):
    """
    Intel Firmware Interface Table

    This version is expected to be externally sized, and will consume 0xff padding
    silently, but then report any additional unexpected bytes.  It is typically used when
    the FIT is contained in a firmware file system file.
    """

    label = "Intel Firmware Interface Table (FIT)"

    definition = (FITable.definition
                  + ("_padding" / GreedyRange(Const(b'\xff')))
                  + ("unexpected" / Class(MysteryBytes)))

    reporting = [
        ["entries"], ["version", "0x%x"], ["type"], ["checksum"], ["checksum_valid"]
    ]

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
