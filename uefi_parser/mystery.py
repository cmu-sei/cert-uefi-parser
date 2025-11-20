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
A FirmwareStructure construct for exploring poorly understood bytes.
"""

from typing import Optional, Union

from construct import (
    Bytes, GreedyBytes, GreedyRange, Select, Computed, Int8ul, Check, Tell, this)

from .base import (
    FirmwareStructure, Class, FixedLength, promote_exceptions, Struct, Commit, FailPeek,
    Opt, Context)
from .guiddb import GUID_DATABASE as GDB

# ----------------------------------------------------------------------------------------
def ascii_char(c: int) -> str:
    '''Return the ASCII or (.) representation of the input character.'''
    if c >= 32 and c <= 126:
        return chr(c)
    return '.'

@promote_exceptions
def asciify(ctx: Context) -> str:
    ascii_str = []
    for c in ctx['_data']:
        ascii_str.append(ascii_char(c))
    return ''.join(ascii_str)

# ----------------------------------------------------------------------------------------
class HexLine(FirmwareStructure):
    """
    Format some raw data
    """

    label = "Hex"

    definition = Struct(
        #"_data" / Bytes(32),
        "_data" / Select(Bytes(32), GreedyBytes),
        Check(lambda ctx: len(ctx['_data']) > 0),
        "hex" / Computed(lambda ctx: ctx['_data'].hex()),
        "ascii" / Computed(asciify),
    )

    reporting = [
        ["hex"],
    ]

# ----------------------------------------------------------------------------------------
@promote_exceptions
def get_hexdump_length(ctx: Context) -> int:
    if len(ctx.lines) == 0:
        return 0
    return (len(ctx.lines) - 1) * 32 + len(ctx.lines[-1]._data)

class HexDump(FirmwareStructure):
    """
    Format some raw data
    """

    label = "Hex Dump"

    definition = Struct(
        "lines" / GreedyRange(Class(HexLine)),
        "length" / Computed(get_hexdump_length),
    )

    reporting = [
        ["length"], ["lines"],
    ]

# ----------------------------------------------------------------------------------------
class MandatoryHexDump(FirmwareStructure):

    label = "Hex Dump"

    definition = Struct(
        # There must be at least one byte for this contrust to match.
        "_peek" / FailPeek(Int8ul),
        "lines" / GreedyRange(Class(HexLine)),
        "length" / Computed(get_hexdump_length),
    )

    reporting = [
        ["length"], ["lines"],
    ]

# ----------------------------------------------------------------------------------------
class MysteryBytes(FirmwareStructure):
    """
    Mystery bytes, intelligently reported with offsets and a truncated value.

    This class is intended for cases where debugging is actively occuring, or when we
    literally don't know what else say about a stream of bytes.  That's in contrast toi
    the AutoObject, where the expectation is is one of the recognized object types, but we
    just don't know one.
    """

    label = "Mystery Bytes"

    definition = Struct(
        "start" / Tell,
        "data" / GreedyBytes,
        "end" / Tell,
        "length" / Computed(this.end - this.start),
    )

    reporting = [
        ["start", "0x%x"], ["end", "0x%x"], ["length"], ["value"],
        ["data", None],
    ]

    def instance_name(self) -> str:
        return ""

    def scan_for_guids(self) -> None:
        self.found_guids = []
        limit = min(0x1000, len(self.data))
        self.info("Scanning for GUIDS...")
        for (offset, gobj) in GDB.scan_for_guids(self.data[:limit]):
            self.found_guids.append((offset, gobj))
            self.info("0x%08x: %s %s" % (offset, gobj.guid, gobj.name))

    def set_value(self) -> None:
        # Also check for zeros...
        if len(self.data) == 0:
            self.value: Optional[Union[str, list[str]]] = "(empty)"
            return

        # Returns the first byte as a byte string of length 1.
        first_byte = self.data[0:1]
        # Returns the first byte as an integer.
        first_int = self.data[0]
        if self.data == first_byte * len(self.data):
            self.value = "(%d 0x%02X bytes)" % (len(self.data), ord(first_byte))
            return

        self.value = self.set_text()
        if self.value is not None:
            return

        if len(self.data) <= 16:
            self.value = self.data
            return
        else:
            leading_bytes = 0
            while leading_bytes < len(self.data) and self.data[leading_bytes] == first_int:
                leading_bytes += 1

            if leading_bytes < 4:
                self.value = "%r..." % self.data[:16]
            else:
                self.value = "(%d leading 0x%02Xs) %r..." % (
                    leading_bytes, first_int, self.data[leading_bytes:leading_bytes + 16])

    def set_text(self) -> Optional[Union[str, list[str]]]:
        # Check if the text is printable...
        try:
            text = self.data.decode('utf-8')
            text = text.rstrip('\x00')
            # Custom isprintable()
            for ch in text:
                if ord(ch) >= 0x20 and ord(ch) <= 0x7e:
                    continue
                if ch in "\n\r\t":
                    continue
                text = None
                break
            if text is not None:
                text = text.replace("\r", "\\r")
                text = text.replace("\t", "\\t")
                if len(text) < 80:
                    text = text.replace("\n", "\\n")
                    return "(text) '%s'" % text
                else:
                    return text.splitlines(keepends=True)  # type: ignore

        except UnicodeError:
            return None
        return None

    def analyze(self) -> None:
        self.set_value()
        if False:
            #self.hex_dump = None
            #if len(self.data) > 0:
            #    self.hex_dump = self.subparse(HexDump, "data")
            self.scan_for_guids()

# ----------------------------------------------------------------------------------------
class MysteryHexPeek(FirmwareStructure):
    """
    A version of MysteryBytes that dumps the first kibibyte as hex.
    """

    label = "Mystery Bytes (Peeked HexDump)"

    definition = Struct(
        "hexpeek" / Opt(FixedLength(1024, Class(HexDump))),
        "remaining" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
class ParseFailure(MysteryBytes):

    label = "Parse Failure"

# ----------------------------------------------------------------------------------------
# Easy shorthand for commiting to mystery bytes.
CommitMystery = Commit(Class(ParseFailure))

# ----------------------------------------------------------------------------------------
# Magic strings seen, sources, etc.

# Lots of good non-UEFI firmware signatures here:
# https://github.com/ReFirmLabs/binwalk/blob/772f271f0bcce18771f814b5f20cb19b29082831/src/binwalk/magic/firmware

# Structure definitions that I'm look for, because I've seen the magic:
#  Starts: "$BVDT$"        -- seen in HPSpectre, Huawei
#  Starts: "$DISPROM"      -- seen in HPSpectre, Apple SCAP
#  Starts: "$PCIDATA"      -- seen in corys-bios.rom, DellPrecision
#  Starts: "$SPF"          -- seen in corys-bios.rom, LenovoThin
#  Starts: "$SVS"          -- seen in Apple
#  Starts: "$VSS"          -- seen in Apple, Apple SCAP
#  Starts: "$PIR"          -- seen in LenovoThin
#  Starts: "PCCT"          -- seen in LenovoThin
#  Starts: "FBB7A"         -- seen in LenovoThin
#  Starts: "---BEGIN PUB"  -- seen in HPSpectre
#  Starts: "APIC"          -- seen in HPSpectre
#  Starts: "BSA_"          -- seen in DellO, LenovoThin
#  Starts: "CND62647"      -- seen in HPSpectre
#  Starts: "FCRI"          -- seen in corys-bios.rom
#  Starts: "FIDT"          -- seen in corys-bios.rom
#  Starts: "MPDT"          -- seen in DellPrecision, LenovoThin
#  Starts: "ROML"          -- seen in corys-bios.rom
#  Starts: "_ARESIGN"      -- seen in DellPrecision
#  Starts: "_ATT"          -- seen in corys-bios.rom
#  Starts: "_FIT_"         -- seen in corys-bios.rom, DellPrecision, DellO, HPSpectre
#  Starts: "\x00LUT"       -- seen in Apple GLUT ME partition
#  Starts: "caff"          -- seen in Apple
#  Starts: "_AMISIGN"      -- seen in LVFS
#  Starts: "SMSCUBIM"      -- seen in LVFS
#  Starts: "DELLBIO$M"     -- seen in Dell Latitude
#  Starts: "__MHTS__"      -- seen in Dell Latitude
#  Starts: "__KEYM__"      -- seen in Dell Latitude, Lenovo
#  Starts: "__ACBP__"      -- seen in Dell Latitude, Lenovo
#  Starts: "PMIM"          -- seen in Dell Latitude
#  Starts: "$PLC"          -- seen in Dell Latitude, Dell Precision
#  Starts: "CSR$"          -- seen in Dell Latitude, Dell Precision
#  Starts: "BIN.HDR."      -- seen in Dell Latitude
#  Starts: "BDAT"          -- seen in Dell R740
#  Starts: "DBG2"          -- seen in Dell R740
#  Starts: "HMAT"          -- seen in Dell R740
#  Starts: "MIGT"          -- seen in Dell R740
#  Starts: "MSCT"          -- seen in Dell R740
#  Starts: "NFIT"          -- seen in Dell R740
#  Starts: "PCAT"          -- seen in Dell R740
#  Starts: "PCCT"          -- seen in Dell R740
#  Starts: "PMTT"          -- seen in Dell R740
#  Starts: "RASF"          -- seen in Dell R740
#  Starts: "SLIT"          -- seen in Dell R740
#  Starts: "SRAT"          -- seen in Dell R740
#  Starts: "SPMI"          -- seen in Dell R740
#  Starts: "SVOS"          -- seen in Dell R740
#  Starts: "OEM1"          -- seen in Dell R740
#  Starts: "OEM2"          -- seen in Dell R740
#  Starts: "OEM3"          -- seen in Dell R740
#  Starts: "OEM4"          -- seen in Dell R740
#  Starts: "IMAP"          -- seen in Dell Precision, Dell Latitude, LVFS
#  Starts: "UTFL"          -- seen in Dell Precision
#  Starts: "HDFM"          -- seen in Huawei
#  Starts: "$_IFLASH_INI"  -- seen in Huawei
#  Starts: "$DF$"          -- seen in an AMD PSP Entry

#  Contains: "_SB_PCI"     -- seen in corys-bios.rom, HPSpectre
#  Contains: "DPTR"        -- seen in corys-bios.rom
#  Contains: "ADBG"        -- seen in corys-bios.rom
#  Contains: "IRMC"        -- seen in corys-bios.rom
#  Contains: "DSSP"        -- seen in corys-bios.rom
#  Contains: "PHCM"        -- seen in DellPrecision, Dell Latitude
#  Contains: "MFS"         -- seen in Apple EFFS ME partition at offset 8.
#  Contains: "MSMT"        -- seen in HPSpectre
#  Contains: "MRPTMD"      -- seen in HPSpectre
#  Contains: "RTD3"        -- seen in HPSpectre
#  Contains: "RCG0"        -- seen in HPSpectre
#  Contains: "TPM_"        -- seen in HPSpectre
#  Contains: "\\._PR_CPU1" -- seen in HPSpectre
#  Contains: "__IBBS__"    -- seen in Lenovo, inside __ACBP__ section
#  Contains: "__PMSG__"    -- seen in Lenovo, inside __ACBP__ section

# Should add support for UEFI Internal Form Representation (IFR)
# https://github.com/LongSoft/IFRExtractor-RS
# Should add support for EFI Byte Code
# https://github.com/pbatard/fasmg-ebc
# https://crates.io/crates/spore-disassembler

# Incompletely parsed:
# $MMX ME partition in Apple ROMS, record subtypes AT, CLS, FPF, HOT, LEG, MV, SES, & UKE.
# Extra header bytes in GUID fc1bcdb0-7d31-49aa-936a-a4600d9dd083 (CRC32GuidedSection)

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
