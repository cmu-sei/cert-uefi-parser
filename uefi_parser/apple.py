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
Data structures seen in Apple ROMs.
"""

from construct import (
    Array, Bytes, Computed, Const, GreedyRange, Int8ul, Int16ul, Int32ul, Int32ub, If,
    Check, Peek, this)

from .base import (
    FirmwareStructure, Class, FixedLength, Struct, HexBytes, PaddedString)
from .mystery import MysteryBytes, HexDump

# ----------------------------------------------------------------------------------------
class AppleIconData(FirmwareStructure):
    """
    An Apple ICNS icon data (for an individual icon).
    """

    label = "Apple ICNS Icon"

    definition = Struct(
        "itype" / Bytes(4),
        "size" / Int32ub,
        "data" / Bytes(this.size - 8),
    )

    reporting = [["itype"], ["size"], ["data", None]]

# ----------------------------------------------------------------------------------------
class AppleIconFile(FirmwareStructure):
    """
    An Apple ICNS icon file.
    """

    label = "Apple ICNS Icon File"

    definition = Struct(
        "_magic" / Const(b'icns'),
        "size" / Int32ub,
        "icons" / GreedyRange(Class(AppleIconData)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["size"], ["icons"]]

# ----------------------------------------------------------------------------------------
class IntelBIOSID(FirmwareStructure):
    """
    This is reported to be an Intel standard, but I originally saw it in Apple files.

    BUG! Move this class to a better location.

    Format is reverse engineered.
    """

    label = "Intel BIOS ID"

    definition = Struct(
        "magic" / Const(b'$IBIOSI$'),

        # Some Intel BIOS ID Sections start with a version number string of the form
        # "x.xx".  If there's a dot in the second utf-16 character, read a version string
        # first.  A better way to detect this might be to check the length of the
        # enclosing section (78 bytes versus 108)
        "_peek" / Peek(Bytes(4)),
        "version" / If(lambda ctx: ctx._peek[2] == 0x2e,
                       PaddedString(30, 'utf-16')),

        "build" / PaddedString(66, 'utf-16'),
    )

    # Based on
    # https://github.com/platomav/BIOSUtilities/blob/main/Apple_EFI_ID.py
    # https://listman.redhat.com/archives/edk2-devel-archive/2019-May/msg01567.html
    # and other sources, there's structure in the build string.
    #  Board, BoardRev, BoardExt, VersionMajor, BuildType, VersionMinor, TimeStamp

    reporting = [
        ["magic"], ["version"], ["build"],
    ]


# ----------------------------------------------------------------------------------------
class BIOSDataBlock(FirmwareStructure):
    """
    A brief description and a list of IDs is here:
    https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/i915/display/intel_vbt_defs.h

    Each appears to have it's own format, which wil lbe tedious, and I don't particularly
    care now that I understand what is in this structure.
    """

    label = "BIOS Data Block"

    definition = Struct(
        "id" / Int8ul,
        Check(lambda ctx: ctx['id'] != 0),
        "size" / Int16ul,
        "data" / Bytes(this.size)
    )

    reporting = [
        ["id"], ["size"], ["data"],
    ]

# ----------------------------------------------------------------------------------------
class BIOSDataBlockHeader(FirmwareStructure):
    """
    https://01.org/linuxgraphics/gfx-docs/drm/API-struct-bdb-header.html
    """
    label = "BIOS Data Block Header"

    definition = Struct(
        "magic" / Const(b'BIOS_DATA_BLOCK '),
        "version" / Int16ul,
        # Not really a constant, but no reason to differ?
        "header_size" / Const(22, Int16ul),
        "bdb_size" / Int16ul,
        "blocks" / GreedyRange(Class(BIOSDataBlock)),
        # Zero padding at the end can also be interpreted as a sequence of blocks with
        # id=0, size=0 and no data, but that's ugly so stop at the
        "unused" / Class(MysteryBytes),
    )

    reporting = [
        ["magic"], ["version"], ["bdb_size"], ["header_size"],
    ]


# ----------------------------------------------------------------------------------------
# FIXME!  This is not an Apple specific thing, and so it doesn't belong here.
class VideoBIOSTable(FirmwareStructure):
    """
    Video BIOS Table

    https://01.org/linuxgraphics/gfx-docs/drm/API-struct-vbt-header.html
    https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/i915/display/intel_bios.c
    """

    label = "Video BIOS Table"

    definition = Struct(
        "magic" / Const(b'$VBT'),
        "platform" / Bytes(16),
        "version" / Int16ul,
        "header_size" / Int16ul,
        "vbt_size" / Int16ul,
        "checksum" / Int8ul,
        "reserved" / Int8ul,
        # Not really a constant, but no reason to differ?
        "bdb_offset" / Const(48, Int32ul),
        "aim_offset" / Array(4, Int32ul),
        # This is really located at bdb_offset, but we've made that a const, so it's here.
        "bdb" / Class(BIOSDataBlockHeader),
    )

    reporting = [
        ["magic"], ["platform"], ["version"],
        ["checksum", "0x%x"], ["header_size"], ["vbt_size"],
        ["bdb_offset"], ["aim_offset"], ["reserved"],
    ]

# ----------------------------------------------------------------------------------------
class SVSThing(FirmwareStructure):
    """
    Section identified by $SVS at offset 8.
    Mentioned here:
    https://boards.rossmanngroup.com/threads/how-to-read-write-erase-apple-efi-spi-rom-with-raspberry-pi.2455/
    Also here: https://gist.github.com/willzhang05/e5b5563cdc65514dfb7ca131e03ca4b2

    Apparently this has something to do with the BIOS password.
    """

    label = "SVS Thing"

    definition = Struct(
        "_filler1" / GreedyRange(Const(b'\xff')),
        "magic1" / Const(b'$SVS'),
        "unk2" / Int32ul,
        "unk3" / Bytes(4),
        "unk4" / Int32ul,
        "_filler2" / GreedyRange(Const(b'\xff')),
        "magic2" / Const(b'$SVS'),
        "unk5" / Int32ul,
        "unk6" / Bytes(4),
        "unk7" / Int32ul,
        "_filler3" / GreedyRange(Const(b'\xff')),
    )

# ========================================================================================
# These data structures are wildly speculative.  They're being parsed mostly to
# demonstrate that they're small and consistently structured.  Importantly, this excludes
# them from the other "MysteryBytes" that migth actually warrant further investigation.

# ----------------------------------------------------------------------------------------
class AppleFreeformHeader(FirmwareStructure):

    label = "Apple Freeform Header"

    definition = Struct(
        "name" / PaddedString(8, 'ascii'),
        "u1" / Int32ul,
        "u2" / Int32ul,
        "size" / Int16ul,
        "u3" / Int16ul,
    )

    reporting = [["name", "'%s'"], ["size"], ["u1"], ["u2", "0x%x"], ["u3"]]

# ----------------------------------------------------------------------------------------
class AppleFreeformGeneric(FirmwareStructure):

    label = "Apple Freeform Generic"

    definition = Struct(
        "header" / Class(AppleFreeformHeader),
        "data" / FixedLength(lambda ctx: ctx.header.size, Class(HexDump)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["header"], ["data"]]

# ----------------------------------------------------------------------------------------
class AppleFreeform1(FirmwareStructure):

    label = "Apple Freeform 1"

    definition = Struct(
        "header" / Class(AppleFreeformHeader),
        "sig" / Bytes(lambda ctx: ctx.header.size),
        "siglen" / Computed(lambda ctx: len(ctx.sig)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["siglen"], ["sig", None], ["header"]]

# ----------------------------------------------------------------------------------------
class AppleFreeform2(FirmwareStructure):

    label = "Apple Freeform 2"

    definition = Struct(
        "header" / Class(AppleFreeformHeader),
        "u1" / Int32ul,
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["u1"], ["header"]]

# ----------------------------------------------------------------------------------------
class AppleFreeform3(FirmwareStructure):

    label = "Apple Freeform 3"

    definition = Struct(
        "header" / Class(AppleFreeformHeader),
        "name" / PaddedString(8, 'ascii'),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["name", "'%s'"], ["header"]]

# ----------------------------------------------------------------------------------------
class AppleFreeform4(FirmwareStructure):

    label = "Apple Freeform 4"

    definition = Struct(
        "header" / Class(AppleFreeformHeader),
        "u1" / Int16ul,
        "empty" / PaddedString(62, 'ascii'),
        "u2" / Int16ul,
        "str" / PaddedString(128, 'utf16'),
        "u3" / Int16ul,
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["u1"], ["u2"], ["u3"], ["empty"], ["str"], ["header"]]

# ----------------------------------------------------------------------------------------
class AppleFreeform5(FirmwareStructure):

    label = "Apple Freeform 5"

    definition = Struct(
        "header" / Class(AppleFreeformHeader),
        "u1" / Int16ul,
        "u2" / Int16ul,
        "u3" / HexBytes(37),
        "empty" / PaddedString(87, 'ascii'),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["u1"], ["u2"], ["empty", "'%s'"], ["u3"], ["header"]]

# ----------------------------------------------------------------------------------------
class AppleFreeform6(FirmwareStructure):
    """
    Almost certainly wrong, but it makes it easier to review which bytes are defined.
    """

    label = "Apple Freeform 6"

    definition = Struct(
        "header" / Class(AppleFreeformHeader),
        "u1" / HexBytes(15),
        "u2" / HexBytes(15),
        "u3" / HexBytes(6),
        "z1" / PaddedString(3, 'ascii'),
        "u4" / Int32ul,
        "z2" / PaddedString(17, 'ascii'),
        "u5" / Int32ul,
        "z3" / PaddedString(32 + 21, 'ascii'),
        "u6" / Int32ul,
        "z4" / PaddedString(5, 'ascii'),
        "u7" / Int16ul,
        "u8" / Bytes(18),
        "u9" / Int16ul,
        "u10" / Int16ul,
        "z5" / PaddedString(106, 'ascii'),
    )

    reporting = [
        ["u1"], ["u2"], ["u3"], ["u4", "0x%08x"],
        [], ["u5", "0x%08x"], ["u6", "0x%08x"], ["u7", "0x%04x"],
        ["u9", "0x%04x"], ["u10", "0x%04x"], ["u8"],
        # All zeros...
        ["z1"], ["z2"], ["z3"], ["z4"], ["z5"],
        ["header"],
    ]

# ----------------------------------------------------------------------------------------
class AppleFreeform7(FirmwareStructure):

    label = "Apple Freeform 7"

    definition = Struct(
        "header" / Class(AppleFreeformHeader),
        "u1" / Array(6, Int32ul),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["u1"], ["header"]]

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
