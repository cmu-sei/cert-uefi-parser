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
Coreboot support.
"""

import lzma
from enum import Enum
from typing import Union, Optional, TYPE_CHECKING

from construct import (
    Bytes, Computed, Const, Switch, Int32ub, Int64ub, Int8ul, Int16ul, Int32ul, Int64ul,
    RepeatUntil, Select, GreedyBytes, GreedyRange, Aligned, Check, Peek, Seek, Tell, this)
from uefi_support import LzmaDecompress

from .base import (
    FirmwareStructure, FixedLength, Class, PaddedString, Struct, CString, FailPeek,
    Until, HexBytes, promote_exceptions, Context, EnumAdapter)
from .uenum import UEnum
from .mystery import MysteryBytes, HexDump, CommitMystery
from .vendor import BIOSExtensionROM
from .me import CPDManifestHeader
if TYPE_CHECKING:
    from .auto import AutoObject

# ----------------------------------------------------------------------------------------
class CorebootPayloadType(Enum):
    CODE = b'CODE'
    DATA = b'DATA'
    BSS = b'BSS '
    PARAMS = b'PARA'
    ENTRY = b'ENTR'

# ----------------------------------------------------------------------------------------
class CorebootCompressionType(UEnum):
    NONE = 0
    LZMA = 1
    NRVB2 = 2

# ----------------------------------------------------------------------------------------
class CorebootPayloadSegment(FirmwareStructure):

    label = "Coreboot Payload Segment"

    definition = Struct(
        "type" / Bytes(4),
        "compression" / EnumAdapter(Int32ub, CorebootCompressionType),
        "offset" / Int32ub,
        "load_addr" / Int64ub,
        "length" / Int32ub,
        "mem_length" / Int32ub,
    )

    data: Optional[Union[bytes, str, 'AutoObject', MysteryBytes]]
    # FIXME! Needed until correct types are returned from the mypy extension...
    compression: CorebootCompressionType

    reporting = [
        ["type"], ["offset"], ["load_addr", "0x%x"], ["mem_length", "0x%x"],
        ["compressed_data", None], ["decompressed_data", None],
    ]

    def decompress(self, compressed_data: bytes) -> None:
        self.decompressed_data = None
        self.decompressed_length = 0
        self.compressed_data = compressed_data

        self.data = None
        if self.length == 0:
            return

        if self.compression == CorebootCompressionType.NONE:
            self.data = self.subparse(MysteryBytes, "compressed_data", 0, 512)
        elif self.compression == CorebootCompressionType.LZMA:
            self.decompressed_data = LzmaDecompress(self.compressed_data)
            self.decompressed_length = len(self.decompressed_data)
            from .auto import AutoObject
            self.data = AutoObject.parse(self.decompressed_data, 0)
        elif self.compression == CorebootCompressionType.NRVB2:
            self.data = "(NRVB2 compressed data)"
        else:
            self.data = "(compressed data in UNKNOWN algoritm)"

# ----------------------------------------------------------------------------------------
class CorebootHeaderPointer(FirmwareStructure):

    label = "Coreboot Header Pointer"

    definition = Struct(
        "address" / Int32ul,
    )

    reporting = [["address", "0x%x"]]

# ----------------------------------------------------------------------------------------
class CorebootPayload(FirmwareStructure):

    label = "Coreboot Payload"

    definition = Struct(
        "_before" / Tell,
        "segments" / RepeatUntil(
            lambda segment, lst, ctx: segment.length == 0,
            Class(CorebootPayloadSegment)),
        "_after" / Tell,
        "hdr_len" / Computed(this._after - this._before),
        "segment_data" / GreedyBytes,
    )

    reporting = [["segment_data", None]]

    def analyze(self) -> None:
        #self.debug("Segments:", self.hdr_len, self.segments)
        for segment in self.segments:
            #self.debug("Segment:", segment.compression, segment.offset, segment.length)
            start = segment.offset - self.hdr_len
            end = start + segment.length
            segment.decompress(self.segment_data[start:end])

# ----------------------------------------------------------------------------------------
class CorebootStage(FirmwareStructure):

    definition = Struct(
        "_compression" / Int32ul,
        "compression" / Computed(lambda ctx: CorebootCompressionType(ctx['_compression'])),
        "entry" / Int64ul,
        "load" / Int64ul,
        "length" / Int32ul,
        "mem_length" / Int32ul,
        "compressed_data" / GreedyBytes,
    )

    data: Optional[Union[str, MysteryBytes]]

    reporting = [
        ["load", "0x%x"], ["entry", "0x%x"], ["length", "0x%x"], ["mem_length", "0x%x"],
        ["compression"], ["decompressed_length", "0x%x"],
        ["compressed_data", None], ["decompressed_data", None],
    ]

    def analyze(self) -> None:
        if self.compression == CorebootCompressionType.NONE:
            self.decompressed_data = None
            self.decompressed_length = 0
            self.data = self.subparse(MysteryBytes, "compressed_data", 0)
        elif self.compression == CorebootCompressionType.LZMA:
            self.decompressed_data = lzma.decompress(self.compressed_data)
            self.decompressed_length = len(self.decompressed_data)
            self.data = MysteryBytes.parse(self.decompressed_data, 0)
        elif self.compression == CorebootCompressionType.LZMA:
            self.decompressed_data = None
            self.decompressed_length = 0
            self.data = "(NRVB2 compressed data)"
        else:
            self.decompressed_data = None
            self.decompressed_length = 0
            self.data = "(compressed data in UNKNOWN algoritm)"

# ----------------------------------------------------------------------------------------
# https://github.com/coreboot/coreboot/blob/master/src/commonlib/include/commonlib/coreboot_tables.h#L465

class CMOSEntry201(FirmwareStructure):

    definition = Struct(
        "tag" / Const(201, Int32ul),
        "size" / Int32ul,
        "bit" / Int32ul,
        "length" / Int32ul,
        "config" / Int32ul,
        "config_id" / Int32ul,
        "name" / PaddedString(this.size - 24),
    )

    reporting = [
        ["tag"], ["size"], ["bit"], ["length"],
        ["config"], ["config_id"], ["name"],
    ]

# ----------------------------------------------------------------------------------------
class CMOSEntry202(FirmwareStructure):

    definition = Struct(
        "tag" / Const(202, Int32ul),
        "size" / Int32ul,
        "bit" / Int32ul,
        "length" / Int32ul,
        "name" / PaddedString(this.size - 16),
    )

    reporting = [
        ["tag"], ["size"], ["bit"], ["length"], ["name"],
    ]

# ----------------------------------------------------------------------------------------
class CMOSEntry204(FirmwareStructure):

    definition = Struct(
        "tag" / Const(204, Int32ul),
        "size" / Int32ul,
        "u1" / Int32ul,
        "u2" / Int32ul,
        "u3" / Int32ul,
        "u4" / Int32ul,
    )

    reporting = [
        ["tag"], ["size"], ["u1"], ["u2"], ["u3"], ["u4"],
    ]

# ----------------------------------------------------------------------------------------
# https://github.com/coreboot/coreboot/blob/master/src/commonlib/include/commonlib/coreboot_tables.h#L452
class CMOSLayout(FirmwareStructure):

    definition = Struct(
        "u1" / Int32ul,
        "u2" / Int32ul,
        "u3" / Int32ul,
        "entries" / GreedyRange(Select(
            Class(CMOSEntry201),
            Class(CMOSEntry202),
            Class(CMOSEntry204),
        )),
        "h" / Class(HexDump),
    )

    reporting = [["u1"], ["u2"], ["u3"]]

# ----------------------------------------------------------------------------------------
class CorebootMasterHeader(FirmwareStructure):

    label = "Coreboot Master Header"

    definition = Struct(
        # Seek back 4 bytes from the end of the stream.
        Seek(-4, 2),
        # The last four bytes of the file points to the master header in RAM.
        "header_address" / Int32ul,
        # How big was the entire ROM image?
        "_image_size" / Tell,
        # The image _ends_ at address 0xFFFFFFFF, so it _begins_ image_size bytes earlier.
        "image_base" / Computed(0x100000000 - this._image_size),
        # Subtracting the image_base from the header address gives us the header offset.
        "header_offset" / Computed(this.header_address - this.image_base),
        Seek(this.header_offset, 0),
        # Start parsing the
        "_magic" / Const(b'ORBC'),
        "version" / Bytes(4),
        # This should match the _image_size! VALIDATE?
        "romsize" / Int32ub,
        "bootblocksize" / Int32ub,
        "align" / Int32ub,
        "offset" / Int32ub,
        "architecture" / Int32ub,
        "pad" / Int32ub,
        # Return the stream pointer to the beginning of the stream so we can pretend that
        # this structure was actually at the beginning of the file.
        Seek(0, 0),
    )

    reporting = [
        ["image_base", "0x%x"],
        ["header_address", "0x%x"],
        ["header_offset", "0x%x"],
        ["romsize", "0x%x"],
        ["bootblocksize", "0x%x"],
        ["architecture", "0x%x"],
        ["pad", "0x%x"],
    ]

    def analyze(self) -> None:
        # Whether this is the rigth thing to do is _very_ unclear.  But at least this
        # results in the Master Header structure being reported at the correct offset in
        # the test spew.  Perhaps this little white lie will be problematic in the future.
        self._data_offset = self.header_offset

# ----------------------------------------------------------------------------------------
class CorebootMasterHeaderExplicit(FirmwareStructure):

    label = "Coreboot Master Header (at explicit offset)"

    definition = Struct(
        "pos" / Tell,
        # Start parsing the
        "_magic" / Const(b'ORBC'),
        "version" / Bytes(4),
        # This should match the _image_size! VALIDATE?
        "romsize" / Int32ub,
        "bootblocksize" / Int32ub,
        "align" / Int32ub,
        "offset" / Int32ub,
        "architecture" / Int32ub,
        "pad" / Int32ub,
    )

    reporting = [
        ["romsize", "0x%x"],
        ["bootblocksize", "0x%x"],
        ["architecture", "0x%x"],
        ["pad", "0x%x"],
        ["align", "0x%x"], ["offset", "0x%x"], ["pos", "0x%x"],
    ]

# ----------------------------------------------------------------------------------------
@promote_exceptions
def junklen(ctx: Context) -> int:
    delta = ctx['offset'] - (ctx['_pos'] - ctx['_start'])
    assert isinstance(delta, int)
    return max(0, delta)

# ----------------------------------------------------------------------------------------
class CorebootComponent(FirmwareStructure):

    label = "Coreboot Component"

    definition = Struct(
        "_start" / Tell,
        "_magic" / Const(b'LARCHIVE'),
        "length" / Int32ub,
        "type" / Int32ub,
        "checksum" / Int32ub,
        "offset" / Int32ub,
        "name" / CString(),
        "_pos" / Tell,
        "junk" / Bytes(junklen),
        "data" / FixedLength(this.length, Switch(
            this.type, {
                0x00000002: Class(CorebootHeaderPointer),
                0x00000010: Class(CorebootStage),
                0x00000020: Class(CorebootPayload),
                0x00000030: Class(BIOSExtensionROM),
                0x00000050: Class(MysteryBytes),
                0x000001aa: Class(CMOSLayout),
                0xffffffff: Class(MysteryBytes),
            }, default=Class(MysteryBytes)
        )),
    )

    reporting = [
        ["name"], ["type", "0x%x"], ["length", "0x%x"], ["checksum"], ["offset"],
        ["junk"],
    ]

# ----------------------------------------------------------------------------------------
class CorebootContainer(FirmwareStructure):

    label = "Coreboot Container"

    definition = Struct(
        "master" / Class(CorebootMasterHeader),
        # There are often no embedded controller bytes, but the Coreboot specification
        # left space here by choosing offset != 0, which is problematic for recognizing
        # the file based on it's leading "magic" bytes, but whatever.
        "embedded_controller" / Bytes(lambda ctx: ctx['master'].offset),
        "components" / GreedyRange(Aligned(64, Class(CorebootComponent))),
        #"module" / Class(CorebootBootblock)
    )

    reporting = [
        ["master"], [], ["embedded_controller"], [], ["components"]
    ]

# ========================================================================================
# Unexplained different (nonstandard? old?) format
#
# This is closer to correct than the "officially documented" code above, but it's still a
# mess.  I'm beginning to suspect that I may have chosen some malformed or "old" files
# from the "being retired" wiki as test cases.  Specifically, while
# qemu_coreboot_seabios.bin and qemu_coreboot_coreinfo.bin parse fine using the documented
# structures, the files qemu_coreboot_filo.bin and qemu_coreboot_openbios.bin are clearly
# in a different format, or are produced by a different tool chain. :-(
#
# This will require more investigation in the future.
# ========================================================================================

# ----------------------------------------------------------------------------------------
class CorebootComponentAlternate(FirmwareStructure):
    """
    I have no idea why the observed structure doesn't match the Coreboot documentation!
    """

    label = "Coreboot Component Alternate"

    definition = Struct(
        "_start" / Tell,
        "_magic" / Const(b'LARCHIVE'),
        "length" / Int32ub,
        "type" / Int32ub,
        "checksum" / Int32ub,
        "offset" / Int32ub,
        "u2" / Int32ub,
        "u3" / Int32ub,
        "u4" / Int32ub,
        "u5" / Int32ub,
        "u6" / Int32ub,
        "u7" / Int32ub,
        #"name" / Opt(CString()),
        "name" / CString(),
        #"name" / Aligned(32, CString()),
        "pos" / Tell,
        "data" / Bytes(this.length),
        #"junk" / Bytes(junklen),
        #"data" / FixedLength(this.length, Switch(
        #    this.type, {
        #        0x00000010: Class(CorebootStage),
        #        0x00000020: Class(CorebootPayload),
        #        0x00000030: Class(BIOSExtensionROM),
        #        0x00000050: Class(MysteryBytes),
        #        0x000001aa: Class(CMOSLayout),
        #        0xffffffff: Class(MysteryBytes),
        #    }, default = Class(MysteryBytes)
        #)),
    )

    @property
    def value(self) -> Optional[MysteryBytes]:
        return self.subparse(MysteryBytes, self.data, 0)

    reporting = [
        ["name"], ["type", "0x%x"], ["length"], ["checksum", "0x%x"], ["offset"],
        ["pos", "0x%x"], ["u2"], ["u3", "0x%x"], ["u4", "0x%x"], ["u5", "0x%x"], ["u6", "0x%x"],
        ["u7", "0x%x"],
        [], ["data", None], ["value"],
        #["junk"],
    ]

# ----------------------------------------------------------------------------------------
CorebootComponentType = Union[CorebootComponent, CorebootComponentAlternate, MysteryBytes]

# ----------------------------------------------------------------------------------------
class CorebootComponentWithPadding(FirmwareStructure):

    label = "Coreboot Component (with padding)"

    definition = Struct(
        "component" / Class(CorebootComponent),
        "_ff_padding" / GreedyRange(Const(b'\xff')),
        "ff_padding" / Computed(lambda ctx: len(ctx._ff_padding)),
    )

# ----------------------------------------------------------------------------------------
class CorebootComponentList(FirmwareStructure):

    label = "Coreboot Component List"
    definition = Struct(
        "_magic" / FailPeek(Const(b'LARCHIVE')),
        "failure" / CommitMystery,
        "components" / GreedyRange(Class(CorebootComponentWithPadding)),
        "unexpected" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
class ARCRegion(FirmwareStructure):

    label = "ARC Program Region"

    definition = Struct(
        "_magic" / FailPeek(Const(b'\xad\xde\xad\xde\xad')),
        "_dead" / GreedyRange(Const(b'\xad\xde')),
        "dead_len" / Computed(lambda ctx: len(ctx._dead)),
        # Named by the last 12 bytes which are "ARC_program\x00"
        "arc_program" / Until(b'\xff' * 16, Class(MysteryBytes)),
        "_ff_padding1" / GreedyRange(Const(b'\xff')),
        "ff_padding1" / Computed(lambda ctx: len(ctx._ff_padding1)),
        "data2" / Until(b'\xff' * 16, Class(MysteryBytes)),
        "_ff_padding2" / GreedyRange(Const(b'\xff')),
        "ff_padding2" / Computed(lambda ctx: len(ctx._ff_padding2)),
    )

# ----------------------------------------------------------------------------------------
class UEPRegion(FirmwareStructure):
    """
    This was just flailing to see if I could find a pattern.

    In the first exemplar, there were 3 sub-records with exactly matching byte sequences,
    but there were also extra zero bytes in between that I could find no way to explain.
    More importantly, I see no offsets that could aid in parsing the rest of the firmware.
    """

    label = "UEP Region"

    definition = Struct(
        "u1" / Int64ul,
        "u2" / Int64ul,
        "magic" / Const(b'$UEP'),
        "u3" / Int16ul,
        "u4" / Int16ul,
        "z1" / Bytes(16),
        "day" / PaddedString(4, 'utf-8'),
        "maybe_date" / HexBytes(6),
        "z2" / Int16ul,
        "z3" / Int64ul,
        "r1a" / HexBytes(16),
        "r1b" / HexBytes(4),
        "r1c" / HexBytes(52),
        "r2a" / HexBytes(16),
        "r2b" / HexBytes(12),
        "r2c" / HexBytes(52),
        "r3a" / HexBytes(16),
        "r3c" / HexBytes(52),
        "data" / Until(b'\xff' * 16, GreedyBytes),
        "_ff_padding" / GreedyRange(Const(b'\xff')),
        "ff_padding" / Computed(lambda ctx: len(ctx._ff_padding)),
    )

    reporting = [
        ["u1"], ["u2"], ["magic"], ["u3"], ["u4"], ["day"], ["maybe_date"],
        [], ["z1"], ["z2"], ["z3"], ["ff_padding"], ["data"],
        [], ["r1a"], ["r1c"], ["r1b"],
        [], ["r2a"], ["r2c"], ["r2b"],
        [], ["r3a"], ["r3c"],
    ]

# ----------------------------------------------------------------------------------------
class FMAPRecord(FirmwareStructure):

    label = "FMAP Record"

    definition = Struct(
        "_reject" / Peek(Int8ul),
        Check(lambda ctx: ctx._reject != 0xff),
        "name" / PaddedString(32, 'utf-8'),
        "u1" / Int16ul,
        "u2" / Int32ul,
        "u3" / Int32ul,
    )

    reporting = [["name"], ["u1", "0x%x"], ["u2", "0x%x"], ["u3", "0x%x"]]

# ----------------------------------------------------------------------------------------
class FMAPRegion(FirmwareStructure):

    label = "FMAP Region"

    definition = Struct(
        "_magic" / Const(b'__FMAP__'),
        "u1" / Int8ul,
        "u2" / Int8ul,
        "u3" / Int64ul,
        "u4" / Int32ul,
        #"data" / Until(b'\xff'*16, Class(HexDump)),
        "recs" / GreedyRange(Class(FMAPRecord)),
    )

    reporting = [["u1"], ["u2"], ["u3"], ["u4", "0x%x"], ["recs"]]

# ----------------------------------------------------------------------------------------
class FMAPAndCoreboot(FirmwareStructure):

    label = "FMAP and Coreboot"

    definition = Struct(
        "_ff_padding1" / GreedyRange(Const(b'\xff')),
        "ff_padding1" / Computed(lambda ctx: len(ctx._ff_padding1)),
        "fmap" / Class(FMAPRegion),
        "_ff_padding2" / GreedyRange(Const(b'\xff')),
        "ff_padding2" / Computed(lambda ctx: len(ctx._ff_padding2)),
        "coreboot" / Class(CorebootComponentList),
        "_ff_padding3" / GreedyRange(Const(b'\xff')),
        "ff_padding3" / Computed(lambda ctx: len(ctx._ff_padding3)),
    )

    reporting = [
        ["ff_padding1"], ["ff_padding2"], ["ff_padding3"],
        ["fmap"], ["coreboot"],
    ]

# ----------------------------------------------------------------------------------------
class TestCorebootHeader(FirmwareStructure):

    label = "Test Coreboot Header"

    definition = Struct(
        "_magic" / FailPeek(Const(b'\xaa\x55\x00\x00')),
        "data" / Until(b'\xff' * 16, Class(HexDump)),
        "_ff_padding1" / GreedyRange(Const(b'\xff')),
        "ff_padding1" / Computed(lambda ctx: len(ctx._ff_padding1)),
    )

# ----------------------------------------------------------------------------------------
@promote_exceptions
def cpd_consumed(ctx: Context) -> int:
    """
    Return the largest offset consumed by the CPD Manifest.
    """
    assert isinstance(ctx.pos, int)
    assert isinstance(ctx.max_offset, int)
    if ctx.max_offset == 0x12a300:
        computed = (ctx.max_offset - ctx.pos) + 0x000
        #log.debug("Returning consumed size of 0x%x" % computed)
        return computed
    return ctx.max_offset - ctx.pos

class CPDManifestWithData(FirmwareStructure):

    label = "ME CPD Manifest With Data"

    definition = Struct(
        "cpd" / Class(CPDManifestHeader),
        "pos" / Tell,
        # Find the end of the data consumed by the CPDManifest.
        "max_offset" / Computed(
            lambda ctx: max([entry.start + entry.size for entry in ctx.cpd.modules])),
        "consumed_size" / Computed(lambda ctx: ctx.max_offset - ctx.pos),
        "data" / FixedLength(this.consumed_size, Class(MysteryBytes)),
        "_ff_padding" / GreedyRange(Const(b'\xff')),
        "ff_padding" / Computed(lambda ctx: len(ctx._ff_padding)),
    )

    reporting = [["pos", "0x%x"], ["max_offset", "0x%x"], ["consumed_size", "0x%x"]]

    def analyze(self) -> None:
        # BUG! FIXME! Committed when incomplete...  In addition to advancing the stream
        # pointer to the correct location, we should do an analysis of the parsed entries
        # to see if there were any gaps/padding in between (there are!)
        self.data.label = "ME CPD Consumed Data"

# ----------------------------------------------------------------------------------------
class TestCorebootRegion(FirmwareStructure):

    label = "Test Coreboot Region"

    definition = Struct(
        "header1" / Class(TestCorebootHeader),
        "failure" / CommitMystery,
        "uep" / Class(UEPRegion),
        "cpds1" / GreedyRange(Class(CPDManifestWithData)),
        "header2" / Class(TestCorebootHeader),
        "cpds2" / GreedyRange(Class(CPDManifestWithData)),
        # Offsets are 0x2000, 0x3000, 0xe000, 0x1d000, 0x7e000, 0xa4000, 0x12e000, 0x381000
        "_ff_padding" / GreedyRange(Const(b'\xff' * 1024)),
        "ff_padding" / Computed(lambda ctx: len(ctx._ff_padding) * 1024),
        "header3" / Class(TestCorebootHeader),
        "header4" / Class(TestCorebootHeader),
        "cpds3" / GreedyRange(Class(CPDManifestWithData)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["header1"], ["uep"], ["cpds1"], ["header2"], ["cpds2"],
        ["header3"], ["header4"], ["cpds3"], ["ff_padding"],
    ]

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
