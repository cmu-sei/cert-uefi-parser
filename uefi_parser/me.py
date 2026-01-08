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
Intel Management Engine parsing.

This code could not have existed without the substantial research that preceded it.  The
most obvious source is Igor Skochinsky's seminal work on Intel Management Engine:

Igor Skochinsky's ME tools
https://github.com/skochinsky/me-tools

But there were numerous other sources for this file, including:

Dmitry Skylarov's Intel ME: Flash File System Explained (BlackHat Europe 2017)
https://www.youtube.com/watch?v=mYsTBPqbya8
https://www.blackhat.com/docs/eu-17/materials/
  eu-17-Sklyarov-Intel-ME-Flash-File-System-Explained.pdf

Mark Ermolov & Maxim Goryachy (Black Hat Europe 2017)
https://www.youtube.com/watch?v=9fhNokIgBMU

Positive Technologies Intel ME 11.x Firmware Images Unpacker
https://github.com/ptresearch/unME11/blob/master/unME11.py

Positive Technologies Intel ME File System Explorer
https://github.com/ptresearch/parseMFS

Plato Mavropoulos' MEAnalyzer
https://github.com/platomav/MEAnalyzer

Teddy Reed & Hector Martin, Intel ME Engine support in uefi-firmware-parser
https://github.com/theopolis/uefi-firmware-parser
"""

import struct
import hashlib
import logging
from enum import Enum
from uuid import UUID
from typing import Optional, Union

from construct import (
    Array, Bytes, Computed, Const, GreedyRange, GreedyBytes, If, Pointer, Select,
    Int8ul, Int16ul, Int16sl, Int24ul, Int32ul, Int32sl, Int64ul, Int64sl, Aligned,
    Switch, Sequence, Check, Peek, Seek, Tell, this)

from uefi_support import (
    HuffmanFlags, HuffmanDecompress, Huffman11Decompress,
    LzmaDecompress, DecompressionError)

from .base import (
    FirmwareStructure, HashedFirmwareStructure, PaddedString, Class, LazyBind, Struct,
    FixedLength, SafeFixedLength, FailPeek, promote_exceptions, UUID16, OneOrMore,
    HexBytes, FirmwareStructureReportContext, Opt, Context)
from .utils import purple
from .mystery import MysteryBytes, HexDump, CommitMystery
from .utils import crc16_me

log = logging.getLogger("cert-uefi-parser")

# ----------------------------------------------------------------------------------------
class MECompressionType(Enum):
    NoCompression = 0
    Huffman = 1
    LZMA = 2
    Unknown = 3

# ----------------------------------------------------------------------------------------
class MEModuleType(Enum):
    Default = 0
    PreMEKernel = 1
    VenomTPM = 2
    AppsQstDt = 3
    AppsAmt = 4
    Test = 5
    Unknown6 = 6
    Unknown7 = 7
    Unknown8 = 8
    Unknown9 = 9
    Unknown10 = 10

# ----------------------------------------------------------------------------------------
class MEAPIType(Enum):
    Data = 0
    ROM = 1
    Kernel = 2
    Unknown = 3

# ----------------------------------------------------------------------------------------
class MEPowerType(Enum):
    Reserved = 0
    M0Only = 1
    M2Only = 2
    Live = 3

# ----------------------------------------------------------------------------------------
class MEPartitionType(Enum):
    Code = 0
    BlockIO = 1
    NVRAM = 2
    Generic = 3
    EFFS = 4
    ROM = 5

# ----------------------------------------------------------------------------------------
class MEModuleHeader1(FirmwareStructure):

    label = "ME Module Header 1"

    definition = Struct(
        "_magic" / Const(b'$MME'),
        "guid" / Bytes(16),
        "major_version" / Int16ul,
        "minor_version" / Int16ul,
        "hotfix_version" / Int16ul,
        "build_version" / Int16ul,
        "name" / PaddedString(16),
        "hash" / Bytes(20),
        "size" / Int32ul,
        "flags" / Int32ul,
        "unknown1" / Int32ul,
        "unknown2" / Int32ul,
    )

# ----------------------------------------------------------------------------------------
class MEModuleHeader2(FirmwareStructure):

    label = "ME Module Header 2"

    definition = Struct(
        "_magic" / Const(b'$MME'),
        "name" / PaddedString(16),
        "rev_hash" / Bytes(32),
        "module_base" / Int32ul,
        "offset" / Int32ul,
        "decomp_size" / Int32ul,
        "comp_size" / Int32ul,
        "u1" / Int32ul,
        "u2" / Int32ul,
        "entry" / Int32ul,
        "flags" / Int32ul,
        "u3" / Int32ul,
        "u4" / Int32ul,
        "u5" / Int32ul,
    )

    decompressed_data: Optional[bytes]

    reporting = [
        ["name", "%s", purple], ["offset", "0x%x"], ["comp_size"],
        ["flags", "0x%x"], ["entry", "0x%x"], ["module_base", "0x%x"], ["decomp_size", "0x%x"],
        [], ["compression"], ["module_type"], ["api_type"], ["power_type"], ["privileged"],
        [], ["u1", "0x%x"], ["u2"], ["u3"], ["u4"], ["u5"],
        ["rev_hash", None], ["mhash", None], ["hexhash"],
        ["decompressed_data", None], ["decompressed_len"],
    ]

    @property
    def power_type(self) -> MEPowerType:
        return MEPowerType((self.flags >> 1) & 0x3)

    @property
    def compression(self) -> MECompressionType:
        return MECompressionType((self.flags >> 4) & 0x7)

    @property
    def module_type(self) -> MEModuleType:
        return MEModuleType((self.flags >> 7) & 0xf)

    @property
    def api_type(self) -> MEAPIType:
        return MEAPIType((self.flags >> 11) & 0x7)

    @property
    def privileged(self) -> bool:
        return bool(self.flags >> 16)

    @property
    def mhash(self) -> bytes:
        return bytes(reversed(self.rev_hash))

    @property
    def hexhash(self) -> str:
        return self.mhash.hex()

    def analyze(self) -> None:
        self.decompressed_data = None
        self.decompressed_len = 0

    def analyze_compression(self, compressed_data: bytes, compressed_offset: int) -> None:
        """
        Analyze the not compressed and LZMA compressed ME modules.
        """
        # We should ignore Huffman compression because it's being handled in the
        # analyze_huffman() method.
        if self.compression == MECompressionType.Huffman:
            return

        # Extract the data from the compressed data.  We've already validated that the
        # compressed data in the modules are all adjancent and contained in the data
        # beginning at compressed_offset.
        offset = self.offset - compressed_offset
        extracted_data = compressed_data[offset:offset + self.comp_size]
        #self.debug("Extract bytes 0x%x - 0x%x = cdata[0x%x:0x%x] -> %r" % (
        #    self.offset, compressed_offset, offset, self.comp_size, extracted_data[:32]))

        # Decompress the data if needed.
        if self.compression == MECompressionType.NoCompression:
            self.decompressed_data = extracted_data
        elif self.compression == MECompressionType.LZMA:
            self.decompressed_data = LzmaDecompress(extracted_data)
        else:
            self.error(f"Unrecognized compression type {self.compression}")

        if self.decompressed_data is None:
            return

        self.decompressed_len = len(self.decompressed_data)

        # Validate that the hashes on the decompressed data match the header.
        decomp_hasher = hashlib.sha256()
        decomp_hasher.update(self.decompressed_data)
        decomp_hash = decomp_hasher.digest()
        if decomp_hash != self.mhash:
            self.error("LZMA/Uncompressed module hashes differ:")
            self.error(f"  Expected:     {self.hexhash}")
            self.error(f"  Decompressed: {decomp_hash.hex()}")

    def analyze_huffman(self, lut: Optional['LLUT'], version: int) -> None:
        if lut is None:
            return

        if self.compression != MECompressionType.Huffman:
            return

        opos = 0
        pos = self.module_base
        end_pos = pos + self.decomp_size
        decomp_base = lut.decomp_base + 0x10000000

        self.info("Analyzing huffman pos=0x%x end_pos=0x%x" % (pos, end_pos))

        self.decompressed_data = b''
        while pos < end_pos:
            i = int((pos - decomp_base) / lut.chunk_size)
            # Check that the chunk index is valid
            if i >= lut.chunk_count:
                self.debug("Chunk index %d was invalid!" % i)
                pos += lut.chunk_size
                continue
            # Get the entry from the LUT.
            entry = lut.entries[i]
            # If the llut chunk was marked as empty, ignore it.
            if entry.flags == HuffmanFlags.Empty:
                pos += lut.chunk_size
                continue

            # Advance opos, but not past the expected end.
            outsize = lut.chunk_size
            if (end_pos - pos) < outsize:
                outsize = end_pos - pos
            opos += outsize

            addr = entry.addr - lut.data_start
            #self.debug("i=%4d opos=0x%x e.addr=0x%x addr=0x%x e.flags=%s csize=0x%x" % (
            #    i, opos, entry.addr, addr, entry.flags, lut.chunk_size))
            #self.debug("  in=%r" % (lut.compressed_data[addr:addr+32].hex()))
            if entry.flags == HuffmanFlags.Uncompressed:
                uncompressed = lut.compressed_data[addr:addr + outsize]
            else:
                uncompressed = HuffmanDecompress(lut.compressed_data, addr,
                                                 entry.flags, lut.chunk_size, version)
            if len(uncompressed) != outsize:
                self.error("Unexpected length fom unhuff %d != %d" % (len(uncompressed), outsize))

            self.decompressed_data += uncompressed
            # Advance to the next entry (and position in the data stream).
            pos += lut.chunk_size

        if self.decompressed_data is None:
            return

        self.decompressed_len = len(self.decompressed_data)

        #self.debug("Final opos=0x%x" % opos)
        decomp_hasher = hashlib.sha256()
        decomp_hasher.update(self.decompressed_data)
        decomp_hash = decomp_hasher.digest()
        if decomp_hash != self.mhash:
            self.error("Huffman decompressed module hashes differ:")
            self.error(f"  Expected:     {self.hexhash}")
            self.error(f"  Decompressed: {decomp_hash.hex()}")

# ----------------------------------------------------------------------------------------
class MCPVariable(FirmwareStructure):

    label = "MCP Variable"

    definition = Struct(
        # These two sizes have been reported to extend the size of the
        # current partition entry, or something like that.  It appears
        # to somehow be related to the poorly parse LLUT table.
        "size1" / Int32ul,
        "size2" / Int32ul,
        "u3" / Int32ul,
        # Probably not really guids?  Just 32 random bytes?
        "guid1" / UUID16,
        "guid2" / UUID16,
        "u4" / Int16ul,
        "u5" / Int16ul,
        "u6" / Int32ul,
        "u7" / Int32ul,
        "u8" / Int32ul,
        "unexpected" / GreedyBytes,
    )

# ----------------------------------------------------------------------------------------
class SKUVariable(FirmwareStructure):
    """$SKU Variable format.  Wild guessing.  Probably 8 bytes clustered in some way."""

    label = "SKU Variable"

    definition = Struct(
        "unk1" / Array(8, Int8ul),
        "unexpected" / GreedyBytes,
    )

# ----------------------------------------------------------------------------------------
class MMXThing(FirmwareStructure):

    label = "MMX Variable Thing"

    definition = Struct(
        "tag" / Bytes(4),
        "u1" / Int32ul,
        "u2" / Int32ul,
        "u3" / Int32ul,
        "u4" / Bytes(4),
        "u5" / Bytes(4),
        "u6" / Bytes(4),
        "u7" / Int32ul,
        "u8" / Int32ul,
        "u9" / Int32ul,
    )

    reporting = [
        ["tag"], ["u1"], ["u2"], ["u3"],
        # ["u4", "0x%x"], ["u5", "0x%x"], ["u6", "0x%x"],
        ["u7", "0x%08x"], ["u8", "0x%08x"], ["u9", "0x%08x"],
        #["data"]
    ]

# ----------------------------------------------------------------------------------------
class MMXVariable(FirmwareStructure):
    """$MMX Variable format.  Wild guessing."""

    label = "MMX Variable"

    definition = Struct(
        "u1" / Int32ul,
        "u2" / Int16ul,
        "u4" / Int32ul,
        "d1" / Bytes(10),
        "unk" / Class(MMXThing),
        "uke" / Class(MMXThing),
        "leg" / Class(MMXThing),
        "hot" / Class(MMXThing),
        "fpf" / Class(MMXThing),
        "ses" / Class(MMXThing),
        "cls" / Class(MMXThing),
        "at0" / Class(MMXThing),
        "mv0" / Class(MMXThing),
        "_padding" / GreedyRange(Const(b'\xff')),
        "zzz_unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["d1"], [],
    ]

# ----------------------------------------------------------------------------------------
class DATVariable(FirmwareStructure):
    """$DAT Variable format.  Wild guessing."""

    label = "DAT Variable"

    definition = Struct(
        "u1" / Int32ul,
        "u2" / Int32ul,
        "u3" / Int32ul,
        "u4" / Int32ul,
        "tag" / Bytes(4),
        "zeros" / GreedyRange(Const(0, Int32ul)),
        "unexpected" / GreedyBytes,
    )

# ----------------------------------------------------------------------------------------
class UPVVariable(FirmwareStructure):
    """$UPV Variable format.  Wild guessing."""

    label = "UPV Variable"

    definition = Struct(
        "u1" / Int32ul,
        "tag" / Bytes(4),
        "u2" / Int16ul,
        "u3" / Int16ul,
        "u4" / Int32ul,
        "u5" / Int32ul,
        "u6" / Int32ul,
        "u7" / Int32ul,
        "data" / GreedyBytes,
    )

# ----------------------------------------------------------------------------------------
class MEVariableModule(FirmwareStructure):

    label = "ME Variable Module"

    definition = Struct(
        #  A valid VariableModule begins with a dollar sign.
        "_magic" / Const(b'$'),
        # Backup one byte and include the '$' in the tag as well.
        Seek(-1, 1),
        "tag" / Bytes(4),
        # Size is in dwords, including the 8 byte header.
        "size" / Int32ul,
        #"data" / Bytes((this.size * 4) - 8),
        # FIXME: Should maybe be SafeFixedLength?
        "failure" / CommitMystery,
        "data" / SafeFixedLength(
            (this.size * 4) - 8,
            Switch(this._.tag, {
                b"$MCP": Class(MCPVariable),
                b"$SKU": Class(SKUVariable),
                b"$MMX": Class(MMXVariable),
                b"$DAT": Class(DATVariable),
                b"$UPV": Class(UPVVariable),
            }, default=Class(MysteryBytes))),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
    )

    # if tag == '$UDC': data = (subtag, hash, name, offset, size) = unpack(4s32s16sII)

    reporting = [
        ["tag", "%s", purple], ["size"],
        # Data is not of much value right now...
        #["data", None],
        #["skipped"],
    ]

# ----------------------------------------------------------------------------------------
class LUTEntry(FirmwareStructure):

    label = "LUT Entry"

    definition = Struct(
        "value" / Int32ul,
        #"addr" / Computed(lambda ctx: ctx['value']  & 0x01ffffff),
        #"flags" / Computed(lambda ctx: (ctx['value'] & 0xfe000000) >> 25),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    value: int

    @property
    def addr(self) -> int:
        return self.value & 0x01ffffff

    @property
    def flags(self) -> HuffmanFlags:
        fval = (self.value & 0xfe000000) >> 25
        try:
            return HuffmanFlags(fval)
        except ValueError:
            return HuffmanFlags(0xff)

    reporting = [["addr", "0x%x"], ["flags"], ["value", None]]

# ----------------------------------------------------------------------------------------
class LLUT(FirmwareStructure):

    label = "Huffman Lookup Table (LLUT)"

    definition = Struct(
        "_magic" / Const(b'LLUT'),
        "chunk_count" / Int32ul,
        "decomp_base" / Int32ul,
        "spi_base" / Int32ul,
        "data_size" / Int32ul,
        "data_start" / Int32ul,
        "flags" / Int32ul,
        "u2" / Array(5, Int32ul),
        "chunk_size" / Int32ul,
        "major_version" / Int16ul,
        "minor_version" / Int16ul,
        "chipset" / Bytes(4),
        "revision" / Bytes(4),
        # The lookup table entries are stored next.
        "entries" / Array(this.chunk_count, Class(LUTEntry)),
        "position_at_probe" / Tell,
        # The compressed data is at [data_start:data_start+data_size].  The
        # previous code said the data was relative to the manifest data, not the header,
        # and subtracted a "relative offset" from both values.
        "compressed_data" / Bytes(this.data_size),
    )

    reporting = [
        ["chipset"], ["revision"], ["chunk_count"], ["chunk_size"], ["data_start", "0x%x"],
        ["data_size"], ["decomp_base", "0x%x"],
        [], ["flags", "0x%x"], ["spi_base", "0x%x"], ["major_version"], ["minor_version"],
        ["u2"], ["position_at_probe", "0x%x"],
        # Entries can be printed, but the output is kind of long, and
        [], ["entries", None],
        ["compressed_data", None]
    ]

    @promote_exceptions
    def unnecessary_analyze(self) -> None:
        # This algorithm determines the approximate non-overlapping size of the LUT entry
        # chunks.  This information is NOT needed to decompress the modules, but it might
        # be interesting when debugging the LUT entries, so I've kept the code.
        self.compressed_len = len(self.compressed_data)
        sorted_addresses = sorted(entry.addr for entry in self.entries)
        for i in range(len(sorted_addresses) - 1):
            addr = sorted_addresses[i]
            if addr == 0:
                continue
            next_addr = sorted_addresses[i + 1]
            if addr == next_addr:
                continue
            length = next_addr - addr
            for entry in self.entries:
                if entry.addr == addr:
                    entry.length = length
                    #a = entry.addr - self.data_start
                    #entry.data = self.compressed_data[a:a+length]
                    break
            #self.debug("i=%s addr=0x%x next_addr=0x%x length=0x%x" % (
            #          i, addr, next_addr, length))

# ----------------------------------------------------------------------------------------
@promote_exceptions
def compressed_data_size(ctx: Context) -> int:
    """
    Return the expected size of the LZMA and uncompressed data.

    This value is the summation of the compressed sizes of the sections in the
    MEManifestPartition that are not Huffman compressed.  We also want to ensure that there
    are no bytes being ignored in the compressed data section, so we check that each file
    begins right after the previous one.  This requirement may in fact be too strict, but
    it works for the files I've seen so far.  If needed, we can make this code more
    permissive in the future.
    """
    expected_size = 0
    last_offset = ctx['compressed_offset'] - ctx['_start_offset']
    for module in ctx['modules']:
        if isinstance(module, MEModuleHeader2):
            if module.compression != MECompressionType.Huffman:
                if module.offset != last_offset:
                    fmt = "MEModule %s not at expected offset 0x%x != 0x%x in compressed data"
                    log.debug(fmt % (module.name, module.offset, last_offset))
                expected_size += module.comp_size
                last_offset = module.offset + module.comp_size
    return expected_size

# ----------------------------------------------------------------------------------------
class MEManifestPartition(FirmwareStructure):

    label = "ME Manifest Header"

    definition = Struct(
        "_start_offset" / Tell,
        # FIXME: These Const() limitations effectively ignore other values!
        "module_type" / Const(4, Int16ul),
        "module_subtype" / Const(0, Int16ul),
        "header_length" / Int32ul,
        "header_major_version" / Int16ul,
        "header_minor_version" / Int16ul,
        "flags" / Int32ul,  # 0x80000000 = Debug
        "module_vendor" / Int32ul,
        "date" / Int32ul,  # BCD yyyy/mm/dd
        "size" / Int32ul,  # Size is in 4-byte dwords
        "tag" / Bytes(4),
        "num_modules" / Int32ul,
        "major_version" / Int16ul,
        "minor_version" / Int16ul,
        "hotfix_version" / Int16ul,
        "build_version" / Int16ul,
        "unknown2" / Bytes(19 * 4),
        "key_size" / Int32ul,
        "scratch_size" / Int32ul,
        "rsa_pub_key" / Bytes(256),
        "rsa_pub_exp" / Int32ul,
        "rsa_sig" / Bytes(256),
        "name" / PaddedString(8),
        "unknown3" / Int32ul,
        "modules" / Array(
            this.num_modules,
            Switch(this.tag, {
                b'$MAN': Class(MEModuleHeader1),
                b'$MN2': Class(MEModuleHeader2),
            }, default=Bytes(16)),
        ),
        # There appears to be an additional "$MN2" sized block (96 bytes) of FFs.
        "_end_of_modules" / Const(b'\xff' * 96),

        # Then there are some variable modules.
        "variable_modules" / GreedyRange(
            Aligned(4, Class(MEVariableModule))),

        # The variable modules ended at _start + (size*4), but then there's some padding
        # that is proving very difficult quantify.
        "ff1_pos" / Tell,
        "_ff1_padding" / GreedyRange(Const(b'\xff')),
        "ff1_len" / Computed(lambda ctx: len(ctx._ff1_padding)),

        # The LLUT object is only present if there was at least one Huffman compressed
        # partition.  Currently rather than testing that, we scheck to see if the LLUT
        # magic is in the right place.  This is probably sufficient, but might not be 100%
        # correct in the compressed data coincidentally started with LLUT.  The LLUT if
        # present should be located at the the offset specified in for all of the Huffman
        # compressed modules in the header (relative to the start of Manifest header).
        "llut" / Opt(Class(LLUT)),

        # The data for the uncompressed and LZMA sections follows the optional LLUT.  The
        # size is apparently implied by the total size of the MEManifest header but that
        # includes some additionl ff padding.  Call compressed_data_size to accumulate the
        # number of bytes actually used, and perform some additional validation.
        "compressed_offset" / Tell,
        "compressed_data" / Bytes(compressed_data_size),

        # After the compressed data there's some more poorly defined padding that appears
        # to be up to 4k in size.
        "ff2_pos" / Tell,
        "_ff2_padding" / GreedyRange(Const(b'\xff')),
        "ff2_len" / Computed(lambda ctx: len(ctx._ff2_padding)),
        "extra" / Class(MysteryBytes),
    )

    reporting = [
        ["name", "%s", purple], ["version"], ["flags", "0x%x"],
        ["module_type"], ["module_subtype"], ["num_modules"], ["unknown2"], ["unknown3", "0x%x"],
        [], ["size"], ["scratch_size"], ["tag"],
        ["major_version", None], ["minor_version", None],
        ["hotfix_version", None], ["build_version", None],
        ["header_major_version", None], ["header_minor_version", None],
        ["rsa_pub_exp"],
        ["date", "0x%x"], ["header_length"], ["header_version"], ["key_size"],
        ["module_vendor"],
        # The padding and the compressed offset are "calcualted" values.
        [], ["ff1_pos", "0x%x"], ["ff1_len"], ["ff2_pos", "0x%x"], ["ff2_len"],
        # We validated that compressed data became the decompressed modules... But we
        # might still want to report the compressed offset.
        ["compressed_offset", "0x%x"], ["compressed_data", None],
        # FIXME: Quit ignoring the RSA signatures!
        ["rsa_pub_key", None],
        ["rsa_sig", None],
        ["unknown1", None],
        # The sub-objects...
        ["modules"], ["variable_modules"], ["llut"], ["extra"],
    ]

    @property
    def header_version(self) -> str:
        return "%s.%s" % (self.header_major_version, self.header_minor_version)

    @property
    def version(self) -> str:
        return "%s.%s.%s.%s" % (self.major_version, self.minor_version,
                                self.hotfix_version, self.build_version)

    @promote_exceptions
    def image_sections(self) -> list[tuple[int, int, str, bytes]]:
        sections = []
        for module in self.modules:
            if module.decompressed_data is not None:
                s = module.module_base
                # Use the actual length of the decompressed data because it sometimes (but
                # not always) differs from the size in the header by one page (0x1000)?
                e = module.module_base + len(module.decompressed_data)
                #if module.decomp_size != len(module.decompressed_data) + 0x1000:
                #    self.debug("Module size mismatch! 0x%x != 0x%x + 0x1000" % (
                #        module.decomp_size, len(module.decompressed_data)))
                sections.append((s, e, module.name, module.decompressed_data))
        return sections

    @promote_exceptions
    def image(self) -> None:
        sections = self.image_sections()
        if len(sections) == 0:
            return
        min_addr = min(s[0] for s in sections)
        max_addr = max(s[1] for s in sections)

        # If the low address is near zero, just move it to zero to be tidy.
        if min_addr < 0x10000:
            min_addr = 0
        image_size = max_addr - min_addr

        image = bytearray(image_size)
        for (start, end, section_name, section_image) in sections:
            rs = start - min_addr
            re = end - min_addr
            self.debug("MAN: 0x%08x 0x%08x %s" % (start, end, section_name))
            image[rs:re] = section_image

        # FIXME!  This should not be here, but instead should be handled by the mostly
        # unimplemented dumping to disk capability.
        if False:
            iname = "%s_0x%0x.bin" % (self.name.decode('utf-8'), min_addr)
            fh = open(iname, 'wb')
            fh.write(image)
            fh.close()
            self.info(f"Wrote image to '{iname}'")

    def analyze(self) -> None:
        for module in self.modules:
            if isinstance(module, MEModuleHeader2):
                # This call will decompress Huffman compressed modules.
                module.analyze_huffman(self.llut, self.major_version)

                # And this one will handle no compression and LZMA compression. The
                # offsets in the compressed data are expressed in the module headers
                # relative to the MEManifestHader, so we subtract self._data_offset.
                comp_offset = self.compressed_offset - self._data_offset
                module.analyze_compression(self.compressed_data, comp_offset)

# ----------------------------------------------------------------------------------------
@promote_exceptions
def version_12_test(ctx: Context) -> bool:
    return int(ctx._._.header.major_version) >= 12

class CPDManifestFileThing(FirmwareStructure):

    label = "ME CPD Manifest File Thing"

    definition = Struct(
        "module" / Bytes(4),
        "name" / PaddedString(12),
        "u1" / Int16ul,
        "u2" / Int16ul,
        "u3" / Int32ul,
        "u4" / If(lambda ctx: version_12_test(ctx), Int32ul),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    name: str

    reporting = [["module"], ["u1"], ["u2"], ["u3"], ["u4"], ["name"]]

    def instance_name(self) -> str:
        return self.name

# ----------------------------------------------------------------------------------------
class ManifestThingList(FirmwareStructure):

    label = "Thing List"

    definition = Struct(
        "type" / Const(1, Int32ul),
        "size" / Int32ul,
        "u1" / Int32ul,
        "num_things" / Int32ul,
        "things" / Array(this.num_things, Class(CPDManifestFileThing)),
        "endloc" / Tell,
    )

    reporting = [
        ["type"], ["size"], ["u1"], ["num_things"], ["endloc", "0x%x"], ["things"]
    ]

# ----------------------------------------------------------------------------------------
class ManifestType0a(FirmwareStructure):

    label = "Manifest File Type 0a"

    definition = Struct(
        "name" / Bytes(4),
        "u1" / Int32ul,
        "u2" / Int16ul,
        "u3" / Int16ul,
    )

    reporting = [
        ["name"], ["u1", "0x%x"], ["u2"], ["u3"],
    ]

    def instance_name(self) -> str:
        return str(self.name)

# ----------------------------------------------------------------------------------------
class ManifestType0(FirmwareStructure):

    label = "Manifest File Type 0"

    definition = Struct(
        "type" / Const(0, Int32ul),
        "size" / Int32ul,
        "u1" / Int32ul,
        "u2" / Int32ul,
        "hash" / HexBytes(32),
        "u3" / Int32ul,
        "u4" / Int32ul,
        "u5" / Int32ul,
        "u6" / Int32ul,
        "subzeros" / SafeFixedLength(this.size - 64, GreedyRange(Class(ManifestType0a))),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
    )

    reporting = [
        ["type"], ["size"], ["u1", "0x%x"], ["u2", "0x%x"], ["u3", "0x%x"],
        ["u4"], ["u5"], ["u6"], ["skipped"],
        [], ["hash"],
    ]

# ----------------------------------------------------------------------------------------
class ManifestType2(FirmwareStructure):

    label = "Manifest File Type 2"

    definition = Struct(
        "type" / Const(2, Int32ul),
        "size" / Int32ul,
        "data" / FixedLength(this.size - 8, OneOrMore(Int32ul)),
    )

    reporting = [["type"], ["size"], ["data"]]

# ----------------------------------------------------------------------------------------
class ManifestType3HashInfo(FirmwareStructure):

    label = "Manifest Hash Info"

    definition = Struct(
        "name" / PaddedString(12),
        "u1" / Int16ul,
        "u2" / Int16sl,
        "size" / Int32ul,  # Decompressed size of the module
        "hash" / HexBytes(32),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    name: str

    reporting = [
        ["hash"], ["size", "0x%04x"], ["u1"], ["u2"], ["name"],
    ]

    def instance_name(self) -> str:
        return self.name

# ----------------------------------------------------------------------------------------
class ManifestType3(FirmwareStructure):

    label = "Manifest File Type 3"

    definition = Struct(
        "type" / Const(3, Int32ul),
        "size" / Int32ul,
        "modname" / Bytes(4),
        "u1" / Int16ul,
        "u2" / Int16ul,
        "hash" / HexBytes(32),
        "u3" / Int32ul,
        "u4" / Int32ul,
        "u5" / Int32ul,
        "u6" / Int32ul,
        "u7" / Int32ul,
        "u8" / Int64sl,
        "u9" / Int64sl,
        "u10" / Int32ul,
        "infos" / SafeFixedLength(this.size - 88, GreedyRange(
            Class(ManifestType3HashInfo))),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
    )

    reporting = [
        ["modname"], ["type"], ["size"],
        ["u1", "0x%x"], ["u2"], ["u3"], ["u4", "0x%x"], ["u5", "0x%x"],
        ["u6"], ["u7"], ["u8"], ["u9"], ["u10"], ["skipped"],
        [], ["hash"],
        ["infos"],
    ]

# ----------------------------------------------------------------------------------------
class ManifestTypeGeneric(FirmwareStructure):

    label = "Manifest Type Generic"

    definition = Struct(
        "type" / Int32ul,
        "size" / Int32ul,
        "data" / FixedLength(this.size - 8, Class(HexDump)),
    )

    reporting = [["type"], ["size"], ["data"]]

# ----------------------------------------------------------------------------------------
class ManifestType12(FirmwareStructure):

    label = "Manifest File Type 12"

    definition = Struct(
        "type" / Const(12, Int32ul),
        "size" / Const(48, Int32ul),
        "u1" / Int32ul,
        "u2" / Int64sl,
        "u3" / Int64sl,
        "u4" / Int64sl,
        "u5" / Int32sl,
        "u6" / Int64ul,
    )

    reporting = [
        ["type"], ["size"], ["u1", "0x%x"], ["u2"], ["u3"], ["u4"], ["u5"], ["u6"],
    ]

# ----------------------------------------------------------------------------------------
class ManifestType15a(FirmwareStructure):

    label = "Manifest File Type 15a"

    definition = Struct(
        "name" / PaddedString(12, 'ascii'),
        "u1" / Int32ul,
        "u2" / Int32ul,
        "hash" / HexBytes(32),
    )

    reporting = [
        ["name"], ["u1", "0x%x"], ["u2"], ["hash"],
    ]

# ----------------------------------------------------------------------------------------
class ManifestType15(FirmwareStructure):

    label = "Manifest File Type 15"

    definition = Struct(
        "type" / Const(15, Int32ul),
        "size" / Int32ul,
        "modname" / Bytes(4),
        "u1" / Int32ul,
        "u2" / Int64ul,
        "u3" / Int64ul,
        "u4" / Int32ul,
        "u5" / Int32ul,
        "u6" / Int64ul,
        "u7" / Int32ul,
        "subrecs" / FixedLength(this.size - 52, GreedyRange(Class(ManifestType15a))),
    )

    reporting = [
        ["type"], ["size"], ["modname"],
        ["u1"], ["u2"], ["u3"], ["u4"], ["u5"], ["u6"], ["u7"],
    ]

# ----------------------------------------------------------------------------------------
class ManifestType18a(FirmwareStructure):

    label = "Manifest File Type 18 Record"

    definition = Struct(
        "u1" / HexBytes(56),
    )

# ----------------------------------------------------------------------------------------
class ManifestType18(FirmwareStructure):

    label = "Manifest File Type 18"

    definition = Struct(
        "type" / Const(18, Int32ul),
        "size" / Int32ul,
        "nrecs" / Int32ul,
        "u1" / Int32ul,
        "u2" / Int32ul,
        "u3" / Int64ul,
        "recs" / Array(this.nrecs, Class(ManifestType18a)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["type"], ["size"], ["nrecs"], ["u1"], ["u2"], ["u3"], ["recs"],
    ]

# ----------------------------------------------------------------------------------------
class ManifestType22(FirmwareStructure):

    label = "Manifest File Type 22"

    definition = Struct(
        "type" / Const(22, Int32ul),
        "size" / Const(88, Int32ul),
        "modname" / Bytes(4),
        "u1" / Int16ul,
        "u2" / Int32ul,
        "u3" / Int32ul,
        "u4" / Int16ul,
        "u5" / Int64ul,
        "u6" / Int32ul,
        "hash" / HexBytes(32),
        "zeros" / Array(5, Int32ul),
    )

    reporting = [
        ["type"], ["size"], ["modname"], ["u1"], ["u2"], ["u3"], ["u4"], ["u5"], ["u6"],
        [], ["hash"], ["zeros"],
    ]

# ----------------------------------------------------------------------------------------
class MEManifestHeaderOnly(FirmwareStructure):

    label = "ME Manifest Header"

    definition = Struct(
        # FIXME: These Const() limitations effectively ignore other values!
        "module_type" / Const(4, Int16ul),
        "module_subtype" / Const(0, Int16ul),
        "header_length" / Int32ul,
        "header_major_version" / Int16ul,
        "header_minor_version" / Int16ul,
        "flags" / Int32ul,  # 0x80000000 = Debug
        "arch" / Int32ul,  # module_vendor in MEManifestPartition!
        "date" / Int32ul,  # BCD yyyy/mm/dd
        "size" / Int32ul,  # Size is in 4-byte dwords
        "tag" / Bytes(4),
        "u1" / Int32ul,  # Differs from MEManifestPartition!
        "major_version" / Int16ul,
        "minor_version" / Int16ul,
        "hotfix_version" / Int16ul,
        "build_version" / Int16ul,
        "u2" / Array(19, Int32ul),
        "key_size" / Int32ul,
        "scratch_size" / Int32ul,
        "rsa_pub_key" / Bytes(256),
        "rsa_pub_exp" / Int32ul,
        "rsa_sig" / Bytes(256),
    )

    reporting = [
        ["version"], ["flags", "0x%x"], ["module_type"], ["module_subtype"],
        [], ["u1", "0x%x"], ["u2"],
        [], ["size"], ["scratch_size"], ["tag"],
        ["major_version", None], ["minor_version", None],
        ["hotfix_version", None], ["build_version", None],
        ["header_major_version", None], ["header_minor_version", None],
        ["rsa_pub_exp"],
        ["date", "0x%x"], ["header_length"], ["header_version"], ["key_size"],
        ["arch", "0x%x"],
        # FIXME: Quit ignoring the RSA signatures!
        ["rsa_pub_key", None],
        ["rsa_sig", None],
    ]

    @property
    def header_version(self) -> str:
        return "%s.%s" % (self.header_major_version, self.header_minor_version)

    @property
    def version(self) -> str:
        return "%s.%s.%s.%s" % (self.major_version, self.minor_version,
                                self.hotfix_version, self.build_version)

# ----------------------------------------------------------------------------------------
class CPDManifestFile(FirmwareStructure):

    label = "ME CPD Manifest File"

    definition = Struct(
        "header" / Class(MEManifestHeaderOnly),
        "records" / OneOrMore(Select(
            Class(ManifestThingList),
            Class(ManifestType0),
            Class(ManifestType2),
            Class(ManifestType3),
            Class(ManifestType12),
            # ManifestType14 has been seen (length 172, body length 164)
            Class(ManifestType15),
            Class(ManifestType18),
            Class(ManifestType22),
            Class(ManifestTypeGeneric))),
        "hex" / Class(MysteryBytes),
    )

    reporting = [["header"], ["records"]]

    def instance_name(self) -> str:
        return "Unknown"

# ----------------------------------------------------------------------------------------
class CPDMetadata4(FirmwareStructure):

    label = "ME CPD Metadata4"

    definition = Struct(
        "type" / Const(4, Int32ul),
        "size" / Int32ul,
        "u1" / Int32ul,
        "u2" / Int32ul,
        "u3" / Int32ul,
        "u4" / Int32ul,
        "u5" / Int32sl,
        "u6" / Int32ul,
        "u7" / Int32ul,
        "u8" / Int32ul,
        "u9" / Int32ul,
    )

    reporting = [
        ["type"], ["size"], ["u1"], ["u2", "0x%x"], ["u3"],
        ["u4"], ["u5"], ["u6"], ["u7"], ["u8", "0x%x"], ["u9"],
    ]

# ----------------------------------------------------------------------------------------
class CPDMetadata5(FirmwareStructure):

    label = "ME CPD Metadata5"

    definition = Struct(
        "type" / Const(5, Int32ul),
        "size" / Int32ul,  # Of this record
        "u3" / Int32ul,
        "u4" / Int32ul,
        "u5" / Int32ul,
        "dataseg" / Int32ul,
        "u7" / Int32ul,
        "u8" / Int32ul,
        "u9" / Int32ul,
        "u10" / Int32ul,
        "u11" / Int32ul,
        "u12" / Int32ul,
        "u13" / Int32ul,
        "u14" / Int32ul,
        "u15" / Int32ul,
        "u16" / Int32ul,
        "u17" / Int32ul,
        "offsets" / FixedLength(this.size - 68, GreedyRange(Int16ul)),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    dataseg: int

    reporting = [
        ["type"], ["size"], ["u3"], ["u4", "0x%x"],
        ["u5", "0x%x"], ["dataseg", "0x%x"],
        ["u7"], ["u8", "0x%x"], ["u9", "0x%x"], ["u10", "0x%x"],
        ["u11", "0x%x"], ["u12", "0x%x"],
        ["u13"], ["u14"], ["u15"], ["u16"], ["u17"],
        [], ["offsets"],
    ]

    def instance_name(self) -> str:
        return "0x%x 0x%x" % (self.u4, self.u11)

# ----------------------------------------------------------------------------------------
class CPDMetadata6Tuple(FirmwareStructure):

    label = "ME CPD Metadata6 Tuple"

    definition = Struct(
        "u1" / Int32ul,
        "one" / Int32ul,
        "u3" / Int32ul,
        "zero" / Int32ul,
    )

    reporting = [["u1", "0x%x"], ["one", "0x%x"], ["u3", "0x%x"], ["zero", "0x%x"]]

# ----------------------------------------------------------------------------------------
class CPDMetadata6(FirmwareStructure):

    label = "ME CPD Metadata6"

    definition = Struct(
        "type" / Const(6, Int32ul),
        "size" / Int32ul,
        "tuples" / FixedLength(this.size - 8, GreedyRange(Class(CPDMetadata6Tuple))),
    )

    reporting = [["type"], ["size"], ["tuples"]]

    def instance_name(self) -> str:
        return ""

# ----------------------------------------------------------------------------------------
class CPDMetadata7Tuple(FirmwareStructure):

    label = "ME CPD Metadata7 Tuple"

    definition = Struct(
        "u1" / Int32ul,
        "u2" / Int32ul,
    )

    reporting = [["u1", "0x%x"], ["u2", "0x%x"]]

    def instance_name(self) -> str:
        return "0x%x 0x%x" % (self.u1, self.u2)

# ----------------------------------------------------------------------------------------
class CPDMetadata7(FirmwareStructure):

    label = "ME CPD Metadata7"

    definition = Struct(
        "type" / Const(7, Int32ul),
        "size" / Int32ul,
        "tuples" / FixedLength(this.size - 8, GreedyRange(Class(CPDMetadata7Tuple))),
    )

    reporting = [["type"], ["size"], ["tuples"]]

    def instance_name(self) -> str:
        return ""

# ----------------------------------------------------------------------------------------
class CPDMetadata8Tuple(FirmwareStructure):

    label = "ME CPD Metadata8 Tuple"

    definition = Struct(
        "u1" / Int32ul,
        "u2" / Int32ul,
        "u3" / Int32ul,
    )

    reporting = [["u3", "0x%x"], ["u1", "0x%x"], ["u2", "0x%x"]]

    def instance_name(self) -> str:
        return "0x%x 0x%x 0x%x" % (self.u1, self.u2, self.u3)

# ----------------------------------------------------------------------------------------
class CPDMetadata8(FirmwareStructure):

    label = "ME CPD Metadata8"

    definition = Struct(
        "type" / Const(8, Int32ul),
        "size" / Int32ul,
        "tuples" / FixedLength(this.size - 8, GreedyRange(Class(CPDMetadata8Tuple))),
    )

    reporting = [["type"], ["size"], ["tuples"]]

    def instance_name(self) -> str:
        return ""

# ----------------------------------------------------------------------------------------
class CPDMetadataEntryPoint(FirmwareStructure):

    # I'm just guessing that these are entry points.  There's no real evidence of that.
    label = "Entry Point Info"

    definition = Struct(
        "name" / PaddedString(12),
        "flags" / Int16ul,  # Maybe?, Usually 0x1b0, occasionally 0x1f0
        "u2" / Int16ul,  # Often the same within a module
        "offset" / Int16ul,  # Offset to something?
        "seq" / Int16ul,  # Usually increases by one for each record.
        "zero" / Int32ul,  # Always zero?
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    name: str

    reporting = [
        ["seq", "0x%04x"], ["flags", "0x%04x"], ["u2", "0x%04x"], ["offset", "0x%04x"],
        ["zero"], ["name"],
    ]

    def instance_name(self) -> str:
        return self.name

# ----------------------------------------------------------------------------------------
class CPDMetadataEntryPointInfoList(FirmwareStructure):

    label = "Entry Point Info List"

    definition = Struct(
        "type" / Const(9, Int32ul),
        "size" / Int32ul,
        "u1" / Int32ul,
        "entries" / FixedLength(this.size - 12,
                                GreedyRange(Class(CPDMetadataEntryPoint))),
    )

    reporting = [["type"], ["size"], ["u1"]]

# ----------------------------------------------------------------------------------------
class CPDMetadataHashInfo(FirmwareStructure):

    label = "Hash Info"

    definition = Struct(
        "type" / Const(10, Int32ul),
        "size" / Int32ul,
        "u1" / Int32ul,
        "usize" / Int32ul,
        "csize" / Int32ul,
        "u2" / Int16ul,
        "arch" / Int16ul,
        "hash" / HexBytes(32),
    )

    reporting = [
        ["type"], ["size"], ["hash"], ["arch", "0x%x"],
        ["csize", "0x%x"], ["usize", "0x%x"],
        ["u1"], ["u2", "0x%x"],
    ]

    def instance_name(self) -> str:
        return str(self.hash)

# ----------------------------------------------------------------------------------------
class CPDMetadata11(FirmwareStructure):

    label = "ME CPD Metadata11"

    definition = Struct(
        "type" / Const(11, Int32ul),
        "size" / Int32ul,
        "u1" / Int32ul,
        "u2" / Int32ul,
    )

    reporting = [["type"], ["size"], ["u1"], ["u2"]]

# ----------------------------------------------------------------------------------------
class CPDMetadataModule(FirmwareStructure):

    label = "Module Info"

    definition = Struct(
        "u1" / Int32ul,
        "u2" / Int32ul,
        "u3" / Int32ul,
        "u4" / Int32ul,
        "_name" / PaddedString(36),
    )

    @property
    def name(self) -> str:
        if isinstance(self._name, str) and self._name.isprintable():
            return self._name
        # BUG! FIXME!  This is meant to be a marker to allow me to grep the results to
        # determine under what conditions the CPDMetadataModuleInfoList is in the
        # "alternative" format.  Perhaps it's Intel ME version 12?
        return "CORRUPT"

    reporting = [
        ["u1", "0x%03x"], ["u2", "0x%05x"], ["u3", "0x%05x"], ["u4", "0x%05x"],
        ["name"],
    ]

    def instance_name(self) -> str:
        return self.name

# ----------------------------------------------------------------------------------------
class CPDMetadataModuleInfoList(FirmwareStructure):

    label = "Module Info List"

    definition = Struct(
        "type" / Const(13, Int32ul),
        "size" / Int32ul,
        "tuples" / FixedLength(this.size - 8, GreedyRange(Class(CPDMetadataModule))),
    )

    reporting = [["type"], ["size"]]

# ----------------------------------------------------------------------------------------
class CPDMetadata(FirmwareStructure):

    label = "ME CPD Metadata"

    definition = Struct(
        "records" / GreedyRange(Select(
            Class(CPDMetadata4),
            Class(CPDMetadata5),
            Class(CPDMetadata6),
            Class(CPDMetadata7),
            Class(CPDMetadata8),
            Class(CPDMetadataEntryPointInfoList),
            Class(CPDMetadataHashInfo),
            Class(CPDMetadata11),
            Class(CPDMetadataModuleInfoList),
        )),
        "unexpected" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
@promote_exceptions
def lazy_fmap_region(ctx: Context) -> Class:
    from .coreboot import FMAPAndCoreboot
    return Class(FMAPAndCoreboot)

@promote_exceptions
def lazy_coreboot(ctx: Context) -> Class:
    from .coreboot import CorebootContainer
    return Class(CorebootContainer)

class CPDEntryPresentation(FirmwareStructure):

    label = "ME CPD Presentation"

    definition = Struct(
        "pres" / Select(
            LazyBind(lazy_fmap_region),
            LazyBind(lazy_coreboot),
        ),
    )

# ----------------------------------------------------------------------------------------
class CPDEntry(FirmwareStructure):

    label = "ME CPD Entry"

    definition = Struct(
        "name" / PaddedString(12),
        # Equivalent to compression = value >> 24, offset = value & 0xffffff
        "offset" / Int24ul,
        "_compression" / Int8ul,
        "size" / Int32ul,
        "flags" / Int32ul,
        "start" / Computed(lambda ctx: ctx._.cpd_start + ctx.offset),
        "data" / Pointer(this.start, Bytes(this.size))
    )

    decompressed_data: Optional[bytes]
    presentation: Optional[FirmwareStructure]
    # FIXME! Needed until correct types are returned from the mypy extension...
    data: bytes

    reporting = [
        ["name", "%s", purple], ["offset", "0x%x"], ["start", "0x%x"],
        ["size", "0x%x"], ["flags", "0x%x"], ["compression"],
        [], ["compressed_hash"], ["decompressed_hash"],
        [], ["decompressed_len", "0x%x"], ["data_len", "0x%x"],
        ["guessed_code_segment", "0x%x"], ["guessed_data_segment", "0x%x"],
        ["presentation"],
        # Value is disabled despite being a property because it's no longer worth
        # reporting.  These bytes have been confirmed to be code (and interleaved data).
        # In other words, the interpretation is (mostly) understood, but not easily
        # displayed.
        ["value", None], ["data", None], ["decompressed_data", None],
    ]

    sbom_fields = ["name", "compressed_hash", "decompressed_hash"]

    # This is a hacky pseudo-global variable for tracking what major version of Intel ME
    # we're currently parsing.
    _version = 0
    _version_reported = 0

    @property
    def compression(self) -> MECompressionType:
        # This seems to be a very odd algorithm for enconding a compression type...
        if (isinstance(self.name, str)
                and (self.name.endswith(".met") or self.name.endswith(".man"))):
            return MECompressionType.NoCompression
        elif self._compression == 2:
            return MECompressionType.Huffman
        elif self._compression == 0:
            return MECompressionType.LZMA
        else:
            return MECompressionType.Unknown

    @promote_exceptions
    def decompress_data(self) -> bytes:
        if self.compression == MECompressionType.NoCompression:
            return self.data
        # Real decompression is not supported for versions other than 11.
        elif self.__class__._version == 11:
            if self.compression == MECompressionType.LZMA:
                fixed = self.data
                #self.debug("Fixed data before len=%6d value=%s" % (len(fixed), fixed[:32].hex()))
                if fixed[0x0e:0x11] == b'\x00\x00\x00':
                    #self.debug("Fixed the data!")
                    fixed = fixed[:0x0e] + fixed[0x11:]
                #self.debug("Fixed data after len=%d value=%r" % (len(fixed), fixed[:32]))
                try:
                    dc = LzmaDecompress(fixed)
                    #fh = open("me_%s_decomp.bin" % self.name, "wb")
                    #fh.write(dc)
                    #fh.close()
                    return dc
                except DecompressionError:
                    self.error(f"LZMA decompression failed for module '{self.name}'")
                return fixed
            else:
                #return self.data
                try:
                    dc = Huffman11Decompress(self.data)
                    return dc
                except AssertionError as e:
                    self.error(f"Huffman decompression failed for module '{self.name}'")
                    self.error(f"  {e}")
                    return b''
                except DecompressionError as e:
                    self.error(f"Huffman decompression failed for module '{self.name}'")
                    self.error(f"  {e}")
                    return b''
        else:
            # In particular, MECompressionType.LZMA doesn't even really mean LZMA in
            # version 14 as far as I can tell.

            # Report problems decrypting, but only once per version number change because
            # lots of these messages get annoying.
            if self.__class__._version != self.__class__._version_reported:
                self.info("Decompression skipped for Intel ME version=%s" % (
                    self.__class__._version))
                self.__class__._version_reported = self.__class__._version

            #from .huffman import save_huffman_codewords
            #save_huffman_codewords("found_huffman_codewords.txt",
            #                       self.data, self.start, self.size)
            return b''

    def guess_data_segment_address(self) -> None:
        if self.decompressed_data is None:
            return

        self.guessed_data_segment = 0
        # First find the code that compares with the marker.
        # jnc +0x13; test bl,0x3; jnz +0xe; cmp ebx,0x53535353
        loader_code = b'\x73\x13\xf6\xc3\x03\x75\x0e\x81\x3b\x53\x53\x53\x53'
        loc = self.decompressed_data.find(loader_code)
        if loc == -1:
            return
        marker_code = struct.unpack("<I", self.decompressed_data[loc - 10:loc - 6])[0]
        #self.debug("Marker code says marker for %s is at: 0x%08x" % (self.name, marker_code))
        # Then find the actual marker.
        marker_bytes = b'\x53\x53\x53\x53\xff\xff\xff\xff'
        marker = self.decompressed_data.rfind(marker_bytes)
        if marker == -1:
            return
        #self.debug("Marker itself for %s is at offset: 0x%08x" % (self.name, marker))
        # Compute the address of the data segment
        self.guessed_data_segment = marker_code - marker

    def guess_code_segment_address(self) -> None:
        # This code was repurposed to try and guess the offset of syslib instead, since it
        # now seems that the "data_segment_offset" is really just the base address of
        # everything in the module.
        self.guessed_code_segment = 0
        if self.compression != MECompressionType.LZMA:
            return
        if self.decompressed_data is None:
            return

        code_base_votes = {}
        total_votes = 0
        for pos, opcode in enumerate(self.decompressed_data):
            if opcode == 0xe8:
                # This is the relative address in the instruction
                relative_addr = struct.unpack("<i", self.decompressed_data[pos + 1:pos + 5])[0]
                # The is the called address relative to the start of the image.  The minus
                # 5 is because the instruction is 5 bytes long, and the call is relative
                # to EIP after the instruction.
                call_offset = pos + relative_addr - 5
                # Calls inside (or after) the image start are not what we're looking for.
                if call_offset > 0:
                    continue
                # This is where the code segment would be loaded to make that a call to 0xa1000.
                #code_segment = 0x1a000 - call_offset
                # The jump table at 0x1a000 is 0x852 bytes long.
                code_segment = self.guessed_data_segment + call_offset
                # Round the code segment to the next multiple of 0x1000
                code_segment = ((code_segment >> 12) << 12) + 0x1000
                #self.debug("Guess syslib is at 0x%x, base=0x%x call=0x%x" %(
                #    code_segment, self.guessed_data_segment, call_offset))

                # Vote for the address suggested by this call.
                if code_segment not in code_base_votes:
                    code_base_votes[code_segment] = 0
                code_base_votes[code_segment] += 1
                total_votes += 1
        # Too few votes means no winner.
        if total_votes < 10:
            return
        # Now figure out who won the election. ;-)
        winner = 0
        winning_votes = 0
        for code_segment in code_base_votes:
            if code_base_votes[code_segment] > winning_votes:
                winner = code_segment
                winning_votes = code_base_votes[code_segment]
        #self.debug("0x%08x is the guessed syslib base of %12s at 0x%08x with %.2f%% of %d votes" % (
        #    winner, self.name, self.guessed_data_segment,
        #    (winning_votes/total_votes)*100, total_votes))
        self.guessed_code_segment = winner

    def image_data(self) -> Optional[bytes]:
        """
        Return the data for this entry that gets written into the image.

        While the Huffman and not compressed modules appear to be decompressed before
        going into the image, the LZMA modules overlap with other if decompressed.  Thus
        we conclude that they must be located at these addresses in compressed for
        instead.  That's also consistent with the size member of the header being the
        compressed size for the LZMA modules, while it's the decompresed size for the
        others.
        """
        if self.compression == MECompressionType.LZMA:
            return self.data
        else:
            return self.decompressed_data

    def save_image(self, data_segment_offset: int) -> None:
        # This needs to be called from the parent long after construction, because
        # data_segment_offset comes from the Metadata file for the corresponsing module.
        # But it's not actually clear that the "data segment offset" code is correct.
        if self.decompressed_data is not None:
            if data_segment_offset != 0:
                base = self.guessed_code_segment
                fh = open("memodules/%s_code_0x%08x.bin" % (self.name, base), "wb")
                fh.write(self.decompressed_data[:data_segment_offset])
                fh.close()

            base = self.guessed_data_segment
            if base == 0:
                base = self.start
            fh = open("memodules/%s_data_0x%08x.bin" % (self.name, base), "wb")
            fh.write(self.decompressed_data[data_segment_offset:])
            fh.close()

    @property
    def value(self) -> Optional[Union[str, bytes]]:
        ddata = self.decompressed_data
        if ddata is None:
            return None
        if len(ddata) > 32:
            return "%r..." % ddata[:32]
        return ddata

    @property
    def decompressed_hash(self) -> Optional[str]:
        # Doesn't match anything in the headers. :-(
        if self.decompressed_data is None:
            return None
        decomp_hasher = hashlib.sha256()
        decomp_hasher.update(self.decompressed_data)
        return decomp_hasher.digest().hex()

    @property
    def compressed_hash(self) -> str:
        # Doesn't match anything in the headers. :-(
        decomp_hasher = hashlib.sha256()
        decomp_hasher.update(self.data)
        return decomp_hasher.digest().hex()

    def analyze(self) -> None:
        self.decompressed_len = 0
        self.data_len = len(self.data)
        self.decompressed_data = self.decompress_data()
        if self.decompressed_data is not None:
            self.decompressed_len = len(self.decompressed_data)
            self.guess_data_segment_address()
            self.guess_code_segment_address()

        # MET and MAN are always not compressed parse using self._memory instead.
        if isinstance(self.name, str) and self.name.endswith('.met'):
            self.presentation = CPDMetadata.parse(self._memory, self.start, self.size)
        elif isinstance(self.name, str) and self.name.endswith('.man'):
            self.presentation = CPDManifestFile.parse(self._memory, self.start, self.size)
        else:
            # Silly switching between compressed and not compressed data, because some CPD
            # entries say compressed, but then aren't actually compresssed?
            if self.decompressed_len == 0:
                self.presentation = CPDEntryPresentation.parse(
                    self._memory, self.start, self.size)
                if self.presentation is None:
                    self.presentation = MysteryBytes.parse(self._memory, self.start, self.size)
                    if self.presentation is not None:
                        self.presentation.label = "CPD Entry Presentation (Mystery Bytes)"
            else:
                self.presentation = CPDEntryPresentation.parse(self.decompressed_data, 0)
                if self.presentation is None:
                    self.presentation = MysteryBytes.parse(self.decompressed_data, 0)
                    if self.presentation is not None:
                        self.presentation.label = "CPD Entry Presentation (Mystery Bytes)"

        # If this was a metadata section that tells us which major version of Intel ME
        # this is, record that now.
        if isinstance(self.presentation, CPDManifestFile):
            # This is very hacky.  We need to know the version number from inside a
            # _different_ CPD Entry (specifically the FTPR.man) to know how to
            # decompress other entries.  For complicated reasons I was unable to
            # figure out how to get that data flow to work without cheating.
            self.__class__._version = self.presentation.header.major_version

# ----------------------------------------------------------------------------------------
class CPDManifestHeader(FirmwareStructure):

    label = "ME CPD Manifest"

    definition = Struct(
        # Used by CPDEntry to find offsets relative to here.
        "cpd_start" / Tell,
        "_magic" / Const(b'$CPD'),
        "num_modules" / Int32ul,
        "flags" / Int32ul,
        "name" / Bytes(4),
        "modules" / Array(this.num_modules, Class(CPDEntry))
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    modules: list[CPDEntry]

    reporting = [
        ["name", "%r", purple], ["num_modules"], ["flags", "0x%x"], ["cpd_start", "0x%x"],
    ]

    sbom_fields = ["name", "modules"]

    def image_sections(self) -> list[tuple[int, int, str, bytes]]:
        sections = []
        for module in self.modules:
            image_data = module.image_data()
            if image_data is not None:
                s = module.start
                e = module.start + module.size
                if len(image_data) != module.size:
                    self.error("Decompressed image size did not match 0x%x != 0x%x" % (
                        module.size, len(image_data)))
                #self.debug("CPD: 0x%08x 0x%08x 0x%08x %s" % (s, e, module.size, module.name))
                sections.append((s, e, module.name, image_data))
        return sections

    def image(self) -> None:
        sections = self.image_sections()
        if len(sections) == 0:
            return
        min_addr = min(s[0] for s in sections)
        max_addr = max(s[1] for s in sections)

        # If the low address is near zero, just move it to zero to be tidy.
        if min_addr < 0x10000:
            min_addr = 0
        image_size = max_addr - min_addr

        image = bytearray(image_size)
        for (start, end, section_name, section_image) in sections:
            rs = start - min_addr
            re = end - min_addr
            #self.debug("CPD: 0x%08x 0x%08x %s" % (start, end, section_name))
            image[rs:re] = section_image

    # def find_metadata_dataseg(self, module: CPDEntry) -> int:
    #     if module.name.endswith(".met") or module.name.endswith(".man"):
    #         return 0
    #
    #     # For modules not named *.met or *.man, we need to find the metadata module
    #     # for this module so we can get the data segment offset.
    #     metname = module.name + ".met"
    #     for metmodule in self.modules:
    #         if metmodule.name != metname:
    #             continue
    #         if metmodule.metadata is None:
    #             return 0
    #         for metarecord in metmodule.metadata.records:
    #             if metarecord.type != 5:
    #                 continue
    #             return metarecord.dataseg
    #     return 0

    def save_images(self) -> None:
        # For each module, save the image(s).
        for module in self.modules:
            # Disable "data segment offset" since that code isn't completely correct.
            dataseg = 0
            #dataseg = self.find_metadata_dataseg(module)
            module.save_image(dataseg)

# ----------------------------------------------------------------------------------------
class MEModuleFile(FirmwareStructure):
    """
    This data structure is expected after $MOD magic, probably in ME Partition entries.

    But I haven't actiually seen it yet to test the code. :-(
    """

    definition = Struct(
        #"magic" / Const(b'$MOD'),
        "magic" / Bytes(4),
        "unk1" / Int32ul,
        "unk2" / Int32ul,
        "major_version" / Int16ul,
        "minor_version" / Int16ul,
        "hotfix_version" / Int16ul,
        "build_version" / Int16ul,
        "unk3" / Int16ul,
        "compressed_size" / Int32ul,
        "decompressed_size" / Int32ul,
        "mapped_size" / Int32ul,
        "unk4" / Int32ul,
        "unk5" / Int32ul,
        "name" / PaddedString(16, 'ascii'),
        "guid" / Bytes(16),
    )

# ----------------------------------------------------------------------------------------
class PartitionEntryHeader(HashedFirmwareStructure):

    label = "ME Partition Entry"

    definition = Struct(
        "name" / Bytes(4),
        "_owner" / Bytes(4),
        "offset" / Int32sl,
        "size" / Int32ul,
        "tokens_on_start" / Int32sl,
        "max_tokens" / Int32sl,
        "scratch_sectors" / Int32sl,
        "multivalue" / Int32ul,
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    _owner: bytes
    multivalue: int

    reporting = [
        ["name", "%s", purple], ["owner"], ["offset", "0x%x"], ["size", "0x%x"],
        ["multivalue", None], ["ptype"], ["flags", "0x%x"],
        ["max_tokens"], ["scratch_sectors"], ["tokens_on_start"], [],
    ]

    sbom_fields = ["name", "body", "hash"]

    @property
    def ptype(self) -> MEPartitionType:
        return MEPartitionType(self.multivalue & 0x7f)

    @property
    def flags(self) -> int:
        return (self.multivalue & 0xffffff80) >> 7

    @property
    def owner(self) -> Optional[bytes]:
        if self._owner == b'\xff\xff\xff\xff':
            return None
        return self._owner

    def instance_name(self) -> str:
        return str(self.name)

# ----------------------------------------------------------------------------------------
class MFSChunk(FirmwareStructure):

    label = "MFS Chunk"

    definition = Struct(
        "data" / Bytes(64),
        "crc" / Int16ul,
    )

    index: Optional[int]

    # This is not usually used because chunk reporting is disabled completely in
    # MFSDataPage and MFSSystemPage.
    reporting = [["crc"], ["index"], ["data"]]

    def analyze(self) -> None:
        self.index = None
        self.data_crc: Optional[int] = None

    @promote_exceptions
    def set_index(self) -> None:
        """
        Set the index for this chunk (on a system page).

        Called by the MFSSystemPage class.
        """
        # Calculate the checksum of the 64 bytes of data.  This is the "constant" part of
        # the data stream to which we'll be appending two additional bytes of index.
        checksum_data64 = crc16_me(self.data)
        self.data_crc = checksum_data64

        # This loop could be prohibitively expensive, but it turns out that the indexes
        # are usually near zero, so it typically only evaluates a small number of the
        # interations that could be required to find the correct index.
        for index in range(2**16):
            combined_crc = crc16_me(struct.pack('H', index), checksum_data64)
            if combined_crc == self.crc:
                self.index = index
                #fmt = "crc_file=0x%04x crc_data=0x%04x crc_calc=0x%04x index=0x%04x"
                #self.debug(fmt % (self.crc, checksum_data64, combined_crc, index))
                break

# ----------------------------------------------------------------------------------------
class MFSPageHeader(FirmwareStructure):

    label = "MFS Page Header"

    definition = Struct(
        #"magic" / Const(0xAA555787, Int32ul),
        "_magic" / Const(b'\x87xU\xaa'),
        #"_magic" / Bytes(4),
        # Update sequence number
        "usn" / Int32ul,
        # How many times page has been erased
        "erased" / Int32ul,
        "next_erase" / Int16ul,
        "first_chunk" / Int16ul,
        "checksum" / Int8ul,
        "_zero" / Const(0, Int8ul),
    )

    reporting = [
        ['usn'], ['erased'], ['next_erase'], ['first_chunk'], ['checksum'],
    ]

# ----------------------------------------------------------------------------------------
class MFSDataPage(FirmwareStructure):

    label = "MFS Data Page"

    definition = Struct(
        "header" / Class(MFSPageHeader),
        # System pages have zero in first chunk
        Check(lambda ctx: ctx['header'].first_chunk != 0),
        "free_chunk_map" / Array(122, Int8ul),
        "chunks" / Array(122, Class(MFSChunk)),
    )

    # This is not usually used because reporting is disabled by the report() override.
    reporting = [["header"], ["free_chunk_map"], ["chunks"]]

    # This is the code that controls reporting (unless it's commented out).
    def report(self, context: FirmwareStructureReportContext
               = FirmwareStructureReportContext()) -> None:
        # Just report the header as the data page with a different label.
        self.header.report(context)

    def analyze(self) -> None:
        self.header.label = self.__class__.label

    def instance_name(self) -> str:
        return ""

# ----------------------------------------------------------------------------------------
class MFSSystemPage(FirmwareStructure):

    label = "MFS System Page"

    definition = Struct(
        "header" / Class(MFSPageHeader),
        "indexes" / Array(121, Int16ul),
        "chunks" / Array(120, Class(MFSChunk)),
        "padding" / Bytes(12),
    )

    # This is not usually used because reporting is disabled byr report() override.
    reporting = [["header"], ["indexes"], ["padding"], ["chunks"]]

    # This is the code that controls reporting (unless it's commented out).
    def report(self, context: FirmwareStructureReportContext
               = FirmwareStructureReportContext()) -> None:
        # Just report the header as the data page with a different label.
        self.header.report(context)

    def analyze(self) -> None:
        self.header.label = self.__class__.label
        for n in range(len(self.chunks)):
            chunk = self.chunks[n]
            # Chunks where the obfuscated index is 0xffff or 0x7ffff don't have really
            # indexes, so don't waste time trying to reverse the checksum of the chunk.
            if self.indexes[n] == 0xffff or self.indexes[n] == 0x7ffff:
                continue
            # For all other chunks recover the index.
            chunk.set_index()

    def instance_name(self) -> str:
        return ""

# ----------------------------------------------------------------------------------------
class MFSEmptyPage(FirmwareStructure):

    label = "MFS Empty Page"

    definition = Struct(
        "bytes" / Bytes(8192),
    )

    reporting = [["data"], ["bytes", None]]

    @property
    def data(self) -> str:
        return "8KB of (unused?) data: %r..." % (self.bytes[0:16])

    def instance_name(self) -> str:
        return ""

# ----------------------------------------------------------------------------------------
class MFSModeBits(object):

    mode: int   # FIXME? A bit hacky?  Is MFSModeBits a mixin?  or an abstract base?

    @property
    def mode_integrity(self) -> bool:
        return bool(self.mode & (1 << 9))

    @property
    def mode_encryption(self) -> bool:
        return bool(self.mode & (1 << 10))

    @property
    def mode_antireplay(self) -> bool:
        return bool(self.mode & (1 << 11))

    @property
    def perm_string(self) -> str:
        return "%s%s%s%s%s%s%s%s%s" % (
            'r' if (self.mode & (1 << 8)) else '-',
            'w' if (self.mode & (1 << 7)) else '-',
            'x' if (self.mode & (1 << 6)) else '-',
            'r' if (self.mode & (1 << 5)) else '-',
            'w' if (self.mode & (1 << 4)) else '-',
            'x' if (self.mode & (1 << 3)) else '-',
            'r' if (self.mode & (1 << 2)) else '-',
            'w' if (self.mode & (1 << 1)) else '-',
            'x' if (self.mode & 1) else '-',
        )

    @property
    def mode_type_dir(self) -> bool:
        return False

    @property
    def mode_non_intel_keys(self) -> bool:
        return False

    @property
    def mode_string(self) -> str:
        return "%s%s%s%s%s%s" % (
            'd' if self.mode_type_dir else '-',
            'N' if self.mode_non_intel_keys else '-',
            'A' if self.mode_antireplay else '-',
            'E' if self.mode_encryption else '-',
            'I' if self.mode_integrity else '-',
            self.perm_string,
        )

# ----------------------------------------------------------------------------------------

# This is the "cwd" while parsing the MFS file stuctures.  Each directory is pushed onto
# the list when found, and a value is popped each time '..' is found.
mfs_full_path: list[str] = []

class MFSFileSecurity(FirmwareStructure):
    """
    Named T_FileSecurity in Skylarov's presentation.
    """

    label = "MFS File Security"

    definition = Struct(
        # The HMAC covers the file data, this security structure (with hmac zerod), plus
        # the fileno and salt from the MFS Directory structure.
        "hmac" / HexBytes(32),
        # These flags are assigned meaning in Skylarov's presentation, but the bits don't
        # line up well with what I found in my ROM, so I'm just leaving them uninterpreted
        # for now.
        "flags" / Int32ul,
        # Likewise, this was a union of a 16-byte nonce and 2 anti-replay 32-bit integers,
        # but in my ROM there was nothing but zeros here.
        "nonce" / HexBytes(16),
    )

    sbom_fields = ["hmac"]

    reporting = [
        ["flags"], ["hmac"], ["nonce"],
    ]

# ----------------------------------------------------------------------------------------
class MFSFile(FirmwareStructure, MFSModeBits):
    """
    A file contained in the intel.cfg archive.

    Named T_CFG_Record in Skylarov's presentation.
    """

    label = "MFS File"

    definition = Struct(
        "name" / PaddedString(12),
        "unused" / Int16ul,
        "mode" / Int16ul,
        "opt" / Int16ul,
        "length" / Int16ul,
        "uid" / Int16ul,
        "gid" / Int16ul,
        "offset" / Int32ul,
    )

    rawdata: bytes

    reporting = [
        ["uid", '%03d'], ["gid", '%03d'],
        ["mode_string"], ["mode", None],
        ["path"], ["name", None],
        ["opt"], ["length"],
        ["offset", '0x%0x'], ["unused"],
        ["mode_encryption", None],
        ["mode_integrity", None],
        ["mode_antireplay", None],
        ["mode_type_dir", None],
        ["mode_non_intel_keys", None],
        ["perm_string", None],
        ["rawdata", None], ["data"]
    ]

    @property
    def mode_type_dir(self) -> bool:
        return bool(self.mode & (1 << 12))

    @property
    def data(self) -> Optional[Union[bytes, MysteryBytes]]:
        if len(self.rawdata) < 8:
            return self.rawdata
        mb = MysteryBytes.parse(self.rawdata, 0)
        if mb is not None:
            mb.label = "Data"
        return mb

    def analyze(self) -> None:
        root = ''
        if len(mfs_full_path) > 0:
            root = '/' + '/'.join(mfs_full_path)
        self.path = root + '/' + self.name
        if self.name == '..':
            mfs_full_path.pop()
        elif self.mode_type_dir:
            mfs_full_path.append(self.name)

# ----------------------------------------------------------------------------------------
class IntelCfg(FirmwareStructure):

    label = "MFS intel.cfg File"

    definition = Struct(
        "_home" / FailPeek(Sequence(
            Int32ul, Const(b'home\x00\x00\x00\x00\x00\x00\x00\x00'))),
        # Beginning of T_CFG from Skylarov's presentation.
        "count" / Int32ul,
        "files" / Array(lambda ctx: ctx.count, Class(MFSFile)),
        "base" / Tell,
        "data" / GreedyBytes,
    )

    def analyze(self) -> None:
        for file in self.files:
            offset = file.offset - self.base
            file.rawdata = self.data[offset:offset + file.length]

    reporting = [
        ["count"], ["base"], ["files"], ["data", None]
    ]

# ----------------------------------------------------------------------------------------
class MFSDirectory(FirmwareStructure, MFSModeBits):

    label = "MFS Directory Entry"

    definition = Struct(
        "multi" / Int32ul,
        # FIXME? This is also a pretty hokey way to detect the end of the valid
        # MFSDirectory objects in a Greedy array.  Skylaraov said that fsid was always 1,
        # but I found one case where fsid was 0.
        Check(lambda ctx: ((ctx['multi'] & 0xf << 28) >> 28) <= 1),
        "mode" / Int16ul,
        "uid" / Int16ul,
        "gid" / Int16ul,
        "salt2" / Int16ul,
        "name" / PaddedString(12),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    multi: int

    @property
    def fileno(self) -> int:
        return self.multi & 0x7ff

    @property
    def salt1(self) -> int:
        return (self.multi & (0xff << 11)) >> 11

    @property
    def fsid(self) -> int:
        return (self.multi & (0xf << 28)) >> 28

    @property
    def mode_type_dir(self) -> bool:
        return bool(self.mode & (1 << 14))

    @property
    def mode_non_intel_keys(self) -> bool:
        return bool(self.mode & (1 << 13))

    reporting = [
        ["mode_string"], ["uid"], ["gid"], ["name"], ["fileno"], ["fsid"],
        ["salt1", "0x%04x"], ["salt2", "0x%04x"],
        ["multi", None],
        ["mode", None],
        ["mode_encryption", None],
        ["mode_integrity", None],
        ["mode_antireplay", None],
        ["mode_type_dir", None],
        ["mode_non_intel_keys", None],
        ["perm_string", None],
    ]

# ----------------------------------------------------------------------------------------
class MFSDirFile(FirmwareStructure):

    label = "MFS Directory File"

    definition = Struct(
        # The legitimate directoty files all seem to start with an entry for "." and "..".
        # But this probably isn't the correct way to detect this.  FIXME?
        "entries" / GreedyRange(Class(MFSDirectory)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["entries"], ["unexpected"],
    ]

    def analyze(self) -> None:
        self.unexpected.label = "Unexpected"

    def update_filenames(self, thisname: str, filenames: dict[int, str]) -> None:
        for entry in self.entries:
            if entry.name != '.':
                namestr = '???'
                if isinstance(entry.name, str):
                    namestr = entry.name
                #elif isinstance(entry.name, bytes):
                #    namestr = entry.name.decode('utf-8')
                filenames[entry.fileno] = thisname + '/' + namestr

# ----------------------------------------------------------------------------------------
class MFSFATFile(HashedFirmwareStructure):

    label = "MFS FAT File"

    # Not really Construct parsed in the traditional sense.
    definition = Struct(
        "data" / GreedyBytes,
    )

    data: bytes

    reporting = [
        ["fileno", "%4d"], ["start", "0x%06x"], ["end", "0x%06x"],
        ["path"], ["secured"], ["encrypted"], ["security"], ["length"],
        [], ["datahash"], ["fshash"],
        ["parsed"],
        ["data", None], ["directory", None], ["chunks", None]
    ]

    sbom_fields = ["fileno", "path", "security", "fshash", "datahash"]

    @property
    def length(self) -> int:
        # FIXME?  Is this needed?
        return self.end - self.start

    def analyze(self) -> None:
        self.parsed: Optional[FirmwareStructure] = None
        self.directory = False
        self.secured = False
        self.encrypted = False
        self.security: Optional[MFSFileSecurity] = None
        self.path: Optional[str] = None
        self.datahash: Optional[str] = None

    def set_fileno(self, fileno: int, start: int, end: int, chunks: list[int]) -> None:
        # The number of this file in the filesystem.
        self.fileno = fileno
        # Possibly the start and end offset
        self.start = start
        self.end = end
        # The list of chunks used in this file.
        self.chunks = chunks

    def visit(self, other_files: dict[int, 'MFSFATFile']) -> None:
        # The raw data for the the file is now complete.  If the file is "secured" the
        # last 52 bytes are not actually actually part of the file, but rather the
        # FileSecurity structure.
        stop = len(self.data)
        if self.secured and self.security is None:
            #fsdata = self.data[-52:]
            #self.security = MFSFileSecurity.parse(fsdata, 0)
            stop -= 52
            self.security = self.subparse(MFSFileSecurity, "data", stop)
            self.data = self.data[:-52]

        # The FileSecurity structure has the hmac of the file, but it's a little unclear
        # right now exactly what was hashed.  The HashedFirmware structure hased the
        # entire object including the FileSecurtity data.  But maybe we also want a hash
        # of just the file data (excluding the FileSecurity)?
        hasher = hashlib.sha256()
        hasher.update(self.data)
        self.datahash = hasher.hexdigest()

        if self.directory:
            self.parsed = MFSDirFile.parse(self.data, 0)
            #self.subparse(MFSDirFile, "data", 0, stop)
            if self.parsed is not None:
                for entry in self.parsed.entries:
                    if entry.fileno not in other_files:
                        # Fileno 0 is the partent of /home, presumably /
                        if entry.fileno != 0:
                            self.error(f"Fileno {entry.fileno} was not in the files dictionary!")
                        continue
                    entry_file = other_files[entry.fileno]
                    # Do not reprocess the current directory or our parent.
                    if entry.name == '.' or entry.name == '..':
                        continue
                    # First mark whether the file is secured or not.
                    if entry.mode_integrity:
                        entry_file.secured = True
                    if entry.mode_encryption:
                        entry_file.encrypted = True
                    if entry.mode_type_dir:
                        entry_file.directory = True
                    # Update the path on the file.
                    if isinstance(entry.name, str):
                        if self.path is None:
                            self.path = ""
                        new_path = self.path + '/' + entry.name
                    elif isinstance(entry.name, bytes):
                        if self.path is None:
                            self.path = ""
                        new_path = self.path + '/' + entry.name.decode('utf-8')

                    if entry_file.path is None or entry_file.path == new_path:
                        entry_file.path = new_path
                    else:
                        self.error(f"Fileno {entry.fileno} already had name '{entry_file.path}'")

                    # Then recursively process that file, even if it's an ordinary file,
                    # since that will cause the security data to get trimmed off.
                    entry_file.visit(other_files)
        elif self.fileno == 6:
            self.parsed = self.subparse(IntelCfg, "data", 0, stop)
        else:
            self.parsed = self.subparse(MysteryBytes, "data", 0, stop)
            if self.parsed is not None:
                self.parsed.label = "Data"

    def instance_name(self) -> str:
        if self.path is None:
            return ""
        return self.path

# ----------------------------------------------------------------------------------------
class MFSVolume(FirmwareStructure):

    label = "MFS Volume (Reconstructed)"

    definition = Struct(
        #"_magic" / Peek(Const(b'\x01\x62\x4f\x72')),
        "magic" / Int32ul,
        "version" / Int32ul,
        "capacity" / Int32ul,  # System area plus data area.
        "num_files" / Int16ul,
        # BUG! FIXME! This is really hacky. 45 is the number of data pages in MY ROM and
        # 122 is the number of chunks per data page.  Not sure why that's needed for this
        # array in the first place.
        "fat" / Array(lambda ctx: ctx['num_files'] + (45 * 122), Int16ul),
        "filler" / FixedLength(14, Class(HexDump)),
        "data" / GreedyBytes,
        #"data" / Class(HexDump),
    )

    _files: dict[int, MFSFATFile]

    reporting = [
        ["magic", "0x%x"], ["version"], ["capacity"], ["num_files"],
        ["data", None], ["fat", None], ["files", None], ["file_list"],
    ]

    sbom_fields = ["version", "file_list"]

    @property
    def file_list(self) -> list[MFSFATFile]:
        return list(self._files.values())

    def analyze(self) -> None:
        # The array of file object we're going to reconstructed from the raw data.  The
        # other local variables below will all eventually be saved here before this
        # analysis is completed.
        self._files = {}

        # ------------------------------------------------------------------------------
        # Phase 1: Assemble file data from chunks, set fileno, etc.
        # ------------------------------------------------------------------------------
        for fileno in range(self.num_files):
            ind = self.fat[fileno]
            if ind == 0 or ind == 0xFFFE:
                # FAT file entry does not exist or is not used
                continue
            # Empty files require no additional information beyond the the FAT entry.
            if ind == 0xFFFF:
                fatfile = MFSFATFile.parse(b'', 0)
                if fatfile is not None:
                    fatfile.set_fileno(fileno, 0, 0, [])
                    self._files[fileno] = fatfile
                continue

            # The data for this file.
            fdata = b''
            # A list of the chunks we've used for this file.
            used_chunks = []

            # Ind is the first chunk of the file. This code corresponds to slide 17 of
            # Skylarov's presentation.
            cnum = ind - self.num_files
            used_chunks.append(cnum)
            # In practice, the chunks composing the file were all adjacent in the first
            # MFS file system I examined, but it's clear that this is not strictly
            # required.  Therefore is not necessarily the case that all bytes between
            # min_offset and max_offset are part of the file.  When this is coincidentally
            # true however, these two numbers are helpful for understanding the data
            # structures involved.
            start_offset = cnum * 64
            if ind > len(self.fat) - 1:
                self.error(f"ME FAT index {ind} is invalid len={len(self.fat)}")
                continue
            ind = self.fat[ind]
            while ind > 64:
                # Append the previous complete chunk to the file data.
                fdata += self.data[cnum * 64:(cnum + 1) * 64]
                # Advance to the next chunk.
                cnum = ind - self.num_files
                used_chunks.append(cnum)
                if ind > len(self.fat) - 1:
                    self.error(f"ME FAT index {ind} is invalid len={len(self.fat)}")
                    break
                ind = self.fat[ind]
            # When ind <= 64, it indicates the length of the final chunk.
            end_offset = (cnum * 64) + ind
            fdata += self.data[cnum * 64:end_offset]

            fatfile = MFSFATFile.parse(fdata, 0)
            #fatfile = self.subparse(MFSFATFile, "data", cnum * 64, end_offset)
            if fatfile is not None:
                fatfile.set_fileno(fileno, start_offset, end_offset, used_chunks)
                self._files[fileno] = fatfile

        # ------------------------------------------------------------------------------
        # Phase 2: Visit files in filesystem order from root (recursively)
        # ------------------------------------------------------------------------------
        if 8 in self._files:
            # Apparently file #8 is hardcoded to be the /home root?
            self._files[8].path = "/home"
            self._files[8].directory = True
            self._files[8].secured = True
            # This will recursively visit each file in the filesystem.
            self._files[8].visit(self._files)

        # ------------------------------------------------------------------------------
        # Phase 3: A pass over the files in fileno order to ensure no file gets missed.
        # ------------------------------------------------------------------------------
        if 2 in self._files:
            self._files[2].secured = True
        if 3 in self._files:
            self._files[3].secured = True
        if 6 in self._files:
            self._files[6].path = "/intel.cfg"

        for fileno in self._files:
            if self._files[fileno].parsed is None:
                self._files[fileno].visit(self._files)

# ----------------------------------------------------------------------------------------
class MEFlashFilesystem(FirmwareStructure):
    """
    Intel Management Engine Flash Filesystem

    Designed to minimize erases and level wear across blocks.
    """

    label = "ME Flash Filesystem"

    definition = Struct(
        "_magic" / Peek(Const(b'\x87xU\xaa')),
        Check(lambda ctx: ctx['_magic'] is not None),
        "pages" / GreedyRange(Select(
            Class(MFSDataPage), Class(MFSSystemPage), Class(MFSEmptyPage),
        )),
    )

    reporting = [
        ['pages'],
    ]

    sbom_fields = ["reconstructed"]

    def analyze(self) -> None:
        # Make separate lists of the system and data pages.
        data_pages = []
        system_pages = []
        for page in self.pages:
            if isinstance(page, MFSDataPage):
                data_pages.append(page)
            elif isinstance(page, MFSSystemPage):
                system_pages.append(page)

        # Allocate a byte array big enough for all of the data pages.
        data_size = len(self.pages) * 122 * 64
        #self.debug("There were %d data pages" % len(data_pages))
        data = bytearray(b'\x00' * data_size)
        lowest_written = data_size

        # Assemble data pages into the image.
        for page in data_pages:
            for chunk_num in range(len(page.chunks)):
                offset = (page.header.first_chunk * 64) + (chunk_num * 64)
                if offset < lowest_written:
                    lowest_written = offset
                #self.debug("Installing bytes from first chunk %d chunk %d at: 0x%x" % (
                #    page.header.first_chunk, chunk_num, offset))
                for b in page.chunks[chunk_num].data:
                    data[offset] = b
                    offset += 1
        #self.debug("Lowest written offset was: 0x%x" % lowest_written)

        # For system pages it's important to process them in USN order.
        sorted_by_usn = sorted(system_pages, key=lambda o: o.header.usn)
        # Find the largest index that we've ever written to.
        #max_index = 0
        #for page in sorted_by_usn:
        #    for chunk_num in range(len(page.chunks)):
        #        chunk = page.chunks[chunk_num]
        #        if chunk.index is not None and chunk.index > max_index:
        #            max_index = chunk.index
        #sysarea = bytearray(b'\x00' * (max_index * 64))
        #self.debug("Sys area size was: 0x%x" % (max_index * 64))
        #highest_written = 0

        for page in sorted_by_usn:
            for chunk_num, chunk in enumerate(page.chunks):
                obindex = page.indexes[chunk_num]
                if obindex == 0x7fff:
                    break
                # The chunk index is expected to be None in the mildly unusual situation
                # where system_page.indexes[n] == 65535.  It appears that this happens
                # when portions of the system page a are unused because the USNs are small?
                if chunk.index is None:
                    continue
                index = chunk.index
                #fmt1 = "System page: usn=%4d index=%4d chunk_num=%4d "
                #fmt2 = fmt1 + "obindex=0x%04x crc=0x%4x data_crc=0x%04x"
                #lo(fmt2 % (page.header.usn, index, chunk_num,
                #             obindex, chunk.crc, chunk.data_crc))

                offset = index * 64
                #self.debug("Installing bytes from chunk %04d-0x%04x-%03d at: 0x%x" % (
                #    page.header.usn, index, chunk_num, offset))
                for b in page.chunks[chunk_num].data:
                    data[offset] = b
                    offset += 1

        # Write out the MFS area as a single image
        #fh = open('mfs.bin', 'wb')
        #fh.write(data)
        #fh.close()

        # Initialize the filesystem full path global variable (in case we parse more than
        # one MFSVolume in this execution).
        global mfs_full_path
        mfs_full_path = []
        # Now parse the filesystem.
        self.reconstructed = MFSVolume.parse(data, 0)

    def instance_name(self) -> str:
        return ""

# ----------------------------------------------------------------------------------------
class ManagementEngineRegion(FirmwareStructure):

    label = "Management Engine (ME) Region"

    definition = Struct(
        "_start" / Tell,
        #"_magic" / Const(b'\x20\x20\x80\x0F\x40\x00\x00\x24'),
        #"u1" / Int64ul,
        # Maybe not really a guid.  Unclear what's here...
        "_guid" / Bytes(16),
        "_magic2" / Const(b'$FPT'),
        "num_entries" / Int32ul,
        "version" / Int8ul,  # binary coded decimal
        "type" / Int8ul,
        "size" / Int8ul,
        "checksum" / Int8ul,
        "lifetime" / Int16ul,  # flash cycle lifetime
        "limit" / Int16ul,  # flash cycle limit
        "uma_size" / Int32ul,
        "flags" / Int32ul,
        "major_version" / Int16ul,
        "minor_version" / Int16ul,
        "hotfix_version" / Int16ul,
        "build_version" / Int16ul,
        "partitions" / Array(this.num_entries, Class(PartitionEntryHeader)),
        # The data for the partitions.
        # BUG?  Might be better to consume bytes to a 0x1000 multiple?
        "_data_start" / Tell,
        "_data" / GreedyBytes,
    )

    reporting = [
        ["guid"], ["num_entries"], ["size"], ["flags", "0x%x"], ["checksum"],
        ["version", "0x%x"],
        [], ["lifetime"], ["limit"], ["type"], ["uma_size"],
        ["major_version"], ["minor_version"], ["hotfix_version"], ["build_version"],
    ]

    sbom_fields = ["guid", "partitions"]

    @property
    def guid(self) -> UUID:
        return UUID(bytes_le=self._guid)

    def image_sections(self) -> list[tuple[int, int, str, bytes]]:
        sections: list[tuple[int, int, str, bytes]] = []
        for entry in self.partitions:
            if not isinstance(entry.body, (CPDManifestHeader, MEManifestPartition)):
                continue
            sections.extend(entry.body.image_sections())
        return sections

    @promote_exceptions
    def image(self) -> None:
        sections = self.image_sections()
        if len(sections) == 0:
            return
        min_addr = min(s[0] for s in sections)
        max_addr = max(s[1] for s in sections)

        # If the low address is near zero, just move it to zero to be tidy.
        if min_addr < 0x10000:
            min_addr = 0
        image_size = max_addr - min_addr

        #self.debug("ME Region Image size: 0x%x 0x%x 0x%x" % (min_addr, max_addr, image_size))
        image = bytearray(image_size)
        sorted_sections = sorted(sections, key=lambda x: x[0])
        for (start, end, section_name, section_image) in sorted_sections:
            rs = start - min_addr
            re = end - min_addr
            #self.debug("MER 0x%08x 0x%08x 0x%08x 0x%08x %s" % (start, end, rs, re, section_name))
            image[rs:re] = section_image

        #self.debug("Image len = 0x%x" % len(image))

        # FIXME!  This should not be here, but instead should be handled by the mostly
        # unimplemented dumping to disk capability.
        if False:
            iname = "intelme_0x%0x.bin" % (min_addr)
            fh = open(iname, 'wb')
            fh.write(image)
            fh.close()
            self.info("Wrote image to '%s'" % iname)

    def analyze(self) -> None:
        processed_offsets = {}
        # Link entry bodies into the entry headers so that they report in the desired order.
        for i in range(len(self.partitions)):
            header = self.partitions[i]
            # Partitions with size zero have no body.
            if header.size == 0:
                self.partitions[i].body = None
                continue

            # Partititions with an offset of negative one means what exactly?
            if header.offset == -1:
                self.partitions[i].body = None
                continue

            # Compute the start and end of the partition body in the data.
            start = header.offset - (self._data_start - self._start)
            end = start + header.size
            body = self._data[start:end]

            if body[0:4] == b'$CPD':
                if header.offset in processed_offsets:
                    header.body = "Duplicate of partition at offset 0x%x" % header.offset
                else:
                    header.body = self.subparse(CPDManifestHeader, "_data", start, end)
                    processed_offsets[header.offset] = True
            elif body[0:4] == b'\x87xU\xaa':
                header.body = self.subparse(MEFlashFilesystem, "_data", start, end)
            elif body[0:4] == b'\x04\x00\x00\x00':
                header.body = self.subparse(MEManifestPartition, "_data", start, end)
            else:
                header.body = self.subparse(MysteryBytes, "_data", start, end)

        # The code to write the modules out to disk is a HUGE mess.  I still haven't
        # really figured out how the modules are layed out in memory in Intel ME 11.
        if False:
            for header in self.partitions:
                if isinstance(header.body, CPDManifestHeader):
                    header.body.save_images()

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
