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
Support for Dell PFS volumes.
"""

import zlib
import logging
from typing import Optional
from enum import Flag

from construct import (
    Array, Bytes, Computed, Const, GreedyRange, Select, GreedyBytes, Switch, Peek, If,
    Int8ul, Int16ul, Int32ul, Int32sl, Int64ul, Check, this)

from .base import (
    FirmwareStructure, Class, FixedLength, LazyBind, UUID16, Struct, promote_exceptions,
    SafeFixedLength, PaddedString, Opt, Context, EnumAdapter)
from .uenum import UEnum
from .finder import FirmwareVolumeFinder
from .mystery import MysteryBytes, CommitMystery
from .me import ManagementEngineRegion
from .exes import PEExecutableSlack
from .bgscript import IntelBIOSGuardScript

log = logging.getLogger("cert-uefi-parser")

# ----------------------------------------------------------------------------------------
# Othe inspirational sources:
# https://github.com/platomav/BIOSUtilities/blob/master/Dell%20PFS%20BIOS%20Extractor/Dell_PFS_Extract.py
# https://github.com/LongSoft/PFSExtractor-RS by Nikolaj Schlej

# Other GUIDs that might be interesting in this file (somehow?)
# "INTEL_ME":         "7439ed9e-70d3-4b65-9e33-1963a7ad3c37",
# "BIOS_ROMS_1":      "08e56a30-62ed-41c6-9240-b7455ee653d7",
# "BIOS_ROMS_2":      "492261e4-0659-424c-82b6-73274389e7a7"

# ----------------------------------------------------------------------------------------
class TextFile(FirmwareStructure):

    label = "Text File"

    definition = Struct(
        "_data" / GreedyBytes,
    )

    def analyze(self) -> None:
        try:
            self.lines = []
            strdata = str(self._data.decode('utf8'))
            for line in strdata.split('\n'):
                if line != '':
                    self.lines.append(line + '\n')
        except UnicodeError:
            self.lines = self._data

    reporting = [["lines"]]

# ----------------------------------------------------------------------------------------
class TCGAttributesXML(TextFile):

    label = "Trusted Computing Group BIOS Attributes XML File"

# ----------------------------------------------------------------------------------------
# https://gist.github.com/skochinsky/181e6e338d90bb7f2693098dc43c6d54
# Currently unused, but watching for $PFH header?
class PFRegion(FirmwareStructure):

    definition = Struct(
        "offset" / Int32ul,
        "size" / Int32ul,
        "flash_address" / Int64ul,
        "name_offset" / Int32ul,
        "data" / FixedLength(this.size - 20, Class(MysteryBytes)),
    )

# ----------------------------------------------------------------------------------------
# https://gist.github.com/skochinsky/181e6e338d90bb7f2693098dc43c6d54
# Currently unused, but watching for $PFH header?
class PFHeader(FirmwareStructure):

    definition = Struct(
        "magic" / Const(b'$PFH'),
        "version" / Int32ul,
        "header_size" / Int32ul,
        "header_checksum" / Int16ul,
        "image_size" / Int32ul,
        "image_checksum" / Int16ul,
        "image_count" / Int32ul,
        "image_table_offset" / Int32ul,  # offset to image entries
        "num_images" / Int32ul,
        "unknown" / Array(48, Int32ul),
        "image_entries" / Array(this.image_count, Class(PFRegion)),
    )

# ----------------------------------------------------------------------------------------
@promote_exceptions
def lazy_pfs_partitioned_file(ctx: Context) -> Class:
    return Class(PFSPartitionedFile)

# ----------------------------------------------------------------------------------------
@promote_exceptions
def concatenate_sections(ctx: Context) -> Optional[FirmwareVolumeFinder]:
    data = b''
    for section in ctx.file.sections:
        data += section.data.data
    # It not clear to me that this technique is only used for volumes, nor what the
    # correct way is to determine whether the contents really are a volume.
    interpreted = FirmwareVolumeFinder.parse(data, 0)
    if interpreted is not None:
        interpreted.label = "PFS Partitioned File Interpretation (Firmware Volume Finder)"
    return interpreted

class PFSPartitionedSection(FirmwareStructure):
    """
    A PFS Paritioned Section.

    A PFS Partitioned Section is a type of PFS Section that appears to be a PFS File
    partitioned into PFS Sections which are individually signed.  The contents of these
    sections are not intelligible independently, but must instead be concatenated together
    to form the intended file.  Presumably, this is motivated by flash rom erase cycles,
    so that a portion of the file can be updated without invalidating the signatures.
    """

    label = "PFS Partitioned Section"

    definition = Struct(
        # The partitioned section is really just an ordinary "PFSFile" structure, with
        # it's own sections,  it's just that the data does
        "file" / LazyBind(lazy_pfs_partitioned_file),
        # Then concatenate the section data together and reinterpret the file.
        "reconstructed" / Computed(concatenate_sections),
    )

    #def analyze(self):
    #    # Relabel
    #    self.file.label = "PFS Partitioned File"
    #    for section in self.file.sections:
    #        section.label = "PFS Partitioned Chunk"

# ----------------------------------------------------------------------------------------
class VersionedObject(object):
    """
    A mixin class to add a version property to several PFS classes with complex versions.

    The class must define thr properties _version_types (an array of four 8-bit unsigned
    integers), and _version_values (an array of four 16-bit unsigned integers).
    """

    _version_types: list[int]
    _version_values: list[int]

    @property
    def version(self) -> str:
        #return repr((self._version_types, self._version_values))
        terms = []
        # The four components are sometimes labeled major, minor, hotfix and build.
        for n in range(4):
            if self._version_types[n] == ord('N'):
                terms.append('%d' % self._version_values[n])
            elif self._version_types[n] == ord('A'):
                terms.append('%s' % self._version_values[n])
            elif self._version_types[n] in (ord(' '), 0):
                pass
        return '.'.join(terms)

# ----------------------------------------------------------------------------------------
class PFSName(FirmwareStructure, VersionedObject):

    label = "PFS Name"

    definition = Struct(
        "hdr_version" / Int32ul,
        "guid" / UUID16,
        "_version_values" / Array(4, Int16ul),
        "_version_types" / Array(4, Int8ul),
        "_namelen" / Int16ul,
        # Dell_PFS_Extract.py says that leading and trailing spaces and nulls are
        # stripped.  Also common windows illegal filename characters are replaced.  We've
        # left the value as we found it here.
        "name" / PaddedString((this._namelen + 1) * 2, 'utf16'),
    )

    reporting = [
        ["guid"], ["name", '"%s"'], ["version"], ["hdr_version"],
    ]

    def instance_name(self) -> str:
        return f"{str(self.guid)} ({self.name})"

# ----------------------------------------------------------------------------------------
class PFSNameInfo(FirmwareStructure):

    label = "PFS Name Info"

    definition = Struct(
        "names" / GreedyRange(Class(PFSName)),
        # This class exists mostly for this hopefully unused MysteryBytes.
        "mystery" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
class PFSModelString(FirmwareStructure):

    label = "PFS Model String"

    definition = Struct(
        "_data" / GreedyBytes,
    )

    def analyze(self) -> None:
        try:
            # Remove trailing NULL and decode to a string.
            self.modelstr = str(self._data.decode('utf8'))[:-1]
        except UnicodeError:
            self.modelstr = self._data

# ----------------------------------------------------------------------------------------
@promote_exceptions
def lazy_volume(ctx: Context) -> Class:
    from .uefi import FirmwareVolume
    return Class(FirmwareVolume)

# ----------------------------------------------------------------------------------------
class BIOSGuardFlags(Flag):
    SFAM = 0x01       # Signed Flash Address Map
    ProtectEC = 0x02  # Protected EC Opcodes
    GFXSecDis = 0x04  # GFX Security Disable
    FTU = 0x08        # Fault Teloerance Update

# ----------------------------------------------------------------------------------------
class IntelBIOSGuardHeader(FirmwareStructure):

    label = "Intel BIOS Guard Header"

    definition = Struct(
        "bg_major_vers" / Const(2, Int16ul),
        "bg_minor_vers" / Int16ul,
        "platform_id" / PaddedString(16, 'utf8'),
        "_flags" / Int32ul,
        "flags" / Computed(lambda ctx: BIOSGuardFlags(ctx._flags)),
        "script_major_vers" / Int16ul,
        "script_minor_vers" / Int16ul,
        "script_size" / Int32ul,
        "data_size" / Int32ul,
        "bios_svn" / Int32ul,
        "ec_scv" / Int32ul,
        "vendor_info" / Int32ul,
        "script" / FixedLength(this.script_size, Class(IntelBIOSGuardScript)),
        # This data is usually _part_ of a reconstructed file.  It doesn't get displayed
        # here because we are supposed to consistently reassemble the file, and then
        # display the parsed interpretation of the resulting file.  See
        # PFSPartitionedSection and AMI_PFAT_Firmware.
        "data" / Bytes(this.data_size),
    )

    data_reminder: Optional[MysteryBytes]

    @property
    def bg_vers(self) -> str:
        return "%d.%d" % (self.bg_major_vers, self.bg_minor_vers)

    @property
    def script_vers(self) -> str:
        return "%d.%d" % (self.script_major_vers, self.script_minor_vers)

    reporting = [
        ["bg_vers"], ["script_vers"], ["bios_svn"], ["data_size"], ["ec_scv"],
        ["flags"], ["platform_id"], ["script_size"], ["vendor_info"],
        ["script"],
        ["bg_major_vers", None], ["bg_minor_vers", None],
        ["script_major_vers", None], ["script_minor_vers", None],
        # We don't display the raw data bytes, but we do display something to remind users
        # that there's data in each block.
        ["data", None],
        ["data_reminder"],
    ]

    def analyze(self) -> None:
        self.data_reminder = self.subparse(MysteryBytes, "data")
        if self.data_reminder is not None:
            self.data_reminder.label = "BIOS Guard Data Chunk"


# ----------------------------------------------------------------------------------------
class IntelBIOSGuardSignature(FirmwareStructure):

    label = "Intel BIOS Guard Signature"

    definition = Struct(
        "unk1" / Int32ul,
        "unk2" / Int32ul,
        "modulus" / Bytes(256),
        "exponent" / Int32ul,
        "signature" / Bytes(256),
    )

    reporting = [
        ["unk1"], ["unk2"], ["exponent"],
        ["modulus", None], ["signature", None],
    ]

# ----------------------------------------------------------------------------------------
class PFATBlockMetadata(FirmwareStructure):
    """
    Dell PFS BIOS Guard Metadata Structure
    """

    label = "PFAT Block Metadata"

    definition = Struct(
        "offset_top" / Int32ul,
        "unk1" / Int32ul,
        "offset_base" / Int32ul,
        "block_size" / Int32ul,
        "unk2" / Int32ul,
        "unk3" / Int32ul,
        "unk4" / Int8ul,
    )

    reporting = [
        ["offset_top", "0x%x"], ["offset_base", "0x%x"], ["block_size", "0x%x"],
        ["unk1"], ["unk2"], ["unk3"], ["unk4"],
    ]

# ----------------------------------------------------------------------------------------
class DellUIFile(FirmwareStructure, VersionedObject):
    """
    A wrapper around a PE executable with a couple of names and a version string.

    Reversed engineered.  No known authoratative source.
    """

    label = "Dell UI File"

    definition = Struct(
        "name1" / PaddedString(256, 'utf8'),
        "u1" / Int32ul,
        "name2" / PaddedString(256, 'utf8'),
        "_version_values" / Array(4, Int16ul),
        "_version_types" / Array(4, Int8ul),
        "u2" / Int32ul,
        "u3" / Int32ul,
        "u4" / Int32ul,
        "u5" / Int32ul,
        "size" / Int32ul,
        "u6" / Int32ul,
        "u7" / Int32ul,
        "u8" / Int32sl,
        # PEExecutableSlack consumes all remaining bytes.
        "exe" / FixedLength(this.size, Class(PEExecutableSlack)),
    )

    reporting = [
        ["name1"], ["name2"], ["version"], ["size"],
        [], ["u1"], ["u2"], ["u3"], ["u4"], ["u5"], ["u6"], ["u7", "0x%x"], ["u8"],
        [], ["exe"],
    ]

# ----------------------------------------------------------------------------------------
class DellUISection(FirmwareStructure):
    """
    The overall structure of the
    Reversed engineered.  No known authoratative source.
    """

    label = "Dell UI Section"

    definition = Struct(
        "_magic1" / Const(b'BIN.HDR.'),
        "unk1" / Int32ul,
        "size" / Int32ul,
        # DellUIFile consumes all remaining bytes.
        "files" / FixedLength(this.size, GreedyRange(Class(DellUIFile))),
        "size_check" / Int32ul,
        "unk2" / Int32ul,
        "_magic2" / Const(b'BIN.FTR.'),
        "extra" / Class(MysteryBytes),
    )

    reporting = [
        ["size"], ["size_check"], ["unk1"], ["unk2", "0x%x"],
    ]

# ----------------------------------------------------------------------------------------
@promote_exceptions
def lazy_dell_updater(ctx: Context) -> Class:
    from .vendor import DellUpdaterExecutable
    return Class(DellUpdaterExecutable)

# ----------------------------------------------------------------------------------------
class PFSSection(FirmwareStructure, VersionedObject):

    label = "PFS Section"

    definition = Struct(
        # This commit seems out of place given that we have not realiably matched any
        # "magic" yet, but the only place that PFS Sections are found is in PFS Files, and
        # once we've committed to the PFS file, we want to keep any partial section that
        # we find.
        "failure" / CommitMystery,
        "guid" / UUID16,
        "spec" / Int32ul,
        "_version_types" / Array(4, Int8ul),
        "_version_values" / Array(4, Int16ul),
        "reserved" / Int64ul,
        "size" / Int32ul,
        "rsa1_size" / Int32ul,
        "pmim_size" / Int32ul,
        "rsa2_size" / Int32ul,
        "eguid1" / UUID16,
        "eguid2" / If(this.spec == 2, UUID16),
        "data" / FixedLength(this.size, Switch(
            lambda ctx: str(ctx.guid), {
                "7ec6c2b0-3fe3-42a0-a316-22dd0517c1e8": Class(FirmwareVolumeFinder),
                # In the old code the Partitioned section was identified by peeking ahead for
                # the PFS.HDR. header bytes.  That might be a more robust approach.
                "f6baa1ac-39bc-4066-92f3-2471d1e7c5c6": Class(PFSPartitionedSection),
                # A sub-section in a PFSPartitionedSection.
                #"59b3e2f6-4e42-41f3-b1f4-446a84bfc6d0": GreedyBytes,

                # There's some confusuion about what this GUID signifies.
                "fd041960-0dc8-4b9f-8225-bba9e37c71e0": Select(
                    Class(PFSNameInfo), LazyBind(lazy_dell_updater), Class(MysteryBytes)),
                "4d583fd3-f80e-4055-a145-9bec16cb33b0": Class(PFSNameInfo),
                #"233ae3fb-da68-4fd4-92cb-a6229a611d6f": Class(HexDump),
                "233ae3fb-da68-4fd4-92cb-a6229a611d6f": Class(PFSModelString),
                "f4dd8e34-3011-40fe-a0b0-6d1fa21f2371": Class(TCGAttributesXML),
                "07dea4e5-c52d-4b43-a1b6-bddcadbe1d45": Class(ManagementEngineRegion),
                # BUG! Really just a FirmwareVolume, but there are cyclical import problems.
                "ea364cb4-0a76-4b38-998d-70f996c8a82e": Class(FirmwareVolumeFinder),
                "0f50ed61-b46e-47e5-8e2e-fb07a5fd531e": Class(FirmwareVolumeFinder),
                "7439ed9e-70d3-4b65-9e33-1963a7ad3c37": Class(ManagementEngineRegion),
                # Just exploring.
                #"36c385cc-ffe3-4492-915d-8704c93e841d": Class(HexDump),
                #"6abbca9e-a5f7-4592-aa66-c2f1fe4d5af3": Class(HexDump),
                "f2c3dc59-c8f6-4b51-9089-8a66d2ed1db6": Select(
                    Class(DellUISection), Class(PEExecutableSlack)),
                "ac9fda84-f456-4055-b13a-7f4360ae0f90": LazyBind(lazy_dell_updater),
            }, default=Class(MysteryBytes))),
        "sig1" / Bytes(this.rsa1_size),
        # In the context of a partitioned section, this variable was named trp_size.
        "pmim" / Bytes(this.pmim_size),
        "sig2" / Bytes(this.rsa2_size),
    )

    reporting = [
        ["guid"], ["size"], ["version"], ["spec"], ["reserved"],
        [], ["eguid1"], ["eguid2"], ["rsa1_size"], ["rsa2_size"], ["pmim_size"],
        ["sig1"],
        [], ["sig2"],
        [], ["pmim"],
    ]

# ----------------------------------------------------------------------------------------
class PFSPartitionedChunk(FirmwareStructure, VersionedObject):

    label = "PFS Partitioned Chunk"

    definition = Struct(
        "guid" / UUID16,
        "spec" / Int32ul,
        "_version_types" / Array(4, Int8ul),
        "_version_values" / Array(4, Int16ul),
        "reserved" / Int64ul,
        "size" / Int32ul,
        "rsa1_size" / Int32ul,
        "metadata_size" / Int32ul,
        "rsa2_size" / Int32ul,
        "eguid1" / UUID16,
        "eguid2" / If(this.spec == 2, UUID16),
        "data" / FixedLength(this.size, Class(IntelBIOSGuardHeader)),
        "sig1" / FixedLength(this.rsa1_size, Class(IntelBIOSGuardSignature)),
        "metadata" / FixedLength(this.metadata_size, Class(PFATBlockMetadata)),
        "sig2" / Bytes(this.rsa2_size),
        #"bios_guard" / ,
    )

    reporting = [
        ["guid"], ["size"], ["version"], ["spec"], ["reserved"],
        [], ["eguid1"], ["eguid2"], ["rsa1_size"], ["rsa2_size"], ["metadata_size"],
        ["sig2"], ["sig1"], ["metadata"],
    ]

# ----------------------------------------------------------------------------------------
@promote_exceptions
def verify_checksum(ctx: Context) -> int:
    # Footer checksums don't actually match via this code. :-(
    zchecksum = zlib.crc32(ctx._raw_data)
    # checksum = ctx.checksum
    # No complaining yet since it never matches...
    #if checksum != zchecksum:
    #    log.debug("Warning: Checksums don't match 0x%08x != 0x%08x" % (checksum, zchecksum))
    return zchecksum

# ----------------------------------------------------------------------------------------
@promote_exceptions
def pfs_file_definition(cls: type) -> Struct:
    return Struct(
        "_hdr_magic" / Const(b'PFS.HDR.'),
        "failure" / CommitMystery,
        "version" / Int32ul,  # 1 or 2
        "header_size" / Int32ul,
        # Read the data once as raw data (for checksumming)
        "_raw_data" / Peek(FixedLength(this.header_size, GreedyBytes)),
        # And then again as a structured list of sections...
        "sections" / SafeFixedLength(this.header_size, GreedyRange(Class(cls))),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
        "footer_size" / Int32ul,
        "checksum" / Int32ul,
        "_ftr_magic" / Const(b'PFS.FTR.'),
        "check" / Computed(verify_checksum),
    )

# ----------------------------------------------------------------------------------------
class PFSRegionType(UEnum):
    Firmware = 0xaa
    Utility = 0xbb
    Unknown = 0xee

# ----------------------------------------------------------------------------------------
class PFSFile(FirmwareStructure):

    label = "PFS File"

    definition = pfs_file_definition(PFSSection)

    reporting = [
        ["header_size", "0x%0x"], ["footer_size", "0x%0x"], ["version"],
        ["checksum", "0x%0x"], ["check", "0x%0x"],
        ["skipped", None], ["unexpected"],
    ]

    @property
    def unexpected(self) -> Optional[MysteryBytes]:
        mb = MysteryBytes.parse(self.skipped, 0)
        if mb is not None:
            mb.label = "PFS File Mystery Bytes"
        return mb

# ----------------------------------------------------------------------------------------
class PFSPartitionedFile(PFSFile):

    label = "PFS Partitioned File"

    definition = pfs_file_definition(PFSPartitionedChunk)

    reporting = [
        ["header_size"], ["footer_size"], ["version"],
        ["checksum", "0x%0x"], ["check", "0x%0x"],
        ["skipped", None], ["unexpected"],
    ]

    @property
    def unexpected(self) -> Optional[MysteryBytes]:
        mb = MysteryBytes.parse(self.skipped, 0)
        if mb is not None:
            mb.label = "PFS Partitioned File Mystery Bytes"
        return mb

# ----------------------------------------------------------------------------------------
class PFSHeader(FirmwareStructure):

    definition = Struct(
        "size" / Int32ul,
        #"_regtype" / Int8ul,
        #"regtype" / Computed(lambda ctx: safe_pfs_region_type(ctx._regtype)),
        "regtype" / EnumAdapter(Int8ul, PFSRegionType),
        "_magic" / Bytes(10),  # (b'\xee\xaa\x76\x1b\xec\xbb\x20\xf1\xe6\x51'),
        "magic" / Computed(lambda ctx: ctx._magic.hex()),
        "failure" / CommitMystery,
        "cksum" / Int8ul,
        "data" / Bytes(this.size + 2),
    )

    reporting = [["regtype"], ["data", None]]

# ----------------------------------------------------------------------------------------
class PFSFooter(FirmwareStructure):

    definition = Struct(
        "size" / Int16ul,
        #"_regtype" / Int8ul,
        #"regtype" / Computed(lambda ctx: safe_pfs_region_type(ctx._regtype)),
        "regtype" / EnumAdapter(Int8ul, PFSRegionType),
        #"magic" / Const(b'\xee\xaa\xee\x8f\x49\x1b\xe8\xae\x14\x37\x90'),
        "_magic" / Bytes(10),  # Const(b'\xee\xaa\xee\x8f\x49\x1b\xe8\xae\x14\x37\x90'),
        "magic" / Computed(lambda ctx: ctx._magic.hex()),
        "cksum" / Int8ul,
        # There's _not_ always this.size bytes after header. :-(
        #"data" / Opt(FixedLength(this.size, Class(HexDump))),
    )

# ----------------------------------------------------------------------------------------
def safe_zlib_decompress(ctx: Context) -> bytes:
    try:
        decompressed = zlib.decompress(ctx._data)
        return decompressed
    except zlib.error:
        return b''

# ----------------------------------------------------------------------------------------
class PFSRegion(FirmwareStructure):

    label = "PFS Region"

    definition = Struct(
        "size" / Int32ul,
        "_regtype" / Int8ul,
        "regtype" / Computed(lambda ctx: PFSRegionType(ctx._regtype)),
        "_magic" / Bytes(10),  # (b'\xee\xaa\x76\x1b\xec\xbb\x20\xf1\xe6\x51'),
        "magic" / Computed(lambda ctx: ctx._magic.hex()),
        "cksum" / Int8ul,
        "_data" / Bytes(this.size + 2),
        "_decomp" / Computed(safe_zlib_decompress),
        Check(lambda ctx: ctx._decomp[0:8] == b'PFS.HDR.'),

        "failure" / CommitMystery,
        # Not really optional, but if magic fails to match data gets lost. :-(
        "footer" / Opt(Class(PFSFooter)),
        # BUG! This is not really correct.  It's probably really alignment to 512/1024.
        # And this object is NOT constrained to a fixed size.
        "_pad" / GreedyRange(Const(b'\xff')),
        "padsize" / Computed(lambda ctx: len(ctx["_pad"])),
    )

    reporting = [
        ["size"], ["regtype"], ["magic"], ["cksum"], ["padsize"],
        ["interpretation"], ["footer"],
    ]

    def analyze(self) -> None:
        self.interpretation = PFSFile.parse(self._decomp, 0)

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
