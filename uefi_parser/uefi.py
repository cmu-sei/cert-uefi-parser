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
EFI and UEFI related structures.

This package defines firmware structures for unpacking, decompressing, extracting, and
rebuilding UEFI data.
"""

import logging
from enum import Flag
from uuid import UUID
from typing import Optional, Union

from construct import (
    Bytes, Computed, Const, GreedyRange, GreedyBytes, Aligned, If, IfThenElse, Pointer,
    Construct, Switch, Select, Sequence, RepeatUntil, Peek, Check, Seek, Tell,
    Int8ul, Int16ul, Int24ul, Int32ul, Int64ul, ExplicitError, ConstructError, this)

from uefi_support import DecompressionError

from .base import (
    FirmwareStructure, HashedFirmwareStructure, LazyBind, FixedLength, Class, Struct,
    SafeFixedLength, PaddedString, CString, OneOrMore, promote_exceptions, UUID16,
    FailPeek, Until, Opt, Context, EnumAdapter)
from .uenum import UEnum
from .exes import PEExecutable, TEExecutable, EFIApplication, WrappedTEExecutable
from .guiddb import GUID_DATABASE as GDB
from .dxedep import DXEDependency
from .compression import decompress, CompressionAlgorithm, sloppy_decompress
from .nvvars import guess_variable_type, ParallelsAuthenticatedVariableStore
from .vendor import BIOSExtensionROM, PNGImage, JPGImage, BMPImageV1, BMPImageV4
from .acpi import ACPITables, FirmwareIdentificationData
from .finder import FirmwareVolumeFinder
from .fit import FITable, FITablePlus
from .mystery import MysteryBytes, CommitMystery, HexDump
from .apple import IntelBIOSID, VideoBIOSTable, AppleIconFile
from .vendor import SignOnSection, DellRawSection1, AMITSESetupData
from .amd import AMDPlatformSecurityProcessor
from .bootguard import BootGuardFile, BootGuardRecord, AuthenticationCodeModule
from .smbios import SMBIOS
from .fsp import (
    FSPHeaderFile, FSPDescriptionFile, FSPTempRAMInit, FSPSiliconInit, FSPMemoryInit)
from .utils import purple

log = logging.getLogger("cert-uefi-parser")

# ----------------------------------------------------------------------------------------
# Platform Initialization Specification, Vol. 3, Table 3, page 529/1630, page 3-9
# Specification defines these as EFI_FV_FILETYPE_*
class FFSFileType(UEnum):
    Unknown = 0x00
    RawData = 0x01
    Freeform = 0x02  # Sectioned data
    SecurityCore = 0x03  # Platform core code used during the SEC phase
    PEICore = 0x04
    DXECore = 0x05
    PEIModule = 0x06  # (PEIM)
    DXEDriver = 0x07
    CombinedDriver = 0x08  # Combined PEIM/DXE driver
    Application = 0x09
    MM = 0x0a  # PE32+ image that will be loaded into MMRAM in MM Traditional Mode.
    FirmwareVolumeImage = 0x0b
    # PE32+ image that will be dispatched by the DXE Dispatcher and
    # will also be loaded into MMRAM in MM Tradition Mode.
    CombinedMMDXE = 0x0c
    MMCore = 0x0d
    MMStandalone = 0x0e
    MMCoreStandalone = 0x0f
    OEMMin = 0xc0
    OEMMax = 0xdf
    DebugMin = 0xe0
    DebugMax = 0xef
    FFSPad = 0xf0
    FFSMax = 0xff

# ----------------------------------------------------------------------------------------
@promote_exceptions
def lazy_safe_firmware_volume(ctx: Context) -> Class:
    return Class(SafeFirmwareVolume)

# ----------------------------------------------------------------------------------------
@promote_exceptions
def lazy_firmware_volume(ctx: Context) -> Class:
    return Class(FirmwareVolume)

# ----------------------------------------------------------------------------------------
# Platform Initialization Specification, Vol. 3, Table 4, page 536/1630, page 3-9
# Specification defines these as EFI_SECTION_*
class EFISection(UEnum):
    Compressed = 0x01
    GuidDefined = 0x02
    Disposable = 0x03
    PE32 = 0x10  # PE32+ Executable image
    PIC = 0x11  # Position-Independent Code
    Terse = 0x12  # Terse Executable image
    DxeDepex = 0x13  # DXE Dependency Expression
    Version = 0x14  # Version, Text and Numeric
    Name = 0x15  # User-Friendly name of the driver
    DOS = 0x16  # DOS-style 16-bit EXE
    Volume = 0x17  # PI Firmware Volume image
    SubtypeGuid = 0x18  # Raw data with GUID in header to define format
    Raw = 0x19
    PEIDepex = 0x1b
    MMDepex = 0x1c

# ----------------------------------------------------------------------------------------
class NVarAttributes(Flag):
    RuntimeVariable = 0x01
    AsciiName = 0x02
    LocalGuid = 0x04
    DataOnly = 0x08
    ExtendedHeader = 0x10
    HwErrRecord = 0x20
    AuthWrite = 0x40
    EntryValid = 0x80

# ----------------------------------------------------------------------------------------
# A couple of interesting links regarding NVRAM variables:
#   https://gist.github.com/jthuraisamy/e602d5d870230df3ce00178001f9ac16
#   https://github.com/perturbed-platypus
class NVRAMVariable(FirmwareStructure):

    label = "NVRAM Variable"

    definition = Struct(
        "_start" / Tell,
        "_magic" / Const(b'NVAR'),
        "total_size" / Int16ul,
        "reserved" / Bytes(3),
        "flags" / EnumAdapter(Int8ul, NVarAttributes),
        "_guid" / IfThenElse(this.flags & NVarAttributes.LocalGuid, Bytes(16), Int8ul),
        "name" / If(lambda ctx: ctx.flags & NVarAttributes.AsciiName, CString('ascii')),
        "_data_start" / Tell,
        "data_size" / Computed(this.total_size - (this._data_start - this._start)),

        "data" / SafeFixedLength(
            this.data_size,
            LazyBind(lambda ctx: guess_variable_type(ctx._.name, ctx._.data_size))),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    data: Union[bytes, Construct]

    reporting = [
        ["name", "'%s'", purple], ["total_size"], ["flags"], ["guid"], ["guid_alt"],
        ["reserved"],
        [], ["value"],
        ["data", None], ["data_size", None]
    ]

    @property
    def guid(self) -> Optional[UUID]:
        if isinstance(self._guid, bytes):
            return UUID(bytes_le=self._guid)
        else:
            return None

    @property
    def guid_alt(self) -> Optional[int]:
        if not isinstance(self._guid, bytes):
            assert isinstance(self._guid, int)
            return self._guid
        else:
            return None

    @property
    def value(self) -> Union[str, bytes, Construct]:
        if isinstance(self.data, bytes) and len(self.data) > 16:
            return "%r..." % self.data[:32]
        return self.data

# ----------------------------------------------------------------------------------------
class NVRAMVariableStore(FirmwareStructure):
    """
    A sequence of NVRAM variables.
    """

    definition = Struct(
        # Require that there be at least one variable so we can call this speculatively.
        "_magic" / Const(b'NVAR'),
        Seek(-4, 1),
        "variables" / OneOrMore(Class(NVRAMVariable)),
    )

# ----------------------------------------------------------------------------------------
class DellSection(FirmwareStructure):
    # Parsing of this structure is highly experimental.  The old code
    # did something, I was investigating enough to establish that it
    # could be thrown away.  This structure is far from understood.
    definition = Struct(
        "u1" / Int16ul,
        "u2" / Int16ul,
        "u3" / Int16ul,
        "u4" / Int16ul,
        "u5" / Int16ul,
        "u6" / Int16ul,
        "u7" / Int16ul,
        "u8" / Int16ul,
        "u9" / Int16ul,
        "u10" / Int16ul,
        # Could just as easily be u8==0x0, or u9==0x500...  Just guessing here..
        "extra1" / If(this.u7 == 0x203, Bytes(5)),
        #"name" / If(this.u7 == 0x204, CString('utf-16-le')),
        "name" / CString('utf-16-le'),
        "u11" / Int16ul,
        "u12" / Int16ul,
        "u13" / Int16ul,
        "u14" / Int16ul,
        "u15" / Int32ul,
        # Consume at extra "\n" / Int16ul in some cases?
        "extra1" / If(this.u11 == 0x806, Int16ul),
        "vers" / If(lambda ctx: ctx.u11 in [0x606, 0x806], CString('utf-16-le')),
        "moreextra" / If(lambda ctx: ctx.u11 in [0x806, 0xc06], Bytes(3)),
        "text" / If(this.u11 == 0x806, CString('utf-8')),
        #"eof" / If(lambda ctx: ctx.u11 in [0x606, 0x806], Const(b'\xff')),
        "eof" / Const(b'\xff'),
        "alignment" / GreedyRange(Const(b'\x00')),
    )

    reporting = [
        ["u1", "0x%0x"], ["u2", "0x%0x"], ["u3", "0x%0x"], ["u4", "0x%0x"],
        ["u5", "0x%0x"], ["u6", "0x%0x"], ["u7", "0x%0x"], ["u8", "0x%0x"],
        ["u9", "0x%0x"], ["u10", "0x%0x"], ["u11", "0x%0x"], ["u12", "0x%0x"],
        ["u13", "0x%0x"], ["u14", "0x%0x"], ["u15", "0x%0x"],
        [], ["name"],
    ]

# ----------------------------------------------------------------------------------------
class SubtypeGuidSection(FirmwareStructure):

    label = "Subtype GUID Section"

    definition = Struct(
        "guid" / UUID16,
        "data" / Switch(lambda ctx: str(ctx.guid), {
            "380b6b4f-1454-41f2-a6d3-61d1333e8cb4": Class(PEExecutable),
            "059ef06e-c652-4a45-9fbe-5975e369461c": Class(DellSection),
            "fe612b72-203c-47b1-8560-a66d946eb371": Class(AMITSESetupData),
            "ab56dc60-0057-11da-a8db-000102eee626": Class(SMBIOS),
            #"2ebe0275-6458-4af9-91ed-d3f4edb100aa": Class(HexDump),
            "2ebe0275-6458-4af9-91ed-d3f4edb100aa":
            Select(Class(SignOnSection),
                   Class(FirmwareIdentificationData),
                   Class(MysteryBytes)),
            "3fd1d3a2-99f7-420b-bc69-8bb1d492a332": Class(HexDump),
        }, default=Class(MysteryBytes)),
    )

# ----------------------------------------------------------------------------------------
class EfiCompression(UEnum):
    NOT_COMPRESSED = 0
    STANDARD = 1
    CUSTOM = 2
    FAILED = 9

# ----------------------------------------------------------------------------------------
class EfiCompressionHeader(FirmwareStructure):
    "Not working, nor used."

    label = "EFI Compression Header"

    definition = Struct(
        "unknown" / Bytes(4),
        "size" / Bytes(4),
        "data" / GreedyBytes,
    )

    reporting = [["size"], ["unknown"], ["data", None]]

# ----------------------------------------------------------------------------------------
class CompressedSection(FirmwareStructure):

    label = "Compressed Section"

    definition = Struct(
        "decompressed_size" / Int32ul,
        "compression_type" / EnumAdapter(Int8ul, EfiCompression),
        "_compressed_data" / GreedyBytes,
        "compressed_size" / Computed(lambda ctx: len(ctx._compressed_data)),
    )

    subsections: Union['Subsections', list[MysteryBytes]]
    decompressed_data: Optional[bytes]

    reporting = [
        ["compression_type"], ["algo"], ["compressed_size"], ["decompressed_size"],
        [], ["value"], ["decompressed_data", None], ["subsections", None]
    ]

    sbom_fields = ["subsections"]

    @property
    def value(self) -> Optional[Union['Subsections', list[MysteryBytes], bytes, str]]:
        if len(self.subsections) > 0:
            return self.subsections
        if isinstance(self.decompressed_data, bytes) and len(self.decompressed_data) > 16:
            return "%r..." % self.decompressed_data[:32]
        return self.decompressed_data

    def analyze(self) -> None:
        #log.debug("Decompressing %d bytes at 0x%x into %d bytes using type %s" % (
        #    self.compressed_size, self._data_offset, self.decompressed_size,
        #    self.compression_type))
        self.subsections: list[MysteryBytes] = []

        if self.compression_type == EfiCompression.NOT_COMPRESSED:
            self.decompressed_data = self._compressed_data
            self.algo = CompressionAlgorithm.NoCompression
        elif self.compression_type in [EfiCompression.STANDARD, EfiCompression.CUSTOM]:
            try:
                (self.decompressed_data, self.algo) = sloppy_decompress(self._compressed_data)
            except Exception:
                raise
                self.decompressed_data = None
                #self.decompressed_data = b''
                self.algo = EfiCompression.FAILED
                self.error("Decompression failed %d bytes at 0x%x into %d bytes using type %s" % (
                    self.compressed_size, self._data_offset, self.decompressed_size,
                    self.compression_type))
                mb = self.subparse(MysteryBytes, "_compressed_data")
                if mb is not None:
                    self.subsections = [mb]
                # Don't process subsections, because the decompressed data is invalid,
                # and there's insufficient magic in the section header.
                return
        else:
            self.error(f"Unrecognized compression type {self.compression_type}")

        if self.decompressed_data is None:
            return

        # Not all compressed sections have subsections, so this is kind of wrong.  On the
        # other hand, most(?) compressed sections do, and doing this here reports it in
        # the correct hierarchy.
        try:
            ss = Subsections.parse(self.decompressed_data, 0)
            if ss is not None and len(ss) != 0:
                self.subsections = ss
        except ExplicitError:
            raise
        except Exception as e:
            self.error("Compressed section at 0x%x failed: %s" % (self._data_offset, e))

        #log.debug("Decompression found %d subsections: %r" % (len(self.subsections), self.subsections))

        # If we didn't parse an structured subsections, at least report the decompressed
        # data as mystery bytes.
        if len(self.subsections) == 0:
            log.warn("no interpretation for compressed section at 0x%x" % (self._data_offset))
            mb = MysteryBytes.parse(self.decompressed_data, 0)
            if mb is not None:
                self.subsections = [mb]
        #self.debug("Decompressing %d bytes into %d bytes using type %s" % (
        #    self.compressed_size, self.decompressed_size, self.compression_type))

# ----------------------------------------------------------------------------------------
class LZMACompressedSection(FirmwareStructure):

    label = "LZMA Compressed Section"

    definition = Struct(
        "compressed_data" / GreedyBytes,
    )

    decompressed_data: Optional[bytes]
    decompressed_length: Optional[int]

    # These should probably be reported in the GUI now...
    reporting = [["compressed_data", None], ["decompressed_data", None]]

    def analyze(self) -> None:
        self.decompressed_data = None
        self.decompressed_length = None
        # Catch decompression errors and report them, but do not abort execution.
        try:
            self.decompressed_data = decompress(self.compressed_data, CompressionAlgorithm.LZMA)
            if self.decompressed_data is not None:
                self.decompressed_length = len(self.decompressed_data)
        except DecompressionError as e:
            self.error("decompression failure in LZMA compressed section")
            self.error(f"  {e}")

# ----------------------------------------------------------------------------------------
class GuidDefinedFlags(Flag):
    ProcessingRequired = 0x01
    AuthStatusValid = 0x02
    Bogus = 1 << 64

# FIXME: Is there a better/safer/more generic way to do this?
#def safe_guid_defined_flags(value):
#    try:
#        return GuidDefinedFlags(value)
#    except ValueError:
#        return GuidDefinedFlags.Bogus

# ----------------------------------------------------------------------------------------
class CRC32GuidedSection(FirmwareStructure):
    """
    A type of Guid Defined Section.

    Interpret EFI_CRC32_GUIDED_SECTION_EXTRACTION_GUID sections.  This a reverse
    engineered interpretation of the bytes.  It seems that there might be a formal
    definition somewhere in the EDK2, but it wasn't easily found, so I RE'd this from an
    Apple ROM instead.  Waiting for more examples to see what additional variation occurs.
    """

    label = "CRC32 Guided Section"

    definition = Struct(
        "crc32" / Int32ul,  # Maybe?
        "size" / Int16ul,
        "unk" / Int8ul,  # Usually zero, small integers or 0xFF.
        "type" / Int8ul,
        "data" / GreedyBytes,
    )

    parsed: Optional[FirmwareStructure]

    def analyze(self) -> None:
        # FIXME! This parsing should be done using Construct.  When I was first figuring
        # this out, this code was more convenient for "exploring", but probably not
        # anymore.

        # Extra header bytes?  Begins \x02 or \x06.  If \x06, the data is much shorter
        # than the \x02 case.  Perhaps first byte is type code?  Always ends with \x10?
        self.extra = b''
        if self.type == 0x17:
            self.parsed = self.subparse(FirmwareVolume, "data")
        elif self.type == 0x19:
            if self.data[:2] == b'BM':
                # The width and heights are strange on many of these, but they do look like
                # legit bitmaps to me.
                self.parsed = self.subparse(BMPImageV4, "data")
            elif self.data[:4] == b'$VBT':
                self.parsed = self.subparse(VideoBIOSTable, "data")
            elif self.data[:4] == b'\x89PNG':
                self.parsed = self.subparse(PNGImage, "data")
            elif self.data[:4] == b'icns':
                self.parsed = self.subparse(AppleIconFile, "data")
            else:
                #self.parsed = self.subparse(HexDump, "data", 0, 512)
                self.parsed = self.subparse(MysteryBytes, "data")
        elif self.type == 0x13:
            mslen = self.size + 3 - ((self.size - 1) % 4)
            self.extra = self.data[:mslen]
            self.parsed = self.subparse(PEExecutable, "data", mslen, 0)
        elif self.type == 0x10:
            self.parsed = self.subparse(PEExecutable, "data")
        else:
            self.parsed = self.subparse(MysteryBytes, "data")

    reporting = [
        ["type", "0x%x"], ["size", "0x%x"], ["crc32", "0x%x"], ["unk", "0x%x"], ["extra"],
        ["data", None], ["parsed"],
    ]

    sbom_fields = ["parsed"]

# ----------------------------------------------------------------------------------------
class GuidDefinedSection(FirmwareStructure):

    label = "GUID Defined Section"

    definition = Struct(
        "guid" / UUID16,
        "offset" / Int16ul,
        "_flags" / Int16ul,
        "flags" / Computed(lambda ctx: GuidDefinedFlags(ctx._flags)),
        "data" / Switch(lambda ctx: str(ctx.guid), {
            "ee4e5898-3914-4259-9d6e-dc7bd79403cf": Class(LZMACompressedSection),
            # "a31280ad-481e-41b6-95e8-127f4c984779": Class(TianoCompressedSection),
            # "24400798-3807-4a42-b413-a1ecee205dd8": Class(FirmwareVolume),
            # "367ae684-335d-4671-a16d-899dbfea6b88": Class(VolumeSection), # ???
            # There was some code about looking for volume sections in static?
            # "fc1bcdb0-7d31-49aa-936a-a4600d9dd083": None, # Static?
            "fc1bcdb0-7d31-49aa-936a-a4600d9dd083": Class(CRC32GuidedSection),
        }, default=Class(MysteryBytes)),
    )

    reporting = [
        ["guid"], ["offset", "0x%x"], ["flags"],
    ]

# ----------------------------------------------------------------------------------------
class VersionSection(FirmwareStructure):
    """
    A currently unused approach for the version section.

    The section is just a number and a string, which is currently returned as a tuple.
    """

    label = "Version Section"

    definition = Struct(
        "number" / Int16ul,
        "string" / CString("utf-16-le"),
    )

    sbom_fields = ["string"]

# ----------------------------------------------------------------------------------------
class GUIDStructure(FirmwareStructure):

    label = "GUID"

    definition = Struct(
        "guid" / UUID16,
    )

# ----------------------------------------------------------------------------------------
def complex_apriori_check(ctx: Context) -> bool:
    # FIXME: this is also a horrible hack.  The guid "usually" two levels up, but not
    # always, (e.g. compressed sections) and failure here causes other failures because of
    # the raise Python exception. :-(
    try:
        return str(ctx._._.guid) != "fc510ee7-ffdc-11d4-bd41-0080c73c8881"
    except AttributeError:
        return True

# ----------------------------------------------------------------------------------------
class AprioriGuidSection(FirmwareStructure):

    label = "Apriori GUIDs"

    definition = Struct(
        # FIXME: This is a super hacky way to cause a soft failure.  This section is NOT
        # an Apriori guid section unless the correct guid is found.  But using
        # construct.Error results in a much harder failure that I intended.
        "_type_check" / If(complex_apriori_check, Bytes(9999999)),
        "guids" / GreedyRange(Class(GUIDStructure)),
    )

# ----------------------------------------------------------------------------------------
class MysteryRawBytes(MysteryBytes):
    "Mystery bytes with an improved label to mark raw FFS section data."

    label = "Mystery Raw Section Bytes"

# ----------------------------------------------------------------------------------------
class FailGracefully(FirmwareStructure):
    label = "Graceful Fail"
    definition = Struct("const" / Const(b'MAGIC_THAT_WONT_BE_FOUND'))

# ----------------------------------------------------------------------------------------
@promote_exceptions
def freeform_guid_class(ctx: Context) -> Class:
    """
    Look up one level in the context to see if we have a guid property.  If we do, we
    could be a FreeformFile, and we'd like to switch on that GUID to determine how to
    parse the raw section.  Return the lazy-bound construct that parses the raw section
    identified by ctx._.guid.
    """
    if not hasattr(ctx._, "guid"):
        return Class(FailGracefully)
    guid = str(ctx._.guid)

    if guid == "b2cb10b1-714a-4e0c-9ed3-35688b2c99f0":
        from .apple import AppleFreeform1
        return Class(AppleFreeform1)
    elif guid in ("64ed8b7e-b1d0-4e9e-9d2a-696718cb8347",
                  "860bd9b5-eb36-429a-9cfb-6e2fd750f764"):
        from .apple import AppleFreeform2
        return Class(AppleFreeform2)
    elif guid == "b8e65062-fb30-4078-abd3-a94e09ca9de6":
        from .apple import AppleFreeform3
        return Class(AppleFreeform3)
    elif guid == "bf7f6f3a-5523-488e-8a60-f04863b975c3":
        from .apple import AppleFreeform4
        return Class(AppleFreeform4)
    elif guid == "a17b39ce-1916-4cfc-9581-7298a745f7a3":
        from .apple import AppleFreeform5
        return Class(AppleFreeform5)
    elif guid == "d357d673-4816-486c-9982-a8f6b7e0f569":
        from .apple import AppleFreeform6
        return Class(AppleFreeform6)
    elif guid == "7b249582-28ad-47d6-aeeb-a13d7c70e77f":
        from .apple import AppleFreeform7
        return Class(AppleFreeform7)
    elif guid in (
            "03583ff6-cb36-4940-947e-b9b39f4afaf7",
            "050a8608-63fa-4096-8cb7-791658e91ac5",
            "06f4c15c-dba1-43d4-a525-e8f5cc5cd6ee",
            "0e8028eb-7594-4eb3-b3c9-13adad2ea35a",
            "10f49a50-8f23-42e5-883b-735753e2ac45",
            "124021fc-ee78-45ec-887b-c9a479c8376f",
            "2f221c54-0d61-4741-8659-bc4ccafc87fe",
            "339370bd-cfc6-4454-8ef7-704653120818",
            "37a34ed8-7b10-4e8c-98d8-e582f0003727",
            "3c2507d7-6986-4597-8de2-e3a1ae39e757",
            "4898fec4-6dee-4235-b949-28bc535fb6ab",
            "4e6c7e95-8de2-437f-a773-c584a06661f8",
            "51871cb9-e25d-44b4-9699-0ee8644ced69",
            "693cb617-2f91-44d2-9f40-0747f77df3e6",
            "6a9586f3-a9d0-4ab4-9486-3b78c799aa10",
            "9707f7b9-2c0f-42ec-b847-d03c65de45dd",
            "9d8cf312-96ba-4493-88f3-95186eb0916e",
            "a1f432cc-60e8-4256-afff-97b7b50c5913",
            "a56b43bb-ba03-4b72-9c52-1d81545b17f0",
            "a7b52c18-6bfd-4593-995a-a3911801bdbb",
            "ab1aa515-00e1-4107-a453-19ed7fa4a6e4",
            "bc3906bd-7712-4197-bd2f-72b951c1c39c",
            "c5936db4-18f6-432a-a488-99a08adec6f0",
            "d1a04d55-75b9-41a3-9036-8f4a261cbba2",
            "d409cba9-1ba8-4f07-9703-d02dea45e0fc",
            "d4a4b482-d4c6-4b0f-97b3-5a3775d18cf3",
            "d68ac0dc-fa5e-4a30-800a-edc62e0ced2e",
            "e117644a-8a61-4532-ba14-505937b76a7b",
            "e6fd74ba-5d61-4050-ab75-5faf824969e1",
            "e7a99ecf-fd51-43a3-9fe4-865fdd4ac78a",
            "e81c2ef6-d353-43d8-afef-2e07832fbe93",
            "f282204d-d58a-4a82-b285-f775377be683",
            "f33528ca-8596-4ac1-bb74-6d9c1b323151",
            "fba385f4-c430-4c51-a70f-e3b54f9a5cf9"):
        from .apple import AppleFreeformGeneric
        return Class(AppleFreeformGeneric)

    return Class(FailGracefully)

# ----------------------------------------------------------------------------------------
class FirmwareFileSystemSection(FirmwareStructure):

    label = "FFS Section"

    definition = Struct(
        "_raw_size" / Int24ul,
        "type" / EnumAdapter(Int8ul, EFISection),
        # In FFSv3, if size is 0xFFFFFF, and additional 32-bit integer contains the size.
        "extra_size" / IfThenElse(
            this._raw_size == 0xFFFFFF, Int32ul, Computed(0)
        ),

        "size" / Computed(this._raw_size),
        #Probe(),

        #"debug" / Computed("FFS Section"),
        "_before" / Tell,
        Seek(0, 2),
        "_end_of_stream" / Tell,
        Seek(this._before, 0),
        #"after" / Tell,
        "_computed_size" / Computed(this._end_of_stream - this._before),
        #"_realsize" / Computed(lambda ctx: ctx.size - 4),
        "_realsize" / Computed(lambda ctx: min(ctx.size - 4, ctx._computed_size)),
        #Probe(),

        "data" / FixedLength(this._realsize, Switch(
            # Only a real lambda works here, not the "this" magic!
            lambda ctx: ctx.type, {
                EFISection.Compressed: Class(CompressedSection),
                EFISection.GuidDefined: Class(GuidDefinedSection),
                EFISection.PE32: Class(PEExecutable),
                EFISection.PIC: Class(PEExecutable),
                EFISection.Terse: Class(TEExecutable),
                EFISection.DxeDepex: Class(DXEDependency),
                EFISection.MMDepex: Class(DXEDependency),
                EFISection.PEIDepex: Class(DXEDependency),
                EFISection.Name: PaddedString(this._realsize, 'utf-16-le'),
                EFISection.Version: Sequence(Int16ul, CString('utf-16-le')),
                EFISection.SubtypeGuid: Class(SubtypeGuidSection),
                EFISection.Volume: LazyBind(lazy_safe_firmware_volume),
                EFISection.Raw: Select(
                    Class(PNGImage),
                    Class(JPGImage),
                    Class(BMPImageV1),
                    Class(EFIApplication),
                    Class(PEExecutable),
                    Class(TEExecutable),
                    Class(NVRAMVariableStore),
                    ACPITables,
                    Class(AprioriGuidSection),
                    Class(BIOSExtensionROM),
                    Class(IntelBIOSID),
                    Class(DellRawSection1),
                    LazyBind(freeform_guid_class),
                    Class(MysteryRawBytes),
                ),
            }, default=Class(MysteryBytes))),

        "_final" / Tell,
        "_pad_remainder" / Computed(lambda ctx: ctx._realsize + 3 - ((ctx._realsize - 1) % 4)),
        "_padsize" / Computed(lambda ctx: min(ctx._pad_remainder - ctx._realsize,
                                              ctx._end_of_stream - ctx._final)),
        #Probe(),
        "padding" / Bytes(this._padsize),
        #Probe(),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    data: list[FirmwareStructure]

    reporting = [
        ["data", None],
    ]

    sbom_fields = ["data"]

    @property
    def value(self) -> Union[str, bytes, list[FirmwareStructure]]:
        if isinstance(self.data, bytes) and len(self.data) > 16:
            return "%r..." % self.data[:32]
        return self.data

    def sbom(self) -> dict[str, Union[FirmwareStructure, list[FirmwareStructure]]]:
        """
        The name and version sections are more like fields on the file.  Let's reduce the
        complexity of the resulting JSON.
        """
        if self.type == EFISection.Name:
            return {"name": self.data}
        elif self.type == EFISection.Version:
            return {"version": self.data[1]}
        else:
            return super().sbom()

    def analyze(self) -> None:
        # BUG! This should be implemented, but it's a bit tricky.
        # if self.name is not None:
        #     GDB.add_dynamic_name(self.guid, self.name)
        pass

    def class_name(self) -> str:
        return "%s (%s)" % (self.label, self.type.name)

# ----------------------------------------------------------------------------------------
def interpret_volume(ctx: Context) -> Optional[FirmwareVolumeFinder]:
    #log.debug("Intrepreting volume %r" % ctx)
    for section in ctx.sections:
        if isinstance(section.data, GuidDefinedSection):
            #log.debug("Found GUIDDefinedSection %r" % section.data.data.decompressed_data)
            try:
                data = section.data.data.decompressed_data
                return FirmwareVolumeFinder.parse(data, 0)
            except ExplicitError:
                raise
            except ConstructError:
                return None
    return None

# ----------------------------------------------------------------------------------------
class FFSVolumeFile(FirmwareStructure):

    label = "Firmware Volume File"

    definition = Struct(
        "sections" / OneOrMore(Class(FirmwareFileSystemSection)),
        "volume" / Computed(interpret_volume),
    )

    reporting = [["sections"], ["volume"]]

    def instance_name(self) -> str:
        return ""

# ----------------------------------------------------------------------------------------
def compressed_section_list(ctx: Context) -> list[FirmwareStructure]:
    #log.debug("got here!")
    #log.debug("got here! ctx=%r" % ctx)
    #log.debug("got here! sections=%r" % ctx.sections)
    #log.debug("got here! section[0]=%r" % ctx.sections[0])
    #section = ctx.sections[0]
    #log.debug("got here! dir(section)=%r" % dir(section))
    cons = GreedyRange(Class(FirmwareFileSystemSection))
    result = cons.parse(ctx.sections[0].decompressed_data)
    assert isinstance(result, list)
    return result

# ----------------------------------------------------------------------------------------
class FreeformFile(FirmwareStructure):

    label = "Freeform File"

    definition = Struct(
        # FIXME: Guid needs to be moved from parent so that FirmwareFileSystemSection can
        # find it where it's expected.
        "guid" / Computed(lambda ctx: ctx._.guid),
        "sections" / GreedyRange(Class(FirmwareFileSystemSection)),
        # FIXME: This "interpretation" field is just return a "type" for the SBOM.
        # Should we keep this or remove it?
        "interpretation" / Switch(
            lambda ctx: str(ctx._.guid), {
                # FIXME: Incomplete...
                #"22046d50-f390-498c-92e5-5ba4f8e7f8b6": Computed(compressed_section_list),
                "22046d50-f390-498c-92e5-5ba4f8e7f8b6": Computed("SSDT"),
                "c118f50d-391d-45f4-b3d3-11bc931aa56d": Computed("DSDT"),
                "a54c760e-415d-4157-a74a-f74941873f65": Computed("SSDT"),
                "6684d675-ee06-49b2-876f-79c58fdda5b7": Computed("SSDT"),
                "8de8964f-2939-4b49-a348-f6b2b2de4a42": Computed("SSDT"),
                "e3164526-690a-4e0d-b028-aea16fe2bcf3": Computed("SSDT"),
                "709e6472-1bcd-43bd-8b6b-cd2d6d08b967": Computed("FIDT"),
                #"a59a0056-3341-44b5-9c9c-6d76f7673817": Computed("SignOn"),
            }, default=Class(MysteryBytes)),
    )

    reporting = [["guid"], ["sections"]]

    sbom_fields = ["guid", "interpretation", "sections"]

# ----------------------------------------------------------------------------------------
@promote_exceptions
def verify_checksum(ctx: Context) -> int:
    # Checksums don't actually match via this code. :-(
    assert isinstance(ctx.checksum, int)
    checksum = ctx.checksum
    zchecksum = checksum
    #from .utils import csum16
    #zchecksum = csum16(ctx._raw_data)
    # No complaining yet since it never matches...
    if checksum != zchecksum:
        log.warn("checksums don't match 0x%04x != 0x%04x" % (checksum, zchecksum))
    return zchecksum

# ----------------------------------------------------------------------------------------
class FirmwareFileSystemFile(HashedFirmwareStructure):

    label = "FFS File"

    definition = Struct(
        "guid" / UUID16,
        #"index" / Computed(lambda ctx: dir(ctx)),
        "checksum" / Int16ul,
        "type" / EnumAdapter(Int8ul, FFSFileType),
        "flags" / Int8ul,
        "size" / Int24ul,  # Size includes header
        "state" / Int8ul,
        #Probe(),
        "_raw_data" / Peek(FixedLength(this.size - 24, GreedyBytes)),
        "data" / FixedLength(this.size - 24, Switch(
            this.type, {
                FFSFileType.RawData: Select(
                    Class(BootGuardFile),
                    Class(NVRAMVariableStore),
                    Class(ParallelsAuthenticatedVariableStore),
                    Class(FITablePlus),
                    Class(VideoBIOSTable),
                    Class(AuthenticationCodeModule),  # Weak magic.
                    Class(FSPHeaderFile),
                    Class(FSPDescriptionFile),
                    Class(FSPTempRAMInit),
                    Class(FSPMemoryInit),
                    Class(FSPSiliconInit),
                    Class(FirmwareVolumeFinder),
                    Class(MysteryBytes),
                ),
                #FFSFileType.Freeform: GreedyRange(Class(FirmwareFileSystemSection)),
                FFSFileType.Freeform: Class(FreeformFile),
                FFSFileType.PEICore: Select(
                    Class(WrappedTEExecutable), Class(MysteryBytes)),
                FFSFileType.DXECore: OneOrMore(Class(FirmwareFileSystemSection)),
                FFSFileType.PEIModule: OneOrMore(Class(FirmwareFileSystemSection)),
                FFSFileType.DXEDriver: OneOrMore(Class(FirmwareFileSystemSection)),
                #FFSFileType.CombinedDriver
                FFSFileType.Application: OneOrMore(Class(FirmwareFileSystemSection)),
                FFSFileType.MM: OneOrMore(Class(FirmwareFileSystemSection)),
                FFSFileType.FirmwareVolumeImage: Class(FFSVolumeFile),
                FFSFileType.CombinedMMDXE: OneOrMore(Class(FirmwareFileSystemSection)),
                FFSFileType.MMCore: OneOrMore(Class(FirmwareFileSystemSection)),
                #FFSFileType.MMCore = 0x0d
                #FFSFileType.MMStandalone = 0x0e
                #FFSFileType.MMCoreStandalone = 0x0f
                #FFSFileType.OEMMin = 0xc0
                #FFSFileType.OEMMax = 0xdf
                #FFSFileType.DebugMin = 0xe0
                #FFSFileType.DebugMax = 0xef
                FFSFileType.FFSPad: Select(
                    Class(BootGuardFile),
                    Class(MysteryBytes),
                ),
                #FFSFileType.FFSPad = 0xf0
                #FFSFileType.FFSMax = 0xff
            }, default=Class(MysteryBytes))),
        # This is the leftover bytes from the SafeFixedLength.
        #"skipped" / Computed(this.extra),
        "check" / Computed(verify_checksum),
        #Probe(),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    data: Construct

    reporting = [
        ["guid"],
        #["index"],
        ["type"], ["size"], ["state"], ["flags"], ["checksum"], ["check"],
        [], ["fshash"],
        [], ["data", None], ["value"],
    ]

    sbom_fields = ["guid", "hash", "data"]

    @property
    def value(self) -> Union[str, bytes, Construct]:
        if isinstance(self.data, bytes) and len(self.data) > 16:
            return "%r..." % self.data[:32]
        return self.data

    def class_name(self) -> str:
        return "%s (%s)" % (self.label, self.type.name)

# ----------------------------------------------------------------------------------------
LENOVO_DATE_TIME_VERSION_GUID = UUID('e5b3315b-14f2-42b3-9c48-19bddc328247')
class LenovoDateTimeVersion(FirmwareStructure):

    label = "Lenovo Date Time Version"

    definition = Struct(
        "_magic_guid" / FailPeek(Const(LENOVO_DATE_TIME_VERSION_GUID.bytes_le)),
        "failure" / CommitMystery,

        "guid" / UUID16,
        # Really a 16-byte, null terminated, 0xff padded string.
        "date" / CString('utf8'),
        "_ff_padding1" / GreedyRange(Const(b'\xff')),
        "ffpad1" / Computed(lambda ctx: len(ctx._ff_padding1)),
        # Really a 16-byte, null terminated, 0xff padded string.
        "time" / CString('utf8'),
        "_ff_padding2" / GreedyRange(Const(b'\xff')),
        "ffpad2" / Computed(lambda ctx: len(ctx._ff_padding2)),
        # Really a 44-byte, null terminated, 0xff padded string.
        "version" / CString('utf8'),
        "_ff_padding3" / GreedyRange(Const(b'\xff')),
        "ffpad3" / Computed(lambda ctx: len(ctx._ff_padding3)),
        # Usually zero.
        "u1" / Int32ul,
        "_ff_padding4" / GreedyRange(Const(b'\xff')),
        "ffpad4" / Computed(lambda ctx: len(ctx._ff_padding4)),
    )

    reporting = [
        ["guid"], ["date"], ["time"], ["version"], ["u1", "0x%x"],
        ["ffpad1"], ["ffpad2"], ["ffpad3"], ["ffpad4"],
    ]

# ----------------------------------------------------------------------------------------
LENOVO_UPDATER_GUID = UUID('c8ab0f4e-26fe-40f1-9579-ea8d30d503a4')
class HackyLenovoUpdater(FirmwareStructure):

    label = "Lenovo Updater File"

    definition = Struct(
        "_magic_guid" / FailPeek(Const(LENOVO_UPDATER_GUID.bytes_le)),
        "failure" / CommitMystery,
        "file" / Class(FirmwareFileSystemFile),
    )

# ----------------------------------------------------------------------------------------
class InsydeML0W(FirmwareStructure):

    label = "Insyde ML0W"

    definition = Struct(
        "_magic" / FailPeek(Sequence(Bytes(80), Const(b'$ML0W.'))),
        "data" / Until(b'\xff' * 16, Class(MysteryBytes)),
    )

    reporting = [
        ["magic"], ["version"], ["data"],
    ]

    def analyze(self) -> None:
        rawdata = self.data.data
        self.magic = rawdata[80:92]
        self.version = rawdata[96:111]

# ----------------------------------------------------------------------------------------
class InsydeGAID(FirmwareStructure):
    """
    A very poorly defined matcher for an unknown data structure that looks like an index
    of magic values.  Often followed by a "Special Memory Block" containing a single 0x95
    byte.
    """

    label = "Insyde GAID"

    definition = Struct(
        "_magic" / FailPeek(Sequence(Bytes(214), Const(b'GAID'))),
        "data" / Until(b'\xff' * 16, Class(MysteryBytes)),
    )

# ----------------------------------------------------------------------------------------
class UnknownDADCBD(FirmwareStructure):
    """
    A completely unidentified but fairly common pattern in special memory blocks.
    """

    label = "Unknown DADCBD"

    definition = Struct(
        "_magic" / FailPeek(Sequence(Bytes(256), Const(b'x\xda\xdc\xbd\r|T'))),
        "data" / Until(b'\xff' * 16, Class(MysteryBytes)),
    )

# ----------------------------------------------------------------------------------------
class Unknown804C14(FirmwareStructure):
    """
    A completely unidentified but fairly common pattern in special memory blocks.
    """

    label = "Unknown 804C14"

    definition = Struct(
        "_pre_ff_padding" / GreedyRange(Const(b'\xff' * 1024)),
        "pre_ff_padding" / Computed(lambda ctx: len(ctx._pre_ff_padding) * 1024),
        "_magic" / FailPeek(Sequence(Bytes(1024), Const(b'\x80\x4c\x14\x00\x70\xc0'))),
        "data" / Until(b'\xff' * 16, Class(MysteryBytes)),
    )

# ----------------------------------------------------------------------------------------
class Unknown102111(FirmwareStructure):
    """
    A completely unidentified but fairly common pattern in special memory blocks.
    """

    label = "Unknown 102111"

    definition = Struct(
        "_magic" / FailPeek(Const(b'\x10\x21\x11\x00\x12')),
        "data" / Until(b'\xff' * 16, Class(MysteryBytes)),
    )

# ----------------------------------------------------------------------------------------
class SingleByteBlock(FirmwareStructure):
    """
    A few blocks contain a single non-FF byte.  I'm not sure what this is, but it's common
    enough to warrant a pattern to detect it.
    """

    label = "Single Byte Block"

    definition = Struct(
        # Consume any single byte.
        "single_byte" / Int8ul,
        # But not 0xff...
        Check(lambda ctx: ctx.single_byte != 0xff),
        # And if the next 1023 bytes are all FF's we're a SingleByteBlock.  But don't
        # actually consume the padding, since we want the SpecialMemoryBlock to do that
        # for consistency.
        FailPeek(Const(b'\xff' * 1023)),
    )

# ----------------------------------------------------------------------------------------
class HackyMysterySkip(FirmwareStructure):

    label = "Hacky Mystery Skip"

    definition = Struct(
        #"_peek" / Peek(Int8ul),
        #Check(lambda ctx: ctx._peek != 0xff),
        "data" / Until(b'\xff' * 16, Class(MysteryBytes)),
        #"preview" / FixedLength(96, Class(HexDump)),
        #"data" / FixedLength(1024-96, Class(MysteryBytes)),
        #"preview"  / Computed(b''),
        #"data" / FixedLength(1024, Class(HexDump)),
    )

    reporting = [
        #["preview"],
        ["data"],
    ]

# ----------------------------------------------------------------------------------------
class SpecialMemoryBlock(FirmwareStructure):
    """
    Represents one "block" of the Special Firmware File.  It's equally likely I suppose
    that the layout is literally just specific structures at specific offsets (e.g. a blob
    of memory), but this approach of consuming an arbitrary object and them some 0xFF
    bytes, and then another object should make the parser more resilient, and easily
    extensible.
    """

    label = "Special Memory Block"

    definition = Struct(
        # Consuming pre-padding breaks the AMD PSP parser, which looks at specific offsets
        # (e.g. 0x20000), but it also begins with 0x10000 bytes of FFs.  Since only the
        # first block can have "pre-padding", and there's only once case where it was
        # needed, I move the padding consumption to Unknown804C14.
        #"_pre_ff_padding" / GreedyRange(Const(b'\xff'*1024)),
        #"pre_ff_padding" / Computed(lambda ctx: len(ctx._pre_ff_padding)*1024),
        "data" / Select(
            Class(BootGuardRecord),
            Class(FITable),
            Class(LenovoDateTimeVersion),
            #Class(AMDPSPFake),
            Class(AMDPlatformSecurityProcessor),
            LazyBind(lazy_firmware_volume),
            Class(HackyLenovoUpdater),
            Class(InsydeML0W),
            Class(InsydeGAID),
            Class(UnknownDADCBD),
            Class(Unknown804C14),
            Class(Unknown102111),
            Class(SingleByteBlock),
            Class(HackyMysterySkip),
        ),
        "_post_ff_padding" / GreedyRange(Const(b'\xff')),
        "post_ff_padding" / Computed(lambda ctx: len(ctx._post_ff_padding)),
    )

    reporting = [["post_ff_padding"]]

# ----------------------------------------------------------------------------------------
class SpecialFileContents(FirmwareStructure):
    """

    """

    label = "Special File Contents"

    definition = Struct(
        "data" / GreedyRange(Class(SpecialMemoryBlock)),
        "file" / Opt(Class(FirmwareFileSystemFile)),
        #"hex" / Opt(FixedLength(4096*60, Class(HexDump))),
        "remaining" / Select(LazyBind(lazy_firmware_volume), Class(MysteryBytes)),
    )

    reporting = [
        ["data"],
        ["file"],
        #["hex"],
        ["remaining"],
    ]

    def analyze(self) -> None:
        self.remaining.label = "Special File Firmware Volume Finder"

# ----------------------------------------------------------------------------------------
class VSSThing(FirmwareStructure):
    """
    An unknown data blob where a file should be.  Seen in hp-spectre-spi-flash.bin.
    """

    label = "$VSS Thing"

    definition = Struct(
        "magic" / Const(b"$VSS"),
        "data" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
SPECIAL_FILE_GUID = UUID('6c60ee00-c316-4c95-a684-cdc7e7033311')
class SpecialFirmwareFile(FirmwareStructure):
    """
    An special firmware file with a non-standard layout.

    It's unclear if this magic GUID is the marker, or whether this is really a property of
    files in that have a size=0 and/or flags=1.  I've chosen to look for this specific
    GUID for right now because it's a narrower constraint than the size of flags.  If some
    other strange files show up, we can evaluate them once we've seen them.
    """

    label = "Special Firmware File"

    definition = Struct(
        # Peek for our magic GUID.  Fail if not found, and immediately commit to this
        # structure if it is.
        "_magic_guid" / FailPeek(Const(SPECIAL_FILE_GUID.bytes_le)),
        "failure" / CommitMystery,

        # Reread the guid as an object this time.  These fields are a duplicate of the
        # normal Firmware File System File structure.
        "guid" / UUID16,
        "checksum" / Int16ul,
        "type" / EnumAdapter(Int8ul, FFSFileType),
        "flags" / Int8ul,
        "size" / Int24ul,  # Size includes header
        "state" / Int8ul,
        #"parsed" / Class(SpecialFileContents),
        # This appears to be the file size.
        "u1" / Int32ul,
        # The next dword is typically either zero or all FFs.  If it's all FFs, it's part
        # of the padding between special blocks, but if it's not it needs to be consumed
        # for the alignment of the AMD PSP section to be correct.
        "_u2" / Peek(Int32ul),
        "u2" / If(this._u2 != 0xffffffff, Int32ul),
        "rawdata" / GreedyBytes,
    )

    reporting = [
        ["guid"], ["type"], ["size"], ["state"], ["flags"], ["checksum"], ["u1"], ["u2"],
        ["rawdata", None], ["parsed"],
    ]

    def analyze(self) -> None:
        # Specifically broken out as a separate parser so that offsets are relative to
        # this position to make debugging a little easier.
        self.parsed = SpecialFileContents.parse(self.rawdata, 0)

# ----------------------------------------------------------------------------------------
class FirmwareFileSystem(FirmwareStructure):

    label = "Firmware File System"

    definition = Struct(
        "files" / GreedyRange(Aligned(8, Select(
            Class(SpecialFirmwareFile), Class(VSSThing), Class(FirmwareFileSystemFile)))),
        "padding" / Class(MysteryBytes),
    )

    sbom_fields = ["files"]

# ----------------------------------------------------------------------------------------
class FirmwareBlock(FirmwareStructure):

    label = "FFS Block"

    definition = Struct(
        "count" / Int32ul,
        "size" / Int32ul,
    )

    def __str__(self) -> str:
        return "FirmwareBlock(%d, %d)" % (self.count, self.size)

# ----------------------------------------------------------------------------------------
class FirmwareVolumeExtraHeader(FirmwareStructure):

    label = "FFS Volume Extra Header"

    definition = Struct(
        "name" / UUID16,
        "size" / Int32ul,
    )

    reporting = [["name"], ["size", None]]

    def __str__(self) -> str:
        return "FirmwareVolumeExtraHeader(%s, %d)" % (self.name, self.size)

# ----------------------------------------------------------------------------------------
class FirmwareVolume(FirmwareStructure):

    label = "FFS Volume"

    definition = Struct(
        "_start" / Tell,
        "_ff_padding1" / GreedyRange(Const(b'\xff' * 64)),
        "ff_padding1_len" / Computed(lambda ctx: len(ctx._ff_padding1)),
        #"_zeros" / Const(b'\x00' * 16),
        "zeros" / UUID16,
        "guid" / UUID16,  # also semi-magical?
        "size" / Int64ul,
        "_magic" / Const(b'_FVH'),
        "failure" / CommitMystery,
        #"magic" / Bytes(4),
        "flags" / Int32ul,
        "header_size" / Int16ul,
        "checksum" / Int16ul,
        "extra_header_offset" / Int16ul,
        "reserved" / Int8ul,
        "revision" / Int8ul,
        # A sequence of FirmwareBlocks terminated by a (0, 0) block.
        "block_map" / RepeatUntil(
            lambda x, lst, ctx: x.size == 0 and x.count == 0,
            Class(FirmwareBlock),
        ),
        #Probe(),
        # The current offset from Tell should match the extra header offset?
        #"tell_check" / Tell,
        "extra_header" / If(
            this.extra_header_offset != 0,
            Pointer(this._start + this.extra_header_offset,
                    Class(FirmwareVolumeExtraHeader))),
        # FIXME: Assume one filesystem in one set of volume blocks!
        # Almost certainly wrong, but correct answer is fairly cryptic.
        "filesystem" / SafeFixedLength(
            # The 48 is the size of the VolumeHeader?
            lambda ctx: (ctx.block_map[0].count * ctx.block_map[0].size) - 72,
            Class(FirmwareFileSystem)),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),

        # FIXME: This is probably wrong...  Sometimes there seems to be a "page" of 64k
        # 0xff bytes in the stream.  I don't know what really determines the correct size,
        # so I've consumed those bytes here is block of 64 bytes.  That sort of includes
        # presumptions about alignment and padding but it seems to work so far.
        "_ff_padding2" / GreedyRange(Const(b'\xff' * 64)),
        "ff_padding2_len" / Computed(lambda ctx: len(ctx._ff_padding2)),
        #Probe(),
    )

    reporting = [
        ["size", "0x%x"], ["flags", "0x%x"], ["revision"], ["checksum", "0x%x"], ["header_size"],
        ["extra_header_offset"], ["reserved"], ["skipped"],
        [], ["guid"], ["zeros"],
    ]

    sbom_fields = ["filesystem"]

    def instance_name(self) -> str:
        return GDB.display_name(self.guid, mode='both', color=False)

# ----------------------------------------------------------------------------------------
class Subsections(FirmwareStructure):
    """
    This unknown structure was common seen in my rom.
    """

    label = "Subsections"

    definition = Struct(
        "subsections" / GreedyRange(Class(FirmwareFileSystemSection)),
    )

# ----------------------------------------------------------------------------------------
class SafeFirmwareVolume(FirmwareStructure):

    label = "FFS Volume"

    definition = Struct(
        "volume" / Class(FirmwareVolume),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["volume"], ["unexpected"]]

# ----------------------------------------------------------------------------------------
class GreedyHex(FirmwareStructure):

    definition = Struct(
        "_data" / Bytes(528),
        "data" / Computed(lambda ctx: ctx._data.hex()),
    )

# ----------------------------------------------------------------------------------------
class PartitionThing(FirmwareStructure):
    """
    Highly experimental exploration of space between volumes in a PFS.
    """

    label = "PFS Interpart"

    # The Partitioned file is probably something more like this:
    #definition = Struct(
    #    "unknown" / Bytes(600),
    #    Aligned(64, lazy_volume),
    #)

    # But just the stuff between the volumes is interpreted as:
    definition = Struct(
        "padding" / GreedyRange(Const(b'\xff')),
        "guid" / UUID16,  # also semi-magical?
        "u1" / Int32ul,
        "str" / PaddedString(16, "utf-8"),
        "u2" / Int32ul,
        "u3" / Int32ul,
        "u4" / Int32ul,
        "s1" / Int16ul,
        "u5" / Int32ul,
        "x" / Bytes(2),
        "u6" / Int32ul,

        "u7" / Int32ul,
        "u8" / Int32ul,
        "u9" / Int32ul,
        "gs" / Class(GreedyHex),
        "more" / Opt(Class(GreedyHex)),
        "remainder" / Class(MysteryBytes),
    )

    reporting = [
        ["guid"], ["u1"], ["u2"], ["u3"], ["u4"], ["str"],
        ["u5"], ["u6"], ["u7"], ["u8"], ["u9"], ["s1"], ["x"],
        ["padding", None],
        [], ["gs"],
        [], ["more"],
    ]

# ----------------------------------------------------------------------------------------
EFI1_CAPSULE_GUID = UUID('3b6686bd-0d76-4030-b70e-b5519e2fc5a0')
class EFI1Capsule(FirmwareStructure):

    label = "EFIv1 Firmware Capsule"

    definition = Struct(
        "_magic_guid" / Const(EFI1_CAPSULE_GUID.bytes_le),
        "header_size" / Int32ul,
        "flags" / Int32ul,
        "capsule_size" / Int32ul,
        "seq_num" / Int32ul,
        "guid" / UUID16,
        "offset_split_info" / Int32ul,
        "offset_capsule_body" / Int32ul,
        "offset_oem_info" / Int32ul,
        "offset_author_info" / Int32ul,
        "offset_revision_info" / Int32ul,
        "offset_short_desc" / Int32ul,
        "offset_long_desc" / Int32ul,
        "offset_devices" / Int32ul,
        # Consume any exta bytes in the header.
        "preamble" / FixedLength(this.header_size - 80, GreedyBytes),
        # Technically the sections start at the offsets in the header.  In the one case
        # I've seen capsule_body == header_size == 80, and it's the only section.
        "body" / SafeFixedLength(this.capsule_size - this.header_size, Class(FirmwareVolume)),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
    )

    reporting = [
        ["guid"], ["flags", "0x%x"], ["header_size"], ["capsule_size"], ["skipped"],
        [],
    ]

# ----------------------------------------------------------------------------------------
EFI2_CAPSULE_GUID = UUID('4a3ca68b-7723-48fb-3d80-578cc1fec44d')
class EFI2Capsule(FirmwareStructure):

    label = "EFIv2 Firmware Capsule"

    definition = Struct(
        "_magic_guid" / Const(EFI2_CAPSULE_GUID.bytes_le),
        "header_size" / Int32ul,
        "flags" / Int32ul,
        "capsule_size" / Int32ul,
        "offset_volume" / Int16ul,
        "offset_oem_info" / Int16ul,
        # Consume any exta bytes in the header.
        "preamble" / FixedLength(this.header_size - 80, GreedyBytes),
        # Technically the sections start at the offsets in the header.  In the one case
        # I've seen capsule_body == header_size == 80, and it's the only section.
        "body" / FixedLength(this.capsule_size - this.header_size, Class(FirmwareVolume)),
    )

# ----------------------------------------------------------------------------------------
UEFI_CAPSULE_GUID = UUID('539182b9-abb5-4391-b69a-e3a943f72fcc')
class UEFICapsule(FirmwareStructure):

    label = "UEFI Firmware Capsule"

    definition = Struct(
        "_magic_guid" / Const(UEFI_CAPSULE_GUID.bytes_le),
        "header_size" / Int32ul,
        "flags" / Int32ul,
        "capsule_size" / Int32ul,
        # It's unclear to me if this is just padding.
        "preamble" / FixedLength(this.header_size - 28, GreedyBytes),
        "body" / SafeFixedLength(this.capsule_size - this.header_size, Class(FirmwareVolume)),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
        "extra" / Class(MysteryBytes),
    )

    reporting = [
        ["flags", "0x%x"], ["header_size"], ["capsule_size"], ["skipped"],
    ]

# ----------------------------------------------------------------------------------------
AMI_CAPSULE_GUID = UUID('6dcbd5ed-e82d-4c44-bda1-7194199ad92a')
class AMICapsule(FirmwareStructure):
    """
    An AMI capsule format?  Identical to UEFI Capsuel with a different guid?
    Never seen, so don't really know.
    """

    label = "AMI Firmware Capsule"

    definition = Struct(
        "_magic_guid" / Const(AMI_CAPSULE_GUID.bytes_le),
        "header_size" / Int32ul,
        "flags" / Int32ul,
        "capsule_size" / Int32ul,
        # It's unclear to me if this is just padding.
        "preamble" / FixedLength(this.header_size - 28, GreedyBytes),
        "body" / SafeFixedLength(this.capsule_size - this.header_size, Class(FirmwareVolume)),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
        "extra" / Class(MysteryBytes),
    )

    reporting = [
        ["flags", "0x%x"], ["header_size"], ["capsule_size"],
    ]

# ----------------------------------------------------------------------------------------
class WorkingBlockFlags(Flag):
    VALID = 1
    INVALID = 2

# ----------------------------------------------------------------------------------------
# https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Include/Guid/SystemNvDataGuid.h
WORKING_BLOCK_GUID = UUID('9e58292b-7c68-497d-a0ce-6500fd9f1b95')
class WorkingBlock(FirmwareStructure):

    label = "EDKII Fault Tolerant Working Block Header"

    definition = Struct(
        "_magic_guid" / Const(WORKING_BLOCK_GUID.bytes_le),
        "crc" / Int32ul,
        "_flags" / Int8ul,
        "reserved" / Bytes(3),
        "write_queue_size" / Int64ul,
    )

    @property
    def flags(self) -> WorkingBlockFlags:
        # Only the lowest two bits have defined meaning, and the rest of the bits are
        # _set_ by default instead of being zero?
        return WorkingBlockFlags(self._flags & 3)

    reporting = [["crc", "0x%x"], ["flags"], ["write_queue_size"], ["reserved"]]

    #        # EFI_FAULT_TOLERANT_WRITE_HEADER is 33 bytes long
    #        # EFI_FAULT_TOLERANT_WRITE_RECORD is 25 bytes + sizeof EFI_LBA (8?)
    #
    #        # This is almost certainly NOT the correct calculation.  But it might be
    #        # kind of close, and it works out correctly in this case.  The 32 is the
    #        # header size, it's clearly rounded to a multiple of 4k.  What I can't quite
    #        # figure is why the size if 67 and not 66, which seems more likely.
    #        data_size = (int((self.wq_size * 67) / 4096) + 1) * 4096 - 32
    #
    #        sig_data = data[offset+32:]
    #        # The checksum is calculated with 0xFF (FTW_ERASED_BYTE)
    #        # bytes in the checksum and the flags/status byte as well.
    #        chkdata = list(data[offset:offset+32])
    #        chkdata[16] = 0xFF
    #        chkdata[17] = 0xFF
    #        chkdata[18] = 0xFF
    #        chkdata[19] = 0xFF
    #        chkdata[20] = 0xFF
    #        computed_checksum = binascii.crc32(bytes(chkdata))
    #        if computed_checksum != self.checksum:
    #            self.debug("Invalid working block checksum: 0x%x == 0x%x" % (
    #                computed_checksum, self.checksum))
    #
    #        #self.debug("Sig size was %x" % self.wq_size)
    #        #self.debug("Offset was %x" % offset)
    #        #self.debug("Data was %x %x" % (data_size, offset + 32 + data_size))
    #        if sig_data != b'\xff' * data_size:
    #            self.debug("EVSA raw sig data was not filled with FFs!")
    #        if self.size != offset + 32 + data_size:
    #            self.debug("EVSA size mismatch %x != %x" % (self.size,  offset + 32 + data_size))
    #

# ----------------------------------------------------------------------------------------
class ParallelsVM_NVRAMFile(FirmwareStructure):

    label = "Parallels VM NVRAM File"

    definition = Struct(
        "_zero_padding" / Const(b'\x00' * 65536),
        "nvdata" / Class(FirmwareVolume),
        "_ff_padding1" / GreedyRange(Const(b'\xff')),
        "ffpad1" / Computed(lambda ctx: len(ctx._ff_padding1)),
        "working_block" / Class(WorkingBlock),
        "_ff_padding2" / GreedyRange(Const(b'\xff')),
        "ffpad2" / Computed(lambda ctx: len(ctx._ff_padding2)),
    )

    reporting = [["ffpad1"], ["ffpad2"], ["nvdata"], ["working_block"]]

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
