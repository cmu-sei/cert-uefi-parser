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
Miscellaneous vendor-specific data structures.
"""

import gzip
import json
import io
import zipfile
from enum import Flag, Enum
from datetime import datetime
from uuid import UUID
from typing import Optional, Union, Any

from construct import (
    Int8ul, Int16ul, Int16sl, Int16ub, Int32ul, Int32sl, Int32ub, Int64ul, Int64sl,
    Bytes, GreedyBytes, GreedyRange, Array, Select, Pointer, Switch,
    Computed, Const, Check, CheckError, SelectError, Seek, Tell, this)

from uefi_support import LzmaDecompress, CabFile, DecompressionError

from .base import (
    FirmwareStructure, FakeFirmwareStructure, HashedFirmwareStructure, Class, Opt,
    CString, PaddedString, FixedLength, FailPeek, UUID16, Struct, LazyBind, HexBytes,
    OneOrMore, Context, get_stream_size, EnumAdapter, promote_exceptions)
from .exes import PEExecutable, PESectionHeader
from .pfs import PFSRegion, TextFile
from .finder import FirmwareVolumeFinder
from .mystery import MysteryBytes, CommitMystery
from .flash import FlashDescriptor

# ----------------------------------------------------------------------------------------
class BIOSExtensionROM(FirmwareStructure):
    """
    The BIOS Extension format.

    Used for VGA BIOS, Intel Boot Agent, Realtek PCIe GBE, Realtek USB, ASIX, etc.

    http://staff.ustc.edu.cn/~xyfeng/research/cos/resources/machine/biosextension.htm

    It's not clear that this is actually a file format, so much as just a magic header
    that marks the start of an arbitrary executable blob.  This code just extracts some
    arbitary descriptive strings fro the blob, so I have an idea of what's in there.

    Exemplars of this data type can be found in the HP BIOSes.
    """

    label = "BIOS Extension ROM"

    definition = Struct(
        "_magic" / Const(b'\x55\xaa'),
        "blocks" / Int8ul,
        # Rewind so that the header is in the data.
        Seek(-3, 1),
        "data" / Bytes(this.blocks * 512),
        "extra" / Class(MysteryBytes),
        "extra_length" / Computed(lambda ctx: len(ctx.extra))
    )

    reporting = [
        ["blocks"], ["name"], ["extra_length"], ["mdata"],
        ["data", None],
    ]

    @property
    def mdata(self) -> Optional[MysteryBytes]:
        # This field is intended to report the raw data bytes as a reminder that despire
        # having pulled a printable string out, we still don't really understand these bytes.
        mdata = self.subparse(MysteryBytes, "data")
        #mdata.label = "Raw Data Bytes"
        return mdata

    def analyze(self) -> None:
        self.name = "unknown"
        try:
            if self.data[30:53] == b"IBM VGA Compatible BIOS":
                self.name = self.data[30:53].decode('utf-8')
            elif self.data[28:50] == b"Intel(R) RAID for SATA":
                self.name = self.data[28:64].decode('utf-8')
            elif self.data[188:207] == b"Intel(R) Boot Agent":
                self.name = self.data[188:218].decode('utf-8')
            elif self.data[161:194] == b"Intel(R) Boot Agent PXE Base Code":
                self.name = self.data[161:214].decode('utf-8')
            elif self.data[236:243] == b"ASIX AX":
                end = self.data.find(b'\x00', 236)
                self.name = self.data[236:end].decode('utf-8')
            elif self.data[341:353] == b"Realtek PCIe":
                end = self.data.find(b'\r', 341)
                self.name = self.data[341:end].decode('utf-8')
            elif self.data[373:384] == b"Realtek USB":
                end = self.data.find(b'\r', 373)
                self.name = self.data[373:end].decode('utf-8')
            elif self.data[34:54] == b"Plex86/Bochs VGABios":
                self.name = self.data[34:54]
            elif len(self.data) > 699 and self.data[671:699] == b"CD Service Base Code Version":
                name = self.data[671:699] + b' ' + self.data[31:41]
                self.name = name.decode('utf-8')
            elif len(self.data) > 663 and self.data[656:663] == b"ReadROM":
                self.name = self.data[656:698].decode('utf-8')
            else:
                self.debug("BIOS Extension ROM initial data: %r" % self.data[:128])
        except Exception as e:
            self.error("Failed to parse BIOS ROM extension")
            self.error(f"  {e}")

# ----------------------------------------------------------------------------------------
class FLUFString(FirmwareStructure):

    label = "FLUF String"

    definition = Struct(
        "_data" / GreedyBytes,
    )

    def analyze(self) -> None:
        try:
            self.lines = []
            strdata = str(self._data.rstrip(b'\x00').decode('utf8'))
            for line in strdata.split('\n'):
                if line != '':
                    self.lines.append(line + '\n')
        except UnicodeError:
            self.lines = self._data

    reporting = [["lines"]]

# ----------------------------------------------------------------------------------------
class FLUF(FirmwareStructure):

    label = "FLUF File"

    definition = Struct(
        # Note that magic if "peeked", and the string "FLUF Format 002" appears to be part
        # of the initial metadata file.
        "_magic" / FailPeek(Const(b'FLUF Format 002')),
        "str1" / FixedLength(0x200 - 18, Class(FLUFString)),
        "len1" / Computed(lambda ctx: len(ctx.str1._data)),
        # These 18 bytes may not actually be a short and a GUID.
        "u1" / Bytes(2),
        "guid" / UUID16,
        # Things look a little more confident starting here again.
        "str2" / FixedLength(7 * 32 + 13, Class(FLUFString)),
        "len2" / Computed(lambda ctx: len(ctx.str2._data)),
        "u2" / Bytes(3),
        "idstr" / PaddedString(17 * 16, 'utf8'),
        # And then it appears to degenerate into random (compressed?) bytes.  There are
        # some zeros at the end, and a few small data blobs separated by sequences of
        # zeros near the end.
        "unknown" / Class(MysteryBytes),
    )

    reporting = [
        ["idstr"], ["guid"], ["u1"], ["u2"], ["len1"], ["len2"], ["str1"], ["str2"],
    ]

# ----------------------------------------------------------------------------------------
class DellFMPThing(FirmwareStructure):

    label = "Dell FMP Thing"

    definition = Struct(
        # Actually the start of a new structure?  Tag is always/usually "$RBU"?
        "tag" / Const(b'$RBU'),
        "header_size" / Int8ul,
        "major_version" / Int8ul,
        "minor_version" / Int8ul,
        "num_systems" / Int8ul,
        "quickcheck" / PaddedString(40, 'utf-8'),
        "bios_major" / Int8ul,
        "bios_minor" / Int8ul,
        "bios_rev" / Int8ul,
        "misc_flags" / Int8ul,
        "bios_internal_only" / Int8ul,
        "reserved" / Bytes(5),
        "compat_flags" / Int16ul,
        "raw_systemids" / Array(12, Int16ul),
        # FIXME: This structure is technically at 40 + header_size (usually 84).
        # That's 84 bytes past tag, and usually next in the stream.
        #"x1" / Int32ul,
        #"xsize" / Int32ul,
        #"x2" / Int32ul,
        #"x3" / Int32ul,
        #"xdata" / FixedLength(this.xsize, Class(MysteryBytes)),
        "compressed" / GreedyBytes,
        #"finder" / Class(FirmwareVolumeFinder),
    )

    parsed: Optional[Union[FlashDescriptor, 'DellFMPThing', MysteryBytes]]
    # FIXME! Needed until correct types are returned from the mypy extension...
    quickcheck: str

    reporting = [
        ["quickcheck", None], ["vendor_string"], ["version"], ["bios_version"],
        ["major_version", None], ["minor_version", None],
        ["bios_major", None], ["bios_minor", None], ["bios_rev", None],
        # The second sub-structure
        [], ["raw_systemids", None], ["systemids"],
        [], ["compressed", None],
        # The third (poorly understood) sub-structure
        # [], ["x1"], ["x2"], ["x3", "0x%0x"], ["xsize"],
    ]

    sbom_fields = ["vendor_string", "version", "bios_version", "parsed"]

    @property
    def vendor_string(self) -> str:
        return self.quickcheck.rstrip()

    @property
    def version(self) -> str:
        return "%d.%d" % (self.major_version, self.minor_version)

    @property
    def bios_version(self) -> str:
        if self.major_version < 2:
            bios_major = chr(self.bios_major)
            bios_minor = chr(self.bios_minor)
            bios_rev = chr(self.bios_rev)
            return "%s%s%s" % (bios_major, bios_minor, bios_rev)
        else:
            return "%d.%d.%d" % (self.bios_major, self.bios_minor, self.bios_rev)

    def analyze(self) -> None:
        # There are 12 system ids in the header, but only ther first "num_systems" are populated.
        # Contains the list of NumSystems Dell System ID and Hardware Revision
        # ID pairs for which the Image Data is valid, in the following format:
        #
        # Bit Range  Description
        # 15:11      Dell System ID, bits 12:8.
        #               This range is set to 00000b if the Dell System ID
        #               is a 1-byte value.
        # 10:8       Hardware Revision ID
        # 7:0        Dell System ID, bits 7:0.
        self.systemids = []
        for sysbits in self.raw_systemids:
            sysid = (sysbits & 0x00ff) | ((sysbits & 0xf800) >> 3)
            hwrev = (sysbits & 0x0700) >> 8
            self.systemids.append((sysid, hwrev))

        try:
            decompressed = LzmaDecompress(self.compressed)
            self.parsed = DellFMPThing.parse(decompressed, 0)
        except DecompressionError:
            self.parsed = self.subparse(FlashDescriptor, "compressed")
            if self.parsed is None:
                self.parsed = self.subparse(MysteryBytes, "compressed")

# ----------------------------------------------------------------------------------------
class EDK2MetaData(FirmwareStructure):
    """
    Just a place holder for the brief investigation I conducted.  This looks like it
    probably has certificates and signatures in it.  The EDK2 FMPCapsule Python code
    mentions some structures that migth be present.
    """

    label = "EDK2 Meta Data"

    definition = Struct(
        "data" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
class FMPDataFile(FirmwareStructure):
    """
    Experimental.
    """

    label = "FMP Data File"

    definition = Struct(
        "version" / Int32ul,
        "guid" / UUID16,
        "u1" / Int32ul,
        "u2" / Int64ul,
        "u3" / Int64ul,
        "u4" / Int64ul,
        "size" / Int32ul,
        # EDK2MetaData will consume all bytes.
        "metadata" / FixedLength(this.size - 4, Class(EDK2MetaData)),
        "volume" / Class(FirmwareVolumeFinder),
    )

    reporting = [
        ["version"], ["guid"], ["u1"], ["u2"], ["u3"], ["u4"], ["size"], ["skipped"],
    ]

# ----------------------------------------------------------------------------------------
class FMPPayload(FirmwareStructure):
    """
    This data structure is still pretty broken.  It needs more work, but it is as
    functional as it was in the previous version of the code.

    There may be relevant documentation here:
    https://github.com/tianocore/edk2-basetools/blob/master/edk2basetools/GenFds/CapsuleData.py#L203

    Or in a now broken reference to: /src/python/libsmbios_c/rbu_hdr.py in the libsmbios library.
    It appears that link was to a file that's been removed from the current version of the repo.
    """

    label = "FMP Payload"

    # EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER
    definition = Struct(
        "version" / Int32ul,
        # Used to identify device firmware targeted by this update. This guid is matched
        # by system firmware against ImageTypeId field within a
        # EFI_FIRMWARE_IMAGE_DESCRIPTOR
        "guid" / UUID16,
        # Passed as ImageIndex in call to EFI_FIRMWARE_MANAGEMENT_PROTOCOL.SetImage().
        "image_index" / Int32ul,  # Technically a byte with 3 zero bytes of padding?
        # Size of the binary update image which immediately follows this structure.
        "image_size" / Int32ul,
        # Size of the VendorCode bytes which optionally immediately follow binary update
        # image in the capsule.
        "vendor_size" / Int32ul,
        # The HardwareInstance to target with this update. If value is zero it means match
        # all HardwareInstances. This field allows update software to target only a single
        # device in cases where there are more than one device with the same ImageTypeId
        # GUID.  This header is outside the signed data of the Authentication Info
        # structure and therefore can be modified without changing the Auth data.
        "hardware_instance" / Int64ul,
        # A 64-bit bitmask that determines what sections are added to the payload.
        # CAPSULE_SUPPORT_AUTHENTICATION = 1
        # CAPSULE_SUPPORT_DEPENDENCY = 2
        # "section_flags" / Int64ul,
        "fmpthing" / Opt(Class(DellFMPThing)),
    )

    reporting = [
        # the human intelligible fields?
        ["guid"], ["version"],
        # The first sub-structure
        [], ["image_index"], ["image_size"], ["vendor_size"], ["hardware_instance"],
    ]

    sbom_fields = ["guid", "fmpthing"]

# ----------------------------------------------------------------------------------------
class FMPCapsuleFlags(Flag):
    PERSIST_ACROSS_RESET = 0x00010000
    POPULATE_SYSTEM_TABLE = 0x00020000
    INITIATE_RESET = 0x00040000

FMP_CAPSULE_GUID = UUID('6dcbd5ed-e82d-4c44-bda1-7194199ad92a')

# ----------------------------------------------------------------------------------------
class FMPCapsule(FirmwareStructure):
    """
    A Firmware Management Protocol (FMP) Capsule.

    The FMPCapsule format from:
    https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Guid/FmpCapsule.h
    https://github.com/tianocore/edk2-basetools/blob/master/edk2basetools/GenFds/Capsule.py

    https://uefi.org/sites/default/files/resources/UEFI%20Fall%202018%20Intel%20UEFI%20Capsules.pdf
    https://microsoft.github.io/mu/dyn/mu_tiano_plus/FmpDevicePkg/Docs/FmpDevicePkg_ReadMe/
    https://raw.githubusercontent.com/tianocore-docs/Docs/master/White_Papers/A_Tour_Beyond_BIOS_Capsule_Update_and_Recovery_in_EDK_II.pdf
    """

    label = "FMP Capsule"

    definition = Struct(
        # UefiCapsuleHeaderClass from the python script in EDK2.
        "_magic_guid" / Const(FMP_CAPSULE_GUID.bytes_le),
        "failure" / CommitMystery,
        # The header size appears to be measured from right before the header.
        "_header_start" / Tell,
        "header_size" / Int32ul,
        "flags" / EnumAdapter(Int32ul, FMPCapsuleFlags),
        "image_size" / Int32ul,
        # EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER from FmpCapsule.h
        "version" / Int32ul,
        "num_data_files" / Int16ul,
        "num_payloads" / Int16ul,
        # The
        "offsets" / Switch(this.version, {
            # I'm guessing on the structure of the version zero data here...
            0: Array(lambda ctx: (ctx.num_payloads + ctx.num_data_files) * 2, Int32ul),
            # But the version one format is more clearly documented in EDK2.
            1: Array(lambda ctx: ctx.num_payloads + ctx.num_data_files, Int64ul),
        }),
        # Some version zero files have additional bytes.  It was four bytes in the case I
        # encountered, but maybe it could be more?
        "_header_end" / Tell,
        "extra_header" / FixedLength(
            this.header_size - (this._header_end - this._header_start), GreedyBytes),

        # Not implemented (now or previously)
        "data_files" / Array(this.num_data_files, Class(FMPDataFile)),
        "payloads" / Array(this.num_payloads, Class(FMPPayload)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["version"], ["header_size"], ["image_size"], ["flags"],
        ["num_data_files"], ["num_payloads"], ["offsets"],
    ]

    sbom_fields = ["payloads", "data_files"]

# ----------------------------------------------------------------------------------------
@promote_exceptions
def find_biosdat_section(ctx: Context) -> Optional[PESectionHeader]:
    for section in ctx.exe.sections:
        assert isinstance(section, PESectionHeader)
        if section.name == ".biosdat":
            return section
    return None

# ----------------------------------------------------------------------------------------
class DellUpdaterEFIApp(FirmwareStructure):
    """
    A Dell BIOS update distributed as an EFI application.
    """

    label = "Dell Updater EFI Application"

    definition = Struct(
        "exe" / Class(PEExecutable),
        "_biosdat_section" / Computed(find_biosdat_section),
        # If we couldn't find the required section, we're not a DellUpdaterEFIApp
        Check(lambda ctx: ctx._biosdat_section is not None),
        # We'll handle the rest of the parsing in analyze() because it's complicated.
    )

    embedded: Optional[PEExecutable]
    capsule: Optional[FMPCapsule]

    reporting = [
        ["biosdat_start"],
        ["biosdat_size"],
        ["embedded_start"],
        ["capsule_start"],
        ["capsule_end"],
        # List the enclosing executable first, then the embedded exe (short) and finally
        # the much larger FMP capsule (that will comprise most of the output).
        ["exe"], ["embedded"], ["capsule"],
    ]

    sbom_fields = ["exe", "embedded", "capsule"]

    def analyze(self) -> None:
        # Do a full PE parse, so we can call read PE memory by virtual address.
        # Does this potentially create problems pefile returning different results?
        pef = self.exe.pefile()
        if pef is None:
            raise CheckError("PEExecutable is corrupt!")

        found_section = False
        self.biosdat_start = 0
        self.biosdat_size = 0
        self.embedded_start = 0
        self.capsule_start = 0
        self.capsule_end = 0
        for section in pef.sections:
            if section.Name == b".biosdat":
                found_section = True
                self.biosdat_start = section.VirtualAddress
                self.biosdat_size = section.SizeOfRawData
                self.embedded_start = pef.get_dword_at_rva(self.biosdat_start)
                self.capsule_start = pef.get_dword_at_rva(self.biosdat_start + 4)
                self.capsule_end = self.biosdat_start + self.biosdat_size

        if not found_section:
            # FIXME report error if it occurs!
            raise CheckError("No biosdat section found!")

        capsule_data = pef.__data__[:self.capsule_end]
        self.capsule = FMPCapsule.parse(capsule_data, self.capsule_start)
        # Curiously, the above works, but this does NOT?  Bug somewhere?
        #self.capsule = FMPCapsule.parse(pef.__data__, self.capsule_start, self.capsule_end)
        self.embedded = PEExecutable.parse(pef.__data__, self.embedded_start, self.capsule_start)
        if self.embedded is not None:
            self.embedded.label = "Embedded Executable"

# ----------------------------------------------------------------------------------------
class IFlashBIOSImage(FirmwareStructure):

    definition = Struct(
        "u1" / Bytes(256),
        "magic" / Const(b'$_IFLASH_BIOSIMG'),
        "volumes" / Select(Class(FirmwareVolumeFinder), Class(MysteryBytes)),
        #"unexpected" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
@promote_exceptions
def lazy_huawei_exe(ctx: Context) -> Class:
    return Class(HuaweiUpdaterExecutable)

# ----------------------------------------------------------------------------------------
class IFlashDriveImage(FirmwareStructure):

    definition = Struct(
        "u1" / Bytes(96),
        "magic" / Const(b'$_IFLASH_DRV_IMG'),
        "u2" / Int32ul,
        "u3" / Int32ul,
        "exe" / LazyBind(lazy_huawei_exe),
        "unexpected" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
class HuaweiUpdaterExecutable(FirmwareStructure):

    definition = Struct(
        "exe" / Class(PEExecutable),
        "signature" / Class(MysteryBytes),
    )

    payload: Optional[Union[IFlashDriveImage, IFlashBIOSImage, FirmwareVolumeFinder]]

    reporting = [
        ["exe"],
        ["payload"], ["signature"],
    ]

    def analyze(self) -> None:
        self.payload = None
        self.signature.label = "Authenticode Signature"
        last_start = self.exe.sections[-1].raw_data_ptr
        last_size = self.exe.sections[-1].size_of_raw_data
        try:
            self.payload = self.exe.subparse(
                Select(Class(IFlashDriveImage), Class(IFlashBIOSImage),
                       Class(FirmwareVolumeFinder)),
                "raw_data", last_start, last_start + last_size)
        except SelectError:
            raise CheckError("Not really a Huawei updater!")

# ----------------------------------------------------------------------------------------
class DellUpdaterExecutable(FirmwareStructure):

    label = "Dell BIOS Updater Executable"

    definition = Struct(
        "exe" / Class(PEExecutable),
        "loc" / Tell,
        "slack" / Pointer(this.loc, GreedyBytes),
        # In some Dell updater executables, the regions are not compressed, and in others
        # they are.  I don't believe there should ever be a mixture, even though this
        # definition would allow that.  Also the Compressed PFS Region code silently
        # consumes FF padding between the regions.
        "_ff_padding" / GreedyRange(Const(b'\xff')),
        "pre_regions_padding" / Computed(lambda ctx: len(ctx._ff_padding)),
        "regions" / OneOrMore(Class(PFSRegion)),
        "signature" / Class(MysteryBytes),
    )

    regions: Optional[Union[list[PFSRegion], IFlashDriveImage]]

    reporting = [
        ["pre_regions_padding"],
        ["exe"],
        ["loc", None],
        ["slack", None],
        ["regions"], ["signature"],
    ]

    def analyze(self) -> None:
        self.signature.label = "Authenticode Signature"
        if (self.regions is not None
                and len(self.regions) == 0 and self.exe is not None
                and len(self.exe.sections) > 0 and self.exe.raw_data is not None):
            last_start = self.exe.sections[-1].raw_data_ptr
            last_size = self.exe.sections[-1].size_of_raw_data
            #self.regions = [last_start, last_size]
            self.regions = IFlashDriveImage.parse(
                self.exe.raw_data[:last_start + last_size], last_start)

# ----------------------------------------------------------------------------------------
# This is messy, and is still being improved...  These are all basically magic's for the
# LVFS Container. It's unclear to me whether the set is bounded at all, but they're being
# enumerated in various web pages, so they might be.

DEVICE_GUIDS = {
    '14cc970e-c105-4eba-a704-448dde9de64d': "Unknown device",
    '1c7df930-c51b-43f2-af4e-01239686ff2d': "Unknown device",
    '1ce1e757-cd07-48e4-9685-c6e7e6eb45b9': "Unknown device",
    '1e1fe415-74e8-49e1-9508-106b3d13d50d': "Unknown device",
    '216e4407-43ff-4b84-9929-a1807761b1a0': "Unknown device",
    '29ca1559-e603-4237-ba5c-2c55348da93e': "Unknown device",
    '31245a58-b272-4776-9398-3df5e8b532db': "Unknown device",
    '42a0a96e-c9f3-438f-9687-7826be33e4ce': "Unknown device",
    '42f29620-3d63-4f09-950b-9b7055570f28': "Unknown device",
    '4e06f4ae-ab2e-4804-9a23-888e596a31e7': "Unknown device",
    '508f7539-1ad6-48b9-8680-38377535009d': "Unknown device",
    '52dd29cd-24b9-4d60-8a45-e72670901924': "Unknown device",
    '55d04ffc-714a-4457-b982-d244343e1958': "Unknown device",
    '604799ec-12a5-4b22-817a-358135296a78': "Unknown device",
    '671d19d0-d43c-4852-98d9-1ce16f9967e4': "In MS URL List",
    '676af093-2a5c-4238-9c29-db8063a33532': "In MS URL List",
    '6c6c8104-65e5-45c2-8e31-059df92ef3fd': "Unknown device",
    '6d265843-ce23-4ba3-a86e-64271ad0aa3f': "Unknown device",
    '6fa2d32b-ec53-44fa-94d6-5ab363c51968': "In MS URL List",
    '74997a6b-1adf-4b12-b994-401f06ea8c72': "In MS URL List",
    '765f81e8-cc44-4d09-8fc4-9a47b167166e': "Unknown device",
    '7a176688-0960-47ba-931b-7829849e8347': "Unknown device",
    '80af5c6d-7e58-4dc9-ad2a-8cdbc425dff9': "Unknown device",
    '84b80435-53b7-4fc0-aa78-d225a59be53f': "In MS URL List",
    '993f4478-ab74-48e2-bf65-26e6462e01d6': "Unknown device",
    '9b0578cf-f035-4fe8-b6ae-42591c946c36': "Unknown device",
    '9ca89fa5-ce05-47ac-bdf3-5b0b6f21d07a': "Unknown device",
    '9d97f767-ea06-474f-9141-7e2430d97fc1': "Unknown device",
    '9e21f98b-fe98-455c-b388-da5450ab6979': "In MS URL List",
    'a121e4b0-a3b9-4f15-b2f6-5f793e21414c': "Unknown device",
    'a4b51dca-8f97-4310-8821-3330f83c9135': "Unknown device",
    'a7c68c44-60f0-431c-9242-926912892f28': "Unknown device",
    'a95d69e7-2fa0-4849-9159-75645bc6e153': "Unknown device",
    'b623bdcf-e25b-4be9-b5f4-821851a54fe0': "Unknown device",
    'b879dc99-6712-40ce-aaa9-de8ff2271d03': "Unknown device",
    'bec0a796-5688-499f-b208-9fc1d1e734a6': "Unknown device",
    'bf2d0f8b-f9a9-400c-8914-36c225d16eb4': "Unknown device",
    'c35736d2-9e47-4578-93e9-68d5b04ea77e': "In MS URL List",
    'c66fada5-ea35-4e93-9c6f-c0667999808a': "Unknown device",
    'c9a0acef-aa63-4b85-a52d-a9384163c0e8': "Unknown device",
    'cdd74097-79ca-451b-b28c-4cf1f6f412a6': "Unknown device",
    'cfe2923b-6406-4e11-8ef9-fc031f277ba7': "Unknown device",
    'd95d3ada-eef1-464f-8a2a-a11232b8556b': "In MS URL List",
    'dc7f0308-1ef8-4774-9ba5-89a58c4d731c': "Unknown device",
    'ddc0ee61-e7f0-4e7d-acc5-c070a398838e': "Unknown device",
    'e1678770-bdc9-47f9-8d90-340e28b6f196': "Unknown device",
    'e949b7e8-acbe-44f2-bd55-6259fd1b0d1d': "Unknown device",
    'ebf05843-2e63-4d7f-9b5e-b2368afdec72': "Unknown device",
    'ebfe8df8-dee7-4692-a721-cbcf5095c5cf': "Unknown device",
    'ed5cd219-4b49-4105-8952-31fe3e09dde4': "Unknown device",
    'f72e048b-65bd-4e71-9071-1ac7045223e5': "Unknown device",


    '09b43c1e-555f-963e-a30f-bfa293062855': "Points to MZ",
    '10c40550-3da1-44aa-8332-74d09bd1b14f': "Points to MZ",
    '124c207d-5db8-4d95-bd31-34fd971b34f9': "Points to MZ",
    '1367a91a-5560-4d8e-aa56-6f32ca80719b': "Points to MZ",
    '212026ee-fde4-4d08-ac41-c62cb4036a42': "Points to MZ",
    '21f94926-ce92-421c-b275-84392db26185': "Points to MZ",
    '293af847-1181-443c-8dd4-5d935d9f8ee5': "Points to MZ",
    '295c1be0-a44b-4f70-ad47-14000e39a487': "Points to MZ",
    '33773727-8ee7-4d81-9fa0-57e8d889e1fa': "Points to MZ",
    '33f0b913-78bf-445e-8a74-5a2c79496946': "Points to MZ",
    '349575b1-57bd-45d1-bf82-2ee2edd5f6e7': "Points to MZ",
    '388ff1f2-f836-48a5-9994-d4992e63faff': "Points to MZ",
    '3c20b9e1-eddd-4507-acd8-aa0d263f8cf6': "Points to MZ",
    '416d1c90-66ba-4f26-af1c-dcc056073c4f': "Points to MZ",
    '417d4c2a-87d1-4d7c-bcea-322041f2d5a3': "Points to MZ",
    '43ca3264-d791-4df8-9695-7b13a7361a0d': "Points to MZ",
    '45e3439b-0ce6-463b-b33f-f8d4a378fde1': "Points to MZ",
    '46166434-dfc6-4f43-b64b-2d12e8997f79': "Points to MZ",
    '479d7d09-78d8-4fb2-af14-ca6ecc80692d': "Points to MZ",
    '4d33b142-9848-42d7-9613-d890f4d4a760': "Points to MZ",
    '4fed6c9d-22b0-4731-a074-084ba68b492a': "Points to MZ",
    '502bff68-b8db-4b01-86ef-ab65f6502a77': "Points to MZ",
    '51b5f98c-650b-49e4-b5e1-4a42d161d7bf': "Points to MZ",
    '51d41d4e-1a18-49fe-9973-5188425d3c56': "Points to MZ",
    '56ced47d-4844-4209-b97b-a6c5f0114b5b': "Points to MZ",
    '5a05eb25-71cb-4331-8095-4c3fbc8636e4': "Points to MZ",
    '5ffdbc0d-f340-441c-a803-8439c8c0ae10': "Points to MZ",
    '603297b5-9cc4-49fa-be2a-c14f6e8c1fb1': "Points to MZ",
    '7c44fa93-aa42-452e-ad31-606da382bdf6': "Points to MZ",
    '7ceaf7a8-0611-4480-9e30-64d8de420c7c': "Points to MZ",
    '7d5f2036-70a7-4edb-9b1c-73d1f1b68c2e': "Points to MZ",
    '8080d214-49e3-4d1a-b6d3-586c2703a0a2': "Points to MZ",
    '8dd9399b-f970-4ab3-948a-6c0b6e9fa5a6': "Points to MZ",
    '8ae34f14-d8af-4d12-82e3-81f2b8dc8820': "Points to MZ",
    '91901960-11bb-49f9-9e88-5729030bdf3b': "Points to MZ",
    '93634829-10b8-4098-a617-d52d056a4dd8': "Points to MZ",
    '98d41f1d-6556-4174-8452-71af5c75361e': "Points to MZ",
    '9f1ecab8-a9d1-4d01-9bf8-b91cb116b641': "Points to MZ",
    'a0a3aa54-0491-4077-b985-c057ad3e749b': "Points to MZ",
    'a4d0dd43-2490-4ff1-a62e-5fa9790c68ec': "Points to MZ",
    'a5d83d78-dcba-46c0-9ec4-b5d333574bd3': "Points to MZ",
    'a86a3f07-b7d3-4545-9238-0274fc1ba682': "Points to MZ",
    'a93d4a5b-9ea6-4b38-b118-bd11484e3f6a': "Points to MZ",
    'ad1841ab-4452-4c34-bc1b-ed250cdaaf86': "Points to MZ",
    'aee2604a-7e36-4738-918d-a8eb8e307e65': "Points to MZ",
    'b13b7af6-9eb2-4672-b0db-05e5bc77b2d5': "Points to MZ",
    'b566a9b1-af40-41cd-84df-865cc703a631': "Points to MZ",
    'b68b18a3-adb2-44c8-9c22-b686cceb9c08': "Points to MZ",
    'b6972c97-f6c6-4a69-9844-694bae3b984e': "Points to MZ",
    'b6972c97-f6c6-4a69-9844-694bae3b984e': "Points to MZ",
    'b7006d41-67dc-47af-9e38-cc64e2898c02': "Points to MZ",
    'bc10e9f2-44e6-47b7-9756-eed2fd2964b9': "Points to MZ",
    'c02a4b5c-7745-45a3-b8df-21023e6d7534': "Points to MZ",
    'caa22c0d-b9cd-4b74-b78c-980297eb3756': "Points to MZ",
    'cbe49cca-492b-93e8-b0f4-f693501f271b': "Points to MZ",
    'cdcae5ae-413a-4198-b866-8028e994dd53': "Points to MZ",
    'ce945437-7358-49f1-95d8-6b694a10a755': "Points to MZ",
    'cfb08d7c-8d3d-41b1-846b-48f634dfac9d': "Points to MZ",
    'd5e264f9-03aa-4a78-aabd-8eb28147d326': "Points to MZ",
    'd63450d6-d611-48ac-8f3b-8d29bad80248': "Points to MZ",
    'd69fed57-d865-43f6-b7f4-26405b40b646': "Points to MZ",
    'db72c932-b3c6-4640-b382-3f4619ab447b': "Points to MZ",
    'e0f614ed-fb82-467a-a34e-71172cc07e4d': "Points to MZ",
    'e3148af6-3764-4616-81a6-fcae5afe87ee': "Points to MZ",
    'e3f7bc02-51ff-4562-b1b3-97351c18e420': "Points to MZ",
    'e4fa1f1c-5f70-4f24-b35d-7eab9bc12f75': "Points to MZ",
    'e8292593-e66e-4878-b051-f152535ab130': "Points to MZ",
    'eefe7fcb-25a5-4680-93ee-5554458e5861': "Points to MZ",
    'f96619f3-92ad-4bed-8af1-d2b8440e84a1': "Points to MZ",
    'fe771285-6926-4d47-a0bc-0f6e2a71e3ad': "Points to MZ",
    'fe8873de-d500-4cb8-a075-cb8eb73fcfa4': "Points to MZ",
}

@promote_exceptions
def validate_lvfs_container(ctx: Context) -> bool:
    # If the guid is a known GUID, we're definitely an LVFS container.
    if str(ctx.guid) in DEVICE_GUIDS:
        #self.debug("GUID %s was a known guid, %s" % (ctx.guid, DEVICE_GUIDS[str(ctx.guid)]))
        return True

    # It's unclear of these next two tests will remain enabled in the long term, but it
    # was handy for testing to identify new LVFS Containers that weren't already in the
    # DEVICE GUID list.

    # Use zeros in padding as a kind of magic?
    if ctx.padding != b'\x00' * len(ctx.padding):
        return False

    # But the real test is whether the size read from the stream matches the stream size.
    if get_stream_size(ctx) == ctx.size:
        #log.debug("Probable LVFS container with GUID %s" % ctx.guid)
        return True
    return False

# ----------------------------------------------------------------------------------------
class LVFSContainer(FirmwareStructure):
    """
    The outer wrapper used by LVFS to distribute updates.
    """

    label = "LVFS Container"

    definition = Struct(
        "guid" / UUID16,
        "offset" / Int32ul,
        "unk1" / Int32ul,
        "size" / Int32ul,
        "unk2" / Int32ul,
        "padding" / Bytes(lambda ctx: max(ctx.offset - 0x20, 0)),
        Check(validate_lvfs_container),
        # FIXME: This is a pretty lame way to do this.   Can we do better?
        "contents" / Select(
            Class(DellUpdaterExecutable),
            Class(FirmwareVolumeFinder),
        ),
        "extra" / Class(MysteryBytes),
    )

    padding: bytes  # FIXME! Should be inferred from definition.

    reporting = [
        ["guid"], ["size"], ["offset"], ["unk1", "0x%x"], ["unk2"]
    ]

    def analyze(self) -> None:
        # There can be quite a lot of zero padding, and we don't usually want to see it.
        if self.padding == b'\x00' * len(self.padding):
            self.padding = b''

# ----------------------------------------------------------------------------------------
# PupHeader, ECFWHeader, IPackFile, and IPackHeader are from:
# https://i.blackhat.com/USA-19/Thursday/us-19-Matrosov-Breaking-Through-Another-Side-Bypassing-Firmware-Security-Boundaries-From-Embedded-Controller.pdf
# Not actually seen yet!

# Known
pup_platforms = [
    # Actually seen in PUP headers.
    "SKYLAKE",
    "KABYLAKE",
    "COMMETLAKE",
    "CANNONLAKE",
    "TIGERLAKE",
    "ALDERLAKE",
    # Presumed...
    "COFFEELAKE",
    "ICELAKE",
    "JASPERLAKE",
    "RAPTORLAKE",
    "GEMINILAKE",
]

# ----------------------------------------------------------------------------------------
class PupHeader(FirmwareStructure):

    definition = Struct(
        "version" / Int16ul,  # 2 in the example
        "unknown1" / Int16ul,
        # SKYLAKE, COMETLAKE, etc.
        "platform" / PaddedString(16, "utf-8"),
        "flags" / Int16ul,
        "unknown2" / Int16ul,
        "unknown3" / Int32ul,
        "script_size" / Int32ul,
        "chunk_size" / Int32ul,
        "fw_svn" / Int32ul,
        "ec_svn" / Int32ul,
        "unknown4" / Int32ul,
    )

# ----------------------------------------------------------------------------------------
class ECFWHeader(FirmwareStructure):

    definition = Struct(
        "magic" / Const(b'_EC'),
        "version" / Int8ul,
        "file_size" / Int32ul,
        "image_size" / Int32ul,
        "hash_algo" / Int8ul,
        "sign_algo" / Int8ul,
        "hash_crc16" / Int16ul,
        "header_crc16" / Int16ul,
        "unknown" / Int8ul,
    )

# ----------------------------------------------------------------------------------------
class IPackFile(FirmwareStructure):

    definition = Struct(
        "name" / PaddedString(0x100, "utf-8"),
        "raw_offset" / Int32ul,
        "raw_size" / Int32ul,
        "flags" / Int32ul,
        "unknown" / Int32ul,
    )

# ----------------------------------------------------------------------------------------
class IPackHeader(FirmwareStructure):

    definition = Struct(
        "magic" / Const(b'$IPACK'),
        "reserved1" / Int16ul,
        "volume_size" / Int32ul,
        "file_count" / Int32ul,
        "reserved2" / Bytes(0x200),
        "files" / Array(this.file_count, Class(IPackFile)),
    )

# ----------------------------------------------------------------------------------------
class PNGImage(HashedFirmwareStructure):
    """
    A PNG Image.
    """

    label = "PNG Image"

    definition = Struct(
        "_magic" / Const(b'\x89PNG\r\n\x1a\n'),
        "failure" / CommitMystery,
        "size" / Int32ub,
        "_ctype" / Const(b'IHDR'),
        "width" / Int32ub,
        "height" / Int32ub,
        "bit_depth" / Int8ul,
        "color_method" / Int8ul,
        "compression_method" / Int8ul,
        "filter_method" / Int8ul,
        "raw_data" / GreedyBytes,
    )

    reporting = [["width"], ["height"], ["raw_data", None]]

    # Not actually the correct hash because we're only reading the header right now!
    sbom_fields = ["fshash"]

    def instance_name(self) -> str:
        return f"PNG Image {self.width}x{self.height}"

# ----------------------------------------------------------------------------------------
class GIFImage(HashedFirmwareStructure):
    """
    A GIF89a Image.
    """

    label = "GIF Image"

    definition = Struct(
        "magic" / Const(b'GIF89a'),
        "width" / Int16ul,
        "height" / Int16ul,
        "flags" / Int8ul,
        "bgindex" / Int8ul,
        "aspect_ratio" / Int8ul,
        # Header parsing was incomplete.  There's a color table next.
        "_raw_data" / GreedyBytes,
    )

    reporting = [
        ["magic"], ["width"], ["height"], ["flags", "0x%02x"], ["bgindex"],
        ["aspect_ratio"],
    ]

    def instance_name(self) -> str:
        return f"GIF Image {self.width}x{self.height}"

# ----------------------------------------------------------------------------------------
class TIFFImage(HashedFirmwareStructure):
    """
    A TIFF Image.
    """

    label = "TIFF Image"

    definition = Struct(
        "magic" / Const(b'II'),  # Can also be MM for big-endian (not implemented)
        "version" / Const(42, Int16ul),
        "offset" / Int32ul,
        "_raw_data" / GreedyBytes,
    )

    reporting = [
        ["magic"], ["version"], ["offset", "0x%08x"],
    ]

    def instance_name(self) -> str:
        return "TIFF Image"

# ----------------------------------------------------------------------------------------
class JPGImage(HashedFirmwareStructure):
    """
    A JPG Image.
    """

    label = "JPEG Image"

    definition = Struct(
        "_header" / Const(b'\xff\xd8\xff\xe0'),
        "length" / Int16ul,
        "_magic" / Const(b'JFIF\x00'),
        "failure" / CommitMystery,
        "major_version" / Int8ul,
        "minor_version" / Int8ul,
        "units" / Int8ul,
        "density_x" / Int16ul,
        "density_y" / Int16ul,
        "thumbnail_x" / Int8ul,
        "thumbnail_y" / Int8ul,
        "raw_data" / GreedyBytes,
    )

    reporting = [["raw_data", None]]

    # Not actually the correct hash because we're only reading the header right now!
    sbom_fields = ["fshash"]

    def instance_name(self) -> str:
        return self.fshash

# ----------------------------------------------------------------------------------------
class BMPImageV1(HashedFirmwareStructure):
    """
    A Microsoft Bitmap (BMP) Image.
    """

    label = "BMP Image (V1)"

    definition = Struct(
        "_magic" / Const(b'BM'),
        "size" / Int32ul,
        "unused" / Int32ul,
        "offset" / Int32ul,
        "_header_length" / Const(40, Int32ul),
        "failure" / CommitMystery,
        "width" / Int32sl,
        "height" / Int32sl,
        "color_planes" / Int16ul,
        "bits_per_pixel" / Int16ul,
        "compression" / Int32ul,
        "data_size" / Int32ul,
        "x_dpi" / Int32ul,
        "y_dpi" / Int32ul,
        "palette_size" / Int32ul,
        "important_colors" / Int32ul,
        "raw_data" / GreedyBytes,
    )

    reporting = [
        ["width"], ["height"], ["bits_per_pixel"], ["size"], ["raw_data", None],
    ]

    # Not actually the correct hash because we're only reading the header right now!
    sbom_fields = ["fshash"]

    def instance_name(self) -> str:
        return self.fshash

# ----------------------------------------------------------------------------------------
class BMPImageV4(HashedFirmwareStructure):
    """
    A Microsoft Bitmap (BMP) Image.
    """

    label = "BMP Image (V4)"

    definition = Struct(
        "_magic" / Const(b'BM'),
        "size" / Int32ul,
        "unused" / Int32ul,
        "offset" / Int32ul,
        "_header_length" / Const(108, Int32ul),
        "failure" / CommitMystery,
        "header_length" / Int32ul,
        "width" / Int32sl,
        "height" / Int32sl,
        "color_planes" / Int16ul,
        "bits_per_pixel" / Int16ul,
        "compression" / Int32ul,
        "data_size" / Int32ul,
        "x_dpi" / Int32ul,
        "y_dpi" / Int32ul,
        "palette_size" / Int32ul,
        "important_colors" / Int32ul,
        "red_mask" / Int32ul,
        "green_mask" / Int32ul,
        "blue_mask" / Int32ul,
        "alpha_mask" / Int32ul,
        "color_space" / Bytes(4),
        "endpoints" / Bytes(36),
        "red_gamma" / Int32ul,
        "green_gamma" / Int32ul,
        "blue_gamma" / Int32ul,
        "raw_data" / GreedyBytes,
    )

    reporting = [
        ["width"], ["height"], ["bits_per_pixel"], ["size"],
        #["red_mask", "0x%x"], ["green_mask", "0x%x"], ["blue_mask", "0x%x"], ["alpha_mask", "0x%x"],
        ["red_mask", None], ["green_mask", None], ["blue_mask", None], ["alpha_mask", None],
        ["red_gamma", None], ["green_gamma", None], ["blue_gamma", None],
        ["endpoints", None], ["color_space", None], ["raw_data", None],
    ]

    # Not actually the correct hash because we're only reading the header right now!
    sbom_fields = ["fshash"]

    def instance_name(self) -> str:
        return self.fshash

# ----------------------------------------------------------------------------------------
# There are actually at least 8 BMP variations.  I've only implemented two (even
# partially) so far.  See: https://en.wikipedia.org/wiki/BMP_file_format
# BMPImage = Select(Class(BMPImageV1), Class(BMPImageV4))

# ----------------------------------------------------------------------------------------
class XMLFile(TextFile):
    """
    Auto detect XML files based on a commoin leading pattern.
    """

    label = "XML File"

    definition = Struct(
        "_magic" / FailPeek(Const(b"<?xml ")),
        "_data" / GreedyBytes,
    )

# ----------------------------------------------------------------------------------------
class INIConfigFile(TextFile):
    """
    INI Config File.
    """

    label = "INI Configuration File"

    definition = Struct(
        "_data" / GreedyBytes,
    )

# ----------------------------------------------------------------------------------------
class PGPSignatureFile(TextFile):
    """
    Auto detect XML
    """

    label = "PGP Signature File"

    definition = Struct(
        "_magic" / FailPeek(Const(b"-----BEGIN PGP SIGNATURE-----")),
        "_data" / GreedyBytes,
    )

# ----------------------------------------------------------------------------------------
class DellRawSection1(FirmwareStructure):
    """
    Reverse engineered, not authoritative.
    """

    label = "Dell Raw Section 1"

    definition = Struct(
        "_magic" / FailPeek(Const(b"n\xf0\x9e\x05")),
        "c1" / HexBytes(19),
        # This appears to always(?) match the file guid that the raw section is contained
        # within.
        "guid" / UUID16,
        "c2" / HexBytes(21),
        # Only big endian because it look prettier.  Maybe really little endian?
        "v1" / Int16ub,
        "c3" / HexBytes(9),
        "v2" / Int16ul,
        "c4" / Int16ul,
        # Perhaps a BCD-encoded architecture?  Often 0x0806, but also sometimes 0x0606.
        "v3" / Int16ul,
        "c5" / HexBytes(3),
        # This is the only variable length component of the structure.
        "nstr" / CString('utf16'),
        # An end of record marker?  Always \xff\x00\x00
        "c6" / Int8ul,
        "c7" / Int16ul,
    )

    reporting = [
        # These are tyhe variable fields in the first file I looked at.
        ["v1", "0x%04x"], ["v2", "0x%04x"], ["v3", "0x%04x"], ["nstr", "'%s'"], ["guid"],
        # These are all constant in the first file I looked at.
        [], ["c1"], ["c2"], ["c3"], ["c4"], ["c5"], ["c6"], ["c7"],
    ]

# ----------------------------------------------------------------------------------------
class AMISetupSection1(FirmwareStructure):
    """
    Reverse engineered, not authoritative, no idea.
    """

    label = "AMI Setup Section 1"

    definition = Struct(
        "ints" / GreedyRange(Int32ul),
    )

# ----------------------------------------------------------------------------------------
class AMISetupOffsetRecord(FirmwareStructure):
    """
    Reverse engineered, not authoritative.  The meanings of fields u1-u8 is unclear.
    """

    label = "AMI Setup Offset Record"

    definition = Struct(
        "u1" / Int64ul,
        "u2" / Int16ul,
        "u3" / Int16ul,
        "u4" / Int16ul,
        "u5" / Int16ul,
        "seq" / Int16ul,
        "u6" / Int16ul,
        "u7" / Int32ul,
        "u8" / Int32ul,
        "cnt" / Int32ul,
        "offsets" / Array(this.cnt, Int32ul),
        "padding" / GreedyBytes,
    )

    reporting = [
        ["u1"], ["u2"], ["u2"], ["u3", "%5d"], ["u4"], ["u5", "%4d"],
        ["seq", "%3d"], ["u6", "%3d"], ["u7"], ["u8", "%3d"],
        ["cnt", "%3d"],
        # Offset reporting was disabled because they can be ugly in the text spew,
        # but in the GUI it makes more sense to display them.  This is possibly an
        # opportunity for using different reporting in the future.
        [], ["offsets"],
    ]

# ----------------------------------------------------------------------------------------
class AMISetupSection2(FirmwareStructure):
    """
    Reverse engineered, not authoritative.  Likely to be correct based on how it explains
    the offsets in section 3 however.
    """

    label = "AMI Setup Section 2"

    definition = Struct(
        "cnt" / Int32ul,
        "offsets" / Array(this.cnt, Int32ul),
        "setup_offset" / Computed(lambda ctx: ctx._.setup_offset),
        "data_offset" / Tell,
        "_data" / GreedyBytes,
    )

    reporting = [["cnt"], ["setup_offset"], ["data_offset"], ["offsets"]]

    def analyze(self) -> None:
        self.records = []
        # Bug? This list was sorted in practice in my test input, but maybe it should be
        # sorted and uniq'd here before processing?
        for n, o in enumerate(self.offsets):
            delta = self.data_offset - self.setup_offset
            start_offset = o - delta
            if n == len(self.offsets) - 1:
                end_offset = len(self._data)
            else:
                end_offset = self.offsets[n + 1] - delta
            rec = self.subparse(AMISetupOffsetRecord, "_data", start_offset, end_offset)
            if rec is None:
                self.error("AMI Setup record failed to parse!")
            else:
                self.records.append(rec)

# ----------------------------------------------------------------------------------------
class AMISetupGroupRecord(FirmwareStructure):

    label = "AMI Setup Group Record"

    definition = Struct(
        #"_data" / GreedyBytes,
        #"hex" / Computed(lambda ctx: ctx._data.hex()),
        "u01" / Int64ul,  # Values: 0
        "u02" / Int32ul,  # Values: 0-105, usually 0
        "u03" / Int32ul,  # Values: 0-3722, 10009-10870
        "u04" / Int32ul,  # Values: 0,1,2
        "u05" / Int16ul,  # Values: 1,3,4,5,6,8,9,11,13,19,27
        "grp" / Int16ul,  # Values: 0-210, increasing.
        "u07" / Int16sl,  # Values: -1, 0-210, (overwhelmingly -1)
        "u08" / Int16ul,  # Values: 0
        "u09" / Int32ul,  # Values: 1,9,33,41,65,73,545,1281
        "u10" / Int16ul,  # Values: 0, many others, often sequential or clustered
        "u11" / Int16ul,  # Values: 0,2,4,6,8   (overwhelmingly zero)

        "seq" / Int16ul,  # Values: 0-5170, mostly monotonically increasing
        "u13" / Int16ul,  # Values: 1-5
        "u14" / Int64ul,  # Values: many, looks like offsets
        "u15" / Int64sl,
        "u16" / Int16ul,  # Values: 0,1,2,4,8
        "u17" / Int16ul,  # Values: 0,1,2,4,8
        "u18" / Int32ul,  # Values: 10-7813
        "extra" / GreedyBytes,
    )

    reporting = [
        ["u01"], ["u02", "%3d"], ["u03", "%5d"], ["u04"], ["u05", "%2d"],
        ["grp", "%3d"], ["u07", "%3d"], ["u08"], ["u09", "0x%03x"], ["u10", "%4d"],
        ["u11"], ["seq", "%4d"], ["u13"], ["u14", "%7d"], ["u15", "%5d"],
        ["u16"], ["u17"], ["u18", "%4d"], ["extra"],
    ]

# ----------------------------------------------------------------------------------------
class AMISetupSection3(FirmwareStructure):
    """
    Reverse engineered, not authoritative, structure probably correct, meaning is very
    unclear.  The algorithm for determining the size of records is almost certainly wrong.
    """

    label = "AMI Setup Section 3"

    definition = Struct(
        "_section2" / Computed(lambda ctx: ctx._.section2),
        "_data" / GreedyBytes,
    )

    def analyze(self) -> None:
        self.records = []
        # Bug? There are duplicates in this offset list, which would cause some bytes to
        # be parsed twice.  So I chose to build up a list of starting offsets, which was
        # uniq'd during insertion into the dictionary, and then sorted for actual parsing.
        parse_offsets = {}
        for ng, grec in enumerate(self._section2.records):
            for no, offset in enumerate(grec.offsets):
                # If we've already parsed this offset, skip it.
                if offset in parse_offsets:
                    continue
                # There's a good chance that there is simpler logic for end_offset.
                if ng == 0:
                    end_offset = offset + 64
                elif no == len(grec.offsets) - 1:
                    if ng >= len(self._section2.records) - 1:
                        end_offset = len(self._data)
                    else:
                        next_rec = self._section2.records[ng + 1]
                        if len(next_rec.offsets) == 0:
                            end_offset = offset + 128
                        else:
                            end_offset = next_rec.offsets[0]
                else:
                    end_offset = grec.offsets[no + 1]
                # Add the parse offset to the todo list
                parse_offsets[offset] = end_offset

        for start_offset in sorted(parse_offsets):
            end_offset = parse_offsets[start_offset]
            rec = self.subparse(AMISetupGroupRecord, "_data", start_offset, end_offset)
            if rec is None:
                self.error("AMISetupGroupRecord failed to parse!")
            else:
                self.records.append(rec)

# ----------------------------------------------------------------------------------------
class AMISetupString1(FirmwareStructure):
    """
    Reverse engineered, not authoritative, looks good though.
    """

    label = "AMI Setup String 1"

    definition = Struct(
        "guid" / UUID16,
        "str" / PaddedString(80, 'utf16'),
        "ints" / Array(7, Int32ul),
    )

# ----------------------------------------------------------------------------------------
class AMISetupSection4(FirmwareStructure):
    """
    Reverse engineered, not authoritative, looks good though.
    """

    label = "AMI Setup Section 4"

    definition = Struct(
        "cnt" / Int32ul,
        "offsets" / Array(this.cnt, Int32ul),
        "records" / GreedyRange(Class(AMISetupString1)),
        "unexpected" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
class AMISetupSection5(FirmwareStructure):
    """
    Reverse engineered, no idea what's correct.
    """

    label = "AMI Setup Section 5"

    definition = Struct(
        "u01" / Int32ul,
        "u03" / Int32ul,
        "u04" / Int32ul,
        "u05" / Int32ul,
        "u06" / Int32ul,
        "u07" / Int32ul,
        "u08" / Int32ul,
        "u09" / Int32ul,
        "u10" / Int32ul,
        "u11" / Int32ul,
    )

# ----------------------------------------------------------------------------------------
class AMISetupString2(FirmwareStructure):
    """
    Reverse engineered, not authoritative, looks good though.
    """

    label = "AMI Setup String 2"

    definition = Struct(
        "guid" / UUID16,
        "str" / PaddedString(80, 'utf16'),
        "ints" / Array(2, Int32ul),
    )

# ----------------------------------------------------------------------------------------
class AMISetupSection6(FirmwareStructure):
    """
    Reverse engineered, not authoritative, looks good though.
    """

    label = "AMI Setup Section 6"

    definition = Struct(
        "cnt" / Int32ul,
        "offsets" / Array(this.cnt, Int32ul),
        "records" / GreedyRange(Class(AMISetupString2)),
        "unexpected" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
class AMISetupGUID(FirmwareStructure):
    """
    Reverse engineered, not authoritative, looks good though.
    """

    label = "AMI TSE Setup GUID"

    definition = Struct(
        "num" / Int32ul,
        "guid" / UUID16,
    )

# ----------------------------------------------------------------------------------------
class AMISetupSection7(FirmwareStructure):
    """
    Reverse engineered, not authoritative, looks good though.
    """

    label = "AMI Setup Section 7"

    definition = Struct(
        "cnt" / Int32ul,
        "offsets" / Array(this.cnt, Int32ul),
        "records" / GreedyRange(Class(AMISetupGUID)),
        "one" / Int32ul,
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["cnt"], ["offsets"], ["one"], [], ["records"]]

# ----------------------------------------------------------------------------------------
class AMITSESetupData(FirmwareStructure):
    """
    Reverse engineered, not authoritative.
    """

    label = "AMI TSE Setup Data "

    definition = Struct(
        # The AMI TSE Setup data structures have offsets, and they are relative to this
        # position.  It would probably be convenient if this value was zero in practice,
        # but it complicates things when this data structure is embedded in a stream,
        # e.g. a subtype GUID section.
        "setup_offset" / Tell,
        "magic" / Const(b"$SPF"),
        "h1" / Int32ul,
        "h2" / Int32ul,
        "h3" / Int32ul,
        "h4" / Int32ul,
        "guid" / UUID16,
        "offsets" / Array(9, Int32ul),
        # Each of these sections consume all bytes and so FixedLength is ok.
        "section1" / FixedLength(
            lambda ctx: ctx.offsets[2] - ctx.offsets[1], Class(AMISetupSection1)),
        "section2" / FixedLength(
            lambda ctx: ctx.offsets[3] - ctx.offsets[2], Class(AMISetupSection2)),
        "section3" / FixedLength(
            lambda ctx: ctx.offsets[4] - ctx.offsets[3], Class(AMISetupSection3)),
        "section4" / FixedLength(
            lambda ctx: ctx.offsets[5] - ctx.offsets[4], Class(AMISetupSection4)),
        "section5" / FixedLength(
            lambda ctx: ctx.offsets[6] - ctx.offsets[5], Class(AMISetupSection5)),
        "section6" / FixedLength(
            lambda ctx: ctx.offsets[7] - ctx.offsets[6], Class(AMISetupSection6)),
        "section7" / FixedLength(
            lambda ctx: ctx.offsets[8] - ctx.offsets[7], Class(AMISetupSection7)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["magic"], ["h1"], ["h2"], ["h3"], ["h4"], ["guid"], ["setup_offset"],
        ["offsets"],
    ]

# ----------------------------------------------------------------------------------------
class AMITSESetupDataWriteFile(FirmwareStructure):
    """
    Reverse engineered, not authoritative.
    """

    label = "AMI TSE Setup Data "

    definition = Struct(
        "data" / GreedyBytes,
    )

    def analyze(self) -> None:
        fh = open("SetupData.bin", "wb")
        fh.write(self.data)
        fh.close()

# ----------------------------------------------------------------------------------------
class SignOnSection(FirmwareStructure):
    """
    Reverse engineered, not authoritative.
    """

    label = "SignOn Section"

    definition = Struct(
        "magic1" / Const(b"$SGN$"),
        # Maybe a record number?  '2' in practice in my sole sample.
        "u1" / Int8ul,
        # Zero?
        "u2" / Int16ul,
        "copyright" / CString('utf8'),
        "biosdate" / CString('utf8'),
        # This is probably not the right way to handle the alignment.  Still experimenting.
        # 5 bytes in my BIOS, 1 in DellO, 7 in Dell Precision, 1 in Lenovo Thin.
        "padding" / GreedyRange(Const(b'\x00')),
        # Relative to the start of this structure, my BIOS is at 88, DellO is at 120, and
        # Dell Precision is at 128, Lenovo Thin is at 76?, so it's not a fixed offset.
        "magic2" / Const(b"$LGO$"),
        # Another record number? '1' in practice in my sole sample.
        "u3" / Int8ul,
        "u4" / Int32ul,
        "u5" / Int32ul,
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["copyright"], ["biosdate"],
        [], ["magic1"], ["magic2"], ["u1"], ["u2"], ["u3"], ["u4", "0x%x"], ["u5", "0x%x"],
    ]

# ----------------------------------------------------------------------------------------
class JCATBlobKind(Enum):
    UNKNOWN = 0
    SHA256 = 1
    GPG = 2
    PKCS7 = 3
    SHA1 = 4
    BT_MANIFEST = 5
    BT_CHECKPOINT = 6
    BT_INCLUSION_PROOF = 7
    BT_VERIFIER = 8
    ED25519 = 9

# ----------------------------------------------------------------------------------------
class JCATBlobFlags(Enum):
    IS_UTF8 = 1

# ----------------------------------------------------------------------------------------
class JCATBlob(FakeFirmwareStructure):

    label = "JCAT Blob"

    definition = Struct()

    def __init__(self, bdict: dict[str, Any]) -> None:
        super().__init__()
        # Get the fields from the json dict.
        self.kind = JCATBlobKind(bdict["Kind"])
        self.flags = JCATBlobFlags(bdict["Flags"])
        self.timestamp = datetime.fromtimestamp(bdict["Timestamp"])
        # Actually one of several kinds of ASCII armored signatures.  I should probably do
        # more with these in the future.
        data = bdict["Data"]
        if data.find('\n') != -1:
            self.data = TextFile.parse(data.encode('utf8'), 0)
        else:
            self.data = data

    reporting = [
        ["kind"], ["flags"], ["timestamp"], ["data"],
    ]

# ----------------------------------------------------------------------------------------
class JCATItem(FakeFirmwareStructure):

    label = "JCAT Item"

    definition = Struct()

    def __init__(self, idict: dict[str, Any]) -> None:
        super().__init__()
        # Get the fields from the json dict.
        self.name = idict["Id"]
        self.blobs = []
        for blob in idict["Blobs"]:
            self.blobs.append(JCATBlob(blob))

    reporting = [
        ["name"], ["blobs"],
    ]

# ----------------------------------------------------------------------------------------
@promote_exceptions
def check_jcat(ctx: Context) -> Optional[Any]:
    try:
        data = gzip.decompress(ctx._compressed)
        jdict = json.loads(data)
    except (OSError, json.decoder.JSONDecodeError, UnicodeDecodeError):
        return None
    return jdict

# ----------------------------------------------------------------------------------------
class JCATFile(FirmwareStructure):

    label = "JCAT File"

    definition = Struct(
        # The data is gzip compressed JSON.
        "_compressed" / GreedyBytes,
        "_jdict" / Computed(check_jcat),
        Check(lambda ctx: ctx._jdict is not None),
    )

    _major_version: str
    _minor_version: str

    @property
    def version(self) -> str:
        return "%s.%s" % (self._major_version, self._minor_version)

    def analyze(self) -> None:
        self._major_version = self._jdict["JcatVersionMajor"]
        self._minor_version = self._jdict["JcatVersionMinor"]
        self.items = []
        for item in self._jdict['Items']:
            self.items.append(JCATItem(item))

        # Display the raw JSON for debugging.
        #pretty = json.dumps(self._jdict, indent=2)
        #self.json = TextFile.parse(pretty.encode('utf8'), 0)

    reporting = [
        ["version"], ["items"],
    ]

@promote_exceptions
def lazy_auto_object(ctx: Context) -> Class:
    from .auto import AutoObject
    return Class(AutoObject)

# ----------------------------------------------------------------------------------------
class ZipContentFile(FirmwareStructure):

    label = "Zip Content File"

    definition = Struct(
        "data" / LazyBind(lazy_auto_object),
    )

    file_name: str
    file_size: int
    compressed_size: int

    reporting = [
        ["file_name"], ["file_size"], ["compressed_size"], ["data"],
    ]

# ----------------------------------------------------------------------------------------
class ZipFile(HashedFirmwareStructure):
    """
    A Zip File (since some ROM updates are distributed as Zip files).
    """

    label = "Zip File"

    definition = Struct(
        "_magic" / FailPeek(Const(b'PK')),
        "_data" / GreedyBytes,
    )

    def analyze(self) -> None:
        self.files = []
        zf = zipfile.ZipFile(io.BytesIO(self._data))
        for info in zf.infolist():
            stream = zf.open(info.filename)
            stream_bytes = stream.read()
            zcf = ZipContentFile.parse(stream_bytes, 0)
            if zcf is not None:
                zcf.file_name = info.filename
                zcf.file_size = info.file_size
                zcf.compressed_size = info.compress_size
            self.files.append(zcf)

    sbom_fields = ["fshash"]

# ----------------------------------------------------------------------------------------
class MicrosoftCabinetContentFile(FakeFirmwareStructure, HashedFirmwareStructure):

    label = "Microsoft Cabinet Content File"

    file_name: str
    size: int
    date_time: Optional[datetime]
    content: Any
    attributes: int

# ----------------------------------------------------------------------------------------
class MicrosoftCabinetFile(HashedFirmwareStructure):
    """
    A Microsoft cabinet file (a common update distribution format).
    """

    label = "Microsoft Cabinet File"

    definition = Struct(
        "_magic" / FailPeek(Const(b'MSCF')),
        "_data" / GreedyBytes,
    )

    def analyze(self) -> None:
        from .auto import AutoObject
        from .finder import FirmwareVolumeFinder
        self.files = []
        cf = CabFile(io.BytesIO(self._data))
        for info in cf.infolist():
            stream = cf.open(info.filename)
            if stream is None:
                continue
            stream_bytes = stream.read()
            auto_object = AutoObject.parse(stream_bytes, 0)
            content = MicrosoftCabinetContentFile(info.file_size, stream_bytes)
            content.content = None
            content.file_name = info.filename
            content.size = info.file_size
            content.attributes = info.attributes
            # Convert tuple of ints to a datetime.
            content.date_time = None
            if info.date_time != (1980, 0, 0, 0, 0, 0):
                try:
                    dt = datetime(*info.date_time)
                    content.date_time = dt
                except ValueError:
                    self.warn("Bad date time in cab file %s" % str(info.date_time))

            # This is pretty hacky.  But it's mostly a placeholder to do something
            # better and more interesting.
            if auto_object is not None:
                if (content.file_name.endswith(".inf")
                        and isinstance(auto_object.auto, FirmwareVolumeFinder)):
                    content.content = INIConfigFile.parse(stream_bytes, 0)
                else:
                    content.content = auto_object.auto

            self.files.append(content)

    sbom_fields = ["fshash"]

    reporting = [["fshash"], ["files"]]

# ----------------------------------------------------------------------------------------
class DellBIOSMZ_Header(FirmwareStructure):

    label = "Dell BIOS Header"

    definition = Struct(
        # Apparently a new guid for each file, so it's not "magic", it's more like
        # fingerprint ID I guess.
        "guid" / UUID16,
        "offset" / Int32ul,  # Always 4096 in practice?
        "u1" / Int16ul,  # Always 0 in practice?
        "u2" / Int16ul,  # Always 7 in practice?
        "size" / Int32ul,
        # this is effectively the "magic" for this structure.  A bunch of zeros followed
        # by an MZ header at the location predicted by offset.  Not exactly "magic", but
        # probably good enough to prevent false positives.
        "_zero_padding" / FixedLength(this.offset - 28, GreedyRange(Const(b'\x00'))),
        "_mzheader" / FailPeek(Const(b'MZ')),
    )

    reporting = [
        ["guid"], ["offset"], ["size"], ["u1"], ["u2"],
    ]

# ----------------------------------------------------------------------------------------
class DellBIOSMZ(FirmwareStructure):
    """
    A Dell BIOS update distributed as something?
    """

    label = "Dell BIOS MZ"

    definition = Struct(
        "header" / Class(DellBIOSMZ_Header),
        "exe" / Class(DellUpdaterExecutable),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["header"], ["exe"], ["unexpected"],
    ]

# ----------------------------------------------------------------------------------------
class OpenTypeTable(FirmwareStructure):
    """
    An OpenType table record.
    """

    label = "OpenType Table"

    definition = Struct(
        "tag" / PaddedString(4),
        "checksum" / Int32ub,
        "offset" / Int32ub,
        "length" / Int32ub,
    )

    reporting = [["tag"], ["checksum", "0x%08x"], ["offset", "0x%08x"], ["length"]]

    def instance_name(self) -> str:
        return str(self.tag)

# ----------------------------------------------------------------------------------------
class OpenTypeFont(FirmwareStructure):
    """
    An OpenType font file.
    """

    label = "OpenType Font File"

    definition = Struct(
        "magic" / Const(b'OTTO'),
        "failure" / CommitMystery,
        "num_tables" / Int16ub,
        "search_range" / Int16ub,
        "entry_selector" / Int16ub,
        "range_shift" / Int16ub,
        "tables" / Array(this.num_tables, Class(OpenTypeTable)),
        "_data" / Class(MysteryBytes),
    )

    reporting = [
        ["magic"], ["num_tables"], ["search_range"], ["entry_selector"], ["range_shift"],
        ["tables"],
    ]


# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
