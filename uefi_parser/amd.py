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
Structures relating to AMD specific ROMs, including AMD's Platform Security Processor
(PSP).
"""

import zlib
from enum import Flag
from uuid import UUID
from typing import Optional, Union

from construct import (
    Bytes, Computed, Const, GreedyRange, GreedyBytes, Pointer, Sequence, Terminated,
    Select, Array, Int8ul, Int8sl, Int16ul, Int16sl, Int32ul, Int32sl, Int64ul, Int64sl,
    Switch, Construct, Check, Peek, Tell, this)

from .base import (
    FirmwareStructure, FixedLength, Class, Struct, SafeFixedLength, promote_exceptions,
    UUID16, FailPeek, LazyBind, Until, HexBytes, Opt, Context, EnumAdapter)
from .uenum import UEnum
from .mystery import MysteryBytes, CommitMystery, MysteryHexPeek, HexDump
from .finder import FirmwareVolumeFinder

# ----------------------------------------------------------------------------------------
class EntryType(UEnum):
    AMD_PUBLIC_KEY              = 0x00
    PSP_FW_BOOT_LOADER          = 0x01
    PSP_FW_TRUSTED_OS           = 0x02
    PSP_FW_RECOVERY_BOOT_LOADER = 0x03
    PSP_NV_DATA                 = 0x04
    BIOS_PUBLIC_KEY             = 0x05
    BIOS_RTM_FIRMWARE           = 0x06
    BIOS_RTM_SIGNATURE          = 0x07
    SMU_OFFCHIP_FW              = 0x08
    SEC_DBG_PUBLIC_KEY          = 0x09
    OEM_PSP_FW_PUBLIC_KEY       = 0x0a
    SOFT_FUSE_CHAIN             = 0x0b
    PSP_BOOT_TIME_TRUSTLETS     = 0x0c
    PSP_BOOT_TIME_TRUSTLETS_KEY = 0x0d
    PSP_AGESA_RESUME_FW         = 0x10
    SMU_OFF_CHIP_FW_2           = 0x12
    DEBUG_UNLOCK                = 0x13
    _PSP_MCLF_TRUSTLETS         = 0x14
    PSP_S3_NV_DATA              = 0x1a
    _TYPE_0x20                  = 0x20
    WRAPPED_IKEK_0x21           = 0x21
    TOKEN_UNLOCK                = 0x22
    SEC_GASKET                  = 0x24
    MP2_FW                      = 0x25
    DRIVER_ENTRIES              = 0x28  # Starts with \x00\x02 and zeros.
    _TYPE_0x29                  = 0x29
    _TYPE_0x2a                  = 0x2a
    _TYPE_0x2b                  = 0x2b
    _TYPE_0x2c                  = 0x2c
    S0I3_DRIVER                 = 0x2d  # Starts with \x00\x02 and zeros.
    _TYPE_0x2e                  = 0x2e
    _TYPE_0x2f                  = 0x2f
    ABL0                        = 0x30
    ABL1                        = 0x31
    ABL2                        = 0x32
    ABL3                        = 0x33
    ABL4                        = 0x34
    ABL5                        = 0x35
    ABL6                        = 0x36
    ABL7                        = 0x37
    _PSP_ENCRYPTED_NV_DATA      = 0x38
    FW_PSP_WHITELIST            = 0x3a
    _TYPE_0x3c                  = 0x3c
    PL2_DIRECTORY_0x40          = 0x40
    FW_IMC_1                    = 0x41
    FW_GEC_1                    = 0x42
    FW_XHCI_1                   = 0x43
    FW_INVALID_1                = 0x44
    _TYPE_0x45                  = 0x45
    ANOTHER_FET                 = 0x46
    _TYPE_0x47                  = 0x47  # Starts with \x00\x02 and zeros.
    PL2_DIRECTORY_0x48          = 0x48
    BL2_DIRECTORY_0x49          = 0x49
    PL2_DIRECTORY_0x4a          = 0x4a
    _TYPE_0x4c                  = 0x4c
    _TYPE_0x4d                  = 0x4d
    _TYPE_0x4e                  = 0x4e
    KEY_DATABASE_0x50           = 0x50
    KEY_DATABASE_0x51           = 0x51
    _TYPE_0x54                  = 0x54
    _TYPE_0x55                  = 0x55  # Starts with \x16 and zeros.
    _TYPE_0x56                  = 0x56  # Starts with \x16 and zeros.
    _TYPE_0x57                  = 0x57
    _TYPE_0x58                  = 0x58
    _TYPE_0x59                  = 0x59
    _TYPE_0x5a                  = 0x5a  # Starts \x02\x00
    _TYPE_0x5c                  = 0x5c  # Starts with 0x1 and 0x12 dwords.
    FW_PSP_SMUSCS               = 0x5f  # Starts with 0x1 and 0x12 dwords.
    APCB_DATA                   = 0x60
    # Coreboot says: APOB = AGESA PSP Output Buffer
    #   A buffer in main memory for storing AGESA BootLoader output.
    APOB_DATA                   = 0x61
    BIOS_RESET_IMAGE            = 0x62
    APOB_NV                     = 0x63
    PMU_FIRMWARE_CODE           = 0x64  # Starts \x02\x00
    PMU_FIRMWARE_DATA           = 0x65  # Starts \x02\x00
    X86_MICROCODE               = 0x66
    APCB_DATA_BACKUP            = 0x68
    MP2_FW_CONFIG               = 0x6a  # Starts \x16
    _TYPE_0x6d                  = 0x6d
    BL2_DIRECTORY_0x70          = 0x70
    _TYPE_0x71                  = 0x71  # \x00\xc5I
    _TYPE_0x72                  = 0x72
    _TYPE_FW_0x73               = 0x73
    _TYPE_0x74                  = 0x74
    _TYPE_0x76                  = 0x76
    _TYPE_0x85                  = 0x85  # Leading zeros and 0x08, 0x10
    _TYPE_0x86                  = 0x86
    _TYPE_0x87                  = 0x87
    _TYPE_WLAN_0x88             = 0x88
    _TYPE_0x89                  = 0x89  # Starts with \x00\x02 and zeros.
    WRAPPED_IKEK_0x8d           = 0x8d
    AMD_AFCT_0x98               = 0x98

# ----------------------------------------------------------------------------------------
class AMDAddressMode(UEnum):
    PhysicalAddress = 0x0
    BIOSStart       = 0x1
    DirectoryHeader = 0x2
    CurrentPosition = 0x3

# ----------------------------------------------------------------------------------------
class PSPDirectoryTableEntry(FirmwareStructure):
    """
    Platform Security Processor (PSP) Directory Table Entry

    https://doc.coreboot.org/soc/amd/psp_integration.html
    """

    label = "PSP Directory Table Entry"

    definition = Struct(
        "etype" / EnumAdapter(Int8ul, EntryType),
        "dirbase" / Computed(lambda ctx: ctx._._dirbase),
        "subprogram" / Int8ul,
        "reserved" / Int16ul,
        "size" / Int32sl,
        "_location" / Int64ul,
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    _location: int
    dirbase: int

    @property
    def address_mode(self) -> AMDAddressMode:
        if self._location < 0xffffffff:
            return AMDAddressMode(self._location & 0x3)
        else:
            return AMDAddressMode(self._location >> 62)

    @property
    def stream_offset(self) -> int:
        # If the location is of the form 0xffXXXXXX, only the XXXXXX represents the file
        # offset.  In some files, the location uses this byte for part of the address,
        # (e.g. 0x100000000), but it's never 0xff in those cases to my knowledge.  It
        # would have to be a _very_ large ROM image for that to work.
        modified_location: int = self.location
        if self.location & 0xffffff000000 == 0xff000000:
            modified_location &= 0xffffff

        if self.address_mode == AMDAddressMode.DirectoryHeader:
            return modified_location + self.dirbase
        elif self.address_mode == AMDAddressMode.BIOSStart:
            # Unlike BIOS directories, it seems to be fine to just return the "usual"
            # offset here.  It seem very likely that there's some subtle issue I'm still
            # misunderstanding though.
            return modified_location
        else:
            return modified_location

    @property
    def location(self) -> int:
        # Mask off the address_mode bits.
        if self._location < 0xffffffff:
            return self._location & 0xffffffffffffffc0
        else:
            return self._location & 0xfffffffffffffff

    reporting = [
        ["location", "0x%08x"], ["size", "0x%06x"], ["subprogram"],
        ["reserved"],
        ["etype"], ["address_mode"], ["dirbase", "0x%x"], ["stream_offset", "0x%x"],
    ]

    def instance_name(self) -> str:
        return "0x%08x" % self.location

# ----------------------------------------------------------------------------------------
class PSPDirectoryTable(FirmwareStructure):

    label = "$PSP Directory"

    definition = Struct(
        "_dirbase" / Tell,
        "magic" / Bytes(4),
        Check(lambda ctx: ctx.magic in [b'$PSP', b'$PL2']),
        # PSPTool knows how to verify and generate these checksums!
        "checksum" / Int32ul,
        "count" / Int32ul,
        "u1" / Int32ul,
        "entries" / Array(this.count, Class(PSPDirectoryTableEntry)),
        #"data" / FixedLength((6*32)-(4+4+4+4), Class(HexDump)),
    )

    reporting = [
        ["magic"], ["checksum", "0x%x"], ["count"], ["u1", "0x%x"], ["entries"],
    ]

# ----------------------------------------------------------------------------------------
class BIOSDirectoryEntryFlags(Flag):
    NoFlags    = 0x0000
    ResetImage = 0x0001
    CopyImage  = 0x0002
    ReadOnly   = 0x0004
    Compressed = 0x0008
    Writable   = 0x2000

# ----------------------------------------------------------------------------------------
class BIOSDirectoryTableEntry(FirmwareStructure):
    """
    BIOS Directory Table Entry

    https://doc.coreboot.org/soc/amd/psp_integration.html
    """

    label = "BIOS Directory Table Entry"

    definition = Struct(
        "etype" / EnumAdapter(Int16ul, EntryType),
        "dirbase" / Computed(lambda ctx: ctx._._dirbase),
        # Several bit fields packed into one 16-bit integer.
        "_multi" / Int16ul,
        "size" / Int32ul,
        "_src_addr" / Int64ul,
        "dest_addr" / Int64sl,
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    _multi: int
    _src_addr: int
    dirbase: int

    @property
    def flags(self) -> BIOSDirectoryEntryFlags:
        return BIOSDirectoryEntryFlags(self._multi & 0xe00f)

    @property
    def instance(self) -> int:
        return (self._multi & 0x00f0) >> 4

    @property
    def subprogram(self) -> int:
        return (self._multi & 0x0700) >> 8

    @property
    def romid(self) -> int:
        return (self._multi & 0x1800) >> 10

    @property
    def address_mode(self) -> AMDAddressMode:
        return AMDAddressMode(self._src_addr >> 62)

    @property
    def stream_offset(self) -> int:
        # If the src addr is of the form 0xffXXXXXX, only the XXXXXX represents the file
        # offset.  In some files, the src_addr uses this byte for part of the address,
        # (e.g. 0x100000000), but it's never 0xff in those cases to my knowledge.  It
        # would have to be a _very_ large ROM image for that to work.
        modified_src_addr = self.src_addr
        if self.src_addr & 0xffffff000000 == 0xff000000:
            modified_src_addr &= 0xffffff

        if self.address_mode == AMDAddressMode.DirectoryHeader:
            return modified_src_addr + self.dirbase
        elif self.address_mode == AMDAddressMode.BIOSStart:
            # Unlike PSP directories, it seems that we need to disable reporting of these
            # entries, because they overlap with addresses that are better interpreted as
            # FFS Volumes.  Clearly there's something I don't understand here...
            return 0
        else:
            return modified_src_addr

    @property
    def src_addr(self) -> int:
        # Mask off the address_mode bits.
        return self._src_addr & 0xfffffffffffffff

    reporting = [
        ["src_addr", "0x%010x"], ["dest_addr", "0x%08x"], ["size", "0x%06x"],
        ["instance", "0x%x"], ["subprogram", "0x%x"], ["romid", "0x%x"],
        [], ["etype"], ["flags"],
        ["address_mode"], ["dirbase", "0x%x"], ["stream_offset", "0x%x"],
    ]

    def instance_name(self) -> str:
        return "0x%08x" % self.src_addr

# ----------------------------------------------------------------------------------------
class BIOSDirectoryTable(FirmwareStructure):
    """
    BIOS Directory Table

    https://doc.coreboot.org/soc/amd/psp_integration.html
    """

    label = "BIOS Directory ($BHD)"

    definition = Struct(
        "_dirbase" / Tell,
        "magic" / Bytes(4),
        Check(lambda ctx: ctx.magic in [b'$BHD', b'$BL2']),
        # PSPTool knows how to verify and generate these checksums!
        "checksum" / Int32ul,
        "count" / Int32ul,
        "reserved" / Int32ul,
        "entries" / Array(this.count, Class(BIOSDirectoryTableEntry)),
    )

    reporting = [["magic"], ["checksum", "0x%x"], ["count"], ["reserved"], ["entries"]]

# ----------------------------------------------------------------------------------------
class AMDPublicKey(FirmwareStructure):

    label = "AMD Public Key"

    definition = Struct(
        "version" / Int32ul,
        Check(lambda ctx: ctx.version == 1),
        "keyid" / HexBytes(16),
        "certid" / HexBytes(16),
        "usage" / Int32ul,
        "u1" / Int32ul,
        "u2" / Int32ul,
        "u3" / Int32ul,
        "u4" / Int32ul,
        "pub_bits" / Int32ul,
        "mod_bits" / Int32ul,
        "pubexp" / Bytes(lambda ctx: int(ctx.pub_bits / 8)),
        "modulus" / Bytes(lambda ctx: int(ctx.mod_bits / 8)),
        # PSPTool calculated the signature length of the Directory Entry size.  This is
        # less principled but would make the size of the object self identifying, and it's
        # reasonable to presume that the signature is 512 bytes.  But is usage the correct
        # way to tell if the signature is present?  Maybe u1?
        # BUG! FIXME! PSPTool knows how to validate this signature!
        "sig" / GreedyBytes,
        "siglen" / Computed(lambda ctx: len(ctx.sig)),
    )

    reporting = [
        ["version"], ["usage"], ["pub_bits"], ["mod_bits"],
        ["u1"], ["u2"], ["u3"], ["u4"], ["siglen"],
        [], ["keyid"], ["certid"],
        ["sig", None],
        ["pubexp", None], ["modulus", None],
    ]

# ----------------------------------------------------------------------------------------
class SMUFirmware(FirmwareStructure):

    label = "SMU Firmware"

    definition = Struct(
        "magic" / Const(b'\x00G7\x00\x00G7\x00'),
        "data" / Class(MysteryBytes),
    )

    def analyze(self) -> None:
        self.data.label = "SMU Firmware Mystery Bytes"

# ----------------------------------------------------------------------------------------
class PMUFirmware(FirmwareStructure):

    label = "PMU Firmware"

    definition = Struct(
        "magic" / Const(b'BPPA \x00\x00\x00'),
        "data" / Class(MysteryBytes),
    )

    def analyze(self) -> None:
        self.data.label = "PMU Firmware Mystery Bytes"

# ----------------------------------------------------------------------------------------
class KeyDatabaseRecord(FirmwareStructure):

    label = "Key Database Record"

    definition = Struct(
        "u1" / Int32ul,
        "u2" / Int32ul,
        "u3" / Int32ul,
        "u4" / Int16ul,
        "u5" / Int16ul,
        "keyid" / HexBytes(16),
        "bits" / Int16ul,
        "_zeros" / Bytes(46),
        "key" / Bytes(lambda ctx: int(ctx.bits / 8)),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    _zeros: bytes

    @property
    def zeros(self) -> Optional[bytes]:
        "Remove lots of zeros from output.  Perhaps replace with a warning generator?"
        if self._zeros == b'\x00' * 46:
            return None
        else:
            return self._zeros

    reporting = [
        ["u1", "0x%x"], ["u2"], ["u3", "%3d"], ["u4"], ["u5"], ["bits"],
        ["keyid"], ["zeros"], ["key", None],
    ]

# ----------------------------------------------------------------------------------------
class KeyDatabase(FirmwareStructure):

    label = "Key Database"

    definition = Struct(
        "size" / Int32ul,
        # Maybe?
        "version" / Int32ul,
        "magic" / Const(b'$KDB'),
        "_zeros" / Bytes(68),
        "records" / GreedyRange(Class(KeyDatabaseRecord)),
        "unexpected" / Class(MysteryBytes),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    _zeros: bytes

    @property
    def zeros(self) -> Optional[bytes]:
        "Remove lots of zeros from output.  Perhaps replace with a warning generator?"
        if self._zeros == b'\x00' * 68:
            return None
        else:
            return self._zeros

    reporting = [
        ["magic"], ["size"], ["version"], ["zeros"], ["records"], ["unexpected"],
    ]

# ----------------------------------------------------------------------------------------
class AMD_AFCT(FirmwareStructure):

    label = "AMD AFCT"

    definition = Struct(
        "magic" / Const(b'AFCT'),
        "u1" / Int32ul,
        "u2" / Int32ul,
        "u3" / Int8ul,
        "unexpected" / GreedyBytes,
    )

# ----------------------------------------------------------------------------------------
class AMDEntry(FirmwareStructure):

    label = "AMD Entry"

    definition = Struct(
        # Prevent AMDEntry from matching all FF bytes since there's no magic.
        "_peek_ffs" / Peek(Bytes(256)),
        Check(lambda ctx: ctx._peek_ffs != b'\xff' * 256),
        # Start of actual structure.
        "guid" / UUID16,
        "magic" / Bytes(4),               # 0x10-0x14
        #"failure" / CommitMystery,
        "body_size" / Int32ul,            # 0x14-0x18
        "encrypted" / Int32ul,            # 0x18-0x1c
        "u1" / Int32ul,                   # 0x1c-0x20
        "iv" / HexBytes(16),              # 0x20-0x30
        "signed" / Int32ul,               # 0x30-0x34
        "two" / Int32ul,                  # 0x34-0x38
        # Also maybe signature fingerprint?
        "certid" / HexBytes(16),
        "compressed" / Int32ul,           # 0x48-0x4c
        "has_sha256" / Int32ul,           # 0x4c-0x50
        "uncompressed_size" / Int32ul,    # 0x50-0x54
        "zlib_size" / Int32ul,            # 0x54-0x58
        "flags" / Int32ul,                # 0x58-0x5c
        "z1" / Int32ul,                   # 0x5c-0x60
        "versions" / Array(4, Int8ul),    # 0x60-0x64
        "load_addr" / Int32sl,            # 0x64-0x68
        "u3" / Int32ul,                   # 0x68-0x6c
        "rom_size" / Int32ul,             # 0x6c-0x70
        "z2" / Int64ul,                   # 0x70-0x78
        "z3" / Int32ul,                   # 0x78-0x7c
        "subtype" / EnumAdapter(Int8ul, EntryType),  # 0x7c-0x7d
        "u4" / Int8sl,                    # 0x7d-0x7e
        "u5" / Int16ul,                   # 0x7e-0x80
        "wrapped_key" / HexBytes(16),     # 0x80-0x90
        "z4" / UUID16,                    # 0x90-0xa0
        "z5" / UUID16,                    # 0xa0-0xb0
        "z6" / UUID16,                    # 0xb0-0xc0
        "z7" / UUID16,                    # 0xc0-0xd0
        # Order might be wrong here, haven't checked yet.
        "sha256" / HexBytes(32),          # 0xd0-0xf0
        "z8" / UUID16,                    # 0xf0-0x100
        # End of the header portion (size 256 bytes)

        "comp_size" / Computed(lambda ctx: ctx.zlib_size if ctx.zlib_size != 0 else ctx.body_size),
        "data_size" / Computed(lambda ctx: ctx.comp_size if ctx.compressed else ctx.body_size),
        "ref_size" / Computed(
            lambda ctx: ctx.rom_size if ctx.rom_size != 0 else ctx.data_size + 512),
        "sig_size" / Computed(
            # The header size is 256 bytes.
            lambda ctx: ctx.ref_size - ctx.data_size - 256 if ctx.signed else 0),

        # Read the data and signature.  These are not really optional, but I've had enough
        # trouble with invalid lengths causing failures here, that I've made them optional
        # to aid in debugging.  I should probably make them non-optional at some point.
        "data" / Opt(FixedLength(this.data_size, Class(MysteryBytes))),
        # This isn't quite right on subtype=0x50 (KEYSTORE)...
        "signature" / Opt(FixedLength(this.sig_size, Class(MysteryBytes))),
    )

    reporting = [
        ["magic"], ["etype"], ["subtype"], ["flags", "0x%x"],
        [], ["rom_size"], ["body_size"], ["uncompressed_size"], ["zlib_size"],
        ["data_size"], ["sig_size"],
        [], ["certid"], ["has_sha256"], ["sha256"],
        [], ["encrypted"], ["signed"], ["compressed"], ["two"], ["u1"],
        ["version"], ["versions", None], ["load_addr"], ["u3"], ["u4"], ["u5"],
        [], ["z1"], ["z2"], ["z3"], ["z4"], ["z5"], ["z6"], ["z7"], ["z8"],
        [], ["iv"], ["wrapped_key"],
        ["guid"],
        # Data is not reported.  The interpretation of the data is reported instead.
        ["data", None], ["interpretation"],
    ]

    interpretation: Optional[Union[KeyDatabase, SMUFirmware, PMUFirmware, MysteryBytes]] = None
    etype: Optional[EntryType]

    @property
    def version(self) -> str:
        return ".".join(["%X" % v for v in reversed(self.versions)])
        # But for most record types, the version is in hexadecimal?
        #return ".".join(["%s" % v for v in self.versions])

    def analyze(self) -> None:
        """
        Presumes that that header was validated using one of several "magic" values, and then
        the data and signature were read immediately following the header.  Put here so we
        can share code for decompression and other analysis while sorting out the magic
        issues.
        """
        # The type should be set by the code that parsed the entry (typically
        # process_directory).  See set_type() below.  We can't compute it from the context
        # because we're being invoking by custom logic that doesn't have a construct
        # context. :-( The value can also continue to be None if the AMDEntry was detected
        # by the $PS1 magic rather and appearing in a directory.
        self.etype = None

        if self.signature is not None:
            self.signature.label = "Signature"
        self.interpretation = self.data
        if self.data is not None:
            self.data.label = "Mystery Bytes (AMD Entry)"
        else:
            return

        #if self.subtype != self.etype:
        #    self.debug("Mismatched types %s != %s" % (self.subtype, self.etype))

        # This is the data that we'll try to interpret.
        raw_data = self.data.data
        # This is the decompressed data if the data was compressed.
        decompressed_data = None
        if self.compressed:
            #decompressed_data = zlib_decompress(self.data.data)
            try:
                decompressed_data = zlib.decompress(self.data.data)
                raw_data = decompressed_data
            except zlib.error as e:
                self.error(f"ZLIB decompression failed {e}")

        #global_decomp_counter = 1
        #global global_decomp_counter
        #fh = open("decomp_%03d.bin" % global_decomp_counter, "wb")
        #global_decomp_counter += 1
        #fh.write(decompressed_data)
        #fh.close()

        # Attempt to interpret the data...
        if self.subtype in [EntryType.KEY_DATABASE_0x50,
                            EntryType.KEY_DATABASE_0x51]:
            self.interpretation = KeyDatabase.parse(raw_data, 0)
        else:
            self.interpretation = SMUFirmware.parse(raw_data, 0)
            if self.interpretation is None:
                self.interpretation = PMUFirmware.parse(raw_data, 0)

        if self.interpretation is None:
            self.interpretation = MysteryBytes.parse(raw_data, 0)
            if self.interpretation is not None:
                if decompressed_data is None:
                    self.interpretation.label = "Mystery Bytes (Raw Data)"
                else:
                    self.interpretation.label = "Mystery Bytes (Decompressed Data)"

    def set_type(self, typeval: Optional[EntryType]) -> None:
        """
        Called to set the type and invoke the correct analysis after the object has been
        constructed.
        """
        self.etype = typeval
        if self.etype in [EntryType.KEY_DATABASE_0x50, EntryType.KEY_DATABASE_0x51]:
            self.interpretation = KeyDatabase.parse(self.data.data, 0)

    # Subtypes:
    #  0x01 = at 0x143400 (PSP_FW_BOOT_LOADER), ARM?
    #  0x02 = at 0x153100 (PSP_FW_TRUSTED_OS), ARM?
    #  0x03 = at 0x041900 (PSP_FW_RECOVERY_BOOT_LOADER), ARM32 (v8?) code module.
    #  0x08 = SMU firmware
    #  0x0c = at 0x188e00 (PSP_BOOT_TIME_TRUSTLETS)
    #  0x12 = SMU firmware
    #  0x13 = at 0x1b6700 (DEBUG_UNLOCK)
    #  0x24 = at 0x080000 (SEC_GASKET), at 0x1ba000 (SEC_GASKET)
    #  0x25 = at 0x1bcf00 (MP2_FW), at 0x49b600 (MP2_FW_CONFIG)
    #  0x28 = at 0x1e7800 (DRIVER_ENTRIES)
    #  0x50 = $KDB keystore
    #  0x51 = $KDB keystore
    #  0x64 = PMU firmware
    #  0x65 = PMU firmware

    # Skips:
    #  0x0f9900 Length 256, BIOS_RTM_SIGNATURE
    #  0x1b8800 Length 1024,
    #  0x1b8c00 Lengths 612, and 16 at 0x1b8f00 (WRAPPED_IKEK_0x21)
    #  0x473900 Length 256, BIOS_RTM_SIGNATURE

# ----------------------------------------------------------------------------------------
# Fancy code searching for zlib headers inside the data blobs -- Always results in offset
# zero in my initial sample.
def zlib_find_header(s: bytes) -> int:
    """Checks s for any zlib magic bytes and returns the offset (or -1)."""

    # The order is important here, as 78da is the most common magic and others might produce
    # false positives
    ZLIB_TYPES = {
        b'\x78\xda': 'Zlib compressed data, best compression',
        b'\x78\x9c': 'Zlib compressed data, default compression',
        b'\x78\x5e': 'Zlib compressed data, compressed',
        b'\x78\x01': 'Zlib header, no compression'
    }

    # Only check the first 0x500 bytes, as the rest is too unlikely to be valid
    s = s[:0x500]

    for zlib_magic in ZLIB_TYPES.keys():
        # Check the most common location at 0x100 first to avoid false positives and save time
        if s[0x100:0x102] == zlib_magic:
            return 0x100

        zlib_start = s.find(zlib_magic)

        if zlib_start != -1:
            return zlib_start

    return -1

def zlib_decompress(s: bytes) -> bytes:
    """
    Checks s for the first appearance of a zlib header and returns the uncompressed start
    of s as well as the decompressed section. If no zlib header is found, s is returned as
    is.
    """

    zlib_start = zlib_find_header(s)

    if zlib_start != -1:
        #log.debug("Found zlib start at offset %s" % (zlib_start))
        uncompressed = s[:zlib_start]
        compressed = s[zlib_start:]
        decompressed = zlib.decompress(compressed)

        return uncompressed + decompressed

    return s

# ----------------------------------------------------------------------------------------
class WrappedIKEK(FirmwareStructure):
    """
    Intermediate Key Encryption Key, used to decrypt encrypted firmware images. This is
    mandatory in order to support encrypted firmware.
    """

    label = "Wrapped IKEK"

    definition = Struct(
        # Often 16 bytes, but also sometimes 48 bytes?
        "key_bytes" / GreedyBytes,
        "key" / Computed(lambda ctx: ctx.key_bytes.hex())
    )

    reporting = [["key"], ["key_bytes", None]]

# ----------------------------------------------------------------------------------------
ABL_GUID = UUID('99b465cf-da6c-f042-9e91-782ff843874f')
class ABL0Record(FirmwareStructure):

    label = "ABL0 Record"

    definition = Struct(
        # FIXME! This is probably not the right way to detect this object!
        "u1" / UUID16,
        "u2" / Int8ul,
        "u3" / Int8ul,
        "u4" / Int16ul,
        "u5" / Int32ul,
        "u6" / Int64ul,
        "u7" / UUID16,
        "u8" / Int32ul,
        "u9" / Int32ul,
        "_magic_guid" / FailPeek(Const(ABL_GUID.bytes_le)),
        "guid" / UUID16,
        "u10" / Int32ul,
        "u11" / Int32ul,
        "u12" / Int32ul,
        "u13" / Int32ul,
        "u14" / Int64ul,
        "extra" / Class(MysteryBytes),
    )

    reporting = [
        ["u2", "%2d"], ["u3", "%2d"], ["u4", "0x%04x"], ["u5", "%5d"], ["u5", "%5d"],
        ["u12", "%5d"], ["u13"], ["guid"],
        [], ["u10"], ["u11"], ["u6"], ["u8"], ["u9"], ["u14"], ["u1"], ["u7"],

    ]

# ----------------------------------------------------------------------------------------
class AGESABootLoader(FirmwareStructure):
    """
    AMD Generic Encapsulated Software Architecture (AGESA) Boot Loader (ABL)

    https://en.wikipedia.org/wiki/AGESA
    https://doc.coreboot.org/soc/amd/psp_integration.html
    """

    label = "AGESA Boot Loader (ABL)"

    definition = Struct(
        # FIXME! This is probably not the right way to detect this object!
        "_magic_guid" / FailPeek(Sequence(Bytes(56), Const(ABL_GUID.bytes_le))),
        "_data" / GreedyBytes,
    )

    reporting = [["records"], ["extra"]]

    def analyze(self) -> None:
        self.records = []
        self.extra = None
        end = 0
        pattern = ABL_GUID.bytes_le
        match = self._data.find(pattern)
        while match != -1:
            # The record starts 56 bytes before the guid.
            start = match - 56
            # Find the start of the next record.
            nextrec = self._data.find(pattern, match+10)
            if nextrec != -1:
                # This record ends 56 bytes before the beginning of the next.
                end = nextrec - 56
            else:
                end = len(self._data)
            rec = self.subparse(ABL0Record, "_data", start, end)
            self.records.append(rec)
            # Repeat the search just past where we found the current record.
            match = nextrec
        self.extra = self.subparse(HexDump, "_data", end)

# ----------------------------------------------------------------------------------------
class AGESABootLoaderAlt(FirmwareStructure):
    """
    An alternate magic for the BootLoader.

    If this is the same structure as the earlier one, it will also need to recognize the guid
    '7ea6bb60-431a-6b4c-9807-bc8dfdb41f40' as ABL_GUID.
    """

    label = "AGESA Boot Loader (ABL)"

    definition = Struct(
        "u1" / UUID16,
        "magic" / Const(b'AW0B'),
        "u5" / Int32ul,
        "u6" / Int64ul,
        "u7" / UUID16,
        "u8" / Int32ul,
        "u9" / Int32ul,
        "magic_guid" / UUID16,
        "guid" / UUID16,
        "u10" / Int32ul,
        "u11" / Int32ul,
        "u12" / Int32ul,
        "u13" / Int32ul,
        "u14" / Int64ul,
        "extra" / Class(MysteryBytes),
    )

    reporting = [["magic"], ["magic_guid"]]


# ----------------------------------------------------------------------------------------
class AGESABootLoaderEntry(FirmwareStructure):
    """
    This version of the AEGSA BootLoader entry has an AMD Entry Header, but it's too small
    to contain the actual bootloader, and has bytes after the entry without much in the
    way of headers.

    This entry has no magic, so it always matches. :-(
    """

    label = "AGESA Boot Loader (ABL)"

    definition = Struct(
        "entry" / Class(AMDEntry),
        # Consume the remaining bytes that the directory said were part of this entry.
        "loader" / Class(MysteryBytes),
    )

    def analyze(self) -> None:
        self.loader.label = "Mystery Bytes (ABL Loader)"

# ----------------------------------------------------------------------------------------
class AGESABootLoaders(FirmwareStructure):
    """
    A hacky little wrapper to catch multiple variants of the AGESA Bootloader.  The hope
    is that since both are so poorly understood, this hack will eventually go away, and
    they'll turn out to be the same structure (more or less).  Later I discovered that
    some files have a proper AMDEntry header in this location as well.
    """

    label = "AGESA Boot Loader (ABL) Wrapper"

    definition = Struct(
        "bootloader" / Select(
            Class(AGESABootLoaderAlt),
            Class(AGESABootLoader),
            Class(AGESABootLoaderEntry),
        ),
    )

    reporting = [["bootloader"]]

# ----------------------------------------------------------------------------------------
class APCB_Thing(FirmwareStructure):

    label = "APCB Thing"

    definition = Struct(
        "u1" / Int32ul,
        "u2" / Int16ul,
        "u3" / Int16sl,
        "u4" / Class(MysteryBytes),
    )

    reporting = [["u1", "0x%x"], ["u2"], ["u3"], ["u4"]]

# ----------------------------------------------------------------------------------------
class APCBSubRecord(FirmwareStructure):
    """
    This is probably really a header on several sub-record types because the
    interpretation of the data seems to vary according to block that the subrecord was
    found in.  But this level of detail is sufficient to know how many bytes to read.
    """

    label = "APCB Sub-record"

    definition = Struct(
        "u1" / Int8ul,
        "u2" / Int8ul,
        "u3" / Int16ul,
        "size" / Int32ul,
        "data" / FixedLength(this.size - 8, Class(APCB_Thing)),
    )

    reporting = [["size", "%4d"], ["u1"], ["u2"], ["u3"], ["data"]]

# ----------------------------------------------------------------------------------------
class APCB_BCPA(FirmwareStructure):

    label = "APCB BCPA Block"

    definition = Struct(
        "magic" / Const(b'BCPA'),
    )

# ----------------------------------------------------------------------------------------
class APCB_BCBA(FirmwareStructure):

    label = "APCB BCBA Block"

    definition = Struct(
        "magic" / Const(b'BCBA'),
    )

# ----------------------------------------------------------------------------------------
class APCB_ECB2(FirmwareStructure):

    label = "APCB ECB2 Block"

    definition = Struct(
        "magic" / Const(b'ECB2'),
        "failure" / CommitMystery,
        "u1" / Int16ul,
        "u2" / Int16ul,
        "u3" / Int8ul,
        "u4" / Int16ul,
        "u5" / Int8ul,
        "u6" / Int32ul,
        "u7" / Int16ul,
        "u8" / Int16sl,
        "u9" / Int32ul,
        "u10" / Int32ul,
        "u11" / Int32ul,
        "u12" / Int32ul,
        # Zeros
        "u13" / Bytes(56),
    )

    reporting = [
        ["magic"],
        ["u1"], ["u2"], ["u3"], ["u4"], ["u5"], ["u6"], ["u7"], ["u8"],
        ["u9"], ["u10"], ["u11"], ["u12"], ["u13"],
    ]

# ----------------------------------------------------------------------------------------
class APCB_PSPG(FirmwareStructure):

    label = "APCB PSPG Block"

    definition = Struct(
        "magic" / Const(b'PSPG'),
        "u1" / Int8ul,
        "u2" / Int8ul,
        "u3" / Int16ul,
        "u4" / Int32ul,
        "size" / Int32ul,
        "records" / SafeFixedLength(this.size - 16, GreedyRange(Class(APCBSubRecord))),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
        # This object was NOT size-bounded, we should be pointing to a new block now.
    )

    reporting = [
        ["magic"], ["size", "%4d"], ["u1"], ["u2"], ["u3"], ["u4"], ["skipped"],
    ]

# ----------------------------------------------------------------------------------------
class APCB_TOKN_SubRecord(FirmwareStructure):

    label = "APCB TOKN Sub-record"

    definition = Struct(
        "u1" / Int8ul,
        "u2" / Int8ul,
        "u3" / Int16ul,
        "u4" / Int16ul,
        "u5" / Int16sl,
        "u6" / Int32ul,
        "u7" / Int16ul,
        "u8" / Int16sl,
    )

    reporting = [
        ["u1", "%3d"], ["u2", "%3d"], ["u3", "%5d"], ["u4", "%5d"], ["u5", "%5d"],
        ["u6", "0x%08x"], ["u7"], ["u8"],
    ]

# ----------------------------------------------------------------------------------------
class APCB_TOKN(FirmwareStructure):

    label = "APCB TOKN Block"

    definition = Struct(
        "magic" / Const(b'TOKN'),
        "failure" / CommitMystery,
        "u1" / Int8ul,
        "u2" / Int8ul,
        "u3" / Int16ul,
        "u4" / Int32ul,
        "size" / Int32ul,
        "records" / SafeFixedLength(this.size - 16, GreedyRange(Class(APCB_TOKN_SubRecord))),
        # This is the leftover bytes from the SafeFixedLength.  There are often 8 bytes of
        # skipped data here.  Is the TOKN subrecord wrong?
        "skipped" / Computed(this.extra),
        # This object was NOT size-bounded, we should be pointing to a new block now.
    )

    reporting = [["magic"], ["size", "%4d"], ["u1"], ["u2"], ["u3"], ["u4"]]

# ----------------------------------------------------------------------------------------
class APCB_GNBG(FirmwareStructure):

    label = "APCB GNBG Block"

    definition = Struct(
        "magic" / Const(b'GNBG'),
        "failure" / CommitMystery,
        "u1" / Int8ul,
        "u2" / Int8ul,
        "u3" / Int16ul,
        "u4" / Int32ul,
        "size" / Int32ul,
        "data" / SafeFixedLength(this.size - 16, GreedyRange(Class(APCBSubRecord))),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
        # This object was NOT size-bounded, we should be pointing to a new block now.
    )

    reporting = [["magic"], ["size", "%4d"], ["u1"], ["u2"], ["u3"], ["u4"]]

# ----------------------------------------------------------------------------------------
class APCB_UNKN(FirmwareStructure):

    label = "APCB UNKN Block"

    definition = Struct(
        "magic" / Const(b'UNKN'),
        "failure" / CommitMystery,
        "u1" / Int8ul,
        "u2" / Int8ul,
        "u3" / Int16ul,
        "u4" / Int32ul,
        "size" / Int32ul,
        "data" / SafeFixedLength(this.size - 16, Class(MysteryBytes)),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
        # This object was NOT size-bounded, we should be pointing to a new block now.
    )

# ----------------------------------------------------------------------------------------
class APCB_DFG(FirmwareStructure):

    label = "APCB DFG  Block"

    definition = Struct(
        "magic" / Const(b'DFG '),
        "failure" / CommitMystery,
        "u1" / Int8ul,
        "u2" / Int8ul,
        "u3" / Int16ul,
        "u4" / Int32ul,
        "size" / Int32ul,
        "records" / SafeFixedLength(this.size - 16, GreedyRange(Class(APCBSubRecord))),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
        # This object was NOT size-bounded, we should be pointing to a new block now.
    )

    reporting = [["magic"], ["size", "%4d"], ["u1"], ["u2"], ["u3"], ["u4"]]

# ----------------------------------------------------------------------------------------
class APCB_MEMG_Type48(FirmwareStructure):

    label = "APCB MEMG Type 48"

    definition = Struct(
        # I had previously proken this up into pieces, large portions of which were zeros.
        # But it turns out that the positions of the zeros is fairly variable across
        # files, so it wasn't very useful.  The only obviously identifiable data is a
        # memory part number at offset 357-377, which I'm no extracting in analyze().
        "data" / FixedLength(1080, Class(MysteryBytes)),
    )

    reporting = [["mempart", "'%s'"]]

    def analyze(self) -> None:
        self.mempart = None
        if len(self.data.data) > 377:
            mempart = self.data.data[357:377]
            self.mempart = mempart.rstrip(b'\x00')
            try:
                self.mempart = self.mempart.decode('utf-8')
            except UnicodeError:
                pass

# ----------------------------------------------------------------------------------------
class APCB_MEMG_Type95(FirmwareStructure):

    label = "APCB MEMG Type 95"

    definition = Struct(
        "u1" / Int32ul,
        "u2" / Int32ul,
        "magic" / Const(b'OPTB'),
        "u3" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
class APCB_MEMG_SubRecord(FirmwareStructure):

    label = "APCB MEMG Sub-record"

    definition = Struct(
        "u1" / Int8ul,
        "failure" / CommitMystery,
        "u2" / Int8ul,
        "u3" / Int16ul,
        "size" / Int16ul,
        "u3a" / Int16ul,
        # This looks like an APCB_Thing,
        "u4" / Int32ul,
        "u5" / Int16ul,
        "u6" / Int16sl,
        # Then there is a mystery dword.
        "u7" / Int32ul,
        # And then repeating structure of size 1080, for the rest of the sub-record.  The
        # 20 is the usual 8 for the subrecord header, another 8 for the "Thing", and then
        # 4 more mystery bytes.
        "data" / SafeFixedLength(this.size - 20, Switch(
            # It's not actually clear whether u3 controls the switching of these
            # record types just yet, but this works for the ones we've implemented.
            lambda ctx: ctx._.u3, {
                48: GreedyRange(Class(APCB_MEMG_Type48)),
                95: GreedyRange(Class(APCB_MEMG_Type95)),
            }, default=Class(MysteryBytes))),

        #"data" / Select(
        #    SafeFixedLength(this.size - 20, GreedyRange(Class(APCB_MEMG_Blob))),
        #    # Strangely, the last record sometimes has an invalidly large size?
        #    GreedyRange(Class(APCB_MEMG_Blob)),
        #),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
    )

    reporting = [
        ["u1"], ["u2"], ["u3"], ["u3a"], ["size"], ["u4", "0x%x"], ["u5"], ["u6"],
        ["u7"],
        ["data"],
    ]

# ----------------------------------------------------------------------------------------
class APCB_MEMG(FirmwareStructure):

    label = "APCB MEMG Block"

    definition = Struct(
        "magic" / Const(b'MEMG'),
        "failure" / CommitMystery,
        "u1" / Int8ul,
        "u2" / Int8ul,
        "u3" / Int16ul,
        "u4" / Int32ul,
        "size" / Int32ul,
        "records" / SafeFixedLength(this.size - 16, GreedyRange(Class(APCB_MEMG_SubRecord))),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
        # This object was NOT size-bounded, we should be pointing to a new block now.
    )

    reporting = [["magic"], ["size", "%4d"], ["u1"], ["u2"], ["u3"], ["u4"]]

# ----------------------------------------------------------------------------------------
class APCB_FCHG(FirmwareStructure):

    label = "APCB FCHG Block"

    definition = Struct(
        "magic" / Const(b'FCHG'),
        "failure" / CommitMystery,
        "u1" / Int8ul,
        "u2" / Int8ul,
        "u3" / Int16ul,
        "u4" / Int32ul,
        "size" / Int32ul,
        "records" / SafeFixedLength(this.size - 16, GreedyRange(Class(APCBSubRecord))),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
        # This object was NOT size-bounded, we should be pointing to a new block now.
    )

    reporting = [["magic"], ["size", "%4d"], ["u1"], ["u2"], ["u3"], ["u4"]]

# ----------------------------------------------------------------------------------------
class APCB_CBSG(FirmwareStructure):

    label = "APCB CBSG Block"

    definition = Struct(
        "magic" / Const(b'CBSG'),
        "failure" / CommitMystery,
        "u1" / Int8ul,
        "u2" / Int8ul,
        "u3" / Int16ul,
        "u4" / Int32ul,
        "size" / Int32ul,
        "records" / FixedLength(this.size - 16, GreedyRange(Class(APCBSubRecord))),
        # This object was NOT size-bounded, we should be pointing to a new block now.
    )

    reporting = [["magic"], ["size", "%4d"], ["u1"], ["u2"], ["u3"], ["u4"]]

# ----------------------------------------------------------------------------------------
class AMDPSPCustomizationBlock(FirmwareStructure):

    label = "AMD PSP Customization Block (APCB)"

    definition = Struct(
        "magic" / Const(b'APCB'),
        "failure" / CommitMystery,
        "u1" / Int16ul,
        "u2" / Int16ul,
        "size" / Int32ul,
        "u3" / Int32ul,
        "u4" / Int32ul,
        "u5" / Int32ul,
        "u6" / Int32ul,
        "u7" / Int32ul,
        # I've been flailing a little bit here with the length of the records portion.
        "records" / SafeFixedLength(
            this.size - 32,  # Possibly incorrect.
            GreedyRange(Select(
                Class(APCB_ECB2), Class(APCB_PSPG), Class(APCB_DFG), Class(APCB_MEMG),
                Class(APCB_FCHG), Class(APCB_CBSG), Class(APCB_BCBA), Class(APCB_BCPA),
                Class(APCB_TOKN), Class(APCB_GNBG), Class(APCB_UNKN)
            ))),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
        # This padding should start at "size".
        "_ff_padding" / GreedyRange(Const(b'\xff')),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["magic"], ["size"], ["u1"], ["u2"], ["u3"], ["u4"], ["u5"], ["u6"], ["u7"],
        ["records"], ["skipped"],
    ]

# ----------------------------------------------------------------------------------------
class CPUMicrocodeRecord(FirmwareStructure):

    label = "CPU Microcode Record"

    definition = Struct(
        "magic" / Int16ul,
        "u1" / Int8ul,
        "size" / Int16ul,
        "hex" / FixedLength((this.size * 4) + 3, Class(HexDump)),
    )

    reporting = [["magic", "0x%x"], ["u1"], ["size"], ["hex"]]

# ----------------------------------------------------------------------------------------
class CPUStupid(FirmwareStructure):

    label = "CPU Stupid"

    definition = Struct(
        "records" / GreedyRange(Class(CPUMicrocodeRecord)),
        "hex" / Class(HexDump),
    )

# ----------------------------------------------------------------------------------------
class CPUMicrocode(FirmwareStructure):

    label = "CPU Microcode"

    definition = Struct(
        # FIXME! This magic is pretty bad.
        #"u1" / Const(0x2020, Int16ul),
        "u1" / Int16ul,
        "u2" / Int32ul,
        #"u3" / Const(0x80040860, Int32ul),
        "u3" / Int32ul,
        "u4" / Int64ul,
        "u5" / Int32ul,
        "u6" / Int16ul,
        "u7" / Int8ul,
        "u8" / Int8ul,
        "u9" / Int16ul,
        "u10" / Const(0, Int32ul),
        # Looks random.
        "crypto" / Bytes(768),
        "data" / Class(MysteryBytes),
    )

    reporting = [
        ["u1", "0x%x"], ["u2", "0x%x"], ["u3", "0x%x"], ["u4"], ["u5"], ["u6"], ["u7"],
        ["u8"], ["u9"], ["u10"],
        ["crypto", None],
        #["data", None],
        #["records"],
    ]

    # Disabled because this was just exploratory.  I really just need to find a source
    # that documents what's in here.
    def _analyze(self) -> None:
        # One pattern that I can see in the data is that 000000009c7f is common.
        self.records = []
        pattern = b'\x9c\x7f'
        offset = 0
        found = self.data.find(pattern, offset)
        while found != -1 and found > 6:
            rec = self.subparse(HexDump, "data", offset, found - 6)
            self.records.append(rec)
            offset = found - 6
            found = self.data.find(pattern, offset + 6 + 2)
        rec = self.subparse(HexDump, "data", offset)
        self.records.append(rec)

# ----------------------------------------------------------------------------------------
class Arbitrary2Entry(FirmwareStructure):

    label = "Arbitrary2 Entry"

    definition = Struct(
        # FIXME! This is a completely bogus way to identify this block!
        "_badmagic" / FailPeek(Const(b'\x48\x00\x1c\x00\x48\x00\x02')),
        # There's structure in this data.  Blocks of zeros, some repeating patterns,
        # printable strings, etc.  But that structure is not immediately clear.
        "data1" / FixedLength(0xc000, Class(HexDump)),
        "data2" / FixedLength(199388 - 0xc000, Class(HexDump)),
    )


# ----------------------------------------------------------------------------------------
class TwoBHDThing(FirmwareStructure):
    """
    Non-authoritative, reverse-engineered.  Appears to be structurally identical to 2PSP.
    """

    label = "2BHD Thing"

    definition = Struct(
        "magic" / Const(b'2BHD'),
        # Names are guessed.
        "checksum" / Int32ul,
        "one" / Int64ul,
        "z1" / UUID16,
        "z2" / Int32ul,
        "cbc" / Int32ul,
        "u1" / Int16ul,
        "u2" / Int16ul,
        "z3" / Int32ul,
    )

    reporting = [
        ["magic"], ["checksum", "0x%x"], ["u1"], ["u2"], ["cbc", "0x%x"],
        ["one"], ["z1"], ["z2"], ["z3"],
    ]

# ----------------------------------------------------------------------------------------
class TwoPSPThing(FirmwareStructure):

    label = "2PSP Thing"

    definition = Struct(
        "magic" / Const(b'2PSP'),
        # Names are guessed.
        "checksum" / Int32ul,
        "one" / Int64ul,
        "z1" / UUID16,
        "z2" / Int32ul,
        "u1" / Int32ul,
        "u2" / Int16ul,
        "u3" / Int16ul,
        "z3" / Int32ul,
    )

    reporting = [
        ["magic"], ["checksum", "0x%x"], ["u1", "0x%x"], ["u2", "0x%x"], ["u3", "0x%x"],
        ["one"], ["z1"], ["z2"], ["z3"],
    ]

# ----------------------------------------------------------------------------------------
class FirmwareEntryTable(FirmwareStructure):

    label = "Firmware Entry Table"

    definition = Struct(
        "magic" / Const(b'\xaa\x55\xaa\x55'),
        "imc_fw" / Int32ul,
        "gbe_fw" / Int32ul,
        "xhci_fw" / Int32ul,
        "psp1" / Int32ul,
        "psp2" / Int32ul,
        "bios1" / Int32ul,
        "bios2" / Int32ul,
        "bios3" / Int32ul,
        "n1" / Int32sl,
        "bios4" / Int32ul,
        #"ints" / Array(16, Int32ul),
        "data" / FixedLength(64, Class(HexDump)),
    )

    reporting = [
        ["magic"], ["imc_fw", "0x%x"], ["gbe_fw", "0x%x"], ["xhci_fw", "0x%x"],
        ["psp1", "0x%x"], ["psp2", "0x%x"], ["bios1", "0x%x"], ["bios2", "0x%x"],
        ["bios3", "0x%x"], ["n1", "0x%x"], ["bios4", "0x%x"], ["data"],
    ]

# ----------------------------------------------------------------------------------------
class EmptyEntry(FirmwareStructure):

    label = "Empty Entry"

    definition = Struct(
        "_ff_padding" / GreedyRange(Const(b'\xff')),
        Terminated,
    )

    etype: EntryType
    size: int

    # The only two reported fields are set from the directory parsing code that constructs
    # this object.  It's implied that the entire object was FF padding of the given size.
    reporting = [["etype"], ["size"]]

# ----------------------------------------------------------------------------------------
class InterEntryPadding(FirmwareStructure):

    label = "Inter Entry 0xFF Padding"

    definition = Struct(
        "_ff_padding" / GreedyRange(Const(b'\xff')),
        "size" / Computed(lambda ctx: len(ctx._ff_padding)),
    )

    # The only two reported fields are set from the directory parsing code that constructs
    # this object.  It's iimplied that the entire object was FF padding of the given size.
    reporting = [["size"]]

# ----------------------------------------------------------------------------------------
class RTMSignature(FirmwareStructure):

    label = "RTM Signature"

    definition = Struct(
        "sig" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
class HackyPreFETThing(FirmwareStructure):

    label = "Hacky PreFET Thing"

    definition = Struct(
        "zeros" / Bytes(48),
        #"_magic" / FailPeek(Const(b'<31V')),
        #"ints" / Array(16, Int32ul),
        "data" / FixedLength(256, Class(HexDump)),
    )

# ----------------------------------------------------------------------------------------
class HackyPHCMThing(FirmwareStructure):

    label = "Hacky PHCM Thing"

    definition = Struct(
        "_magic" / FailPeek(Const(b'PHCM')),
        # Arbitrary length chosen based on one sample. :-(
        "data" / FixedLength(102 * 1024, Class(MysteryBytes)),
    )

# ----------------------------------------------------------------------------------------
class HackyPreAMDPSP(FirmwareStructure):

    label = "Hacky PRE-AMD PSP"

    # This is an example of the byte rigth before PHCM being 0x0f!
    #   dirs/a/a8/a8b17b2b44626df90384c51100f750b6/firmware.bin

    definition = Struct(
        "_pos" / Tell,
        # BUG! FIXME! This hardcoded 0x20000 shoudl really be _magicpos!
        "_len" / Computed(lambda ctx: 0x20000 - ctx._pos),
        "data" / FixedLength(this._len, Class(MysteryBytes)),

        #"_ff_paddingn1" / GreedyRange(Const(b'\xff')),
        #"phcm" / Class(HackyPHCMThing),
        #"_ff_padding00" / GreedyRange(Const(b'\xff')),
        #"prefet" / Class(HackyPreFETThing),
        #"_pos01" / Tell,
        #"_ff_padding00" / GreedyRange(Const(b'\xff')),
    )

# ----------------------------------------------------------------------------------------
class AMDPSPHeader(FirmwareStructure):

    label = "AMD PSP Header"

    # Maybe ends at 0x510000, but definitely by 0x5e0000
    # The end value is this header is 0x51c000, u7 is 0x520000, u9 is 0x52d000
    # There's a real bounday at 0x516000 (zeros to data)
    # That data continues with the same "character" through 0x540ac0
    # Then ff padding through 0x5e0000, so that's apparently the real end.

    # This file completely wrecks this data structure:
    #   dirs/d/d5/d551eded1684d77b3d366e610e6780bd/firmware.bin

    definition = Struct(
        "version" / Int8ul,
        "u1" / Int16ul,
        "u2" / Int8ul,
        "u3" / Int32sl,
        "u4" / Int64sl,
        "end" / Int32ul,
        "u5" / Int32ul,
        "u6" / Int64sl,
        "u7" / Int32ul,
        "u8" / Int32ul,
        "u9" / Int32ul,
        "u10" / Int32ul,
    )

    reporting = [
        ["version"], ["end", "0x%x"], ["u1"], ["u2"], ["u3"], ["u4"], ["u5", "0x%x"],
        ["u6"], ["u7", "0x%x"], ["u8", "0x%x"], ["u9", "0x%x"], ["u10", "0x%x"],
    ]

# ----------------------------------------------------------------------------------------
class LostEntry(FirmwareStructure):

    label = "Lost Entry"

    definition = Struct(
        "data" / Until(b'\xff' * 512, Class(MysteryBytes)),
    )

    reporting = [["data"]]

# ----------------------------------------------------------------------------------------
class AMDPSPFake(FirmwareStructure):

    label = "AMD PSP Fake"

    definition = Struct(
        "data" / FixedLength(0x22000, Class(HexDump)),
        "more" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
@promote_exceptions
def fet_magic_matcher(ctx: Context) -> Construct:
    args = []
    # A construct that reports the current stream location and matches the magic.
    matcher = Struct("_magicpos" / Tell, Const(b'\xaa\x55\xaa\x55'))
    # This is a list of offsets (the addresses have an additioal leading 0xff byte) that
    # are reportedly searched.
    for faddr in [0xfa0000, 0xf20000, 0xe20000, 0xc20000, 0x820000, 0x020000]:
        arg = Pointer(lambda ctx: ctx._pos + faddr, matcher)
        args.append(arg)
    return Select(*args)

# ----------------------------------------------------------------------------------------
DirectoryType = Union[PSPDirectoryTable, BIOSDirectoryTable]
EntryDictType = Union[AMDEntry, InterEntryPadding, MysteryHexPeek, MysteryBytes,
                      LostEntry, FirmwareVolumeFinder, FirmwareEntryTable, EmptyEntry,
                      HackyPreAMDPSP, TwoPSPThing, TwoBHDThing, DirectoryType,
                      AMDPublicKey, WrappedIKEK, AMDPSPCustomizationBlock, AMDPSPHeader,
                      RTMSignature, CPUMicrocode, AGESABootLoaders, AMD_AFCT]

# ----------------------------------------------------------------------------------------
class AMDPlatformSecurityProcessor(FirmwareStructure):

    label = "AMD Platform Security Processor Section"

    definition = Struct(
        # Relative to our current position, try each of the "known offsets" to see if the
        # FET magic is at that location.  That's how we'll decide if we're and AMD PSP
        # section at all.
        "_pos" / Tell,
        "_matcher" / LazyBind(fet_magic_matcher),
        # If we've matched, _matcher._magicpos will tell us which FET offset matched.
        "_matchpos" / Computed(lambda ctx: ctx._matcher._magicpos),
        # Consume all remaining bytes as rawdata, but unusually this structure is really a
        # "variable length" structure that will reset the stream pointer to the end of the
        # bytes that we were actually able to interpret.
        "rawdata" / GreedyBytes,
        "failure" / CommitMystery,
    )

    #_io: Any
    rawdata: bytes
    entries: list[EntryDictType]
    _entry_dict: dict[int, EntryDictType]

    #"bhd2" / Class(TwoBHDThing),
    #"_ff_padding04" / GreedyRange(Const(b'\xff')),

    # magic=b'2PSP', checksum=0xf3e5cd53, u1=0xbc0c0140, u2=0x1000, u3=0x6, one=1,
    #    z1=00000000-0000-0000-0000-000000000000 (ZERO_GUID), z2=0, z3=0,
    # magic=b'2PSP', checksum=0xec5fcc11, u1=0xbc0c0000, u2=0x1000, u3=0x4, one=1,
    #    z1=00000000-0000-0000-0000-000000000000 (ZERO_GUID), z2=0, z3=0,

    reporting = [["rawdata", None], ["entries"]]

    def ff_padding(self, start: int) -> int:
        """
        Not generally used to skip padding, but needed for the PHCM blob after the initial AMD
        PSP header?
        """
        pos = start
        while self.rawdata[pos] == 0xff:
            pos += 1
        return pos

    def cleanup_entries(self) -> bool:
        lost_entries = False
        # Make a pass over the addresses in order, making padding structures from the
        # bytes that haven't been analyzed.
        addresses = sorted(self._entry_dict.keys())
        padding: Optional[EntryDictType]
        for n, address in enumerate(addresses):
            if n + 1 != len(addresses):
                entry = self._entry_dict[address]
                if entry is None:  # Should we allow None in the list in the first place?
                    continue
                start = address + len(entry)
                next_address = addresses[n + 1]
                #self.debug("Considering padding at 0x%x-0x%x" % (start, next_address))
                # If there's no gap between the existing structures, there's nothing to do.
                if start == next_address:
                    continue
                padding = self.subparse(InterEntryPadding, "rawdata", start, next_address)
                # If we didn't find the "expected" padding, try looking for the $PS1 magic
                # that marks an AMD Entry.  Occasionally there are ones that are not
                # referenced in the directory?  This seems hacky, but it's better than
                # calling the block mystery bytes I suppose.
                if self.rawdata[start + 16:start + 20] == b'$PS1':
                    padding = self.subparse(AMDEntry, "rawdata", start, next_address)
                # If we found something, just add it to the entry dict.
                if padding is not None and len(padding) != 0:
                    self._entry_dict[start] = padding
                    end = start + len(padding)
                    if end not in self._entry_dict:
                        self.warn("lost entry starting at 0x%x, max 0x%x" % (
                            end, addresses[-1]))
                        lost_entry = self.subparse(LostEntry, "rawdata", end)
                        if lost_entry is not None:
                            self._entry_dict[end] = lost_entry
                            lost_entries = True
                else:
                    self.info("padding failed at 0x%x-0x%x" % (start, next_address))
                    length = next_address - start
                    if length == 0:
                        continue
                    padding = self.subparse(FirmwareVolumeFinder, "rawdata", start, next_address)
                    if padding is not None:
                        padding.label = "AMD PSP Cleanup Firmware Volume Finder"
                    else:
                        padding = self.subparse(MysteryHexPeek, "rawdata", start, next_address)
                        if padding is not None:
                            padding.label = "Mystery Bytes (Inter Entry Padding)"
                    if padding is not None:
                        self._entry_dict[start] = padding
        return lost_entries

    def build_entries(self) -> None:
        # Now that we've added additional padding structures, sort the dictionary again,
        # and make an ordered list for reporting.
        self.entries = []
        for address, entry in sorted(self._entry_dict.items()):
            self.entries.append(entry)

        # Finally one last (and very important hack) is to rewind the stream back to the
        # last offset that we correctly interpreted.  This probably "gives back" some of
        # the bytes that we consumed in rawdata.  This complexity could be avoided if we
        # could determine the size of the entire region easily, but I haven't been able to
        # figure out how to that that yet.
        addresses = sorted(self._entry_dict.keys())
        if len(addresses) != 0:
            last_address = addresses[-1]
            entry = self._entry_dict[last_address]
            if entry is None:  # Should we allow None in the list in the first place?
                return
            final = last_address + len(entry)
            data_length = len(self.rawdata)
            delta = data_length - final
            if delta > 0:
                self.error("Giving back 0x%x-0x%x=0x%x!" % (data_length, final, delta))
                # Rewind the stream pointer so that construct knows that we're not really
                # at the end of the stream anymore.  This is the most important part of
                # the hack.
                self._io.seek(-delta, 1)
                # Also correct the parsed length so that future calls to len(self) return
                # the correct length.
                self._parsed_length = final
                # Also truncate self.rawdata to that address.  Technically, we could just
                # discard rawdata entirely at this point as well, since all bytes should
                # be in entries now.
                self.rawdata = self.rawdata[:final]

    def process_directory(self, directory: DirectoryType) -> None:
        for entry in directory.entries:
            if entry is None:  # Should we allow None in the list in the first place?
                continue
            offset = entry.stream_offset

            # Entries at offset zero are always parsing errors in my experience.
            if offset == 0:
                continue
            # Entries of type SOFT_FUSE_CHAIN often has a size of -1, and we don't jknow
            # what to do with it yet.
            if entry.size == -1:
                continue

            # Entries are of a variety of types.  The type is determined by the entry
            # header.  Most entries are of type AMDEntry, which are further distinguished
            # by the header type (or maybe the entry subtype which is often equal to the
            # header type).
            type_to_class_map: dict[EntryType, type[EntryDictType]] = {
                EntryType.AMD_PUBLIC_KEY: AMDPublicKey,
                EntryType.BIOS_PUBLIC_KEY: AMDPublicKey,
                EntryType.SEC_DBG_PUBLIC_KEY: AMDPublicKey,
                EntryType.OEM_PSP_FW_PUBLIC_KEY: AMDPublicKey,
                EntryType.PSP_BOOT_TIME_TRUSTLETS_KEY: AMDPublicKey,
                EntryType.WRAPPED_IKEK_0x21: WrappedIKEK,
                EntryType.FW_XHCI_1: AMDPublicKey,
                EntryType._TYPE_0x4e: AMDPublicKey,
                EntryType.WRAPPED_IKEK_0x8d: WrappedIKEK,
                EntryType.APCB_DATA: AMDPSPCustomizationBlock,
                EntryType.APCB_DATA_BACKUP: AMDPSPCustomizationBlock,
                EntryType.BIOS_RTM_SIGNATURE: RTMSignature,
                EntryType.X86_MICROCODE: CPUMicrocode,
                EntryType.PL2_DIRECTORY_0x40: PSPDirectoryTable,
                EntryType.PL2_DIRECTORY_0x48: PSPDirectoryTable,
                EntryType.PL2_DIRECTORY_0x4a: PSPDirectoryTable,
                EntryType.BL2_DIRECTORY_0x49: BIOSDirectoryTable,
                EntryType.BL2_DIRECTORY_0x70: BIOSDirectoryTable,
                EntryType.BIOS_RESET_IMAGE: FirmwareVolumeFinder,
                EntryType.PSP_NV_DATA: MysteryBytes,
                EntryType.TOKEN_UNLOCK: MysteryBytes,
                EntryType.FW_PSP_SMUSCS: MysteryBytes,
                EntryType.BIOS_RTM_FIRMWARE: MysteryBytes,
                EntryType._TYPE_0x6d: FirmwareVolumeFinder,
                EntryType.ABL0: AGESABootLoaders,
                EntryType.AMD_AFCT_0x98: AMD_AFCT,
                EntryType.ANOTHER_FET: FirmwareEntryTable,
            }

            # Determine the appropriate class to parse, and parse it.
            cls: type[EntryDictType] = AMDEntry
            if entry.etype in type_to_class_map:
                cls = type_to_class_map[entry.etype]

            # The size is sometimes inexplicably zero. :-(
            esize = entry.size
            if esize == 0:
                esize = 1024

            #self.debug("Parsing AMD Entry of type %s at 0x%x" % (cls.__name__, offset))
            obj = self.subparse(cls, "rawdata", offset, offset + esize)
            # Cleanup labels on MysteryBytes classes.  Of course these should eventually
            # be replaced with proper firmware structures that interpret the bytes.
            if isinstance(obj, MysteryBytes):
                obj.label = "Mystery Bytes (AMD Entry %s)" % (entry.etype)

            # If something went wrong, try a couple of fall back approaches.  Fist check
            # to see if the entry is composed entirely of FF bytes (and empty entry), and
            # if that fails, just return a MysteryBytes
            if obj is None:
                obj = self.subparse(EmptyEntry, "rawdata", offset, offset + esize)

                if obj is None:
                    self.error("Parsing entry failed at: 0x%x, size 0x%x" % (offset, esize))
                    obj = self.subparse(MysteryBytes, "rawdata", offset, offset + esize)
                    if obj is not None:
                        obj.label = "Mystery Bytes (Entry Parse Failure %s)" % (entry.etype)
                else:
                    self.warn("AMD Entry of type %s at 0x%x was empty" % (
                        cls.__name__, offset))
                    obj.etype = entry.etype
                    obj.size = esize

            # If we parse an AMDEntry, set the etype property to the value that came out of
            # the directory entry.  This allows us to know what the directory entry said
            # the etype of this entry was without having to search for it.
            if isinstance(obj, AMDEntry):
                obj.set_type(entry.etype)

            # Defer processing sub-entries until after we've added the directory to the
            if isinstance(obj, (PSPDirectoryTable, BIOSDirectoryTable)):
                #self.debug("Processing directory at 0x%x" % (obj._data_offset))
                self.process_directory(obj)
            else:
                # Record the newly parsed entry.
                self.add_entry(offset, obj)  # type: ignore

    def add_entry(self, offset: int, entry: Optional[EntryDictType]) -> None:
        """
        Add an entry that has already been parsed to the entry dictionary.

        Complain about duplicate entries at the same offset.
        """
        if offset in self._entry_dict:
            self.info("duplicate entry in entry_dict at offset 0x%x" % (offset))
        elif entry is not None:
            self._entry_dict[offset] = entry

    def parse_and_add_entry(self, cls: type[EntryDictType],
                            offset: int) -> Optional[EntryDictType]:
        """
        Parse an entry of the specified cls type at offset, and add it to the dictionary.
        """
        obj: Optional[EntryDictType] = self.subparse(cls, "rawdata", offset)  # type: ignore
        if obj is None:
            self.error(f"Failed to parse {cls.__name__}")
        else:
            self.add_entry(offset, obj)
        return obj

    def search_entry(self, cls: type[EntryDictType], magic: bytes,
                     start_offset: int = 0) -> tuple[bool, Optional[EntryDictType]]:
        """
        Find an entry that starts with the specified magic, and parse it.
        """

        obj: Optional[EntryDictType] = None
        new = True
        offset = start_offset
        # In a loop not because we're going to process multiple entries, but because we
        # might decide to skip the first match if it's not well aligned.
        while True:
            loc = self.rawdata.find(magic, offset)
            if loc == -1:
                break
            # Any references to the magic that are not on an even multiple of 256 bytes is
            # a reference to something unintentional (perhaps the code that parses the
            # entries?)  Skip those entries so we don't make invalid entries.
            if (loc & 0xff) != 0:
                offset = loc + 4
                continue
            #self.debug("Found %s at offset 0x%x" % (cls.__name__, loc))
            # If there's already an entry at that offset...
            if loc in self._entry_dict:
                new = False
                # If it's the correct type, return the one we've already parsed.
                if isinstance(self._entry_dict[loc], cls):
                    #self.debug("Already found %s at 0x%x" % (cls.__name__, loc))
                    obj = self._entry_dict[loc]
                    break
                else:
                    self.warn("existing entry at offset 0x%x is of type %s not %s" % (
                        loc, type(self._entry_dict[loc]), cls.__name__))
            obj = self.parse_and_add_entry(cls, loc)
            break

        return (new, obj)

    def search_multiple_entries(self, cls: type[DirectoryType], magic: bytes) -> None:
        """
        Search for multiple directory entries, parse them, add them to the dictionary, and
        process the directory.  Skip entries that have already been found.
        """
        off = 0
        while True:
            (new, entry) = self.search_entry(cls, magic, off)
            if entry is not None:
                if new and isinstance(entry, (PSPDirectoryTable, BIOSDirectoryTable)):
                    self.process_directory(entry)
                off = entry._data_offset + len(entry)
            else:
                break

    def analyze(self) -> None:
        # This is a dictionary of all the structures we've found.  We'll sort it by
        # address and convert it to an ordered list for reporting.
        self._entry_dict = {}
        # This is the ordered list built from _entry_dict.
        self.entries = []

        # Parsing...
        header = self.parse_and_add_entry(AMDPSPHeader, 0)
        if header is not None:
            hlen = len(header)
        else:
            hlen = 0
        pos = self.ff_padding(hlen)
        self.parse_and_add_entry(HackyPreAMDPSP, pos)
        fet = self.parse_and_add_entry(FirmwareEntryTable, self._matchpos)
        if fet is not None:
            self.parse_and_add_entry(TwoPSPThing, fet.psp2)
            self.parse_and_add_entry(TwoBHDThing, fet.bios4)

        self.search_multiple_entries(PSPDirectoryTable, b'$PSP')
        self.search_multiple_entries(BIOSDirectoryTable, b'$BHD')
        self.search_multiple_entries(PSPDirectoryTable, b'$PL2')
        self.search_multiple_entries(BIOSDirectoryTable, b'$BL2')

        # Loop over cleanup until there are no new missed entries.
        while self.cleanup_entries():
            self.debug("Cleaning up entries again!")
            pass

        self.build_entries()

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
