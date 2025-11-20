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
Silicon Labs Gecko Bootloader support.

Used for Wi-Fi, Zigbee, Thread, Z-Wave, Xbee, etc. firmware packages.
"""

from enum import Flag

from construct import (
    Bytes, Const, If, Int8ul, Int16ul, Int24ul, Int32ul, Int32ub, Int64ul,
    BytesInteger, GreedyBytes, GreedyRange, Select, this)

from .base import (
    FirmwareStructure, FixedLength, Class, PaddedString, Struct, OneOrMore, UUID16,
    EnumAdapter)
from .uenum import UEnum
from .mystery import MysteryBytes
from .compression import decompress, CompressionAlgorithm

# The authoritative reference document appears to be:
#   https://www.silabs.com/documents/public/user-guides/ug489-gecko-bootloader-user-guide-gsdk-4.pdf
# This page was initially helpful:
#   https://docs.silabs.com/mcu-bootloader/1.12/group-EblParserFormat

# There are ordering requirements for the record types that are NOT enforced by this logic
# currently!  While that shouldn't be a problem for parsing firmware packages, it
# obviously could be if we started modifying images.  It doubtful that this is the right
# tool for modifying Gecko Boot Loader images anyway.

# ----------------------------------------------------------------------------------------
class ApplicationType(Flag):
    ZigBee       = 1 << 0
    Thread       = 1 << 1
    Flex         = 1 << 2
    Bluetooth    = 1 << 3
    MCU          = 1 << 4
    BluetoothApp = 1 << 5
    Bootloader   = 1 << 6
    ZWave        = 1 << 7

# ----------------------------------------------------------------------------------------
class Application(FirmwareStructure):
    """
    This tag contains information about the application update image that is contained in
    this GBL file.
    """

    label = "Gecko Boot Loader Application"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0xf40a0af4, Int32ul),
        "length" / Int32ul,
        # Application
        "apptype" / EnumAdapter(Int32ul, ApplicationType),
        "version" / Int32ul,
        "capabilities" / Int32ul,
        "product" / UUID16,
    )

    reporting = [
        ["tag", "0x%x"], ["length"], ["apptype"], ["version"], ["capabilities", "0x%x"],
        ["product"],
    ]


# ----------------------------------------------------------------------------------------
class BootLoader(FirmwareStructure):
    """
    This tag contains a complete bootloader update image.
    """

    label = "Gecko Boot Loader BootLoader"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0xf50909f5, Int32ul),
        "length" / Int32ul,
        # BootLoader
        "version" / Int32ul,
        "address" / Int32ul,
        "data" / FixedLength(this.length - 8, GreedyBytes),
    )

    reporting = [
        ["tag", "0x%x"], ["version"], ["address", "0x%x"], ["length"],
        ["data", None],  # Big binary blob
    ]

# ----------------------------------------------------------------------------------------
class Metadata(FirmwareStructure):
    """
    This tag contains metadata that the bootloader does not parse but can be returned to
    the application through a callback.
    """

    label = "Gecko Boot Loader Metadata"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0xf60808f6, Int32ul),
        "length" / Int32ul,
        # Metadata (interpretation unclear)
        "data" / Bytes(this.length),
    )

    reporting = [
        ["tag", "0x%x"], ["length"], ["data"],
    ]

# ----------------------------------------------------------------------------------------
class ProgramData1(FirmwareStructure):
    """
    This tag contains information about what application data to program at a specific
    address into the main flash memory.
    """

    label = "Gecko Boot Loader Program Data 1"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0xfe0101fe, Int32ul),
        "length" / Int32ul,
        # Program Data
        "address" / Int32ul,
        "data" / Bytes(this.length - 4),
    )

    reporting = [
        ["tag", "0x%x"], ["length"], ["data"],
    ]

# ----------------------------------------------------------------------------------------
class ProgramData2(FirmwareStructure):
    """
    This tag contains information about what application data to program at a specific
    address into the main flash memory.
    """

    label = "Gecko Boot Loader Program Data 2"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0xfd0303fd, Int32ul),
        "length" / Int32ul,
        # Program Data
        "data" / Bytes(this.length),
    )

    reporting = [
        ["tag", "0x%x"], ["length"], ["data"],
    ]

# ----------------------------------------------------------------------------------------
class SecureElementUpgrade(FirmwareStructure):
    """
    This tag contains a complete encrypted Secure Element update image. Only applicable on
    Series 2 devices.
    """

    label = "Gecko Boot Loader Secure Element Upgrade"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0x5ea617eb, Int32ul),
        "length" / Int32ul,
        # Secure Element Upgrade
        "blob_size" / Int32ul,
        "version" / Int32ul,
        "data" / Bytes(this.length - 8),
    )

    reporting = [
        ["tag", "0x%x"], ["length"], ["data"],
    ]

# ----------------------------------------------------------------------------------------
class ImageType(UEnum):
    Application = 1
    Bootloader = 2
    SecureElement = 3

# ----------------------------------------------------------------------------------------
class Operator(UEnum):
    Shift    = 0x00
    Negate   = 0x01
    LT       = 0x00
    LEQ      = 0x02
    EQ       = 0x04
    GEQ      = 0x06
    GT       = 0x08
    TypeMask = 0x0e
    Mask     = 0x0f

# ----------------------------------------------------------------------------------------
class Connective(UEnum):
    Mask = 0xf0
    Shift = 0x04

# ----------------------------------------------------------------------------------------
class VersionDependency(FirmwareStructure):
    """
    This optional tag contains encoded version dependencies that the software currently
    running on the device must satisfy before an upgrade can be attempted. Only available
    on Series 2 devices.
    """

    label = "Gecko Boot Loader Version Dependency"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0x76a617eb, Int32ul),
        "length" / Int32ul,
        # "image_type" / Int8ul,
        # "statement" / Int8ul,
        # "reserved" / Int16ul,
        # "version" / Int32ul,
        "data" / Bytes(this.length),
    )

    reporting = [
        ["tag", "0x%x"], ["length"], ["data"],
    ]

# ----------------------------------------------------------------------------------------
class EndOfFile(FirmwareStructure):
    """
    This tag indicates the end of the GBL file. It contains a 32-bit CRC for the entire
    file as an integrity check. The CRC is a non-cryptographic check. This must be the
    last tag.
    """

    label = "Gecko Boot Loader End-of-File"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0xfc0404fc, Int32ul),
        "length" / Int32ul,
        "crc" / Int32ul,
    )

    reporting = [
        ["tag", "0x%x"], ["length"], ["crc", "0x%x"],
    ]

# ----------------------------------------------------------------------------------------
class ProgramLZMACompressed(FirmwareStructure):
    """
    This tag contains LZMA compressed information about what application data to program
    at a specific address into the main flash memory.
    """

    label = "Gecko Boot Loader Program LZMA Compressed"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0xfd0707fd, Int32ul),
        "length" / Int32ul,
        # Program Data
        "address" / Int32ul,
        "data" / Bytes(this.length - 4),
    )

    reporting = [
        ["tag", "0x%x"], ["length"], ["data", None], ["decomp", None], ["dsize"],
    ]

    def analyze(self) -> None:
        try:
            # Uses the same LZMA header as the UEFI implementation...
            self.decomp = decompress(self.data, CompressionAlgorithm.LZMA)
        except Exception as e:
            self.decomp = None
            self.dsize = 0
            self.error(f"LZMA Decompression Failed {e}")

        if self.decomp is None:
            return

        self.dsize = len(self.decomp)
        if False:
            fh = open("gbl.rom", "wb")
            fh.write(self.decomp)
            fh.close()

# ----------------------------------------------------------------------------------------
class ProgramLZ4Compressed(FirmwareStructure):
    """
    This tag contains LZ4 compressed information about what application data to program at
    a specific address into the main flash memory.
    """

    label = "Gecko Boot Loader Program LZ4 Compressed"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0xfd0505fd, Int32ul),
        "length" / Int32ul,
        "data" / FixedLength(this.length, Class(MysteryBytes)),
    )

    reporting = [
        ["tag", "0x%x"], ["length"], ["data"],
    ]

# ----------------------------------------------------------------------------------------
class DeltaPatch(FirmwareStructure):
    """
    This tag contains the information about the delta patch that should be used to create
    the new app.
    """

    label = "Gecko Boot Loader Delta Patch"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0xf80a0af8, Int32ul),
        "length" / Int32ul,
        "data" / FixedLength(this.length, GreedyBytes),
    )

    reporting = [
        ["tag", "0x%x"], ["length"],
        ["data", None],
    ]

    def analyze(self) -> None:
        self.error("No LZ4 decompression yet!")

# ----------------------------------------------------------------------------------------
class DeltaLZMACompressed(FirmwareStructure):
    """
    This tag contains LZMA compressed information about the delta patch that should be
    used to create the new app.
    """

    label = "Gecko Boot Loader Delta LZMA Compressed"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0xf80c0cf8, Int32ul),
        "length" / Int32ul,
        "data" / Bytes(this.length),
    )

    reporting = [
        ["tag", "0x%x"], ["length"], ["data", None], ["decomp"],
    ]

    def analyze(self) -> None:
        try:
            # Uses the same LZMA header as the UEFI implementation...
            self.decomp = decompress(self.data, CompressionAlgorithm.LZMA)
        except Exception as e:
            self.decomp = None
            self.dsize = 0
            self.error(f"LZMA Decompression Failed {e}")

        if self.decomp is None:
            return

        self.dsize = len(self.decomp)
        if False:
            fh = open("gbl.rom", "wb")
            fh.write(self.decomp)
            fh.close()

# ----------------------------------------------------------------------------------------
class DeltaLZ4Compressed(FirmwareStructure):
    """
    This tag contains LZ4 compressed information about the delta patch that should be used
    to create the new app.
    """

    label = "Gecko Boot Loader Delta LZ4 Compressed"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0xf80b0bf8, Int32ul),
        "length" / Int32ul,
        "data" / FixedLength(this.length, Class(MysteryBytes)),
    )

    reporting = [
        ["tag", "0x%x"], ["length"], ["data"],
    ]

    def analyze(self) -> None:
        self.error("No LZ4 decompression yet!")

# ----------------------------------------------------------------------------------------
class Signature(FirmwareStructure):

    label = "Gecko Boot Loader Signature ECDSA P256"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0xf70a0af7, Int32ul),
        "length" / Const(64, Int32ul),
        # I presume these are integers.  I have no idea if the byte order is correct.
        "r" / BytesInteger(32),
        "s" / BytesInteger(32),
        #"r" / Bytes(32),
        #"s" / Bytes(32),
    )

    reporting = [
        ["tag", "0x%x"], ["length"], [], ["r"], [], ["s"],
    ]

# ----------------------------------------------------------------------------------------
class Certificate(FirmwareStructure):

    label = "Gecko Boot Loader Certificate"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0xf30b0bf3, Int32ul),
        "length" / Int32ul,
        "struct_version" / Int8ul,
        "flags" / Int24ul,
        "key" / Bytes(64),
        "certificate_version" / Int32ul,
        "signature" / Bytes(64),
        "extra" / Bytes(this.length - 136),
    )

    reporting = [
        ["tag", "0x%x"], ["length"], ["data"],
    ]

# ----------------------------------------------------------------------------------------
class Encryption(FirmwareStructure):

    label = "Gecko Boot Loader Encryption"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0xfa0606fa, Int32ul),
        "length" / Int32ul,
        "cipher_length" / Int32ul,
        "nonce" / Bytes(12),
        "extra" / Bytes(this.length - 16),
    )

    reporting = [
        ["tag", "0x%x"], ["length"], ["data"],
    ]

# ----------------------------------------------------------------------------------------
class ProgramEncrypted(FirmwareStructure):

    label = "Gecko Boot Loader Program Encrypted Data"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0xf90707f9, Int32ul),
        "length" / Int32ul,
        "data" / Bytes(this.length),
    )

    reporting = [
        ["tag", "0x%x"], ["length"], ["data"],
    ]

# ----------------------------------------------------------------------------------------
class GBLGenericRecord(FirmwareStructure):

    label = "Gecko Boot Loader Generic Record"

    definition = Struct(
        # GBL Tag Header
        "tag" / Int32ul,
        "length" / Int32ul,
        "data" / FixedLength(this.length, GreedyBytes),
    )

    reporting = [
        ["tag", "0x%x"], ["length"],
        ["data", None],
    ]

# ----------------------------------------------------------------------------------------
class FileType(Flag):
    NoType = 0
    Encrypted = 1
    Signed = 0x100

# ----------------------------------------------------------------------------------------
class GeckoBootLoaderFile(FirmwareStructure):

    label = "Gecko Boot Loader File Header"

    definition = Struct(
        # GBL Tag Header
        "tag" / Const(0x03A617EB, Int32ul),
        "length" / Int32ul,
        # File Header
        "version" / Int32ub,
        "file_type" / EnumAdapter(Int32ul, FileType),
        "records" / GreedyRange(Select(
            Class(BootLoader),
            Class(Application),
            Class(Signature),
            Class(Metadata),
            Class(ProgramLZMACompressed),
            Class(EndOfFile),
            # Not seen yet.
            Class(ProgramData1),
            Class(ProgramData2),
            Class(ProgramLZ4Compressed),
            Class(DeltaPatch),
            Class(DeltaLZ4Compressed),
            Class(DeltaLZMACompressed),
            Class(Certificate),
            Class(Encryption),
            Class(ProgramEncrypted),
            Class(VersionDependency),
            Class(SecureElementUpgrade),
            Class(GBLGenericRecord))),
        "extra" / Class(MysteryBytes),
    )

    reporting = [
        ["tag", "0x%x"], ["version"], ["file_type"], ["length"],
    ]

# The reference documentation for the OTA format appears to be here:
#   https://zigbeealliance.org/wp-content/uploads/2021/10/07-5123-08-Zigbee-Cluster-Library.pdf
# I guess technically this

# ----------------------------------------------------------------------------------------
class ZigbeeVersion(UEnum):
    ZigBee2006 = 0
    ZigBee2007 = 1
    ZigBeePro = 2
    ZigBeeIP = 3

# ----------------------------------------------------------------------------------------
class FieldControl(Flag):
    NoFieldControl = 0
    SecurityCredential = 1
    DeviceSpecificFile = 2
    HardwareVersions = 4

# ----------------------------------------------------------------------------------------
class Manufacturer(UEnum):
    SiliconLabs = 4126

# ----------------------------------------------------------------------------------------
class ZigbeeImageType(UEnum):

    ClientCredentials = 0xffc0
    ClientConfiguration = 0xffc1
    ServerLog = 0xffc2
    Picture = 0xffc3
    WildCard = 0xffcf

# ----------------------------------------------------------------------------------------
class Credential(UEnum):
    SE10 = 0
    SE11 = 1
    SE20 = 2
    SE12 = 3

# ----------------------------------------------------------------------------------------
class ZigbeeTag(UEnum):
    UpgradeImage = 0
    ECDSASignature1 = 1
    ECDSACertificate1 = 2
    ImageIntegrityCode = 3
    PictureData = 4
    ECDSASignature2 = 5
    ECDSACertificate2 = 6

# ----------------------------------------------------------------------------------------
class ZigbeeOverTheAirSubElement(FirmwareStructure):
    label = "Zigbee Over-The-Air Upgrade"

    definition = Struct(
        "tag" / EnumAdapter(Int16ul, ZigbeeTag),
        "length" / Int32ul,
        "data" / Select(
            # I seriously doubt that all "uprades" are Gecko Boot Loader images.
            FixedLength(this.length, Class(GeckoBootLoaderFile)),
            # The standard defined formats for the ECDSA fields (which I did not
            # implement) and the Image Integrity Code. The standard was not terribly clear
            # on the format of the update images, or the picture data.
            Bytes(this.length),
        ),
    )

    reporting = [
        ["tag"], ["length"],
    ]

# ----------------------------------------------------------------------------------------
class ZigbeeOverTheAir(FirmwareStructure):

    label = "Zigbee Over-The-Air Upgrade"

    definition = Struct(
        "tag" / Const(0x0beef11e, Int32ul),
        "hdr_version_minor" / Int8ul,
        "hdr_version_major" / Int8ul,
        "hdr_length" / Int16ul,
        "field_control" / EnumAdapter(Int16ul, FieldControl),
        "manufacturer" / EnumAdapter(Int16ul, Manufacturer),
        "image_type" / EnumAdapter(Int16ul, ZigbeeImageType),
        "file_version" / Int32ul,
        "zigbee_version" / EnumAdapter(Int16ul, ZigbeeVersion),
        "header_string" / PaddedString(32, 'utf8'),
        "file_size" / Int32ul,  # The size of this entire data structure.

        # Not tested.
        "cred_version" / If(this.hdr_length >= 57, EnumAdapter(Int8ul, Credential)),
        "destination" / If(this.hdr_length >= 61, Int64ul),
        "min_hardware_version" / If(this.hdr_length >= 63, Int16ul),
        "max_hardware_version" / If(this.hdr_length >= 65, Int16ul),
        "extra_header" / If(this.hdr_length >= 65, Bytes(this.hdr_length - 65)),

        #"gbl" / FixedLength(this.file_size - this.hdr_length, Class(GeckoBootLoaderFile)),
        #"tagid" / Int16ul,
        #"length" / Int32ul,
        #"gbl" / Class(GeckoBootLoaderFile),
        "elements" / OneOrMore(Class(ZigbeeOverTheAirSubElement)),
    )

    reporting = [
        ["tag", "0x%x"], ["header_string"],
        ["app_version", '"%s"'], ["stack_version", '"%s"'], ["file_size"],
        [],
        ["manufacturer"], ["zigbee_version"], ["field_control"], ["image_type"],
        [],
        ["cred_version"], ["destination"], ["min_hardware_version"], ["max_hardware_version"],
        ["hdr_version"], ["hdr_length"], ["extra_header"],
        [],
        # ["fc_flags", None], ["mfg_code", None], ["image_type_code", None],
        ["hdr_version_major", None], ["hdr_version_minor", None],
        ["zigbee_version_code", None], ["file_version", None],
    ]

    def analyze(self) -> None:
        self.hdr_version = f"{self.hdr_version_major}.{self.hdr_version_minor}"

        app_major = "%x" % ((self.file_version & 0xF0000000) >> 28)
        app_minor = "%x" % ((self.file_version & 0x0F000000) >> 24)
        app_build = "%x" % ((self.file_version & 0x00FF0000) >> 16)
        self.app_version = f"r{app_major}.{app_minor} b{app_build}"

        stack_major = "%x" % ((self.file_version & 0x0000F000) >> 12)
        stack_minor = "%x" % ((self.file_version & 0x00000F00) >> 8)
        stack_build = "%x" % ((self.file_version & 0x000000FF) >> 0)
        self.stack_version = f"r{stack_major}.{stack_minor} b{stack_build}"

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
