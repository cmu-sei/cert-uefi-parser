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
NVRAM variables.
"""

from uuid import UUID
from typing import Union, Optional

from construct import (
    Array, Bytes, GreedyRange, Computed, Const, Int8ul, Int16ul, Int32ul, Int64ul,
    Select, Switch, Aligned, Peek, Check, Construct, this)

from .base import (
    FirmwareStructure, Class, LazyBind, FixedLength, promote_exceptions, Struct, UUID16,
    FailPeek, OneOrMore, HexBytes, PaddedString, Opt, CString, EnumAdapter)
from .uenum import UEnum
from .utils import purple
from .mystery import MysteryBytes, HexDump
from .asn1 import X509_DER, X509_SignedData

# ----------------------------------------------------------------------------------------
class EfiTime(FirmwareStructure):

    definition = Struct(
        "year" / Int16ul,
        "month" / Int8ul,
        "day" / Int8ul,
        "hour" / Int8ul,
        "minute" / Int8ul,
        "second" / Int8ul,
        "pad1" / Int8ul,
        "nanosecond" / Int32ul,
        "timezone" / Int16ul,
        "daylight" / Int8ul,
        "pad2" / Int8ul,
    )

    def __str__(self) -> str:
        result = "%04d-%02d-%02d %02d:%02d:%02d.%d %d %d" % (
            self.year, self.month, self.day, self.hour, self.minute,
            self.second, self.nanosecond, self.timezone, self.daylight)
        if result == "0000-00-00 00:00:00.0 0 0":
            return "(empty)"
        return result

# ----------------------------------------------------------------------------------------
EFI_CERT_SHA256_GUID = UUID('c1c41626-504c-4092-aca9-41f936934328')
EFI_CERT_X509_GUID = UUID('a5c059a1-94e4-4aa7-87b5-ab155c2bf072')
EFI_CERT_RSA2048_GUID = UUID('3c5766e8-269c-4e34-aa14-ed776e85b3b6')
EFI_CERT_SHA1_GUID = UUID('826ca512-cf10-4ac9-b187-be01496631bd')
EFI_CERT_SHA224_GUID = UUID('0b6e5233-a65c-44c9-9407-d9ab83bfc8bd')
EFI_CERT_SHA384_GUID = UUID('ff3e5307-9fd0-48c9-85f1-8ad56c701e01')
EFI_CERT_SHA512_GUID = UUID('093e0fae-a6c4-4f50-9f1b-d41e2b89c19a')
EFI_CERT_X509_SHA256_GUID = UUID('3bd2a492-96c0-4079-b420-fcf98ef103ed')
EFI_CERT_X509_SHA384_GUID = UUID('7076876e-80c2-4ee6-aad2-28b349a6865b')
EFI_CERT_X509_SHA512_GUID = UUID('446dbf63-2502-4cda-bcfa-2465d2b0fe9d')
EFI_CERT_EXTERNAL_MANAGEMENT_GUID = UUID('452e8ced-dfff-4b8c-ae01-5118862e682c')

# ----------------------------------------------------------------------------------------
class X509_SHA256(FirmwareStructure):

    definition = Struct(
        "hash" / HexBytes(32),
        "expiration" / Class(EfiTime),
    )

# ----------------------------------------------------------------------------------------
class X509_SHA384(FirmwareStructure):

    definition = Struct(
        "hash" / HexBytes(48),
        "expiration" / Class(EfiTime),
    )

# ----------------------------------------------------------------------------------------
class X509_SHA512(FirmwareStructure):

    definition = Struct(
        "hash" / HexBytes(64),
        "expiration" / Class(EfiTime),
    )

# ----------------------------------------------------------------------------------------
class SignatureData(FirmwareStructure):
    """
    EFI_SIGNATURE_DATA
    Section 32.4.1.1 Signature Data
    https://uefi.org/specs/UEFI/2.9_A/32_Secure_Boot_and_Driver_Signing.html
    edk2/MdePkg/Include/Guid/ImageAuthentication.h
    """

    label = "Signature Data"

    definition = Struct(
        "owner" / UUID16,
        "data" / Switch(lambda ctx: ctx._.sig_type, {
            EFI_CERT_SHA1_GUID: HexBytes(20),
            EFI_CERT_SHA224_GUID: HexBytes(28),
            EFI_CERT_SHA256_GUID: HexBytes(32),
            EFI_CERT_SHA384_GUID: HexBytes(48),
            EFI_CERT_SHA512_GUID: HexBytes(64),
            EFI_CERT_RSA2048_GUID: HexBytes(256),
            EFI_CERT_X509_SHA256_GUID: Class(X509_SHA256),
            EFI_CERT_X509_SHA384_GUID: Class(X509_SHA384),
            EFI_CERT_X509_SHA512_GUID: Class(X509_SHA512),
            # 16 bytes is the size of the owner guid.
            EFI_CERT_X509_GUID: FixedLength(lambda ctx: ctx._.size - 16, Class(X509_DER)),
            EFI_CERT_EXTERNAL_MANAGEMENT_GUID: FixedLength(
                lambda ctx: ctx._.size - 16, Class(HexDump)),
        }, default=Class(HexDump)),
        "unexpected" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
class SignatureList(FirmwareStructure):
    """
    EFI_SIGNATURE_LIST
    Section 32.4.1
    https://uefi.org/specs/UEFI/2.9_A/32_Secure_Boot_and_Driver_Signing.html
    edk2/MdePkg/Include/Guid/ImageAuthentication.h
    """

    label = "Signature List"

    definition = Struct(
        "sig_type" / UUID16,
        "list_size" / Int32ul,
        "header_size" / Int32ul,
        "size" / Int32ul,
        "header" / Bytes(this.header_size),
        # 28 bytes is the size of the SignatureList header.
        "data" / FixedLength(lambda ctx: ctx.list_size - ctx.header_size - 28,
                             GreedyRange(FixedLength(this.size, Class(SignatureData)))),
    )

    reporting = [
        ["sig_type"], ["list_size"], ["header_size"], ["size"], ["header"], ["data"],
    ]

# ----------------------------------------------------------------------------------------
class SignatureDatabase(FirmwareStructure):
    """
    A list of EFI_SIGNATURE_LIST structures.
    """

    label = "Signature Database"

    definition = Struct(
        "lists" / GreedyRange(Class(SignatureList)),
        "unexpected" / Class(MysteryBytes),
        #"extra" / Class(HexDump),
    )

# ----------------------------------------------------------------------------------------
class AuthenticatedVariable(FirmwareStructure):

    label = "Authenticated Variable"

    definition = Struct(
        "magic" / Const(0x55aa, Int16ul),
        "state" / Int8ul,
        "reserved" / Int8ul,
        "attributes" / Int32ul,
        "monotonic_count" / Int64ul,
        "timestamp" / Class(EfiTime),
        "pubkey_index" / Int32ul,
        "name_size" / Int32ul,
        "data_size" / Int32ul,
        "_guid" / Bytes(16),
        #StopIf(this.guid == b'\xff' * 16) ?
        "name" / PaddedString(this.name_size, "utf-16-le"),
        "data" / Aligned(2, FixedLength(
            this.data_size,
            # Mypy is struggling with the forward declaration here...
            LazyBind(lambda ctx: guess_variable_type(ctx.name, ctx.data_size)))),  # type: ignore
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    data: Construct

    reporting = [
        ["guid"], ["name", "%s", purple],
        [], ["timestamp", "%s"], ["attributes"], ["data_size"], ["monotonic_count"],
        ["name_size"], ["pubkey_index"], ["state"],
        ["reserved", None], ["magic", None], ["data", None],
        [], ["value"],
    ]

    def validate(self) -> None:
        if self.reserved != 0:
            self.validation_error("unexpected reserved = %d" % self.reserved)

    @property
    def value(self) -> Union[str, bytes, Construct]:
        if isinstance(self.data, bytes) and len(self.data) > 16:
            return "%r..." % self.data[:32]
        return self.data

    @property
    def guid(self) -> UUID:
        return UUID(bytes_le=self._guid)

    @guid.setter
    def guid(self, value: UUID) -> None:
        self._guid = value.bytes_le

# ----------------------------------------------------------------------------------------
class ParallelsAuthenticatedVariableStore(FirmwareStructure):

    label = "Parallels Authenticated Variable Store"

    definition = Struct(
        "u1" / Const(0, Int32ul),
        "variables" / OneOrMore(Aligned(4, Class(AuthenticatedVariable))),
        "_ff_padding1" / GreedyRange(Const(b'\xff')),
        "unexpected" / Class(HexDump),
    )

# ----------------------------------------------------------------------------------------
class SecureBootExtraStuff(FirmwareStructure):
    """
    I think this additional data is alluded to by CreatePkX509SignatureList in
    edk2/SecurityPkg/VariableAuthenticated/SecureBootConfigDxe/SecureBootConfigImpl.c
    since it seems to be allocating space for what we've found plus "X509Data".
    """

    label = "Secure Boot Extra Stuff"

    definition = Struct(
        "u1" / Int8ul,
        "u2" / Int8ul,
        "u3" / HexBytes(7),
        "u4" / HexBytes(32),
        "u5" / Int16ul,
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["u1"], ["u2"], ["u3"]]

# ----------------------------------------------------------------------------------------
class SecureBootVariable(FirmwareStructure):
    """
    Secure Boot Variable

    Includes db, dbDefault, dbx, dbxDefault, KEK, KEKDefault, PK, and PKDefault.  The
    individual variables have different constraints, but the cleanest way to implement the
    parsing was to make the variable one or more records of a self-identifying type.
    Thisfirmware structure does not include the cryptographic signature used for updates,
    which is described in SecureBootSignedVariable.
    """

    label = "Secure Boot Variable"

    definition = Struct(
        "_rectype" / Peek(UUID16),
        Check(lambda ctx: str(ctx._rectype) in [
            'a5c059a1-94e4-4aa7-87b5-ab155c2bf072',  # EFI_CERT_X509_GUID
            '452e8ced-dfff-4b8c-ae01-5118862e682c',  # EFI_CERT_EXTERNAL_MANAGEMENT_GUID
            'c1c41626-504c-4092-aca9-41f936934328',  # EFI_CERT_SHA256_GUID
        ]),
        # Basically a SignatureDatabase without the greedy MysteryBytes.
        "lists" / GreedyRange(Class(SignatureList)),
        "extra" / Opt(Class(SecureBootExtraStuff)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["lists"], ["extra"]]

# ----------------------------------------------------------------------------------------
EFI_CERT_TYPE_PKCS7_GUID = UUID('4aafd29d-68df-49ee-8aa9-347d375665a7')
class SecureBootSignedVariable(FirmwareStructure):
    """
    A Secure Boot variable with a PKCS7 signature prepended.  This is the format used to
    update the variables, which includes how uefi.org distributes the updates to the
    Secure Boot Forbidden Signature Database, which they call the UEFI Revocation List.
    """

    definition = Struct(
        # EFI_VARIABLE_AUTHENTICATION_2 from edk2/MdePkg/Include/Uefi/UefiMultiPhase.h
        "timestamp" / Class(EfiTime),
        # WIN_CERTIFICATE https://dox.ipxe.org/structWIN__CERTIFICATE.html
        "size" / Int32ul,
        "revision2" / Int8ul,
        "revision1" / Int8ul,
        "certtype" / Int16ul,
        # Our magic isn't literally at the start of the structure, but it's close enough.
        "_magic" / FailPeek(Const(EFI_CERT_TYPE_PKCS7_GUID.bytes_le)),
        "guid" / UUID16,
        # 24 is the size of the WIN_CERTIFICATE header.
        "sigdata" / FixedLength(this.size - 24, Class(X509_SignedData)),
        # Seems to work, not sure if this is correct.
        "variable" / Class(SecureBootVariable),
    )

    @property
    def version(self) -> str:
        return "%s.%s" % (self.revision1, self.revision2)

    reporting = [
        ["size"], ["version"], ["certtype"], ["guid"],
        ["timestamp"],
        ["sigdata"], ["variable"],
        ["revision1", None], ["revision2", None],
    ]

# ----------------------------------------------------------------------------------------
class EFIFirmwarePerformance(FirmwareStructure):

    definition = Struct(
        "boot_table_ptr" / Int64ul,
        "s3_table_ptr" / Int64ul,
    )

    reporting = [["boot_table_ptr", "0x%x"], ["s3_table_ptr", "0x%x"]]

# ----------------------------------------------------------------------------------------
class DevicePathType(UEnum):
    HARDWARE_DEVICE_PATH = 0x01
    ACPI_DEVICE_PATH = 0x02
    MESSAGING_DEVICE_PATH = 0x03
    MEDIA_DEVICE_PATH = 0x04
    BBS_DEVICE_PATH = 0x05
    END_DEVICE_PATH = 0x7f

# ----------------------------------------------------------------------------------------
class HardwareDevicePathSubType(UEnum):
    HW_PCI_DP = 0x01
    HW_PCCARD_DP = 0x02
    HW_MEMMAP_DP = 0x03
    HW_VENDOR_DP = 0x04
    HW_CONTROLLER_DP = 0x05
    HW_BMC_DP = 0x06

# ----------------------------------------------------------------------------------------
class ACPIDevicePathSubType(UEnum):
    ACPI_DP = 0x01
    ACPI_EXTENDED_DP = 0x02
    ACPI_ADR_DP = 0x03
    ACPI_NVDIMM_DP = 0x04

# ----------------------------------------------------------------------------------------
class MessagingDevicePathSubType(UEnum):
    MSG_ATAPI_DP = 0x01
    MSG_SCSI_DP = 0x02
    MSG_FIBRECHANNEL_DP = 0x03
    MSG_1394_DP = 0x04
    MSG_USB_DP = 0x05
    MSG_I2O_DP = 0x06
    MSG_INFINIBAND_DP = 0x09
    MSG_VENDOR_DP = 0x0a
    MSG_MAC_ADDR_DP = 0x0b
    MSG_IPv4_DP = 0x0c
    MSG_IPv6_DP = 0x0d
    MSG_UART_DP = 0x0e
    MSG_USB_CLASS_DP = 0x0f
    MSG_USB_WWID_DP = 0x10
    MSG_DEVICE_LOGICAL_UNIT_DP = 0x11
    MSG_SATA_DP = 0x12
    MSG_ISCSI_DP = 0x13
    MSG_VLAN_DP = 0x14
    MSG_FIBRECHANNELEX_DP = 0x15
    MSG_SASEX_DP = 0x16
    MSG_NVME_NAMESPACE_DP = 0x17
    MSG_URI_DP = 0x18
    MSG_UFS_DP = 0x19
    MSG_SD_DP = 0x1a
    MSG_BLUETOOTH_DP = 0x1b
    MSG_WIFI_DP = 0x1c
    MSG_EMMC_DP = 0x1d
    MSG_BLUETOOTH_LE_DP = 0x1e
    MSG_DNS_DP = 0x1f

# ----------------------------------------------------------------------------------------
class MediaDevicePathSubType(UEnum):
    MEDIA_HARDDRIVE_DP = 0x01
    MEDIA_CDROM_DP = 0x02
    MEDIA_VENDOR_DP = 0x03
    MEDIA_FILEPATH_DP = 0x04
    MEDIA_PROTOCOL_DP = 0x05
    MEDIA_PIWG_FW_FILE_DP = 0x06
    MEDIA_PIWG_FW_VOL_DP = 0x07
    MEDIA_RELATIVE_OFFSET_RANGE_DP = 0x08
    MEDIA_RAM_DISK_DP = 0x09

# ----------------------------------------------------------------------------------------
class BiosBootSpecDevicePathSubType(UEnum):
    BBS_BBS_DP = 0x01

# ----------------------------------------------------------------------------------------
class EndDevicePathSubType(UEnum):
    END_DEVICE_PATH_MORE = 0x1  # Unofficial?  Seen in Ed's Dell ROM?
    END_DEVICE_PATH_SUBTYPE = 0xff

# ----------------------------------------------------------------------------------------
class GenericSubType(UEnum):
    UNKNOWN = 0x0

# ----------------------------------------------------------------------------------------
DevicePathSubTypes = Union[HardwareDevicePathSubType, ACPIDevicePathSubType,
                           MessagingDevicePathSubType, MediaDevicePathSubType,
                           BiosBootSpecDevicePathSubType, EndDevicePathSubType]

# ----------------------------------------------------------------------------------------
class EFIDevicePath(FirmwareStructure):
    """
    EFI_DEVICE_PATH_PROTOCOL
    https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Protocol/DevicePath.h

    Since each device path structure has a different interpretation of the data, I should
    probably create a firmware structure for each of these types and subtypes, with
    constants for type and subtype, and then make this one the generic EFI device path.
    """

    label = "EFI Device Path"

    definition = Struct(
        "dptype" / EnumAdapter(Int8ul, DevicePathType),
        "_subtype" / Int8ul,  # EnumAdapater(Int8ul, DevicePathSubTypes)?
        "size" / Int16ul,
        "data" / Array(this.size - 4, Int8ul),
    )

    @property
    def subtype(self) -> Union[DevicePathSubTypes, GenericSubType]:
        if self.dptype == DevicePathType.HARDWARE_DEVICE_PATH:
            return HardwareDevicePathSubType(self._subtype)
        elif self.dptype == DevicePathType.ACPI_DEVICE_PATH:
            return ACPIDevicePathSubType(self._subtype)
        elif self.dptype == DevicePathType.MESSAGING_DEVICE_PATH:
            return MessagingDevicePathSubType(self._subtype)
        elif self.dptype == DevicePathType.MEDIA_DEVICE_PATH:
            return MediaDevicePathSubType(self._subtype)
        elif self.dptype == DevicePathType.BBS_DEVICE_PATH:
            return BiosBootSpecDevicePathSubType(self._subtype)
        elif self.dptype == DevicePathType.END_DEVICE_PATH:
            return EndDevicePathSubType(self._subtype)
        else:
            return GenericSubType(self._subtype)

    reporting = [
        ["dptype"], ["subtype"],
        ["size", "0x%02x"],
        ["data", lambda self: str(["0x%02x" % v for v in self.data])],
    ]

# ----------------------------------------------------------------------------------------
class EFIUSBDevicePath(FirmwareStructure):
    """
    USB_DEVICE_PATH in edk2/MdePkg/Include/Protocol/DevicePath.h
    """

    label = "EFI USB Device Path"

    definition = Struct(
        "dptype" / EnumAdapter(
            Const(DevicePathType.MESSAGING_DEVICE_PATH.value, Int8ul), DevicePathType),
        "subtype" / EnumAdapter(
            Const(MessagingDevicePathSubType.MSG_USB_DP.value, Int8ul),
            MessagingDevicePathSubType),
        "size" / Int16ul,
        "port" / Int8ul,
        "interface" / Int8ul,
    )

    reporting = [
        ["dptype"], ["subtype"], ["size", "0x%02x"], ["port"], ["interface"],
    ]

# ----------------------------------------------------------------------------------------
class EFIPCIDevicePath(FirmwareStructure):
    """
    PCI_DEVICE_PATH in edk2/MdePkg/Include/Protocol/DevicePath.h
    """

    label = "EFI PCI Device Path"

    definition = Struct(
        "dptype" / EnumAdapter(
            Const(DevicePathType.HARDWARE_DEVICE_PATH.value, Int8ul), DevicePathType),
        "subtype" / EnumAdapter(
            Const(HardwareDevicePathSubType.HW_PCI_DP.value, Int8ul),
            HardwareDevicePathSubType),
        "size" / Int16ul,
        "function" / Int8ul,
        "device" / Int8ul,
    )

    reporting = [
        ["dptype"], ["subtype"], ["size", "0x%02x"], ["function"], ["device"],
    ]

# ----------------------------------------------------------------------------------------
class EFIACPIDevicePath(FirmwareStructure):
    """
    ACPI_HID_DEVICE_PATH in edk2/MdePkg/Include/Protocol/DevicePath.h
    """

    label = "EFI ACPI Device Path"

    definition = Struct(
        "dptype" / EnumAdapter(
            Const(DevicePathType.ACPI_DEVICE_PATH.value, Int8ul), DevicePathType),
        "subtype" / EnumAdapter(
            Const(ACPIDevicePathSubType.ACPI_DP.value, Int8ul),
            ACPIDevicePathSubType),
        "size" / Int16ul,
        "hid" / Int32ul,
        "uid" / Int32ul,
    )

    reporting = [
        ["dptype"], ["subtype"], ["size", "0x%02x"], ["hid", "0x%x"], ["uid", "0x%x"],
    ]

# ----------------------------------------------------------------------------------------
class EFIMediaHarddrive(FirmwareStructure):

    label = "EFI Media Harddrive"

    definition = Struct(
        "dptype" / EnumAdapter(
            Const(DevicePathType.MEDIA_DEVICE_PATH.value, Int8ul), DevicePathType),
        "subtype" / EnumAdapter(
            Const(MediaDevicePathSubType.MEDIA_HARDDRIVE_DP.value, Int8ul),
            MediaDevicePathSubType),
        "size" / Int16ul,
        "partition_number" / Int32ul,
        "partition_start" / Int64ul,
        "partition_size" / Int64ul,
        "partition_id" / UUID16,
        "mbr_type" / Int8ul,
        "signature_type" / Int8ul,
        #"data" / Array(this.size - 4, Int8ul),
    )

    reporting = [
        ["dptype"], ["subtype"], ["size", "0x%02x"],
        [], ["partition_number"], ["partition_start"],
        ["partition_size"], ["partition_id"], ["mbr_type"], ["signature_type"],
    ]

# ----------------------------------------------------------------------------------------
class EFIMediaFilepath(FirmwareStructure):

    label = "EFI Media Filepath"

    definition = Struct(
        "dptype" / EnumAdapter(
            Const(DevicePathType.MEDIA_DEVICE_PATH.value, Int8ul), DevicePathType),
        "subtype" / EnumAdapter(
            Const(MediaDevicePathSubType.MEDIA_FILEPATH_DP.value, Int8ul),
            MediaDevicePathSubType),
        "size" / Int16ul,
        "path" / PaddedString(this.size - 4, "utf-16"),
    )

    reporting = [
        ["dptype"], ["subtype"], ["size", "0x%02x"], ["path"],
    ]

# ----------------------------------------------------------------------------------------
class EFIMediaPIWGVolume(FirmwareStructure):
    """
    Part of the UEFI PI Specification 1.0 to describe a firmware volume.
    MEDIA_FW_VOL_DEVICE_PATH in edk2/MdePkg/Include/Protocol/DevicePath.h
    """

    label = "EFI Media PIWG Volume"

    definition = Struct(
        "dptype" / EnumAdapter(
            Const(DevicePathType.MEDIA_DEVICE_PATH.value, Int8ul), DevicePathType),
        "subtype" / EnumAdapter(
            Const(MediaDevicePathSubType.MEDIA_PIWG_FW_VOL_DP.value, Int8ul),
            MediaDevicePathSubType),
        "size" / Int16ul,
        "guid" / UUID16
    )

    reporting = [
        ["dptype"], ["subtype"], ["size", "0x%02x"], ["guid"],
    ]

# ----------------------------------------------------------------------------------------
class EFIMediaPIWGFile(FirmwareStructure):
    """
    Part of the UEFI PI Specification 1.0 to describe a firmware file.
    MEDIA_FW_VOL_FILEPATH_DEVICE_PATH in edk2/MdePkg/Include/Protocol/DevicePath.h
    """

    label = "EFI Media PIWG File"

    definition = Struct(
        "dptype" / EnumAdapter(
            Const(DevicePathType.MEDIA_DEVICE_PATH.value, Int8ul), DevicePathType),
        "subtype" / EnumAdapter(
            Const(MediaDevicePathSubType.MEDIA_PIWG_FW_FILE_DP.value, Int8ul),
            MediaDevicePathSubType),
        "size" / Int16ul,
        "guid" / UUID16
    )

    reporting = [
        ["dptype"], ["subtype"], ["size", "0x%02x"], ["guid"],
    ]

# ----------------------------------------------------------------------------------------
AMI_DEVICE_NAME_DEVICE_PATH_GUID = UUID('2d6447ef-3bc9-41a0-ac19-4d51d01b4ce6')
class EFIVendorDevicePath(FirmwareStructure):
    """
    VENDOR_DEVICE_PATH in edk2/MdePkg/Include/Protocol/DevicePath.h
    """

    label = "EFI Vendor Device Path"

    definition = Struct(
        "dptype" / EnumAdapter(
            Const(DevicePathType.HARDWARE_DEVICE_PATH.value, Int8ul), DevicePathType),
        "subtype" / EnumAdapter(
            Const(HardwareDevicePathSubType.HW_VENDOR_DP.value, Int8ul),
            HardwareDevicePathSubType),
        "size" / Int16ul,
        "guid" / UUID16,
        # Presumably, the remaining data is dependent on the GUID.
        "data" / Bytes(this.size - 20),
    )

    @property
    def interpretation(self) -> Optional[Union[str, bytes, HexDump]]:
        if self.guid == AMI_DEVICE_NAME_DEVICE_PATH_GUID:
            interp = CString('utf-16').parse(self.data)
            assert isinstance(interp, (str, bytes))
            return interp
        return self.subparse(HexDump, "data")

    reporting = [
        ["dptype"], ["subtype"], ["size", "0x%02x"],
        [], ["guid"], ["data", None], ["interpretation"]
    ]

# ----------------------------------------------------------------------------------------
EFIDevicePathSelect = Select(
    Class(EFIMediaHarddrive),
    Class(EFIMediaFilepath),
    Class(EFIUSBDevicePath),
    Class(EFIPCIDevicePath),
    Class(EFIACPIDevicePath),
    Class(EFIMediaPIWGVolume),
    Class(EFIMediaPIWGFile),
    Class(EFIVendorDevicePath),
    Class(EFIDevicePath),
)

# ----------------------------------------------------------------------------------------
class EFIDevicePathProtocol(FirmwareStructure):

    label = "EFI Device Path Protocol"

    definition = Struct(
        "entries" / GreedyRange(EFIDevicePathSelect),
    )

# ----------------------------------------------------------------------------------------
class EFILoadOption(FirmwareStructure):

    label = "EFI Load Option"

    definition = Struct(
        "attrs" / Int32ul,
        "path_len" / Int16ul,
        "description" / CString("utf-16-le"),
        #"devices" / RepeatUntil(lambda x, lst, ctx: x.type == 0x7f, EFIDevicePathSelect),
        "devices" / GreedyRange(EFIDevicePathSelect),
    )

    reporting = [
        ["attrs", "0x%x"], ["path_len"], ["description", "'%s'", purple], ["devices"]
    ]

# ----------------------------------------------------------------------------------------
class EVSAVariableStore(FirmwareStructure):

    label = "EVSA Variable Store"

    definition = Struct(
        # Should constant guid be parsed by parent object?
        # This is the EFI_AUTHENTICATED_VARIABLE_GUID
        "_guid" / Const(UUID('aaf32c78-947b-439a-a180-2e144ec37792').bytes_le),
        # https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Include/Guid/VariableFormat.h
        "size" / Int32ul,
        "_block_size" / Computed(this.size + 4096 - 44),
        "pad_size" / Computed(this._block_size - this.size),
        "format" / Int8ul,
        "state" / Int8ul,
        "reserved" / Bytes(6),
        "variables" / GreedyRange(Aligned(4, Class(AuthenticatedVariable))),
    )

    reporting = [
        ["guid"], ["size"], ["reserved", None]
    ]

    @property
    def guid(self) -> UUID:
        return UUID(bytes_le=self._guid)

    def validate(self) -> None:
        if self.reserved != b'\x00\x00\x00\x00\x00\x00':
            self.validation_error("EVSA reserved bytes were not zeros!")
        if self.format != 0x5a:
            self.validation_error("EVSA format was not formatted!")
        if self.state != 0xfe:
            self.validation_error("EVSA was not healthy!")

    #def __init__(self, data):
    #    # It appears that the var_size is padded out to a multiple of 4k?
    #    # The 28 substraction appears to be the EVSA header size.
    #    self.var_size += 4096 - 28
    #
    #    remaining_size = self.var_size - o
    #    remaining_data = raw_data[o:o+remaining_size]
    #    if remaining_data != b'\xff' * remaining_size:
    #        self.debug("Variable store was not padded out with FF bytes.")
    #
    #    offset = 28+self.var_size
    #    self.sig_guid = None
    #    self.checksum = 0
    #    self.flags = 0
    #    self.reserved = 0
    #    self.wq_size = 0
    #    if self.size < offset + 16:
    #        return
    #    self.sig_guid = UUID(bytes_le=data[offset:offset+16])
    #
    #    # Also, decide how to interpret EFI_FFS_VOLUME_TOP_FILE_GUID

# ----------------------------------------------------------------------------------------
@promote_exceptions
def guess_variable_type(name: str, vallen: int) -> Construct:
    """
    Guess a reasonable interpretation of the value.

    Moved out of NVARVariable because of different kinds of variable objects.
    """

    do_load_option = False
    # Known variables...  See Table 11, UEFI Spec version 2.6, page 83
    # https://uefi.org/sites/default/files/resources/UEFI%20Spec%202_6.pdf
    if name in ["StdDefaults"]:
        from .uefi import NVRAMVariableStore
        return Class(NVRAMVariableStore)
    elif name in ["FirmwarePerformance"] and vallen == 16:
        return Class(EFIFirmwarePerformance)
    elif name in ["BootOrder", "DriverOrder", "DefaultBootOrder"]:
        return Array(int(vallen / 2), Int16ul)
    elif name in ["ConIn", "ConOut", "ErrOut", "ConInDev", "ConOutDev", "ErrOutDev"]:
        return Class(EFIDevicePathProtocol)
    elif name in ["Timeout", "BootNext", "BootCurrent"]:
        return Int16ul
    elif name in ["BootOptionSupport"]:
        return Int32ul
    elif name in ["InitialAttemptOrder"]:
        return Array(vallen, Int8ul)
    elif name in ["PlatformLangCodes", "PlatformLang", "PlatformLastLangCodes", "Lang"]:
        return PaddedString(vallen, "ascii")
    elif name in ["db", "PK", "KEK", "dbx"]:
        return Class(SecureBootVariable)
    elif name in ["MokList"]:
        return Class(MokList)
    # Not working well.  Mildly too permissive, so should be last.
    elif name and len(name) == 8 and name.startswith("Boot"):
        do_load_option = True
    elif name and len(name) == 10 and name.startswith("Driver"):
        do_load_option = True
    elif name and len(name) == 16 and name.startswith("PlatformRecovery"):
        do_load_option = True

    if do_load_option:
        try:
            int(name[4:8], 16)
            return Class(EFILoadOption)
        except ValueError:
            pass

    # The first algorithm is just to return ints.
    if vallen == 1:
        return Int8ul
    if vallen == 2:
        return Int16ul
    if vallen == 4:
        return Int32ul

    # By default, just parse an array of bytes.
    return Bytes(vallen)
    #return Class(HexDump)

# ----------------------------------------------------------------------------------------
class VMWareCMOSThing(FirmwareStructure):

    label = "VMWare CMOS Thing"

    definition = Struct(
        "_magic" / Const(b'CMOS'),
        "name" / Bytes(4),
        "size" / Int16ul,
        #"data" / Bytes(this.size + 2),
        "data" / FixedLength(this.size + 2, Class(MysteryBytes)),
    )

# ----------------------------------------------------------------------------------------
class VMWareESCDThing(FirmwareStructure):

    label = "VMWare ESCD Thing"

    definition = Struct(
        "_magic" / Const(b'ESCD'),
        "u1" / Int32ul,
    )

    reporting = [["u1", "0x%x"]]

# ----------------------------------------------------------------------------------------
class VMWareELOGThing(FirmwareStructure):

    label = "VMWare ELOG Thing"

    definition = Struct(
        "_magic" / Const(b'ELOG'),
        # Size maybe?  The ACFG records that follow total 1200 bytes, while this value is
        # 1217, so it's close to being correct, but it doesn't match exactly?
        "size" / Int16ul,
        "u2" / Int8ul,
        "u3" / Int8ul,
        # These could be counts, there are 7 ACFG records that follow and u4=4 & u5=3.
        "u4" / Int8ul,
        "u5" / Int8ul,
    )

# ----------------------------------------------------------------------------------------
class VMWareNAPIThing(FirmwareStructure):

    label = "VMWare NAPI Thing"

    definition = Struct(
        "_magic" / Const(b'NAPI'),
        "u1" / Int8ul,
        "u2" / Int8ul,
        "u3" / Int8ul,
    )

# ----------------------------------------------------------------------------------------
class VMWareBBSIThing(FirmwareStructure):

    label = "VMWare BBSI Thing"

    definition = Struct(
        "_magic" / Const(b'BBSI'),
        "u1" / Int32ul,
    )

    reporting = [["u1", "0x%x"]]

# ----------------------------------------------------------------------------------------
class VMWareACFGThing344(FirmwareStructure):

    label = "VMWare ACFG Thing"

    definition = Struct(
        "_magic" / Const(b'ACFG'),
        "u1" / Int8ul,
        "u2" / Int8ul,
        "data" / FixedLength(344, Class(HexDump)),
    )

# ----------------------------------------------------------------------------------------
class VMWareACFGThing53(FirmwareStructure):

    label = "VMWare ACFG Thing"

    definition = Struct(
        "_magic" / Const(b'ACFG'),
        "u1" / Int8ul,
        "u2" / Int8ul,
        "data" / FixedLength(53, Class(HexDump)),
    )

# ----------------------------------------------------------------------------------------
class VMWareACFGThing98(FirmwareStructure):

    label = "VMWare ACFG Thing"

    definition = Struct(
        "_magic" / Const(b'ACFG'),
        "u1" / Int8ul,
        "u2" / Int8ul,
        "data" / FixedLength(98, Class(HexDump)),
    )

# ----------------------------------------------------------------------------------------
class VMWareACFGThing57(FirmwareStructure):

    label = "VMWare ACFG Thing"

    definition = Struct(
        "_magic" / Const(b'ACFG'),
        "u1" / Int8ul,
        "u2" / Int8ul,
        "data" / FixedLength(57, Class(HexDump)),
    )

# ----------------------------------------------------------------------------------------
class VMWareACFGThing40(FirmwareStructure):

    label = "VMWare ACFG Thing"

    definition = Struct(
        "_magic" / Const(b'ACFG'),
        "u1" / Int8ul,
        "u2" / Int8ul,
        "data" / FixedLength(40, Class(HexDump)),
    )

# ----------------------------------------------------------------------------------------
class VMWareACFGThing76(FirmwareStructure):

    label = "VMWare ACFG Thing"

    definition = Struct(
        "_magic" / Const(b'ACFG'),
        "u1" / Int8ul,
        "u2" / Int8ul,
        "data" / FixedLength(76, Class(HexDump)),
    )

# ----------------------------------------------------------------------------------------
class VMWareACFGThing490(FirmwareStructure):

    label = "VMWare ACFG Thing"

    definition = Struct(
        "_magic" / Const(b'ACFG'),
        "u1" / Int8ul,
        "u2" / Int8ul,
        "data" / FixedLength(490, Class(HexDump)),
    )

# ----------------------------------------------------------------------------------------
class VMWareSecureBootVariable(FirmwareStructure):

    label = "VMWare Secure Boot Variable"

    definition = Struct(
        "guid1" / UUID16,
        "u1" / Int32ul,
        "u2" / Int16ul,
        "u3" / Int16ul,
        "guid2" / UUID16,
        "sbvar" / Class(SecureBootVariable),
    )

    reporting = [["u1"], ["u2"], ["u3"], [], ["guid1"], ["guid2"]]

# ----------------------------------------------------------------------------------------
class MemoryRange(FirmwareStructure):
    # EDK2: MdeModulePkg/Include/Guid/MemoryTypeInformation.h
    # UEFI Spec Section 15.3, Table 15.6 UEFI Memory Types and mapping to ACPI address range types

    label = "Memory Range"

    definition = Struct(
        "type" / Int32ul,
        "pages" / Int32ul,
    )

    reporting = [["type"], ["pages"]]

# ----------------------------------------------------------------------------------------
class MemoryTypeInformation(FirmwareStructure):

    label = "Memory Type Information"

    definition = Struct(
        "ranges" / GreedyRange(Class(MemoryRange)),
        "unexpected" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
class MokList(SignatureDatabase):
    """
    A list of authorized keys and hashes.

    EFI_SIGNATURE_LIST as described in the UEFI specification. BS,NV
    https://github.com/rhboot/shim/blob/main/MokVars.txt
    edk2/MdePkg/Include/Guid/ImageAuthentication.h
    https://uefi.org/specs/UEFI/2.9_A/32_Secure_Boot_and_Driver_Signing.html#efi-signature-data
    """

    label = "Machine Owner Key (MOK) List"

# ----------------------------------------------------------------------------------------
@promote_exceptions
def guess_vmware_type(name: str, vallen: int) -> Construct:
    """
    Guess a reasonable interpretation of the value (for VMWare NVRAM variables).
    """

    if name in ["PK", "KEK", "db", "dbx"]:
        return Class(VMWareSecureBootVariable)
    elif name in ["MokList"]:
        return Class(MokList)
    # Maybe NOT VMWare Specific?
    elif name in ["MemoryTypeInformation"]:
        return Class(MemoryTypeInformation)
    else:
        return guess_variable_type(name, vallen)

    #elif name in ["Boot0000", "Boot0001", "Boot0002", "Boot0003", "Boot0004", "Boot0005"]:
    #    return Class(EFILoadOption)
    #elif name in ["ConIn", "ConOut", "ErrOut", "ConInDev", "ConOutDev", "ErrOutDev"]:
    #    return Class(EFIDevicePathProtocol)
    #else:
    #    return Class(HexDump)

# ----------------------------------------------------------------------------------------
class VMWareVariable(FirmwareStructure):

    label = "VMWare NVRAM Variable"

    definition = Struct(
        "guid" / UUID16,
        "flags" / Int32ul,
        "size" / Int32ul,
        "name_size" / Int32ul,
        "name" / PaddedString(this.name_size, "utf-16-le"),
        "data_size" / Computed(lambda ctx: ctx.size - ctx.name_size),
        #"data" / FixedLength(this.data_size, Class(HexDump)),
        "data" / FixedLength(this.data_size,
                             LazyBind(lambda ctx: guess_vmware_type(ctx.name, ctx.data_size))),

        # "attributes" / Int32ul,
        # "monotonic_count" / Int64ul,
        # "timestamp" / Class(EfiTime),
        # "pubkey_index" / Int32ul,
        # "name_size" / Int32ul,
        # "data_size" / Int32ul,
        # #StopIf(this.guid == b'\xff' * 16) ?
        # "data" / Aligned(2, FixedLength(
        #     this.data_size,
        #     LazyBind(lambda ctx: guess_variable_type(ctx.name, ctx.data_size)))),
    )

    reporting = [
        ["guid"], ["name"], ["flags", "0x%x"], ["size"], ["name_size"], ["data_size"],
        ["data"],
    ]

# ----------------------------------------------------------------------------------------
class VMWareNVVars(FirmwareStructure):

    label = "VMWare NVVars"

    definition = Struct(
        "u1" / Int8ul,
        "_magic1" / Const(b'EFI_NV\x00\x00'),
        "size1" / Int32ul,
        # size1 = size2 + ffpad
        "_magic2" / Const(b'VMWNVRAM'),
        "u3" / Int32ul,
        "size2" / Int32ul,
        "vars" / GreedyRange(Class(VMWareVariable)),
        "_ff_padding" / GreedyRange(Const(b'\xff')),
        "ffpad" / Computed(lambda ctx: len(ctx._ff_padding)),
        "unexpected" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
class VMWareNVRAM(FirmwareStructure):

    label = "VMWare NVRAM"

    definition = Struct(
        "_mvrn_magic" / Const(b'MRVN'),
        "version" / Int32ul,  # Maybe?
        "cmos" / GreedyRange(Class(VMWareCMOSThing)),
        "escd0" / Class(VMWareESCDThing),
        "u1" / Int32ul,
        "napi1" / Class(VMWareNAPIThing),
        "escd1" / Class(VMWareESCDThing),
        "bbsi1" / Class(VMWareBBSIThing),
        "elog1" / Class(VMWareELOGThing),
        "acfg11" / Class(VMWareACFGThing344),
        "acfg12" / Class(VMWareACFGThing53),
        "acfg13" / Class(VMWareACFGThing98),
        "acfg14" / Class(VMWareACFGThing57),
        "acfg15" / Class(VMWareACFGThing40),
        "acfg16" / Class(VMWareACFGThing76),
        "acfg17" / Class(VMWareACFGThing490),
        "_ff_padding1" / GreedyRange(Const(b'\xff')),
        "ffpad1" / Computed(lambda ctx: len(ctx._ff_padding1)),
        "_zero_padding1" / GreedyRange(Const(b'\x00')),
        "zpad1" / Computed(lambda ctx: len(ctx._zero_padding1)),

        "napi2" / Class(VMWareNAPIThing),
        "escd2" / Class(VMWareESCDThing),
        "bbsi2" / Class(VMWareBBSIThing),
        "elog2" / Class(VMWareELOGThing),
        "acfg21" / Class(VMWareACFGThing344),
        "acfg22" / Class(VMWareACFGThing53),
        "acfg23" / Class(VMWareACFGThing98),
        "acfg24" / Class(VMWareACFGThing57),
        "acfg25" / Class(VMWareACFGThing40),
        "acfg26" / Class(VMWareACFGThing76),
        "acfg27" / Class(VMWareACFGThing490),
        "_ff_padding2" / GreedyRange(Const(b'\xff')),
        "ffpad2" / Computed(lambda ctx: len(ctx._ff_padding2)),
        "_zero_padding2" / GreedyRange(Const(b'\x00')),
        "zpad2" / Computed(lambda ctx: len(ctx._zero_padding2)),

        "data" / Class(VMWareNVVars),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["version"], ["u1"], ["ffpad1"], ["zpad1"], ["ffpad2"], ["zpad2"],
        ["cmos"], ["escd0"],

        ["napi1"], ["escd1"], ["bbsi1"], ["elog1"],
        ["acfg11"], ["acfg12"], ["acfg13"], ["acfg14"], ["acfg15"], ["acfg16"], ["acfg17"],

        ["napi2"], ["escd2"], ["bbsi2"], ["elog2"],
        ["acfg21"], ["acfg22"], ["acfg23"], ["acfg24"], ["acfg25"], ["acfg26"], ["acfg27"],

        ["data"],
    ]

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
