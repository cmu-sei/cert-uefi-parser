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
Executable file formats.
"""

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Union, Any

from construct import (
    Array, Bytes, Computed, Const, GreedyBytes, GreedyRange, Select, Switch,
    Int8ul, Int16ul, Int32ul, Int64ul, BytesInteger, Tell, this)
from construct.lib.containers import ListContainer  # type: ignore

from .base import (
    FirmwareStructure, Class, PaddedString, FixedLength, Struct, UUID16, LazyBind,
    HexBytes, Context, CString, EnumAdapter)
from .uenum import UEnum
from .mystery import MysteryBytes, CommitMystery, HexDump
from .bootguard import TPMAlgorithm
from .nvvars import EFIDevicePathProtocol

log = logging.getLogger("cert-uefi-parser")

# ========================================================================================
# PCR Usage Notes
# ========================================================================================

# PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf
# Especially figure 6 on page 25 amnd table 1 on page 26, but also pages 28, 31, ...
# Also: https://tianocore-docs.github.io/edk2-TrustedBootChain/release-1.00/3_TCG_Trusted_Boot_Chain_in_EDKII.html

# ----------------------------------------------------------------------------------------
# PCR[0-7]: Host Platform’s pre-OS environment
# ----------------------------------------------------------------------------------------

# PCR[0] typically represents a consistent view of the Host Platform between boot cycles.
# SRTM, BIOS, Host Platform Extensions, Embedded Option ROMs and PI Drivers.

# PCR[1] contains information about the configuration of the PC Motherboard including
# hardware components and how they are configured.

# PCR[2] is intended to represent a more “user” configurable environment where the user
# has the ability to alter the set of installed components that are measured.  UEFI driver
# and application Code.

# PCR[3] contains UEFI driver and application Configuration and Data.

# PCR[4] is intended to represent the entity that manages the transition between the pre-
# OS and the OS-Present state of the platform. This PCR, along with PCR[5], identifies the
# initial OS loader.

# PCR[5] Boot Manager Code Configuration and Data (for use by the Boot Manager Code) and
# GPT/Partition Table.

# PCR[6] Host Platform Manufacturer Specific

# PCR[7] Secure Boot Policy

# ----------------------------------------------------------------------------------------
# PCR[8-15]: Host Platform’s Static OS environment
# ----------------------------------------------------------------------------------------

# ----------------------------------------------------------------------------------------
# PCR[16-23]: ???
# ----------------------------------------------------------------------------------------

# PCR[16] Debug
# PCR[23] Application Support

# ========================================================================================

# Also check out this source code for dumping the log at at EFI shell prompt.
#   https://blog.fpmurphy.com/2015/11/uefi-shell-utility-to-display-tpm-1-2-event-log.html

# ----------------------------------------------------------------------------------------
class TPMEventLogTLV(FirmwareStructure):

    definition = Struct(
        "T" / Int8ul,
        "L" / Int32ul,
        "V" / Bytes(this.L),
    )

# ----------------------------------------------------------------------------------------
class EventType(UEnum):
    """
    EDK2: MdePkg/Include/IndustryStandard/UefiTcgPlatform.h
    https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_05_3feb20.pdf
    """

    EV_PREBOOT_CERT = 0
    EV_POST_CODE = 1
    EV_UNUSED = 2
    EV_NO_ACTION = 3
    EV_SEPARATOR = 4
    EV_ACTION = 5
    EV_EVENT_TAG = 6
    EV_S_CRTM_CONTENTS = 7
    EV_S_CRTM_VERSION = 8
    EV_CPU_MICROCODE = 9
    EV_PLATFORM_CONFIG_FLAGS = 0xa
    EV_TABLE_OF_DEVICES = 0xb
    EV_COMPACT_HASH = 0xc
    EV_IPL = 0xd  # Decprecated
    EV_IPL_PARTITION_DATA = 0xe  # Decprecated
    EV_NONHOST_CODE = 0xf
    EV_NONHOST_CONFIG = 0x10
    EV_NONHOST_INFO = 0x11
    EV_OMIT_BOOT_DEVICE_EVENTS = 0x12

    EV_EFI_EVENT_BASE = 0x80000000
    EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001
    EV_EFI_VARIABLE_BOOT = 0x80000002
    EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003
    EV_EFI_BOOT_SERVICES_DRIVER = 0x80000004
    EV_EFI_RUNTIME_SERVICES_DRIVER = 0x80000005
    EV_EFI_GPT_EVENT = 0x80000006
    EV_EFI_ACTION = 0x80000007
    EV_EFI_PLATFORM_FIRMWARE_BLOB = 0x80000008
    EV_EFI_HANDOFF_TABLES = 0x80000009
    EV_EFI_PLATFORM_FIRMWARE_BLOB2 = 0x8000000a
    EV_EFI_HANDOFF_TABLES2 = 0x8000000b
    # 0xc-0xf are reserved for future use.
    EV_EFI_HCRTM_EVENT = 0x80000010
    # 0x11-0xdf are reserved for future use.
    EV_EFI_VARIABLE_AUTHORITY = 0x800000e0
    EV_EFI_SPDM_FIRMWARE_BLOB = 0x800000e1
    EV_EFI_SPDM_FIRMWARE_CONFIG = 0x800000e2
    # 0xe1-0xffff are reserved for future use.

# ----------------------------------------------------------------------------------------
class TPMAlgorithmSize(FirmwareStructure):
    """
    TCG_EfiSpecIdEventAlgorithmSize in UefiTcgPlatform.h
    """

    label = "TPM Algorithm Size"

    definition = Struct(
        "algorithm" / EnumAdapter(Int16ul, TPMAlgorithm),
        "size" / Int16ul,
    )

# ----------------------------------------------------------------------------------------
class TPMEventLogHeader(FirmwareStructure):
    """

    """

    label = "TPM Event Log Header"

    definition = Struct(
        "pcr" / Const(0, Int32ul),
        "event" / EnumAdapter(Const(3, Int32ul), EventType),
        "_sha1" / Const(b'\x00' * 20),
        "sha1" / Computed(lambda ctx: ctx._sha1.hex()),
        "data_size" / Const(37, Int32ul),

        "signature" / PaddedString(16, 'utf-8'),
        "platform_class" / Int32ul,
        "spec_vers_minor" / Int8ul,
        "spec_vers_major" / Int8ul,
        "spec_errata" / Int8ul,
        "uintn_size" / Int8ul,  # 1=32-bit, 2=64-bit
        "num_algos" / Int32ul,
        "algorithms" / Array(this.num_algos, Class(TPMAlgorithmSize)),
        "vendor_size" / Int8ul,
        "vendor_info" / Bytes(this.vendor_size),
    )

    reporting = [
        ["pcr"], ["event"], ["signature"], ["platform_class"],
        ["spec_vers_minor"], ["spec_vers_major"], ["spec_errata"],
        [], ["uintn_size"], ["sha1"], ["data_size"], ["num_algos"],
        ["vendor_size"], ["vendor_info"],
        ["algorithms"],
    ]

# ----------------------------------------------------------------------------------------
class TPMEventDigest(FirmwareStructure):

    label = "TPM Event Digest"

    definition = Struct(
        "type" / EnumAdapter(Int16ul, TPMAlgorithm),
        "value" / Switch(this.type, {
            TPMAlgorithm.SHA1: Bytes(20),
            TPMAlgorithm.SHA256: Bytes(32),
        }),
        # "hex" / Computed(lambda ctx: ctx.value.hex()),
    )

    value: bytes

    @property
    def digest(self) -> str:
        if self.value is not None:
            return self.value.hex()
        return "NONE"

    reporting = [["digest"], ["value", None], ["type"]]

# ----------------------------------------------------------------------------------------
class TPMEventVariableData(FirmwareStructure):

    label = "TPM Event Variable Data"

    definition = Struct(
        "guid" / UUID16,
        "name_size" / Int64ul,
        "data_size" / Int64ul,
        "name" / PaddedString(lambda ctx: int(ctx.name_size * 2), "utf-16"),
        "failure" / CommitMystery,
        "data" / GreedyBytes,
    )

    intepretation: Union[list[FirmwareStructure], FirmwareStructure]

    reporting = [
        ["name"], ["guid"], ["name_size"], ["data_size"], ["data", None], ["interpretation"],
    ]

    def analyze(self) -> None:
        from .nvvars import guess_variable_type
        objtype = guess_variable_type(self.name, self.data_size)
        value = self.subparse(objtype, "data")

        # Print BootOrder nicely...
        if isinstance(value, ListContainer):
            self.interpretation = list(value)
        else:
            self.interpretation = value  # type: ignore

# ----------------------------------------------------------------------------------------
class TPMEventImageLoad(FirmwareStructure):
    """
    UEFI_IMAGE_LOAD_EVENT
    https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf
    """

    label = "TPM Event Image Load"

    definition = Struct(
        "location" / Int64ul,  # UEFI Physical address
        "length" / Int64ul,
        "address" / Int64ul,
        "path_size" / Int64ul,
        "path" / FixedLength(this.path_size, Class(EFIDevicePathProtocol)),
    )

    reporting = [
        ["location", "0x%x"], ["length", "0x%x"], ["address", "0x%x"],
        ["path_size"], ["path"],
    ]

# ----------------------------------------------------------------------------------------
class SIPAEventType(UEnum):
    # SIPAEVENTTYPE_CONTAINER
    SIPAEVENT_TRUSTBOUNDARY                       = 0x40010001  # 'TrustBoundary'
    SIPAEVENT_ELAM_AGGREGATION                    = 0x40010002  # 'ELAMAggregation'
    SIPAEVENT_LOADEDMODULE_AGGREGATION            = 0x40010003  # 'LoadedModuleAggregation'
    SIPAEVENT_TRUSTPOINT_AGGREGATION              = 0xC0010004  # 'TrustpointAggregation'
    SIPAEVENT_KSR_AGGREGATION                     = 0x40010005  # 'KSRAggregation'
    SIPAEVENT_KSR_SIGNED_MEASUREMENT_AGGREGATION  = 0x40010006  # 'KSRSignedMeasurementAggregation'
    # SIPAEVENTTYPE_INFORMATION
    SIPAEVENT_INFORMATION                         = 0x00020001  # 'Information'
    SIPAEVENT_BOOTCOUNTER                         = 0x00020002  # 'BootCounter'
    SIPAEVENT_TRANSFER_CONTROL                    = 0x00020003  # 'TransferControl'
    SIPAEVENT_APPLICATION_RETURN                  = 0x00020004  # 'ApplicationReturn'
    SIPAEVENT_BITLOCKER_UNLOCK                    = 0x00020005  # 'BitlockerUnlock'
    SIPAEVENT_EVENTCOUNTER                        = 0x00020006  # 'EventCounter'
    SIPAEVENT_COUNTERID                           = 0x00020007  # 'CounterID'
    SIPAEVENT_MORBIT_NOT_CANCELABLE               = 0x00020008  # 'MORBitNotCancelable'
    SIPAEVENT_APPLICATION_SVN                     = 0x00020009  # 'ApplicationSVN'
    SIPAEVENT_SVN_CHAIN_STATUS                    = 0x0002000A  # 'SVNChainStatus'
    SIPAEVENT_MORBIT_API_STATUS                   = 0x0002000B  # 'MORBitAPIStatus'
    # SIPAEVENTTYPE_PREOSPARAMETER
    SIPAEVENT_BOOTDEBUGGING                       = 0x00040001  # 'BootDebugging'
    SIPAEVENT_BOOT_REVOCATION_LIST                = 0x00040002  # 'BootRevocationList'
    # SIPAEVENTTYPE_OSPARAMETER
    SIPAEVENT_OSKERNELDEBUG                       = 0x00050001  # 'OSKernelDebug'
    SIPAEVENT_CODEINTEGRITY                       = 0x00050002  # 'CodeIntegrity'
    SIPAEVENT_TESTSIGNING                         = 0x00050003  # 'TestSigning'
    SIPAEVENT_DATAEXECUTIONPREVENTION             = 0x00050004  # 'DataExecutionPrevention'
    SIPAEVENT_SAFEMODE                            = 0x00050005  # 'SafeMode'
    SIPAEVENT_WINPE                               = 0x00050006  # 'WinPE'
    SIPAEVENT_PHYSICALADDRESSEXTENSION            = 0x00050007  # 'PhysicalAddressExtension'
    SIPAEVENT_OSDEVICE                            = 0x00050008  # 'OSDevice'
    SIPAEVENT_SYSTEMROOT                          = 0x00050009  # 'SystemRoot'
    SIPAEVENT_HYPERVISOR_LAUNCH_TYPE              = 0x0005000A  # 'HypervisorLaunchType'
    SIPAEVENT_HYPERVISOR_PATH                     = 0x0005000B  # 'HypervisorPath'
    SIPAEVENT_HYPERVISOR_IOMMU_POLICY             = 0x0005000C  # 'HypervisorIOMMUPolicy'
    SIPAEVENT_HYPERVISOR_DEBUG                    = 0x0005000D  # 'HypervisorDebug'
    SIPAEVENT_DRIVER_LOAD_POLICY                  = 0x0005000E  # 'DriverLoadPolicy'
    SIPAEVENT_SI_POLICY                           = 0x0005000F  # 'SIPolicy'
    SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY           = 0x00050010  # 'HypervisorMMIONXPolicy'
    SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY        = 0x00050011  # 'HypervisorMSRFilterPolicy'
    SIPAEVENT_VSM_LAUNCH_TYPE                     = 0x00050012  # 'VSMLaunchType'
    SIPAEVENT_OS_REVOCATION_LIST                  = 0x00050013  # 'OSRevocationList'
    SIPAEVENT_OS_0x00050014                       = 0x00050014  #
    SIPAEVENT_VSM_IDK_INFO                        = 0x00050020  # 'VSMIDKInfo'
    SIPAEVENT_FLIGHTSIGNING                       = 0x00050021  # 'FlightSigning'
    SIPAEVENT_PAGEFILE_ENCRYPTION_ENABLED         = 0x00050022  # 'PagefileEncryptionEnabled'
    SIPAEVENT_VSM_IDKS_INFO                       = 0x00050023  # 'VSMIDKSInfo'
    SIPAEVENT_HIBERNATION_DISABLED                = 0x00050024  # 'HibernationDisabled'
    SIPAEVENT_DUMPS_DISABLED                      = 0x00050025  # 'DumpsDisabled'
    SIPAEVENT_DUMP_ENCRYPTION_ENABLED             = 0x00050026  # 'DumpEncryptionEnabled'
    SIPAEVENT_DUMP_ENCRYPTION_KEY_DIGEST          = 0x00050027  # 'DumpEncryptionKeyDigest'
    SIPAEVENT_LSAISO_CONFIG                       = 0x00050028  # 'LSAISOConfig'
    SIPAEVENT_OS_0x00050030                       = 0x00050030  #
    # SIPAEVENTTYPE_AUTHORITY
    SIPAEVENT_NOAUTHORITY                         = 0x00060001  # 'NoAuthority'
    SIPAEVENT_AUTHORITYPUBKEY                     = 0x00060002  # 'AuthorityPubKey'
    # SIPAEVENTTYPE_LOADEDIMAGE
    SIPAEVENT_FILEPATH                            = 0x00070001  # 'FilePath'
    SIPAEVENT_IMAGESIZE                           = 0x00070002  # 'ImageSize'
    SIPAEVENT_HASHALGORITHMID                     = 0x00070003  # 'HashAlgorithmID'
    SIPAEVENT_AUTHENTICODEHASH                    = 0x00070004  # 'AuthenticodeHash'
    SIPAEVENT_AUTHORITYISSUER                     = 0x00070005  # 'AuthorityIssuer'
    SIPAEVENT_AUTHORITYSERIAL                     = 0x00070006  # 'AuthoritySerial'
    SIPAEVENT_IMAGEBASE                           = 0x00070007  # 'ImageBase'
    SIPAEVENT_AUTHORITYPUBLISHER                  = 0x00070008  # 'AuthorityPublisher'
    SIPAEVENT_AUTHORITYSHA1THUMBPRINT             = 0x00070009  # 'AuthoritySHA1Thumbprint'
    SIPAEVENT_IMAGEVALIDATED                      = 0x0007000A  # 'ImageValidated'
    SIPAEVENT_MODULE_SVN                          = 0x0007000B  # 'ModuleSVN'
    # SIPAEVENTTYPE_TRUSTPOINT
    SIPAEVENT_QUOTE                               = 0x80080001  # 'Quote'
    SIPAEVENT_QUOTESIGNATURE                      = 0x80080002  # 'QuoteSignature'
    SIPAEVENT_AIKID                               = 0x80080003  # 'AIKID'
    SIPAEVENT_AIKPUBDIGEST                        = 0x80080004  # 'AIKPubDigest'
    # SIPAEVENTTYPE_ELAM
    SIPAEVENT_ELAM_KEYNAME                        = 0x00090001  # 'ELAMKeyname'
    SIPAEVENT_ELAM_CONFIGURATION                  = 0x00090002  # 'ELAMConfiguration'
    SIPAEVENT_ELAM_POLICY                         = 0x00090003  # 'ELAMPolicy'
    SIPAEVENT_ELAM_MEASURED                       = 0x00090004  # 'ELAMMeasured'
    # SIPAEVENTTYPE_VBS
    SIPAEVENT_VBS_VSM_REQUIRED                    = 0x000A0001  # 'VBSVSMRequired'
    SIPAEVENT_VBS_SECUREBOOT_REQUIRED             = 0x000A0002  # 'VBSSecurebootRequired'
    SIPAEVENT_VBS_IOMMU_REQUIRED                  = 0x000A0003  # 'VBSIOMMURequired'
    SIPAEVENT_VBS_MMIO_NX_REQUIRED                = 0x000A0004  # 'VBSNXRequired'
    SIPAEVENT_VBS_MSR_FILTERING_REQUIRED          = 0x000A0005  # 'VBSMSRFilteringRequired'
    SIPAEVENT_VBS_MANDATORY_ENFORCEMENT           = 0x000A0006  # 'VBSMandatoryEnforcement'
    SIPAEVENT_VBS_HVCI_POLICY                     = 0x000A0007  # 'VBSHVCIPolicy'
    SIPAEVENT_VBS_MICROSOFT_BOOT_CHAIN_REQUIRED   = 0x000A0008  # 'VBSMicrosoftBootChainRequired'
    SIPAEVENT_VBS_0x000A000A                      = 0x000A000A  #
    # SIPAEVENTTYPE_KSR
    SIPAEVENT_KSR_SIGNATURE                       = 0x000B0001  # 'KSRSignature'

# ----------------------------------------------------------------------------------------
def lazy_sipa_event(ctx: Context) -> Select:
    return SIPAEvent

# ----------------------------------------------------------------------------------------
class SIPAEventAuthorityPubKey(FirmwareStructure):
    """
    No evidence for this parse, but it's probably not a coincidence that it works.
    """

    label = "SIPA Event Authority Public Key"

    definition = Struct(
        # SIPAEVENT_AUTHORITYPUBKEY                         = 0x00060002 # 'AuthorityPubKey'
        "_event_type" / Const(0x00060002, Int32ul),
        "event_size" / Int32ul,

        "hdr" / HexBytes(29),
        "u1" / Int8ul,
        "msize" / Int8ul,
        "u2" / Int8ul,
        "u3" / Int8ul,
        "modulus" / Bytes(lambda ctx: ctx.msize * 256),
        "u4" / Int8ul,
        "esize" / Int8ul,
        "exponent" / BytesInteger(this.esize, swapped=True),
    )

    reporting = [
        ["event_size"], ["exponent"], ["modulus", None], ["u1"], ["u2"], ["u3"], ["u4"],
        [], ["esize"], ["msize"], ["hdr"]
    ]

# ----------------------------------------------------------------------------------------
class SIPAPubKeyInfo(FirmwareStructure):

    label = "SIPA Public Key Info"

    definition = Struct(
        "algorithm" / Int32ul,
        "bits" / Int32ul,
        "exponent_size" / Int32ul,
        "modulus_size" / Int32ul,
        #"exponent" / Bytes(this.exponent_size),
        "exponent" / BytesInteger(this.exponent_size, swapped=True),
        # This is a big integer, and
        #"modulus" / Bytes(this.modulus_size),
        "modulus_int" / BytesInteger(this.modulus_size, swapped=True),
    )

    @property
    def modulus(self) -> str:
        return "(%d-byte integer)" % self.modulus_size

    reporting = [
        ["algorithm"], ["bits"], ["exponent"], ["modulus"], ["modulus_int", None],
        ["exponent_size", None], ["modulus_size", None],
    ]

# ----------------------------------------------------------------------------------------
class SIPAEventRevocationList(FirmwareStructure):

    label = "SIPA Event Revocation List"

    definition = Struct(
        "nanoseconds" / Int64ul,
        "digest_size" / Int32ul,
        "algorithm" / EnumAdapter(Int16ul, TPMAlgorithm),
        "digest" / HexBytes(16),
    )

    @property
    def creation_date(self) -> datetime:
        return datetime(1601, 1, 1) + timedelta(microseconds=(self.nanoseconds / 10))

    reporting = [
        ["creation_date"], ["nanoseconds", None], ["digest"],
        ["algorithm"], ["digest_size"]
    ]

# ----------------------------------------------------------------------------------------
class SIPAEventSIPolicy(FirmwareStructure):
    """
    https://github.com/mattifestation/TCGLogTools/blob/master/TCGLogTools.psm1#L607

    Also apparently:
    https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/operations/inbox-wdac-policies
    """

    label = "SIPA Event SI Policy"

    definition = Struct(
        "revision" / Int16ul,
        "build" / Int16ul,
        "minor" / Int16ul,
        "major" / Int16ul,
        "str_size" / Int16ul,
        "algorithm" / EnumAdapter(Int16ul, TPMAlgorithm),
        "digest_size" / Int32ul,
        #"data" / Class(HexDump),
        "str" / CString('utf-16'),
        "digest" / HexBytes(16),
    )

    reporting = [
        ["major"], ["minor"], ["revision"], ["build"],
        ["str"], ["digest"], ["algorithm"], ["str_size"], ["digest_size"],
    ]

# ----------------------------------------------------------------------------------------
class SIPAEventLoadedModule(FirmwareStructure):

    label = "SIPA Event Loaded Module"

    definition = Struct(
        "event_type" / Const(0x40010003, Int32ul),
        "event_size" / Int32ul,
        "_event_start" / Tell,
        "u1" / Int16ul,
        "u2" / Int16ul,
        "str_size" / Int32ul,
        "str" / PaddedString(this.str_size, 'utf-16'),
        "_event_end" / Tell,
        "remaining_size" / Computed(lambda ctx: ctx._event_end - ctx._event_end),
        "remaining" / Bytes(this.remaining_size),
    )

    reporting = [
        ["str"], ["str_size"], ["u1"], ["u2"],
    ]

# ----------------------------------------------------------------------------------------
class SIPAEventGeneric(FirmwareStructure):

    label = "SIPA Event Generic"

    definition = Struct(
        "event_type" / EnumAdapter(Int32ul, SIPAEventType),
        "event_size" / Int32ul,
        "failure" / CommitMystery,
        "data" / Bytes(this.event_size),
    )

    def analyze(self) -> None:
        self.interpretation = self.analyze_interpretation()

    def analyze_interpretation(self) -> Any:
        if self.event_size == 1:
            return Int8ul.parse(self.data)
        elif self.event_size == 4:
            return Int32ul.parse(self.data)
        elif self.event_size == 8:
            return Int64ul.parse(self.data)
        elif (self.event_type == SIPAEventType.SIPAEVENT_SYSTEMROOT
              or self.event_type == SIPAEventType.SIPAEVENT_ELAM_KEYNAME):
            string = PaddedString(self.event_size, 'utf-16').parse(self.data)
            return '"%s"' % string
        elif (self.event_type == SIPAEventType.SIPAEVENT_VSM_IDK_INFO
              or self.event_type == SIPAEventType.SIPAEVENT_VSM_IDKS_INFO):
            return self.subparse(SIPAPubKeyInfo, "data")
        elif (self.event_type == SIPAEventType.SIPAEVENT_OS_REVOCATION_LIST
              or self.event_type == SIPAEventType.SIPAEVENT_BOOT_REVOCATION_LIST):
            return self.subparse(SIPAEventRevocationList, "data")
        elif (self.event_type == SIPAEventType.SIPAEVENT_SI_POLICY):
            return self.subparse(SIPAEventSIPolicy, "data")
        elif self.data is not None:
            return self.data.hex()
        else:
            return None

    reporting = [
        ["event_type"], ["event_size"], ["data", None], ["interpretation"],
    ]

# ----------------------------------------------------------------------------------------
class SIPAEventTrustBoundary(FirmwareStructure):

    label = "SIPA Event Trust Boundary"

    definition = Struct(
        "_event_type" / Const(0x40010001, Int32ul),
        "event_size" / Int32ul,
        "subevents" / FixedLength(
            this.event_size,
            GreedyRange(LazyBind(lazy_sipa_event))),
    )

# ----------------------------------------------------------------------------------------
class SIPAEventELAMAggregation(FirmwareStructure):

    label = "SIPA Event ELAM Aggregation"

    definition = Struct(
        # SIPAEVENT_ELAM_AGGREGATION                        = 0x40010002 # 'ELAMAggregation'
        "_event_type" / Const(0x40010002, Int32ul),
        "event_size" / Int32ul,
        "subevents" / FixedLength(
            this.event_size,
            GreedyRange(LazyBind(lazy_sipa_event))),
    )

# ----------------------------------------------------------------------------------------
# System Integrity Platform Attestation (SIPA)
SIPAEvent = Select(
    Class(SIPAEventTrustBoundary),
    Class(SIPAEventLoadedModule),
    Class(SIPAEventAuthorityPubKey),
    Class(SIPAEventELAMAggregation),
    Class(SIPAEventGeneric),
)

# ----------------------------------------------------------------------------------------
class TPMEventTag(FirmwareStructure):

    definition = Struct(
        "events" / GreedyRange(SIPAEvent),
    )

# ----------------------------------------------------------------------------------------
class TPMEventPostCode(FirmwareStructure):
    """
    Used for PCR[0] only to record POST code, embedded SMM code, ACPI flash data, BIS code
    or manufacturer-controlled embedded option ROMs as a binary image.

    The digest field contains the tagged hash of the code or data to be measured (e.g.,
    POST portion of Platform Firmware) for each PCR bank.

    The event field SHOULD NOT contain the actual code or data, but MAY contain
    informative information about the POST code.

    For POST code, the event data SHOULD be “POST CODE”.  For embedded SMM code, the event
    data SHOULD be “SMM CODE”.  For ACPI flash data, the event data SHOULD be “ACPI DATA”.
    For BIS code, the event data SHOULD be “BIS CODE”.  For embedded option ROMs, the
    event data SHOULD be “Embedded UEFI Driver”.
    """

    label = "TPM Event Post Code"

    definition = Struct(
        "value" / Class(HexDump),
    )

# ----------------------------------------------------------------------------------------
class TPMEventPlatformConfigFlags(FirmwareStructure):
    """
    Section 2.3.4
    PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf

    Which measurements are currently on or off are measured using the
    EV_PLATFORM_CONFIG_FLAGS event in a vendor-specific format.

    EDK sample invocation at:
    edk2/IntelFsp2WrapperPkg/Library/BaseFspMeasurementLib/FspMeasurementLib.c
    """

    # 8b040000011c040000003004000001a90600000122070000002307000000aa06
    # 000000ce06000001120400000142040000014a04000001c504000001c6040000
    # 00610500000160050000015f0500000144240000001b04000000cc06000002cd
    # 060000007c040000000106000000780400000037040000012906000001230600
    # 0001220600000124060000016205000001860500000187050000003207000000
    # 0000000000

    label = "TPM Event Platform Configs Flags"

    definition = Struct(
        "value" / Class(HexDump),
    )

# ----------------------------------------------------------------------------------------
class TPMEventHandoffTable(FirmwareStructure):
    """
    Section 9.2.4
    PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf
    Also maybe: edk2/SecurityPkg/Tcg/Tcg2Pei/Tcg2Pei.c
    """

    label = "TPM Event Handoff Table"

    definition = Struct(
        "guid" / UUID16,
        "ptr" / Int64ul,
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["guid"], ["ptr", "0x%x"]]

# ----------------------------------------------------------------------------------------
class TPMEventHandoffTables(FirmwareStructure):
    """
    tdUEFI_HANDOFF_TABLE_POINTERS, Section 9.2.4
    PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf
    """

    label = "TPM Event Handoff Tables"

    definition = Struct(
        "num_tables" / Int64ul,
        "tables" / Array(this.num_tables, Class(TPMEventHandoffTable)),
    )

# ----------------------------------------------------------------------------------------
class EFIPartitionTableEntry(FirmwareStructure):
    """
    EFI_PARTITION_ENTRY in edk2/MdePkg/Include/Uefi/UefiGpt.h
    """

    label = "EFI Partition Table Entry"

    definition = Struct(
        # ID that defines the purpose and type of this Partition.
        "type" / UUID16,
        # GUID that is unique for every partition entry.
        "id" / UUID16,
        # Starting LBA of the partition defined by this entry
        "start_lba" / Int64ul,
        # Ending LBA of the partition defined by this entry.
        "end_lba" / Int64ul,
        # Attribute bits, all bits reserved by UEFI
        # Bit 0:      If this bit is set, the partition is required for the platform to
        #             function. The owner/creato partition indicates that deletion or
        #             modification of the contents can result in loss of plat features or
        #             failure for the platform to boot or operate. The system cannot
        #             function normally this partition is removed, and it should be
        #             considered part of the hardware of the system.  Actions such as
        #             running diagnostics, system recovery, or even OS install or boot,
        #             could potentially stop working if this partition is removed. Unless
        #             OS software or firmware recognizes this partition, it should never
        #             be removed or modified as the UEFI firmware or platform hardware may
        #             become non-functional.
        # Bit 1:      If this bit is set, then firmware must not produce an
        #             EFI_BLOCK_IO_PROTOCOL device for this partition. By not producing an
        #             EFI_BLOCK_IO_PROTOCOL partition, file system mappings will not be
        #             created for this partition in UEFI.
        # Bit 2:      This bit is set aside to let systems with traditional PC-AT BIOS firmware
        #             implementations inform certain limited, special-purpose software
        #             running on these systems that a GPT partition may be bootable. The
        #             UEFI boot manager must ignore this bit when selecting a
        #             UEFI-compliant application, e.g., an OS loader.
        # Bits 3-47:  Undefined and must be zero. Reserved for expansion by future versions
        #             of the UEFI specification.
        # Bits 48-63: Reserved for GUID specific use. The use of these bits will vary
        #             depending on the PartitionTypeGUID. Only the owner of the
        #             PartitionTypeGUID is allowed to modify these bits. They must be
        #             preserved if Bits 0-47 are modified..
        "attributes" / Int64ul,
        "name" / PaddedString(72, "utf-16"),
    )

    reporting = [
        ["id"], ["type"],
        [], ["name"], ["start_lba"], ["end_lba"], ["attributes", "0x%x"],
    ]

# ----------------------------------------------------------------------------------------
class EFIPartitionTable(FirmwareStructure):
    """
    EFI_PARTITION_TABLE_HEADER in edk2/MdePkg/Include/Uefi/UefiGpt.h
    EFI_TABLE_HEADER edk2/MdePkg/Include/Uefi/UefiMultiPhase.h
    """

    label = "EFI Partition Table"

    definition = Struct(
        # --------------------------------------------------------------------------------
        # EFI_TABLE_HEADER
        # --------------------------------------------------------------------------------
        "_magic" / Const(b'EFI PART'),
        #
        "revision_major" / Int16ul,
        "revision_minor" / Int16ul,
        #
        "header_size" / Int32ul,
        # The 32-bit CRC for the entire table. This value is computed by setting this
        #  field to 0, and computing the 32-bit CRC for HeaderSize bytes.
        "header_crc" / Int32ul,
        # Reserved field that must be set to 0.
        "reserved" / Const(0, Int32ul),
        # --------------------------------------------------------------------------------
        # EFI_PARTITION_TABLE_HEADER
        # --------------------------------------------------------------------------------
        # The LBA that contains this data structure.
        "my_lba" / Int64ul,
        # LBA address of the alternate GUID Partition Table Header.
        "alternate_lba" / Int64ul,
        # The first usable logical block that may be used by a partition described by a
        # GUID Partition Entry.
        "first_usable_lba" / Int64ul,
        # The last usable logical block that may be used by a partition described by a
        # GUID Partition Entry.
        "last_usable_lba" / Int64ul,
        # GUID that can be used to uniquely identify the disk.
        "disk_guid" / UUID16,
        # The starting LBA of the GUID Partition Entry array.
        "entry_lba" / Int64ul,
        # The number of Partition Entries in the GUID Partition Entry array.
        "num_entries" / Int32ul,
        # The size, in bytes, of each the GUID Partition Entry structures in the GUID
        # Partition Entry array. This field shall be set to a value of 128 x 2^n where n
        # is an integer greater than or equal to zero (e.g., 128, 256, 512, etc.).
        "entry_size" / Int32ul,
        # The CRC32 of the GUID Partition Entry array. Starts at PartitionEntryLBA and is
        # computed over a byte length of NumberOfPartitionEntries * SizeOfPartitionEntry.
        "crc" / Int32ul,
    )

    reporting = [
        ["revision_major"], ["revision_minor"], ["header_size"], ["header_crc"], ["reserved"],
        [],
    ]

# ----------------------------------------------------------------------------------------
class TPMEventGPTData(FirmwareStructure):
    """
    EFI_GPT_DATA in edk2/MdePkg/Include/IndustryStandard/UefiTcgPlatform.h
    Also: edk2/SecurityPkg/Library/DxeTpmMeasureBootLib/DxeTpmMeasureBootLib.c
    """

    label = "TPM Event GPT Data"

    definition = Struct(
        "header" / Class(EFIPartitionTable),
        "num_entries" / Int64ul,
        "entries" / Array(this.num_entries, Class(EFIPartitionTableEntry)),
    )

    reporting = [["num_entries"], ["header"], ["entries"]]

# ----------------------------------------------------------------------------------------
class TPMEventLogEntry(FirmwareStructure):
    """
    TCG_PCR_EVENT_HDR and tdTCG_PCR_EVENT structures in
    EDK2: MdePkg/Include/IndustryStandard/UefiTcgPlatform.h
    """

    label = "TPM Event Log Entry"

    definition = Struct(
        "pcr" / Int32ul,
        "event" / EnumAdapter(Int32ul, EventType),
        "digest_count" / Int32ul,
        "digests" / Array(this.digest_count, Class(TPMEventDigest)),
        "size" / Int32ul,
        "failure" / CommitMystery,
        "data" / Bytes(this.size),
    )

    pcr_value: str
    # FIXME: Needed until the mypy extension returns the correct type.
    data: bytes
    digests: list[TPMEventDigest]

    def analyze(self) -> None:
        self.interpretation = self.analyze_interpretation()

    def analyze_interpretation(self) -> Any:
        """
        An interpretation loop seemed appropriatate here rather continuing to use Construct,
        because 1. Some of the types "vendor-specific" and poorly specified.  2. We need
        to check the hash the data value.
        """
        if self.event == EventType.EV_SEPARATOR:
            # The string "WBCL" is apparently used by the Windows Boot Configuration Log
            # mechanism to finalize the values in PCR12, PCR13, and PCR14.
            if self.data == b'\x57\x42\x43\x4c':
                return '"%s"' % self.data.decode("utf-8")
            return "0x%x" % Int32ul.parse(self.data)
        elif (self.event == EventType.EV_EFI_VARIABLE_BOOT
              or self.event == EventType.EV_EFI_VARIABLE_DRIVER_CONFIG):
            return self.subparse(TPMEventVariableData, "data")
        # Sometimes a string, sometimes not. :-(
        elif self.event == EventType.EV_COMPACT_HASH:
            # Integers?
            if self.size == 4:
                return self.data.hex()
            # Try for a string.
            try:
                string = PaddedString(len(self.data), 'utf-8').parse(self.data)
                return '"%s"' % string
            except ValueError:
                # But handle failures gracefully.
                return self.data.hex()
        elif self.event == EventType.EV_EFI_BOOT_SERVICES_APPLICATION:
            return self.subparse(TPMEventImageLoad, "data")
        elif self.event == EventType.EV_EVENT_TAG:
            return self.subparse(TPMEventTag, "data")
        elif self.event == EventType.EV_POST_CODE:
            return self.subparse(TPMEventPostCode, "data")
        elif self.event == EventType.EV_EFI_GPT_EVENT:
            return self.subparse(TPMEventGPTData, "data")
        elif self.event == EventType.EV_EFI_HANDOFF_TABLES:
            return self.subparse(TPMEventHandoffTables, "data")
        elif self.event == EventType.EV_PLATFORM_CONFIG_FLAGS:
            return self.subparse(TPMEventPlatformConfigFlags, "data")
        elif (self.event == EventType.EV_IPL
              or self.event == EventType.EV_S_CRTM_CONTENTS):
            string = CString('utf-8').parse(self.data)
            if '\n' not in string:
                return '"%s"' % string
            from .pfs import TextFile
            # Do we really need to strip zeros here?  It seems to be a single NULL,
            # and it results in an unprocessed gap in file to skip it.
            #stripped = self.data.rstrip(b'\x00')
            #return self.subparse(TextFile, "data", 0, len(stripped))
            return self.subparse(TextFile, "data")
        return self.data.hex()

    def hashed_value(self) -> bytes:
        """
        In some events the hashed data is different from the actual event data because
        reasons.  Return the value that was hashed to create the digest if possible.
        """
        if self.event == EventType.EV_IPL:
            if self.data[:10] == b"grub_cmd: " and self.data[-1] == 0:
                return self.data[10:-1]
            if self.data[:16] == b"kernel_cmdline: " and self.data[-1] == 0:
                return self.data[16:-1]
            # Events in GRUB that look like filenames, e.g.:
            #   /initrd.img-5.7.19-050719-generic
            #   (hd1,gpt5)/grub/x86_64-efi/crypto.lst
            # Are the digests of the actual file listed.
        return self.data

    def get_digest(self, algo: TPMAlgorithm) -> Optional[bytes]:
        for digest_object in self.digests:
            if digest_object.type == algo:
                return digest_object.value
        return None

    def hash_check_helper(self, algo: TPMAlgorithm, found: str) -> str:
        expected = self.get_digest(algo)
        if expected is None:
            return "absent"
        elif expected.hex() == found:
            return "matches"
        else:
            return "FAIL"
            #return "FAIL(%s)" % found

    @property
    def sha1_check(self) -> str:
        sha1_hasher = hashlib.sha1()
        sha1_hasher.update(self.hashed_value())
        found = sha1_hasher.hexdigest()
        return self.hash_check_helper(TPMAlgorithm.SHA1, found)

    @property
    def sha256_check(self) -> str:
        sha256_hasher = hashlib.sha256()
        sha256_hasher.update(self.hashed_value())
        found = sha256_hasher.hexdigest()
        return self.hash_check_helper(TPMAlgorithm.SHA256, found)

    reporting = [
        ["pcr"], ["event"], ["digest_count"], ["size"],
        ["data", None], ["interpretation"],
        [], ["sha1_check"], ["sha256_check"], ["pcr_value"],
        ["digests"],
    ]

    def instance_name(self) -> str:
        return f"PCR{self.pcr:02}: {self.pcr_value}"

# The PCRs used to seal the BitLocker key are:
#   7 & 11 if SecureBoot is on and 0, 2, 4, and 11 otehrwise.

# ----------------------------------------------------------------------------------------
class TPMComputedPCRValue(FirmwareStructure):

    label = "TPM Computed PCR Register Value"

    definition = Struct(
        "digest" / HexBytes(32),
    )

    register: str

    reporting = [["register"], ["digest"]]

# ----------------------------------------------------------------------------------------
class TPMEventLog(FirmwareStructure):

    label = "TPM Event Log"

    definition = Struct(
        "header" / Class(TPMEventLogHeader),
        "events" / GreedyRange(Class(TPMEventLogEntry)),
    )

    pcrs: list[TPMComputedPCRValue]

    def analyze(self) -> None:
        pcrs = {}
        for pcr in range(24):
            pcrs[pcr] = b'\x00' * 32
        for event in self.events:
            pcr = event.pcr
            digest = event.get_digest(TPMAlgorithm.SHA256)
            sha256_hasher = hashlib.sha256()
            sha256_hasher.update(pcrs[pcr] + digest)
            event.pcr_value = sha256_hasher.hexdigest()
            pcrs[pcr] = sha256_hasher.digest()

        self.pcrs = []
        for pcr in range(24):
            computed = TPMComputedPCRValue.parse(pcrs[pcr], 0)
            if computed is None:
                continue
            self.pcrs.append(computed)
            self.pcrs[-1].register = "PCR%02d" % pcr

    reporting = [["header"], ["events"], ["pcrs"]]

    def instance_name(self) -> str:
        return ""

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
