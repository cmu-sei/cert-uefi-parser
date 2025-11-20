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
Automatic detection and parsing of supported object formats.
"""

from construct import Select, GreedyBytes

from .base import FirmwareStructure, Class, Struct
from .mystery import MysteryBytes
from .uefi import (
    EFI1Capsule, EFI2Capsule, UEFICapsule, AMICapsule, ParallelsVM_NVRAMFile)
from .pfs import PFSFile, PFHeader
from .flash import FlashDescriptor
from .me import ManagementEngineRegion, MEManifestPartition
from .vendor import (
    LVFSContainer, DellUpdaterExecutable, DellUpdaterEFIApp, BIOSExtensionROM,
    FMPCapsule, ZipFile, MicrosoftCabinetFile, PNGImage, JPGImage, FLUF,
    BMPImageV1, BMPImageV4, AMITSESetupData, XMLFile, PGPSignatureFile, JCATFile,
    DellBIOSMZ, HuaweiUpdaterExecutable, OpenTypeFont)
from .exes import PEExecutable, TEExecutable, ELFExecutable
from .sbom import USwid
from .acpi import SecondarySystemDescriptionTable
from .finder import FirmwareVolumeFinder
from .coreboot import CorebootContainer, CorebootComponentList
from .ami import AMI_PFAT_Firmware
from .amd import AMDPlatformSecurityProcessor
from .nvvars import SecureBootVariable, SecureBootSignedVariable, VMWareNVRAM
from .tpm import TPMEventLog
from .smbios import SMBIOSFile
from .gecko import GeckoBootLoaderFile, ZigbeeOverTheAir
from .devicetree import FlattenedDevicetree
from .plf import PLFFirmware, UBX8Firmware

# ----------------------------------------------------------------------------------------
class AutoObject(FirmwareStructure):

    label = "Auto Detected Object"

    definition = Struct(
        "auto" / Select(
            # Start with classes that are quickly and conclusively identified by leading GUID.
            Class(UEFICapsule),
            Class(EFI1Capsule),
            Class(EFI2Capsule),
            Class(FMPCapsule),
            Class(AMICapsule),
            Class(SecureBootVariable),
            Class(SecureBootSignedVariable),

            # Quick leading magic checks.
            Class(PFSFile),
            Class(AMI_PFAT_Firmware),
            Class(SecondarySystemDescriptionTable),
            Class(ManagementEngineRegion),
            Class(MEManifestPartition),
            Class(PNGImage),
            Class(JPGImage),
            Class(BMPImageV1),
            Class(BMPImageV4),
            Class(AMITSESetupData),
            Class(MicrosoftCabinetFile),
            Class(FLUF),
            Class(ZipFile),
            Class(XMLFile),
            Class(VMWareNVRAM),
            Class(TPMEventLog),
            Class(USwid),
            Class(PGPSignatureFile),
            Class(FlattenedDevicetree),
            Class(PLFFirmware),
            Class(OpenTypeFont),
            Class(DellUpdaterEFIApp),
            Class(DellUpdaterExecutable),  # After DellUpdaterEFIApp
            #Class(EFIApplication),  # Disabled because it "blocks" PEExecutable.
            Class(HuaweiUpdaterExecutable),
            Class(PEExecutable),  # After the more specific executable testers.
            Class(TEExecutable),
            Class(ELFExecutable),
            Class(UBX8Firmware),
            Class(GeckoBootLoaderFile),
            Class(ZigbeeOverTheAir),
            Class(CorebootContainer),
            # Coreboot containers often start with a Coreboot Component magic, so ordering
            # is important here...
            Class(CorebootComponentList),

            # Other more complicated tests.
            Class(SMBIOSFile),
            Class(ParallelsVM_NVRAMFile),
            Class(DellBIOSMZ),
            Class(FlashDescriptor),
            Class(PFHeader),
            Class(AMDPlatformSecurityProcessor),
            Class(JCATFile),

            # LVFSContainer, FirmwareVolumeFinder, and FirmwareVolume appear to overlap.
            Class(LVFSContainer),
            # Late in list just because the magic is not very strong.
            Class(BIOSExtensionROM),
            # The FirmwareVolumeFinder always matches right now. :-(
            Class(FirmwareVolumeFinder),
            # The reason we don't list FirmwareVolume before FirmwareVolumeFinder is
            # a single volume silently discards bytes after the volume?
            #Class(FirmwareVolume),
            Class(MysteryBytes),
        )
    )

    sbom_fields = ["auto"]

# ----------------------------------------------------------------------------------------
class BruteForceFinder(FirmwareStructure):

    definition = Struct(
        "_rawdata" / GreedyBytes,
    )

    def analyze(self) -> None:
        self.found = []
        i = 0

        while i < len(self._rawdata):
            self.info(f"Trying at offset {hex(i)}...")
            result = self.subparse(AutoObject, "_rawdata", i)
            # Some hard failures of AutoObject, shouldn't happen?
            if result is None or result.auto is None:
                i += 1
                continue
            # These aren't real matches for our purposes.
            if isinstance(result.auto, (MysteryBytes, FirmwareVolumeFinder)):
                i += 1
                continue

            self.info(f"Found object {result.auto} at {hex(i)}, length {len(result.auto)}")
            self.found.append(result.auto)
            i += len(result.auto)

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
