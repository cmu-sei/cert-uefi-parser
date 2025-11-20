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
Support for Flash ROM images.
"""

from construct import Const, Pointer, Select, Int8sl, Int8ul, Int16ul, Int16sl, Tell

from .base import (
    FirmwareStructure, Class, FixedLength, UUID16, Struct, LazyBind, Context)
from .me import ManagementEngineRegion
from .finder import FirmwareVolumeFinder
from .mystery import MysteryBytes, CommitMystery

# Lots of really great info for this file located here:
# https://opensecuritytraining.info/IntroBIOS_files/
# Day2_02_Advanced%20x86%20-%20BIOS%20and%20SMM%20Internals%20-%20Flash%20Descriptor.pdf

# ----------------------------------------------------------------------------------------
class DescriptorMap(FirmwareStructure):

    definition = Struct(
        "component_base" / Int8sl,
        "num_flash_chips" / Int8sl,
        "region_base" / Int8sl,
        "num_regions" / Int8sl,
        "master_base" / Int8sl,
        "num_masters" / Int8sl,
        "pch_straps_base" / Int8sl,
        "num_pch_straps" / Int8sl,
        "proc_straps_base" / Int8sl,
        "num_proc_straps" / Int8sl,
        "icc_table_base" / Int8sl,
        "num_icc_tables" / Int8sl,
        "dmi_table_base" / Int8sl,
        "num_dmi_tables" / Int8sl,
        "reserved" / Int16sl,
    )

    reporting = [
        ["num_flash_chips"], ["num_regions"], ["num_masters"], ["num_pch_straps"],
        ["num_proc_straps"], ["num_icc_tables"], ["num_dmi_tables"],
        [], ["component_base"], ["region_base"], ["master_base"], ["pch_straps_base"],
        ["proc_straps_base"], ["icc_table_base"], ["dmi_table_base"], ["reserved"],
    ]

# ----------------------------------------------------------------------------------------
class MasterSection(FirmwareStructure):

    definition = Struct(
        "bios_id" / Int16ul,
        "bios_read" / Int8ul,
        "bios_write" / Int8ul,
        "me_id" / Int16ul,
        "me_read" / Int8ul,
        "me_write" / Int8ul,
        "gbe_id" / Int16ul,
        "gbe_read" / Int8ul,
        "gbe_write" / Int8ul,
    )

# ----------------------------------------------------------------------------------------
class RegionSection(FirmwareStructure):

    definition = Struct(
        "reserved" / Int16ul,
        "erase_size" / Int16ul,
        "bios_start" / Int16ul,
        "bios_end" / Int16ul,
        "me_start" / Int16ul,
        "me_end" / Int16ul,
        "gbe_start" / Int16ul,
        "gbe_end" / Int16ul,
        "pdr_start" / Int16ul,
        "pdr_end" / Int16ul,
    )

    reporting = [
        ["pdr_start"], ["pdr_end"], ["me_start"], ["me_end"],
        ["bios_start"], ["bios_end"], ["gbe_start"], ["gbe_end"],
    ]

# ----------------------------------------------------------------------------------------
class GenericFlashRegion(FirmwareStructure):
    """
    A generic flash region to be overloaded with a more specific label.
    """

    definition = Struct(
        "data" / Class(MysteryBytes),
    )

# ----------------------------------------------------------------------------------------
class GigabitEthernetRegion(GenericFlashRegion):

    label = "Gigabit Ethernet (GBE) Region"

# ----------------------------------------------------------------------------------------
class PlatformDescriptorRegion(GenericFlashRegion):

    label = "Platform Descriptor (PDR) Region"

# ----------------------------------------------------------------------------------------
class BIOSFlashRegion(FirmwareStructure):

    label = "BIOS Flash Region"

    definition = Struct(
        "volumes" / Class(FirmwareVolumeFinder),
    )

    sbom_fields = ["volumes"]

# ----------------------------------------------------------------------------------------
def lazy_coreboot(ctx: Context) -> Class:
    from .coreboot import TestCorebootRegion
    return Class(TestCorebootRegion)

def region_size(start: int, end: int) -> int:
    if end:
        #size = (end + 1 - start) * 0x1000
        #log.debug("Region size is: start=%d end=%d offset=0x%x size=0x%x" % (
        #    start, end, start * 0x1000, size))
        #return size
        return (end + 1 - start) * 0x1000
    return 0

class FlashDescriptor(FirmwareStructure):

    definition = Struct(
        "_start" / Tell,
        "guid" / UUID16,
        "_magic" / Const(b'\x5a\xa5\xf0\x0f'),
        "failure" / CommitMystery,
        "descriptor_map" / Class(DescriptorMap),
        "region" / Pointer(
            lambda ctx: (ctx.descriptor_map.region_base * 0x10) + ctx._start,
            Class(RegionSection)),
        "master" / Pointer(
            lambda ctx: (ctx.descriptor_map.master_base * 0x10) + ctx._start,
            Class(MasterSection)),

        "bios" / Pointer(
            lambda ctx: (ctx.region.bios_start * 0x1000) + ctx._start, FixedLength(
                lambda ctx: region_size(ctx.region.bios_start, ctx.region.bios_end),
                Select(LazyBind(lazy_coreboot), Class(BIOSFlashRegion)))),
        "me" / Pointer(
            lambda ctx: (ctx.region.me_start * 0x1000) + ctx._start, FixedLength(
                lambda ctx: region_size(ctx.region.me_start, ctx.region.me_end),
                # Protect against parsing failures...
                Select(Class(ManagementEngineRegion), Class(MysteryBytes)))),
        "gbe" / Pointer(
            lambda ctx: (ctx.region.gbe_start * 0x1000) + ctx._start, FixedLength(
                lambda ctx: region_size(ctx.region.gbe_start, ctx.region.gbe_end),
                Class(GigabitEthernetRegion))),
        "pdr" / Pointer(
            lambda ctx: (ctx.region.pdr_start * 0x1000) + ctx._start, FixedLength(
                lambda ctx: region_size(ctx.region.pdr_start, ctx.region.pdr_end),
                Class(PlatformDescriptorRegion))),
    )

    reporting = [
        ["guid"], ["descriptor_map"], ["region"], ["master"],
        ["pdr"], ["me"], ["bios"], ["gbe"],
    ]

    sbom_fields = ["bios", "me"]

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
