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
Intel Firmware Support Package
https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/fsp-architecture-spec-v2.pdf
"""

from construct import Bytes, Const, Int8ul, Int16ul, Int32ul, Check, this

from .base import (
    FirmwareStructure, Class, PaddedString, Struct, HexBytes)
from .pfs import TextFile
from .mystery import HexDump, MysteryBytes

# ----------------------------------------------------------------------------------------
class FSPInfoHeader(FirmwareStructure):
    """
    """

    label = "FSP Info Header"

    definition = Struct(
        "u1" / Int16ul,
        "u2" / Int16ul,
        "_magic" / Const(b'FSPH'),
        "hdr_len" / Int32ul,
        "reserved1" / Int16ul,
        "spec_version" / Int8ul,
        "hdr_revision" / Int8ul,
        "image_revision" / Int32ul,
        "image_id" / PaddedString(8, "utf-8"),
        "image_size" / Int32ul,
        "image_base" / Int32ul,
        "image_attributes" / Int16ul,
        "component_attributes" / Int16ul,
        "cfg_region_offset" / Int32ul,
        "cfg_region_size" / Int32ul,
        "reserved2" / Int32ul,
        "temp_ram_init" / Int32ul,
        "reserved3" / Int32ul,
        "notify_phase" / Int32ul,
        "fsp_memory_init" / Int32ul,
        "temp_ram_exit" / Int32ul,
        "fsp_silicon_init" / Int32ul,
    )

    reporting = [
        ["u1"], ["u2"], ["hdr_len"], ["spec_version", "0x%02x"],
        ["hdr_revision"], ["image_revision", "0x%x"], ["image_id"],
        [], ["image_base", "0x%x"], ["image_size"],
        ["image_attributes"],
        ["component_attributes", "0x%x"],
        ["cfg_region_offset"],
        ["cfg_region_size"],
        [], ["temp_ram_init"], ["notify_phase"], ["fsp_memory_init"],
        ["temp_ram_exit"], ["fsp_silicon_init"],
        ["reserved1"], ["reserved2"], ["reserved3"],
    ]

# ----------------------------------------------------------------------------------------
class FSPInfoExtendedHeader(FirmwareStructure):
    """
    """

    label = "FSP Info Extended Header "

    definition = Struct(
        "u1" / Int16ul,
        "u2" / Int16ul,
        "_magic" / Const(b'FSPE'),
        "hdr_len" / Int32ul,
        "revision" / Int8ul,
        "reserved1" / Int8ul,
        "producer" / PaddedString(6, "utf-8"),
        "revision" / Int32ul,
        "size" / Int32ul,
        "data" / Bytes(this.size),
    )

# ----------------------------------------------------------------------------------------
class FSPPatchTable(FirmwareStructure):
    """
    """

    label = "FSP Patch Table"

    definition = Struct(
        "_magic" / Const(b'FSPP'),
        "hdr_len" / Int16ul,
        "revision" / Int8ul,
        "reserved1" / Int8ul,
        "count" / Int32ul,
        "data" / Class(HexDump),
    )

# ----------------------------------------------------------------------------------------
class FSPHeaderFile(FirmwareStructure):
    """
    """

    label = "FSP Header File"

    definition = Struct(
        "hdr" / Class(FSPInfoHeader),
        "exthdr" / Class(FSPInfoExtendedHeader),
        "patch" / Class(FSPPatchTable),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["hdr"], ["exthdr"], ["patch"]]

# ----------------------------------------------------------------------------------------
class FSPDescriptionFile(FirmwareStructure):
    """
    """

    label = "FSP Description File"

    definition = Struct(
        "_guid_match" / Check(
            lambda ctx: str(ctx._.guid) == "d9093578-08eb-44df-b9d8-d0c1d3d55d96"),
        "u1" / Int16ul,
        "u2" / Int16ul,
        "contents" / Class(TextFile),
    )

# ----------------------------------------------------------------------------------------
class FSP_UPD_Header(FirmwareStructure):
    """
    """

    label = "FSP UPD Header"

    definition = Struct(
        "u1" / Int16ul,
        "u2" / Int16ul,
        "signature" / PaddedString(8, "utf-8"),
        "revision" / Int8ul,
        "reserved1" / HexBytes(23),
    )

# ----------------------------------------------------------------------------------------
class FSPTempRAMInit(FirmwareStructure):
    """
    """

    label = "FSP-T Temp Ram Init"

    definition = Struct(
        # RawData file has guid: FSP_T_UPD_FFS_GUID
        "_guid_match" / Check(
            lambda ctx: str(ctx._.guid) == "70bcf6a5-ffb1-47d8-b1ae-efe5508e23ea"),
        "header" / Class(FSP_UPD_Header),
        "unexpected" / Class(HexDump),
    )

# ----------------------------------------------------------------------------------------
class FSPMemoryInit(FirmwareStructure):
    """
    """

    label = "FSP-M Memory Init"

    definition = Struct(
        # RawData file has guid: FSP_M_UPD_FFS_GUID
        "_guid_match" / Check(
            lambda ctx: str(ctx._.guid) == "d5b86aea-6af7-40d4-8014-982301bc3d89"),
        "header" / Class(FSP_UPD_Header),
        "unexpected" / Class(HexDump),
    )

# ----------------------------------------------------------------------------------------
class FSPSiliconInit(FirmwareStructure):
    """
    """

    label = "FSP-S Silicon Init"

    definition = Struct(
        # RawData file has guid: FSP_T_UPD_FFS_GUID
        "_guid_match" / Check(
            lambda ctx: str(ctx._.guid) == "e3cd9b18-998c-4f76-b65e-98b154e5446f"),
        "header" / Class(FSP_UPD_Header),
        "unexpected" / Class(HexDump),
    )

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
