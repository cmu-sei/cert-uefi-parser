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
System Management BIOS (SMBIOS)
https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.0.0.pdf

See also:
https://www.nongnu.org/dmidecode/
/sys/firmware/dmi/tables/DMI

This parser needs more work to add enumerations and improve robustness. In particular,
this parser should better respect optional fields from multiple versions of the
specification.
"""

from typing import Optional, Type

from construct import (
    Array, Bytes, Computed, Const, GreedyRange, RepeatUntil, Switch, If, IfThenElse,
    Int8ul, Int16ul, Int32ul, Int64ul, Check, Peek, this)

from .base import (
    FirmwareStructure, FixedLength, Class, Struct, CString, UUID16, HexBytes, Context)
from .mystery import MysteryBytes, HexDump

# ----------------------------------------------------------------------------------------
class SMBIOSStructure(FirmwareStructure):
    """
    A base class to provide a string helper function.
    """

    strings: list[str]

    def set_strings(self) -> None:
        pass

    # Helper to convert snums to actual strings.
    def string_from_num(self, snum: Optional[int]) -> Optional[str]:
        if snum is None:
            return None
        if snum <= 0 or snum >= len(self.strings):
            return ""
        return self.strings[snum - 1]

# ----------------------------------------------------------------------------------------
class SMBIOSType0(SMBIOSStructure):
    """
    Section 7.1 BIOS Information (Type 0)
    """

    label = "BIOS"

    definition = Struct(
        "vendor_snum" / Int8ul,
        "version_snum" / Int8ul,
        "address" / Int16ul,
        "date_snum" / Int8ul,
        "rom_size" / Int8ul,
        "characteristics" / Int64ul,
        "extensions" / HexBytes(lambda ctx: max(ctx._.length - 22, 0)),
        "major" / Int8ul,
        "minor" / Int8ul,
        "ec_major" / Int8ul,
        "ec_minor" / Int8ul,
    )

    def set_strings(self) -> None:
        self.vendor = self.string_from_num(self.vendor_snum)
        self.version = self.string_from_num(self.version_snum)
        self.date = self.string_from_num(self.date_snum)

    reporting = [
        ["major"], ["minor"], ["ec_major"], ["ec_minor"],
        [], ["vendor"], ["version"], ["date"], ["address", "0x%x"],
        ["characteristics", "0x%x"], ["extensions"],
        ["vendor_snum", None], ["version_snum", None], ["date_snum", None],
        ["strings", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType1(SMBIOSStructure):
    """
    Section 7.2 System Information (Type 1)
    """

    label = "System"

    definition = Struct(
        "manufacturer_snum" / Int8ul,
        "product_snum" / Int8ul,
        "version_snum" / Int8ul,
        "serial_snum" / Int8ul,
        "uuid" / UUID16,
        "wakeup" / Int8ul,
        "sku_snum" / If(this._.length >= 26, Int8ul),
        "family" / If(this._.length >= 27, Int8ul),
    )

    def set_strings(self) -> None:
        self.manufacturer = self.string_from_num(self.manufacturer_snum)
        self.product = self.string_from_num(self.product_snum)
        self.version = self.string_from_num(self.version_snum)
        self.serial = self.string_from_num(self.serial_snum)
        self.sku = self.string_from_num(self.sku_snum)

    reporting = [
        ["family"], ["uuid"], ["wakeup"],
        [], ["manufacturer"], ["product"], ["version"], ["serial"], ["sku"],
        ["manufacturer_snum", None], ["product_snum", None], ["version_snum", None],
        ["serial_snum", None], ["sku_snum", None], ["strings", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType2(SMBIOSStructure):
    """
    Section 7.3 Baseboard Information (Type 2)
    """

    label = "Baseboard"

    definition = Struct(
        "manufacturer_snum" / Int8ul,
        "product_snum" / Int8ul,
        "version_snum" / Int8ul,
        "serial_snum" / Int8ul,
        "asset_tag_snum" / Int8ul,
        # Everything after this may be optional?
        "features" / Int8ul,
        "location_snum" / Int8ul,
        "chassis_handle" / Int16ul,
        "board_type" / Int8ul,
        "num_handles" / Int8ul,
        "handles" / Array(this.num_handles, Int16ul),
    )

    def set_strings(self) -> None:
        self.manufacturer = self.string_from_num(self.manufacturer_snum)
        self.product = self.string_from_num(self.product_snum)
        self.version = self.string_from_num(self.version_snum)
        self.serial = self.string_from_num(self.serial_snum)
        self.asset_tag = self.string_from_num(self.asset_tag_snum)
        self.location = self.string_from_num(self.location_snum)

    reporting = [
        ["chassis_handle"], ["board_type"],
        ["num_handles"], ["handles"],
        [], ["manufacturer"], ["product"], ["version"], ["serial"], ["asset_tag"], ["location"],
        ["manufacturer_snum", None], ["product_snum", None], ["version_snum", None],
        ["serial_snum", None], ["asset_tag_snum", None], ["location_snum", None],
        ["strings", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType3(SMBIOSStructure):
    """
    Section 7.4 System Enclosure or Chassis (Type 3)
    """

    label = "Chassis"

    definition = Struct(
        "manufacturer_snum" / Int8ul,
        "chassis_type" / Int8ul,
        "version_snum" / Int8ul,
        "serial_snum" / Int8ul,
        "asset_tag_snum" / Int8ul,
        "bootup_state" / Int8ul,
        "power_state" / Int8ul,
        "thermal_state" / Int8ul,
        "security_state" / Int8ul,
        "oem" / Int32ul,
        "height" / Int8ul,
        "power_cords" / Int8ul,
        "elem_count" / Int8ul,
        "elem_size" / Int8ul,
        "elements" / Array(this.elem_count, Bytes(this.elem_size)),
        "sku_snum" / Int8ul,
    )

    def set_strings(self) -> None:
        self.manufacturer = self.string_from_num(self.manufacturer_snum)
        self.version = self.string_from_num(self.version_snum)
        self.serial = self.string_from_num(self.serial_snum)
        self.asset_tag = self.string_from_num(self.asset_tag_snum)
        self.sku = self.string_from_num(self.sku_snum)

    reporting = [
        ["strings", None],
        ["bootup_state"], ["power_state"],
        ["thermal_state"], ["security_state"], ["elem_count"], ["elem_size"], ["elements"],
        [], ["manufacturer"], ["version"], ["serial"], ["asset_tag"], ["sku"],
        ["manufacturer_snum", None], ["version_snum", None],
        ["serial_snum", None], ["asset_tag_snum", None], ["sku_snum", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType4(SMBIOSStructure):
    """
    Section 7.5 Processor Information (Type 4)
    """

    label = "Processor Information"

    definition = Struct(
        # Length is 1Ah for version 2.0 implementations; 23h for 2.3; 28h for 2.5; 2Ah for
        # 2.6, and 30h for version 3.0 and later implementations.
        "socket_snum" / Int8ul,
        "type" / Int8ul,
        "family" / Int8ul,
        "manufacturer_snum" / Int8ul,
        "id" / Int64ul,
        "version_snum" / Int8ul,
        "voltage" / Int8ul,
        "clock" / Int16ul,
        "max_speed" / Int16ul,
        "curr_speed" / Int16ul,
        "status" / Int8ul,
        # Version 2.1
        "upgrade" / If(this._.length >= 26, Int8ul),
        "l1_cache_handle" / If(this._.length >= 29, Int16ul),
        "l2_cache_handle" / If(this._.length >= 31, Int16ul),
        "l3_cache_handle" / If(this._.length >= 33, Int16ul),
        # Version 2.3
        "serial_snum" / Int8ul,
        "asset_tag_snum" / Int8ul,
        "part_number_snum" / Int8ul,
        # Version 2.5
        "core_count" / Int8ul,
        "core_enabled" / Int8ul,
        "thread_count" / Int8ul,
        "characteristics" / Int16ul,
        # Version 2.6
        "family2" / Int16ul,
        # Version 3.0
        "core_count2" / Int16ul,
    )

    def set_strings(self) -> None:
        self.socket = self.string_from_num(self.socket_snum)
        self.manufacturer = self.string_from_num(self.manufacturer_snum)
        self.version = self.string_from_num(self.version_snum)
        self.serial = self.string_from_num(self.serial_snum)
        self.asset_tag = self.string_from_num(self.asset_tag_snum)
        self.part_number = self.string_from_num(self.part_number_snum)

    reporting = [
        ["strings", None],
        [], ["socket"], ["manufacturer"], ["version"], ["serial"],
        ["asset_tag"], ["part_number"],
        [], ["id", "0x%x"],
        ["socket_snum", None],
        ["manufacturer_snum", None],
        ["version_snum", None],
        ["serial_snum", None],
        ["asset_tag_snum", None],
        ["part_number_snum", None],

    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType9(SMBIOSStructure):
    """
    Section 7.10 System Slots (Type 9)
    """

    label = "System Slots"

    definition = Struct(
        "slot_snum" / Int8ul,
        "slot_type" / Int8ul,
        "data_bus_width" / Int8ul,
        "current_usage" / Int8ul,
        "slot_id" / Int16ul,
        "characteristics" / Int16ul,
        "segment_group" / Int16ul,
        "bus" / Int8ul,
        "dev_func" / Int8ul,
    )

    def set_strings(self) -> None:
        self.slot = self.string_from_num(self.slot_snum)

    reporting = [["strings", None]]

# ----------------------------------------------------------------------------------------
class SMBIOSType10(SMBIOSStructure):
    """
    Section 7.11 On Board Devices Information (Type 10, Obsolete)
    """

    label = "On Board Devices"

    definition = Struct(
        "devices" / Array(lambda ctx: int(((ctx._.length - 4) / 2)), Int8ul),
        "description_snums" / Array(lambda ctx: int(((ctx._.length - 4) / 2)), Int8ul),
    )

    def set_strings(self) -> None:
        self.descriptions = []
        for snum in self.description_snums:
            self.descriptions.append(self.string_from_num(snum))

    reporting = [
        ["strings", None],
        ["devices"], ["descriptions"], ["description_snums", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType11(SMBIOSStructure):
    """
    Section 7.12 OEM Strings (Type 11)
    """

    label = "OEM Strings"

    definition = Struct(
        "count" / Int8ul,
    )

    def set_strings(self) -> None:
        self.oem_strings = self.strings[:-1]

    reporting = [
        ["strings", None],
        ["count"], ["oem_strings"],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType12(SMBIOSStructure):
    """
    Section 7.13 OEM System Configuration Options (Type 12)
    """

    label = "System Configuration Options"

    definition = Struct(
        "count" / Int8ul,
    )

    def set_strings(self) -> None:
        self.options = self.strings[:-1]

    reporting = [
        ["strings", None],
        ["count"], ["options"],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType15(SMBIOSStructure):
    """
    Section 7.13 System Event Log (Type 15)
    """

    label = "System Event Log"

    definition = Struct(
        "log_length" / Int16ul,
        "log_header_offset" / Int16ul,
        "log_data_offset" / Int16ul,
        "access" / Int8ul,
        "status" / Int8ul,
        "token" / Int32ul,
        "method" / Int32ul,
        "format" / Int8ul,
        "desc_count" / Int8ul,
        "desc_size" / Int8ul,
        "descriptors" / Array(this.desc_count, Bytes(this.desc_size)),
    )

    reporting = [
        ["strings", None],
        ["log_length"], ["log_header_offset"], ["log_data_offset"],
        ["access"], ["status"], ["token"], ["method"], ["format"],
        [], ["desc_count"], ["desc_size"], ["descriptors"],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType16(SMBIOSStructure):
    """
    Section 7.17 Physical Memory Array (Type 16)
    """

    label = "Physical Memory Array"

    definition = Struct(
        "location" / Int8ul,
        "use" / Int8ul,
        "error_correction" / Int8ul,
        "max_capacity32" / Int32ul,
        "mem_info_handle" / Int16ul,
        "num_devices" / Int16ul,
        "max_capacity64" / Int64ul,
    )

    reporting = [
        ["strings", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType17(SMBIOSStructure):
    """
    Section 7.18 Memory Device (Type 17)
    """

    label = "Memory Device"

    definition = Struct(
        "mem_handle" / Int16ul,
        "error_handle" / Int16ul,
        "total_width" / Int16ul,
        "data_width" / Int16ul,
        "size" / Int16ul,
        "form_factor" / Int8ul,
        "device_set" / Int8ul,
        "device_locator_snum" / Int8ul,
        "bank_locator_snum" / Int8ul,
        "mem_type" / Int8ul,
        "type_detail" / Int16ul,
        "speed" / Int16ul,
        "manufacturer_snum" / Int8ul,
        "serial_snum" / Int8ul,
        "asset_tag_snum" / Int8ul,
        "part_number_snum" / Int8ul,
        "attributes" / Int8ul,
        "extended_size" / Int32ul,
        "clock" / Int16ul,
        "min_volts" / Int16ul,
        "max_volts" / Int16ul,
        "voltage" / Int16ul,
    )

    def set_strings(self) -> None:
        self.device_locator = self.string_from_num(self.device_locator_snum)
        self.bank_locator = self.string_from_num(self.bank_locator_snum)
        self.manufacturer = self.string_from_num(self.manufacturer_snum)
        self.serial = self.string_from_num(self.serial_snum)
        self.asset_tag = self.string_from_num(self.asset_tag_snum)
        self.part_number = self.string_from_num(self.part_number_snum)

    reporting = [
        ["strings", None],
        [], ["device_locator"], ["bank_locator"], ["manufacturer"],
        ["serial"], ["asset_tag"], ["part_number"],

        ["device_locator_snum", None], ["bank_locator_snum", None],
        ["manufacturer_snum", None], ["serial_snum", None],
        ["asset_tag_snum", None], ["part_number_snum", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType19(SMBIOSStructure):
    """
    Section 7.20 Memory Array Mapped Address (Type 19)
    """

    label = "Memory Array Mapped Address"

    definition = Struct(
        "start" / Int32ul,
        "end" / Int32ul,
        "mem_array_handle" / Int16ul,
        "partition_width" / Int8ul,
        "start64" / Int64ul,
        "end64" / Int64ul,
    )

    reporting = [
        ["strings", None],
        ["start", "0x%x"], ["end", "0x%x"],
        ["start64", "0x%x"], ["end64", "0x%x"],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType20(SMBIOSStructure):
    """
    Section 7.21 Memory Device Mapped Address (Type 20)
    """

    label = "Memory Device Mapped Address"

    definition = Struct(
        # Lengths of 19 (for v2.1) and 35 (for version >=2.7) are expected.
        "start" / Int32ul,
        "end" / Int32ul,
        "device_handle" / Int16ul,
        "address_handle" / Int16ul,
        "row" / Int8ul,
        "interleave" / Int8ul,
        "depth" / Int8ul,
        "start64" / If(this._.length >= 24, Int64ul),
        "end64" / If(this._.length >= 32, Int64ul),
    )

    reporting = [
        ["strings", None],
        ["start", "0x%x"], ["end", "0x%x"],
        ["start64", "0x%x"], ["end64", "0x%x"],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType21(SMBIOSStructure):
    """
    Section 7.22 Built-in Pointing Device (Type 21)
    """

    label = "Built-in Pointing Device"

    definition = Struct(
        "pointer_type" / Int8ul,
        "interface" / Int8ul,
        "num_buttons" / Int8ul,
    )

    reporting = [
        ["strings", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType22(SMBIOSStructure):
    """
    Section 7.23 Portable Battery (Type 22)
    """

    label = "Portable Battery"

    definition = Struct(
        "location_snum" / Int8ul,
        "manufacturer_snum" / Int8ul,
        "date_snum" / Int8ul,
        "serial_snum" / Int8ul,
        "device_snum" / Int8ul,
        "chemistry_snum" / Int8ul,
        "capacity" / Int16ul,
        "voltage" / Int16ul,
        "sbds_snum" / Int8ul,
        "error" / Int8ul,
        "sbds_serial" / Int16ul,
        "_sbds_date" / Int16ul,
        "sbds_chemistry_snum" / Int8ul,
        "multiplier" / Int8ul,
        "oem" / Int32ul,
    )

    @property
    def sbds_date(self) -> str:
        year = self._sbds_date & 0xff00
        month = self._sbds_date & 0x00f0
        day = self._sbds_date & 0x000f
        return "%s/%s/%s" % (month, day, year + 1980)

    def set_strings(self) -> None:
        self.location = self.string_from_num(self.location_snum)
        self.manufacturer = self.string_from_num(self.manufacturer_snum)
        self.date = self.string_from_num(self.date_snum)
        self.serial = self.string_from_num(self.serial_snum)
        self.device = self.string_from_num(self.device_snum)
        self.chemistry = self.string_from_num(self.chemistry_snum)
        self.sbds = self.string_from_num(self.sbds_snum)
        self.sbds_chemistry = self.string_from_num(self.sbds_chemistry_snum)

    reporting = [
        ["strings", None],
        ["capacity"], ["voltage"], ["error"], ["multiplier"], ["oem"],
        [], ["location"], ["manufacturer"], ["date"], ["serial"], ["device"], ["chemistry"],
        [], ["sbds"], ["sbds_serial"], ["sbds_date"], ["sbds_chemistry"],
        ["location_snum", None], ["manufacturer_snum", None], ["date_snum", None],
        ["serial_snum", None], ["device_snum", None], ["chemistry_snum", None],
        ["sbds_snum", None], ["sbds_chemistry_snum", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType25(SMBIOSStructure):
    """
    Section 7.26 System Power Controls (Type 25)
    """

    label = "System Power Controls"

    definition = Struct(
        "month" / Int8ul,
        "day" / Int8ul,
        "hour" / Int8ul,
        "minute" / Int8ul,
        "second" / Int8ul,
    )

    reporting = [
        ["strings", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType26(SMBIOSStructure):
    """
    Section 7.27 Voltage Probe (Type 26)
    """

    label = "Voltage Probe"

    definition = Struct(
        "description_snum" / Int8ul,
        "location" / Int8ul,
        "maximum" / Int16ul,
        "minimum" / Int16ul,
        "resolution" / Int16ul,
        "tolerance" / Int16ul,
        "accuracy" / Int16ul,
        "oem" / Int32ul,
        "nominal" / Int16ul,
    )

    def set_strings(self) -> None:
        self.description = self.string_from_num(self.description_snum)

    reporting = [
        ["strings", None],
        ["description"], ["description_snum", None],
        [], ["location"], ["maximum"], ["minimum"], ["resolution"],
        ["tolerance"], ["accuracy"], ["oem"], ["nominal"],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType27(SMBIOSStructure):
    """
    Section 7.28 Cooling Device (Type 27)
    """

    label = "Cooling Device"

    definition = Struct(
        "temp_probe_handle" / Int16ul,
        "device_type" / Int8ul,
        "cooling_unit_group" / Int8ul,
        "oem" / Int32ul,
        "nominal_speed" / Int16ul,
        "description_snum" / Int8ul,
    )

    def set_strings(self) -> None:
        self.description = self.string_from_num(self.description_snum)

    reporting = [
        ["strings", None],
        ["description"], ["description_snum", None],
        [], ["temp_probe_handle"], ["device_type"], ["cooling_unit_group"],
        ["oem"], ["nominal_speed"],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType28(SMBIOSStructure):
    """
    Section 7.29 Temperature Probe (Type 28)
    """

    label = "Temperature Probe"

    definition = Struct(
        "description_snum" / Int8ul,
        "location" / Int8ul,
        "maximum" / Int16ul,
        "minimum" / Int16ul,
        "resolution" / Int16ul,
        "tolerance" / Int16ul,
        "accuracy" / Int16ul,
        "oem" / Int32ul,
        "nominal" / Int16ul,
    )

    def set_strings(self) -> None:
        self.description = self.string_from_num(self.description_snum)

    reporting = [
        ["strings", None],
        ["description"], ["description_snum", None],
        [], ["location"], ["maximum"], ["minimum"], ["resolution"],
        ["tolerance"], ["accuracy"], ["oem"], ["nominal"],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType29(SMBIOSStructure):
    """
    Section 7.30 Electrical Current Probe (Type 29)
    """

    label = "Electrical Current Probe"

    definition = Struct(
        "description_snum" / Int8ul,
        "location" / Int8ul,
        "maximum" / Int16ul,
        "minimum" / Int16ul,
        "resolution" / Int16ul,
        "tolerance" / Int16ul,
        "accuracy" / Int16ul,
        "oem" / Int32ul,
        "nominal" / Int16ul,
    )

    def set_strings(self) -> None:
        self.description = self.string_from_num(self.description_snum)

    reporting = [
        ["strings", None],
        ["description"], ["description_snum", None],
        [], ["location"], ["maximum"], ["minimum"], ["resolution"],
        ["tolerance"], ["accuracy"], ["oem"], ["nominal"],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType32(SMBIOSStructure):
    """
    Section 7.33 System Boot Information (Type 32)
    """

    label = "System Boot"

    definition = Struct(
        "reserved" / HexBytes(6),
        #"data" / GreedyHexBytes(),
        "data" / HexBytes(lambda ctx: ctx._.length - 10),
    )

    reporting = [
        ["strings", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType34(SMBIOSStructure):
    """
    Section 7.35 Management Device (Type 34)
    """

    label = "Management Device"

    definition = Struct(
        "description_snum" / Int8ul,
        "device_type" / Int8ul,
        "address" / Int32ul,
        "address_type" / Int8ul,
    )

    def set_strings(self) -> None:
        self.description = self.string_from_num(self.description_snum)

    reporting = [
        ["strings", None],
        ["description_snum", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType35(SMBIOSStructure):
    """
    Section 7.36 Management Device Component (Type 35)
    """

    label = "Management Device Component"

    definition = Struct(
        "description_snum" / Int8ul,
        "device_handle" / Int16ul,
        "component_handle" / Int16ul,
        "threshold_handle" / Int16ul,
    )

    reporting = [
        ["strings", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType36(SMBIOSStructure):
    """
    Section 7.37 Management Device Threshold Data (Type 36)
    """

    label = "Management Device Threshold Data"

    definition = Struct(
        "lower_non_crit" / Int16ul,
        "upper_non_crit" / Int16ul,
        "lower_crit" / Int16ul,
        "upper_crit" / Int16ul,
        "lower_non_recov" / Int16ul,
        "upper_non_recov" / Int16ul,
    )

    reporting = [
        ["strings", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType39(SMBIOSStructure):
    """
    Section 7.40 System Power Supply (Type 39)
    """

    label = "System Power Supply "

    definition = Struct(
        "location_snum" / Int8ul,
        "device_snum" / Int8ul,
        "manufacturer_snum" / Int8ul,
        "serial_snum" / Int8ul,
        "asset_tag_snum" / Int8ul,
        "part_number_snum" / Int8ul,
        "revision_snum" / Int8ul,
        "power_supply_characteristics" / Int16ul,
        "voltage_handle" / Int16ul,
        "cooling_handle" / Int16ul,
        "current_handle" / Int16ul,
    )

    def set_strings(self) -> None:
        self.location = self.string_from_num(self.location_snum)
        self.device = self.string_from_num(self.device_snum)
        self.manufacturer = self.string_from_num(self.manufacturer_snum)
        self.serial = self.string_from_num(self.serial_snum)
        self.asset_tag = self.string_from_num(self.asset_tag_snum)
        self.part_number = self.string_from_num(self.part_number_snum)
        self.revision = self.string_from_num(self.revision_snum)

    reporting = [
        ["strings", None],
        ["power_supply_characteristics"],
        ["voltage_handle"], ["cooling_handle"], ["current_handle"],
        [], ["location"], ["device"], ["manufacturer"], ["serial"],
        [], ["asset_tag"], ["part_number"], ["revision"],
        ["location_snum", None], ["device_snum", None], ["manufacturer_snum", None],
        ["serial_snum", None], ["asset_tag_snum", None], ["part_number_snum", None],
        ["revision_snum", None],
    ]

# ----------------------------------------------------------------------------------------
class AddInfoEntry(SMBIOSStructure):
    """
    Section 7.41.1 Additional Information Entry
    """

    label = "Additonal Information Entry"

    definition = Struct(
        "length" / Int8ul,
        "handle" / Int16ul,
        "offset" / Int8ul,
        "str_num" / Int8ul,
        "data" / HexBytes(this.length - 5),
    )

# ----------------------------------------------------------------------------------------
class SMBIOSType40(SMBIOSStructure):
    """
    Section 7.41 Additional Information (Type 40)
    """

    label = "Additional Information"

    definition = Struct(
        "count" / Int8ul,
        "data" / Array(this.count, Class(AddInfoEntry)),
    )

    reporting = [["data"]]

# ----------------------------------------------------------------------------------------
class SMBIOSType41(SMBIOSStructure):
    """
    Section 7.42 Onboard Devices Extended Information (Type 41)
    """

    label = "Onboard Devices Extended"

    definition = Struct(
        "designation_snum" / Int8ul,
        "type" / Int8ul,
        "instance" / Int8ul,
        "segment" / Int16ul,
        "bus" / Int8ul,
        "dev_func" / Int8ul,
    )

    def set_strings(self) -> None:
        self.designation = self.string_from_num(self.designation_snum)

    reporting = [["strings", None], ["designation_snum", None]]

# ----------------------------------------------------------------------------------------
class SMBIOSType127(SMBIOSStructure):
    """
    Section 7.45 End of Table (Type 127)
    """

    label = "End of Table"

    definition = Struct(
    )

    reporting = [
        ["strings", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOSType255Dell(SMBIOSStructure):
    """
    Undocumented Dell extension?
    """

    label = "Dell Extension"

    definition = Struct(
        "u1" / Int8ul,
        "u2" / Int8ul,
        "u3" / Int8ul,
        "u4" / Int8ul,
    )

# ----------------------------------------------------------------------------------------
class SMBIOSGenericRecord(SMBIOSStructure):
    """
    Detailed reporting for generic records.
    """

    label = "Generic Record"

    definition = Struct(
        "data" / Class(HexDump)
    )

    reporting = [["data"], ["strings"]]

# ----------------------------------------------------------------------------------------
def lazy_record_select(rectype: int) -> Type[SMBIOSStructure]:
    types = {
        0: SMBIOSType0,
        1: SMBIOSType1,
        2: SMBIOSType2,
        3: SMBIOSType3,
        4: SMBIOSType4,
        9: SMBIOSType9,
        10: SMBIOSType10,
        11: SMBIOSType11,
        12: SMBIOSType12,
        15: SMBIOSType15,
        16: SMBIOSType16,
        17: SMBIOSType17,
        19: SMBIOSType19,
        20: SMBIOSType20,
        21: SMBIOSType21,
        22: SMBIOSType22,
        25: SMBIOSType25,
        26: SMBIOSType26,
        27: SMBIOSType27,
        28: SMBIOSType28,
        29: SMBIOSType29,
        32: SMBIOSType32,
        34: SMBIOSType34,
        35: SMBIOSType35,
        36: SMBIOSType36,
        39: SMBIOSType39,
        40: SMBIOSType40,
        41: SMBIOSType41,
        127: SMBIOSType127,
        255: SMBIOSType255Dell,
    }
    if rectype in types:
        return types[rectype]
    return SMBIOSGenericRecord

# ----------------------------------------------------------------------------------------
class SMBIOSRecord(SMBIOSStructure):
    """
    A generic SMBIOS Record.
    """

    label = "SMBIOS Record"

    definition = Struct(
        "type" / Int8ul,
        "length" / Int8ul,
        "handle" / Int16ul,
        "interpretation" / FixedLength(this.length - 4, Switch(this.type, {
            0: Class(SMBIOSType0),
            1: Class(SMBIOSType1),
            2: Class(SMBIOSType2),
            3: Class(SMBIOSType3),
            4: Class(SMBIOSType4),
            9: Class(SMBIOSType9),
            10: Class(SMBIOSType10),
            11: Class(SMBIOSType11),
            12: Class(SMBIOSType12),
            15: Class(SMBIOSType15),
            16: Class(SMBIOSType16),
            17: Class(SMBIOSType17),
            19: Class(SMBIOSType19),
            20: Class(SMBIOSType20),
            21: Class(SMBIOSType21),
            22: Class(SMBIOSType22),
            25: Class(SMBIOSType25),
            26: Class(SMBIOSType26),
            27: Class(SMBIOSType27),
            28: Class(SMBIOSType28),
            29: Class(SMBIOSType29),
            32: Class(SMBIOSType32),
            34: Class(SMBIOSType34),
            35: Class(SMBIOSType35),
            36: Class(SMBIOSType36),
            39: Class(SMBIOSType39),
            40: Class(SMBIOSType40),
            41: Class(SMBIOSType41),
            127: Class(SMBIOSType127),
            255: Class(SMBIOSType255Dell),
        }, default=Class(SMBIOSGenericRecord))),
        "_null" / Peek(Int16ul),
        "strings" / IfThenElse(
            this._null == 0,
            Array(2, CString('utf-8')),
            RepeatUntil(lambda string, lst, ctx: len(string) == 0, CString('utf-8'))),
    )

    def analyze(self) -> None:
        if self.interpretation is not None:
            self.interpretation.strings = self.strings
            self.interpretation.set_strings()

    reporting = [
        ["type"], ["length"], ["handle"], ["interpretation"], ["strings", None],
    ]

# ----------------------------------------------------------------------------------------
class SMBIOS(FirmwareStructure):
    """
    The main SMBIOS data structure.
    """

    label = "SMBIOS Table"

    definition = Struct(
        "tables" / GreedyRange(Class(SMBIOSRecord)),
        "_padding" / GreedyRange(Const(b'\xff')),
        "padlen" / Computed(lambda ctx: len(ctx._padding)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["padlen"], ["tables"]]

# ----------------------------------------------------------------------------------------
def handle_order_check(ctx: Context) -> bool:
    tables = ctx.table.tables
    for n in range(len(tables)):
        # One example I've found had a strange number for the "end of table" handle.
        if tables[n].handle != n and tables[n].type != 127:
            return False
    return True

# ----------------------------------------------------------------------------------------
class SMBIOSFile(FirmwareStructure):
    """
    A version of the SMBIOS parser that attempts to identify whether the input file is in
    fact an SMBIOS table.  This is somewhat difficult, since there's no "magic" for the
    file.  The current approach is based on the presumption that the SMBIOS handles will
    increment monotonically beginning with zero.
    """

    label = "SMBIOS File"

    definition = Struct(
        "_magic" / Peek(Int32ul),
        Check(lambda ctx: (ctx._magic is not None and ctx._magic & 0xffff00ff) == 0),
        "table" / Class(SMBIOS),
        Check(lambda ctx: len(ctx.table.tables) > 3),
        Check(handle_order_check),
    )

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
