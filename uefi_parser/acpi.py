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
ACPI data structures, like the SSDT and others.
"""

import os
import subprocess
from enum import Flag
from datetime import datetime
from tempfile import NamedTemporaryFile

from construct import (
    Bytes, GreedyBytes, GreedyRange, Select, Computed, Const,
    If, Array, Int8ul, Int16ul, Int32ul, Int32sl, Int64ul, Check, Peek, this)

from .base import (
    FirmwareStructure, HashedFirmwareStructure, Struct, Class, FailPeek, UUID16,
    SafeFixedLength, PaddedString, promote_exceptions, CString, Opt, Context,
    EnumAdapter)
from .uenum import UEnum
from .mystery import MysteryBytes

# Standard documentation about many ACPI features:
# https://uefi.org/specs/ACPI/6.4/05_ACPI_Software_Programming_Model/ACPI_Software_Programming_Model.html

# Links to extensions to the API standard:  https://uefi.org/acpi

# ACPICA reference implementation: https://github.com/acpica/acpica/

# ----------------------------------------------------------------------------------------
# This is the variable length encoding mechanism used AML.  I got it working and didn't
# want to delete it until after I'd committed it somewhere.
@promote_exceptions
def pkglength_interpretation(ctx: Context) -> int:
    assert isinstance(ctx['len1'], int)
    assert isinstance(ctx['len2'], int)
    assert isinstance(ctx['len3'], int)
    assert isinstance(ctx['len4'], int)
    if ctx['num_bytes'] == 0:
        return ctx['len1'] & 0x3f
    if ctx['len3'] is None:
        return (ctx['len1'] & 0x0f << 4) + ctx['len2']
    if ctx['len4'] is None:
        return (ctx['len1'] & 0x0f << 12) + (ctx['len2'] << 8) + ctx['len3']
    return (ctx['len1'] & 0x0f << 20) + (ctx['len2'] << 16) + (ctx['len3'] << 8) + ctx['len4']

# ----------------------------------------------------------------------------------------
class PkgLength(FirmwareStructure):

    label = "PkgLength"

    definition = Struct(
        "len1" / Int8ul,
        "num_bytes" / Computed(lambda ctx: ((ctx["len1"] & 0xc0) >> 6)),
        "len2" / If(this.num_bytes > 0, Int8ul),
        "len3" / If(this.num_bytes > 1, Int8ul),
        "len4" / If(this.num_bytes > 2, Int8ul),
        "length" / Computed(pkglength_interpretation)
    )

    reporting = [
        ["len1", "0x%0x"],
    ]

# ----------------------------------------------------------------------------------------
class ACPIHeader(FirmwareStructure):

    label = "ACPI Header"

    definition = Struct(
        "signature" / Bytes(4),
        "length" / Int32ul,
        "revision" / Int8ul,
        "checksum" / Int8ul,
        "oem_id" / PaddedString(6),
        "oem_table_id" / PaddedString(8),
        "oem_vers" / Int32ul,
        "compiler_id" / PaddedString(4),
        "compiler_vers" / Int32ul,
    )

    reporting = [
        ["oem_id", "'%s'"], ["oem_table_id", "'%s'"], ["compiler_id", "'%s'"],
        ["length"], ["oem_vers", "0x%x"], ["compiler_vers", "0x%x"]
    ]

    sbom_fields = ["oem_id", "oem_table_id", "oem_vers"]

# ----------------------------------------------------------------------------------------
class GenericACPITable(FirmwareStructure):
    # Hmm.  I can't define a "shared" reporting value here...
    pass

# ----------------------------------------------------------------------------------------
class GenericACPIAMLTable(HashedFirmwareStructure):

    definition = Struct(
        "hdr_bytes" / Peek(Bytes(36)),
        "header" / Class(ACPIHeader),
        "aml" / GreedyBytes,
    )

    reporting = [
        ["header"], ["hdr_bytes", None], ["aml", None],
    ]

    def analyze(self) -> None:
        # Disabled because IASL is non-deterministic, and it was intereferring with
        # regression testing.  It's not shipped as a Python module, and we haven't told
        # users/how where to install it.  Finally, you may not actually want to see the
        # output in the text mode, because it's quite large.
        #self.disassembly = self.run_iasl(self.hdr_bytes + self.aml)
        self.disassembly = "Disassembly is possible using the iasl tool."

    def run_iasl(self, raw_data: bytes) -> str:
        tmp = NamedTemporaryFile(prefix="acpi", suffix=".acpi", delete=False)
        tmp.write(raw_data)
        tmp.flush()
        try:
            cp = subprocess.run(["iasl", "-d", tmp.name],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            tmp.close()
            if cp.returncode != 0:
                self.error("ACPI decompilation failed!")
                self.error("stdout=%r" % cp.stdout)
                self.error("stderr=%r" % cp.stderr)
                return "(FAILED, %d lines of stdout and %d lines of stderr)" % (
                    len(cp.stdout), len(cp.stderr))
            outname = tmp.name[:-5] + ".dsl"
            outfh = open(outname, "r")
            disassembly = outfh.readlines()
            outfh.close()
            os.remove(outname)
            os.remove(tmp.name)
            # Return the actual disassembly (which will be intelligibly printed by default)
            #return disassembly
            # Or instead return a summary of the disassembly to keep the output short.
            return "(CORRECT, %d lines)" % (len(disassembly))
        except FileNotFoundError:
            tmp.close()
            return "(FAILED, could not find iasl binary in PATH)"

# ----------------------------------------------------------------------------------------
class AddressSpaceName(UEnum):
    SystemMemorySpace = 0x00
    SystemIOSpace = 0x01
    PCIConfigurationSpace = 0x02
    EmbeddedController = 0x03
    SMBus = 0x04
    SystemCMOS = 0x05
    PCIBarTarget = 0x06
    IPMI = 0x07
    GeneralPurposeIO = 0x08
    GenericSerialBus = 0x09
    PlatformCommunicationsChannel = 0x0a
    FunctionalFixedHardware = 0x7f
    # All bytes values are defined in the standard!
    # Unused values < 0xc0 are reserved.
    # Values >= 0xc0 are OEM defined.

# ----------------------------------------------------------------------------------------
class AddressAccessSize(UEnum):
    Undefined = 0
    Byte = 1
    Word = 2
    Dword = 3
    Qword = 4

# ----------------------------------------------------------------------------------------
class GenericAddress(FirmwareStructure):
    """
    The Generic Address Structure (GAS) provides the platform with a robust means to
    describe register locations.

    Standard 6.4, section 5.2.3.2.
    """

    label = "Generic Address"

    definition = Struct(
        "space" / EnumAdapter(Int8ul, AddressSpaceName),
        "reg_width" / Int8ul,
        "reg_offset" / Int8ul,
        "access_size" / EnumAdapter(Int8ul, AddressAccessSize),
        "address" / Int64ul,
    )

    reporting = [
        ["address", "0x%x"], ["space"], ["reg_width"], ["reg_offset"], ["access_size"],
    ]

# ----------------------------------------------------------------------------------------
class DifferentiatedSystemDescriptionTable(GenericACPIAMLTable):
    """
    Differentiated System Description Table (DSDT)

    A DSDT is required; see also SSDT.  ACPI tables contain only one DSDT but can contain
    one or more SSDTs, which are optional. Each SSDT can only add to the ACPI namespace,
    but cannot modify or replace anything in the DSDT.

    Standard 6.4, section 5.2.11.1.
    """

    label = "Differentiated System Description Table"

    definition = Struct(
        FailPeek(Const(b'DSDT')),
        "hdr_bytes" / Peek(Bytes(36)),
        "header" / Class(ACPIHeader),
        "aml" / GreedyBytes,
    )

    sbom_fields = ["fshash", "header"]

# ----------------------------------------------------------------------------------------
class SecondarySystemDescriptionTable(GenericACPIAMLTable):
    """
    Secondary System Description Table (SSDT)

    These tables are a continuation of the DSDT; these are recommended for use with
    devices that can be added to a running system, but can also serve the purpose of
    dividing up device descriptions into more manageable pieces.  An SSDT can only ADD to
    the ACPI namespace. It cannot modify or replace existing device descriptions already
    in the namespace.  These tables are optional, however. ACPI tables should contain only
    one DSDT but can contain many SSDTs.

    Standard 6.4, section 5.2.11.1.
    """

    label = "Secondary System Description Table"

    definition = Struct(
        FailPeek(Const(b'SSDT')),
        "hdr_bytes" / Peek(Bytes(36)),
        "header" / Class(ACPIHeader),
        "aml" / GreedyBytes,
    )

    sbom_fields = ["fshash", "header"]

# ----------------------------------------------------------------------------------------
# The comments from these ACPI tables are largely from:
#   https://www.kernel.org/doc/html/latest/arm64/acpi_object_usage.html
# Another good source is:
#   https://wiki.osdev.org/RSDT

# ----------------------------------------------------------------------------------------
class ASFInfoRecord(FirmwareStructure):
    """
    This structure contains information that identifies the system’s type and
    configuration requirements for ASF alerts.

    Distributed Management Task Force (DMTF) extension.
    Alert Standard Format Specification, version 2.0, 23 April 2003, section 4.1.2.1
    """

    label = "ASF Info Record"

    definition = Struct(
        "_type" / Int8ul,
        "last" / Computed(lambda ctx: bool(ctx['_type'] & 0x80)),
        "type" / Computed(lambda ctx: ctx['_type'] & 0x7f),
        Check(lambda ctx: ctx['type'] == 0),
        "reserved" / Int8ul,
        "length" / Int16ul,
        "min_watchdog" / Int8ul,
        "min_sensor" / Int8ul,
        "system_id" / Int16ul,
        "IANA_mfg" / Bytes(4),
        "flags" / Int8ul,
        "reserved" / Bytes(3),
    )

# ----------------------------------------------------------------------------------------
class ASFAlertData(FirmwareStructure):
    """
    Alert Data contained in the ASF Alert Record of an ASF ACPI table.

    Distributed Management Task Force (DMTF) extension.
    Alert Standard Format Specification, version 2.0, 23 April 2003, section 4.1.2.3
    """

    label = "ASF Alert Data"

    definition = Struct(
        "dev_addr" / Int8ul,
        "command" / Int8ul,
        "data_mask" / Int8ul,
        "compare" / Int8ul,
        "event_sensor_type" / Int8ul,
        "event_type" / Int8ul,
        "event_offset" / Int8ul,
        "event_source_type" / Int8ul,
        "event_severity" / Int8ul,
        "sensor_number" / Int8ul,
        "entity" / Int8ul,
        "entity_instance" / Int8ul,
    )

# ----------------------------------------------------------------------------------------
class ASFAlertRecord(FirmwareStructure):
    """
    This structure contains information that identifies the system’s type and
    configuration requirements for ASF alerts.

    Distributed Management Task Force (DMTF) extension.
    Alert Standard Format Specification, version 2.0, 23 April 2003, section 4.1.2.1
    """

    label = "ASF Alert Record"

    definition = Struct(
        "_type" / Int8ul,
        "last" / Computed(lambda ctx: bool(ctx['_type'] & 0x80)),
        "type" / Computed(lambda ctx: ctx['_type'] & 0x7f),
        Check(lambda ctx: ctx['type'] == 1),
        "reserved" / Int8ul,
        "length" / Int16ul,
        "assertion" / Int8ul,
        "deassertion" / Int8ul,
        "num_alerts" / Int8ul,
        "elem_length" / Int8ul,
        # BUG!  Messy.  I meant to always consume the specific number of bytes, but that's
        # not really what this code does. :-( It'll work though so long as the record is
        # propoerly formed (e.g. length aligns with num_alerts and elem_length.
        "data" / SafeFixedLength(
            lambda ctx: ctx['elem_length'] * ctx['num_alerts'],
            GreedyRange(Class(ASFAlertData))
        ),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
    )

    reporting = [
        ["assertion"], ["deassertion"], ["num_alerts"], ["elem_length"],
        ["type"], ["last"], ["length"], ["reserved"], ["skipped"],
    ]

# ----------------------------------------------------------------------------------------
class ASFRemoteControlData(FirmwareStructure):
    """
    Remote Control Data contained in the ASF Remote Control Record of an ASF ACPI table.

    Distributed Management Task Force (DMTF) extension.
    Alert Standard Format Specification, version 2.0, 23 April 2003, section 4.1.2.5
    """

    label = "ASF Remote Control Data"

    definition = Struct(
        "function" / Int8ul,
        "dev_addr" / Int8ul,
        "command" / Int8ul,
        "data_value" / Int8ul,
    )

# ----------------------------------------------------------------------------------------
class ASFRemoteControlRecord(FirmwareStructure):
    """
    Devices might be used in a system to provide ASF-compatible remote-control system
    actions.

    Distributed Management Task Force (DMTF) extension.
    Alert Standard Format Specification, version 2.0, 23 April 2003, section 4.1.2.4
    """

    label = "ASF Remote Control Record"

    definition = Struct(
        "_type" / Int8ul,
        "last" / Computed(lambda ctx: bool(ctx['_type'] & 0x80)),
        "type" / Computed(lambda ctx: ctx['_type'] & 0x7f),
        Check(lambda ctx: ctx['type'] == 2),
        "reserved" / Int8ul,
        "length" / Int16ul,
        "num_controls" / Int8ul,
        "elem_length" / Int8ul,
        "reserved" / Int16ul,
        # BUG!  Messy.  I meant to always consume the specific number of bytes, but that's
        # not really what this code does. :-( It'll work though so long as the record is
        # propoerly formed (e.g. length aligns with num_controls and elem_length.
        "data" / SafeFixedLength(
            lambda ctx: ctx['elem_length'] * ctx['num_controls'],
            GreedyRange(Class(ASFRemoteControlData))
        ),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
    )

    reporting = [
        ["num_controls"], ["elem_length"], ["type"], ["last"], ["length"],
        ["reserved"], ["skipped"],
    ]

# ----------------------------------------------------------------------------------------
class ASFRemoteControlCapabilities(FirmwareStructure):
    """

    Distributed Management Task Force (DMTF) extension.
    Alert Standard Format Specification, version 2.0, 23 April 2003, section 4.1.2.6
    """

    label = "ASF Remote Control Capabilities (RMCP)"

    definition = Struct(
        "_type" / Int8ul,
        "last" / Computed(lambda ctx: bool(ctx['_type'] & 0x80)),
        "type" / Computed(lambda ctx: ctx['_type'] & 0x7f),
        Check(lambda ctx: ctx['type'] == 3),
        "reserved" / Int8ul,
        "length" / Int16ul,
        "capabilities" / Bytes(7),
        "completion_code" / Int8ul,
        "iana" / Bytes(4),
        "special_command" / Int8ul,
        "special_params" / Bytes(2),
        "boot_options" / Bytes(2),
        "oem_params" / Bytes(2),
    )

# ----------------------------------------------------------------------------------------
class ASFAddressRecord(FirmwareStructure):
    """
    This information record’s presence within a managed client’s ACPI implementation
    implies that the client includes SMBus devices with fixed addresses.

    Distributed Management Task Force (DMTF) extension.
    Alert Standard Format Specification, version 2.0, 23 April 2003, section 4.1.2.7
    """

    label = "ASF Address Record"

    definition = Struct(
        "_type" / Int8ul,
        "last" / Computed(lambda ctx: bool(ctx['_type'] & 0x80)),
        "type" / Computed(lambda ctx: ctx['_type'] & 0x7f),
        Check(lambda ctx: ctx['type'] == 4),
        "reserved" / Int8ul,
        "length" / Int16ul,
        "seeprom_addr" / Int8ul,
        "num_devices" / Int8ul,
        "addresses" / Array(this.num_devices, Int8ul),
    )

    reporting = [
        ["seeprom_addr"], ["num_devices"], ["addresses"],
        ["type"], ["last"], ["length"], ["reserved"],
    ]

# ----------------------------------------------------------------------------------------
class ASFUnknownRecord(FirmwareStructure):
    """
    Unrecognized ASF Record types not defined in the standard.

    Since the record format contains the length, we can consume the correct number of data
    bytes, and presumbly be somewhat robust to new standard versions.
    """

    label = "ASF Unknown Record"

    definition = Struct(
        "_type" / Int8ul,
        "last" / Computed(lambda ctx: ctx['_type'] & 0x80),
        "type" / Computed(lambda ctx: ctx['_type'] & 0x7f),
        "reserved" / Int8ul,
        "length" / Int16ul,
        "data" / Bytes(lambda ctx: 0 if ctx['length'] <= 4 else ctx['length'] - 4)
    )

    reporting = [["type"], ["last"], ["length"], ["data"], ["reserved"]]

# ----------------------------------------------------------------------------------------
class AlertStandardFormatTable(GenericACPITable):
    """
    Alert Standard Format Table

    Distributed Management Task Force (DMTF) extension.
    Alert Standard Format Specification, version 2.0, 23 April 2003, section 4.1.2

    https://www.dmtf.org/sites/default/files/standards/documents/DSP0136.pdf
    """

    label = "Alert Standard Format Table"

    definition = Struct(
        FailPeek(Const(b'ASF!')),
        "header" / Class(ACPIHeader),
        "entries" / GreedyRange(Select(
            Class(ASFInfoRecord),
            Class(ASFAlertRecord),
            Class(ASFRemoteControlRecord),
            Class(ASFRemoteControlCapabilities),
            Class(ASFAddressRecord),
            Class(ASFUnknownRecord),
        )),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["header"]]

# ----------------------------------------------------------------------------------------
class ACPISystemPerformanceTuning(GenericACPITable):
    """
    ACPI System Performance Tuning

    https://firmwaresecurity.com/2016/01/22/who-created-the-acpi-aspt-spec/
    https://firmwaresecurity.com/2015/12/08/fwts-adds-test-for-undocumented-aspt-acpi/

    Extension of unknown origin, reportedly Intel, but maybe AMD?
    Related to overclocking
    """

    label = "ACPI System Performance Tuning"

    definition = Struct(
        FailPeek(Const(b'ASPT')),
        "header" / Class(ACPIHeader),
        "addr1" / Int32ul,
        "addr2" / Int32ul,
        "addr3" / Int32ul,
        "addr4" / Int32ul,
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["header"]]

# ----------------------------------------------------------------------------------------
class BootErrorRecordTable(GenericACPITable):
    """
    Standard 6.4, Section 18.3.1.
    """

    label = "Boot Error Record Table"

    definition = Struct(
        FailPeek(Const(b'BERT')),
        "header" / Class(ACPIHeader),
        # Points (in memory) to an Error Status Block
        "boot_error_region_ptr" / Int64ul,
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["header"]]

# ----------------------------------------------------------------------------------------
class BootFlagTable(GenericACPITable):
    """
    Standard 6.4, Section 5.2.6, Table 5.6, simply "Reserved Signature".

    Reportedly a Microsoft extension.
    """

    label = "Boot Flag Table"

    definition = Struct(
        FailPeek(Const(b'BOOT')),
        "header" / Class(ACPIHeader),
        # This is speculative since I haven't found an official description of the table
        # format, but it seems to just be the a Windows drive letter?
        "boot_drive" / PaddedString(4, 'utf-8'),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["header"]]

# ----------------------------------------------------------------------------------------
class BootGraphicsResourceTable(GenericACPITable):
    """
    Standard 6.4, Section 5.2.22.
    """

    label = "Boot Graphics Resource Table"

    definition = Struct(
        FailPeek(Const(b'BGRT')),
        "header" / Class(ACPIHeader),
        # FIXME! Incomplete!
        "unparsed" / Class(MysteryBytes),
    )

    reporting = [["header"]]

# ----------------------------------------------------------------------------------------
# CPEP, Corrected Platform Error Polling table
#   Optional, not currently supported, and not recommended until such time as
#   ARM-compatible hardware is available, and the specification suitably modified.

# ----------------------------------------------------------------------------------------
# CSRT, Core System Resources Table
#   Optional, not currently supported.

# ----------------------------------------------------------------------------------------
# DBG2, DeBuG port table 2
#   License has changed and should be usable. Optional if used instead of
#   earlycon=<device> on the command line.

# ----------------------------------------------------------------------------------------
class DebugPortTable(GenericACPITable):
    """
    Debug Port Table

    Microsoft extension.
    """

    label = "Debug Port Table"

    definition = Struct(
        FailPeek(Const(b'DBGP')),
        "header" / Class(ACPIHeader),
        "interface_type" / Int8ul,
        "reserved" / Bytes(3),
        "base_address" / Class(GenericAddress),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["header"]]

# DBGP, DeBuG Port table
#   Present
#   Microsoft only table, will not be supported.

# ----------------------------------------------------------------------------------------
class DeviceScope(FirmwareStructure):
    """
    Device Scope

    A sub-record in the Hardware Unit Definition record of the DMAR Table.

    Specification: vt-directed-io-spec.pdf, section 8.3.1
    """

    label = "Device Scope"

    definition = Struct(
        "type" / Int8ul,
        "length" / Int8ul,
        "reserved" / Int16ul,
        "enum" / Int8ul,
        "start_bus" / Int8ul,
        "path_dev" / Int8ul,
        "path_func" / Int8ul,
    )

    reporting = [
        ["type"], ["length"], ["enum"], ["start_bus"],
        ["path_dev"], ["path_func"], ["reserved"],
    ]

# ----------------------------------------------------------------------------------------
class HardwareUnitDefinition(FirmwareStructure):
    """
    DMA Remapping Hardware Unit Definition (DRHD)

    Record type 0 in a DMA Remapping Table.

    Specification: vt-directed-io-spec.pdf, section 8.3
    """

    label = "DMA Remapping Hardware Unit Definition"

    definition = Struct(
        "type" / Const(0, Int16ul),
        "length" / Int16ul,
        "flags" / Int8ul,
        "reserved" / Int8ul,
        "segment" / Int16ul,
        "reg_addr" / Int64ul,
        "scopes" / SafeFixedLength(
            lambda ctx: 0 if ctx['length'] <= 16 else ctx['length'] - 16,
            GreedyRange(Class(DeviceScope))),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
    )

    reporting = [
        ["type"], ["length"], ["flags"], ["reserved"], ["segment"],
        ["reg_addr", "0x%x"], ["skipped"],
    ]

# ----------------------------------------------------------------------------------------
class ReservedMemoryRegionReporting(FirmwareStructure):
    """
    Reserved Memory Region Reporting

    Record type 1 in a DMA Remapping Table.

    Specification: vt-directed-io-spec.pdf, section 8.4
    """

    label = "Reserved Memory Region Reporting"

    definition = Struct(
        "type" / Const(1, Int16ul),
        "length" / Int16ul,
        "reserved" / Int16ul,
        "segment" / Int16ul,
        "base_addr" / Int64ul,
        "limit_addr" / Int64ul,
        "scopes" / SafeFixedLength(
            lambda ctx: 0 if ctx['length'] <= 24 else ctx['length'] - 24,
            GreedyRange(Class(DeviceScope))),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
    )

    reporting = [
        ["type"], ["length"], ["segment"],
        ["base_addr", "0x%x"], ["limit_addr", "0x%x"], ["skipped"],
    ]

# ----------------------------------------------------------------------------------------
class ACPINamespaceDeviceDeclaration(GenericACPITable):

    label = "ACPI Name-space Device Declaration"

    definition = Struct(
        "type" / Const(4, Int16ul),
        "length" / Int16ul,
        "reserved" / Bytes(3),
        "dev_num" / Int8ul,
        "name" / SafeFixedLength(
            lambda ctx: 0 if ctx['length'] <= 8 else ctx['length'] - 8,
            CString('utf8')
        ),
        # This is the leftover bytes from the SafeFixedLength.
        "skipped" / Computed(this.extra),
    )

    reporting = [["dev_num"], ["name"], ["type"], ["length"], ["skipped"]]

# ----------------------------------------------------------------------------------------
class GenericDMAREntry(GenericACPITable):

    definition = Struct(
        "type" / Int16ul,
        "length" / Int16ul,
        "data" / Bytes(lambda ctx: 0 if ctx['length'] <= 4 else ctx['length'] - 4)
    )

# ----------------------------------------------------------------------------------------
class DMARemappingTable(GenericACPITable):
    """
    DMA Remapping from the Intel Virtualization Technology for Directed I/O standard.

    Intel extension.

    Specification: vt-directed-io-spec.pdf, section 8.1
    """

    label = "DMA Remapping Table"

    definition = Struct(
        FailPeek(Const(b'DMAR')),
        "header" / Class(ACPIHeader),
        "haw" / Int8ul,
        "flags" / Int8ul,
        "reserved" / Bytes(10),
        "mappings" / GreedyRange(Select(
            Class(HardwareUnitDefinition),  # type 0
            Class(ReservedMemoryRegionReporting),  # type 1
            Class(ACPINamespaceDeviceDeclaration),  # type 4
            Class(GenericDMAREntry)
        )),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["header"]]

# ----------------------------------------------------------------------------------------
# DRTM, Dynamic Root of Trust for Measurement table
#   Optional, not currently supported.

# ----------------------------------------------------------------------------------------
class EmbeddedControllerDescriptionTable(GenericACPITable):

    label = "Embedded Controller Description Table"

    definition = Struct(
        FailPeek(Const(b'ECDT')),
        "header" / Class(ACPIHeader),
        "unparsed" / Class(MysteryBytes),
    )

    reporting = [["header"]]

# ----------------------------------------------------------------------------------------
# EINJ, Error Injection table
#   This table is very useful for testing platform response to error conditions; it
#   allows one to inject an error into the system as if it had actually occurred.
#   However, this table should not be shipped with a production system; it should be
#   dynamically loaded and executed with the ACPICA tools only during testing.

# ----------------------------------------------------------------------------------------
# ERST, Error Record Serialization Table
#   On a platform supports RAS, this table must be supplied if it is not UEFI-based;
#   if it is UEFI-based, this table may be supplied. When this table is not present,
#   UEFI run time service will be utilized to save and retrieve hardware error
#   information to and from a persistent store.

# ----------------------------------------------------------------------------------------
# ETDT, Event Timer Description Table
#   Obsolete table, will not be supported.

# ----------------------------------------------------------------------------------------
# FACS, Firmware ACPI Control Structure
#   It is unlikely that this table will be terribly useful. If it is provided, the
#   Global Lock will NOT be used since it is not part of the hardware reduced profile,
#   and only 64-bit address fields will be considered valid.

# ----------------------------------------------------------------------------------------
# NOT Parsing in HP Spectre?
class FixedACPIDescriptionTable(GenericACPITable):
    """
    The Fixed ACPI Description Table (FADT) defines various fixed hardware ACPI
    information vital to an ACPI-compatible OS, such as the base address for various
    hardware registers.

    Standard 6.4, Section 5.2.9.
    """

    label = "Fixed ACPI Description Table"

    definition = Struct(
        # Note that this magic intentionally does NOT match the table name 'FADT'!
        # Apparently this is because the signature predates ACPI version 1.0.
        FailPeek(Const(b'FACP')),
        "header" / Class(ACPIHeader),
        "facs_addr" / Int32ul,
        "dsdt_addr" / Int32ul,
        "reserved1" / Int8ul,
        "profile" / Int8ul,
        "sci" / Int16ul,
        "smi_cmd" / Int32ul,
        "acpi_enable" / Int8ul,
        "acpi_disable" / Int8ul,
        "s4bios" / Int8ul,
        "pstate_cnt" / Int8ul,
        "pm1a_evt" / Int32ul,
        "pm1b_evt" / Int32ul,
        "pm1a_cnt" / Int32ul,
        "pm1b_cnt" / Int32ul,
        "pm2_cnt" / Int32ul,
        "pm_tmr" / Int32ul,
        "gpe0" / Int32ul,
        "gpe1" / Int32ul,
        "pm1_evt_len" / Int8ul,
        "pm1_cnt_len" / Int8ul,
        "pm2_cnt_len" / Int8ul,
        "gpe0_len" / Int8ul,
        "gpe1_len" / Int8ul,
        "gpe1_base" / Int8ul,
        "cst_cnt" / Int8ul,
        "plvl2" / Int16ul,
        "plvl3" / Int16ul,
        "flush_size" / Int16ul,
        "flush_stride" / Int16ul,
        "duty_offset" / Int8ul,
        "duty_width" / Int8ul,
        "day_alarm" / Int8ul,
        "mon_alarm" / Int8ul,
        "century" / Int8ul,
        "iapc_boot_arch" / Int16ul,
        "reserved2" / Int8ul,
        "flags" / Int32ul,
        "reset_reg" / Class(GenericAddress),
        "reset_value" / Int8ul,
        "arm_boot_arch" / Int16ul,
        "minor_vers" / Int8ul,
        "x_facs_addr" / Int64ul,
        "x_dsdt" / Int64ul,
        "x_pm1a_evt" / Class(GenericAddress),
        "x_pm1b_evt" / Class(GenericAddress),
        "x_pm1a_cnt" / Class(GenericAddress),
        "x_pm1b_cnt" / Class(GenericAddress),
        "x_pm2_cnt" / Class(GenericAddress),
        "x_pm_tmr" / Class(GenericAddress),
        "x_gpe0" / Class(GenericAddress),
        "x_gpe1" / Class(GenericAddress),
        # So I've found at least one instance of this table that was only 244 bytes long,
        # and was presumably missing these extra fields.  There's probably a more
        # principled explanation about older standard versions, but for now I'm just going
        # to mark them as optional.
        "sleep_control" / Opt(Class(GenericAddress)),
        "sleep_status" / Opt(Class(GenericAddress)),
        "hyper_identity" / Opt(Int64ul),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["header"]]

    def analyze(self) -> None:
        # So we can tell the multiple addresses apart.
        self.reset_reg.label = "Reset Register"
        self.x_pm1a_evt.label = "PM1a Event Register Block"
        self.x_pm1b_evt.label = "PM1b Event Register Block"
        self.x_pm1a_cnt.label = "PM1b Control Register Block"
        self.x_pm1b_cnt.label = "PM1b Control Register Block"
        self.x_pm2_cnt.label = "PM2 Control Register Block"
        self.x_pm_tmr.label = "Power Management Timer Control Register Block"
        self.x_gpe0.label = "General Purpose Event 0 Register Block"
        self.x_gpe1.label = "General Purpose Event 1 Register Block"
        if self.sleep_control is not None:
            self.sleep_control.label = "Sleep Control Register"
            self.sleep_status.label = "Sleep Status Register"

# ----------------------------------------------------------------------------------------
class FirmwareACPIControlStructure(FirmwareStructure):
    """
    The Firmware ACPI Control Structure (FACS) is a structure in read/write memory that
    the platform boot firmware reserves for ACPI usage.

    Standard 6.4, Section 5.2.10.
    """

    label = "Firmware ACPI Control Structure"

    definition = Struct(
        "_magic" / Const(b'FACS'),
        "length" / Int32ul,
        "hwsig" / Bytes(4),
        "wake_vector" / Int32ul,
        "global_lock" / Int32ul,
        "flags" / Int32ul,
        "x_wake_vector" / Int64ul,
        "version" / Int8ul,
        "_reserved1" / Const(b'\x00\x00\x00'),
        "ospm_flags" / Int32ul,
        "_reserved2" / Const(b'\x00' * 24),
    )

# ----------------------------------------------------------------------------------------
class FirmwareIdentificationData(FirmwareStructure):
    """
    This is the $FID blob inside the "Firmware Identification Table" (FIDT) ACPI Table.

    It sometimes occurs without the ACPI Header, perhaps because it was a proprietary AMI
    data structure before they standardized it as and ACPI extension?
    """

    label = "Firmware Identification Data"

    definition = Struct(
        "magic" / Const(b'$FID'),
        "version" / Int8ul,
        "length" / Int16ul,
        "tag" / PaddedString(9, 'utf-8'),
        "guid" / UUID16,
        "core_major_vers" / PaddedString(3, 'utf-8'),
        "core_minor_vers" / PaddedString(3, 'utf-8'),
        "project_major_vers" / PaddedString(3, 'utf-8'),
        "project_minor_vers" / PaddedString(3, 'utf-8'),
        "year" / Int16ul,
        "month" / Int8ul,
        "day" / Int8ul,
        "hour" / Int8ul,
        "minute" / Int8ul,
        "second" / Int8ul,
        # These fields were not documented in the patent.
        "pad" / Bytes(2),
        "oem_id" / PaddedString(6, 'utf-8'),
        "oem_table_id" / PaddedString(8, 'utf-8'),
        "oem_vers" / Int32ul,
        # The FF padding is often not present in the FIDT ACPI tables, but is present when
        # this data structure is found in otehr contexts.
        "_ff_padding" / GreedyRange(Const(b'\xff')),
        "unexpected" / Class(MysteryBytes),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    core_major_vers: str
    core_minor_vers: str
    project_major_vers: str
    project_minor_vers: str

    reporting = [
        ["guid"], ["tag", "'%s'"], ["oem_id", "'%s'"],
        ["oem_table_id", "'%s'"], ["oem_vers"],
        [], ["timestamp", "'%s'"],
        ["core_vers", "'%s'"], ["core_major_vers", None], ["core_minor_vers", None],
        ["project_vers", "'%s'"], ["project_major_vers", None], ["project_minor_vers", None],
        ["magic"], ["version"], ["length"],
        ["year", None], ["month", None], ["day", None],
        ["hour", None], ["minute", None], ["second", None],
    ]

    @property
    def timestamp(self) -> datetime:
        return datetime(self.year, self.month, self.day, self.hour, self.minute, self.second)

    @property
    def core_vers(self) -> str:
        return self.core_major_vers + "." + self.core_minor_vers

    @property
    def project_vers(self) -> str:
        return self.project_major_vers + "." + self.project_minor_vers

# ----------------------------------------------------------------------------------------
class FirmwareIdentificationTable(GenericACPITable):
    """
    American Megatrends extension.

    https://patents.justia.com/patent/10891139
    """

    label = "Firmware Identification Table"

    definition = Struct(
        FailPeek(Const(b'FIDT')),
        "header" / Class(ACPIHeader),
        "data" / Class(FirmwareIdentificationData),
    )

    reporting = [["header"], ["data"]]

# ----------------------------------------------------------------------------------------
# FETR - Firmware Enabled Tool Registry
# https://patents.google.com/patent/US10262158B1/en

# ----------------------------------------------------------------------------------------
class FirmwarePerformanceDataTable(GenericACPITable):
    """
    Standard 6.4, Section 5.2.32.
    """

    label = "Firmware Performance Data Table"

    definition = Struct(
        FailPeek(Const(b'FPDT')),
        "header" / Class(ACPIHeader),
        # FIXME! Incomplete!
        "unparsed" / Class(MysteryBytes),
    )

    reporting = [["header"]]

# ----------------------------------------------------------------------------------------
class GenericTimerDescriptionTable(GenericACPITable):
    """
    Standard 6.4, Section 5.2.24.
    """

    label = "Generic Timer Description Table"

    definition = Struct(
        FailPeek(Const(b'GTDT')),
        "header" / Class(ACPIHeader),
        # FIXME! Incomplete!
        "unparsed" / Class(MysteryBytes),
    )

    reporting = [["header"]]

# ----------------------------------------------------------------------------------------
class HardwareErrorSource(FirmwareStructure):
    """
    Standard 6.4, Section 18.3.2.7.
    """

    label = "Hardware Error Source"

    definition = Struct(
        "type" / Int16ul,
        "source" / Int16ul,
        "related_source" / Int16ul,
        "flags" / Int8ul,
        "enabled" / Int8ul,
        "prealloc" / Int32ul,
        "max_sections" / Int32ul,
        # FIXME! These two are really structures!
        "error_address" / Class(GenericAddress),
        "notification" / Bytes(28),
        "error_length" / Int32ul,
    )

# ----------------------------------------------------------------------------------------
class HardwareErrorSourceTable(GenericACPITable):
    """
    Standard 6.4, Section 18.3.2.
    """

    label = "Hardware Error Source Table"

    definition = Struct(
        FailPeek(Const(b'HEST')),
        "header" / Class(ACPIHeader),
        "num_entries" / Int32ul,
        "entries" / Array(this.num_entries, Class(HardwareErrorSource)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["header"]]

    # ARM-specific error sources have been defined; 6 = AER Root Port, 7 = AER Endpoint,
    # 8 = AER Bridge, 9 = Generic Hardware Error Source

# ----------------------------------------------------------------------------------------
class HighPrecisionEventTimerTable(GenericACPITable):
    """
    IA-PC High Precision Event Timer Table

    Intel ACPI extension.
    """

    label = "IA-PC High Precision Event Timer Table"

    definition = Struct(
        FailPeek(Const(b'HPET')),
        "header" / Class(ACPIHeader),
        # Incomplete!
        "timer_block" / Int32ul,
        "base_address" / Class(GenericAddress),
        "sequence" / Int8ul,
        "minimum" / Int16ul,
        "flags" / Int8ul,
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["header"], ["sequence"], ["timer_block", "0x%x"]]

# ----------------------------------------------------------------------------------------
# IBFT, iSCSI Boot Firmware Table
#   Microsoft defined table, support TBD.

# ----------------------------------------------------------------------------------------
# IORT, Input Output Remapping Table
#   arm64 only table, required in order to describe IO topology, SMMUs, and GIC ITSs, and
#   how those various components are connected together, such as identifying which
#   components are behind which SMMUs/ITSs. This table will only be required on certain
#   SBSA platforms (e.g., when using GICv3-ITS and an SMMU); on SBSA Level 0 platforms,
#   it remains optional.

# IVRS, I/O Virtualization Reporting Structure
#   x86_64 (AMD) only table, will not be supported.

# ----------------------------------------------------------------------------------------
class LowPowerIdleDescriptor(FirmwareStructure):
    """
    Entries in the Low Power Idle Table.
    """

    label = "Low Power Idle Descriptor"

    definition = Struct(
        "type" / Int32ul,
        "length" / Int32ul,
        "unique_id" / Int16ul,
        "reserved" / Int16ul,
        "flags" / Int32ul,
        # Really a Generic Address Structure
        "trigger" / Class(GenericAddress),
        "residency" / Int32ul,
        "latency" / Int32ul,
        # Really a Generic Address Structure
        "counter" / Class(GenericAddress),
        "frequency" / Int64ul,
    )

    reporting = [["unique_id"], ["type"], ["flags"]]

    def analyze(self) -> None:
        # So we can tell the two addresses apart.
        self.trigger.label = "Trigger Address"
        self.counter.label = "Counter Address"

# ----------------------------------------------------------------------------------------
class LowPowerIdleTable(GenericACPITable):
    """
    Low Power S0 Idle Table

    Intel ACPI Extension.
    """

    label = "Low Power Idle Table"

    definition = Struct(
        FailPeek(Const(b'LPIT')),
        "header" / Class(ACPIHeader),
        "entries" / GreedyRange(Class(LowPowerIdleDescriptor)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["header"]]

# ----------------------------------------------------------------------------------------
class ProcessorLocalAPIC(FirmwareStructure):

    label = "Processor Local APIC"

    definition = Struct(
        "type" / Const(0, Int8ul),
        "length" / Int8ul,
        # OVMF includes additional data after an invalid "zero block".
        Check(lambda ctx: ctx['length'] >= 2),
        "proc_id" / Int8ul,
        "apic_id" / Int8ul,
        "flags" / Int32ul,
    )

    reporting = [["proc_id"], ["apic_id"], ["flags"], ["type"], ["length"]]

# ----------------------------------------------------------------------------------------
class IOAPIC(FirmwareStructure):

    label = "I/O APIC"

    definition = Struct(
        "type" / Const(1, Int8ul),
        "length" / Int8ul,
        "apic_id" / Int8ul,
        "reserved" / Int8ul,
        "address" / Int32ul,
        "interrupt_base" / Int32ul,
    )

    reporting = [
        ["apic_id"], ["address", "0x%x"],
        ["interrupt_base", "0x%0x"], ["type"], ["length"], ["reserved"],
    ]

# ----------------------------------------------------------------------------------------
class InterruptSourceOverride(FirmwareStructure):

    label = "Interrupt Source Override"

    definition = Struct(
        "type" / Const(2, Int8ul),
        "length" / Int8ul,
        "bus" / Int8ul,
        "source" / Int8ul,
        "global_system_interrupt" / Int32ul,
        "flags" / Int16ul,
    )

    reporting = [
        ["bus"], ["source"], ["global_system_interrupt"], ["flags"], ["type"], ["length"]
    ]

# ----------------------------------------------------------------------------------------
# Type=3 IO/APIC Non-maskable interrupt source

# ----------------------------------------------------------------------------------------
class LocalAPICNonMaskable(FirmwareStructure):
    """
    Local APIC Non-maskable Interrupt
    """

    label = "Local APIC Non-maskable Interrupt"

    definition = Struct(
        "type" / Const(4, Int8ul),
        "length" / Int8ul,
        "apic_id" / Int8ul,
        "flags" / Int16ul,
        "lint" / Int8ul,
    )

    reporting = [["apic_id"], ["flags"], ["lint"], ["type"], ["length"]]

# ----------------------------------------------------------------------------------------
class ProcessorLocalx2APIC(FirmwareStructure):
    """
    Processor Local x2APIC

    Represents a physical processor and its Local x2APIC. Identical to Local APIC; used
    only when that struct would not be able to hold the required values.
    """

    label = "Processor Local x2APIC"

    definition = Struct(
        "type" / Const(9, Int8ul),
        "length" / Int8ul,
        "reserved" / Int16ul,
        "proc_id" / Int32sl,
        "flags" / Int32ul,
        "acpi_id" / Int32ul,
    )

    reporting = [["proc_id"], ["acpi_id"], ["flags"], ["type"], ["length"], ["reserved"]]

# ----------------------------------------------------------------------------------------
class GenericAPIC(FirmwareStructure):

    label = "Generic Interrupt Controller"

    definition = Struct(
        "type" / Int8ul,
        "length" / Int8ul,
        "data" / Bytes(this.length - 2),
    )

    reporting = [["type"], ["length"], ["data"]]

# ----------------------------------------------------------------------------------------
class MultipleAPICDescriptionTable(GenericACPITable):
    """
    Multiple APIC Description Table (MADT)

    Standard 6.4, section 5.21.12
    https://wiki.osdev.org/MADT
    https://www.naic.edu/~phil/software/intel/318148.pdf
    """

    label = "Multiple APIC Description Table"

    definition = Struct(
        FailPeek(Const(b'APIC')),
        "header" / Class(ACPIHeader),
        "controller_address" / Int32ul,
        "flags" / Int32ul,
        "entries" / GreedyRange(Select(
            Class(ProcessorLocalAPIC),
            Class(IOAPIC),
            Class(InterruptSourceOverride),
            Class(LocalAPICNonMaskable),
            Class(ProcessorLocalx2APIC),
            Class(GenericAPIC),
        )),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["header"],
        ["controller_address", "0x%x"], ["flags"],
    ]

# ----------------------------------------------------------------------------------------
class PCIExpress(FirmwareStructure):
    """
    The PCI Express related structures in side the PCI Express Memory-mapped Configuration
    Space.
    """

    label = "PCI Express Configuration"

    definition = Struct(
        "base_address" / Int64ul,
        "pci_segment" / Int16ul,
        "start" / Int8ul,
        "end" / Int8ul,
        "reserved" / Int32ul,
    )

    reporting = [["base_address", "0x%x"], ["pci_segment"], ["start"], ["end"]]

# ----------------------------------------------------------------------------------------
class MemoryMappedConfigurationSpace(GenericACPITable):
    """
    PCI Express Memory-mapped Configuration Space

    PCI-SIG extension.

    The standard is reportedly at: https://pcisig.com/, but I found the definition at
    https://wiki.osdev.org/PCI_Express more easily.
    """

    label = "PCI Express Memory-mapped Configuration Space"

    definition = Struct(
        FailPeek(Const(b'MCFG')),
        "header" / Class(ACPIHeader),
        "reserved" / Int64ul,
        "entries" / GreedyRange(Class(PCIExpress)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["header"]]

# ----------------------------------------------------------------------------------------
# MCHI, Management Controller Host Interface table
#   Optional, not currently supported.

# ----------------------------------------------------------------------------------------
# MPST, Memory Power State Table
#   Standard 6.4, Section 5.2.21, Not AML

# ----------------------------------------------------------------------------------------
# MSCT, Maximum System Characteristic Table
#   Optional, not currently supported.

# ----------------------------------------------------------------------------------------
class MicrosoftDataManagementTable(GenericACPITable):
    """
    Microsoft Data Management Table

    Microsoft extension.
    """

    label = "Microsoft Data Management Table"

    definition = Struct(
        FailPeek(Const(b'MSDM')),
        "header" / Class(ACPIHeader),
        # Wow.  Super helpful.  The standard just says "proprietary data structure".
        "proprietary" / Class(MysteryBytes),
    )

    reporting = [["header"]]

# ----------------------------------------------------------------------------------------
# NFIT, NVDIMM Firmware Interface Table
#   Standard 6.4, Section 5.2.25, Not AML

# ----------------------------------------------------------------------------------------
# OEMx, OEM Specific Tables
#   All tables starting with a signature of “OEM” are reserved for OEM use. Since these
#   are not meant to be of general use but are limited to very specific end users, they
#   are not recommended for use and are not supported by the kernel for arm64.

# ----------------------------------------------------------------------------------------
# PCCT, Platform Communications Channel Table
#   Recommend for use on arm64; use of PCC is recommended when using CPPC to control
#   performance and power for platform processors.

# ----------------------------------------------------------------------------------------
# PMTT, Platform Memory Topology Table
#   Standard 6.4, Section 5.2.21.12, Not AML

# ----------------------------------------------------------------------------------------
# PSDT, Persistent System Description Table
#   Obsolete table, will not be supported.

# ----------------------------------------------------------------------------------------
# RASF, RAS Feature table
#   Standard 6.4, Section 5.2.20

# ----------------------------------------------------------------------------------------
# RSDP, Root System Description PoinTeR
#   Required for arm64.

# ----------------------------------------------------------------------------------------
# RSDT, Root System Description Table
#   https://wiki.osdev.org/RSDT
#   Since this table can only provide 32-bit addresses, it is deprecated on arm64, and
#   will not be used. If provided, it will be ignored.

# ----------------------------------------------------------------------------------------
# SBST, Smart Battery Subsystem Table
#   Optional, not currently supported.

# ----------------------------------------------------------------------------------------
class SoftwareLicensingTable(GenericACPITable):
    """
    Software Licensing Table

    Microsoft extension.
    """

    label = "Software Licensing Table"

    definition = Struct(
        FailPeek(Const(b'SLIC')),
        "header" / Class(ACPIHeader),
        # Wow.  Super helpful.  The standard just says "proprietary data structure".
        "proprietary" / Class(MysteryBytes),
    )

    reporting = [["header"]]

# ----------------------------------------------------------------------------------------
# SLIT, System Locality distance Information Table
#   Optional in general, but required for NUMA systems.

# ----------------------------------------------------------------------------------------
class SerialPortConsoleRedirectionTable(GenericACPITable):
    """
    Serial Port Console Redirection Table

    Microsoft extension.
    """

    label = "Serial Port Console Redirection Table"

    definition = Struct(
        FailPeek(Const(b'SPCR')),
        "header" / Class(ACPIHeader),
        "interface_type" / Int8ul,
        "reserved" / Bytes(3),
        "base_address" / Class(GenericAddress),
        "interrupt_type" / Int8ul,
        "irq" / Int8ul,
        "gsiv" / Int32ul,
        "baud" / Int8ul,
        "parity" / Int8ul,
        "stop_bits" / Int8ul,
        "flow_control" / Int8ul,
        "terminal_type" / Int8ul,
        "language" / Int8ul,
        "pci_device_id" / Int16ul,
        "pci_vendor_id" / Int16ul,
        "pci_bus" / Int8ul,
        "pci_device" / Int8ul,
        "pci_function" / Int8ul,
        "pci_flags" / Int32ul,
        "pci_segment" / Int8ul,
        "uart_freq" / Int32ul,
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["header"]]

# ----------------------------------------------------------------------------------------
# SPMI, Server Platform Management Interface table
#   Optional, not currently supported.

# ----------------------------------------------------------------------------------------
# SRAT, System Resource Affinity Table
#   Optional, but if used, only the GICC Affinity structures are read. To support arm64
#   NUMA, this table is required.

# ----------------------------------------------------------------------------------------
# STAO _STA Override table
#   Optional, but only necessary in virtualized environments in order to hide devices
#   from guest OSs.

# ----------------------------------------------------------------------------------------
# TCPA, Trusted Computing Platform Alliance table
#   Optional, not currently supported, and may need changes to fully interoperate
#   with arm64.

# ----------------------------------------------------------------------------------------
# TPM2, Trusted Platform Module 2 table
#   Optional, not currently supported, and may need changes to fully interoperate
#   with arm64.

# ----------------------------------------------------------------------------------------
# UEFI, UEFI ACPI data table
#   Optional, not currently supported. No known use case for arm64, at present.

# ----------------------------------------------------------------------------------------
# WAET, Windows ACPI Emulated devices Table
#   Microsoft only table, will not be supported.

# ----------------------------------------------------------------------------------------
class WatchdogInstructionFlags(Flag):
    Countdown = 1
    Write = 2
    Preserve = 0x80

# ----------------------------------------------------------------------------------------
class WatchdogInstructionEntry(FirmwareStructure):
    """
    Watchdog instruction entries for the Watchdog Action Table.
    """

    label = "Watchdog Instruction Entry"

    definition = Struct(
        "action" / Int8ul,
        "flags" / EnumAdapter(Int8ul, WatchdogInstructionFlags),
        "reserved" / Int16ul,
        "reg_region" / Class(GenericAddress),
        "value" / Int32ul,
        "mask" / Int32ul,
    )

    def analyze(self) -> None:
        self.reg_region.label = "Register Region"

# ----------------------------------------------------------------------------------------
class WatchdogActionTable(GenericACPITable):
    """
    Hardware Watchdog Action Timer Table

    Microsoft ACPI extension.
    """

    label = "Watchdog Action Table"

    definition = Struct(
        FailPeek(Const(b'WDAT')),
        "header" / Class(ACPIHeader),
        "wd_hdr_len" / Int32ul,
        "pci_segment" / Int16ul,
        "pci_bus" / Int8ul,
        "pci_device" / Int8ul,
        "pci_function" / Int8ul,
        "_reserved1" / Bytes(3),
        "timer" / Int32ul,
        "max" / Int32ul,
        "min" / Int32ul,
        "flags" / Int8ul,
        "_reserved2" / Bytes(3),
        "num_entries" / Int32ul,
        "entries" / Array(this.num_entries, Class(WatchdogInstructionEntry)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["header"],
        ["num_entries"], ["min"], ["max"],
        ["pci_segment"], ["pci_bus"], ["pci_device"], ["pci_function"],
        ["timer"], ["flags"], ["wd_hdr_len", None]
    ]

# ----------------------------------------------------------------------------------------
# WDRT, Watch Dog Resource Table
#   Microsoft only table, will not be supported.

# ----------------------------------------------------------------------------------------
# WPBT, Windows Platform Binary Table
#   Microsoft only table, will not be supported.

# ----------------------------------------------------------------------------------------
class WindowsSMMSecurityMitigationsTable(GenericACPITable):
    """
    Windows SMM Security Mitigations Table

    Microsoft ACPI extension.
    """

    label = "Windows SMM Security Mitigations Table"

    definition = Struct(
        FailPeek(Const(b'WSMT')),
        "header" / Class(ACPIHeader),
        "flags" / Int32ul,
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["header"], ["flags", "0x%x"],
    ]

# XENV, Xen project table
#   Optional, used only by Xen at present.

# XSDT, eXtended System Description Table
#   Required for arm64.

ACPITables = Select(
    Class(SecondarySystemDescriptionTable),
    Class(DifferentiatedSystemDescriptionTable),
    Class(HighPrecisionEventTimerTable),
    Class(LowPowerIdleTable),
    Class(WindowsSMMSecurityMitigationsTable),
    Class(WatchdogActionTable),
    Class(FixedACPIDescriptionTable),
    Class(FirmwareACPIControlStructure),
    Class(MultipleAPICDescriptionTable),
    Class(MemoryMappedConfigurationSpace),
    Class(SerialPortConsoleRedirectionTable),
    Class(DMARemappingTable),
    Class(DebugPortTable),

    # No real standard found.
    Class(FirmwareIdentificationTable),
    Class(SoftwareLicensingTable),
    Class(BootFlagTable),
    Class(ACPISystemPerformanceTuning),
    Class(AlertStandardFormatTable),

    # No exemplar found yet
    # Class(EmbeddedControllerBootResourcesTable),
    # Class(MicrosoftDataManagementTable),
)

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
