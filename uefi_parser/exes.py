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

from typing import Optional

from construct import (
    Array, Bytes, Computed, Const, GreedyBytes, Int8ul, Int16ul, Int32ul, Int64ul,
    Select, IfThenElse, Check, Seek, Tell, this)
import pefile

from .base import (
    FirmwareStructure, HashedFirmwareStructure, Class, PaddedString, FixedLength,
    promote_exceptions, Struct, Context, EnumAdapter)
from .uenum import UEnum
from .mystery import MysteryBytes, CommitMystery
from .utils import purple
from .sbom import USwid

# ----------------------------------------------------------------------------------------
class PEMachine(UEnum):
    Unknown = 0x0         # Unknown
    ALPHA = 0x184         # Alpha AXP, 32-bit address space
    ALPHA64 = 0x284       # Alpha 64, 64-bit address space
    AM33 = 0x1d3          # Matsushita AM33
    AMD64 = 0x866         # x64
    ARM = 0x1c0           # ARM little endian
    ARM64 = 0xaa64        # ARM64 little endian
    ARM64EC = 0xa641      # ARM64 / emulated x64 code
    ARM64X = 0xa64e       # ARM64 & ARM64EC
    ARMNT = 0x1c4         # ARM Thumb-2 little endian
    AXP64 = 0x284         # AXP 64 (Same as Alpha 64)
    EBC = 0xebc           # EFI byte code
    I386 = 0x14c          # Intel 386 and compatible
    IA64 = 0x200          # Intel Itanium processor family
    LoongArch32 = 0x6232  # LoongArch 32-bit processor family
    LoongArch64 = 0x6264  # LoongArch 64-bit processor family
    M32R = 0x9041         # Mitsubishi M32R little endian
    MIPS16 = 0x266        # MIPS16
    MIPSFPU = 0x366       # MIPS with FPU
    MIPSFPU16 = 0x466     # MIPS16 with FPU
    PowerPC = 0x1f0       # Power PC little endian
    PowerPCFP = 0x1f1     # Power PC with floating point
    R3000BE = 0x160       # MIPS I, 32-bit big endian
    R3000 = 0x162         # MIPS I, 32-bit little endian
    R4000 = 0x166         # MIPS III, 64-bit little endian
    R10000 = 0x168        # MIPS IV, 64-bit little endian
    RISCV32 = 0x5032      # RISC-V 32-bit address space
    RISCV64 = 0x5064      # RISC-V 64-bit address space
    RISCV128 = 0x512      # RISC-V 128-bit address space
    SH3 = 0x1a2           # Hitachi SH3
    SH3DSP = 0x1a3        # Hitachi SH3 DSP
    SH4 = 0x1a6           # Hitachi SH4
    SH5 = 0x1a8           # Hitachi SH5
    Thumb = 0x1c2         # Thumb
    WCEMIPSV2 = 0x169     # MIPS little-endian WCE v2

# ----------------------------------------------------------------------------------------
class DOSHeader(FirmwareStructure):

    definition = Struct(
        "_magic" / Const(b'MZ'),
        "lastsize" / Int16ul,
        "num_pages" / Int16ul,
        "num_relocs" / Int16ul,
        "header_size" / Int16ul,
        "min_alloc" / Int16ul,
        "max_alloc" / Int16ul,
        "ss" / Int16ul,
        "sp" / Int16ul,
        "checksum" / Int16ul,
        "ip" / Int16ul,
        "cs" / Int16ul,
        "relocpos" / Int16ul,
        "num_overlay" / Int16ul,
        "reserved1" / Int64ul,
        "oem_id" / Int16ul,
        "oem_info" / Int16ul,
        "reserved2" / Array(10, Int16ul),
        "e_lfanew" / Int32ul,
    )

# ----------------------------------------------------------------------------------------
class COFFHeader(FirmwareStructure):

    definition = Struct(
        "machine" / EnumAdapter(Int16ul, PEMachine),
        "num_sections" / Int16ul,
        "datetime" / Int32ul,
        "symbol_table" / Int32ul,
        "num_symbols" / Int32ul,
        "optional_header_size" / Int16ul,
        "characteristics" / Int16ul,
    )

# ----------------------------------------------------------------------------------------
class DataDirectory(FirmwareStructure):

    definition = Struct(
        "virtual_address" / Int32ul,
        "size" / Int32ul,
    )

    # Not usually reported, but if we did, we'd want to do it like this:
    reporting = [["virtual_address", "0x%x"], ["size"]]

# ----------------------------------------------------------------------------------------
class PESectionHeader(FirmwareStructure):

    label = "PE Section"

    definition = Struct(
        "name" / Select(PaddedString(8, 'ascii'), Bytes(8)),
        "physical_address" / Int32ul,
        "virtual_address" / Int32ul,
        "size_of_raw_data" / Int32ul,
        "raw_data_ptr" / Int32ul,
        "relocations_ptr" / Int32ul,
        "line_numbers_ptr" / Int32ul,
        "num_relocations" / Int16ul,
        "num_line_numbers" / Int16ul,
        "characteristics" / Int32ul,
    )

    reporting = [
        ["name", "%s", purple],
        ["virtual_address", "0x%x"], ["physical_address", "0x%x"], ["raw_data_ptr", "0x%x"],
        ["characteristics", "0x%x"], ["size_of_raw_data"],
        ["parsed"],
        # Supress these just to fit on a line nicely...
        ["line_numbers_ptr", None], ["num_line_numbers", None],
        ["relocations_ptr", None], ["num_relocations", None],
    ]

    def analyze(self) -> None:
        # May be set dynamically, e.g. by the SWID SBOM parser.  I should probably change
        # the design here so that every section can optionally have it's own raw data for
        # the section, and if it does, then that raw data gets reprocessed using the
        # standard Construct approach automatically.  That way the section interpretation
        # could be more principled, and not quite so hacky.
        self.parsed = None

# ----------------------------------------------------------------------------------------
class PE32OptionalHeader(FirmwareStructure):

    definition = Struct(
        "signature" / Int16ul,
        "major_linker_version" / Int8ul,
        "minor_linker_version" / Int8ul,
        "size_of_code" / Int32ul,
        "size_of_init_data" / Int32ul,
        "size_of_uninit_data" / Int32ul,
        "entry_point" / Int32ul,
        "code_base" / Int32ul,
        "data_base" / Int32ul,
        "image_base" / Int32ul,
        "section_alignment" / Int32ul,
        "file_alignment" / Int32ul,
        "major_os_version" / Int16ul,
        "minor_os_version" / Int16ul,
        "major_image_version" / Int16ul,
        "minor_image_version" / Int16ul,
        "major_subsystem_version" / Int16ul,
        "minor_subsystem_version" / Int16ul,
        "win32_version" / Int32ul,
        "size_of_image" / Int32ul,
        "size_of_headers" / Int32ul,
        "checksum" / Int32ul,
        "subsystem" / Int16ul,
        "dll_characteristics" / Int16ul,
        # These four are 64-bit values in the 64-bit header.
        "stack_reserve_size" / IfThenElse(this.signature == 523, Int64ul, Int32ul),
        "stack_commit_size" / IfThenElse(this.signature == 523, Int64ul, Int32ul),
        "heap_reserve_size" / IfThenElse(this.signature == 523, Int64ul, Int32ul),
        "heap_commit_size" / IfThenElse(this.signature == 523, Int64ul, Int32ul),

        "loader_flags" / Int32ul,
        "num_rvas_ignored" / Int32ul,
        "data_directories" / Array(16, Class(DataDirectory))
    )

# ----------------------------------------------------------------------------------------
class PESubsystem(UEnum):
    Unknown = 0x0
    Native = 0x01
    GUI = 0x02
    Console = 0x03
    POSIX = 0x07
    WindowsCE = 0x09
    EFIApplication = 0x0a
    EFIBootServiceDriver = 0xb
    EFIRuntimeDriver = 0xc
    EFIROM = 0x0d
    XBOX = 0x0e
    WindowsBootApplication = 0x10

# ----------------------------------------------------------------------------------------
class PEExecutable(HashedFirmwareStructure):
    """
    A Portable executable (PE) file.
    """

    label = "PE Executable"

    definition = Struct(
        "_start_offset" / Tell,
        "dos_header" / Class(DOSHeader),
        "_dos_stub_size" / Computed(lambda ctx: ctx.dos_header.e_lfanew - len(ctx.dos_header)),
        "dos_stub" / Bytes(this._dos_stub_size),
        # The PE header is inlined here largely because we don't want a separate PEHeader object.
        "_magic" / Const(b'PE'),
        "_zero" / Const(0, Int16ul),
        "coff_header" / Class(COFFHeader),
        "opt_pe_header" / Class(PE32OptionalHeader),
        "sections" / Array(lambda ctx: ctx.coff_header.num_sections, Class(PESectionHeader)),
        # Find the section with the largest end offset.  That's the file size (without any
        # "slack" data).  Unfortunately, the size of the slack cannot be detected from the
        # PE header, so we can't consume that here, and will have to rely on an externally
        # specified size.
        "file_size" / Computed(
            lambda ctx: max(s.raw_data_ptr + s.size_of_raw_data for s in ctx.sections)),
        # This commit could have been right after the PE magic, but then we'd have to deal
        # with more fields possibly being None.  Only having to deal with raw_data being
        # optional makes things much easier, and there's very little chance of the
        # optional header, sections, etc failing to parse unless there aren't enough bytes.
        "failure" / CommitMystery,
        # Seek back to where we read the MZ header.
        Seek(this._start_offset),
        # And read the entire executable again as a byte array.  This is required if we
        # want to be able to construct a pefile module object from the stream.
        # Doesn't need to be "SafeFixedLength", because HexDump will consume all bytes.
        "raw_data" / Select(
            FixedLength(this.file_size, GreedyBytes),
            # This case implies a malformed PE executable where the sections are bigger
            # than the actual file size. Sadly this occurs in at least one kind of ROM
            # update file, so I've decided to at least consume all available bytes in this
            # case, so that what was present will be accessible. :-(
            GreedyBytes),
        # FIXME: Maybe the right construct is that after confirming that there's a valid
        # PE object, create a subobject that "clarifies" the type of executable by
        # identifying EFI applications, Dell Updaters, etc.  Right now it's the otehr way
        # around.
    )

    reporting = [
        ["subsystem"], ["dos_header", None], ["dos_stub", None],
        ["coff_header", None], ["opt_pe_header", None], ["raw_data", None],
    ]

    sbom_fields = ["fshash"]

    @property
    def subsystem(self) -> PESubsystem:
        return PESubsystem(self.opt_pe_header.subsystem)

    def pefile(self, fast_load: bool = True) -> Optional[pefile.PE]:
        """Analyze the PE file with the PEFile Python library."""
        if isinstance(self.raw_data, bytes):
            return pefile.PE(data=self.raw_data, fast_load=fast_load)
        else:
            return None

    def analyze(self) -> None:
        # Search for .sbom sections, and report those specially.
        sbom_section = None
        for section in self.sections:
            if section.name == '.sbom':
                sbom_section = section
                break

        # Demonstrate that we can get a full pefile parse of the executable from the raw
        # data.  But remember that analyze() here will be called by all classes that are
        # derived from PEExecutable.
        if sbom_section is not None:
            #self.debug("Analyzing PE file!")
            pe = self.pefile()
            if pe is None:
                return
            #self.debug("PE=%r" % dir(pe))
            # Dump the sections as MysteryBytes (or HexDump if desired).
            #for sn in range(len(self.sections)):
            #    sdata = pe.sections[sn].get_data()
            #    self.sections[sn].mb = MysteryBytes.parse(sdata, 0)
            for sn in range(len(self.sections)):
                try:
                    # Confusingly, if you don't strip the NULL bytes they end up in the
                    # resulting string, buit are not visible. :-(
                    sname = pe.sections[sn].Name.rstrip(b'\x00').decode('ascii')
                    if sname == '.sbom':
                        sdata = pe.sections[sn].get_data()
                        sbom_section.parsed = USwid.parse(sdata, 0)
                except UnicodeError:
                    pass

    def instance_name(self) -> str:
        return self.fshash

# ----------------------------------------------------------------------------------------
class PEExecutableSlack(HashedFirmwareStructure):
    """
    A sized Portable executable (PE) file with slack.

    The remaining bytes will be interpreted as "slack" in executable.
    """

    label = "PE Executable (with slack)"

    definition = Struct(
        "_start_offset" / Tell,
        "dos_header" / Class(DOSHeader),
        "_dos_stub_size" / Computed(lambda ctx: ctx.dos_header.e_lfanew - len(ctx.dos_header)),
        "dos_stub" / Bytes(this._dos_stub_size),
        # The PE header is inlined here largely because we don't want a separate PEHeader object.
        "_magic" / Const(b'PE'),
        "_zero" / Const(0, Int16ul),
        "coff_header" / Class(COFFHeader),
        "opt_pe_header" / Class(PE32OptionalHeader),
        "sections" / Array(lambda ctx: ctx.coff_header.num_sections, Class(PESectionHeader)),
        # Find the section with the largest end offset.  That's the file size (without any
        # "slack" data).  Unfortunately, the size of the slack cannot be detected from the
        # PE header, so we can't consume that here, and will have to rely on an externally
        # specified size.
        "file_size" / Computed(
            lambda ctx: max(s.raw_data_ptr + s.size_of_raw_data for s in ctx.sections)),
        # Seek back to where we read the MZ header.
        Seek(this._start_offset),
        # And read the entire executable again as a byte array.  This is required if we
        # want to be able to construct a pefile module object from the stream.
        "raw_data" / Bytes(this.file_size),
        # FIXME: Maybe the right construct is that after confirming that there's a valid
        # PE object, create a subobject that "clarifies" the type of executable by
        # identifying EFI applications, Dell Updaters, etc.  Right now it's the otehr way
        # around.
        "slack" / Class(MysteryBytes),
    )

    reporting = [
        ["subsystem"], ["dos_header", None], ["dos_stub", None],
        ["coff_header", None], ["opt_pe_header", None], ["raw_data", None],
    ]

    sbom_fields = ["fshash"]

    @property
    def subsystem(self) -> PESubsystem:
        return PESubsystem(self.opt_pe_header.subsystem)

    def pefile(self, fast_load: bool = True) -> pefile.PE:
        """Analyze the PE file with the PEFile Python library."""
        return pefile.PE(data=self.raw_data, fast_load=fast_load)

    def analyze(self) -> None:
        # Search for .sbom sections, and report those specially.
        sbom_section = None
        for section in self.sections:
            if section.name == '.sbom':
                sbom_section = section
                break

        self.slack.label = "Slack Mystery Bytes"

        # Demonstrate that we can get a full pefile parse of the executable from the raw
        # data.  But remember that analyze() here will be called by all classes that are
        # derived from PEExecutable.
        if sbom_section is not None:
            #self.debug("Analyzing PE file!")
            pe = self.pefile()
            #self.debug("PE=%r" % dir(pe))
            # Dump the sections as MysteryBytes (or HexDump if desired).
            #for sn in range(len(self.sections)):
            #    sdata = pe.sections[sn].get_data()
            #    self.sections[sn].mb = MysteryBytes.parse(sdata, 0)
            for sn in range(len(self.sections)):
                try:
                    # Confusingly, if you don't strip the NULL bytes they end up in the
                    # resulting string, buit are not visible. :-(
                    sname = pe.sections[sn].Name.rstrip(b'\x00').decode('ascii')
                    if sname == '.sbom':
                        sdata = pe.sections[sn].get_data()
                        sbom_section.parsed = USwid.parse(sdata, 0)
                except UnicodeError:
                    pass

# ----------------------------------------------------------------------------------------
class EFIApplication(PEExecutable):
    """
    An EFI application (a kind of PE executable).
    """

    label = "EFI Application"

    # BUG! FIXME! Inheritance from PEExecutable is wasteful and results in duplicate
    # parsing which is not really desired.  We need to switch to a model with a Const
    # clause in the definition, so that this performs better.

    def validate(self) -> None:
        # Is there any reason that these types need their own FirmwareStructure?
        # Not yet, but there might be in the future...
        if self.subsystem not in [
                PESubsystem.EFIApplication,
                PESubsystem.EFIBootServiceDriver,
                PESubsystem.EFIRuntimeDriver]:
            self._valid = False

# ----------------------------------------------------------------------------------------
class TESectionHeader(FirmwareStructure):
    """
    A section header in a Terse executable.

    This structure is identical to the PE section header, but the algorithm for mapping TE
    sections into memory, and out of the file stream are slightly different, so this
    structure eventually got it's own implementation with a different analyze function in
    the TE executable class.
    """

    label = "TE Section"

    definition = Struct(
        "name" / Select(PaddedString(8, 'ascii'), Bytes(8)),
        "physical_address" / Int32ul,
        "virtual_address" / Int32ul,
        "size_of_raw_data" / Int32ul,
        "raw_data_ptr" / Int32ul,
        "relocations_ptr" / Int32ul,
        "line_numbers_ptr" / Int32ul,
        "num_relocations" / Int16ul,
        "num_line_numbers" / Int16ul,
        "characteristics" / Int32ul,
    )

    reporting = [
        ["name", "%s", purple],
        ["virtual_address", "0x%x"], ["physical_address", "0x%x"], ["raw_data_ptr", "0x%x"],
        ["characteristics", "0x%x"], ["size_of_raw_data"],
        ["data", None], ["padding"],
        # Supress these just to fit on a line nicely...
        ["line_numbers_ptr", None], ["num_line_numbers", None],
        ["relocations_ptr", None], ["num_relocations", None],
    ]

    def analyze(self) -> None:
        # May be set dynamically, e.g. by the SWID SBOM parser.  I should probably change
        # the design here so that every section can optionally have it's own raw data for
        # the section, and if it does, then that raw data gets reprocessed using the
        # standard Construct approach automatically.  That way the section interpretation
        # could be more principled, and not quite so hacky.
        self.data = b''
        self.padding = None

# ----------------------------------------------------------------------------------------
class TEPeiCorePadding(FirmwareStructure):
    "An unusual padding block found at the end of many TE executables (Dell?)"

    label = "TE PeiCore Padding"

    definition = Struct(
        "name" / PaddedString(16, 'utf16'),
        Check(this.name == 'PeiCore'),
        "u1" / Int16ul,
        "u2" / Int32ul,
        "u3" / Int16ul,
        "u4" / Int16ul,
        "u5" / Int32ul,
    )

    reporting = [
        ["name"], ["u1"], ["u2"], ["u3"], ["u4"], ["u5"],
    ]

# ----------------------------------------------------------------------------------------
@promote_exceptions
def pad_size(ctx: Context) -> int:
    # The TE section mapping is kind of complicated.  The documentation says in
    # section 17.2 (digital page 273), that TE executables without relocations can be
    # executed in place (XIP) using this calculation:
    #
    # For example, if the image (and thus the TE header) resides at memory location
    # LoadedImageAddress, then the actual entry for the driver is computed as follows:
    # EntryPoint = LoadedImageAddress + sizeof (EFI_TE_IMAGE_HEADER) +
    #   ((EFI_TE_IMAGE_HEADER *)LoadedImageAddress)–>AddressOfEntryPoint –
    #   ((EFI_TE_IMAGE_HEADER *)LoadedImageAddress)–>StrippedSize;
    #
    # This means that the image base is the offset of the magic.  But the addressing
    # is apparently relative to the end of the rewritten TE header, not the image
    # base.  Additionally, there were bytes that were removed from the PE header, and
    # that's recorded in stripped size.  Finally, we want to calculate our parsing
    # deltas relative to where the section data starts (after the section structures).

    # This is the size of the actual header (40 bytes) plus the bytes consumed the
    # section data structures (40 bytes each).
    header_size = 40 + (ctx.num_sections * 40)
    # This is the delta between where the section data starts in the stream and the
    # "address" of the section.  This value can be positive of negative.
    addr_delta = ctx.base_of_code - (header_size + ctx.stripped_size)
    assert isinstance(addr_delta, int)
    # And here's where things are still a little confusing.  There appears to be 40 bytes
    # of padding that's expected by default, and the address delta either adds or removes
    # bytes from that data structure.
    return 40 + addr_delta

# ----------------------------------------------------------------------------------------
class TEExecutable(HashedFirmwareStructure):
    """
    A Terse executable (TE).
    """

    label = "TE Executable"

    # EFI_TE_IMAGE_HEADER, section 15.1, digital page 267 (print page 241)
    # https://uefi.org/sites/default/files/resources/PI_Spec_1_6.pdf
    definition = Struct(
        "_magic" / Const(b'VZ'),
        "machine" / EnumAdapter(Int16ul, PEMachine),
        "num_sections" / Int8ul,
        "subsystem" / EnumAdapter(Int8ul, PESubsystem),
        "stripped_size" / Int16ul,
        "entry_point" / Int32ul,
        "base_of_code" / Int32ul,
        "image_base" / Int64ul,
        # Two instances of EFI_IMAGE_DATA_DIRECTORY, page 244
        "reloc_va" / Int32ul,
        "reloc_size" / Int32ul,
        "debug_va" / Int32ul,
        "debug_size" / Int32ul,
        "sections" / Array(this.num_sections, Class(TESectionHeader)),
        "pad_size" / Computed(pad_size),
        # Commit rather late after the 'VZ' magic for the same reason as PE executables.
        "failure" / CommitMystery,
        "padding" / Bytes(this.pad_size),
        "u1" / Int32ul,
        "_section_data" / GreedyBytes,
        #"section_data" / Class(MysteryBytes),
    )

    reporting = [
        ["subsystem"], ["num_sections"],
        ["image_base", "0x%x"], ["base_of_code", "0x%x"], ["pad_size"], ["u1", "0x%x"],
        ["padding", None],
        [],
        ["machine"],
        ["entry_point", "0x%x"], ["stripped_size"], ["debug_va", "0x%x"], ["debug_size"],
        ["reloc_va", "0x%x"], ["reloc_size"],
    ]

    # Not actually the correct hash because we're only reading the header right now!
    sbom_fields = ["fshash"]

    def analyze(self) -> None:
        # Complain if the padding is not full of zeros.
        if self.padding is not None and self.padding != b'\x00' * len(self.padding):
            self.warn("TE executable padding was not zero. %s" % (self.padding))
        # If we failed to correctly parse the section data, we can just skip the section
        # analysis, since the required fields were initialized in the TESection::analyze().
        if self._section_data is None:
            return
        # If we do have section data, copy the appropriate slices into the corresponding
        # section objects.
        for snum, section in enumerate(self.sections):
            # First extract the explicit data for the section.
            start = section.raw_data_ptr - self.base_of_code
            end = start + section.size_of_raw_data
            section.data = self._section_data[start:end]

            # Then extract the data between this section and the next section.  If there
            # is no next section, consume the remainder of the section data.
            if snum < len(self.sections) - 1:
                last_section = False
                next_section = self.sections[snum + 1]
                next_start = next_section.raw_data_ptr - self.base_of_code
            else:
                last_section = True
                next_start = len(self._section_data)

            # In almost all cases, there is no additional padding between sections.
            if next_start <= end:
                pass
            # If next start was less than end, the sections were in an unusual order, and
            # we should test for that condition since the algorithm above might need to be
            # more complicated.
            elif next_start < end:
                self.warn("TE section in unexpected order. (0x%x < 0x%x)" % (
                    next_start, end))
            # Otherwise we have some additional padding, which should be zeros or one of a
            # limited number of unusual values.
            else:
                pad_len = next_start - end
                pad_data = self._section_data[end:next_start]
                section.padding = TEPeiCorePadding.parse(pad_data, 0)
                if section.padding is None:
                    section.padding = MysteryBytes.parse(pad_data, 0)
                    if pad_data != b'\x00' * pad_len:
                        self.warn(f"TE section padding was not zero: {pad_data}")
                    if last_section and next_start != end:
                        self.warn(f"Last TE section has padding: {section.padding}")

            # This was a check that the algorithm was working.  In an Apple ROM, many of
            # the TE executables had debug sections, and all of those sections had the
            # string MTOC at offset 24-28.  Validating this was easier than validating
            # that the entry point pointed to the correct arbitrary code, which would have
            # been a better check.  There's open source code from Apple describing the
            # MTOC data structure.
            #if section.name == ".debug":
            #    self.mtoc = section.data[24:28]

    def instance_name(self) -> str:
        return self.fshash

# ----------------------------------------------------------------------------------------
class WrappedTEExecutable(FirmwareStructure):

    label = "Wrapped TE Executable"

    definition = Struct(
        "u1" / Int32ul,
        "exe" / Class(TEExecutable),
    )

    reporting = [["u1", "0x%x"]]

# ----------------------------------------------------------------------------------------
class ELFExecutable(FirmwareStructure):
    """
    A ELF Executable.
    """

    label = "ELF Executable"

    definition = Struct(
        "_magic" / Const(b'\x7fELF'),
        "iclass" / Int8ul,
        "idata" / Int8ul,
        "iversion" / Int8ul,
        "iosabi" / Int8ul,
        "iabiversion" / Int8ul,
        "ipad" / Bytes(8),
        "type" / Int16ul,
        "machine" / Int16ul,
        "version" / Int32ul,
        "entry" / Int16ul,
        "phoff" / Int16ul,
        "shoff" / Int16ul,
        "flags" / Int32ul,
        "ehsize" / Int16ul,
        "phentsize" / Int16ul,
        "phnum" / Int16ul,
        "shentsize" / Int16ul,
        "shentnum" / Int16ul,
        "shstrndx" / Int16ul,
    )

    reporting = [
        ["iclass"], ["idata"], ["iversion"], ["iosabi"], ["iabiversion"], ["ipad"],
        [], ["type"], ["machine"], ["version"], ["entry"], ["phoff"], ["shoff"], ["flags"],
        [], ["ehsize"], ["phentsize"], ["phnum"], ["shentsize"], ["shentnum"], ["shstrndx"],
    ]

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
