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
Support for flattened devicetrees.

https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html
"""
import datetime
import gzip
import zlib
from typing import Optional, Union, Any

from construct import (
    Int16ub, Int32ub, Int64ub, Const, Bytes, Computed, GreedyBytes, GreedyRange,
    Aligned, Select, Tell, Adapter, this)

from .base import (
    FirmwareStructure, Struct, Class, FixedLength, CString, LazyBind,
    PaddedString, Context, PathType)
from .mystery import MysteryBytes

# ----------------------------------------------------------------------------------------
def lazy_tree_nodes(ctx: Context) -> GreedyRange:
    return GreedyRange(Select(Class(BeginNode), Class(Property), Class(Nop)))

# ----------------------------------------------------------------------------------------
class FlattenedDevicetreeHeader(FirmwareStructure):
    """
    The header for a flattened devicetree.

    https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html#header
    """

    label = "Flattened Devicetree Header"

    definition = Struct(
        "magic" / Const(0xd00dfeed, Int32ub),
        "totalsize" / Int32ub,
        "off_dt_struct" / Int32ub,
        "off_dt_strings" / Int32ub,
        "off_mem_rsvmap" / Int32ub,
        "version" / Int32ub,
        "last_comp_version" / Int32ub,
        "boot_cpuid_phys" / Int32ub,
        "size_dt_strings" / Int32ub,
        "size_dt_struct" / Int32ub,
        "alignment" / Bytes(this.off_mem_rsvmap - 40),
    )

    reporting = [
        ["magic"], ["totalsize"], ["off_dt_struct"], ["off_dt_strings"],
        ["off_mem_rsvmap"], ["version"], ["last_comp_version"], ["boot_cpuid_phys"],
        ["size_dt_strings"], ["size_dt_struct"],
    ]

# ----------------------------------------------------------------------------------------
class ReserveEntry(FirmwareStructure):
    """
    A reserved memory entry.
    """

    label = "Reserve Entry"

    definition = Struct(
        "address" / Int64ub,
        "size" / Int64ub,
    )

    reporting = [["address", "0x%016x"], ["size", "0x%016x"]]

# ----------------------------------------------------------------------------------------
class MemoryReservationBlock(FirmwareStructure):
    """
    A flattened devicetree memory reservation block.
    """

    label = "Memory Reservation Block"

    definition = Struct(
        # Actually terminated by an entry with address=0, size=0.
        "entries" / GreedyRange(Class(ReserveEntry)),
        "alignment" / Class(MysteryBytes),
    )

    reporting = [["entries"], ["alignment"]]

# ----------------------------------------------------------------------------------------
class EndNode(FirmwareStructure):
    """
    An end node.
    """

    label = "End Node"

    definition = Struct(
        "token_type" / Aligned(4, Const(2, Int32ub)),
    )

    reporting = [["token_type"]]

    def update_name(self, strings: dict[int, str]) -> None:
        pass

# ----------------------------------------------------------------------------------------
class Image(FirmwareStructure):
    """
    A binary image embedded in a device tree.
    """

    label = "Binary Image"

    definition = Struct(
        "_data" / GreedyBytes,
    )

PropertyType = Union['FlattenedDevicetree', Image, list[str], bytes, str, int]

# ----------------------------------------------------------------------------------------
class Property(FirmwareStructure):
    """
    A property.
    """

    label = "Property"

    definition = Struct(
        "token_type" / Aligned(4, Const(3, Int32ub)),
        "len" / Int32ub,
        "name_offset" / Int32ub,
        "_value" / Aligned(4, Bytes(this.len)),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    _value: bytes
    # It's expected that I had to type these dynamically created values though.
    name: Optional[str]
    value: PropertyType

    reporting = [
        ["token_type"], ["len"], ["name_offset"], ["value"],
    ]

    def guess_value_type(self) -> PropertyType:
        # Nested device trees
        if self._value[0:4] == b'\xd0\x0d\xfe\xed':
            fdt = self.subparse(FlattenedDevicetree, "_value")
            if fdt is not None:
                return fdt

        # Large binaries, like kernel images.
        if len(self._value) > 1024:
            image = self.subparse(Image, "_value")
            if image is not None:
                return image

        # Empty strings
        if len(self._value) == 0:
            return ''

        # Null terminated strings
        if self._value[-1] == 0:
            try:
                value = self._value[:-1].decode()
                if value.isprintable():
                    return str(value)
            except UnicodeDecodeError:
                pass

            valid = True
            strlist = []
            last_pos = 0
            while valid and last_pos < len(self._value):
                zero_pos = self._value.find(0, last_pos)
                try:
                    value = self._value[last_pos:zero_pos].decode()
                    if value.isprintable() and (len(value) > 2 or value == '/'):
                        strlist.append(value)
                        last_pos = zero_pos + 1
                    else:
                        valid = False
                except UnicodeDecodeError:
                    valid = False
            if valid:
                return strlist

        if len(self._value) == 4 and self.name == 'timestamp':
            # We're fighting with mypy a little here on parsing these integers... :-(
            ts = self.subparse(Int32ub, "_value")
            assert ts is not None
            dt = datetime.datetime.utcfromtimestamp(ts)
            return dt.isoformat()

        if len(self._value) == 8:
            val = self.subparse(Int64ub, "_value")
            assert val is not None
            return int(val)
        if len(self._value) == 4:
            val = self.subparse(Int32ub, "_value")
            assert val is not None
            return int(val)
        if len(self._value) == 2:
            val = self.subparse(Int16ub, "_value")
            assert val is not None
            return int(val)

        return self._value

    def update_name(self, strings: dict[int, str]) -> None:
        self.name = None
        if self.name_offset in strings:
            self.name = strings[self.name_offset]
        else:
            # Unfortunately, name can also point into the middle of other strings.
            for offset in strings:
                if (self.name_offset > offset
                        and self.name_offset < offset + len(strings[offset])):
                    self.name = strings[offset][self.name_offset - offset:]
                    break

        self.value = self.guess_value_type()

    def analyze(self) -> None:
        self.name = None

    def instance_name(self) -> str:
        return str(self.name)

# ----------------------------------------------------------------------------------------
class Nop(FirmwareStructure):
    """
    A no operation tree node.
    """

    label = "Nop"

    definition = Struct(
        "token_type" / Aligned(4, Const(4, Int32ub)),
    )

    reporting = [["token_type"]]

    def update_name(self, strings: dict[int, str]) -> None:
        pass

# ----------------------------------------------------------------------------------------
class End(FirmwareStructure):
    """
    Marks the end of flattened devictree.
    """

    label = "End"

    definition = Struct(
        "token_type" / Aligned(4, Const(9, Int32ub)),
    )

    reporting = [["token_type"]]

# ----------------------------------------------------------------------------------------
class BeginNode(FirmwareStructure):
    """
    A begin node.
    """

    label = "Begin Node"

    definition = Struct(
        "token_type" / Const(1, Int32ub),
        "name" / Aligned(4, CString()),
        "tree" / LazyBind(lazy_tree_nodes),
        "end" / Class(EndNode),
    )

    decompressed: Optional[FirmwareStructure]

    reporting = [
        ["token_type"], ["name"], ["tree"], ["end"], ["decompressed"],
    ]

    def analyze(self) -> None:
        self.decompressed = None

    def update_name(self, strings: dict[int, str]) -> None:
        for node in self.tree:
            node.update_name(strings)
        self.decompress()

    def decompress(self) -> None:
        # Some nodes have compressed data.  In the samples I saw, the compressed data was
        # in a property named "data", and the algorithm was identified by a property named
        # "compression".
        compression = None
        data = None
        for node in self.tree:
            if isinstance(node, Property):
                if node.name == "compression":
                    compression = node
                if node.name == "data":
                    data = node

        if compression is not None and data is not None:
            # Sigh.  GZip compressed RAM disks are identified as compression "none".
            # Presumably because the ramdisk was compressed before being added to the
            # device tree?  Instead will just try gzip on everything. :-(
            cval = compression.value
            try:
                if cval not in ['none', 'gzip']:
                    self.warn(f"Unrecognized compression algorithm '{cval!r}'")

                decompressed = gzip.decompress(data._value)
                interpretation = CPIOArchive.parse(decompressed, 0)
                if interpretation is not None:
                    self.decompressed = interpretation
                else:
                    self.decompressed = Image.parse(decompressed, 0)
            except (gzip.BadGzipFile, zlib.error):
                pass

    def instance_name(self) -> str:
        return str(self.name)

# ----------------------------------------------------------------------------------------
class ASCIIHexNumAdapter(Adapter):

    def __init__(self, length: int):
        self.str_length = length
        super().__init__(PaddedString(length))

    def _decode(self, obj: str, context: Context, path: PathType) -> int:
        return int(obj, 16)

    def _encode(self, obj: int, context: Context, path: PathType) -> Any:
        return f"%{self.str_length}x" % obj

# ----------------------------------------------------------------------------------------
class CPIOFile(FirmwareStructure):
    """
    A new format CPIO archive file.
    """

    label = "CPIO Archive File"

    definition = Struct(
        "magic" / Const(b'\x30\x37\x30\x37\x30\x31', Bytes(6)),
        "ino" / ASCIIHexNumAdapter(8),
        "mode" / ASCIIHexNumAdapter(8),
        "uid" / ASCIIHexNumAdapter(8),
        "gid" / ASCIIHexNumAdapter(8),
        "nlink" / ASCIIHexNumAdapter(8),
        "mtime" / ASCIIHexNumAdapter(8),
        "filesize" / ASCIIHexNumAdapter(8),
        "devmajor" / ASCIIHexNumAdapter(8),
        "devminor" / ASCIIHexNumAdapter(8),
        "rdevmajor" / ASCIIHexNumAdapter(8),
        "rdevminor" / ASCIIHexNumAdapter(8),
        "namesize" / ASCIIHexNumAdapter(8),
        "check" / ASCIIHexNumAdapter(8),
        "filename" / PaddedString(this.namesize),
        # Align to 4 bytes
        "_tell1" / Tell,
        "pad1" / Bytes(lambda ctx: 4 - (ctx._tell1) % 4 if ctx._tell1 % 4 else 0),
        "_filedata" / Bytes(this.filesize),
        # Align to 4 bytes
        "_tell2" / Tell,
        "pad2" / Bytes(lambda ctx: 4 - (ctx._tell2) % 4 if ctx._tell2 % 4 else 0),
    )

    reporting = [
        ["magic"], ["ino"], ["mode", "0o%o"], ["uid"], ["gid"], ["nlink"], ["filesize"],
        ["devmajor"], ["devminor"], ["rdevmajor"], ["rdevminor"], ["namesize"],
        ["check"], ["filename"], ["pad1"], ["pad2"],
    ]

    # There should probably be an "interpretation" of each file as well.

    def instance_name(self) -> str:
        return str(self.filename)

# ----------------------------------------------------------------------------------------
class CPIOArchive(FirmwareStructure):
    """
    A newformat CPIO archive.

    https://manpages.ubuntu.com/manpages/focal/man5/cpio.5.html
    """

    label = "CPIO Archive"

    definition = Struct(
        "files" / GreedyRange(Class(CPIOFile)),
        "padding" / GreedyRange(Const(b'\x00')),
    )

# ----------------------------------------------------------------------------------------
class StructureBlock(FirmwareStructure):
    """
    A flattened devicetree structure block.
    """

    label = "Structure Block"

    definition = Struct(
        "tree" / LazyBind(lazy_tree_nodes),
        "end" / Class(End),
    )

    reporting = [["tree"], ["end"]]

# ----------------------------------------------------------------------------------------
class String(FirmwareStructure):
    """
    A string in the strings block.
    """

    label = "String"

    definition = Struct(
        "_tell" / Tell,
        "offset" / Computed(lambda ctx: ctx._tell - ctx._._strings_block_start),
        "string" / CString(),
    )

    reporting = [["offset"], ["string"]]

    def instance_name(self) -> str:
        return str(self.string)

# ----------------------------------------------------------------------------------------
class StringsBlock(FirmwareStructure):
    """
    A flattened devicetree strings block.
    """

    label = "Strings Block"

    definition = Struct(
        "_strings_block_start" / Tell,
        "strings" / GreedyRange(Class(String))
    )

    reporting = [["strings"]]

# ----------------------------------------------------------------------------------------
class FlattenedDevicetree(FirmwareStructure):
    """
    A flattened devicetree binary encoding.

    Also possibly a Flat Image Tree (FIT)
    https://docs.u-boot.org/en/stable/usage/fit/index.html
    """

    label = "Flattened Devicetree"

    definition = Struct(
        "header" / Class(FlattenedDevicetreeHeader),
        "mem_rsvmap" / FixedLength(
            lambda ctx: ctx.header.off_dt_struct - ctx.header.off_mem_rsvmap,
            Class(MemoryReservationBlock)),
        "structure_block" / FixedLength(
            lambda ctx: ctx.header.size_dt_struct, Class(StructureBlock)),
        "strings_block" / FixedLength(
            lambda ctx: ctx.header.size_dt_strings, Class(StringsBlock)),
    )

    reporting = [
        ["header"], ["mem_rsvmap"], ["structure_block"], ["strings_block"],
    ]

    def analyze(self) -> None:
        strings_dict = {}
        for string in self.strings_block.strings:
            strings_dict[string.offset] = string.string
        for node in self.structure_block.tree:
            node.update_name(strings_dict)

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
