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
Lua Byte Code
"""

import os
import subprocess
from typing import Optional, Union
from tempfile import NamedTemporaryFile

from construct import Int8ul, Int32ul, Int64ul, Const, Bytes, Array, Select, this

from .base import FirmwareStructure, Struct, Class, PaddedString
from .mystery import MysteryBytes
from .pfs import TextFile

# ----------------------------------------------------------------------------------------
class LuaBytesConstant(FirmwareStructure):

    label = "Lua Bytes Constant"

    definition = Struct(
        "ctype" / Const(4, Int8ul),
        "len" / Int32ul,
        "_value" / Bytes(this.len),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    _value: bytes

    reporting = [["ctype"], ["len"], ["string"], ["binary"]]

    @property
    def binary(self) -> Optional[str]:
        try:
            self._value[:-1].decode('utf8')
            return None
        except UnicodeDecodeError:
            return self._value.hex()

    @property
    def string(self) -> Optional[str]:
        try:
            string = self._value[:-1].decode('utf8')
            return string
        except UnicodeDecodeError:
            return None

    def instance_name(self) -> str:
        if self.string is not None:
            return self.string
        return str(self.binary)

# ----------------------------------------------------------------------------------------
class LuaIntegerConstant(FirmwareStructure):

    label = "Lua Integer Constant"

    definition = Struct(
        "ctype" / Const(3, Int8ul),
        "value" / Int64ul,
    )

    reporting = [["ctype"], ["value", "0x%08x"]]

# ----------------------------------------------------------------------------------------
class LuaByteConstant(FirmwareStructure):

    label = "Lua Byte Constant"

    definition = Struct(
        "ctype" / Const(1, Int8ul),
        "value" / Int8ul,
    )

    reporting = [["ctype"], ["value", "0x%02x"]]

# ----------------------------------------------------------------------------------------
class LuaNilConstant(FirmwareStructure):

    label = "Lua Nil Constant"

    definition = Struct(
        "ctype" / Const(0, Int8ul),
    )

    reporting = [["ctype"]]

# ----------------------------------------------------------------------------------------
class LuaFunction(FirmwareStructure):
    pass

# ----------------------------------------------------------------------------------------
class LuaInstruction(FirmwareStructure):

    label = "Lua Instruction"

    definition = Struct(
        "insn" / Int32ul,
    )

    reporting = [["insn", "0x%08x"]]

# ----------------------------------------------------------------------------------------
class LuaScript(FirmwareStructure):

    label = "Lua Script"

    definition = Struct(
        # Lua global header
        "magic" / Const(b"\x1bLua", Bytes(4)),
        "version" / Int8ul,  # e.g. 0x52 (high nybble = major, low nybble = minor)
        "format" / Int8ul,  # 0 = official
        "endianness" / Int8ul,  # 1 = little
        # If we end up encountering otehr Lua formats
        "size_int" / Const(4, Int8ul),
        "size_size_t" / Const(8, Int8ul),
        "size_insn" / Const(4, Int8ul),
        "size_number" / Const(8, Int8ul),
        "integral" / Int8ul,  # integral = 1
        # End of global header

        "func_name_size" / Int32ul,  # size_int?
        "func_name" / PaddedString(this.func_name_size),
        "line_defined" / Int32ul,  # size_int?
        "last_line_defined" / Int32ul,  # size_int?
        "num_upvalues" / Int8ul,
        "num_params" / Int8ul,
        "is_vararg" / Int8ul,
        "max_stacksize" / Int8ul,

        "num_insns" / Int32ul,
        "insns" / Array(this.num_insns, Class(LuaInstruction)),  # size_insn?
        "num_consts" / Int32ul,
        "consts" / Array(this.num_consts, Select(
            Class(LuaBytesConstant), Class(LuaIntegerConstant),
            Class(LuaByteConstant), Class(LuaNilConstant),
        )),
        "num_funcs" / Const(0, Int32ul),
        #"funcs" / Array(this.num_funcs, Class(LuaFunction)),

        "num_src_line_pos" / Int32ul,
        "num_locals" / Int32ul,
        "num_upvalues2" / Int32ul,
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["magic", "%s"], ["version", "0x%02x"], ["format"], ["endianness"], ["size_int"],
        ["size_size_t"], ["size_insn"], ["size_number"], ["integral"],
        [], ["func_name_size"], ["func_name"], ["line_defined"], ["last_line_defined"],
        ["num_upvalues"], ["num_params"], ["is_vararg"], ["max_stacksize"],
        [], ["num_insns"], ["num_consts"], ["num_funcs"], ["num_src_line_pos"],
        ["num_locals"], ["num_upvalues2"],
    ]

    # This method currently needs to be invoked by the analyze() method of a derived class
    # or by the analyze() method of a containing firmware structure.  It is not enabled by
    # default due to performance concerns, and complexities surrounding the distribution
    # of luadec.
    def decompile(self, code: Optional[bytes] = None) -> Optional[Union[TextFile, str]]:
        if code is None:
            code = self._memory[self._data_offset:self._data_offset + self._parsed_length]

        tmp = NamedTemporaryFile(prefix="lua", suffix=".lua", delete=False)
        tmp.write(code)
        tmp.flush()

        try:
            decomp = subprocess.run(
                ["luadec", tmp.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            tmp.close()
            if decomp.returncode != 0:
                self.error("LUA decompilation failed!")
                self.error("stdout=%r" % decomp.stdout)
                self.error("stderr=%r" % decomp.stderr)
                return "(FAILED, %d lines of stdout and %d lines of stderr)" % (
                    len(decomp.stdout), len(decomp.stderr))
            self.decompilation = TextFile.parse(decomp.stdout, 0)
            os.remove(tmp.name)
            return self.decompilation
        except FileNotFoundError:
            tmp.close()

        return None

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
