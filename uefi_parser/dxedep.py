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
Display and format DXE dependency structures.

DXE, PEI and SMM DEPEX sections
See: efi-driver-execution-interface-dxe-cis-specification.pdf, pages 140-154.
See: https://uefi.org/sites/default/files/resources/PI_Spec_1_7_A_final_May1.pdf
Section 5.7, pages 1-70 through 1-80.
"""

import textwrap

from construct import GreedyRange, Int8ul, If

from .base import (
    FirmwareStructure, HashedFirmwareStructure, Class, Struct, EnumAdapter, UUID16)
from .uenum import UEnum
from .utils import yellow
from .guiddb import GUID_DATABASE as GDB
from .mystery import MysteryBytes

# ----------------------------------------------------------------------------------------
class DXEOpcode(UEnum):
    BEFORE = 0
    AFTER = 1
    PUSH = 2
    AND = 3
    OR = 4
    NOT = 5
    TRUE = 6
    FALSE = 7
    END = 8
    SOR = 9

# ----------------------------------------------------------------------------------------
class DXEOp(FirmwareStructure):

    definition = Struct(
        "opcode" / EnumAdapter(Int8ul, DXEOpcode),
        "guid" / If(lambda ctx: ctx.opcode.value < 3, UUID16),
    )

    # Standard reporting in the "usual" format.
    reporting = [
        ["opcode"], ["guid"],
    ]

    def __str__(self) -> str:
        if self.guid is not None:
            return "%s %s" % (self.opcode.name, self.guid)
        else:
            return "%s" % self.opcode.name

    # Perhaps the JSON should include the guid NAME as well?

# ----------------------------------------------------------------------------------------
class DXEDependency(HashedFirmwareStructure):

    definition = Struct(
        "opcodes" / GreedyRange(Class(DXEOp)),
        "unexpected" / Class(MysteryBytes),
    )

    def sbom(self) -> dict[str, str]:
        return {"dependencies": self.exprstr, "fshash": self.fshash}

    @property
    def exprstr(self) -> str:
        return self.as_expression('both')

    def as_expression(self, display_mode: str = 'name') -> str:
        stack = []
        result = ""
        if len(self.unexpected.data) > 0:
            return "INVALID"
        for op in self.opcodes:
            opname = op.opcode.name
            if op.opcode == DXEOpcode.PUSH:
                display = GDB.display_name(op.guid, display_mode)
                stack.append(display)
            elif op.opcode in [DXEOpcode.BEFORE, DXEOpcode.AFTER]:
                display = GDB.display_name(op.guid, display_mode)
                stack.append("%s %s" % (yellow(opname), display))
            elif op.opcode in [DXEOpcode.AND, DXEOpcode.OR]:
                t1 = stack.pop()
                t2 = stack.pop()
                nt = "(%s %s %s)" % (t1, opname, t2)
                stack.append(nt)
            elif op.opcode in [DXEOpcode.TRUE, DXEOpcode.FALSE]:
                stack.append(opname)
            elif op.opcode == DXEOpcode.NOT:
                term = stack.pop()
                stack.append("%s %s" % (opname, term))
            elif op.opcode == DXEOpcode.END:
                result = stack.pop()
            # Deprecated, but still shows up in some old ROMs (HP Spectre)
            elif op.opcode == DXEOpcode.SOR:
                stack.append(opname)
            else:  # Unknown opcodes aren't possible since using an enum.
                raise ValueError("Invalid DXE opcode")
        return result

    def as_commands(self, display_mode: str = 'name') -> str:
        lines = []
        for op in self.opcodes:
            lines.append(str(op))
        return '\n'.join(lines)

    def report_as_expression(self, dxe_offset: int, indentation: str,
                             display_mode: str = 'name') -> str:
        result = self.as_expression(display_mode)

        prefix1 = yellow("0x%08x" % dxe_offset) + indentation
        prefix2 = yellow("0x%08x>" % dxe_offset) + indentation + " "

        lines = textwrap.wrap(str(result), width=180, initial_indent=prefix1,
                              subsequent_indent=prefix2)
        return '\n'.join(lines)

    def instance_name(self) -> str:
        return self.fshash

    #def report(self, context):
    #    # DXEDep reporting temporarily disabled!
    #    pass

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
