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
Test our extensions to construct.  This should probably use the unittest module.
"""

import struct
import json
from enum import Flag
from uuid import UUID
from typing import Optional

from construct import (
    Array, Bytes, Computed, Const, Int8ul, Int32ul, Int16ul, Float32l,
    PaddedString, this)

from .base import FirmwareStructure, Class, Struct, SoftCheck, EnumAdapter
from .utils import cyan

# ----------------------------------------------------------------------------------------
class FakeCStruct(FirmwareStructure):
    """
    Completely standard ctypes structure behavior.
    """
    definition = Struct(
        "a" / Int8ul,
        "b" / Int8ul,
        "c" / Int16ul,
        "d" / Int32ul,
        "_check" / SoftCheck(this.d == 54, lambda ctx: "invalid value d = %d" % (ctx.d))
    )

    reporting = [
        ["a", "%d"],
        ["b", "0x%04x"],
        ["c", lambda self: self.report_c()],
        ["d", "%d", cyan],
    ]

    def validate(self) -> None:
        if self.a == 51:
            self.validation_error("invalid value a = %d" % (self.a))

    def report_c(self) -> str:
        return "SPECIAL(%d)" % self.c

# ----------------------------------------------------------------------------------------
class FakeSubStruct(FirmwareStructure):
    """
    A full (but also fairly minimal substruct using the FirmwareStructure infrastructure.
    """

    label = "Fake Sub-structure"

    # Note that construct doesn't use C alignments by default unlike ctypes.Structure
    # which required setting _pack_ to 1 here.
    definition = Struct(
        "a" / Int8ul,
        "b" / Int16ul,
        "c" / Int8ul,
        "d" / Int32ul,
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    a: int
    b: int
    c: int
    d: int

    @property
    def summation(self) -> int:
        return self.a + self.b + self.c + self.d

# ----------------------------------------------------------------------------------------
# Unfortunately, FlagsEnum must in the outer scope, because it doesn't work when it's
# inside the fake class definition.
class MyFlags(Flag):
    BIG = 0x00000001
    SPECIAL = 0x00002000
    DISABLED = 0x04000000
    EXTRA = 0x04000040

# ----------------------------------------------------------------------------------------
class Fake(FirmwareStructure):
    """
    A feature demonstration of the FirmwareStructure class.
    """

    label = "Fake Structure"
    definition = Struct(
        "_magic" / Const(b'MAGI'),
        "_guid" / Bytes(16),
        "flags" / EnumAdapter(Int32ul, MyFlags),
        "cstruct" / Class(FakeCStruct),
        "fcount" / Int16ul,
        "_plen" / Int16ul,
        "substructs" / Array(this.fcount, Class(FakeSubStruct)),
        "floats" / Array(this.fcount, Float32l),
        "path" / PaddedString(this._plen, "utf-8"),
        "_pathcheck" / SoftCheck(lambda ctx: ctx.path.startswith('/'), "path was not absolute"),
        "skipme" / Computed(34),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    flags: MyFlags

    reporting = [
        ["guid"],
        ["flags", lambda self: "0x%x (%s)" % (self.flags.value, self.flags)],
        # Should this be used to determine which fields end up in the JSON dictionary?
        # Because despite being excluded here, nothing excluded "skipme" from the JSON.
        ["skipme", None],
        [],  # Mark where we passed into automatic reporting, but it's NOT required.
    ]

    @property
    def guid(self) -> UUID:
        return UUID(bytes_le=self._guid)

    @guid.setter
    def guid(self, value: UUID) -> None:
        self._guid = value.bytes_le

    # @property
    # def flags(self) -> MyFlags:
    #     return MyFlags(self._flags)
    #
    # @flags.setter
    # def flags(self, value: MyFlags) -> None:
    #     self._flags = value.value

    def validate(self) -> None:
        # Floats should all be >=0.  Demonstrate how offsets can be calculated if it's
        # worth the trouble to report that more accurately.
        o = self._data_offset + len(self)
        for i in range(len(self.floats)):
            f = self.floats[i]
            if f < 0:
                self.validation_error("float[%d] %f < 0" % (i, f), offset=o + (i * 4))
        # A more typical validation error, that defaults to the object's offset.
        if len(self.path) < 5:
            self.validation_error("path is too short '%s'" % self.path)

# ----------------------------------------------------------------------------------------
def fake_test() -> None:
    tguid = UUID("eea2f5d2-c835-4e8c-ae00-c1605a53bb43")
    # Manually build a buffer with the correct structure, so we can parse it.
    buf = struct.pack("<4s16sIBBHIHHBHBIBHBIff6s", b'MAGI', tguid.bytes_le,
                      0x04002001, 51, 52, 53, 54, 2, 6,
                      61, 62, 63, 64, 71, 72, 73, 74, 3.5, -2.5, b'./etc\x00')
    emit = print  # Print is generally banned from use in CERT UEFI parser.
    emit("Buf = %r" % buf)
    fake: Optional[Fake] = Fake.parse(buf, 0)
    if fake is None:
        emit("Buf was not a valid fake object.")
    else:
        fake.report()
        emit(json.dumps(fake.to_dict(json=True)))
        #emit(fake.to_dict())

        # Conduct a modification & build test...
        if True:
            check = bytearray(buf)
            fake.cstruct.c = 88
            check[26] = 88
            fake.flags |= MyFlags.EXTRA
            check[20] = 0x41
            check = bytearray(check)

            fake.report()
            new_bytes = fake.generate_from_memory()
            emit("Built: %r" % (new_bytes))
            emit("Check: %r" % (check))
            if new_bytes == check:
                emit("They match!")
            else:
                emit("They don't match!")

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
