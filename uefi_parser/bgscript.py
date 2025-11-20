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
Intel BIOS Guard Script
"""

from typing import Union

from construct import Select, Computed, Const, Int8ul, Int16ul, Int32ul, Peek, GreedyRange

from .base import FirmwareStructure, Class, Opt, Struct
from .mystery import MysteryBytes

# ----------------------------------------------------------------------------------------
opcodes = {
    0x00: ('nop',         None,   None,  None),
    0x01: ('begin',       None,   None,  None),
    0x10: ('write',       'f%X',  'b%X', 'r%X'),
    0x11: ('write',       'f%X',  'b%X', '0x%X'),
    0x12: ('read',        'b%X',  'f%X', 'r%X'),
    0x13: ('read',        'b%X',  'f%X', '0x%X'),
    0x14: ('eraseblk',    'f%X',  None,  None),
    0x15: ('erase64kblk', 'f%X',  None,  None),
    0x20: ('eccmdwr',     'r%X',  None,  None),
    0x21: ('eccmdwr',     None,   None,  '0x%X'),
    0x22: ('ecstsrd',     'r%X',  None,  None),
    0x23: ('ecdatawr',    'r%X',  None,  None),
    0x24: ('ecdatawr',    None,   None,  '0x%X'),
    0x25: ('ecdatard',    'r%X',  None,  None),
    0x30: ('add',         'r%X',  'r%X', None),
    0x31: ('add',         'r%X',  None,  '0x%X'),
    0x32: ('add',         'b%X',  'r%X', None),
    0x33: ('add',         'b%X',  None,  '0x%X'),
    0x34: ('add',         'f%X',  'r%X', None),
    0x35: ('add',         'f%X',  None,  '0x%X'),
    0x36: ('sub',         'r%X',  'r%X', None),
    0x37: ('sub',         'r%X',  None,  '0x%X'),
    0x38: ('sub',         'b%X',  'r%X', None),
    0x39: ('sub',         'b%X',  None,  '0x%X'),
    0x3a: ('sub',         'f%X',  'r%X', None),
    0x3b: ('sub',         'f%X',  None,  '0x%X'),
    0x40: ('and',         'r%X',  'r%X', None),
    0x41: ('and',         'r%X',  None,  '0x%X'),
    0x42: ('or',          'r%X',  'r%X', None),
    0x43: ('or',          'r%X',  None,  '0x%X'),
    0x44: ('shiftr',      'r%X',  None,  '0x%X'),
    0x45: ('shiftl',      'r%X',  None,  '0x%X'),
    0x46: ('rotater',     'r%X',  None,  '0x%X'),
    0x47: ('rotatel',     'r%X',  None,  '0x%X'),
    0x50: ('set',         'r%X',  'r%X', None),
    0x51: ('set',         'r%X',  None,  '0x%X'),
    0x52: ('set',         'b%X',  'r%X', None),
    0x53: ('set',         'b%X',  None,  '0x%X'),
    0x54: ('set',         'f%X',  'r%X', None),
    0x55: ('set',         'f%X',  None,  '0x%X'),
    0x60: ('loadbyte',    'r%X',  'b%X', None),
    0x61: ('loadword',    'r%X',  'b%X', None),
    0x62: ('loaddword',   'r%X',  'b%X', None),
    0x63: ('storebyte',   'b%X',  'r%X', None),
    0x64: ('storeword',   'b%X',  'r%X', None),
    0x65: ('storedword',  'b%X',  'r%X', None),
    0x70: ('compare',     'r%X',  'r%X', None),
    0x71: ('compare',     'r%X',  None,  '0x%X'),
    0x72: ('compare',     'b%X',  'r%X', None),
    0x73: ('compare',     'b%X',  None,  '0x%X'),
    0x74: ('compare',     'f%X',  'r%X', None),
    0x75: ('compare',     'f%X',  None,  '0x%X'),
    0x76: ('compare',     'b%X',  'b%X', 'r%X'),
    0x77: ('compare',     'b%X',  'b%X', '0x%X'),
    0x80: ('copy',        'b%X',  'b%X', 'r%X'),
    0x81: ('copy',        'b%X',  'b%X', '0x%X'),
    0x90: ('jmp',         None,   None,  '0x%X'),
    0x91: ('je',          None,   None,  '0x%X'),
    0x92: ('jne',         None,   None,  '0x%X'),
    0x93: ('jg',          None,   None,  '0x%X'),
    0x94: ('jge',         None,   None,  '0x%X'),
    0x95: ('jl',          None,   None,  '0x%X'),
    0x96: ('jle',         None,   None,  '0x%X'),
    0x97: ('jmp',         'r%X',  None,  None),
    0xa0: ('log',         '0x%x', 'r%X', None),
    0xa1: ('log',         '0x%X', None,  '0x%X'),
    0xb0: ('rdsts',       'r%X',  None,  None),
    0xb1: ('rdkeyslot',   'r%X',  None,  None),
    0xb2: ('rdrand',      'r%X',  None,  None),
    0xc0: ('stall',       None,   None,  '0x%X'),
    0xc1: ('rdts',        'r%X',  None,  None),
    0xc2: ('setts',       None,   None,  None),
    0xc3: ('clearts',     None,   None,  None),
    0xff: ('end',         None,   None,  None),
}

# ----------------------------------------------------------------------------------------
standard_script = (
    #b'\x01\x00\x00\x00\x00\x00\x00\x00'  # begin
    #b'\x51\x00\x00\x00\x??\x??\x??\x??'  # set         r0 0x????????
    #b'\x51\x00\x01\x00\x00\x10\x00\x00'  # set         r1 0x1000
    #b'\x51\x00\x02\x00\x??\x??\x??\x??'  # set         r2 0x????????
    b'\x51\x00\x03\x00\x00\x00\x00\x00'  # set         r3 0x0
    b'\x55\x00\x00\x00\x00\x00\x00\x00'  # set         f0 0x0
    b'\x53\x00\x00\x00\x00\x00\x00\x00'  # set         b0 0x0
    b'\x51\x00\x04\x00\x00\x00\x00\x00'  # set         r4 0x0
    b'\x51\x00\x05\x00\x00\x00\x00\x00'  # set         r5 0x0
    b'\x51\x00\x06\x00\x00\x00\x00\x00'  # set         r6 0x0
    b'\x51\x00\x07\x00\x00\x00\x00\x00'  # set         r7 0x0
    b'\x51\x00\x08\x00\x03\x00\x00\x00'  # set         r8 0x3
    b'\x51\x00\x09\x00\x00\x00\x00\x00'  # set         r9 0x0
    b'\x55\x00\x00\x00\x16\x00\x00\x00'  # set         f0 0x16
    b'\x53\x00\x01\x00\x00\x00\x00\x00'  # set         b1 0x0
    b'\x13\x00\x01\x00\x01\x00\x00\x00'  # read        b1 f0 0x1
    b'\x60\x00\x03\x01\x00\x00\x00\x00'  # loadbyte    r3 b1
    b'\x45\x00\x03\x00\x04\x00\x00\x00'  # shiftl      r3 0x4
    b'\x31\x00\x03\x00\x04\x00\x00\x00'  # add         r3 0x4
    b'\x54\x00\x00\x03\x00\x00\x00\x00'  # set         f0 r3
    b'\x53\x00\x01\x00\x00\x00\x00\x00'  # set         b1 0x0
    b'\x13\x00\x01\x00\x02\x00\x00\x00'  # read        b1 f0 0x2
    b'\x61\x00\x03\x01\x00\x00\x00\x00'  # loadword    r3 b1
    b'\x41\x00\x03\x00\xff\x7f\x00\x00'  # and         r3 0x7FFF
    b'\x45\x00\x03\x00\x0c\x00\x00\x00'  # shiftl      r3 0xC
    b'\x30\x00\x03\x00\x00\x00\x00\x00'  # add         r3 r0
    b'\x54\x00\x00\x03\x00\x00\x00\x00'  # set         f0 r3
    b'\x12\x00\x01\x00\x01\x00\x00\x00'  # read        b1 f0 r1
    b'\xb0\x00\x09\x00\x00\x00\x00\x00'  # rdsts       r9
    b'\x71\x00\x09\x00\x00\x00\x00\x00'  # compare     r9 0x0
    b'\x92\x00\x00\x00\x2f\x00\x00\x00'  # jne         0x2F
    b'\x76\x00\x00\x01\x01\x00\x00\x00'  # compare     b0 b1 r1
    b'\x91\x00\x00\x00\x29\x00\x00\x00'  # je          0x29
    b'\x14\x00\x00\x00\x00\x00\x00\x00'  # eraseblk    f0
    b'\xb0\x00\x09\x00\x00\x00\x00\x00'  # rdsts       r9
    b'\x71\x00\x09\x00\x00\x00\x00\x00'  # compare     r9 0x0
    b'\x92\x00\x00\x00\x33\x00\x00\x00'  # jne         0x33
    b'\x10\x00\x00\x00\x01\x00\x00\x00'  # write       f0 b0 r1
    b'\xb0\x00\x09\x00\x00\x00\x00\x00'  # rdsts       r9
    b'\x71\x00\x09\x00\x00\x00\x00\x00'  # compare     r9 0x0
    b'\x92\x00\x00\x00\x37\x00\x00\x00'  # jne         0x37
    b'\x30\x00\x04\x01\x00\x00\x00\x00'  # add         r4 r1
    b'\x70\x00\x04\x02\x00\x00\x00\x00'  # compare     r4 r2
    b'\x94\x00\x00\x00\x41\x00\x00\x00'  # jge         0x41
    b'\x34\x00\x00\x01\x00\x00\x00\x00'  # add         f0 r1
    b'\x32\x00\x00\x01\x00\x00\x00\x00'  # add         b0 r1
    b'\x90\x00\x00\x00\x1b\x00\x00\x00'  # jmp         0x1B
    b'\x31\x00\x05\x00\x01\x00\x00\x00'  # add         r5 0x1
    b'\x70\x00\x05\x08\x00\x00\x00\x00'  # compare     r5 r8
    b'\x94\x00\x00\x00\x3b\x00\x00\x00'  # jge         0x3B
    b'\x90\x00\x00\x00\x1b\x00\x00\x00'  # jmp         0x1B
    b'\x31\x00\x06\x00\x01\x00\x00\x00'  # add         r6 0x1
    b'\x70\x00\x06\x08\x00\x00\x00\x00'  # compare     r6 r8
    b'\x94\x00\x00\x00\x3d\x00\x00\x00'  # jge         0x3D
    b'\x90\x00\x00\x00\x21\x00\x00\x00'  # jmp         0x21
    b'\x31\x00\x07\x00\x01\x00\x00\x00'  # add         r7 0x1
    b'\x70\x00\x07\x08\x00\x00\x00\x00'  # compare     r7 r8
    b'\x94\x00\x00\x00\x3f\x00\x00\x00'  # jge         0x3F
    b'\x90\x00\x00\x00\x25\x00\x00\x00'  # jmp         0x25
    b'\x51\x00\x0f\x00\x01\x00\x00\x00'  # set         rF 0x1
    b'\x90\x00\x00\x00\x42\x00\x00\x00'  # jmp         0x42
    b'\x51\x00\x0f\x00\x02\x00\x00\x00'  # set         rF 0x2
    b'\x90\x00\x00\x00\x42\x00\x00\x00'  # jmp         0x42
    b'\x51\x00\x0f\x00\x03\x00\x00\x00'  # set         rF 0x3
    b'\x90\x00\x00\x00\x42\x00\x00\x00'  # jmp         0x42
    b'\x51\x00\x0f\x00\x00\x00\x00\x00'  # set         rF 0x0
    b'\xff\x00\x00\x00\x00\x00\x00\x00'  # end
)

# ----------------------------------------------------------------------------------------
standard_script_setts = (
    #b'\x01\x00\x00\x00\x00\x00\x00\x00'  # begin
    #b'\x51\x00\x00\x00\x??\x??\x??\x??'  # set         r0 0x????????
    #b'\x51\x00\x01\x00\x00\x10\x00\x00'  # set         r1 0x1000
    #b'\x51\x00\x02\x00\x??\x??\x??\x??'  # set         r2 0x????????
    b'\x51\x00\x03\x00\x00\x00\x00\x00'  # set         r3 0x0
    b'\x55\x00\x00\x00\x00\x00\x00\x00'  # set         f0 0x0
    b'\x53\x00\x00\x00\x00\x00\x00\x00'  # set         b0 0x0
    b'\x51\x00\x04\x00\x00\x00\x00\x00'  # set         r4 0x0
    b'\x51\x00\x05\x00\x00\x00\x00\x00'  # set         r5 0x0
    b'\x51\x00\x06\x00\x00\x00\x00\x00'  # set         r6 0x0
    b'\x51\x00\x07\x00\x00\x00\x00\x00'  # set         r7 0x0
    b'\x51\x00\x08\x00\x03\x00\x00\x00'  # set         r8 0x3
    b'\x51\x00\x09\x00\x00\x00\x00\x00'  # set         r9 0x0
    b'\x51\x00\x0a\x00\x00\x00\x00\x00'  # set         rA 0x0            New instruction!
    b'\x55\x00\x00\x00\x16\x00\x00\x00'  # set         f0 0x16
    b'\x53\x00\x01\x00\x00\x00\x00\x00'  # set         b1 0x0
    b'\x13\x00\x01\x00\x01\x00\x00\x00'  # read        b1 f0 0x1
    b'\x60\x00\x03\x01\x00\x00\x00\x00'  # loadbyte    r3 b1
    b'\x45\x00\x03\x00\x04\x00\x00\x00'  # shiftl      r3 0x4
    b'\x31\x00\x03\x00\x04\x00\x00\x00'  # add         r3 0x4
    b'\x54\x00\x00\x03\x00\x00\x00\x00'  # set         f0 r3
    b'\x53\x00\x01\x00\x00\x00\x00\x00'  # set         b1 0x0
    b'\x13\x00\x01\x00\x02\x00\x00\x00'  # read        b1 f0 0x2
    b'\x61\x00\x03\x01\x00\x00\x00\x00'  # loadword    r3 b1
    b'\x41\x00\x03\x00\xff\x7f\x00\x00'  # and         r3 0x7FFF
    b'\x45\x00\x03\x00\x0c\x00\x00\x00'  # shiftl      r3 0xC
    b'\x30\x00\x03\x00\x00\x00\x00\x00'  # add         r3 r0
    b'\x54\x00\x00\x03\x00\x00\x00\x00'  # set         f0 r3
    b'\x12\x00\x01\x00\x01\x00\x00\x00'  # read        b1 f0 r1
    b'\xb0\x00\x09\x00\x00\x00\x00\x00'  # rdsts       r9
    b'\x71\x00\x09\x00\x00\x00\x00\x00'  # compare     r9 0x0
    b'\x92\x00\x00\x00\x31\x00\x00\x00'  # jne         0x31              CF: 0x2f -> 0x31 (+2)
    b'\x76\x00\x00\x01\x01\x00\x00\x00'  # compare     b0 b1 r1
    b'\x91\x00\x00\x00\x2b\x00\x00\x00'  # je          0x2b              CF: 0x29 -> 0x2b (+2)
    b'\xc2\x00\x00\x00\x00\x00\x00\x00'  # setts                         New instruction!
    b'\x14\x00\x00\x00\x00\x00\x00\x00'  # eraseblk    f0
    b'\xb0\x00\x09\x00\x00\x00\x00\x00'  # rdsts       r9
    b'\x71\x00\x09\x00\x00\x00\x00\x00'  # compare     r9 0x0
    b'\x92\x00\x00\x00\x35\x00\x00\x00'  # jne         0x35              CF: 0x33 -> 0x35 (+2)
    b'\x10\x00\x00\x00\x01\x00\x00\x00'  # write       f0 b0 r1
    b'\xb0\x00\x09\x00\x00\x00\x00\x00'  # rdsts       r9
    b'\x71\x00\x09\x00\x00\x00\x00\x00'  # compare     r9 0x0
    b'\x92\x00\x00\x00\x39\x00\x00\x00'  # jne         0x39              CF: 0x37 -> 0x39 (+2)
    b'\x30\x00\x04\x01\x00\x00\x00\x00'  # add         r4 r1
    b'\x70\x00\x04\x02\x00\x00\x00\x00'  # compare     r4 r2
    b'\x94\x00\x00\x00\x43\x00\x00\x00'  # jge         0x43              CF: 0x41 -> 0x43 (+2)
    b'\x34\x00\x00\x01\x00\x00\x00\x00'  # add         f0 r1
    b'\x32\x00\x00\x01\x00\x00\x00\x00'  # add         b0 r1
    b'\x90\x00\x00\x00\x1c\x00\x00\x00'  # jmp         0x1C              CF: 0x1b -> 0x1c (+1)
    b'\x31\x00\x05\x00\x01\x00\x00\x00'  # add         r5 0x1
    b'\x70\x00\x05\x08\x00\x00\x00\x00'  # compare     r5 r8
    b'\x94\x00\x00\x00\x3d\x00\x00\x00'  # jge         0x3D              CF: 0x3b -> 0x3d (+2)
    b'\x90\x00\x00\x00\x1c\x00\x00\x00'  # jmp         0x1C              CF: 0x1b -> 0x1c (+1)
    b'\x31\x00\x06\x00\x01\x00\x00\x00'  # add         r6 0x1
    b'\x70\x00\x06\x08\x00\x00\x00\x00'  # compare     r6 r8
    b'\x94\x00\x00\x00\x3f\x00\x00\x00'  # jge         0x3F              CF: 0x3d -> 0x3f (+2)
    b'\x90\x00\x00\x00\x23\x00\x00\x00'  # jmp         0x23              CF: 0x21 -> 0x23 (+2)
    b'\x31\x00\x07\x00\x01\x00\x00\x00'  # add         r7 0x1
    b'\x70\x00\x07\x08\x00\x00\x00\x00'  # compare     r7 r8
    b'\x94\x00\x00\x00\x41\x00\x00\x00'  # jge         0x41              CF: 0x3f -> 0x41 (+2)
    b'\x90\x00\x00\x00\x27\x00\x00\x00'  # jmp         0x27              CF: 0x25 -> 0x27 (+2)
    b'\x51\x00\x0f\x00\x01\x00\x00\x00'  # set         rF 0x1
    b'\x90\x00\x00\x00\x44\x00\x00\x00'  # jmp         0x44              CF: 0x42 -> 0x24 (+2)
    b'\x51\x00\x0f\x00\x02\x00\x00\x00'  # set         rF 0x2
    b'\x90\x00\x00\x00\x44\x00\x00\x00'  # jmp         0x44              CF: 0x42 -> 0x24 (+2)
    b'\x51\x00\x0f\x00\x03\x00\x00\x00'  # set         rF 0x3
    b'\x90\x00\x00\x00\x44\x00\x00\x00'  # jmp         0x44              CF: 0x42 -> 0x24 (+2)
    b'\x51\x00\x0f\x00\x00\x00\x00\x00'  # set         rF 0x0
    b'\xff\x00\x00\x00\x00\x00\x00\x00'  # end
)

# ----------------------------------------------------------------------------------------
standard_script_clearts = (
    #b'\x01\x00\x00\x00\x00\x00\x00\x00'  # begin
    #b'\x51\x00\x00\x00\x??\x??\x??\x??'  # set         r0 0x????????
    #b'\x51\x00\x01\x00\x00\x10\x00\x00'  # set         r1 0x1000
    #b'\x51\x00\x02\x00\x??\x??\x??\x??'  # set         r2 0x????????
    b'\x51\x00\x03\x00\x00\x00\x00\x00'  # set         r3 0x0
    b'\x55\x00\x00\x00\x00\x00\x00\x00'  # set         f0 0x0
    b'\x53\x00\x00\x00\x00\x00\x00\x00'  # set         b0 0x0
    b'\x51\x00\x04\x00\x00\x00\x00\x00'  # set         r4 0x0
    b'\x51\x00\x05\x00\x00\x00\x00\x00'  # set         r5 0x0
    b'\x51\x00\x06\x00\x00\x00\x00\x00'  # set         r6 0x0
    b'\x51\x00\x07\x00\x00\x00\x00\x00'  # set         r7 0x0
    b'\x51\x00\x08\x00\x03\x00\x00\x00'  # set         r8 0x3
    b'\x51\x00\x09\x00\x00\x00\x00\x00'  # set         r9 0x0
    b'\x51\x00\x0a\x00\x00\x00\x00\x00'  # set         rA 0x0            New instruction!
    b'\x55\x00\x00\x00\x16\x00\x00\x00'  # set         f0 0x16
    b'\x53\x00\x01\x00\x00\x00\x00\x00'  # set         b1 0x0
    b'\x13\x00\x01\x00\x01\x00\x00\x00'  # read        b1 f0 0x1
    b'\x60\x00\x03\x01\x00\x00\x00\x00'  # loadbyte    r3 b1
    b'\x45\x00\x03\x00\x04\x00\x00\x00'  # shiftl      r3 0x4
    b'\x31\x00\x03\x00\x04\x00\x00\x00'  # add         r3 0x4
    b'\x54\x00\x00\x03\x00\x00\x00\x00'  # set         f0 r3
    b'\x53\x00\x01\x00\x00\x00\x00\x00'  # set         b1 0x0
    b'\x13\x00\x01\x00\x02\x00\x00\x00'  # read        b1 f0 0x2
    b'\x61\x00\x03\x01\x00\x00\x00\x00'  # loadword    r3 b1
    b'\x41\x00\x03\x00\xff\x7f\x00\x00'  # and         r3 0x7FFF
    b'\x45\x00\x03\x00\x0c\x00\x00\x00'  # shiftl      r3 0xC
    b'\x30\x00\x03\x00\x00\x00\x00\x00'  # add         r3 r0
    b'\x54\x00\x00\x03\x00\x00\x00\x00'  # set         f0 r3
    b'\xc3\x00\x00\x00\x00\x00\x00\x00'  # clearts                       New instruction!
    b'\x12\x00\x01\x00\x01\x00\x00\x00'  # read        b1 f0 r1
    b'\xb0\x00\x09\x00\x00\x00\x00\x00'  # rdsts       r9
    b'\x71\x00\x09\x00\x00\x00\x00\x00'  # compare     r9 0x0
    b'\x92\x00\x00\x00\x31\x00\x00\x00'  # jne         0x31              CF: 0x2f -> 0x31 (+2)
    b'\x76\x00\x00\x01\x01\x00\x00\x00'  # compare     b0 b1 r1
    b'\x91\x00\x00\x00\x2b\x00\x00\x00'  # je          0x2b              CF: 0x29 -> 0x2b (+2)
    b'\x14\x00\x00\x00\x00\x00\x00\x00'  # eraseblk    f0
    b'\xb0\x00\x09\x00\x00\x00\x00\x00'  # rdsts       r9
    b'\x71\x00\x09\x00\x00\x00\x00\x00'  # compare     r9 0x0
    b'\x92\x00\x00\x00\x35\x00\x00\x00'  # jne         0x35              CF: 0x33 -> 0x35 (+2)
    b'\x10\x00\x00\x00\x01\x00\x00\x00'  # write       f0 b0 r1
    b'\xb0\x00\x09\x00\x00\x00\x00\x00'  # rdsts       r9
    b'\x71\x00\x09\x00\x00\x00\x00\x00'  # compare     r9 0x0
    b'\x92\x00\x00\x00\x39\x00\x00\x00'  # jne         0x39              CF: 0x37 -> 0x39 (+2)
    b'\x30\x00\x04\x01\x00\x00\x00\x00'  # add         r4 r1
    b'\x70\x00\x04\x02\x00\x00\x00\x00'  # compare     r4 r2
    b'\x94\x00\x00\x00\x43\x00\x00\x00'  # jge         0x43              CF: 0x41 -> 0x43 (+2)
    b'\x34\x00\x00\x01\x00\x00\x00\x00'  # add         f0 r1
    b'\x32\x00\x00\x01\x00\x00\x00\x00'  # add         b0 r1
    b'\x90\x00\x00\x00\x1d\x00\x00\x00'  # jmp         0x1D              CF: 0x1b -> 0x1d (+2)
    b'\x31\x00\x05\x00\x01\x00\x00\x00'  # add         r5 0x1
    b'\x70\x00\x05\x08\x00\x00\x00\x00'  # compare     r5 r8
    b'\x94\x00\x00\x00\x3d\x00\x00\x00'  # jge         0x3D              CF: 0x3b -> 0x3d (+2)
    b'\x90\x00\x00\x00\x1d\x00\x00\x00'  # jmp         0x1D              CF: 0x1b -> 0x1d (+2)
    b'\x31\x00\x06\x00\x01\x00\x00\x00'  # add         r6 0x1
    b'\x70\x00\x06\x08\x00\x00\x00\x00'  # compare     r6 r8
    b'\x94\x00\x00\x00\x3f\x00\x00\x00'  # jge         0x3F              CF: 0x3d -> 0x3f (+2)
    b'\x90\x00\x00\x00\x23\x00\x00\x00'  # jmp         0x23              CF: 0x21 -> 0x23 (+2)
    b'\x31\x00\x07\x00\x01\x00\x00\x00'  # add         r7 0x1
    b'\x70\x00\x07\x08\x00\x00\x00\x00'  # compare     r7 r8
    b'\x94\x00\x00\x00\x41\x00\x00\x00'  # jge         0x41              CF: 0x3f -> 0x41 (+2)
    b'\x90\x00\x00\x00\x27\x00\x00\x00'  # jmp         0x27              CF: 0x25 -> 0x27 (+2)
    b'\x51\x00\x0f\x00\x01\x00\x00\x00'  # set         rF 0x1
    b'\x90\x00\x00\x00\x44\x00\x00\x00'  # jmp         0x44              CF: 0x42 -> 0x24 (+2)
    b'\x51\x00\x0f\x00\x02\x00\x00\x00'  # set         rF 0x2
    b'\x90\x00\x00\x00\x44\x00\x00\x00'  # jmp         0x44              CF: 0x42 -> 0x24 (+2)
    b'\x51\x00\x0f\x00\x03\x00\x00\x00'  # set         rF 0x3
    b'\x90\x00\x00\x00\x44\x00\x00\x00'  # jmp         0x44              CF: 0x42 -> 0x24 (+2)
    b'\x51\x00\x0f\x00\x00\x00\x00\x00'  # set         rF 0x0
    b'\xff\x00\x00\x00\x00\x00\x00\x00'  # end
)

standard_script_names = {
    standard_script: 'baseline',
    standard_script_setts: 'setts',
    standard_script_clearts: 'clearts',
}

# ----------------------------------------------------------------------------------------
class Instruction(FirmwareStructure):
    """
    An Intel BIOS Guard Script instruction.
    """

    label = "Instruction"

    definition = Struct(
        "opcode" / Int16ul,
        "op1" / Int8ul,
        "op2" / Int8ul,
        "op3" / Int32ul,
    )

    reporting = [
        ["opcode", "0x%02x"], ["op1", "0x%02x"], ["op2", "0x%02x"], ["op3", "0x%08x"],
        ["disassembly", "'%s'"], ["as_tuple", None],
    ]

    @property
    def as_tuple(self) -> tuple[int, int, int, int]:
        return (self.opcode, self.op1, self.op2, self.op3)

    @property
    def disassembly(self) -> str:
        terms: list[str] = []
        if self.opcode in opcodes:
            definition = opcodes[self.opcode]
            terms.append(definition[0])
            for n in range(1, 4):
                fmtstr = definition[n]
                if fmtstr is not None:
                    terms.append(fmtstr % self.as_tuple[n])
        return ' '.join(terms)

# ----------------------------------------------------------------------------------------
class IntelBIOSGuardScriptStandard(FirmwareStructure):
    """
    The 'standard' Intel BIOSGuard Script, which varies only in the address in the second
    instruction.
    """

    label = "Standard Intel BIOS Guard Script"

    # A script is a list of instructions.
    definition = Struct(
        # First instruction and a half... "begin", "set r0, ?????"
        "_start" / Const(b'\x01\x00\x00\x00\x00\x00\x00\x00\x51\x00\x00\x00'),
        "address" / Int32ul,
        # Third instruction and another half... "set r1 0x1000", "set r2 0x????????"
        "_middle" / Const(b'\x51\x00\x01\x00\x00\x10\x00\x00\x51\x00\x02\x00'),
        "blocksize" / Int32ul,
        "_code" / Select(
            Const(standard_script),
            Const(standard_script_setts),
            Const(standard_script_clearts),
        ),
        "variant" / Computed(lambda ctx: standard_script_names[ctx._code]),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["address", "0x%x"], ["blocksize", "0x%x"], ["variant"]]

# ----------------------------------------------------------------------------------------
class IntelBIOSGuardScript(FirmwareStructure):
    """
    An Intel BIOS Guard Script (found in an Intel BIOS Guard signed data block).

    """

    label = "Intel BIOS Guard Script"

    # A script is a list of instructions.
    definition = Struct(
        # Try for a "standard" interpretation.
        "_standard" / Opt(Peek(Class(IntelBIOSGuardScriptStandard))),
        # But regardless, parse the script in the standard way.  This ensures that users
        # can access the individual instructions if they want.
        "instructions" / GreedyRange(Class(Instruction)),
        "unexpected" / Class(MysteryBytes),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    instructions: list[Instruction]

    reporting = [
        ["address", "0x%x"], ["blocksize", "0x%x"], ["variant"], ["code"],
        ["instructions", None],
    ]

    @property
    def code(self) -> Union[str, list[Instruction]]:
        if self._standard is not None:
            return "not displayed"
        else:
            return self.instructions

    def analyze(self) -> None:
        # Integrate standard BIOSGuard scripts and non-standard ones.
        self.variant = 'nonstandard'
        self.address = 0
        self.blocksize = 0
        if self._standard is not None:
            self.variant = self._standard.variant
            self.address = self._standard.address
            self.blocksize = self._standard.blocksize

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
