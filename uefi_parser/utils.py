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
Utility functions.

ANSI color coding and checksums.
"""

import os
import struct
import re
import logging

__all__ = ["ansi_to_html", "ansi_to_plaintext",
           "red", "green", "yellow", "blue", "purple", "cyan",
           "dump_data", "csum16", "csum32", "crc_test", "crc16_me"]

log = logging.getLogger("cert-uefi-parser")

# ----------------------------------------------------------------------------------------
number_to_color = {"31": "red",
                   "32": "green",
                   "33": "yellow",
                   "34": "blue",
                   "35": "magenta",
                   "36": "cyan"}

ansi_match = re.compile("\033\\[([1-9][0-9]*);?m")

def ansi_replace(m: re.Match[str]) -> str:
    number = m.group(1)
    if number == '1':
        return "</span>"
    value = number_to_color.get(number)
    if value is None:
        return "<span>"
    return f'<span style="color:{value}">'

def plain_replace(m: re.Match[str]) -> str:
    return ''

def ansi_to_html(msg: str) -> str:
    return ansi_match.sub(ansi_replace, msg)

def ansi_to_plaintext(msg: str) -> str:
    return ansi_match.sub(plain_replace, msg)

def emit_color(msg: str, color: int) -> str:
    """Emit a string with a console color escape sequence, if requested by the user."""
    # FIXME?  Using a global to control the nocolor option isn't ideal...  But it's ok?
    from .cmds import nocolor
    if nocolor:
        return msg
    else:
        return "\033[%dm%s\033[1;m" % (color, msg)

# ----------------------------------------------------------------------------------------
def red(msg: str) -> str:
    return emit_color(msg, 31)

# ----------------------------------------------------------------------------------------
def green(msg: str) -> str:
    return emit_color(msg, 32)

# ----------------------------------------------------------------------------------------
def yellow(msg: str) -> str:
    return emit_color(msg, 33)

# ----------------------------------------------------------------------------------------
def blue(msg: str) -> str:
    return emit_color(msg, 34)

# ----------------------------------------------------------------------------------------
def purple(msg: str) -> str:
    return emit_color(msg, 35)

# ----------------------------------------------------------------------------------------
def cyan(msg: str) -> str:
    return emit_color(msg, 36)

# ----------------------------------------------------------------------------------------
def dump_data(name: str, data: bytes) -> None:
    """
    Write binary data to name.

    Args:
        name (string): Path to output file, created if it does not exist.
        data (binary): Content to be written.
    """
    try:
        if os.path.dirname(name) != '':
            if not os.path.exists(os.path.dirname(name)):
                os.makedirs(os.path.dirname(name))
        with open(name, 'wb') as fh:
            fh.write(data)
        log.info("wrote: %s" % (red(name)))
    except Exception as e:
        log.error("could not write (%s), (%s)." % (name, str(e)))

# ----------------------------------------------------------------------------------------
def csum16(buf: bytes) -> int:
    assert len(buf) & 0x1 == 0
    #if len(buf) & 0x1 != 0:
    #    buf += b'\x00'
    num_int16s = len(buf) / 2
    summation = 0
    words = struct.unpack("<%dH" % num_int16s, buf)
    #log.debug("L: %d D: %r" % (num_int16s, words))
    for b in words:
        #log.debug("summation=%x b=%x" % (summation, b))
        summation += b
    return summation % 2**16

# ----------------------------------------------------------------------------------------
def csum32(buf: bytes) -> int:
    assert len(buf) & 0x3 == 0
    num_int32s = len(buf) / 4
    summation = 0
    for b in struct.unpack("<%dI" % num_int32s, buf):
        summation += b
    return summation % 2**32

# ----------------------------------------------------------------------------------------
def crc_test() -> bool:
    zeros = b'\x00' * 64
    mydata = zeros + struct.pack('H', 0x1201)
    return crc16_me(mydata, 0xffff) == 0xd4f4

# ----------------------------------------------------------------------------------------
def crc16_me(data: bytes, initial: int = 0xffff) -> int:
    "CRC-16 algorithm used in ME"
    crc = initial
    for b in data:
        crc = crc ^ (b << 8)
        for _ in range(0, 8):
            if (crc & 0x8000):
                crc = (crc << 1) ^ 0x1021
            else:
                crc = crc << 1
        crc = crc & 0xffff
    return crc

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
