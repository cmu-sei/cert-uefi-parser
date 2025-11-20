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
Convenience routines to normalize compression and decompression APIs.
"""

import logging
from enum import Enum
from typing import Optional

from uefi_support import (
    UefiDecompress, FrameworkDecompress, LzmaDecompress, DecompressionError)

log = logging.getLogger("cert-uefi-parser")

class CompressionAlgorithm(Enum):
    NoCompression = 0
    UEFI = 1
    Framework = 2
    LZMA = 3

def decompress(cdata: bytes, algorithm: CompressionAlgorithm,
               quiet: bool = False) -> Optional[bytes]:
    """
    Decompress data using the specified algorithm.

    Raise ValueError if decompression failed, unless quiet is True.
    """
    #log.debug("Trying %s l=%d d=%r" % (algorithm, len(cdata), cdata[:16]))

    data = None
    try:
        if algorithm == CompressionAlgorithm.NoCompression:
            return cdata
        if algorithm == CompressionAlgorithm.UEFI:
            #log.debug("Length of data1 is: %d" % len(cdata))
            data = UefiDecompress(cdata)
        elif algorithm == CompressionAlgorithm.Framework:
            data = FrameworkDecompress(cdata)
        elif algorithm == CompressionAlgorithm.LZMA:
            data = LzmaDecompress(cdata)
    except DecompressionError as e:
        if not quiet:
            # This line was here because the raise alone might be silently swallowed by
            # Construct. :-(
            log.error(f"Decompression exception raised! {e}")
            raise

    # If we still don't have valid data it's a more serious error.
    if data is None and not quiet:
        raise ValueError("Decompression failed")

    #if data is not None:
    #    log.debug("Decompressing %s l=%d d=%r to l=%d d=%r" % (
    #        algorithm, len(cdata), cdata[:16], len(data), data[:16]))
    #else:
    #    log.debug("Decompressing %s l=%d d=%r to l=%d d=%r" % (
    #        algorithm, len(cdata), cdata[:16], 0, data))

    return data

def compress(data: bytes, algorithm: CompressionAlgorithm) -> bytes:
    """
    Compress data using the specified algorithm, and report any failures.
    """
    # FIXME! Untested and previously broken.
    # if algorithm == CompressionAlgorithm.NoCompression:
    #     return data
    # elif algorithm == CompressionAlgorithm.UEFI:
    #     cdata = UefiCompress(data, len(data))
    # elif algorithm == CompressionAlgorithm.Framework:
    #     cdata = FrameworkCompress(data, len(data))
    # elif algorithm == CompressionAlgorithm.LZMA:
    #     cdata = lzma.compress(data)
    #
    # if cdata is None:
    #     raise ValueError("Compression failed")
    raise NotImplementedError

def sloppy_decompress(
        cdata: bytes, quiet: bool = False) -> tuple[Optional[bytes], CompressionAlgorithm]:
    """
    Decompress the data, trying all available algorithms until one works.
    """
    data = decompress(cdata, CompressionAlgorithm.UEFI, quiet=True)
    algorithm = CompressionAlgorithm.UEFI
    if data is None:
        data = decompress(cdata, CompressionAlgorithm.LZMA, quiet=True)
        algorithm = CompressionAlgorithm.LZMA
    if data is None:
        data = decompress(cdata, CompressionAlgorithm.Framework, quiet=True)
        algorithm = CompressionAlgorithm.Framework
    if data is None:
        if not quiet:
            raise ValueError("Decompression failed")
        algorithm = CompressionAlgorithm.NoCompression
    return (data, algorithm)

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
