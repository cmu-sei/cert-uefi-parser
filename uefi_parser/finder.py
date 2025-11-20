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
This module builds on the UEFI module to create a "finder" for firmware volumes.

The primary purpose of the module is to solves some recursive import problems by importing
the FirmwareVolume class dynamically.
"""

from typing import Optional

from construct import GreedyBytes, CheckError

from .base import FirmwareStructure, Struct
from .mystery import MysteryBytes

# ========================================================================================

# ----------------------------------------------------------------------------------------
class FirmwareVolumeFinder(FirmwareStructure):
    """
    This class searches an arbitrary binary blob to find volume headers.
    """

    label = "Firmware Volume Finder"

    definition = Struct(
        "raw_data" / GreedyBytes,
    )

    reporting = [["raw_data", None], ["volumes"], ["unrecognized"]]

    sbom_fields = ["volumes"]

    # This search criteria requries the _FVH to be 64-byte block aligned.  Why?
    def find_next_volume(self, data: bytes, offset: int) -> Optional[int]:
        #self.debug("Searching for volumes...")
        for aligned in range(offset + 32, len(data), 16):
            if data[aligned:aligned + 4] == b'_FVH':
                return aligned - 40
            if data[aligned + 8:aligned + 12] == b'_FVH':
                return aligned - 32
        return None

    def analyze(self) -> None:
        # Dynamically importing this (and thus resolving module dependencies) is more or
        # less the point of having broken this into a separate file.
        from .uefi import FirmwareVolume
        # This is working, but it would be better if it was a lambda because then it would
        # have the correct absolute file offsets!
        self.unrecognized = []
        self.volumes = []

        next_offset: Optional[int] = 0
        previous_offset = 0
        # Find the next volume header.
        next_offset = self.find_next_volume(self.raw_data, previous_offset)
        while next_offset is not None:
            #self.debug("Found volume header at offset 0x%x (0x%x)" % (
            #    next_offset, self._data_offset + next_offset))
            #self.debug(f"previous_offset={hex(previous_offset)} "
            #    f"next_offset={hex(next_offset)}")

            # Record the bytes until the next volume header.
            if previous_offset != next_offset:
                #self.debug("Case one 0x%x 0x%x 0x%x" % (
                #     previous_offset, next_offset, len(self.raw_data)))
                plen = next_offset - previous_offset
                #mb = self.subparse(PartitionThing, "raw_data", previous_offset, plen)
                #if mb is None:
                mb = self.subparse(MysteryBytes, "raw_data", previous_offset, plen)
                if mb is not None:
                    mb.label = "Mystery Inter-volume Bytes"
                self.unrecognized.append(mb)

            # Parse the volume
            volume: Optional[FirmwareVolume]
            volume = self.subparse(FirmwareVolume, "raw_data", next_offset)
            #self.debug(f"Volume was {volume}")
            # I've found at least one bad match for _FVH, so this is meant to be further
            # validation that the volume is legitimate.
            if volume and (volume.size > 1024 * 1024 * 512):
                volume = None
            # If a valid volume was not found...
            if volume is None:
                previous_offset = next_offset
                next_offset = None
            else:
                self.volumes.append(volume)
                previous_offset = next_offset + len(volume)
                #self.debug("New previous offset is 0x%x len=0x%x end=0x%x" % (
                #    previous_offset, len(volume), len(self.raw_data)))
                next_offset = self.find_next_volume(self.raw_data, previous_offset)

        if len(self.volumes) == 0:
            raise CheckError("No firmware volumes were found!")

        if previous_offset != len(self.raw_data):
            #self.debug("Case two 0x%x 0x%x" % (previous_offset, len(self.raw_data)))
            #mb = self.subparse(PartitionThing, "raw_data", previous_offset, plen)
            #if mb is None:
            mb = self.subparse(MysteryBytes, "raw_data", previous_offset)
            if mb is not None:
                mb.label = "Mystery Inter-volume Bytes"
            self.unrecognized.append(mb)

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
