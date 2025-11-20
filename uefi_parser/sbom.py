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
SBOM related formats, especially uSWID and CoSWID.
"""

import lzma
import zlib
from datetime import datetime
from typing import Optional

from construct import Const, GreedyBytes, If, Int8ul, Int16ul, Int32ul, this
import uswid

from .base import FirmwareStructure, FakeFirmwareStructure, Struct

# ----------------------------------------------------------------------------------------
class USwidHash(FakeFirmwareStructure):

    label = "uSWID Hash"

    def __init__(self, alg_id: Optional[str], value: Optional[str]):
        super().__init__()
        self.alg_id = alg_id
        self.value = value

    @classmethod
    def from_hash(cls, uhash: uswid.uSwidHash) -> 'USwidHash':
        return USwidHash(str(uhash.alg_id), uhash.value)

    def instance_name(self) -> str:
        return str(self.value)

# ----------------------------------------------------------------------------------------
class VexProduct(FakeFirmwareStructure):

    label = "VexProduct"

    def __init__(self, tag_ids: list[str], hashes: list[USwidHash]):
        super().__init__()
        self.tag_ids = tag_ids
        self.hashes = hashes

    @classmethod
    def from_product(cls, p: uswid.uSwidVexProduct) -> 'VexProduct':
        tag_ids = [str(t) for t in p.tag_ids]
        hashes = [USwidHash.from_hash(e) for e in p.hashes]
        return VexProduct(tag_ids, hashes)

# ----------------------------------------------------------------------------------------
class VexStatement(FakeFirmwareStructure):

    label = "VexStatement"

    def __init__(self, name: Optional[str], status: Optional[str],
                 justification: Optional[str], impact: Optional[str],
                 products: list[VexProduct]):
        super().__init__()
        self.name = name
        self.status = status
        self.justification = justification
        self.impact = impact

    @classmethod
    def from_statement(cls, s: uswid.uSwidVexStatement) -> 'VexStatement':
        products = [VexProduct.from_product(p) for p in s.products]
        return VexStatement(s.vulnerability_name, str(s.status),
                            str(s.justification), s.impact_statement, products)

# ----------------------------------------------------------------------------------------
class USwidEvidence(FakeFirmwareStructure):

    label = "uSWID Evidence"

    def __init__(self, date: Optional[datetime], device_id: Optional[str]):
        super().__init__()
        self.date = date
        self.device_id = device_id

    @classmethod
    def from_evidence(cls, e: uswid.uSwidEvidence) -> 'USwidEvidence':
        return USwidEvidence(e.date, e.device_id)

    def instance_name(self) -> str:
        return f"{self.device_id} {self.date}"

# ----------------------------------------------------------------------------------------
class USwidPayload(FakeFirmwareStructure):

    label = "uSWID Payload"

    def __init__(self, name: Optional[str], size: Optional[int], hashes: list[USwidHash]):
        super().__init__()
        self.name = name
        self.size = size
        self.hashes = hashes

    @classmethod
    def from_payload(cls, p: uswid.uSwidPayload) -> 'USwidPayload':
        hashes = [USwidHash.from_hash(e) for e in p.hashes]
        return USwidPayload(p.name, p.size, hashes)

    reporting = [["name"], ["size"], ["hashes"]]

# ----------------------------------------------------------------------------------------
class USwidEntity(FakeFirmwareStructure):

    label = "uSWID Entity"

    def __init__(self, regid: Optional[str], name: Optional[str], roles: str):
        super().__init__()
        self.regid = regid
        self.name = name
        self.roles = roles

    @classmethod
    def from_entity(cls, e: uswid.uSwidEntity) -> 'USwidEntity':
        roles = ", ".join([role.name for role in e.roles])
        return USwidEntity(e.regid, e.name, roles)

    reporting = [["name"], ["regid"], ["roles"]]

# ----------------------------------------------------------------------------------------
class USwidLink(FakeFirmwareStructure):

    label = "uSWID Link"

    def __init__(self, rel: str, use: str, href: Optional[str]):
        super().__init__()
        self.rel = rel
        self.use = use
        self.href = href

    @classmethod
    def from_link(cls, link: uswid.uSwidLink) -> 'USwidLink':
        # FIXME! Calling str here is wrong!
        return USwidLink(str(link.rel), str(link.use), link.href)

# ----------------------------------------------------------------------------------------
class USwidComponent(FakeFirmwareStructure):
    """
    A uSWID Component.
    """

    label = "uSWID Component"

    def __init__(self, tag_id: Optional[str], tag_version: int,
                 software_name: Optional[str], software_version: Optional[str],
                 links: list[USwidLink], entities: list[USwidEntity],
                 payloads: list[USwidPayload], evidences: list[USwidEvidence],
                 length: int, memory: bytes, offset: int):
        super().__init__(length, memory, offset)
        self.tag_id = tag_id
        self.tag_version = tag_version
        self.software_name = software_name
        self.software_version = software_version
        self.links = links
        self.entities = entities
        self.payloads = payloads
        self.evidences = evidences

    @classmethod
    def from_component(cls, c: uswid.uSwidComponent, length: int,
                       memory: bytes, offset: int) -> 'USwidComponent':
        links = [USwidLink.from_link(link) for link in c.links]
        entities = [USwidEntity.from_entity(e) for e in c.entities]
        payloads = [USwidPayload.from_payload(p) for p in c.payloads]
        evidences = [USwidEvidence.from_evidence(e) for e in c.evidences]
        # vex_statements
        return USwidComponent(
            c.tag_id, c.tag_version, c.software_name, c.software_version,
            links, entities, payloads, evidences, length, memory, offset)

    reporting = [
        ["tag_id"], ["tag_version"], ["software_name"], ["software_version"],
        ["links"], ["payloads"], ["evidences"], ["entities"],
        #[], ["xparsed"],
    ]

# ----------------------------------------------------------------------------------------
class USwid(FirmwareStructure):
    """
    A uSWID blob.

    In practice a Constrained Software Indentification Tagging (CoSWID) section.  I'll
    need to investigate/understand more about the other formats.

    It appears that the CoSWID format is in draft status, and specifies the CBOR encoding
    for the data.

    https://csrc.nist.gov/Projects/Software-Identification-SWID/guidelines
    """

    label = "uSWID"

    definition = Struct(
        "_magic" / Const(b'SBOM\xD6\xBA\x2E\xAC\xA3\xE6\x7A\x52\xAA\xEE\x3B\xAF'),
        "header_version" / Int8ul,
        "header_length" / Int16ul,
        "payload_length" / Int32ul,
        "flags" / If(this.header_version >= 2, Int8ul),
        "compression" / If(this.header_version >= 3, Int8ul),
        "_data" / GreedyBytes,
    )

    reporting = [
        ["header_version"], ["header_length"], ["payload_length"],
        ["flags", "0x%02x"], ["compression", "0x%02x"],
        ["components"],
    ]

    def analyze(self) -> None:
        if self.compression is None or self.compression == 0:
            decompressed_data = self._data
        elif self.compression == 1:
            decompressed_data = zlib.decompress(self._data)
        elif self.compression == 2:
            decompressed_data = lzma.decompress(self._data)
        else:
            return

        self.components = []
        payload_offset = 0
        while payload_offset < len(decompressed_data):

            component = uswid.uSwidComponent()
            length = uswid.uSwidFormatCoswid()._load_component(  # type: ignore
                component, decompressed_data, payload_offset
            )
            comp = USwidComponent.from_component(
                component, length, decompressed_data, payload_offset)
            #comp.xparsed = str(component)
            self.components.append(comp)
            payload_offset += length

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
