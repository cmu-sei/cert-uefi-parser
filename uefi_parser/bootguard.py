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
Boot Guard, Intel Trusted Execution Environment (TXT), etc.
"""

import os
import hashlib
from enum import Flag
from uuid import UUID

from construct import (
    Bytes, Computed, Const, GreedyRange, GreedyBytes, Int8ul, Int16ul, Int32ul, Int64ul,
    Array, Select, If, Check, Peek, this)

from .base import (
    FirmwareStructure, FixedLength, Class, Struct, OneOrMore, FailPeek, Until, Opt,
    Commit, EnumAdapter)
from .uenum import UEnum
from .fit import FITable
from .mystery import MysteryBytes, CommitMystery, HexDump, MysteryHexPeek

# ----------------------------------------------------------------------------------------
class BootGuardHashAlgorithm(UEnum):
    SHA1 = 4
    SHA256 = 11
    SHA384 = 12
    SM3 = 18

# ----------------------------------------------------------------------------------------
class BootGuardKeyAlgorithm(UEnum):
    RSA = 1

# ----------------------------------------------------------------------------------------
class ACMChipsetType(Flag):
    BIOS = 0
    SINIT = 1
    UNKNOWN = 4
    REVOCATION = 8

# ----------------------------------------------------------------------------------------
# TPM-Rev-2.0-Part-2-Structures-00.96-130315.pdf, Section 6.3, TMP_ALG_ID
class TPMAlgorithm(UEnum):
    RSA = 0x0001
    SHA1 = 0x0004
    HMAC = 0x0005
    AES = 0x0006
    MGF1 = 0x0007
    KEYEDHASH = 0x0008
    XOR = 0x000a
    SHA256 = 0x000b
    SHA384 = 0x000c
    SHA512 = 0x000d
    NULL = 0x0010
    SM3_256 = 0x0012
    SM4 = 0x0013
    RSASSA = 0x0014
    RSSES = 0x0015
    RSAPSS = 0x0016
    OAEP = 0x0017
    ECDSA = 0x0018
    ECDH = 0x0019
    ECDAA = 0x001a
    SM2 = 0x001b
    ECSCHNORR = 0x001c
    ECMQV = 0x001d
    KDF1_SP800_56a = 0x0020
    KDF2 = 0x0021
    KDF1_SP800_108 = 0x0022
    ECC = 0x0023
    SYMCIPHER = 0x0025
    CTR = 0x0040
    OFB = 0x0041
    CBC = 0x0042
    CFB = 0x0043
    ECB = 0x0044

# ----------------------------------------------------------------------------------------
class BootGuardRSAPublicKey(FirmwareStructure):

    label = "Boot Guard RSA Public Key"

    definition = Struct(
        "version" / Int8ul,
        "size" / Int16ul,
        "exponent" / Int32ul,
        "modulus" / Bytes(lambda ctx: int(ctx.size / 8)),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    modulus: bytes

    @property
    def modulus_hex(self) -> str:
        return self.modulus.hex()

    reporting = [
        ["version", "0x%x"], ["size"], ["exponent"], ["modulus", None], ["modulus_hex"],
    ]

# ----------------------------------------------------------------------------------------
class BootGuardSignature(FirmwareStructure):

    label = "Boot Guard Signature"

    definition = Struct(
        "version" / Int8ul,
        "size" / Int16ul,
        "algorithm" / EnumAdapter(Int16ul, BootGuardHashAlgorithm),
        "signature" / Bytes(lambda ctx: int(ctx.size / 8)),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    signature: bytes

    @property
    def signature_hex(self) -> str:
        return self.signature.hex()

    reporting = [
        ["version", "0x%x"], ["size"], ["algorithm"], ["signature", None], ["signature_hex"],
    ]

# ----------------------------------------------------------------------------------------
class BootGuardKeyAndSignature(FirmwareStructure):

    label = "Boot Guard Key and Signature"

    definition = Struct(
        "version" / Int8ul,
        "algorithm" / EnumAdapter(Int16ul, BootGuardKeyAlgorithm),
        "pubkey" / Class(BootGuardRSAPublicKey),
        "scheme" / Int16ul,
        "signature" / Class(BootGuardSignature),
    )

    reporting = [
        ["version", "0x%x"], ["algorithm"], ["scheme"], ["pubkey"], ["signature"],
    ]

# ----------------------------------------------------------------------------------------
class BootGuardPMSG(FirmwareStructure):

    label = "Boot Guard PMSG"

    definition = Struct(
        "magic" / Const(b'__PMSG__'),
        "version" / Int8ul,
        "reserved" / If(this.version >= 0x20, Bytes(3)),
        #
        "rsassa_version" / Int8ul,
        "key_algo" / Int16ul,
        #
        "key_version" / Int8ul,
        "key_size" / Int16ul,
        "exponent" / Int32ul,
        "modulus" / Bytes(lambda ctx: int(ctx.key_size / 8)),
        #
        "sig_scheme" / Int16ul,
        #
        "sig_version" / Int8ul,
        "sig_size" / Int16ul,
        "hash_algo" / Int16ul,
        "signature" / Bytes(lambda ctx: int(ctx.sig_size / 8)),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    modulus: bytes
    signature: bytes

    @property
    def signature_hex(self) -> str:
        return self.signature.hex()

    @property
    def modulus_hex(self) -> str:
        return self.modulus.hex()

    reporting = [
        ["magic"], ["version", "0x%x"], ["rsassa_version", "0x%x"], ["key_version", "0x%x"],
        ["sig_version", "0x%x"],
        [], ["key_size"], ["key_algo"], ["exponent"], ["sig_scheme", "0x%s"],
        ["sig_size"], ["hash_algo"],
        [], ["modulus", None], ["modulus_hex"],
        [], ["signature", None], ["signature_hex"],
    ]

# ----------------------------------------------------------------------------------------
class SHAXHashStructure(FirmwareStructure):

    label = "SHAX Hash Structure"

    definition = Struct(
        "hash_algo" / EnumAdapter(Int16ul, BootGuardHashAlgorithm),
        "hash_size" / Int16ul,
        "hash_value" / Bytes(this.hash_size),
    )

    # FIXME! Needed until correct types are returned from the mypy extension...
    hash_value: bytes

    reporting = [
        ["hash_algo"], ["hash_size"], ["hash_value", None], ["hash_value_hex"],
    ]

    @property
    def hash_value_hex(self) -> str:
        return self.hash_value.hex()

# ----------------------------------------------------------------------------------------
class IBBSegment(FirmwareStructure):

    label = "IBB Segment"

    definition = Struct(
        "reserved" / Int16ul,
        "flags" / Int16ul,
        "base" / Int32ul,
        "size" / Int32ul,
    )

    reporting = [
        ["base", "0x%x"], ["size", "0x%x"], ["flags", "0x%x"], ["reserved"],
    ]

# ----------------------------------------------------------------------------------------
class IBBSegmentList(FirmwareStructure):

    label = "IBB Segment List"

    definition = Struct(
        "count" / Int8ul,
        "segments" / Array(this.count, Class(IBBSegment)),
    )

    reporting = [
        ["count"], ["segments"],
    ]

# ----------------------------------------------------------------------------------------
class HashList(FirmwareStructure):

    label = "Hash List"

    definition = Struct(
        "size" / Int16ul,
        "count" / Int16ul,
        "hashes" / Array(this.count, Class(SHAXHashStructure)),
    )

    reporting = [
        ["size"], ["count"], ["hashes"],
    ]

# ----------------------------------------------------------------------------------------
class TXTElement(FirmwareStructure):

    label = "TXT Element"

    definition = Struct(
        "magic" / Const(b'__TXTS__'),
        "version" / Int8ul,
        "reserved1" / Int8ul,
        "element_size" / Int16ul,
        "reserved2" / Int8ul,
        "set_type" / Int8ul,
        "reserved3" / Int16ul,
        "flags" / Int32ul,
        "power_down_interval" / Int16ul,
        "ptt_cmos_offset0" / Int8ul,
        "ptt_cmos_offset1" / Int8ul,
        "acpi_base_offset" / Int16ul,
        "reserved4" / Int16ul,
        "prwm_base_offset" / Int32ul,
        "hashes" / Class(HashList),
        "reserved5" / Bytes(3),
        "segments" / Class(IBBSegmentList),
    )

    reporting = [
        ["magic"], ["version", "0x%x"], ["element_size", "0x%x"], ["set_type"], ["flags"],
        ["power_down_interval"], ["ptt_cmos_offset0"], ["ptt_cmos_offset1"],
        [], ["acpi_base_offset"], ["prwm_base_offset", "0x%x"],
        ["reserved1"], ["reserved2"], ["reserved3"], ["reserved4"], ["reserved5"],
        ["hashes"], ["segments"],
    ]

# See: https://dannyodler.medium.com/intel-boot-of-trust-2020-6385e72aeab0
# ----------------------------------------------------------------------------------------
class PDRSRecord(FirmwareStructure):
    """
    Wild guessing because the structure doesn't appear to be documented.
    """

    label = "PDRS Record"

    definition = Struct(
        "_data" / Bytes(8),
        "data" / Computed(lambda ctx: ctx._data.hex()),
    )

# ----------------------------------------------------------------------------------------
class PDRSElement(FirmwareStructure):
    """
    Wild guessing because the structure doesn't appear to be documented.
    """

    label = "PDRS Element"

    definition = Struct(
        "magic" / Const(b'__PDRS__'),
        "version" / Int8ul,
        # Size of remaining data including the alignment padding?
        "size" / Int16ul,
        # Alignment padding?
        "u1" / Int8ul,
        # Maybe a
        "records" / FixedLength(this.size - 1, GreedyRange(Class(PDRSRecord))),
    )

    reporting = [
        ["magic"], ["version", "0x%x"], ["size"], ["u1"],
        [], ["records"],
    ]

# ----------------------------------------------------------------------------------------
class PlatformConfigDataElement(FirmwareStructure):

    label = "Platform Config Data Element"

    definition = Struct(
        "magic" / Const(b'__PCDS__'),
        "version" / Int8ul,
        "reserved1" / Int8ul,
        "element_size" / Int16ul,
        "reserved2" / Int16ul,
        "size" / Int16ul,
        "pdrs" / FixedLength(this.size, Select(
            Class(PDRSElement), Class(HexDump))),
    )

    reporting = [
        ["magic"], ["version", "0x%x"], ["element_size"], ["size"],
        ["reserved1"], ["reserved2"],
    ]

# ----------------------------------------------------------------------------------------
class IBBSDatav10(FirmwareStructure):

    label = "Initial Boot Block (IBB) Data"

    definition = Struct(
        "ibb_mch_bar" / Int64ul,
        "failure" / Commit(Class(MysteryHexPeek)),
        "vtd_bar" / Int64ul,
        "dma_prot_base0" / Int32ul,
        "dma_prot_limit0" / Int32ul,
        "dma_prot_base1" / Int64ul,
        "dma_prot_limit1" / Int64ul,

        "zeros" / FixedLength(36, Class(MysteryBytes)),
        "ibb_entry_point" / Int32ul,
        "hash" / Class(SHAXHashStructure),
        "segments" / Class(IBBSegmentList),
    )

    reporting = [
        ["ibb_mch_bar", "0x%x"], ["vtd_bar", "0x%x"],
        [], ["dma_prot_base0", "0x%x"], ["dma_prot_limit0", "0x%x"],
        [], ["dma_prot_base1", "0x%x"], ["dma_prot_limit1", "0x%x"],
        [], ["ibb_entry_point", "0x%x"], ["zeros"], ["hash"], ["segments"],
    ]

# ----------------------------------------------------------------------------------------
class MSGStuff(FirmwareStructure):
    """
    This seems to be some kind of corruption in the file.  Or perhaps someone has
    overwritten sensitive data?
    """

    label = "MSG Stuff"

    definition = Struct(
        "_magic" / FailPeek(Const(b'\xff')),
        "_ff_padding1" / GreedyRange(Const(b'\xff')),
        "ffpad1" / Computed(lambda ctx: len(ctx._ff_padding1)),
        "magic" / Const(b'MSG__'),
        "version" / Int8ul,
        "u1" / Int8ul,
        "u2" / Int16ul,
        "u3" / Int32ul,
        "u4" / Int32ul,
        "_ff_padding2" / GreedyRange(Const(b'\xff')),
        "ffpad2" / Computed(lambda ctx: len(ctx._ff_padding2)),
    )

    reporting = [
        ["magic"], ["version", "0x%x"],
        ["u1"], ["u2"], ["u3", "0x%x"], ["u4", "0x%x"], ["ffpad1"], ["ffpad2"],
    ]

# ----------------------------------------------------------------------------------------
class ACMBootGuardPolicyIBBSv10(FirmwareStructure):

    label = "Initial Boot Block (IBB) Segments?"

    definition = Struct(
        "magic" / Const(b'__IBBS__'),
        "version" / Const(0x10, Int8ul),
        "failure" / Commit(Class(MysteryHexPeek)),
        "reserved0" / Int8ul,
        "element_size" / Int16ul,  # Sometimes 0?
        "flags" / Int32ul,
        # Data is supposed to be an IBBSDatav10 structure, but sometimes it's corrupt?
        "data" / Select(Class(MSGStuff), Class(IBBSDatav10)),
    )

    reporting = [
        ["magic"], ["version", "0x%x"], ["element_size"], ["flags", "0x%x"],
    ]

# ----------------------------------------------------------------------------------------
class ACMBootGuardPolicyIBBSv20(FirmwareStructure):

    label = "Initial Boot Block (IBB) Segments?"

    definition = Struct(
        "magic" / Const(b'__IBBS__'),
        "version" / Const(0x20, Int8ul),
        "failure" / Commit(Class(MysteryHexPeek)),
        "reserved0" / Int8ul,
        "element_size" / Int16ul,  # ~300 bytes?
        "reserved1" / Int8ul,
        "set_type" / Int8ul,
        "reserved2" / Int8ul,
        "pbet_value" / Int8ul,  # 15?

        "flags" / Int32ul,  # 0x13?

        "ibb_mch_bar" / Int64ul,      # Often 0xfed10000
        "vtd_bar" / Int64ul,          # Often 0xfed91000
        "dma_prot_base0" / Int32ul,   # Often 0x100000, sometimes 0
        "dma_prot_limit0" / Int32ul,  # Often 0xf00000, sometimes 0
        "dma_prot_base1" / Int64ul,   # Often 0x100000000, sometimes 0
        "dma_prot_limit1" / Int64ul,  # Often 0xf00000000, sometimes 0

        "u1" / Int32ul,
        "ibb_entry_point" / Int32ul,  # Often 0xFFFFFFF0
        "hashes" / Class(HashList),
        "obb_hash" / Class(SHAXHashStructure),
        "reserved3" / Bytes(3),
        "segments" / Class(IBBSegmentList),

    )

    reporting = [
        ["magic"], ["version", "0x%x"], ["element_size"], ["flags", "0x%x"],
        ["set_type"], ["pbet_value"],
        [], ["ibb_mch_bar", "0x%x"], ["vtd_bar", "0x%x"],
        [], ["dma_prot_base0", "0x%x"], ["dma_prot_limit0", "0x%x"],
        ["dma_prot_base1", "0x%x"], ["dma_prot_limit1", "0x%x"],
        [], ["reserved0"], ["reserved1"], ["reserved2"], ["reserved3"],
        ["u1"], ["ibb_entry_point", "0x%x"],
        ["hashes"], ["obb_hash"], ["segments"],
    ]

# ----------------------------------------------------------------------------------------
class ACMBootGuardPolicy(FirmwareStructure):

    label = "ACM Boot Guard Policy (ACBP)"

    definition = Struct(
        "magic" / Const(b'__ACBP__'),
        "failure" / Commit(Class(MysteryHexPeek)),

        # Structure BOOT_POLICY_MANIFEST_HEADER
        "version" / Int8ul,
        "header_version" / Int8ul,
        "size" / Int16ul,
        "key_sig_offset" / Int16ul,
        # Wildly guessing about _which_ dword was not present for version 0x10.
        "bpm_revision" / If(this.version > 0x10, Int8ul),
        "bpm_revocation" / If(this.version > 0x10, Int8ul),
        "acm_revocation" / If(this.version > 0x10, Int8ul),
        "reserved" / If(this.version > 0x10, Int8ul),
        "nem_pages" / Int16ul,

        #    # Are the __IBBS__, __PCDS__, __PMSG__, and __TXTS__ really records after __ACBP__?
        #    "ibbs" / Select(
        #        Class(ACMBootGuardPolicyIBBSv10),
        #        Class(ACMBootGuardPolicyIBBSv20)),
        #
        #    # These may in fact NOT be optional, but I mad them optional because they're
        #    # clearly identified by magic headers.
        #    "txt" / Opt(Class(TXTElement)),
        #    "pcds" / Opt(Class(PlatformConfigDataElement)),
        #    "pmsg" / Opt(Class(BootGuardPMSG)),

        # When processed in the context of a "SpecialMemoryBlock" this happens
        # automatically.
        #"_ff_padding1" / GreedyRange(Const(b'\xff')),
        #"ffpad1" / Computed(lambda ctx: len(ctx._ff_padding1)),
        #"unexpected" / Class(MysteryBytes),
    )

    reporting = [
        ["magic"], ["version", "0x%x"], ["header_version", "0x%x"], ["size"],
        ["key_sig_offset"],
        [], ["bpm_revision"], ["bpm_revocation"], ["acm_revocation"], ["nem_pages"],
        ["reserved"],
        # ["ibbs"], ["txt"], ["pcds"], ["pmsg"],
    ]

# ----------------------------------------------------------------------------------------
class BootGuardKeyManifest1(FirmwareStructure):

    label = "Key Manifest v1 (__KEYM__)"

    definition = Struct(
        "magic" / Const(b'__KEYM__'),
        "version" / Int8ul,
        Check(this.version < 0x20),
        "failure" / CommitMystery,

        # It appears that the three reserved bytes in version 0x20 are really the only
        # bytes in version 0x16.  I'm arbitrarily guessing that the fields are
        # km_revision, km_svn, and manifest_id for right now.

        "km_revision" / Int8ul,
        "km_svn" / Int8ul,
        "manifest_id" / Int8ul,

        "hash" / Class(SHAXHashStructure),

        # If the hash structure is present, but is all FF bytes, there's no
        "keysig" / If(lambda ctx: (ctx.hash is not None
                                   and ctx.hash.hash_value != b'\xff' * ctx.hash.hash_size),
                      Class(BootGuardKeyAndSignature)),

        # Some files are padded with zeros.
        "_zeros" / Opt(Const(b'\x00' * 3519)),
        "padding" / Computed(lambda ctx: 0 if ctx._zeros is None else len(ctx._zeros)),

        #"unexpected" / Until(b'\xff'*16, Class(MysteryBytes)),
    )

    reporting = [
        ["magic"], ["version", "0x%x"],
        ["km_revision", "0x%x"], ["km_svn"], ["manifest_id"], ["padding"],
        ["hash"],
    ]

# File 14bd277d5475e30fbc32f61c3649a351 has lots of FFs in strange places.

# Key Manifest v1 (__KEYM__): magic=b'__KEYM__', version=0x10, km_revision=0x10, km_svn=0,
#    manifest_id=1, hash_algo=BootGuardHashAlgorithm.SHA256, hash_size=32,
#    hash_value_hex=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, keysig=None,

# Key Manifest (__KEYM__): magic=b'__KEYM__', version=0x21, km_revision=0x1, km_svn=0,
#    manifest_id=15, pub_key_hash_algo=BootGuardHashAlgorithm.SHA384, key_count=1,
#    key_sig_offset=0x54, usage=1, reserved1=b'\x00\x00\x00', reserved2=b'\x00\x00\x00', u1=b'',

# ----------------------------------------------------------------------------------------
class BootGuardKeyManifest2(FirmwareStructure):

    label = "Key Manifest v2 (__KEYM__)"

    definition = Struct(
        #"_startpos" / Tell,
        "magic" / Const(b'__KEYM__'),
        "version" / Int8ul,
        Check(this.version >= 0x20),
        "failure" / CommitMystery,

        # These three bytes were used in the BootGuardKeyManifest version 0x10, and are
        # ignored in version 0x20 and later?  Then the new-style values come after?
        "reserved1" / Bytes(3),
        "key_sig_offset" / Int16ul,
        "reserved2" / Bytes(3),
        "km_revision" / Int8ul,
        "km_svn" / Int8ul,
        "manifest_id" / Int8ul,
        "pub_key_hash_algo" / EnumAdapter(Int16ul, BootGuardHashAlgorithm),

        # I've never seen this be greater than one.  Presumably controls number of keysigs?
        "key_count" / Int16ul,

        # Begin SHAX_KMHASH_STRUCT
        "usage" / Int64ul,  # Usually 1?
        # Begin SHAX_HASH_STRUCTURE
        "hash" / Class(SHAXHashStructure),

        # Should be empty.
        "u1" / Bytes(lambda ctx: max(0, ctx.key_sig_offset - (36 + ctx.hash.hash_size))),

        # RSA_PUBLIC_KEY_STRUCT;
        "keysig" / Class(BootGuardKeyAndSignature),

        # Bug! Should be mystery bytes.
        "unexpected" / Until(b'\xff' * 16, Class(HexDump)),
    )

    reporting = [
        ["magic"], ["version", "0x%x"], ["key_sig_offset", "0x%x"],
        ["km_revision", "0x%x"], ["km_svn"], ["manifest_id"],
        [], ["pub_key_hash_algo"], ["key_count"],
        ["usage"], ["reserved1"], ["reserved2"], ["u1"],
    ]


# ----------------------------------------------------------------------------------------
class BootGuardRecord(FirmwareStructure):
    """
    Consume one self-identifying Boot Guard record based on leading magic and version.

    External API to this module for "Special Memory Block" structures.
    """

    label = "Boot Guard Record"

    definition = Struct(
        "record" / Select(
            Class(BootGuardKeyManifest1),
            Class(BootGuardKeyManifest2),
            Class(ACMBootGuardPolicy),
            Class(ACMBootGuardPolicyIBBSv10),
            Class(ACMBootGuardPolicyIBBSv20),
            Class(TXTElement),
            Class(PlatformConfigDataElement),
            Class(BootGuardPMSG),
            Class(FITable),
        )
    )

    reporting = [["record"]]

# ----------------------------------------------------------------------------------------
class BootGuardAlignedRecord(FirmwareStructure):
    """
    Kind of like "Special Memory Blocks", this structure consumes a group of structures in
    ROM memory that's not well bounded in a UEFI filesystem.  Specifically, it often
    consumes bytes in a filesysdtem file of type FFSFileType.FFPad.
    """

    label = "Boot Guard Aligned Record"

    definition = Struct(
        "_ff_padding" / GreedyRange(Const(b'\xff')),
        "ff_len" / Computed(lambda ctx: len(ctx._ff_padding)),
        "record" / Select(
            Class(BootGuardKeyManifest1),
            Class(BootGuardKeyManifest2),
            Class(ACMBootGuardPolicy),
            # These are usually immediately adjacent to the ACMBootGuard Policy, and so
            # are not technically "aligned" records.
            Class(ACMBootGuardPolicyIBBSv10),
            Class(ACMBootGuardPolicyIBBSv20),
            Class(TXTElement),
            Class(PlatformConfigDataElement),

            Class(BootGuardPMSG),
            Class(FITable),
            #Class(MysteryBytes),
        ),
    )

    reporting = [["ff_len"], ["record"]]

# ----------------------------------------------------------------------------------------
class BootGuardRecords(FirmwareStructure):

    label = "Boot Guard Records"

    definition = Struct(
        # Usually in the order:
        #   Key Manifest (version 1 or 2)
        #   ACMBootGuardPolicy
        #     ACMBootGuardPolicyIBBS (version 1 or 2)
        #     TXTElement (optional?)
        #     PlatformConfigDataElement (optional?)
        #   BootGuardPMSG
        #   Firmware Interface Table (optional)
        "records" / OneOrMore(Class(BootGuardAlignedRecord))
    )

    reporting = [["records"]]

# ----------------------------------------------------------------------------------------
class BootGuardFile(FirmwareStructure):
    """
    One or more Boot Guard records with defensive consumption of the remaining bytes.

    For use in the context where we know where the end of the current
    """
    label = "Boot Guard File"

    definition = Struct(
        "records" / OneOrMore(Class(BootGuardAlignedRecord)),
        "_ff_padding" / GreedyRange(Const(b'\xff')),
        "ff_len" / Computed(lambda ctx: len(ctx._ff_padding)),
        "unexpected" / Class(MysteryBytes),
    )

    reporting = [["ff_len"], ["records"]]

# ----------------------------------------------------------------------------------------
class ACMChipsetID(FirmwareStructure):
    """
    An ACM chipset ID.

    Documented in 315168_TXT_MLE_Development Guide_rev_017_3-2.pdf, Appendix A, Table 12.
    """
    label = "ACM Chipset ID"

    definition = Struct(
        "flags" / Int32ul,
        "vendor" / Int16ul,
        "device" / Int16ul,
        "revision" / Int16ul,
        "reserved" / Bytes(6),
    )

    reporting = [
        ["flags"], ["vendor", "0x%x"], ["device", "0x%x"], ["revision"], ["reserved"],
    ]

# ----------------------------------------------------------------------------------------
class ACMChipsetIDList(FirmwareStructure):
    """
    A list of chipset IDs.

    Documented in 315168_TXT_MLE_Development Guide_rev_017_3-2.pdf, Appendix A, Table 11.
    """
    label = "ACM Chipset ID List"

    definition = Struct(
        "count" / Int32ul,
        "chipsets" / Array(this.count, Class(ACMChipsetID)),
    )

    reporting = [["count"], ["chipsets"]]

# ----------------------------------------------------------------------------------------
class ACMProcessorID(FirmwareStructure):
    """
    An ACM processor ID.

    Documented in 315168_TXT_MLE_Development Guide_rev_017_3-2.pdf, Appendix A, Table 14.
    """
    label = "ACM Processor ID"

    definition = Struct(
        "fms" / Int32ul,
        "fms_mask" / Int32ul,
        "platform" / Int64ul,
        "platform_mask" / Int64ul,
    )

    reporting = [
        ["fms", "0x%x"], ["fms_mask", "0x%x"],
        ["platform", "0x%x"], ["platform_mask", "0x%x"],
    ]

# ----------------------------------------------------------------------------------------
class ACMProcessorIDList(FirmwareStructure):
    """
    A list of processor IDs.

    Documented in 315168_TXT_MLE_Development Guide_rev_017_3-2.pdf, Appendix A, Table 13.
    """
    label = "ACM Processor ID List"

    definition = Struct(
        "count" / Int32ul,
        "processors" / Array(this.count, Class(ACMProcessorID)),
    )

    reporting = [["count"], ["processors"]]

# ----------------------------------------------------------------------------------------
class ACMTPMInfoList(FirmwareStructure):
    """
    A list of processor IDs.

    Documented in 315168_TXT_MLE_Development Guide_rev_017_3-2.pdf, Appendix A, Table 13.
    """
    label = "ACM TPM Info List"

    definition = Struct(
        "capabilities" / Int32ul,
        "count" / Int16ul,
        "_algorithms" / Array(this.count, Int16ul),
        "algorithms" / Computed(lambda ctx: [TPMAlgorithm(x) for x in ctx._algorithms])
    )

    reporting = [["capabilities"], ["count"], ["algorithms"]]

# ----------------------------------------------------------------------------------------
# Measured Launch Environment GUID (reminder to watch for this GUID)
# 315168_TXT_MLE_Development Guide_rev_017_3-2.pdf, Section 2.1, Table 3
ACM_MLE_GUID = UUID('5aac8290-6f47-a774-0f5c-55a2cb51b642')

# ----------------------------------------------------------------------------------------
ACM_INFO_GUID = UUID('aa3ac07f-a746-db18-2eac-698f8d417f5a')
class ACMInformationTable(FirmwareStructure):
    """
    ACM Information Table (including the actual executable code).

    Documented in 315168_TXT_MLE_Development Guide_rev_017_3-2.pdf, Appendix A, Section
    A.1.2, Table 10.
    """

    label = "ACM Information Table"

    definition = Struct(
        # This GUID is unusually in Big-Endian order.
        "_guid" / Bytes(16),
        "guid" / Computed(lambda ctx: UUID(bytes=ctx._guid)),
        Check(this.guid == ACM_INFO_GUID),
        "failure" / CommitMystery,
        "_chipset" / Int8ul,
        "chipset" / Computed(lambda ctx: ACMChipsetType(ctx._chipset)),
        "version" / Int8ul,
        "size" / Int16ul,
        "chipset_offset" / Int32ul,
        "os_sinit_ver" / Int32ul,
        "min_mle" / Int32ul,
        "capabilities" / Int32ul,
        "acm_version" / Int32ul,
        "processor_offset" / Int32ul,
        "tpm_offset" / If(this.version >= 5, Int32ul),
        "acm_info_tables" / If(this.version >= 9, Int32ul),

        # Technically at chipset_offset.
        "chipsets" / Class(ACMChipsetIDList),
        # Technically at processor_offset.
        "processors" / Class(ACMProcessorIDList),
        # Technically at tpm_offset.
        "tpm_info" / If(this.version >= 5, Class(ACMTPMInfoList)),

        "code" / Class(MysteryBytes),
    )

    reporting = [
        ["guid"], ["chipset"], ["version"], ["size"],
        ["os_sinit_ver"], ["min_mle"], ["capabilities", "0x%x"], ["acm_version", "0x%x"],
        [], ["chipset_offset"], ["processor_offset"], ["tpm_offset"],
        ["chipsets"], ["processors"], ["tpm_info"], ["code"],
    ]

    def analyze(self) -> None:
        if self.code is not None:
            self.code.label = "Executable Code"

# ----------------------------------------------------------------------------------------
class ACMOldProcessor(FirmwareStructure):
    label = "ACM Old Processor"

    definition = Struct(
        "fms" / Int32ul,
        "fms_mask" / Int32ul,
    )

    reporting = [["fms", "0x%x"], ["fms_mask", "0x%x"]]

# ----------------------------------------------------------------------------------------
class ACMOldInfoTable(FirmwareStructure):
    """
    This appears to be an even older version of the ACM Information Table.  Notably, it
    does NOT begin with the required GUID.  After spending some time on this, it looks
    like these bytes were interpreted however the ACM code chose to interpret them.  My
    guess is that that this was the convention that preceeded the standardized
    ACMInformationTable, which was eventually by the "Flexible ACM Information Table"
    format.

    Manually reverse-engineered to fit existing data (partially, but then abandonded).
    """

    label = "ACM Old Information Table"

    definition = Struct(
        "u1" / Int32ul,
        "u2" / Int32ul,
        "u3" / Int32ul,
        "u4" / Int32ul,
        "chipsets" / Class(ACMChipsetIDList),
        # Zeros?
        "pad1" / FixedLength(64, Class(MysteryBytes)),
        "proc_count" / Int32ul,
        "processors" / Array(this.proc_count, Class(ACMOldProcessor)),
        "pad2" / FixedLength(40, Class(MysteryBytes)),
        "u5" / Array(3, Class(ACMOldProcessor)),
        "_zeros" / GreedyRange(Const(b'\x00')),
        "zeros" / Computed(lambda ctx: len(ctx._zeros)),
        "code" / Class(MysteryBytes),
    )

    reporting = [
        ["u1", "0x%x"], ["u2"], ["u3"], ["u4"], ["zeros"],
        ["chipsets"], ["processors"], ["u5"], ["code"],
    ]

    def analyze(self) -> None:
        if self.code is not None:
            self.code.label = "Executable Code"

# ----------------------------------------------------------------------------------------
class AuthenticationCodeModule(FirmwareStructure):
    """
    Authenticated Code Module

    Documented in 315168_TXT_MLE_Development Guide_rev_017_3-2.pdf, Appendix A, Table 8.
    """

    label = "Authentication Code Module (ACM)"

    definition = Struct(
        # Read all bytes into a buffer since the "base address" of the ACM starts here.
        "raw" / Peek(GreedyBytes),
        # This is pretty weak magic for this data structure.
        "module_type" / Const(2, Int16ul),
        "module_sub_type" / Int16ul,
        # Should be 161=0x00a1 for 0.0, 224=0x00e0 for 3.0, of 928=0x03a0 for 4.0
        "header_length" / Int32ul,
        "header_version" / Int32ul,
        "chipset" / Int16ul,
        "flags" / Int16ul,  # Bit 14 is pre-production, bit 15 is debug
        "module_vendor" / Int32ul,  # Usually 0x8086
        "date" / Int32ul,  # BCD
        "size" / Int32ul,  # In dwords
        # TXT Security Version Number
        "txt_svn" / Int16ul,
        # Software Guard Extensions (Secure Enclaves) Security Version Number
        "sgx_svn" / Int16ul,
        # Authenticated code control flags
        "code_control" / Int32ul,
        # Error response entry point offset (bytes)
        "error_entry_point" / Int32ul,
        # GDT limit (defines last byte of GDT)
        "gdt_limit" / Int32ul,
        # GDT base pointer offset (bytes)
        "gdt_base_ptr" / Int32ul,
        # Segment selector initializer
        "seg_sel" / Int32ul,
        # Authenticated code entry point offset (bytes)
        "entry_point" / Int32ul,
        # Reserved for future extensions
        "reserved" / FixedLength(64, Class(MysteryBytes)),
        # Module public key size less then exponent (dwords),  64 or 96
        "key_size" / Int32ul,
        # Scratch field size (dwords), 143, 208 or 896
        "scratch_size" / Int32ul,
        "rsa_pub_key" / FixedLength(this.key_size * 4, Class(MysteryBytes)),
        "rsa_exponent" / If(this.header_version == 0, Int32ul),
        "rsa_sig" / FixedLength(this.key_size * 4, Class(MysteryBytes)),

        # "xmss_pub_key" / If(this.header_version >= 4, FixedLength(64, Class(MysteryBytes))),
        # "xmss_sig" / If(this.header_version >= 4, FixedLength(2692, Class(MysteryBytes))),
        # "reserved3" / If(this.header_version >= 4, FixedLength(60, Class(MysteryBytes))),

        "scratch" / FixedLength(this.scratch_size * 4, Class(MysteryBytes)),

        "code" / Select(Class(ACMInformationTable),
                        Class(ACMOldInfoTable),
                        Class(HexDump)),
    )

    reporting = [
        ["module_type"], ["module_sub_type"], ["header_length"], ["header_version", "0x%x"],
        ["chipset", "0x%x"], ["flags", "0x%x"], ["module_vendor", "0x%x"],
        [], ["date", "0x%x"], ["txt_svn"], ["sgx_svn"], ["code_control"],
        ["error_entry_point"], ["gdt_limit"], ["gdt_base_ptr", "0x%x"], ["seg_sel"],
        ["entry_point", "0x%x"], ["md5"],
        [], ["key_size"], ["scratch_size"], ["size"], ["rsa_exponent"],
        [], ["rsa_pub_key"],
        [], ["rsa_sig"],
        [], ["scratch"],
        [], ["reserved"],
        ["raw", None],
    ]

    def analyze(self) -> None:
        self.rsa_pub_key.label = "RSA Public Key"
        self.rsa_sig.label = "RSA Signature"
        self.scratch.label = "ACM Scratch Area (Mystery Bytes)"
        self.reserved.label = "ACM Reserved (Mystery Bytes)"

        hasher = hashlib.md5()
        hasher.update(self.raw)
        self.md5 = hasher.hexdigest()

        if False:
            filename = 'acm-code-analysis/binary/acm-code-%s.dat' % self.md5
            if not os.path.exists(filename):
                fh = open(filename, "wb")
                fh.write(self.raw)
                fh.close()

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
