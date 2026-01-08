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
ASN1 data structures.

ASN1 is far too crazy to parse with Construct, so we rely on the asn1crypto module to do
most of the heavy lifting.  This module is designed so that we get firmware structures in
the output, even if the asn1crypto module is not present.
"""

from typing import Any

from construct import GreedyBytes
from asn1crypto.x509 import Certificate
from asn1crypto.cms import SignedData, IssuerAndSerialNumber

from .base import FirmwareStructure, Struct, FakeFirmwareStructure

# ----------------------------------------------------------------------------------------
class X509_DER(FirmwareStructure):
    """
    An X509 DER encoded certificate, parsed by asn1crypto if present.

    Size is expected to be determined externally.
    """

    # Begins: 30 82 0. .. 30 82 0. .. a0 03 02 01 02 02
    # Debug with: openssl x509 -inform der -text <file.der

    label = "X509 DER Certificate"

    definition = Struct(
        "x509_der_bytes" / GreedyBytes,
    )

    reporting = [["keyid"], ["subject"], ["x509_der_bytes", None]]

    def analyze(self) -> None:
        # Ensure that fields have values.
        self.keyid = None
        self.subject = None

        # Extract fields from the X509 certificate if asn1crypto is installed.
        try:
            cert = Certificate.load(self.x509_der_bytes)
            if cert.key_identifier is not None:
                self.keyid = cert.key_identifier.hex()
            if cert.subject is not None:
                self.subject = cert.subject.human_friendly
        except ValueError as e:
            self.error("X509 certificate parsing error at 0x%x, der=%s" % (
                self._data_offset, self.x509_der_bytes[:16]))
            self.error(f"  {e}")

        # For debugging, write the DER certificate out to a file.
        if False:
            filename = "key_0x%x.der" % (self._data_offset)
            fh = open(filename, "wb")
            fh.write(self.x509_der_bytes)
            fh.close()

    def instance_name(self) -> str:
        if self.subject is not None:
            return self.subject
        if self.keyid is not None:
            return self.keyid
        return ""

# ----------------------------------------------------------------------------------------
class X509_Signature(FakeFirmwareStructure):
    """
    An X509 signature parsed by asn1crpyto if present.
    """

    label = "X509 Signature"

    definition = Struct()

    reporting = [
        ["version"], ["digest_algorithm"], ["signature_algorithm"],
        ["siglen"],
        [], ["issuer"], ["serial"],
    ]

    def __init__(self, signer: dict[str, Any]):
        super().__init__()
        # Extract data fields from the ASN parse.
        self.version = signer["version"].native
        self.digest_algorithm = signer["digest_algorithm"]['algorithm'].native
        self.signature_algorithm = signer["signature_algorithm"]['algorithm'].native
        self.issuer = None
        sid = signer["sid"].chosen
        # There's a second alternative call Subject key indentifier that's not handled.
        if isinstance(sid, IssuerAndSerialNumber):
            self.issuer = str(sid["issuer"].human_friendly)
            self.serial = int(sid["serial_number"])

        #self.issuer = .issuer"]
        self._sigbytes = bytes(signer["signature"])
        self.siglen = len(self._sigbytes)

    def instance_name(self) -> str:
        if self.issuer is not None:
            return self.issuer
        if self.serial is not None:
            return str(self.serial)
        return ""

# ----------------------------------------------------------------------------------------
class X509_SignedData(FirmwareStructure):
    """
    An X509 signed data blob.

    Size is expected to be determined externally.
    """

    label = "X509 Signed Data"

    definition = Struct(
        "x509_der_bytes" / GreedyBytes,
    )

    reporting = [["digest_algo"], ["certs"], ["x509_der_bytes", None]]

    def analyze(self) -> None:
        # Ensure that fields have values.
        self.certs = []
        self.signers = []
        self.digest_algo = None
        # Extract fields from the X509 certificate if asn1crypto is installed.
        try:
            sd = SignedData.load(self.x509_der_bytes)
            if 'certificates' in sd:
                for cert in sd['certificates']:
                    obj = X509_DER.parse(cert.chosen.dump(), 0)
                    self.certs.append(obj)
            if 'digest_algorithms' in sd:
                self.digest_algo = sd['digest_algorithms'][0]['algorithm'].native
                if len(sd['digest_algorithms']) > 1:
                    self.warn("more than one digest algorithm!")
            if 'signer_infos' in sd:
                #sd['signer_infos'].debug()
                for signer in sd['signer_infos']:
                    self.signers.append(X509_Signature(signer))
        except ModuleNotFoundError:
            pass
        except ValueError as e:
            self.error("X509 certificate parsing error at 0x%x, der=%s" % (
                self._data_offset, self.x509_der_bytes[:16]))
            self.error(f"  {e}")

        # For debugging, write the DER certificate out to a file.
        if False:
            filename = "key_0x%x.der" % (self._data_offset + 44)
            fh = open(filename, "wb")
            fh.write(self.x509_der_bytes)
            fh.close()

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
