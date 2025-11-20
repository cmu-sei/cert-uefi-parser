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
Some assistsance for mypy.
"""

import functools
from typing import Optional, Union
from collections.abc import Callable

from mypy.options import Options
from mypy.plugin import Plugin, AttributeContext
from mypy.types import Type, Instance, AnyType
from mypy.nodes import TypeInfo
from mypy.messages import format_type
from mypy.errorcodes import ATTR_DEFINED
# find_member(attr, generic_type, generic_type)

# https://www.youtube.com/watch?v=tH3Nul6jDQM
from construct import Construct

def enumerate_firmware_structures() -> dict[str, dict[str, Union[Construct, property]]]:
    import uefi_parser.acpi
    import uefi_parser.amd
    import uefi_parser.ami
    import uefi_parser.apple
    import uefi_parser.asn1
    import uefi_parser.auto
    import uefi_parser.base
    import uefi_parser.bgscript
    import uefi_parser.bootguard
    import uefi_parser.coreboot
    import uefi_parser.dxedep
    import uefi_parser.efiguid
    import uefi_parser.exes
    import uefi_parser.finder
    import uefi_parser.fit
    import uefi_parser.flash
    import uefi_parser.fsp
    import uefi_parser.gecko
    import uefi_parser.icon
    import uefi_parser.lua
    import uefi_parser.me
    import uefi_parser.mystery
    import uefi_parser.nvvars
    import uefi_parser.pfs
    import uefi_parser.sbom
    import uefi_parser.smbios
    import uefi_parser.test_construct
    import uefi_parser.tpm
    import uefi_parser.uefi
    import uefi_parser.uenum
    import uefi_parser.vendor  # noqa

    import inspect
    import sys
    from uefi_parser.base import FirmwareStructure, Struct

    answers: dict[str, dict[str, Union[Construct, property]]] = {}
    for module_name, module_handle in sys.modules.items():
        if not module_name.startswith("uefi_parser"):
            continue
        #log.debug(f"Inspecting: {module_name} {module_handle}")
        for cls_name, cls_obj in inspect.getmembers(module_handle, inspect.isclass):
            if not cls_obj.__module__.startswith(module_name):
                continue
            if not issubclass(cls_obj, FirmwareStructure):
                continue
            #log.debug(f"Found FirmwareStructure subclass: {cls_name} {cls_obj}")
            try:
                definition = getattr(cls_obj, "definition")
            except AttributeError:
                # The base class and intermediates (e.g. HashedFirmwareStructure) don't
                # have definitions.
                pass

            if not isinstance(definition, Struct):
                #log.debug(f"{cls_name} definition was NOT a Struct! {type(definition)}")
                continue

            cls_path = module_name + "." + cls_name
            answers[cls_path] = {}
            for field in definition.by_name:
                answers[cls_path][field] = definition.by_name[field]
                #log.debug(f"Adding: [{cls_path}][{field}] = ?")

            # We also need to add the properties on the class...
            for prop_name, prop_obj in inspect.getmembers(cls_obj):
                if isinstance(prop_obj, property):
                    answers[cls_path][prop_name] = prop_obj

    return answers

#def construct_to_mypy_type(ctx: AttributeContext, cons: Construct) -> Optional[Type]:
#    import construct.core  # type: ignore
#    import uefi_parser.base
#    from uuid import UUID
#
#    # The type of a Const object, is the type of the Subconstruct?
#    #if isinstance(cons, construct.core.Const):
#    #    cons = cons.subcon
#    ctype = type(cons)
#
#    int_type = ctx.api.lookup_fully_qualified_type("builtins.int")
#    bytes_type = ctx.api.lookup_fully_qualified_type("builtins.bytes")
#    log.debug(f"Evaluating type {cons} {type(cons)}")
#
#    type_map = {
#        construct.core.FormatField: int_type,
#        construct.core.BytesInteger: int_type,
#        construct.core.Bytes: bytes_type,
#        construct.core.GreedyBytes: bytes_type,
#        construct.core.Tell: int,
#        construct.core.Array: list,  # List of what?
#        construct.core.GreedyRange: list,  # List of what?
#        uefi_parser.base.Class: uefi_parser.base.FirmwareStructure,
#        uefi_parser.base.UUIDAdapter: UUID,
#        uefi_parser.base.HexBytesAdapter: str,
#        uefi_parser.base.Commit: None,
#        uefi_parser.base.FailPeek: None,
#    }
#
#    if ctype in type_map:
#        return type_map[ctype]
#    else:
#        log.debug(f"Type failure {ctype}")
#        pass
#
#    return None

class MyPlugin(Plugin):

    def __init__(self, options: Options) -> None:
        super().__init__(options)
        self.constructs = enumerate_firmware_structures()

    def get_attribute_hook(
            self, fullname: str
    ) -> Optional[Callable[[AttributeContext], Type]]:

        if fullname.startswith('uefi_parser.'):
            return functools.partial(self._my_attribute_hook, attr=fullname)
        return None

    def _my_attribute_hook(self, ctx: AttributeContext, *, attr: str) -> Type:
        attr_name = attr.split('.')[-1]

        # The Type could be a Union instead of an Instance.
        if not isinstance(ctx.type, Instance):
            #log.debug(f"Strange case: {attr_name} {ctx}")
            return ctx.default_attr_type

        # The TypeInfo for the class we're being asked about.
        cls_type_info = ctx.type.type
        assert isinstance(cls_type_info, TypeInfo), cls_type_info

        # If there are no base classes, it's not a FirmwareStructure
        if len(cls_type_info.bases) < 1:
            return ctx.default_attr_type

        is_firmware_struct = False
        for base in cls_type_info.bases:
            if base.type.fullname == 'uefi_parser.base.FirmwareStructure':
                is_firmware_struct = True
                break

        if not is_firmware_struct:
            return ctx.default_attr_type

        #log.debug(f"Is {attr_name} in {cls_type_info.fullname}... ")
        if cls_type_info.fullname in self.constructs:
            if attr_name in self.constructs[cls_type_info.fullname]:
                #construct = self.constructs[cls_type_info.fullname]
                #mypy_type = construct_to_mypy_type(ctx, construct)
                #if mypy_type is not None:
                #    return mypy_type
                return ctx.default_attr_type

        if isinstance(ctx.default_attr_type, AnyType):
            ctx.api.fail(
                f'{format_type(ctx.type, ctx.api.options)} has no attribute "{attr_name}"',
                ctx.context, code=ATTR_DEFINED)

        return ctx.default_attr_type

def plugin(version: str) -> type[MyPlugin]:
    return MyPlugin

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
