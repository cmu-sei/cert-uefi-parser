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
Command line utility code for CERT UEFI Parser.
"""

import argparse
import json
import logging
import sys
from typing import Optional

from .base import FirmwareStructure
from .auto import AutoObject, BruteForceFinder
from .utils import red, blue

# Hacky solution for --no-color option, using a global.
nocolor = False

log = logging.getLogger("cert-uefi-parser")

def process_file(filename: str, args: argparse.Namespace) -> bool:
    emit = print  # Print is generally banned from use in CERT UEFI parser.
    if args.text:
        emit("%s %s" % (blue("File:"), red(filename)))

    try:
        with open(filename, 'rb') as fh:
            input_data = fh.read()
    except Exception as e:
        log.error("Error: Cannot read file (%s) (%s)." % (filename, str(e)))
        return False

    result: Optional[FirmwareStructure] = None
    # A hard code brute force approach if the user requested it...
    if args.brute:
        result = BruteForceFinder.parse(input_data, 0)
        if result is None or len(result.found) == 0:
            log.error("Brute forcing found nothing!")
            return False
    else:
        auto_result = AutoObject.parse(input_data, 0)
        if auto_result is None or auto_result.auto is None:
            log.error("AutoObject result was none!")
            return False
        else:
            result = auto_result.auto

    if result is None:
        return False

    if result is not None:
        if args.json:
            emit(json.dumps(result.to_dict(True), indent=2))
        elif args.sbom:
            emit(json.dumps(result.sbom(), indent=2))
        elif args.gui:
            try:
                from .gui import run_gui
            except ImportError:
                print("GUI mode requires the optional 'qt' dependency:")
                print("    pip install uefi_parser[qt]")
                return False
            run_gui(result, args)
        else:
            result.report()

    # This code is half baked.  It needs to be invoked per file because it catalogs the
    # existence of the guid in the file.  But in it's current form it's incompatible with
    # multiple file parameters on the same invocaiton of the program.  It's also unclear
    # how it interacts with other modes of operation like extract, etc.
    #if args.updatedb:
    #    update_database(filename)

    return True

def cert_uefi_parser() -> None:
    argparser = argparse.ArgumentParser(
        description="Parse the contents of a UEFI-related firmware file.")

    mode = argparser.add_argument_group(
        "Output mode", description="Choose one of the output modes")
    exmode = mode.add_mutually_exclusive_group(required=True)
    exmode.add_argument(
        '-g', "--gui", default=False, action="store_true",
        help="display the gui")
    exmode.add_argument(
        '-t', "--text", default=False, action="store_true",
        help="output in ASCII text format")
    exmode.add_argument(
        '-j', "--json", default=False, action='store_true',
        help="output in JSON format")
    exmode.add_argument(
        '-s', "--sbom", default=False, action='store_true',
        help="output SBOM data in JSON format")

    argparser.add_argument(
        '--verbose', default=False, action='store_true',
        help='enable verbose logging while parsing')
    argparser.add_argument(
        '-n', "--no-color", default=False, action="store_true",
        help="do not use ANSI colors in text output mode")
    argparser.add_argument(
        '-b', "--brute", default=False, action="store_true",
        help='brute force search the input file for known objects')
    argparser.add_argument(
        "--debug-gui", default=False, action="store_true", help=argparse.SUPPRESS)

    # Disable some options that aren't fully implemented or working yet.
    #argparser.add_argument(
    #    '-e', "--extract", action="store_true",
    #    help="Extract all files/sections/volumes.")
    #argparser.add_argument(
    #    '-o', "--output", default=".",
    #    help="Dump firmware objects to this folder.")
    #argparser.add_argument(
    #    '-g', "--generate", default=None,
    #    help="Generate a FDF, implies extraction (volumes only)")
    #argparser.add_argument(
    #    '-u', "--updatedb", default=False, action='store_true',
    #    help="Update the guid database")
    #argparser.add_argument(
    #    '-q', "--quiet", default=False, action="store_true",
    #    help="do not show info.")

    argparser.add_argument(
        "file", help="the file to examine")
    args = argparser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    else:
        logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

    # We'll expose this module level global to the util.py module.
    # FIXME?  Using a global to control the nocolor option isn't ideal...  But it's ok?
    global nocolor
    nocolor = args.no_color
    if args.no_color and not args.text:
        log.warning("--no-color is only valid with --text")

    # Unless we're generating JSON, which always has no color.
    if args.json or args.sbom:
        nocolor = True

    try:
        succeeded = process_file(args.file, args)
        # Continue processing the next file, even if this one failed, but remeber thet
        # there were failures for when we exit.
        if not succeeded:
            sys.exit(1)
    except BrokenPipeError:
        log.warning("Broken pipe!")
        sys.exit(2)

    sys.exit(0)

# Local Variables:
# mode: python
# fill-column: 90
# End:
