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
EFI GUID database management.
"""

import logging
from uuid import UUID
from typing import Optional, Union, Iterator

from .utils import green, purple

log = logging.getLogger("cert-uefi-parser")

# The capitalization of these class names is a little strange.  It seemed better than just
# having a bunch of capital letter acronyms jammed together.

# ----------------------------------------------------------------------------------------
class EfiGuid(object):

    def __init__(self, guid: str, name: str, description: str = '',
                 aliases: Optional[list[str]] = None, urls: Optional[list[str]] = None,
                 vendors: Optional[list[str]] = None, filenames: Optional[list[str]] = None,
                 hashes: Optional[list[str]] = None, junk: Optional[list[str]] = None):
        # The unique guid key (a UUID object, right now just a string)
        self.guid = guid
        # Our "best" name for the guid, since there's no real authority.
        self.name = name
        # Some human commentary on the guid, if valuable.
        self.description = description
        # Other aliases for the guid, useful for googling when different vendors have
        # different names for the same GUID. :-(
        if aliases is None:
            self.aliases = []
        else:
            self.aliases = aliases
            # Reference urls, preferably github, but otehr sources as well.
        if urls is None:
            self.urls = []
        else:
            self.urls = urls
            # Vendors we've seen using the GUID (from automated BIOS inspection)
        if vendors is None:
            self.vendors = []
        else:
            self.vendors = vendors
            # Filenames associated with the GUID (from automated BIOS inspection)
        if filenames is None:
            self.filenames = []
        else:
            self.filenames = filenames
            # Hashes of particular BIOS files in the catalog.
        if hashes is None:
            self.hashes = []
        else:
            self.hashes = hashes
            # For unverified crap found during scraping?
        if junk is None:
            self.junk = []
        else:
            self.junk = junk

    def add_name(self, name: str, improve: bool = False) -> None:
        if name == self.name:
            return
        if name in self.aliases:
            return

        if improve and name.isupper() and not self.name.isupper():
            log.info(f"Changed name of '{self.guid}' from '{self.name}' to '{name}'")
            self.name = name
        else:
            log.info(f"Added alias to '{self.guid}' ('{self.name}') of '{name}'")
            self.aliases = sorted(set(self.aliases) | {name})

    def add_vendor(self, vendor: Optional[str]) -> None:
        if vendor is None or vendor == '':
            return
        if vendor not in self.vendors:
            self.vendors = sorted(set(self.vendors) | {vendor})

    def add_url(self, url: Optional[str]) -> None:
        if url is None or url == '':
            return
        if url not in self.urls:
            self.urls = sorted(set(self.urls) | {url})

    def add_filename(self, filename: Optional[str]) -> None:
        if filename is None or filename == '':
            return
        if filename not in self.filenames:
            self.filenames = sorted(set(self.filenames) | {filename})

    def add_bios_hash(self, bios_hash: Optional[str]) -> None:
        if bios_hash is None or bios_hash == '':
            return
        if bios_hash not in self.hashes:
            self.hashes = sorted(set(self.hashes) | {bios_hash})

    def as_python(self, indent: str) -> str:
        result = ""
        # header, guid, and name
        result += '%s"%s": EfiGuid(\n' % (indent, self.guid)
        indent += " " * 4
        result += '%s"%s", "%s",\n' % (indent, self.guid, self.name)

        # description
        if (self.description.find("\n") == -1
                and self.description.find('"') == -1 and len(self.description) < 80):
            result += '%sdescription = "%s",\n' % (indent, self.description)
        else:
            result += '%sdescription = """%s""",\n' % (indent, self.description)

        # aliases
        result += '%saliases = %r,\n' % (indent, self.aliases)

        # urls
        if len(self.urls) <= 1:
            result += '%surls = %r,\n' % (indent, self.urls)
        else:
            result += '%surls = [\n' % (indent)
            for url in self.urls:
                result += '%s    "%s",\n' % (indent, url)
                result += '%s],\n' % (indent)

        # vendors
        result += '%svendors = %r,\n' % (indent, self.vendors)

        # filenames
        result += '%sfilenames = %r,\n' % (indent, self.filenames)

        # hashes
        if len(self.hashes) <= 2:
            result += '%shashes = %r,\n' % (indent, self.hashes)
        else:
            result += '%shashes = [\n' % (indent)
            pos = 1
            for bios_hash in self.hashes:
                if pos % 2:
                    result += "%s    '%s'," % (indent, bios_hash)
                else:
                    result += " '%s',\n" % (bios_hash)
                    pos += 1
                    # If we were in the middle of a line, finish it.
            if pos % 2 == 0:
                result += '\n'
                result += '%s],\n' % (indent)

        # junk
        result += '%sjunk = %r),\n' % (indent, self.junk)
        return result

# ----------------------------------------------------------------------------------------
class EfiGuidDb(object):
    """
    A database of GUIDs with multiple properties describing the GUID.

    This database is not just a list of guids, but a real database of
    aliases, references, evidence, etc.  Eventually it should be converted
    to a json or SQL database, but this was convenient to get started.
    """

    def __init__(self, db: dict[str, EfiGuid]):
        # This is static database of guids scraped from the Internet, other firmware
        # images, etc.  It documents "well known guids", and is populated from the
        # hardcoded database shipped with the package.
        self.static_db = db
        # This is the dynamic database of guids found in this firmware image, so that we
        # can track guid names from file name associations, catalog new guids, etc.
        self.dynamic_db: dict[str, EfiGuid] = {}

    def get_object(self, guid: str, create: bool = True) -> Optional[EfiGuid]:
        """
        Return the guid object matching the specified UUID.

        This method looks in both the static and dynamic databases, and if found return
        the EfiGuid object.  If not found, and the create option is True (the default),
        then a new entry is created in the dynamic database and returned, resulting in
        fairly automatic tracking of guids found in the current firmware image.  If create
        is False, and the guid is not found, then None is returned.
        """
        if guid in self.static_db:
            return self.static_db[guid]
        if guid in self.dynamic_db:
            return self.dynamic_db[guid]

        gobj = None
        if create:
            gobj = EfiGuid(guid, name='', description='', aliases=None, urls=None,
                           vendors=None, filenames=None, hashes=None, junk=None)
            self.dynamic_db[guid] = gobj
        return gobj

    def add_dynamic_name(self, gstr: str, name: str) -> None:
        """
        Explicitly add the guid to the dynamic database with the specified name.

        If the guid already exists, and the name does not match the existing name, add the
        new name to the "filenames list in the guid database.
        """
        if gstr in self.dynamic_db:
            gobj = self.dynamic_db[gstr]
            if name != gobj.name:
                gobj.add_filename(name)
        else:
            gobj = EfiGuid(gstr, name)
            self.dynamic_db[gobj.guid] = gobj

    def get_name(self, guid: Union[str, UUID, bytes]) -> Optional[str]:
        """
        Return the name of a given guid.

        Currently the API is messy, accepting a wide variety of types for guid and always
        returning either a string or None.
        """
        # Cleanup for messy old API!  FIXME!
        if isinstance(guid, str):
            gstr = guid
        elif isinstance(guid, UUID):
            gstr = str(guid)
        elif isinstance(guid, bytes):
            gstr = str(UUID(bytes_le=guid))
        else:
            raise TypeError("guid_get_name called with unknown type: '%s', '%r'" % (type(guid), guid))

        gobj = self.get_object(gstr)
        if gobj is None or gobj.name == '':
            return None
        return gobj.name

    def display_name(self, guid: UUID, mode: str = 'both', color: bool = True) -> str:
        """
        Return a console-colored "display" version of the guid.

        The resulting string is ASCII colored, with the contents depending on the value of
        the 'mode' parawmeter.  If mode is 'both', which is the default setting, then the
        guid itself is green, and the name of the guid (if known) follows it in purple and
        enclosed in parentheses.  If mode is 'name' and the name is known, then only the
        name is displayed (in purple).  If mode is 'guid' or if the name is not known,
        then only the guid is displayed (in green).
        """
        # guid is a UUID
        assert mode in ['both', 'name', 'guid']
        guid_name = self.get_name(guid)
        display = str(guid)
        if color:
            display = green(display)
            if guid_name is not None:
                guid_name = purple(guid_name)
        if mode == 'both' and guid_name is not None:
            gstr = str(guid)
            if color:
                gstr = green(gstr)
            display = "%s (%s)" % (display, guid_name)
        elif mode == 'name' and guid_name is not None:
            display = guid_name
        return display

    def all_guid_objects(self) -> Iterator[EfiGuid]:
        """
        Yield all EfiGuid object from bothe the static and dynamic databases.
        """
        for gstr in self.static_db:
            yield self.static_db[gstr]
        for gstr in self.dynamic_db:
            yield self.dynamic_db[gstr]

    def scan_for_guids(self, data: bytes) -> Iterator[tuple[int, EfiGuid]]:
        """
        Given an arbitrary set of data bytes, scan for guids.

        Yields tuples of the form: (offset: int, gobj: EfiGuid).  Certain guids, including
        the zero guid and the all FFs guid are not included.
        """
        offset = 0
        while offset < len(data) - 15:
            guid = UUID(bytes_le=data[offset:offset + 16])
            gstr = str(guid)
            gobj = self.get_object(gstr, create=False)
            if gobj is not None:
                gname = gobj.name
                if gname == 'ZERO_GUID' or gname == 'ALL_FF_GUID':
                    # Some guids are too common to be useful.
                    pass
                #elif gname == '':
                #    # And some names just aren't useful
                #    pass
                else:
                    yield (offset, gobj)
            offset += 1

    def find_name(self, name: str) -> Optional[EfiGuid]:
        """
        A mostly unused API to search the static database for a specific name.

        Used for updating the guid database when information is keyed by name, and
        shouldn't generally be used in normal code.
        """
        for gstr in self.static_db:
            gobj = self.static_db[gstr]
            if gobj.name == name:
                return gobj
            if name in gobj.aliases:
                return gobj
        return None

    def write_database(self, outfile: str = "new_guiddb.py") -> None:
        """
        Write the database out as a new guiddb.py file.
        """
        fh = open(outfile, "w")
        write = print  # Print is generally banned from use in CERT UEFI parser.
        write("#!/usr/bin/env python3", file=fh)
        write("# -*- coding: utf-8 -*-", file=fh)
        write("# Copyright 2025 Carnegie Mellon University.  ", end='', file=fh)
        write("See LICENSE file for terms.", file=fh)
        write('"""', file=fh)
        write("A database of GUIDs seen in UEFI ROMs.", file=fh)
        write('"""', file=fh)
        write("", file=fh)
        write("from .efiguid import EfiGuid, EfiGuidDb", file=fh)
        write("", file=fh)
        write("GUID_DATABASE = EfiGuidDb({", file=fh)
        for guid in sorted(self.static_db):
            gobj = self.static_db[guid]
            write(gobj.as_python(" " * 4), file=fh)
        write("})", file=fh)
        write("", file=fh)
        write(f"# {'-' * 88}", file=fh)
        write("# Local Variables:", file=fh)
        write("# mode: python", file=fh)
        write("# fill-column: 90", file=fh)
        write("# End:", file=fh)
        fh.close()

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
