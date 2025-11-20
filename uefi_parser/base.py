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
Infrastructure for parsing the firmware structures using Construct.
"""

import sys
import os
import io
import hashlib
import dataclasses
import traceback
import logging
from enum import Flag, Enum
from datetime import datetime
from uuid import UUID
from collections.abc import Callable
from typing import Union, Type, Optional, TypeVar, ParamSpec, TYPE_CHECKING, Any
from typing_extensions import Self
from functools import wraps

import construct
from construct import (
    Bytes, Computed, Tell, Pointer, GreedyRange, GreedyBytes, Select, FixedSized,
    Seek, Check, Adapter, Renamed, ExprValidator, Pass, Optional as OptionalCons,
    Construct, Subconstruct, Container, ListContainer, NullTerminated, StringEncoded,
    extractfield, stream_read, stream_tell, stream_seek,
    CheckError, SelectError, PaddingError, StopFieldError, ExplicitError, ConstructError)

from .utils import red, cyan, yellow
from .guiddb import GUID_DATABASE as GDB

log = logging.getLogger("cert-uefi-parser")

# Avoid confusion with typing.Optional by giving the construct a new name.
Opt = OptionalCons

# Context is intended for typing the "Context" which is in fact a Container.
Context = Container
Stream = io.BytesIO
PathType = str

# The types that are convertable to JSON by our system,
Jsonable = Union['FirmwareStructure', list['Jsonable'], bytes,
                 Flag, Enum, datetime, UUID]
PostJsonable = Union[str, int, bool, list['PostJsonable'], dict[str, 'PostJsonable']]

ReportTerm = Union[tuple[str], tuple[str, None],
                   tuple[str, str], tuple[str, str, Callable[[str], str]]]

# A specific FirmwareStructure sub-type
FSType = TypeVar('FSType', bound='FirmwareStructure')
RetVal = TypeVar('RetVal')  # Return type of the decorated function
Params = ParamSpec('Params')  # Parameters of the decorated function

# ----------------------------------------------------------------------------------------
def error(msg: str, clsname: str, offset: Optional[int] = None, fatal: bool = False) -> None:
    """
    Report an error.
    """
    # Check program args, etc. here in the future.
    if offset is None:
        ostr = ""
    else:
        ostr = yellow("0x%08x" % offset)
        log.error("%s %s in class %s: %s" % (ostr, red("ERROR:"), cyan(clsname), red(msg)))

# ----------------------------------------------------------------------------------------
class ValidationError(Exception):
    """
    Raised when there was an unexpected input during parsing.
    """
    pass

# ----------------------------------------------------------------------------------------
class HexPythonBytes(bytes):
    """
    A version of the Python bytes object that prints itself in hex.
    """

    def __str__(self) -> str:
        return self.hex()

# ----------------------------------------------------------------------------------------
class HexBytesAdapter(Adapter):
    """
    An adapter to facilitate HexBytes() a variation of the Bytes() construct.
    """

    def _decode(self, obj: bytes, context: Context, path: PathType) -> HexPythonBytes:
        return HexPythonBytes(obj)

# ----------------------------------------------------------------------------------------
def HexBytes(size: Union[Callable[[Any], int], int]) -> HexBytesAdapter:
    """
    A construct to read size bytes from the stream and return HexPythonBytes.  This
    results in the value being displayed in hex in the debugging output, but it is still
    accessible like an ordinary Python bytes object.
    """
    return HexBytesAdapter(Bytes(size))

# ----------------------------------------------------------------------------------------
def GreedyHexBytes() -> HexBytesAdapter:
    """
    A construct to read size bytes from the stream and return HexPythonBytes.  This
    results in the value being displayed in hex in the debugging output, but it is still
    accessible like an ordinary Python bytes object.
    """
    return HexBytesAdapter(GreedyBytes)

# ----------------------------------------------------------------------------------------
def validation_error(msg: str, clsname: str, offset: Optional[int] = None,
                     fatal: bool = False) -> None:
    """
    Report a validation error for the current class based on the user's configuration.

    Typically raises ValidationError, but can be configured by the user to simply log
    errors to facilitate file format debugging.

    When a class cannot continue with essential parsing the fatal parameter should be set
    to True, which will cause the ValidationError to always be raised.  In general, this
    option should retain the default value of False, since changing it probably represents
    a failure to be sufficiently defensive prior to validation, and the implementation
    should have instead set self._valid to False to prevent further use of the API
    (including calls to validate()).  There are circumstances however in which this would
    result in errors being silently ignored, for example if a self-identifying magic
    header was detected, but then subsequently _required_ portions of the object had
    invalid values.

    Errors between those that should be ignored during speculative evaluation
    (auto-detection), and completely successful parsing, should be left to user
    configuration.  In general, the goal is for an implementation to set self._valid to
    False until the object is certain to be of the correct type, call validation_error()
    with fatal=True for any circumstance that prevents the correct determination of
    len(self) and then call validation_error() with fatal=False in all other
    circumstances.  Whenever possible, the calls to validation_error() should be placed in
    the validate() method to make it clear that the checks are NOT critical.
    """
    # Check program args, etc. here in the future.
    if offset is None:
        ostr = ""
    else:
        ostr = yellow("0x%08x" % offset)
    if fatal:
        raise ValidationError("%s ERROR: in class %s: %s" % (ostr, clsname, msg))
    else:
        log.error("%s %s in class %s: %s" % (ostr, red("ERROR:"), cyan(clsname), red(msg)))

# ----------------------------------------------------------------------------------------
class CollisionError(Exception):
    """
    Raised when two object attempt to dump to the same file system path.
    """
    pass

# ----------------------------------------------------------------------------------------
class GenerationError(Exception):
    """
    Raised when a modification to an image is unsupported.
    """
    pass

# ----------------------------------------------------------------------------------------
class LazyBind(Construct):
    """
    Lazily bind the construct type based on a lamba that receives the context.

    Like LazyBound(), but provides the context as a parameter to the
    lambda.  Like Switch(), but with an implicit case map from type to type.
    """

    def __init__(self, func: Callable[[Context], Construct]) -> None:
        super().__init__()
        self.func = func

    def _parse(self, stream: Stream, context: Context, path: PathType) -> Any:
        subcon = self.func(context)
        return subcon._parsereport(stream, context, path)

    def _build(self, obj: Any, stream: Stream, context: Context, path: PathType) -> bytes:
        subcon = self.func(context)
        return subcon._build(obj, stream, context, path)

    def _sizeof(self, context: Context, path: PathType) -> int:  # type: ignore
        subcon = self.func(context)
        return subcon._sizeof(context, path)  # type: ignore

# ----------------------------------------------------------------------------------------
def OneOrMore(subcons: Construct) -> ExprValidator:
    "Matches one or more of the subconstruct, or raises a ValidationError."
    return ExprValidator(GreedyRange(subcons), lambda obj, ctx: len(obj) >= 1)

# ----------------------------------------------------------------------------------------
class OffsetBytesIO(io.BytesIO):
    """
    A wrapper around BytesIO that maintains and external offset for byte zero.
    """

    def __init__(self, data_bytes: bytes, offset: int) -> None:
        self.base_offset = offset
        super().__init__(data_bytes)

    def tell(self) -> int:
        return super().tell() + self.base_offset

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            offset = offset - self.base_offset
        return super().seek(offset, whence)

# ----------------------------------------------------------------------------------------
class FixedLength(FixedSized):
    """
    A modified FixedSized that preserves absolute stream offsets in the substream.
    """

    # FIXME? The callable for length should return an int, but that's currently
    # pretty hard because of how badly a context is typed.  Maybe use int() in lambda?
    def __init__(self, length: Union[Callable[[Any], Any], int],
                 subcons: Construct, skip: int = 0) -> None:
        super().__init__(length, subcons)
        self.skip = skip

    def _parse(self, stream: Stream, context: Context, path: PathType) -> Any:
        length = construct.evaluate(self.length, context)
        if length < 0:
            raise PaddingError("length cannot be negative", path=path)
        current_offset = stream.tell()
        data = stream_read(stream, length, path)
        if self.subcon is GreedyBytes:
            return data
        if (isinstance(self.subcon, StringEncoded)
                and self.subcon.subcon is GreedyBytes):
            return data.decode(self.subcon.encoding)
        oio = OffsetBytesIO(data, current_offset + self.skip)
        return self.subcon._parsereport(oio, context, path)

# ----------------------------------------------------------------------------------------
class SafeFixedLength(Construct):
    """
    A modified version of FixedLength that knows how to convert a size calculation
    exception into a FailedParse rather than a normal construct failure to find the object
    that contains the FixedLength.
    """

    # FIXME? The callable for length should return an int, but that's currently
    # pretty hard because of how badly a context is typed.  Maybe use int() in lambda?
    def __init__(self, length: Union[Callable[[Any], Any], int],
                 subcons: Construct, extra: str = "extra") -> None:
        super().__init__()
        self.extra = extra
        self.struct = FixedLength(length, Struct(
            "data" / subcons,
            "extra" / GreedyBytes))

    def _parse(self, stream: Stream, context: Context, path: PathType) -> Any:
        context[self.extra] = None
        obj = self.struct._parsereport(stream, context, path)
        if obj.data is None:
            return obj
        if obj.extra == b'':
            obj.extra = None
        context[self.extra] = obj.extra
        return obj.data

# ----------------------------------------------------------------------------------------
class Search(Select):
    """
    Search for a byte pattern in the stream, and return its position.
    """

    def __init__(self, pattern: bytes, relative: bool = False,
                 max_on_fail: bool = False) -> None:
        """
        If relative is False, the position returned will be the absolute
        """
        super().__init__()
        self.pattern = pattern
        self.relative = relative
        self.max_on_fail = max_on_fail

    def _parse(self, stream: Stream, context: Context, path: PathType) -> int:
        """
        This isn't the most efficient way to do this, but it works, and it can be replaced
        with something better in the future if needed.
        """
        # Get the current position.
        pos = stream_tell(stream, path)
        # Read all remaining bytes.
        remaining_bytes = stream.read()
        # Return the stream to the original position.
        stream_seek(stream, pos, 0, path)
        # Search for the requested pattern.
        match = remaining_bytes.find(self.pattern)
        # If the pattern wasn't found, either return -1 or set the match to the end of the
        # stream, depending on the max_on_fail parameter.
        if match == -1:
            if self.max_on_fail:
                match = len(remaining_bytes)
            else:
                return match
        # If the caller asked for a relative position just return pos.
        if self.relative:
            return match
        # Otherwise return the position in the stream that matched.
        return pos + match

# ----------------------------------------------------------------------------------------
class Until(Construct):
    """
    Search for a pattern, and then parse the sub-construct in the bytes between the
    current position and the location where the pattern matched.  Useful for determining
    the size of structures that are marked at their end rather than having an explicit
    size.

    BUG! Should really used a SafeFixedLength!
    """

    def __init__(self, pattern: bytes, subcons: Construct) -> None:
        super().__init__()
        self.struct = construct.Struct(
            "_match" / Search(pattern, relative=True),
            Check(lambda ctx: ctx._match != -1),
            "data" / FixedLength(lambda ctx: ctx._match, subcons))

    def _parse(self, stream: Stream, context: Context, path: PathType) -> Any:
        obj = self.struct._parsereport(stream, context, path)
        return obj.data

# ----------------------------------------------------------------------------------------
class UnicodeSelect(Select):
    """A version of select that tries the next choice on UnicodeError."""
    def _parse(self, stream: Stream, context: Context, path: PathType) -> Union[str, bytes]:
        for sc in self.subcons:
            fallback = stream_tell(stream, path)
            try:
                obj = sc._parsereport(stream, context, path)
            except ExplicitError:
                raise
            except ConstructError:
                stream_seek(stream, fallback, 0, path)
            except UnicodeError:
                log.error("UnicodeError in string at 0x%x in %s!" % (stream.tell(), path))
            else:
                assert isinstance(obj, (str, bytes))
                return obj
        raise SelectError("no subconstruct matched", path=path)

# ----------------------------------------------------------------------------------------
class Commit(Subconstruct):
    """
    Mark the point in a structure in which we're "committed" to parsing that structure,
    and should not treat parsing failures in the normal construct way of rolling back to a
    previous decision point.  This construct takes one parameter, which should be a
    subconstruct to consume the remaining bytes in the stream (or if possible, return the
    stream to state where that's a chance that the parsing can resume.  See Struct below
    for more details.
    """

    def __init__(self, subcon: Construct) -> None:
        super().__init__(subcon)

    def _parse(self, stream: Stream, context: Context, path: PathType) -> Any:
        return self.subcon._parse(stream, context, path)

# ----------------------------------------------------------------------------------------
class Struct(construct.Struct):
    """
    A replacement for the normal Struct construct that knows how to handle Commit markers
    in the structure definition.  When this implementation of Struct encounters a Commit
    construct, it tells construct that we do not want to rollback to previous decision
    point but instead want to report as much of the current structure as we were able to
    parse.  If no Commit marker is present in the Struct, the behavior is identical to the
    standard construct Struct type.

    This commit behavior is useful because UEFI structures are often very deeply nested,
    and the default behavior of construct trends toward simply reporting that the file was
    not a completely valid UEFI firmware image.  With this implementation it is easier to
    see where the UEFI stream was malformed, or more likely where the UEFI parser was
    incorrect.

    The challenges mostly involve how to handle the remaining portion of the stream that
    is malformed, and what to do with the structure that was incompletely parsed.

    The first challenge is typically handled by providing a subconstruct to Commit that
    says how to return the stream to a valid state. In most cases this means using a call
    like ParseFailure to consume all of the remaining bytes in the stream.  This is often
    possible because there are explicit lengths in the data structures meaning that we
    only abort to the most recent SafeFixedLength.

    The second challenge, involving the incompleteness of the current sructure is handled
    in this code, by continuing to set all of the remaining fields in the structure to
    None. Nota bene: This does not prevent type errors where the structure definition
    expected say an int value, but received None instead, so any subsequent Python code
    that presumes a type needs to handle the unexpected type confusion.
    """

    def __init__(self, *args: Construct, **kwds: Any) -> None:
        realcons: list[Construct] = []
        for cons in args:
            if isinstance(cons, tuple):
                realcons.extend(cons)
            else:
                realcons.append(cons)
        self.by_name = {}
        for cons in realcons:
            if isinstance(cons, Renamed):
                self.by_name[cons.name] = cons.subcon
        super().__init__(*realcons, **kwds)

    def _parse(self, stream: Stream, context: Context, path: PathType) -> Self:
        obj = Container()
        obj._io = stream

        # FIXME!!!   Hack for fixing missing _memory!
        if "_memory" not in context:
            context._memory = b''

        obj._memory = context._memory
        obj._field_offsets = {}
        context = Container(
            _=context, _obj=obj, _params=context._params, _root=None,
            _parsing=context._parsing, _building=context._building,
            _sizing=context._sizing, _subcons=self._subcons, _io=stream,
            _memory=context._memory, _index=context.get("_index", None))
        context._root = context._.get("_root", context)
        committed = None
        commit_name = None
        commit_error = False
        start = stream_tell(stream, path)
        for sc in self.subcons:
            if commit_error:
                if sc.name:
                    obj[sc.name] = None
                    context[sc.name] = None
                continue
            if isinstance(extractfield(sc), Commit):
                committed = sc
                if sc.name:
                    commit_name = sc.name
                    obj[sc.name] = None
                    context[sc.name] = None
                continue
            fallback = stream_tell(stream, path)
            try:
                start = stream_tell(stream, path)
                subobj = sc._parsereport(stream, context, path)
                if sc.name:
                    end = stream_tell(stream, path)
                    obj._field_offsets[sc.name] = (start, end)
                    obj[sc.name] = subobj
                    context[sc.name] = subobj
            except StopFieldError:
                break
            except ExplicitError:
                raise
            except ConstructError:
                if committed is None:
                    raise
                stream_seek(stream, fallback, 0, path)
                subobj = committed._parsereport(stream, context, path)
                # If we've read no bytes at all since the beginning of the struct,
                # consider this a real failure, We do this because allowing the commit
                # sub-construct to consume zero bytes will result in endless loops when
                # the Struct is inside a GreedyRange for example, and a failure occurs.
                # We do not need to continue to loop through the fields of the structure,
                # setting them to None, because there's no partial object to report (we've
                # probably already reported the partial object on a previous invocation).
                if stream_tell(stream, path) == start:
                    raise
                if commit_name:
                    obj[commit_name] = subobj
                    context[commit_name] = subobj
                if sc.name:
                    obj[sc.name] = None
                    context[sc.name] = None
                # Mark that there's been an error, but continue to process the remaining
                # fields so that all fields in the structure are set to None.
                commit_error = True
        return obj

    def __add__(self, other: Construct) -> 'Struct':
        "Ensure that adding fields to our custom Struct returns our custom Struct"
        lhs = self.subcons if isinstance(self, Struct) else [self]
        rhs = other.subcons if isinstance(other, Struct) else [other]
        return Struct(*(lhs + rhs))

# ----------------------------------------------------------------------------------------
class Report(Subconstruct):
    "Report whether an object was parsed successfully and any exception raised."
    # Debug why a construct didn't parse correctly.

    def __init__(self, name: str, subcon: Construct) -> None:
        super().__init__(subcon)
        self.name = name

    def _parse(self, stream: Stream, ctx: Context, path: PathType) -> Any:
        log.error("{}: Parsing...".format(self.name))
        try:
            val = self.subcon._parse(stream, ctx, path)
            log.error("{}: Succeeded.  Returned {}".format(self.name, val))
            return val
        except Exception as e:
            log.error("{}: Failed.  Exception {}".format(self.name, e))
            raise

# ----------------------------------------------------------------------------------------
class WithOffset(Renamed):
    """If the sub-construct is named, stores the stream offset at "_offset_of_<name>"."""

    def _parse(self, stream: Stream, ctx: Context, path: PathType) -> Any:
        if self.name is not None:
            offset = Tell._parse(stream, ctx, path)
            offset_name = "_offset_of_" + self.name
            ctx[offset_name] = offset
            if "_obj" in ctx:
                ctx._obj[offset_name] = offset
        return super()._parse(stream, ctx, path)

    def __rtruediv__(self, name: str) -> Self:
        self.name = name
        return self

    def __mul__(self, other: Any) -> None:
        if isinstance(other, (bytes, str,)):
            self.docs = other
        elif callable(other):
            self.parsed = other
        raise ConstructError("operator * can only be used with string or lambda")

    def __rmul__(self, other: Any) -> None:
        return self.__mul__(other)

# ----------------------------------------------------------------------------------------
class UUIDAdapter(Adapter):

    def _decode(self, obj: bytes, context: Context, path: PathType) -> UUID:
        return UUID(bytes_le=obj)

    def _encode(self, obj: UUID, context: Context, path: PathType) -> bytes:
        return obj.bytes_le

UUID16 = UUIDAdapter(Bytes(16))

# ----------------------------------------------------------------------------------------
class EnumAdapter(Adapter):

    def __init__(self, subcon: Construct, enum_type: Type[Enum]):
        super().__init__(subcon)
        self.enum_type = enum_type

    def _decode(self, obj: int, context: Context, path: PathType) -> Enum:
        return self.enum_type(obj)

    def _encode(self, obj: Enum, context: Context, path: PathType) -> Any:
        return obj.value

# ----------------------------------------------------------------------------------------
class FailPeek(Subconstruct):
    """Peek a construct but raise an errors that occur."""
    def _parse(self, stream: Stream, context: Context, path: PathType) -> Any:
        fallback = stream_tell(stream, path)
        try:
            return self.subcon._parsereport(stream, context, path)
        finally:
            stream_seek(stream, fallback, 0, path)

# ----------------------------------------------------------------------------------------
def PaddedString(size: Union[Callable[..., int], int],
                 encoding: str = "utf-8") -> UnicodeSelect:
    return UnicodeSelect(construct.PaddedString(size, encoding), Bytes(size))

# ----------------------------------------------------------------------------------------
def CString(encoding: str = "utf-8") -> UnicodeSelect:
    return UnicodeSelect(
        construct.CString(encoding),
        NullTerminated(GreedyBytes))

# ----------------------------------------------------------------------------------------
def get_stream_size(ctx: Context) -> int:
    current_pos = ctx._io.tell()
    end_pos = ctx._io.seek(0, os.SEEK_END)
    if isinstance(ctx._io, OffsetBytesIO):
        end_pos -= ctx._io.base_offset
    ctx._io.seek(current_pos, os.SEEK_SET)
    return end_pos

# ----------------------------------------------------------------------------------------
# Unused so far?
def Aligned(size: int) -> Bytes:

    def padsize(ctx: Context) -> int:
        pos = ctx._io.tell()
        newpos = pos + (size - 1) - ((pos - 1) % size)
        endpos = len(ctx._io.getbuffer())
        if newpos > endpos:
            newpos = endpos
        return newpos - pos

    # This construct is more forgiving about end-of-file alignment.
    #return Select(Bytes(padsize), Computed(b''))
    return Bytes(padsize)

# ----------------------------------------------------------------------------------------
class SoftCheck(Check):
    # This method should really append the errors to a list of errors stored in the
    # construct context.  Another method should read the errors from that list and report
    # them to the console in the order (and with the appropriate context).  However, if
    # the user has requested that the errors raise Exceptions, that should probably
    # continue to happen here immediately.

    def __init__(self, func: Callable[..., bool], msg: Union[Callable[..., str], str]):
        def myfunc(ctx: Context) -> bool:
            passed = func(ctx)
            if passed:
                clsname = ctx.get('_clsname', '???')
                offset = ctx._io.tell()
                if callable(msg):
                    msgstr = msg(ctx)
                else:
                    msgstr = msg
                validation_error(msgstr, clsname, offset)
            return True
        super().__init__(myfunc)

# ----------------------------------------------------------------------------------------
class Class(Construct):
    """
    Wrap an ordinary construct.Struct() to use the structure definition from a class.

    The goal of this class is to replace the Struct() construct with a Python class as
    transparently as possible.

    The usage pattern is instead of Struct(field, field, ...), you specify Class(type)
    and then set the class variable "definition" to the construct.Struct() definition in
    the Python class.

    The class should also define a classmethod "from_container" that constructs an
    instance of the class from a construct.Container, and a start offset.  The class
    should also define a method "build_dict" that builds the value dictionary used by
    construct to build a byte stream.
    """

    def __init__(self, cls: Type['FirmwareStructure']) -> None:
        super().__init__()
        self.cls = cls
        self.definition = cls.definition

    def _parse(self, stream: Stream, context: Context,
               path: PathType) -> Optional['FirmwareStructure']:
        # What does it mean to parse a FirmwareStructure class?
        #   1. We pull the modified definition from the class.
        #   2. We initiate the construct parse.
        #   3. We call FirmwareStructure.from_container()
        #   4. We build an Firmware object instance.
        #   5. We populate the object with from fields the container.

        # Get the offset in the stream before we being parsing.
        start_offset = stream.tell()
        # Inject the class name into the context.
        #cls_def = "_clsname" / Computed(self.cls.__name__)
        #definition = cls_def + self.definition
        definition = self.cls.modified_definition(start_offset)
        # Parse from the stream, obtaining the container.
        container = definition._parse(stream, context, path)
        # Construct an instance of the class.
        obj = self.cls.from_container(container, start_offset)
        # Return the class instance.
        return obj

    def _build(self, obj: 'FirmwareStructure',  # type: ignore[override]
               stream: Stream, context: Context, path: PathType) -> bytes:
        # Build a dictionary of values, and then build the byte stream.
        built_dict = obj.build_dict()
        return self.definition._build(built_dict, stream, context, path)

    def _sizeof(self, **contextkw: Any) -> int:
        return self.definition._sizeof(**contextkw)

@dataclasses.dataclass(slots=True)
class FirmwareStructureReportContext(object):
    color: bool = True
    clsname: bool = True
    indentation: str = ''

    def indent(self, level: Union[int, str]) -> 'FirmwareStructureReportContext':
        if isinstance(level, str):
            indentation = self.indentation + level
        else:
            indentation = self.indentation + ' ' * level
        return dataclasses.replace(self, indentation=indentation)

    def without_clsname(self) -> 'FirmwareStructureReportContext':
        return dataclasses.replace(self, clsname=False)

class FirmwareStructure(object):
    """
    The new (more clearly?) defined API for all firmware objects.

    This class is designed to reduce the amount of code that must be written to add new
    firmware objects to the system.  Fimrware objects are expected to support
    auto-detection, validation, JSON (dict) generation, debugging output, extraction and
    generation.

    Resonable default implementations of all required methods are provided, but most
    methods can be overriden at several points in processing to make it easy to implement
    common cases of custom behavior.

    The data array will be provided again when dumping and generating, allowing the class
    to implement a very simple implementation of those methods.  The data will not be
    provided during analysis, validation, conversion to JSON, or reporting, since those
    operations are expected to use metadata only.
    """

    definition = Struct()

    # The class must define the structure definition (a Struct) in a class variable named
    # definition.

    # There's no default implementation of the constructor at the present time, but there
    # could be...  It would probably convert kwargs to a container/dictionary, and then
    # reuse some of the logic in from_container().  I don't think it's required at present
    # because there probably aren't many use cases where we're constructing object
    # instances without parsing them from files, but if we need this is should be fairly
    # straight forward to implement.
    def __init__(self) -> None:
        self._logger = logging.getLogger("cert-uefi-parser")

    _io: io.BytesIO
    _data_offset: int
    _memory: bytes
    _valid: bool
    _field_offsets: dict[str, tuple[int, int]]
    _parsed_length: int
    label: str

    # Signal to mypy that we have dynamically defined attributes, so that our custom mypy
    # hook gets called, but we don't actually need this method at runtime.
    if TYPE_CHECKING:
        def __getattr__(self, name: str) -> Any:
            return None

    @classmethod
    def from_container(cls: type[FSType], container: Container,
                       offset: int) -> Optional[FSType]:
        """
        Create an instance of this class from a Container (a dictionary).

        Return None if construct fails, or if analyze() or validate() sets self._valid to
        False.  The default implementation should be correct for practically all
        subclasses, since it implements calls to other parts of the API.
        """
        obj = cls()
        # The offset into "whole" memory (aka obj._memory).
        obj._data_offset = offset
        # The parsed length object. It is always true that:
        #   obj._memory[obj._data_offset:obj._data_offset + obj._parsed_length]
        # are the bytes that corresponding to object.
        obj._parsed_length = container._io.tell() - offset
        # obj._io is a subclass of BytesIO, and has the following restrictions.  It mostly
        # behaves as if it was operating on obj._memory, aka tell and seek operates
        # relative to obj._memory.  However, in many cases it is illegal to seek to a
        # position outside of the memory of the current object's parsed range.  In
        # particular, a FixedLength operation, may truncate the stream.
        #
        # In particular, any Construct that seeks to zero is faulty.  This is easily
        # corrected by using Tell and Seek, or Pointer.
        obj._io = container._io
        # Represents the raw bytes object from everything that is parsed.  This is the
        # "whole" memory, not a extracted subset of the memory.
        obj._memory = container._memory
        # Field offsets is a map from field name as they appear in the Struct that was the
        # definition to the begin and end offsets used to parse that field with within the
        # object.  These offsets are into obj._memory, not relative the start of the
        # definiton structure.
        obj._field_offsets = container._field_offsets

        # Transfer attributes from the container to the class itself.
        for attr in container:
            value = container[attr]
            # Always cleanup construct's "ListContainer" object into a proper list.
            if isinstance(value, ListContainer):
                value = list(value)
            setattr(obj, attr, value)

        # Ths object is valid by default after having been parsed by construct.
        obj._valid = True
        # A method to do additional analysis of the object after it has been fully parsed.
        try:
            obj.analyze()
        except (StopFieldError, ExplicitError, CheckError):
            raise
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback, file=sys.stdout)
            traceback.print_exception(exc_type, exc_value, exc_traceback, file=sys.stdout)
            sys.exit()

        if not obj._valid:
            return None

        # If the object is of the correct type, call validate to give the object a chance
        # to complain about various validation problems.  This may log errors, or throw
        # exceptions.
        obj.validate()
        # In some cases it might be cleaner for validate() to implement auto-detection,
        # and decide whether an object is present at the requested offset, but care must
        # be taken not to allow user configuration of validation errors to interfere with
        # auto-detection, which is under developer control.
        if not obj._valid:
            return None
        return obj

    @classmethod
    def parse(cls: Type[FSType], data: Union[bytes, bytearray], offset: int,
              length: Optional[int] = None, skip: Optional[int] = None,
              context: Optional[Context] = None) -> Optional[FSType]:
        """
        Construct an instance of the class from an offset in a byte stream.

        Any ConstructErrors raised during parsing will cause this method to return None,
        meaning that auto-detection failed, and a valid object was not found in the
        stream.  Note that embedding references to the class in another construct
        definition does NOT catch these errors, so this is the sole interface to the
        auto-detection feature.

        The data bytes array and offset should be file absolute to simplify debugging with
        a hex-editor, and to prevent needless copies of subsets of the data stream, but it
        doesn't strictly have to be.  The data is typically NOT stored in object except in
        the form of "parsed" fields.
        """
        # Wrapped in a try/except block so that errors raised by construct are ignored and
        # treated as an auto-detection failure.
        try:
            definition = cls.modified_definition(offset)
            if skip is not None:
                if length is None:
                    length = len(data) - offset
                definition = FixedLength(offset + length, definition, skip=skip)
            elif length is not None:
                definition = FixedLength(offset + length, definition)
            _context = Container()
            if context is not None:
                _context = context
            _context['_memory'] = data
            container = definition.parse(data, **_context)
            return cls.from_container(container, offset)
        except ConstructError:
            return None

    def subparse(self, cls: Union[type[FSType], Construct], field: str,
                 start: Optional[int] = None,
                 stop: Optional[int] = None) -> Optional[FSType]:
        """
        Parses an instance of cls from the data of the given field (string).

        The start and stop arguments can be used to limit the portion of the field that is
        to be parsed.
        """
        offsets = self._field_offsets[field]
        start_of_field = offsets[0]
        end_of_field = offsets[1]

        if start is None:
            start = 0

        if stop is None:
            end_of_parse = end_of_field
        else:
            end_of_parse = min(end_of_field, start_of_field + stop)

        start_of_parse = start_of_field + start
        length_of_parse = end_of_parse - start_of_parse

        result: Optional[FirmwareStructure]
        if isinstance(cls, type) and issubclass(cls, FirmwareStructure):
            result = cls.parse(self._memory, start_of_parse, length=length_of_parse)
        elif isinstance(cls, Class):
            result = cls.cls.parse(self._memory, start_of_parse, length=length_of_parse)
        elif isinstance(cls, Construct):
            correct_memory = self._memory[start_of_parse:start_of_parse + length_of_parse]
            result = cls.parse_stream(OffsetBytesIO(correct_memory, start_of_parse),
                                      _memory=self._memory)
        else:
            assert False, f"Incorrect type {type(cls)}"

        # I'm not sure I understand mypy's complaint here...  error: Incompatible return
        # value type (got "FirmwareStructure | None", expected "FSType | None")
        # FSType is supposed to be bound to FirmwareStructure
        return result  # type: ignore

    def add_field(self, name: str, value: Any, origin_field: str,
                  start: Optional[int] = None, stop: Optional[int] = None) -> None:
        """
        Add a new field to this structure.

        Add a field 'name' with the value 'value' to this object.  This field's value was
        created from data from the named 'origin_field'.  If 'start' and 'stop' are
        included, they represent the portion of 'origin_field' that was used to construct
        'value'.
        """
        setattr(self, name, value)
        (ostart, ostop) = self._field_offsets[origin_field]
        if start is None:
            start = ostart
        else:
            start = min(ostart + start, ostop)
        if stop is None:
            stop = ostop
        else:
            stop = min(ostart + stop, ostop)
        self._field_offsets[name] = (start, stop)

    @classmethod
    def modified_definition(cls: type['FirmwareStructure'], offset: int) -> Construct:
        # Inject the class name into the context
        #log.debug("Using standard modified_definition for %s" % cls.__name__)
        if cls == FirmwareStructure:
            return Pass
        if not isinstance(cls.definition, construct.Struct):
            raise TypeError('Definition of class "%s" is not a Struct.' % cls)
        cls_def = "_clsname" / Computed(cls.__name__)
        definition = Struct(Seek(offset), cls_def, *cls.definition.subcons)
        return definition

    def analyze(self) -> None:
        """
        Implemented by subclasses to do additional analysis post construct parsing.

        This method is invoked after construct has finished parsing the object, and values
        from the definition are stored in the object attributes.  If this method sets
        self._valid to False, None will be returned during auto-detection parsing.

        A common use would be to create additional computed values, although caution
        should be exercised because updates to those values will NOT be serialized back
        into the byte sream by default.  Property setters should probably be used instead.

        Further, at the present time this method does not have access to the parsing
        stream handle, meaning that it is not possibleto perform additional parsing.  That
        choice was intentional, since there's no simple approach to reversing the stream
        manipulations thta might occur.  That feature can be added in the future if needed.

        The default implementation of this method is to do nothing, and ideally subclasses
        would NOT override this method.
        """
        pass

    def __len__(self) -> int:
        """
        Return the length of the object.

        Specifically, this is the number of bytes parsed and 'owned' by this object from
        the offset supplied during construction.  The default implementation is to return
        the value of self._parsed_length, but the method can also be overriden by
        subclasses that require a special implementation.
        """
        return self._parsed_length

    def validation_error(self, msg: str, offset: Optional[int] = None,
                         fatal: bool = False) -> None:
        """
        Report a validation error for the current class based on the user's configuration.

        This method simply assigns reasonable defaults to the class name and offset
        parameters of the context-free function of the same name, which is also used by
        by the custom SoftCheck() construct.
        """
        if offset is None:
            offset = self._data_offset
        validation_error(msg, self.__class__.__name__, offset, fatal)

    def error(self, msg: str, offset: Optional[int] = None, fatal: bool = False) -> None:
        """
        Report an error that is more general than validation.

        This method simply assigns reasonable defaults to the class name and offset
        parameters of the context-free function of the same name, which is also used by
        by the custom SoftCheck() construct.
        """
        if offset is None:
            offset = self._data_offset
        #error(msg, self.__class__.__name__, offset, fatal)
        self._logger.error(msg)

    def warn(self, msg: str) -> None:
        self._logger.warning(msg)

    def info(self, msg: str) -> None:
        self._logger.info(msg)

    def debug(self, msg: str) -> None:
        self._logger.debug(msg)

    def validate(self) -> None:
        """
        Implement optional validation of the object.

        This method should invoke self.validation_error() for each unexpected condition
        encountered while parsing.  Depending on user configuration options, this will
        probably raise ValidationError, but can also log errors to a log file, print
        messages to standard error, print messages to standard output, or a combination of
        these.

        Note that if the developer chooses to implement any portion of auto-detection in
        the validate() method, care must be taken to set self._valid to False and return
        without calling validation_error(), which may be under user control to raise
        ValidationError.  This is permitted because auto-detection validation logic might
        be cleaner in validate() in some simple implementations.

        The default implementation is to preform no additional validation.
        """
        pass

    def _dict_convert_value(self, value: Jsonable) -> PostJsonable:
        if isinstance(value, FirmwareStructure):
            return value.to_dict(True)
        if isinstance(value, list):
            return [self._dict_convert_value(v) for v in value]
        if isinstance(value, bytes):
            return "hex(" + value.hex() + ")"
        if isinstance(value, Flag):
            return value.value
        if isinstance(value, Enum):
            assert isinstance(value.value, (str, int))
            return value.value
        if isinstance(value, (datetime, UUID)):
            return str(value)
        return value

    def memory_location(self) -> tuple[bytes, int, int]:
        """
        Return a triple of array, offset, length.

        The returned triple represents the location of this parsed FirmwareStructure.  It
        consists of the raw bytes from which it was constructed, the offset within the raw
        bytes from where it was constructed, and the length in bytes of the structure.
        """
        return self._memory, self._data_offset, self._parsed_length

    def memory_view(self) -> memoryview:
        """
        Return a memoryview that represents the memory occupied by this object.
        """
        start, end = self._data_offset, self._data_offset + self._parsed_length
        return memoryview(self._memory)[start:end]

    def to_dict(self, json: bool = False) -> dict[str, Any]:
        """
        Return the object as a dictionary suitable for reporting in JSON format.

        If the optional json parameter is set to True (False by default), several common
        types will be coerced into the primitive types required by JSON.  This includes
        recursive calls to to_dict() for embedded FirmwareStructure objects.

        The default implementation is to serialize the object's _data_offset and
        _parsed_length attributes, fields in struct definition that do not begin with an
        underscore, and any dynamic properites (via @property) defined on the class.
        """
        result = {}
        if hasattr(self, "_data_offset"):
            result["_class"] = self._clsname
            result["_offset"] = self._data_offset
            result["_length"] = self._parsed_length

        # Make a list of the completely suppressed fields in the reporting guidance.
        rejects = []
        if hasattr(self, "reporting"):
            for term in self.reporting:
                if len(term) == 2 and term[1] is None:
                    rejects.append(term[0])
        #log.debug(f"type={type(self)} rejects={rejects}", file=sys.stderr)

        for fieldname in self.get_field_names():
            # The net effect here is to NOT report fields that have been suppressed in the
            # reporting list, and to report all other fields (same result as text
            # printing) but to NOT use the formatting advice in the reporting list.  This
            # primarily motivated by hex (0xXXX) not being valid in JSON, and preferring
            # not to export integers as strings.
            if fieldname in rejects:
                continue
            # Get the value of the attribute.
            value = getattr(self, fieldname)
            # Don't export methods.
            if callable(value):
                continue

            # There are a couple of names that we don't really want to report unless
            # they're non-None.
            if value is None and fieldname in ["failure", "unexpected", "skipped"]:
                continue
            # Another variation to suppress those same bytes if they're a zero size
            # MysteryBytes.
            from .mystery import MysteryBytes
            if (isinstance(value, MysteryBytes) and len(value) == 0
                    and fieldname in ["failure", "unexpected", "skipped"]):
                continue

            # Convert types to JSON compatibility if requested.
            if json:
                result[fieldname] = self._dict_convert_value(value)
            else:
                result[fieldname] = value
        return result

    def sbom(self) -> dict[str, Any]:
        """
        Return the software bill of materials as JSON-compatible dictionary.

        This is a subset of the full JSON format intended to produce a more reasonably
        sized report with just the fields of interest to a software bill of materials.
        """
        result: dict[str, Any] = {}
        if not hasattr(self, "sbom_fields"):
            return result
        for fieldname in self.sbom_fields:
            # Get the value of the attribute.
            value = getattr(self, fieldname)
            if isinstance(value, FirmwareStructure):
                sbom_dict = value.sbom()
                if len(sbom_dict) > 0:
                    result[fieldname] = sbom_dict
            elif (isinstance(value, list) and len(value) > 0
                  and isinstance(value[0], FirmwareStructure)):
                newlist = []
                for lvalue in value:
                    sbom_dict = lvalue.sbom()
                    if len(sbom_dict) > 0:
                        newlist.append(sbom_dict)
                if len(newlist) > 0:
                    result[fieldname] = newlist
            elif isinstance(value, bytes):
                try:
                    result[fieldname] = value.decode('utf8')
                except UnicodeError:
                    result[fieldname] = self._dict_convert_value(value)
            else:
                result[fieldname] = self._dict_convert_value(value)

        # If no sbom fields were reported, return an empty dictionary.
        if len(result) == 0:
            return result
        # Otherwise add some context for this object.
        if hasattr(self, "_data_offset"):
            result["_class"] = self._clsname
            #result["_offset"] = self._data_offset
            #result["_length"] = self._parsed_length
        return result

    def offset_string(self) -> str:
        return "0x%08x" % self._data_offset

    def class_name(self) -> str:
        if hasattr(self, "label"):
            return self.label
        else:
            return self.__class__.__name__

    def instance_name(self) -> str:
        default_instance_name = ""
        first_field = None
        if hasattr(self, "reporting"):
            if len(self.reporting) > 0:
                if len(self.reporting[0]) > 0:
                    first_field = self.reporting[0][0]
        if first_field is None:
            return default_instance_name
        if hasattr(self, first_field):
            value = getattr(self, first_field)
            if isinstance(value, UUID):
                return GDB.display_name(value, mode='both', color=False)
            if isinstance(value, FirmwareStructure):
                return default_instance_name
            if (isinstance(value, list) and len(value) > 0
                    and isinstance(value[0], FirmwareStructure)):
                return default_instance_name
            if not isinstance(value, bytes):
                return str(value)
        return default_instance_name

    def report_prefix(self, context: FirmwareStructureReportContext
                      ) -> tuple[str, str, Optional[str]]:
        # Build the offset portion of a report line.
        offset = self.offset_string()
        if context.color:
            offset = yellow(offset)

        # Add the class name if requested.
        clsname = None
        if context.clsname:
            clsname = self.class_name()
            if context.color:
                clsname = cyan(clsname)
            prefix = "%s %s%s: " % (offset, context.indentation, clsname)
        else:
            prefix = "%s>  %s" % (offset, context.indentation)
        return (prefix, offset, clsname)

    def term_value_string(self, term: ReportTerm) -> Optional[str]:
        field = term[0]
        value = getattr(self, field)
        # FIXME! Mypy struggles to detect which size of tuple natches which case here.
        # A better design wouldn't have this problem.
        match term:
            # A term with one element is the field name, and the formatting is implied.
            # Formatting is report(), hard-coded here based on name, or "%s" % field
            case [_]:
                if isinstance(value, UUID):
                    return GDB.display_name(value)
                return yellow(str(value))
            case [_, None]:
                return None
            # A term with two elements contains the field name and a formatter.
            # e.g. ("x" "%d") or ("x", lambda self: self.report_x(self.x))
            case [_, formatter]:
                if callable(formatter):
                    return formatter(self)  # type: ignore
                strval = str(value) if value is None else formatter % value
                return yellow(strval)
            # A term with three elements adds a lambda called on the formatted value.
            case [_, formatter, post_lambda]:
                return post_lambda(formatter % value)  # type: ignore
            case _:
                raise AssertionError

    def get_field_names(self) -> list[str]:
        """
        We were using to_dict() in filter_terms() which is probably bad in several
        ways.  This is a stripped down version that does what Duggan presumably intended,
        but without the interference in JSON reporting, some excessive computing, and
        perhaps other bugs?
        """
        fields = []
        for fieldname in dir(self):
            # Don't export names that begin with underscores.  This provides a simple way
            # to configure the behavior of this default implementation.
            if fieldname.startswith('_'):
                continue
            # Skip the API required structure definition.
            if fieldname in ['label', 'definition', 'reporting', 'sbom_fields']:
                continue
            # Get the value of the attribute.
            value = getattr(self, fieldname)
            # Don't export methods.
            if callable(value):
                continue

            fields.append(fieldname)
        return fields

    def filter_terms(self) -> list[ReportTerm]:
        # Get the reporting guidance from the class, or make a resonable default if none
        # was provided.
        rkeys = []
        if hasattr(self, "reporting"):
            reporting: list[ReportTerm] = self.reporting
            # Make a list of the field names found in the user provided reporting.
            for term in reporting:
                if len(term) > 0:
                    rkeys.append(term[0])
        else:
            reporting = []

        for firmware_structs in [False, True]:
            for key in self.get_field_names():
                # Also don't add fields that have been already reported on.
                if key in rkeys:
                    continue
                # We'll add fields that are not FirmwareStructures, and are therefor not
                # capable of self-reporting in the first pass, and then in the second pass
                # we'll add the ones that are.  This keeps the hierarchy tidy.
                value = getattr(self, key)
                if isinstance(value, FirmwareStructure) == firmware_structs:
                    reporting.append((key,))

        return reporting

    def report(self, context: FirmwareStructureReportContext = FirmwareStructureReportContext()) -> None:
        """
        Emit text formatted lines report the structure of the UEFI files.

        The default implementation is customizable via a class variable named "reporting".
        The reporting class variable is a list of terms which describe how to report on
        one of the fields in the structure.  Each term is itself a list, where the length
        of the list determines the significance of the elements.  An empty term ends the
        current output line.  A term with one element contains just the field name, which
        will result in the default formatting for that field.  A term with two elements is
        a field name and either a format string or a callable function that takes self as
        a parameter. A term with three elements is contains a field name, a format string,
        and a callable that takes the formatted value as a parameter.

        Lines are typically of the form:
          0x<offset> <indentation> cyan(<ObjectType>) [name] field1=val field2=val

        Guids are typically displayed in green, and names/ids are displayed in purple.
        The default implementation calls report() on embedded instances of
        FirmwareStructure and custom implementations should do this as well.
        """
        reporting = self.filter_terms()

        # Emit nothing if reporting is explicitly empty.
        if len(reporting) == 0:
            return
        #log.debug("Reporting: %r" % (reporting))

        (prefix, offset, objType) = self.report_prefix(context)
        line: Optional[str] = prefix

        emit = print  # Print is generally banned from use in CERT UEFI parser.

        for term in reporting:
            #log.debug("Term len=%d term=%r" % (len(term), term))
            # An empty term marks a line break.
            if len(term) == 0:
                # This change silently suppresses having two line breaks in a row in a
                # reporting field.  Is this a useful feature, or does it enable bad code?
                if line is not None:
                    emit(line)
                line = None
                continue

            # Prempt the special case where there's an implied call to report() on the
            # value, because this case affects when lines are output.
            if len(term) == 1:
                field = term[0]
                if not hasattr(self, term[0]):
                    log.warning("Reporting for %s uses non-existent field %s" %
                                (self.__class__.__name__, term[0]))
                    continue
                value = getattr(self, term[0])
                # There are a couple of names that we don't really want to report unless
                # they're non-None.
                if value is None and field in ["failure", "unexpected", "skipped"]:
                    continue
                # Another variation to suppress those same bytes if they're a zero size
                # MysteryBytes.
                from .mystery import MysteryBytes
                if (isinstance(value, MysteryBytes) and len(value) == 0
                        and field in ["failure", "unexpected", "skipped"]):
                    continue
                # Field is a single instance of a FirmwareStructure
                if isinstance(value, FirmwareStructure):
                    if line is not None:
                        emit(line)
                    line = None
                    value.report(context.indent(2))
                    continue
                # Field is a list of strings ending in newlines.  This is bit hacky. :-(
                elif (isinstance(value, list) and len(value) > 0
                      and isinstance(value[0], str)
                      and len(value[0]) > 0 and value[0][-1] == '\n'):
                    if line is not None:
                        emit(line)
                    line = None

                    (prefix, _, _) = self.report_prefix(context.without_clsname())
                    for fline in value:
                        emit(prefix + fline.rstrip())
                    continue
                # Field is a list of FirmwareStructures
                elif (isinstance(value, list) and len(value) > 0
                        and isinstance(value[0], FirmwareStructure)):
                    if line is not None:
                        emit(line)
                    #line = self.report_prefix(indentation, color, False)
                    #emit(line + " " + field)
                    line = None
                    for v in value:
                        if v is None:
                            log.error(f"can't report value '{field}' with value None")
                        elif isinstance(v, FirmwareStructure):
                            v.report(context.indent(2))
                        else:
                            log.error(f"can't report value '{field}' with type '{type(v)}'")
                    continue

            # Another case that does NOT force a new line is the field skipping logic.
            if len(term) == 2 and term[1] is None:
                continue

            # All other cases will be generating some more output on the current line, so
            # if we don't have a new line prefix yet, make one.  Reusing this code is the
            # point of having handled a couple of cases already.
            if line is None:
                (line, _, _) = self.report_prefix(context.without_clsname())

            field = term[0]
            valuestr = self.term_value_string(term)
            if valuestr is None:
                continue
            term_str = f"{field}={valuestr}, "
            line += term_str

        # Report any remaining line that was in progress.
        if line is not None:
            emit(line)

    def dump_path(self, parent: str, index: int) -> str:
        """
        Return the path that this object will dump itself to.

        The parent parameter is an os.path (directory) object reflecting the parent's
        value returned by dump_path().  A valid implementation should only returns paths
        that are and addition to the parent's dump path.  A valid implementation may
        return either a filename or a directory, but if the value is passed to sub-objects
        as a parent path, it should be a directory.

        In most cases, the path for an object should be self-identifying and unique, but
        there can be conflicts where two sub-objects under the same parent return the same
        path.  In these cases, the parent is responsible for providing a unique integer
        index, and the sub-object is expected to use the parameter in cases where that is
        possible, but is not required to in all cases (although it may choose to).

        The default implementation is to return the name of the class and the index.
        """
        return os.path.join(parent, "%s-%d" % (self.__class__.__name__, index))

    def write_file(self, data: bytes, path: str, offset: int, length: int) -> None:
        """
        Dump data from offset (with a given length) to path.

        This routine may be helpful for custom implementations of dump(), but should not
        need to be implemented by subclasses.
        """
        # Raise CollisionError is the requested file path already exists.
        if os.path.exists(path):
            raise CollisionError(path)
        # Open the file, write the requested data, and close the file.
        fh = open(path, "wb")
        fh.write(data[offset:offset + length])
        fh.close()

    def dump(self, data: bytes, parent: str, index: int) -> None:
        """
        Dump this object to one or more files in the filesystem at dump_path().

        The data parameter is the input data buffer that was used to construct the object.
        The parent and index parameters are identical to the parameters to dump_path()
        which should be called to obtain the correct filesystem path.

        This method is responsible for creating the directory or files at the path.  The
        recommended implementation is to dump the contents of the object to a single file,
        or to create a directory and then dump the entire object to a single file, and
        also invoke dump on each of the owned sub-objects.  Whatever implementation is
        chosen, an object MUST be able to reconstruct the object from a subsequent call to
        generate().

        In typical usage, the method will have been invoked with path set to the return
        value from self.dump_path(). Implementations that want to dump to multiple files
        can utiltize the default base class implementation by calling the method
        repeatedly with different values for data and path (while mildly violating the
        recommendations below), but should not alter dumppath for sub-objects.

        If this method creates a single file at that path, it should contain the input
        stream from offset to offset + len(self).  This is the default implementation of
        the method, and is appropriate for objects with no sub-objects.

        If this method creates a directory at that path, it may dump multiple files in
        that directory, which may or may not be accomplished by recursively invoking
        dump() on sub-objects.  Typically an implementation will also dump the entire
        object to a single file within the created directory.

        Implementations should check for existing files and raise CollisionError when they
        are encountered to detect collisions in the dump_path() return values.
        """
        # Determine the correct dump path.
        path = self.dump_path(parent, index)
        # Dump the entire object to a single file as recommended for simple objects.
        self.write_file(data, path, self._data_offset, len(self))

    def detect_modification(self, data: bytes, path: str, offset: int,
                            length: int) -> tuple[bool, bytes]:
        """
        Return (True, modified data) if the file dumped into the filesystem has been modified.

        Return (False, original data) if the file has not been modified.  The default
        implementation is to compare the sha256 hashes of the data to detect whether the
        file has been modified.   This method may be helpful for custom
        """
        # Will throw exceptions if required file does not exist.
        fh = open(path, "rb")
        modified_data = fh.read()
        fh.close()
        modified_hash = hashlib.sha256()
        modified_hash.update(modified_data)

        # Now obtain the original data as well.
        original_data = data[offset:offset + length]
        original_hash = hashlib.sha256()
        original_hash.update(original_data)

        if original_hash.digest() != modified_hash.digest():
            return (True, modified_data)
        else:
            return (False, original_data)

    def generate(self, data: bytes, parent: str, index: int, origin: str = "disk") -> bytes:
        """
        UNUSED FUTURE API.  Return the object packed back into a byte buffer.

        The data parameter is the _input_ data byte buffer.  The parent and index
        parameters are identical to the parameters to dump_path() which should be called
        to obtain the correct filesystem path.  The origin parameter indicates whether
        this object should be generated from the disk dump or the in-memory metadata.

        The input file can be recreated by sequentially appending the results from
        generate().  This method can implement generate() in a wide variety of ways,
        including returning the original data bytes, or calling generate() recursively on
        each of the owned sub-objects.

        Objects that can be modified
        """
        if origin == "disk":
            path = self.dump_path(parent, index)
            (modified, modified_data) = self.detect_modification(
                data, path, self._data_offset, len(self))
            return self.generate_from_disk(data, path, modified)
        else:
            return self.generate_from_memory()

    def generate_from_disk(self, data: bytes, path: str, modified: bool) -> bytes:
        """
        UNUSED FUTURE API.  Generate a byte stream from the dumped to disk representation.

        The default implementation simply returns the disk representation if it has not
        been modified.  If it has been modified, it attempts to reparse the object from
        the modified representation, and if that doesn't raise any ValidationErrors, the
        modified representation is returned, otherwise a GenerationError is raised.

        Classes can reject all modifications by raising a GenerationError if modified is
        true, and silently accept (almost) all modifications by using a configuration that
        disables most ValidationErrors.
        """
        if modified:
            try:
                self.__class__.parse(data, 0)
            except ValidationError:
                raise GenerationError(path)
        return data

    def build_dict(self) -> dict[str, Any]:
        """
        Build a dictionary of values to be passed to definition.build().

        The default implementation is a straight forward conversion of the attributes from
        the current object into a dictionary, while excluding several attibutes defined by
        this API.  The default implementation is likely to produce a dictionary with
        more attributes than constuct requires, but this doesn't appear to be a problem.

        The most common reason to override this method would be to produce value
        dictionaries with updated checksums or additional buld-time specific validation
        checks.
        """
        build_dict = {}
        for attrname, value in vars(self).items():
            if attrname in ["_data_offset", "_parsed_length", "_io", "_valid"]:
                continue
            #log.debug("Setting build_dict[%s] = %r" % (attrname, value))
            build_dict[attrname] = value
        #log.debug("Done!")
        return build_dict

    def generate_from_memory(self) -> bytes:
        """
        Generate a byte stream from the in-memory object representation.

        The default implementation is to rely on the definition.build() process to
        generate the byte stream from the class' structure definition and a call to
        self.build_dict() to set the curretn values.  As a consequence, values not stored
        in the variables defined in the definition will not be serialized into the byte
        stream.

        Values like checksums could be updated automatically using the build customizaton
        features of construct.  Using property decorators (including @setter) is one
        approach to ensuring that computed fields are consistently written back into the
        structure definition.  Another approach is to override the subclass' build_dict()
        method to calculate the values passed to construct.build().  Finally, a subclass
        can override this method to produce a byte stream using arbitrary code.
        """
        # Extract the container from the custom class and call build().
        build_dict = self.build_dict()
        self.definition.build(build_dict)
        # FIXME! The API for definition.build() actually put the bytes in an IOBytes.
        built_bytes = b''
        return built_bytes

    def process(self) -> None:
        """
        NOT part of the new API, but an assumed part of the old API.

        This is here just to make it a little easier to transition.  The plan is
        eventually replace this with a warning to track down any remaining calls,
        eradicate them, and then remove this stub.
        """
        pass

# ----------------------------------------------------------------------------------------
class Wrapper(Subconstruct):

    def __init__(self, subcon: Construct) -> None:
        super().__init__(subcon)

    def _parse(self, stream: Stream, ctx: Context, path: PathType) -> Any:
        try:
            return self.subcon._parse(stream, ctx, path)
        except ConstructError as e:
            raise ExplicitError from e

# ----------------------------------------------------------------------------------------
class HashedFirmwareStructure(FirmwareStructure):

    fshash: str

    @classmethod
    def modified_definition(cls: type[FirmwareStructure], offset: int) -> Struct:
        cls_def = "_clsname" / Computed(cls.__name__)
        definition = Struct(Seek(offset), cls_def, *cls.definition.subcons)
        end_offset = "_end_offset" / Tell
        object_length = "_object_length" / Computed(lambda ctx: ctx['_end_offset'] - offset)
        raw_bytes = "_raw_object_bytes" / Pointer(offset, Bytes(lambda ctx: ctx['_object_length']))

        def hash_func(ctx: Context) -> str:
            hasher = hashlib.sha256()
            hasher.update(ctx['_raw_object_bytes'])
            return hasher.hexdigest()
        hash_value = "fshash" / Computed(hash_func)
        definition = Struct(*definition.subcons, end_offset,
                            object_length, raw_bytes, hash_value)
        return definition

# ----------------------------------------------------------------------------------------
class FakeFirmwareStructure(FirmwareStructure):

    def __init__(self, length: int = 0, memory: bytes = b'', offset: int = 0):
        self._memory = memory
        self._data_offset = offset
        self._parsed_length = length
        self._clsname = self.__class__.__name__

# ----------------------------------------------------------------------------------------
class FailedParse(FirmwareStructure):
    "A failed parse."

    label = "Failed Parse"

    definition = Struct(
        "data" / Computed(None),
        "_extra" / GreedyBytes,
    )

    def analyze(self) -> None:
        from .mystery import MysteryBytes
        assert isinstance(self._extra, bytes)
        self.extra = self.subparse(MysteryBytes, "_extra")

# ----------------------------------------------------------------------------------------
def promote_exceptions(fn: Callable[Params, RetVal]) -> Callable[Params, RetVal]:
    @wraps(fn)
    def fun(*args: Params.args, **kwds: Params.kwargs) -> RetVal:
        try:
            return fn(*args, **kwds)
        except (StopFieldError, ExplicitError, CheckError):
            raise
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback, file=sys.stdout)
            traceback.print_exception(exc_type, exc_value, exc_traceback, file=sys.stdout)
            sys.exit()
    return fun

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
