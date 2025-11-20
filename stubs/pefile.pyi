# pefile-stubs - Python type stubs for pefile
#
# Copyright (C) 2023  coloursofnoise
#
# This software is licensed under the GNU General Public License, version 3 or
# later (GPLv3+). A full copy of the license is available in the COPYING file
# located at the root of the project, or at <https://www.gnu.org/licenses/>.

# WARNING: Using docstrings in a type stub file will override the regular
# project docstrings in some IDEs

from contextlib import AbstractContextManager
from abc import ABC
import mmap
from types import TracebackType
import ordlookup as ordlookup # type: ignore [import-untyped]
from ._generated import pefile_lookup as _gen, pefile_formats as _fmt # type: ignore
from typing import (
    Any,
    Callable,
    Generic,
    Literal,
    ParamSpec,
    Sequence,
    TypeVar,
    TypedDict,
    overload,
)
from hashlib import _Hash
from typing import Optional

# TypeVars
_P = ParamSpec("_P")
_T = TypeVar("_T")
_K = TypeVar("_K")
_V = TypeVar("_V")
_Ptr = TypeVar("_Ptr", _UInt32, _UInt64)

# Primitive Types
class _char(bytes):  # c
    def __class_getitem__(cls, key: int) -> type[bytes]: ...  # [n]s

_UInt64 = int  # Q
_UInt32 = int  # I
_UInt16 = int  # H
_Int32 = int  # I
_byte = bytes  # B
_WORD = _UInt16
_DWORD = _UInt32
_QWORD = _UInt64

# Other TypeAliases
_DATA_TYPE = bytes | bytearray | mmap.mmap

__author__: str = ...
__version__: str = ...
__contact__: str = ...

long: type[int] = int

def lru_cache(
    maxsize: int = ..., typed: bool = ..., copy: bool = ...
) -> Callable[[Callable[_P, _T]], Callable[_P, _T]]: ...
@lru_cache(maxsize=2048)
def cache_adjust_FileAlignment(val: int, file_alignment: int) -> int: ...
@lru_cache(maxsize=2048)
def cache_adjust_SectionAlignment(
    val: int, section_alignment: int, file_alignment: int
) -> int: ...
def count_zeroes(data: list[int]) -> int: ...

fast_load: bool = ...
MAX_STRING_LENGTH: Literal[0x100000] = ...
MAX_IMPORT_SYMBOLS: Literal[0x2000] = ...
MAX_IMPORT_NAME_LENGTH: Literal[0x200] = ...
MAX_DLL_LENGTH: Literal[0x200] = ...
MAX_SYMBOL_NAME_LENGTH: Literal[0x200] = ...
MAX_SECTIONS: Literal[0x800] = ...
MAX_RESOURCE_ENTRIES: Literal[0x8000] = ...
MAX_RESOURCE_DEPTH: Literal[32] = ...
MAX_SYMBOL_EXPORT_COUNT: Literal[0x2000] = ...
IMAGE_DOS_SIGNATURE: Literal[0x5A4D] = ...
IMAGE_DOSZM_SIGNATURE: Literal[0x4D5A] = ...
IMAGE_NE_SIGNATURE: Literal[0x454E] = ...
IMAGE_LE_SIGNATURE: Literal[0x454C] = ...
IMAGE_LX_SIGNATURE: Literal[0x584C] = ...
IMAGE_TE_SIGNATURE: Literal[0x5A56] = ...
IMAGE_NT_SIGNATURE: Literal[0x00004550] = ...
IMAGE_NUMBEROF_DIRECTORY_ENTRIES: Literal[16] = ...
IMAGE_ORDINAL_FLAG: Literal[0x80000000] = ...
IMAGE_ORDINAL_FLAG64: Literal[0x8000000000000000] = ...
OPTIONAL_HEADER_MAGIC_PE: Literal[0x10B] = ...
OPTIONAL_HEADER_MAGIC_PE_PLUS: Literal[0x20B] = ...

class _TwoWayDict(dict[_K | _V, _V | _K]):
    @overload
    def __getitem__(self, key: _K) -> _V: ...
    @overload
    def __getitem__(self, key: _V) -> _K: ...
    @overload
    def __getitem__(self, key: _K | _V) -> _K | _V: ...

def two_way_dict(pairs: list[tuple[_K, _V]]) -> _TwoWayDict[_K, _V]: ...

_NAME_LOOKUP_LIST = list[tuple[str, bytes]]

directory_entry_types: _NAME_LOOKUP_LIST = ...
DIRECTORY_ENTRY: _gen.DIRECTORY_ENTRY_DICT = ...

image_characteristics: _NAME_LOOKUP_LIST = ...
IMAGE_CHARACTERISTICS: _gen.IMAGE_CHARACTERISTICS_DICT = ...

section_characteristics: _NAME_LOOKUP_LIST = ...
SECTION_CHARACTERISTICS: _gen.SECTION_CHARACTERISTICS_DICT = ...

debug_types: _NAME_LOOKUP_LIST = ...
DEBUG_TYPE: _gen.DEBUG_TYPE_DICT = ...

subsystem_types: _NAME_LOOKUP_LIST = ...
SUBSYSTEM_TYPE: _gen.SUBSYSTEM_TYPE_DICT = ...

machine_types: _NAME_LOOKUP_LIST = ...
MACHINE_TYPE: _gen.MACHINE_TYPE_DICT = ...

relocation_types: _NAME_LOOKUP_LIST = ...
RELOCATION_TYPE: _gen.RELOCATION_TYPE_DICT = ...

dll_characteristics: _NAME_LOOKUP_LIST = ...
DLL_CHARACTERISTICS: _gen.DLL_CHARACTERISTICS_DICT = ...

FILE_ALIGNMENT_HARDCODED_VALUE: Literal[0x200] = ...

unwind_info_flags: _NAME_LOOKUP_LIST = ...
UNWIND_INFO_FLAGS: _gen.UNWIND_INFO_FLAGS_DICT = ...

registers: _NAME_LOOKUP_LIST = ...
REGISTERS: _gen.REGISTERS_DICT = ...

UWOP_PUSH_NONVOL: Literal[0] = ...
UWOP_ALLOC_LARGE: Literal[1] = ...
UWOP_ALLOC_SMALL: Literal[2] = ...
UWOP_SET_FPREG: Literal[3] = ...
UWOP_SAVE_NONVOL: Literal[4] = ...
UWOP_SAVE_NONVOL_FAR: Literal[5] = ...
UWOP_EPILOG: Literal[6] = ...
UWOP_SAVE_XMM128: Literal[8] = ...
UWOP_SAVE_XMM128_FAR: Literal[9] = ...
UWOP_PUSH_MACHFRAME: Literal[10] = ...

resource_type: _NAME_LOOKUP_LIST = ...
RESOURCE_TYPE: _gen.RESOURCE_TYPE_DICT = ...

lang: _NAME_LOOKUP_LIST = ...
LANG: _gen.LANG_DICT = ...

sublang: _NAME_LOOKUP_LIST = ...
SUBLANG: _gen.SUBLANG_DICT = ...

sublang_name: Any
sublang_value: Any

def get_sublang_name_for_lang(
    lang_value: _gen.LANG_DICT_VALUES, sublang_value: _gen.SUBLANG_DICT_VALUES
) -> str: ...
def parse_strings(data: str, counter: int, l: list[bytes]) -> None: ...
def retrieve_flags(
    flag_dict: dict[str | bytes, str | bytes], flag_filter: str | bytes
) -> list[tuple[str | bytes, str | bytes]]: ...
def set_flags(obj: Any, flag_field: bytes, flags: list[tuple[str, bytes]]) -> None: ...
def power_of_two(val: bytes) -> bool: ...
def b(x: _DATA_TYPE) -> bytes: ...

class AddressSet(set[_T]):
    def __init__(self) -> None: ...
    def add(self, value: _T) -> None: ...
    def diff(self) -> _T: ...

class UnicodeStringWrapperPostProcessor:
    string: Optional[bytes]
    def __init__(self, pe: PE, rva_ptr: int) -> None: ...
    def get_rva(self) -> int: ...
    def __str__(self) -> str: ...
    def decode(self, *args: str) -> str: ...
    def invalidate(self) -> None: ...
    def render_pascal_16(self) -> None: ...
    def get_pascal_16_length(self) -> Any | Literal[False]: ...
    def ask_unicode_16(self, next_rva_ptr: int) -> bool: ...
    def render_unicode_16(self) -> None: ...

class PEFormatError(Exception):
    def __init__(self, value: Any) -> None: ...
    def __str__(self) -> str: ...

class Dump:
    def __init__(self) -> None: ...
    def add_lines(self, txt: list[str], indent: int = ...) -> None: ...
    def add_line(self, txt: str, indent: int = ...) -> None: ...
    def add(self, txt: str, indent: int = ...) -> None: ...
    def add_header(self, txt: str) -> None: ...
    def add_newline(self) -> None: ...
    def get_text(self) -> str: ...

STRUCT_SIZEOF_TYPES: dict[str, int] = ...

_STRUCTURE_FORMAT = tuple[str, Sequence[str]]
_NAMED_STRUCTURE_FORMAT = tuple[_T, Sequence[str]]

@lru_cache(maxsize=2048)
def sizeof_type(t: str) -> int: ...
@lru_cache(maxsize=2048, copy=True)
def set_format(
    format: _STRUCTURE_FORMAT,
) -> tuple[str, list[None], dict[str, int], list[str], int]: ...

class _Structure_Dict_Value(TypedDict):
    FileOffset: int
    Offset: int
    Value: str

class Structure:
    __file_offset__: int

    def __init__(
        self,
        format: _STRUCTURE_FORMAT,
        name: str | None = ...,
        file_offset: int | None = ...,
    ) -> None: ...
    def __get_format__(self) -> str: ...
    def get_field_absolute_offset(self, field_name: str) -> int: ...
    def get_field_relative_offset(self, field_name: str) -> int: ...
    def get_file_offset(self) -> int: ...
    def set_file_offset(self, offset: int) -> None: ...
    def all_zeroes(self) -> bool: ...
    def sizeof(self) -> int: ...
    def __unpack__(self, data: _DATA_TYPE) -> None: ...
    def __pack__(self) -> bytes: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def dump(self, indentation: int = ...) -> list[str]: ...
    def dump_dict(self) -> dict[str, str | _Structure_Dict_Value]: ...

class SectionStructure(Structure):
    pe: PE
    PhysicalAddress: _UInt32
    VirtualAddress: _UInt32
    Misc_VirtualSize: _UInt32
    SizeOfRawData: _UInt32
    PointerToRawData: _UInt32
    PointerToRelocations: _UInt32
    PointerToLinenumbers: _UInt32
    NumberOfRelocations: _UInt16
    NumberOfLinenumbers: _UInt16
    Characteristics: _UInt32
    Name: _char[8]  # type: ignore[type-arg,valid-type]

    PointerToRawData_adj: int | None
    VirtualAddress_adj: int | None
    section_min_addr: int | None
    section_max_addr: int | None

    next_section_virtual_address: int | None

    def __init__(self, *argl: Any, **argd: Any) -> None: ...
    def get_PointerToRawData_adj(self) -> int: ...
    def get_VirtualAddress_adj(self) -> int: ...
    def get_data(
        self,
        start: int | None = ...,
        length: int | None = ...,
        ignore_padding: bool = ...,
    ) -> bytes: ...
    def __setattr__(self, name: str, val: Any) -> None: ...
    def get_rva_from_offset(self, offset: int) -> int: ...
    def get_offset_from_rva(self, rva: int) -> int: ...
    def contains_offset(self, offset: int) -> bool: ...
    def contains_rva(self, rva: int) -> bool: ...
    def contains(self, rva: int) -> bool: ...
    def get_entropy(self) -> float | Literal[0]: ...
    def get_hash_sha1(self) -> str | None: ...
    def get_hash_sha256(self) -> str | None: ...
    def get_hash_sha512(self) -> str | None: ...
    def get_hash_md5(self) -> str | None: ...
    def entropy_H(self, data: _DATA_TYPE) -> float | Literal[0]: ...

@lru_cache(maxsize=2048, copy=False)
def set_bitfields_format(
    format: _STRUCTURE_FORMAT,
) -> tuple[
    str,
    int,
    dict[str, int],
    list[str],
    list[str],
    dict[int, tuple[str, list[tuple[str, int]]]],
]: ...

class StructureWithBitfields(Structure):
    BTF_NAME_IDX: Literal[0] = ...
    BTF_BITCNT_IDX: Literal[1] = ...
    CF_TYPE_IDX: Literal[0] = ...
    CF_SUBFLD_IDX: Literal[1] = ...
    def __init__(
        self,
        format: _STRUCTURE_FORMAT,
        name: str | None = ...,
        file_offset: int | None = ...,
    ) -> None: ...
    def __unpack__(self, data: _DATA_TYPE) -> None: ...
    def __pack__(self) -> bytes: ...
    def dump(self, indentation: int = ...) -> list[str]: ...
    def dump_dict(self) -> dict[str, str | _Structure_Dict_Value]: ...

class _DOS_Header(Structure):
    name: _fmt.IMAGE_DOS_HEADER_format_name
    e_magic: _char[2]  # type: ignore[type-arg,valid-type] # H
    e_cblp: _UInt16
    e_cp: _UInt16
    e_crlc: _UInt16
    e_parhdr: _UInt16
    e_minalloc: _UInt16
    e_maxalloc: _UInt16
    e_ss: _UInt16
    e_sp: _UInt16
    e_csum: _UInt16
    e_ip: _UInt16
    e_cs: _UInt16
    e_lfarlc: _UInt16
    e_ovno: _UInt16
    e_res: _char[8]  # type: ignore[type-arg,valid-type] # 8s
    e_oemid: _UInt16
    e_oeminfo: _UInt16
    e_res2: _char[20]  # type: ignore[type-arg,valid-type] # 20s
    e_lfanew: _Int32

class _File_Header(Structure):
    name: _fmt.IMAGE_FILE_HEADER_format_name
    Machine: _gen.MACHINE_TYPE_DICT_VALUES
    NumberOfSections: _UInt16
    TimeDateStamp: _UInt32
    PointerToSymbolTable: _UInt32
    NumberOfSymbols: _UInt32
    SizeOfOptionalHeader: _UInt16
    Characteristics: _UInt16

class _Data_Directory(Structure):
    name: _fmt.IMAGE_DATA_DIRECTORY_format_name
    VirtualAddress: _UInt32
    Size: _UInt32

_MAGIC_TYPE = _UInt16

class _Optional_Header_Base(Structure, Generic[_Ptr]):
    Magic: _MAGIC_TYPE
    MajorLinkerVersion: _byte
    MinorLinkerVersion: _byte
    SizeOfCode: _UInt32
    SizeOfInitializedData: _UInt32
    SizeOfUninitializedData: _UInt32
    AddressOfEntryPoint: _UInt32
    BaseOfCode: _UInt32
    ImageBase: _Ptr
    SectionAlignment: _UInt32
    FileAlignment: _UInt32
    MajorOperatingSystemVersion: _UInt16
    MinorOperatingSystemVersion: _UInt16
    MajorImageVersion: _UInt16
    MinorImageVersion: _UInt16
    MajorSubsystemVersion: _UInt16
    MinorSubsystemVersion: _UInt16
    Win32VersionValue: _UInt32
    SizeOfImage: _UInt32
    SizeOfHeaders: _UInt32
    CheckSum: _UInt32
    Subsystem: _gen.SUBSYSTEM_TYPE_DICT_VALUES
    DllCharacteristics: _gen.DLL_CHARACTERISTICS_DICT_VALUES
    SizeOfStackReserve: _Ptr
    SizeOfStackCommit: _Ptr
    SizeOfHeapReserve: _Ptr
    SizeOfHeapCommit: _Ptr
    LoaderFlags: _UInt32
    NumberOfRvaAndSizes: _UInt32
    # DataDirectory: list[int]
    DATA_DIRECTORY: list[_Data_Directory]

class _Optional_Header32(_Optional_Header_Base[_UInt32]):
    name: _fmt.IMAGE_OPTIONAL_HEADER_format_name
    BaseOfData: _UInt32

class _Optional_Header64(_Optional_Header_Base[_UInt64]):
    name: _fmt.IMAGE_OPTIONAL_HEADER64_format_name

_Optional_Header = _Optional_Header32 | _Optional_Header64

class _NT_Headers(Structure):
    name: _fmt.IMAGE_NT_HEADERS_format_name
    Signature: _UInt32
    # FileHeader: _File_Header
    FILE_HEADER: _File_Header
    # OptionalHeader: _Optional_Header
    OPTIONAL_HEADER: _Optional_Header32 | _Optional_Header64

# IMAGE_SECTION_HEADER is implemented as SectionStructure

class _Delay_Import_Descriptor(Structure):
    name: _fmt.IMAGE_DELAY_IMPORT_DESCRIPTOR_format_name
    grAttrs: _UInt32
    szName: _UInt32
    phmod: _UInt32
    pIAT: _UInt32
    pINT: _UInt32
    pBoundIAT: _UInt32
    pUnloadIAT: _UInt32
    dwTimeStamp: _UInt32

class _Import_Descriptor(Structure):
    name: _fmt.IMAGE_IMPORT_DESCRIPTOR_format_name
    OriginalFirstThunk: _UInt32
    Characteristics: _UInt32
    TimeDateStamp: _UInt32
    ForwarderChain: _UInt32
    Name: _UInt32
    FirstThunk: _UInt32

class _Export_Directory(Structure):
    name: _fmt.IMAGE_EXPORT_DIRECTORY_format_name
    Characteristics: _UInt32
    TimeDateStamp: _UInt32
    MajorVersion: _UInt16
    MinorVersion: _UInt16
    Name: _UInt32
    Base: _UInt32
    NumberOfFunctions: _UInt32
    NumberOfNames: _UInt32
    AddressOfFunctions: _UInt32
    AddressOfNames: _UInt32
    AddressOfNameOrdinals: _UInt32

class _Resource_Directory(Structure):
    name: _fmt.IMAGE_RESOURCE_DIRECTORY_format_name
    Characteristics: _UInt32
    TimeDateStamp: _UInt32
    MajorVersion: _UInt16
    MinorVersion: _UInt16
    NumberOfNamedEntries: _UInt16
    NumberOfIdEntries: _UInt16

class _Resource_Directory_Entry(Structure):
    name: _fmt.IMAGE_RESOURCE_DIRECTORY_ENTRY_format_name
    Name: _gen.RESOURCE_TYPE_DICT_VALUES
    Id: _gen.RESOURCE_TYPE_DICT_VALUES
    NameOffset: _UInt32

    OffsetToData: _UInt32
    Size: _UInt32
    CodePage: _UInt32
    Reserved: _UInt32

    DataIsDirectory: _UInt32
    OffsetToDirectory: _UInt32

    __pad: _UInt32

class _Resource_Data_Entry(Structure):
    name: _fmt.IMAGE_RESOURCE_DATA_ENTRY_format_name
    OffsetToData: _UInt32
    Size: _UInt32
    CodePage: _UInt32
    Reserved: _UInt32

class _VersionStructure(Structure):
    Length: _UInt16
    ValueLength: _UInt16
    Type: _UInt16
    Key: bytes

class _VersionInfo(_VersionStructure):
    name: _fmt.VS_VERSIONINFO_format_name

class _FixedFileInfo(Structure):
    name: _fmt.VS_FIXEDFILEINFO_format_name
    Signature: _UInt32
    StrucVersion: _UInt32
    FileVersionMS: _UInt32
    FileVersionLS: _UInt32
    ProductVersionMS: _UInt32
    ProductVersionLS: _UInt32
    FileFlagsMask: _UInt32
    FileFlags: _UInt32
    FileOS: _UInt32
    FileType: _UInt32
    FileSubtype: _UInt32
    FileDateMS: _UInt32
    FileDateLS: _UInt32

class _StringFileInfo(_VersionStructure):
    name: _fmt.StringFileInfo_format_name
    StringTable: list["_StringTable"]
    Var: list["_Var"]

class _StringTable(_VersionStructure):
    name: _fmt.StringTable_format_name

    entries: dict[bytes, bytes]
    entries_offsets: dict[bytes, tuple[_UInt32, _UInt32]]
    entries_lengths: dict[bytes, tuple[int, int]]
    LangID: bytes
    Length: int

class _String(_VersionStructure):
    name: _fmt.String_format_name

class _VarFileInfo(_VersionStructure):
    name: Literal["VarFileInfo"]
    Var: list[_Var]  # "Children"

class _Var(_VersionStructure):
    name: _fmt.Var_format_name
    entry: dict[bytes, str]  # "Value"

class _Thunk_Data_Base(Structure, Generic[_Ptr]):
    # Union
    ForwarderString: _Ptr
    Function: _Ptr
    Ordinal: _Ptr
    AddressOfData: _Ptr
    # /Union

class _Thunk_Data32(_Thunk_Data_Base[_UInt32]):
    name: _fmt.IMAGE_THUNK_DATA_format_name

class _Thunk_Data64(_Thunk_Data_Base[_UInt64]):
    name: _fmt.IMAGE_THUNK_DATA64_format_name

_Thunk_Data = _Thunk_Data32 | _Thunk_Data64

class _Debug_Directory(Structure):
    name: _fmt.IMAGE_DEBUG_DIRECTORY_format_name
    Characteristics: _UInt32
    TimeDateStamp: _UInt32
    MajorVersion: _UInt16
    MinorVersion: _UInt16
    Type: _gen.DEBUG_TYPE_DICT_VALUES
    SizeOfData: _UInt32
    AddressOfRawData: _UInt32
    PointerToRawData: _UInt32

class _Base_Relocation(Structure):
    name: _fmt.IMAGE_BASE_RELOCATION_format_name
    VirtualAddress: _UInt32
    SizeOfBlock: _UInt32

class _Base_Relocation_Entry(Structure):
    name: _fmt.IMAGE_BASE_RELOCATION_ENTRY_format_name
    Data: _UInt16

class _Dynamic_Relocation_Bitfield(StructureWithBitfields):
    PageRelativeOffset: int  # I:12

class _Import_Control_Transfer_Dynamic_Relocation(_Dynamic_Relocation_Bitfield):
    name: _fmt.IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format_name
    PageRelativeOffset: int  # I:12
    IndirectCall: int  # I:1
    IATIndex: int  # I:19

class _Indir_Control_Transfer_Dynamic_Relocation(_Dynamic_Relocation_Bitfield):
    name: _fmt.IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format_name
    PageRelativeOffset: int  # H:12
    IndirectCall: int  # H:1
    RexWPrefix: int  # H:1
    CfgCheck: int  # H:1
    Reserved: int  # H:1

class _Switchtable_Branch_Dynamic_Relocation(_Dynamic_Relocation_Bitfield):
    name: _fmt.IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION_format_name
    PageRelativeOffset: int  # H:12
    RegisterNumber: int  # H:4

class _TLS_Directory_Base(Structure, Generic[_Ptr]):
    SizeOfZeroFill: _UInt32
    Characteristics: _UInt32
    StartAddressOfRawData: _Ptr
    EndAddressOfRawData: _Ptr
    AddressOfIndex: _Ptr
    AddressOfCallBacks: _Ptr

class _TLS_Directory32(_TLS_Directory_Base[_UInt32]):
    name: _fmt.IMAGE_TLS_DIRECTORY_format_name

class _TLS_Directory64(_TLS_Directory_Base[_UInt64]):
    name: _fmt.IMAGE_TLS_DIRECTORY64_format_name

_TLS_Directory = _TLS_Directory32 | _TLS_Directory64

class _Load_Config_Directory_Base(Structure, Generic[_Ptr]):
    Size: _UInt32
    TimeDateStamp: _UInt32
    MajorVersion: _UInt16
    MinorVersion: _UInt16
    GlobalFlagsClear: _UInt32
    GlobalFlagsSet: _UInt32
    CriticalSectionDefaultTimeout: _UInt32
    DeCommitFreeBlockThreshold: _Ptr
    DeCommitTotalFreeThreshold: _Ptr
    LockPrefixTable: _Ptr
    MaximumAllocationSize: _Ptr
    VirtualMemoryThreshold: _Ptr
    ProcessHeapFlags: _UInt32
    ProcessAffinityMask: _Ptr
    CSDVersion: _UInt16
    DependentLoadFlags: _UInt16
    EditList: _Ptr
    SecurityCookie: _Ptr
    SEHandlerTable: _Ptr
    SEHandlerCount: _Ptr
    GuardCFCheckFunctionPointer: _Ptr
    GuardCFDispatchFunctionPointer: _Ptr
    GuardCFFunctionTable: _Ptr
    GuardCFFunctionCount: _Ptr
    GuardFlags: _UInt32
    CodeIntegrityFlags: _UInt16
    CodeIntegrityCatalog: _UInt16
    CodeIntegrityCatalogOffset: _UInt32
    CodeIntegrityReserved: _UInt32
    GuardAddressTakenIatEntryTable: _Ptr
    GuardAddressTakenIatEntryCount: _Ptr
    GuardLongJumpTargetTable: _Ptr
    GuardLongJumpTargetCount: _Ptr
    DynamicValueRelocTable: _Ptr
    CHPEMetadataPointer: _Ptr
    GuardRFFailureRoutine: _Ptr
    GuardRFFailureRoutineFunctionPointer: _Ptr
    DynamicValueRelocTableOffset: _UInt32
    DynamicValueRelocTableSection: _UInt16
    Reserved2: _UInt16
    GuardRFVerifyStackPointerFunctionPointer: _Ptr
    HotPatchTableOffset: _UInt32
    Reserved3: _UInt32
    EnclaveConfigurationPointer: _Ptr
    VolatileMetadataPointer: _Ptr
    GuardEHContinuationTable: _Ptr
    GuardEHContinuationCount: _Ptr
    GuardXFGCheckFunctionPointer: _Ptr
    GuardXFGDispatchFunctionPointer: _Ptr
    GuardXFGTableDispatchFunctionPointer: _Ptr
    CastGuardOsDeterminedFailureMode: _Ptr
    GuardMemcpyFunctionPointer: _Ptr

class _Load_Config_Directory32(_Load_Config_Directory_Base[_UInt32]):
    name: _fmt.IMAGE_LOAD_CONFIG_DIRECTORY_format_name

class _Load_Config_Directory64(_Load_Config_Directory_Base[_UInt64]):
    name: _fmt.IMAGE_LOAD_CONFIG_DIRECTORY64_format_name

_Load_Config_Directory = _Load_Config_Directory32 | _Load_Config_Directory64

class _Dynamic_Relocation_Table(Structure):
    name: _fmt.IMAGE_DYNAMIC_RELOCATION_TABLE_format_name
    Version: _UInt32
    Size: _UInt32

class _Dynamic_Relocation_Base(Structure, Generic[_Ptr]):
    Symbol: _Ptr
    BaseRelocSize: _UInt32

class _Dynamic_Relocation32(_Dynamic_Relocation_Base[_UInt32]):
    name: _fmt.IMAGE_DYNAMIC_RELOCATION_format_name

class _Dynamic_Relocation64(_Dynamic_Relocation_Base[_UInt64]):
    name: _fmt.IMAGE_DYNAMIC_RELOCATION64_format_name

_Dynamic_Relocation = _Dynamic_Relocation32 | _Dynamic_Relocation64

class _Dynamic_Relocation_V2_Base(Structure, Generic[_Ptr]):
    HeaderSize: _UInt32
    FixupInfoSize: _UInt32
    Symbol: _Ptr
    SymbolGroup: _UInt32
    Flags: _UInt32

class _Dynamic_Relocation32_V2(_Dynamic_Relocation_V2_Base[_UInt32]):
    name: _fmt.IMAGE_DYNAMIC_RELOCATION_V2_format_name

class _Dynamic_Relocation64_V2(_Dynamic_Relocation_V2_Base[_UInt64]):
    name: _fmt.IMAGE_DYNAMIC_RELOCATION64_V2_format_name

_Dynamic_Relocation_V2 = _Dynamic_Relocation32_V2 | _Dynamic_Relocation64_V2

class _Bound_Import_Descriptor(Structure):
    name: _fmt.IMAGE_BOUND_IMPORT_DESCRIPTOR_format_name
    TimeDateStamp: _UInt32
    OffsetModuleName: _UInt16
    NumberOfModuleForwarderRefs: _UInt16

class _Bound_Forwarder_Ref(Structure):
    name: _fmt.IMAGE_BOUND_FORWARDER_REF_format_name
    TimeDateStamp: _UInt32
    OffsetModuleName: _UInt16
    Reserved: _UInt16

class _Runtime_Function(Structure):
    name: _fmt.RUNTIME_FUNCTION_format_name
    BeginAddress: _UInt32
    EndAddress: _UInt32
    UnwindData: _UInt32
    UnwindInfoAddress: _UInt32

# Debug Types
class _Debug_Type(Structure):
    pass

class _Debug_Misc(_Debug_Type):
    name: Literal["IMAGE_DEBUG_MISC"]
    DataType: _UInt32
    Length: _UInt32
    Unicode: _char
    Reserved1: _char
    Reserved2: _UInt16

class _CV_Info_PDB20(_Debug_Type):
    name: Literal["CV_INFO_PDB20"]
    CvHeaderSignature: _UInt32
    CvHeaderOffset: _UInt32
    Signature: _UInt32
    Age: _UInt32

class _CV_Info_PDB70(_Debug_Type):
    name: Literal["CV_INFO_PDB70"]
    CvSignature: _char[4]  # type: ignore[type-arg,valid-type]
    Signature_Data1: _UInt32  # Signature is of GUID type
    Signature_Data2: _UInt16
    Signature_Data3: _UInt16
    Signature_Data4: _char
    Signature_Data5: _char
    Signature_Data6: _char[6]  # type: ignore[type-arg,valid-type]
    Signature_Data6_value: bytes
    Age: _UInt32
    # int == (Debug_Directory.SizeOfData - sizeof(CV_INFO_PDB70))
    PdbFileName: _char
    Signature_String: str

# Misc
class _RichHeader:
    checksum: bytes
    values: bytes
    key: bytes
    raw_data: bytes
    clear_data: bytes

class DataContainer:
    name: bytes | None
    def __init__(self, **args: Any) -> None: ...

class _DataContainer_Struct(DataContainer, Generic[_T]):
    struct: _T
    def __init(self, struct: _T, **args: Any) -> None: ...

class ImportDescData(
    _DataContainer_Struct[_Import_Descriptor | _Delay_Import_Descriptor]
):
    dll: bytes
    imports: list["ImportData"]

class ImportData(DataContainer):
    pe: PE
    struct_table: _Thunk_Data
    struct_iat: _Thunk_Data | None
    import_by_ordinal: bool
    ordinal: bytes | None
    ordinal_offset: int
    hint: _UInt16
    name_offset: int
    bound: _UInt32 | _UInt64
    address: _UInt32 | _UInt64
    hint_name_table_rva: _UInt32 | _UInt64
    thunk_offset: int
    thunk_rva: int
    def __setattr__(self, name: str, val: Any) -> None: ...

class ExportDirData(_DataContainer_Struct[_Export_Directory]): ...

class ExportData(DataContainer):
    pe: PE
    ordinal: int
    ordinal_offset: int
    address: int
    address_offset: int
    name: bytes
    name_offset: int
    forwarder: bytes
    forwarder_offset: int
    def __setattr__(self, name: str, val: Any) -> None: ...

class ResourceDirData(_DataContainer_Struct[_Resource_Directory]):
    entries: list[ResourceDirEntryData]
    strings: dict[int, str]

class ResourceDirEntryData(_DataContainer_Struct[_Resource_Directory_Entry]):
    name: Optional[UnicodeStringWrapperPostProcessor] # type: ignore
    id: _gen.RESOURCE_TYPE_DICT_VALUES
    directory: ResourceDirData
    data: ResourceDataEntryData

class ResourceDataEntryData(_DataContainer_Struct[_Resource_Data_Entry]):
    lang: _gen.LANG_DICT_VALUES
    sublang: _gen.SUBLANG_DICT_VALUES

class DebugData(_DataContainer_Struct[_Debug_Directory]):
    entry: _Debug_Type

class DynamicRelocationData(_DataContainer_Struct[_Dynamic_Relocation]):
    relocations: list[BaseRelocationData]

class BaseRelocationData(_DataContainer_Struct[_Base_Relocation]):
    entries: list[RelocationData]

class RelocationData(
    _DataContainer_Struct[_Base_Relocation_Entry | _Dynamic_Relocation_Bitfield]
):
    type: _gen.RELOCATION_TYPE_DICT_VALUES
    rva: int
    base_rva: int
    def __setattr__(self, name: str, val: Any) -> None: ...

class TlsData(_DataContainer_Struct[_TLS_Directory]): ...

class BoundImportDescData(_DataContainer_Struct[_Bound_Import_Descriptor]):
    entries: list[BoundImportRefData]

class LoadConfigData(_DataContainer_Struct[_Load_Config_Directory]):
    dynamic_relocations: list[DynamicRelocationData]

class BoundImportRefData(_DataContainer_Struct[_Bound_Forwarder_Ref]): ...

class ExceptionsDirEntryData(_DataContainer_Struct[_Runtime_Function]):
    unwindinfo: UnwindInfo

class UnwindInfo(StructureWithBitfields):
    Version: _char[3]  # type: ignore[type-arg,valid-type]
    Flags: _char[5]  # type: ignore[type-arg,valid-type]
    SizeOfProlog: _char
    CountOfCodes: int
    FrameRegister: _char[4]  # type: ignore[type-arg,valid-type]
    FrameOffset: _char[4]  # type: ignore[type-arg,valid-type]

    UNW_FLAG_EHANDLER: Literal[0, 0x01]
    UNW_FLAG_UHANDLER: Literal[0, 0x02]
    UNW_FLAG_CHAININFO: Literal[0, 0x04]
    def __init__(self, file_offset: int = ...) -> None: ...
    def unpack_in_stages(self, data: _DATA_TYPE) -> str | None: ...
    def dump(self, indentation: int = ...) -> list[str]: ...
    def dump_dict(self) -> dict[str, str | _Structure_Dict_Value]: ...
    def __setattr__(self, name: str, val: Any) -> None: ...
    def sizeof(self) -> int: ...
    def __pack__(self) -> bytes: ...
    def get_chained_function_entry(self) -> ExceptionsDirEntryData: ...
    def set_chained_function_entry(self, entry: ExceptionsDirEntryData) -> None: ...

class _Unwind_Code_Base(UnwindInfo):
    CodeOffset: _char
    UnwindOp: _char[4]  # type: ignore[type-arg,valid-type]
    OpInfo: _char[4]  # type: ignore[type-arg,valid-type]

class _Unwind_Code(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE"]

_Unwind_Code_Type = TypeVar("_Unwind_Code_Type", bound=_Unwind_Code_Base)

class _Unwind_Code_Push_NonVol(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_PUSH_NONVOL"]
    Reg: _gen.REGISTERS_DICT_VALUES

class _Unwind_Code_Alloc_Large(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_ALLOC_LARGE"]
    AllocSizeInQwords: _UInt16
    AllocSize: _UInt32

class _Unwind_Code_Alloc_Small(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_ALLOC_SMALL"]
    AllocSizeInQwordsMinus8: int

_Unwind_Code_Set_Fp = _Unwind_Code

class _Unwind_Code_Save_Reg(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_SAVE_NONVOL"]
    Reg: _gen.REGISTERS_DICT_VALUES
    OffsetInQwords: _UInt16

class _Unwind_Code_Save_Reg_Far(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_SAVE_NONVOL_FAR"]
    Reg: _gen.REGISTERS_DICT_VALUES
    Offset: _UInt32

class _Unwind_Code_Save_XMM(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_SAVE_XMM128"]
    Reg: _char[4]  # type: ignore[type-arg,valid-type]
    OffsetIn2Qwords: _UInt16

class _Unwind_Code_Save_XMM_Far(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_SAVE_XMM128_FAR"]
    Reg: int
    Offset: "_UInt32"

_Unwind_Code_Push_Frame = _Unwind_Code

class _Unwind_Code_Epilog_Marker(_Unwind_Code_Base):
    name: Literal["UNWIND_CODE_EPILOG"]
    Size: _char
    UnwindOp: _char[4]  # type: ignore[type-arg,valid-type]
    Flags: _char[4]  # type: ignore[type-arg,valid-type]
    OffsetLow: _char
    Unused: _char[4]  # type: ignore[type-arg,valid-type]
    OffsetHigh: _char[4]  # type: ignore[type-arg,valid-type]

class PrologEpilogOp(ABC, Generic[_Unwind_Code_Type]):
    struct: _Unwind_Code_Type
    def initialize(
        self,
        unw_code: StructureWithBitfields,
        data: _DATA_TYPE,
        unw_info: UnwindInfo,
        file_offset: int | None,
    ) -> None: ...
    def length_in_code_structures(
        self, unw_code: StructureWithBitfields, unw_info: UnwindInfo
    ) -> int: ...
    def is_valid(self) -> bool: ...

class PrologEpilogOpPushReg(PrologEpilogOp[_Unwind_Code_Push_NonVol]):
    def __str__(self) -> str: ...

class PrologEpilogOpAllocLarge(PrologEpilogOp[_Unwind_Code_Alloc_Large]):
    def length_in_code_structures(
        self, unw_code: StructureWithBitfields, unw_info: UnwindInfo
    ) -> int: ...
    def get_alloc_size(self) -> int: ...
    def __str__(self) -> str: ...

class PrologEpilogOpAllocSmall(PrologEpilogOp[_Unwind_Code_Alloc_Small]):
    def get_alloc_size(self) -> int: ...
    def __str__(self) -> str: ...

class PrologEpilogOpSetFP(PrologEpilogOp[_Unwind_Code_Set_Fp]):
    def initialize(
        self,
        unw_code: StructureWithBitfields,
        data: _DATA_TYPE,
        unw_info: UnwindInfo,
        file_offset: int | None,
    ) -> None: ...
    def __str__(self) -> str: ...

class PrologEpilogOpSaveReg(PrologEpilogOp[_Unwind_Code_Save_Reg]):
    def length_in_code_structures(
        self, unwcode: StructureWithBitfields, unw_info: UnwindInfo
    ) -> int: ...
    def get_offset(self) -> int: ...
    def __str__(self) -> str: ...

class PrologEpilogOpSaveRegFar(PrologEpilogOp[_Unwind_Code_Save_Reg_Far]):
    def length_in_code_structures(
        self, unw_code: StructureWithBitfields, unw_info: UnwindInfo
    ) -> int: ...
    def get_offset(self) -> int: ...
    def __str__(self) -> str: ...

class PrologEpilogOpSaveXMM(PrologEpilogOp[_Unwind_Code_Save_XMM]):
    def length_in_code_structures(
        self, unw_code: StructureWithBitfields, unw_info: UnwindInfo
    ) -> int: ...
    def get_offset(self) -> int: ...
    def __str__(self) -> str: ...

class PrologEpilogOpSaveXMMFar(PrologEpilogOp[_Unwind_Code_Save_XMM_Far]):
    def length_in_code_structures(
        self, unw_code: StructureWithBitfields, unw_info: UnwindInfo
    ) -> int: ...
    def get_offset(self) -> int: ...
    def __str__(self) -> str: ...

class PrologEpilogOpPushFrame(PrologEpilogOp[_Unwind_Code_Push_Frame]):
    def __str__(self) -> str: ...

class PrologEpilogOpEpilogMarker(PrologEpilogOp[_Unwind_Code_Epilog_Marker]):
    def initialize(
        self,
        unw_code: StructureWithBitfields,
        data: _DATA_TYPE,
        unw_info: UnwindInfo,
        file_offset: int | None,
    ) -> None: ...
    def length_in_code_structures(
        self, unw_code: StructureWithBitfields, unw_info: UnwindInfo
    ) -> int: ...
    def get_offset(self) -> int: ...
    def is_valid(self) -> bool: ...
    def __str__(self) -> str: ...

class PrologEpilogOpsFactory:
    _class_dict: dict[int, type[PrologEpilogOp[Any]]] = ...
    @staticmethod
    def create(unwcode: StructureWithBitfields) -> PrologEpilogOp[Any]: ...

allowed_filename: bytes = ...

def is_valid_dos_filename(s: str | bytes | bytearray) -> bool: ...

allowed_function_name: bytes = ...

@lru_cache(maxsize=2048)
def is_valid_function_name(
    s: str | bytes | bytearray, relax_allowed_characters: bool = ...
) -> bool: ...

class PE(AbstractContextManager["PE"], _fmt.PE): # type: ignore[misc]
    DOS_HEADER: _DOS_Header
    OPTIONAL_HEADER: _Optional_Header
    NT_HEADERS: _NT_Headers
    FILE_HEADER: _File_Header

    sections: list[SectionStructure]

    DIRECTORY_ENTRY_IMPORT: list[ImportDescData]
    DIRECTORY_ENTRY_EXPORT: ExportDirData
    DIRECTORY_ENTRY_RESOURCE: ResourceDirData
    DIRECTORY_ENTRY_DEBUG: list[DebugData]
    DIRECTORY_ENTRY_BASERELOC: list[BaseRelocationData]
    DIRECTORY_ENTRY_TLS: TlsData
    DIRECTORY_ENTRY_BOUND_IMPORT: list[BoundImportDescData]

    DIRECTORY_ENTRY_LOAD_CONFIG: LoadConfigData
    DIRECTORY_ENTRY_EXCEPTION: list[ExceptionsDirEntryData]
    DIRECTORY_ENTRY_DELAY_IMPORT: list[ImportDescData]

    VS_VERSIONINFO: list[_VersionInfo]
    VS_FIXEDFILEINFO: list[_FixedFileInfo]
    FileInfo: list[list[_StringFileInfo]]

    __data__: _DATA_TYPE
    __structures__: list[Structure]

    @overload
    def __init__(
        self,
        name: str = ...,
        data: None = ...,
        fast_load: bool | None = ...,
        max_symbol_exports: int = ...,
        max_repeated_symbol: int = ...,
    ) -> None: ...
    @overload
    def __init__(
        self,
        name: None = ...,
        data: _DATA_TYPE = ...,
        fast_load: bool | None = ...,
        max_symbol_exports: int = ...,
        max_repeated_symbol: int = ...,
    ) -> None: ...
    def __enter__(self) -> 'PE': ...
    def __exit__(
        self,
        type: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...
    def close(self) -> None: ...
    def __unpack_data__(
        self,
        format: _fmt.IMAGE_DOS_HEADER_format,
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _DOS_Header | None: ...
    def __unpack_data_with_bitfields__(
        self,
        format: _fmt.IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION_format,
        data: _DATA_TYPE,
        file_offset: int,
    ) -> _Import_Control_Transfer_Dynamic_Relocation | None: ...
    @overload
    def __parse__(self, fname: str, data: None, fast_load: bool) -> None: ...
    @overload
    def __parse__(self, fname: None, data: _DATA_TYPE, fast_load: bool) -> None: ...
    def parse_rich_header(self) -> dict[str, bytes] | None: ...
    def get_warnings(self) -> list[str]: ...
    def show_warnings(self) -> None: ...
    def full_load(self) -> None: ...
    @overload
    def write(self) -> bytearray: ...
    @overload
    def write(self, filename: str) -> None: ...
    @overload
    def write(self, filename: None = ...) -> bytearray: ...
    def parse_sections(self, offset: int) -> None: ...
    def parse_data_directories(
        self,
        directories: list[int] | None = ...,
        forwarded_exports_only: bool = ...,
        import_dllnames_only: bool = ...,
    ) -> None: ...
    def parse_exceptions_directory(
        self, rva: int, size: int
    ) -> list[ExceptionsDirEntryData] | None: ...
    def parse_directory_bound_imports(
        self, rva: int, size: int
    ) -> list[ImportData] | None: ...
    def parse_directory_tls(self, rva: int, size: int) -> TlsData | None: ...
    def parse_directory_load_config(
        self, rva: int, size: int
    ) -> LoadConfigData | None: ...
    def parse_dynamic_relocations(
        self,
        dynamic_value_reloc_table_offset: int,
        dynamic_value_reloc_table_section: int,
    ) -> list[DynamicRelocationData] | None: ...
    def parse_relocations_directory(
        self, rva: int, size: int
    ) -> list[BaseRelocationData]: ...
    def parse_image_base_relocation_list(
        self, rva: int, size: int, fmt: _STRUCTURE_FORMAT | None = ...
    ) -> list[BaseRelocationData]: ...
    def parse_relocations(
        self, data_rva: int, rva: int, size: int
    ) -> list[RelocationData]: ...
    def parse_relocations_with_format(
        self, data_rva: int, rva: int, size: int, format: _STRUCTURE_FORMAT | None
    ) -> list[RelocationData]: ...
    def parse_debug_directory(self, rva: int, size: int) -> list[DebugData] | None: ...
    def parse_resources_directory(
        self,
        rva: int,
        size: int = ...,
        base_rva: int | None = ...,
        level: int = ...,
        dirs: list[int] | None = ...,
    ) -> ResourceDirData | None: ...
    def parse_resource_data_entry(self, rva: int) -> _Resource_Data_Entry | None: ...
    def parse_resource_entry(self, rva: int) -> _Resource_Directory_Entry | None: ...
    def parse_version_information(
        self, version_struct: _Resource_Data_Entry
    ) -> None: ...
    def parse_export_directory(
        self, rva: int, size: int, forwarded_only: bool = ...
    ) -> ExportDirData | None: ...
    def dword_align(self, offset: int, base: int) -> int: ...
    def normalize_import_va(self, va: int) -> int: ...
    def parse_delay_import_directory(
        self, rva: int, size: int
    ) -> list[ImportDescData]: ...
    def get_rich_header_hash(
        self,
        algorithm: Literal["md5", "sha1", "sha256", "sha512"] = ...,
    ) -> _Hash: ...
    def get_imphash(self) -> str: ...
    def get_exphash(self) -> str: ...
    def parse_import_directory(
        self, rva: int, size: int, dllnames_only: bool = ...
    ) -> list[ImportDescData]: ...
    def parse_imports(
        self,
        original_first_thunk: int,
        first_thunk: int,
        forwarder_chain: Any | None,
        max_length: int | None = ...,
        contains_addresses: bool = ...,
    ) -> list[ImportData]: ...
    def get_import_table(
        self, rva: int, max_length: int | None = ..., contains_addresses: bool = ...
    ) -> list[_Thunk_Data] | None: ...
    def get_memory_mapped_image(
        self, max_virtual_address: int = ..., ImageBase: int | None = ...
    ) -> bytes: ...
    def get_resources_strings(self) -> list[str]: ...
    def get_data(self, rva: int = ..., length: int | None = ...) -> bytes: ...
    def get_rva_from_offset(self, offset: int) -> int: ...
    def get_offset_from_rva(self, rva: int) -> int: ...
    @overload
    def get_string_at_rva(self, rva: None, max_length: int | None) -> None: ...
    @overload
    def get_string_at_rva(self, rva: int, max_length: int | None = ...) -> bytes: ...
    def get_bytes_from_data(self, offset: int, data: _DATA_TYPE) -> bytes: ...
    def get_string_from_data(self, offset: int, data: _DATA_TYPE) -> bytes: ...
    def get_string_u_at_rva(
        self, rva: int, max_length: int | None = ..., encoding: str | None = ...
    ) -> bytes: ...
    def get_section_by_offset(self, offset: int) -> SectionStructure | None: ...
    def get_section_by_rva(self, rva: int) -> SectionStructure | None: ...
    def __str__(self) -> str: ...
    def has_relocs(self) -> bool: ...
    def has_dynamic_relocs(self) -> bool: ...
    def print_info(self, encoding: str | None = ...) -> None: ...
    def dump_info(self, dump: Dump | None = ..., encoding: str | None = ...) -> str: ...
    def dump_dict(self) -> dict[str, Any]: ...
    def get_physical_by_rva(self, rva: int) -> int: ...
    def get_data_from_dword(self, dword: _DWORD) -> bytes: ...
    def get_dword_from_data(self, data: _DATA_TYPE, offset: int) -> _DWORD | None: ...
    def get_dword_at_rva(self, rva: int) -> _DWORD | None: ...
    def get_dword_from_offset(self, offset: int) -> _DWORD | None: ...
    def set_dword_at_rva(self, rva: int, dword: _DWORD) -> bool: ...
    def set_dword_at_offset(self, offset: int, dword: _DWORD) -> bool: ...
    def get_data_from_word(self, word: _WORD) -> bytes: ...
    def get_word_from_data(self, data: _DATA_TYPE, offset: int) -> _WORD | None: ...
    def get_word_at_rva(self, rva: int) -> _WORD | None: ...
    def get_word_from_offset(self, offset: int) -> _WORD | None: ...
    def set_word_at_rva(self, rva: int, word: _WORD) -> bool: ...
    def set_word_at_offset(self, offset: int, word: _WORD) -> bool: ...
    def get_data_from_qword(self, word: _QWORD) -> bytes: ...
    def get_qword_from_data(self, data: _DATA_TYPE, offset: int) -> _QWORD | None: ...
    def get_qword_at_rva(self, rva: int) -> _QWORD | None: ...
    def get_qword_from_offset(self, offset: int) -> _QWORD | None: ...
    def set_qword_at_rva(self, rva: int, qword: _QWORD) -> bool: ...
    def set_qword_at_offset(self, offset: int, qword: _QWORD) -> bool: ...
    def set_bytes_at_rva(self, rva: int, data: _DATA_TYPE) -> bool: ...
    def set_bytes_at_offset(self, offset: int, data: _DATA_TYPE) -> bool: ...
    def set_data_bytes(self, offset: int, data: _DATA_TYPE) -> None: ...
    def merge_modified_section_data(self) -> None: ...
    def relocate_image(self, new_ImageBase: int) -> None: ...
    def verify_checksum(self) -> bool: ...
    def generate_checksum(self) -> int: ...
    def is_exe(self) -> bool: ...
    def is_dll(self) -> bool: ...
    def is_driver(self) -> bool: ...
    def get_overlay_data_start_offset(self) -> int | None: ...
    def get_overlay(self) -> bytes | None: ...
    def trim(self) -> bytes: ...
    def adjust_FileAlignment(self, val: int, file_alignment: int) -> int: ...
    def adjust_SectionAlignment(
        self, val: int, section_alignment: int, file_alignment: int
    ) -> int: ...

def main() -> None: ...

if __name__ == "__main__": ...
