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
UEFI Parser Qt GUI main logic.
"""

import sys
import functools
import traceback
import json
import typing
import bisect
import operator
import argparse
import binascii
import pdb
import logging
from dataclasses import dataclass
from typing import Any, Optional, Iterator, Iterable, ParamSpec, TypeVar
from types import TracebackType
from collections.abc import Callable

import construct
from PySide6.QtCore import (
    QAbstractItemModel, QModelIndex, Qt, QItemSelectionModel, QPersistentModelIndex,
    QPoint)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTreeView, QTableView, QSplitter, QAbstractItemView,
    QMenu, QFileDialog, QMessageBox, QVBoxLayout, QDialog, QFormLayout, QComboBox,
    QWidget, QDialogButtonBox, QPushButton, QCompleter)
from PySide6.QtGui import (
    QClipboard, QAction, QColor, QKeySequence, QValidator, QImage, QPixmap, QIcon,
    QCloseEvent)

from .qhexview import QHexView, QHexDocument, QHexMetadata
from .base import FirmwareStructure, UUIDAdapter
from .mystery import MysteryBytes
from .utils import ansi_to_html, ansi_to_plaintext
from .auto import AutoObject
from .icon import icon_data

log = logging.getLogger("cert-uefi-parser")

# ========================================================================================

selectionFlags = (QItemSelectionModel.SelectionFlag.Clear
                  | QItemSelectionModel.SelectionFlag.Select
                  | QItemSelectionModel.SelectionFlag.Rows
                  | QItemSelectionModel.SelectionFlag.Current)

def report_exception(exc_type: type[BaseException], exc_value: BaseException,
                     exc_tb: Optional[TracebackType]) -> None:
    log2stderr = print  # Print is generally banned from use in CERT UEFI parser.
    log2stderr("Type", exc_type, file=sys.stderr)
    log2stderr("Value", exc_value, file=sys.stderr)
    log2stderr("Tb", ''.join(traceback.format_tb(exc_tb)), file=sys.stderr)

def custom_excepthook(exc_type: type[BaseException], exc_value: BaseException,
                      exc_tb: Optional[TracebackType]) -> None:
    report_exception(exc_type, exc_value, exc_tb)
    pdb.pm()
    sys.__excepthook__(exc_type, exc_value, exc_tb)  # run standard exception hook

DEBUG = False
COLOR = False

def enable_debug() -> None:
    global DEBUG
    DEBUG = True
    sys.excepthook = custom_excepthook

def print_args(*args: Any, **kwds: dict[str, Any]) -> str:
    argstr = ', '.join(repr(x) for x in args)
    kwdstr = ', '.join(f'{k}={v!r}' for (k, v) in kwds.items())
    return ', '.join((argstr, kwdstr))


R = TypeVar('R')  # Return type of the decorated function
P = ParamSpec('P')  # Parameters of the decorated function
def debugmeth(func: Callable[P, R]) -> Callable[P, R]:
    if not DEBUG:
        return func

    @functools.wraps(func)
    def fun(*args: Any, **kwds: Any) -> Any:
        try:
            log2stderr = print  # Print is generally banned from use in CERT UEFI parser.
            log2stderr(f"{func.__name__}({print_args(*args, **kwds)}", file=sys.stderr)
            rv = func(*args, **kwds)
            log2stderr(f"{func.__name__}() => {rv!r}", file=sys.stderr)
            return rv
        except Exception:
            log2stderr(f"{func.__name__} => Exception", file=sys.stderr)
            traceback.print_exc()
            raise
    return fun


# ----------------------------------------------------------------------------------------
@dataclass(slots=True)
class TreeModelData:
    field_name: str  # Name of this struct as parent's field
    row: int  # Row of this struct in parent
    value: typing.Optional[FirmwareStructure]  # The actual struct
    parent: typing.Optional['TreeModelData']  # Pointer to parent or None
    children: list['TreeModelData']  # List of structs at this level of the tree
    table: list[Any]  # Terms from struct

    def __repr__(self) -> str:
        return f"<TreeModelData {hex(id(self))}>"

    def __str__(self) -> str:
        return f"<TreeModelData {hex(id(self))}>"

    def _tree_iter_helper(self, offset: int = 0) -> Iterator['TreeModelData']:
        for i in range(offset, len(self.children)):
            yield self.children[i]
            yield from self.children[i]._tree_iter_helper()

    def _rev_tree_iter_helper(self,
                              offset: Optional[int] = None) -> Iterator['TreeModelData']:
        if offset is None:
            offset = len(self.children) - 1
        for i in range(offset, -1, -1):
            yield from self.children[i]._rev_tree_iter_helper()
            yield self.children[i]

    def index(self, model: QAbstractItemModel) -> QModelIndex:
        if self.parent is None:
            return model.index(0, 0)
        pindex = self.parent.index(model)
        return model.index(self.row, 0, pindex)

    def root(self) -> 'TreeModelData':
        item = self
        while item.parent is not None:
            item = item.parent
        return item

    def tree_iter(self, full: bool = True, incl: bool = True,
                  circular: bool = False) -> Iterator['TreeModelData']:
        if incl:
            yield self
        yield from self._tree_iter_helper()
        if full:
            current = self
            while current.parent is not None:
                yield from current.parent._tree_iter_helper(current.row + 1)
                current = current.parent
            if circular:
                for item in current.tree_iter():
                    if item is self:
                        return None
                    yield item

    def rev_tree_iter(self, full: bool = True, incl: bool = True,
                      circular: bool = False) -> Iterator['TreeModelData']:
        if full:
            current = self
            while current.parent is not None:
                yield from current.parent._rev_tree_iter_helper(current.row - 1)
                current = current.parent
                yield current
            if circular:
                for item in current.rev_tree_iter():
                    if item is self:
                        if incl:
                            yield self
                        return None
        else:
            yield from self._rev_tree_iter_helper()
            if incl:
                yield self

    def __iter__(self) -> Iterator['TreeModelData']:
        return self.tree_iter(full=False)

    def __reversed__(self) -> Iterator['TreeModelData']:
        return self.rev_tree_iter(full=False)

    def debug_report(self, indent: str = '') -> None:
        log.info(f"{indent}{hex(id(self))} {self.row}")
        for child in self.children:
            child.debug_report(indent + ' ')

# ----------------------------------------------------------------------------------------
QMIndex = QModelIndex | QPersistentModelIndex

class FirmwareStructureModel(QAbstractItemModel):

    OFFSET = 0
    LENGTH = 1
    JSON_NAME = 2
    CLASS_NAME = 3
    INSTANCE_NAME = 4
    IDENT = 5

    def __init__(self, data: TreeModelData):
        super().__init__()
        if DEBUG:
            data.debug_report()
        self.root_data = TreeModelData("root", -1, None, None, [data], [])

    def index(self, row: int, column: int,
              parent: QMIndex = QModelIndex()) -> QModelIndex:
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        if not parent.isValid():
            parent_item = self.root_data
        else:
            parent_item = parent.internalPointer()
        children = parent_item.children
        if row < 0 or row > len(children):
            return QModelIndex()
        return self.createIndex(row, column, children[row])

    def parent(self, index: QMIndex) -> QModelIndex:  # type: ignore
        # Mypy error is a Liskov Substitution Principle error in Qt6?
        if not index.isValid():
            return QModelIndex()
        item = index.internalPointer()
        if item.parent is None:
            return QModelIndex()
        return self.createIndex(item.parent.row, 0, item.parent)

    def rowCount(self, parent: QMIndex = QModelIndex()) -> int:
        if parent.column() > 0:
            return 0
        if not parent.isValid():
            base = self.root_data
        else:
            base = parent.internalPointer()
        return len(base.children)

    def columnCount(self, parent: QMIndex = QModelIndex()) -> int:
        return 6 if DEBUG else 5

    def data(self, index: QMIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if not index.isValid():
            return None
        data = index.internalPointer()
        match index.column():
            case FirmwareStructureModel.OFFSET:
                return data.value.offset_string()
            case FirmwareStructureModel.LENGTH:
                return str(len(data.value))
            case FirmwareStructureModel.JSON_NAME:
                return data.field_name
            case FirmwareStructureModel.CLASS_NAME:
                return data.value.class_name()
            case FirmwareStructureModel.INSTANCE_NAME:
                return data.value.instance_name()
            case FirmwareStructureModel.IDENT:
                return hex(id(data))
            case _:
                return None

    def headerData(self, section: int, orientation: Qt.Orientation,
                   role: int = Qt.ItemDataRole.DisplayRole) -> Optional[str]:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation != Qt.Orientation.Horizontal:
            return None
        match section:
            case FirmwareStructureModel.OFFSET:
                return "Offset"
            case FirmwareStructureModel.LENGTH:
                return "Length"
            case FirmwareStructureModel.JSON_NAME:
                return "JSON Name"
            case FirmwareStructureModel.CLASS_NAME:
                return "Class Name"
            case FirmwareStructureModel.INSTANCE_NAME:
                return "Instance Name"
            case FirmwareStructureModel.IDENT:
                return "Identifier"
            case _:
                return None

# ----------------------------------------------------------------------------------------
format_field_names = {}
for name in dir(construct):
    item = getattr(construct, name)
    if isinstance(item, construct.FormatField):
        format_field_names[item.fmtstr] = name

def pretty_type_name(struct: FirmwareStructure, field: str) -> str:
    definition = struct.definition
    item = definition.by_name.get(field)
    if item is None:
        return str(getattr(struct, field).__class__.__name__)
    match item:
        case construct.FormatField():
            return format_field_names.get(item.fmtstr, item.__class__.__name__)
        case UUIDAdapter():
            return "GUID"
        case _:
            return item.__class__.__name__

# ----------------------------------------------------------------------------------------
class FirmwareStructureFieldModel(QAbstractItemModel):

    FIELD = 0
    TYPE = 1
    VALUE = 2

    def __init__(self, item: TreeModelData):
        super().__init__()
        assert item.value is not None
        self.struct = item.value
        self.terms = item.table

    def index(self, row: int, column: int, parent: QMIndex = QModelIndex()) -> QModelIndex:
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        if row < 0 or row > len(self.terms):
            return QModelIndex()
        return self.createIndex(row, column, None)

    def parent(self, index: QMIndex) -> QModelIndex:  # type: ignore
        # Mypy error is a Liskov Substitution Principle error in Qt6?
        return QModelIndex()

    def rowCount(self, parent: QMIndex = QModelIndex()) -> int:
        return len(self.terms)

    def columnCount(self, parent: QMIndex = QModelIndex()) -> int:
        return 3

    def rawdata(self, index: QMIndex) -> Any:
        if not index.isValid():
            return None
        term = self.terms[index.row()]
        match index.column():
            case FirmwareStructureFieldModel.FIELD:
                return str(term[0])
            case FirmwareStructureFieldModel.VALUE:
                return self.struct.term_value_string(term)
            case FirmwareStructureFieldModel.TYPE:
                return pretty_type_name(self.struct, term[0])

    def data(self, index: QMIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        value = self.rawdata(index)
        if value is None:
            return None
        if COLOR:
            return ansi_to_html(value)
        else:
            return ansi_to_plaintext(value)

    def headerData(self, section: int, orientation: Qt.Orientation,
                   role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if role != Qt.ItemDataRole.DisplayRole or orientation != Qt.Orientation.Horizontal:
            return super().headerData(section, orientation, role)
        match section:
            case FirmwareStructureFieldModel.FIELD:
                return "Field"
            case FirmwareStructureFieldModel.VALUE:
                return "Value"
            case FirmwareStructureFieldModel.TYPE:
                return "Type"
            case _:
                return None

# ----------------------------------------------------------------------------------------
def debug_tree_index(index: QMIndex) -> str:
    if not index.isValid():
        return "<invalid index>"
    ofs = index.sibling(index.row(), FirmwareStructureModel.OFFSET).data()
    name = index.sibling(index.row(), FirmwareStructureModel.JSON_NAME).data() or '<unnamed>'
    cls = index.sibling(index.row(), FirmwareStructureModel.CLASS_NAME).data()
    item = index.internalPointer()
    _, offset, length = item.value.memory_location()
    extra = f" ({offset:#x}, {offset + length:#x})[{length:#x}]"
    return f"[{ofs} {name} ({cls}){extra}]"

# ----------------------------------------------------------------------------------------
class Interval:
    __slots__ = ['model', 'row', 'column', 'ptr', 'children']

    def __init__(self, index: QMIndex):
        self.model = index.model()
        self.row = index.row()
        self.column = index.column()
        self.ptr: TreeModelData = index.internalPointer()
        self.children: list['Interval'] = []

    def index(self) -> QPersistentModelIndex:
        return QPersistentModelIndex(self.model.createIndex(self.row, self.column, self.ptr))

    @functools.cache
    def location(self) -> tuple[bytes, int, int]:
        assert self.ptr.value is not None
        return self.ptr.value.memory_location()

    def data(self, column: int) -> Any:
        return self.model.createIndex(self.row, column, self.ptr).data()

    def debug_name(self) -> str:
        return debug_tree_index(self.index())

    def memory(self) -> bytes:
        return self.location()[0]

    def offset(self) -> int:
        return self.location()[1]

    def length(self) -> int:
        return self.location()[2]

    def end(self) -> int:
        _, offset, length = self.location()
        return offset + length

    def insert(self, interval: 'Interval') -> None:
        if len(self.children) == 0:
            self.children.append(interval)
            return
        loc = bisect.bisect(self.children, interval._key(), key=self._keyfun)
        if loc != 0:
            last = self.children[loc - 1]
            if last.end() >= interval.end():
                last.insert(interval)
                return
        self.children.insert(loc, interval)

    def locate(self, byte: int) -> Optional[QPersistentModelIndex]:
        _, offset, length = self.location()
        if byte < offset or byte >= offset + length:
            return None
        loc = bisect.bisect(self.children, (byte, -1), key=self._keyfun)
        if loc != 0:
            last = self.children[loc - 1]
            if last.end() > byte:
                sublocate = last.locate(byte)
                if sublocate is not None:
                    return sublocate
        return self.index()

    def contains(self, other: 'Interval') -> bool:
        a = self.location()
        b = other.location()
        return a[0] is b[0] and a[1] <= b[1] and a[1] + a[2] >= b[1] + b[2]

    def _key(self) -> tuple[int, int]:
        _, offset, length = self.location()
        if not isinstance(length, int):
            log.error(f"Invalid offset in {type(self.ptr.value)}")
        return (offset, -length)

    def __hash__(self) -> int:
        return id(self)

    _keyfun = operator.methodcaller("_key")

# ----------------------------------------------------------------------------------------
class IntervalMap:
    def __init__(self, model: FirmwareStructureModel):
        self.model = model
        self.map: dict[int, list[Interval]] = {}
        root = model.index(0, 0)
        assert root.isValid()
        self.build(root)

    def build(self, index: QMIndex, parent: Optional[Interval] = None) -> None:
        interval = Interval(index)
        if parent is not None and parent.contains(interval):
            parent.insert(interval)
        else:
            self.insert(interval)
        for i in range(index.model().rowCount(index)):
            idx = index.model().index(i, 0, index)
            if idx.isValid():
                self.build(idx, interval)

    def insert(self, interval: Interval) -> None:
        ident = id(interval.memory())
        intervals = self.map.get(ident)
        if intervals is None:
            self.map[ident] = [interval]
            return
        loc = bisect.bisect(intervals, interval._key(), key=Interval._keyfun)
        if loc != 0:
            last = intervals[loc - 1]
            if last.end() >= interval.end():
                last.insert(interval)
                return
            log.warning(f"{interval.debug_name()} is not contained in {last.debug_name()}")
            return

        log.warning(f"{interval.debug_name()} is not contained by its parent struct's range.")
        intervals.insert(loc, interval)

    def locate(self, memory: bytes, byte: int) -> Optional[QPersistentModelIndex]:
        intervals = self.map.get(id(memory))
        if intervals is None:
            return None
        loc = bisect.bisect(intervals, (byte, -1), key=Interval._keyfun)
        if loc == 0:
            return None
        last = intervals[loc - 1]
        index = last.locate(byte)
        if index is None:
            return None
        return index

# ----------------------------------------------------------------------------------------
class InternalState:
    def __init__(self) -> None:
        self.count = 0

    def __enter__(self) -> bool:
        rv = bool(self)
        self.count += 1
        return rv

    def __exit__(self, exc_type: type[BaseException], exc_value: BaseException,
                 traceback: TracebackType) -> None:
        self.count -= 1

    def __bool__(self) -> bool:
        return self.count > 0


# ----------------------------------------------------------------------------------------
maybe_skip_fields = {"failure", "unexpected", "skipped"}

# ----------------------------------------------------------------------------------------
# FIXME!  This class was a bit of a mess.  Please review prior commit.
class ListValidator(QValidator):

    def __init__(self, validlist: Iterable[str]):
        super().__init__()
        self.validlist = set(validlist)

    def validate(self, value: str, pos: int) -> bool:
        return value in self.validlist

# ----------------------------------------------------------------------------------------
class Finder:

    def __init__(self) -> None:
        self.value: Optional[str] = None
        self.widget: Optional[QWidget] = None

    def create_widget(self) -> QComboBox:
        raise NotImplementedError

    def get_widget_value(self) -> Optional[str]:
        raise NotImplementedError

    def set_widget_value(self, value: str) -> None:
        raise NotImplementedError

    def save_widget_value(self) -> None:
        self.value = self.get_widget_value()

    def matcher(self, value: str, item: TreeModelData) -> bool:
        raise NotImplementedError

# ----------------------------------------------------------------------------------------
class ListFinder(Finder):

    def __init__(self, values: list[str]):
        self.values = values
        super().__init__()

    def create_widget(self) -> QComboBox:
        widget = QComboBox()
        completer = QCompleter(self.values)
        completer.setFilterMode(Qt.MatchFlag.MatchContains)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        widget.setEditable(True)
        widget.addItems(self.values)
        widget.setValidator(ListValidator(self.values))
        widget.setCompleter(completer)
        widget.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        widget.setMaximumWidth(400)
        self.widget = widget
        if self.value is not None:
            self.set_widget_value(self.value)
        return widget

    def get_widget_value(self) -> Optional[str]:
        assert self.widget is not None
        assert isinstance(self.widget, QComboBox)
        return str(self.widget.currentText())

    def set_widget_value(self, value: str) -> None:
        assert self.widget is not None
        assert isinstance(self.widget, QComboBox)
        self.widget.setEditText(value)

# ----------------------------------------------------------------------------------------
class ClassFinder(ListFinder):

    def matcher(self, value: str, item: TreeModelData) -> bool:
        assert item.value is not None
        return bool(value == item.value.class_name())

# ----------------------------------------------------------------------------------------
class InstanceFinder(ListFinder):

    def matcher(self, value: str, item: TreeModelData) -> bool:
        assert item.value is not None
        return bool(value == item.value.instance_name())

# ----------------------------------------------------------------------------------------
class FindDialog(QDialog):

    CLASS_NAME = 0
    INSTANCE_NAME = 1

    def __init__(self, gui: 'Gui') -> None:
        super().__init__()
        self.gui = gui

        vlayout = QVBoxLayout(self)
        self.form = QFormLayout()

        self.findmode = QComboBox(self)
        self.findmode.addItem("Class Name", self.CLASS_NAME)
        self.findmode.addItem("Instance Name", self.INSTANCE_NAME)
        self.findmode.currentIndexChanged.connect(self.mode_changed)

        self.finders = {
            self.CLASS_NAME: ClassFinder(self.gui.classnames),
            self.INSTANCE_NAME: InstanceFinder(self.gui.instancenames)
        }

        self.form.addRow("&Mode:", self.findmode)
        self.currentmode = None
        self.currentwidget: Optional[Finder] = None
        self.update_for_mode()

        vlayout.addLayout(self.form)

        buttons = QDialogButtonBox(Qt.Orientation.Horizontal)
        findForward = QPushButton("Find &Forward")
        findForward.clicked.connect(self.find_forward)
        findForward.setDefault(True)
        findBackward = QPushButton("Find &Backward")
        findBackward.clicked.connect(self.find_backward)
        buttons.addButton(findForward, QDialogButtonBox.ButtonRole.ApplyRole)
        buttons.addButton(findBackward, QDialogButtonBox.ButtonRole.ApplyRole)
        buttons.addButton(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)

        vlayout.addWidget(buttons)

    def mode_changed(self, index: QModelIndex) -> None:
        self.update_for_mode()

    def update_for_mode(self) -> None:
        mode = self.findmode.currentData()
        if mode == self.currentmode:
            return
        if self.currentwidget is not None:
            self.currentwidget.save_widget_value()
            self.form.removeRow(1)
        self.currentmode = mode
        newwidget = self.finders[mode]
        widget = newwidget.create_widget()
        self.form.addRow("&Value:", widget)
        self.currentwidget = newwidget

    def _find(self, forward: bool) -> None:
        current = self.gui.current_tree_selection().internalPointer()
        assert self.currentwidget is not None
        match_value = self.currentwidget.get_widget_value()
        if match_value is None:
            return
        if forward:
            generator = current.tree_iter(full=True, incl=False)
        else:
            generator = current.rev_tree_iter(full=True, incl=False)
        for item in generator:
            if self.currentwidget.matcher(match_value, item):
                self.select(item)
                return

    def select(self, item: TreeModelData) -> None:
        model = self.gui.treeview.model()
        index = item.index(model)
        selmodel = self.gui.treeview.selectionModel()
        selmodel.select(index, selectionFlags)
        selmodel.setCurrentIndex(index, selectionFlags)
        self.gui.treeview.scrollTo(index)

    def find_forward(self) -> None:
        self._find(True)

    def find_backward(self) -> None:
        self._find(False)

# ----------------------------------------------------------------------------------------
class StructTree(QTreeView):
    def __init__(self, gui: 'Gui') -> None:
        super().__init__()
        self.gui = gui
        model = FirmwareStructureModel(gui.model_data)
        self.setModel(model)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.expanded.connect(self.expanded_or_collapsed)
        self.collapsed.connect(self.expanded_or_collapsed)
        self.setAlternatingRowColors(True)
        self.expanded_or_collapsed()
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.treeContextMenu)

    def root_index(self) -> QModelIndex:
        return self.model().index(0, 0)

    def expanded_or_collapsed(self, index: QModelIndex = QModelIndex()) -> None:
        self.resizeColumnToContents(0)

    def export(self, index: QModelIndex,
               fn: Callable[[FirmwareStructure], dict[str, Any]]) -> None:
        (filename, _) = QFileDialog.getSaveFileName(
            self, f"Save {name}", filter="JSON Files (*.json)")
        if filename is not None and len(filename) > 0:
            item = index.internalPointer()
            data = fn(item)
            #data = getattr(item.value, fn)(*args, **kwds)
            try:
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
            except OSError as e:
                QMessageBox.critical(self, "Export Failed", str(e))
            except Exception:
                QMessageBox.critical(self, "Export Exception", traceback.format_exc())

    def export_sbom(self, index: QModelIndex) -> None:
        self.export(index, lambda obj: FirmwareStructure.sbom(obj))

    def export_json(self, index: QModelIndex) -> None:
        self.export(index, lambda obj: FirmwareStructure.to_dict(obj, True))

    def export_binary(self, index: QModelIndex) -> None:
        (filename, _) = QFileDialog.getSaveFileName(
            self, "Save as Binary", filter="Binary Files (*.bin)")
        if filename is not None and len(filename) > 0:
            mem = index.internalPointer().value.memory_view()
            try:
                with open(filename, 'wb') as f:
                    f.write(mem)
            except OSError as e:
                QMessageBox.critical(self, "Export Failed", str(e))
            except Exception:
                QMessageBox.critical(self, "Export Exception", traceback.format_exc())

    def treeContextMenu(self, point: QPoint) -> None:
        index = self.indexAt(point)
        if not index.isValid():
            return
        menu = QMenu()
        json = menu.addAction("Export as &JSON...")
        json.triggered.connect(lambda: self.export_json(index))
        binary = menu.addAction("Export as &Binary...")
        binary.triggered.connect(lambda: self.export_binary(index))
        menu.exec_(self.viewport().mapToGlobal(point))

# ----------------------------------------------------------------------------------------
class MainWindow(QMainWindow):

    def __init__(self, gui: 'Gui') -> None:
        self.gui = gui
        super().__init__()

    def closeEvent(self, event: QCloseEvent) -> None:
        self.gui.closeAllWindows()
        event.accept()

# ----------------------------------------------------------------------------------------
class Gui(QApplication):

    def __init__(self, struct: FirmwareStructure, args: argparse.Namespace) -> None:
        super().__init__([])
        self.struct = struct
        self.args = args
        if args.debug_gui:
            enable_debug()
        self.memory = None
        self.treeselection: Optional[QHexMetadata] = None
        self.tableselection: Optional[QHexMetadata] = None
        self.model_data = self.generate_model_data()
        self.collect_listnames()
        self.intervals: Optional[IntervalMap] = None
        self.processing = InternalState()
        self.findDialog: Optional[FindDialog] = None

    def generate_model_data(self) -> TreeModelData:
        def partition_terms(data: TreeModelData) -> TreeModelData:
            struct = data.value
            assert struct is not None
            terms: list[Any] = struct.filter_terms()
            treevalues: list[TreeModelData] = []
            tablevalues = []
            for term in terms:
                match term:
                    case [] | [_, None]:
                        continue
                field = term[0]
                if not hasattr(struct, field):
                    log.warning("reporting for %s uses non-existent field %s" %
                                (struct.__class__.__name__, field))
                    continue
                value = getattr(struct, field)
                match value:
                    case MysteryBytes() if value.length == 0:
                        pass
                    case FirmwareStructure():
                        treevalues.append(TreeModelData(field, len(treevalues), value, data,
                                                        [], []))
                    case [FirmwareStructure(), *_]:
                        for item in value:
                            treevalues.append(TreeModelData(field, len(treevalues), item, data,
                                                            [], []))
                    case None if field in maybe_skip_fields:
                        pass
                    case MysteryBytes() if (len(value) == 0 and field in maybe_skip_fields):
                        pass
                    case _:
                        tablevalues.append(term)
            data.children = treevalues
            data.table = tablevalues
            for child in data.children:
                partition_terms(child)
            return data
        model = partition_terms(TreeModelData('', 0, self.struct, None, [], []))
        # Strip off any top-level AutoObject
        if len(model.children) == 1 and isinstance(model.value, AutoObject):
            model = model.children[0]
            model.parent = None
        return model

    def collect_listnames(self) -> None:
        classnames = set()
        instancenames = set()
        for item in self.model_data:
            assert item.value is not None
            classnames.add(item.value.class_name())
            val = item.value.instance_name()
            if val is not None:
                instancenames.add(val)
        self.classnames = sorted(classnames)
        self.instancenames = sorted(instancenames)

    def run(self) -> None:
        self.treeview = StructTree(self)
        treemodel = self.treeview.model()
        assert isinstance(treemodel, FirmwareStructureModel)
        self.intervals = IntervalMap(treemodel)
        treeselect = self.treeview.selectionModel()
        treeselect.currentChanged.connect(self.treeSelectionChanged)

        self.tableview = QTableView()
        table_header = self.tableview.horizontalHeader()
        table_header.setStretchLastSection(True)
        self.tableview.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tableview.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tableview.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tableview.customContextMenuRequested.connect(self.tableContextMenu)

        self.hexview = QHexView(doc=None)
        self.hexview.positionChanged.connect(self.hexviewChanged)

        hsplitter = QSplitter()
        hsplitter.addWidget(self.treeview)
        vsplitter = QSplitter(Qt.Orientation.Vertical)
        vsplitter.addWidget(self.tableview)
        vsplitter.addWidget(self.hexview)
        hsplitter.addWidget(vsplitter)

        window = MainWindow(self)
        window.setCentralWidget(hsplitter)

        file_menu = window.menuBar().addMenu("&File")
        export_json_action = file_menu.addAction("Export as &JSON...")
        export_json_action.triggered.connect(
            lambda: self.treeview.export_json(self.treeview.root_index()))
        export_sbom_action = file_menu.addAction("Export &SBOM...")
        export_sbom_action.triggered.connect(
            lambda: self.treeview.export_sbom(self.treeview.root_index()))
        quit_action = QAction("&Quit")
        quit_action.setShortcuts(QKeySequence.StandardKey.Quit)
        quit_action.setStatusTip("Exit the application")
        quit_action.triggered.connect(window.close)
        file_menu.addAction(quit_action)

        edit_menu = window.menuBar().addMenu("&Edit")
        find_action = QAction("&Find...")
        find_action.setShortcuts(QKeySequence.StandardKey.Find)
        find_action.setStatusTip("Locate structures and fields")
        find_action.triggered.connect(self.find_dialog)
        edit_menu.addAction(find_action)

        about_action = QAction("&About")
        about_action.setToolTip('Information about CERT UEFI Parser.')
        about_action.setIcon(QIcon.fromTheme('help-about'))
        about_action.triggered.connect(self.about)

        about_qt_action = QAction("About &Qt")
        about_qt_action.triggered.connect(self.aboutQt)

        help_menu = window.menuBar().addMenu("&Help")
        help_menu.addAction(about_action)
        help_menu.addAction(about_qt_action)

        icon_image = QImage.fromData(binascii.a2b_base64(icon_data))
        icon_pixmap = QPixmap.fromImage(icon_image)
        app_icon = QIcon(icon_pixmap)
        self.setWindowIcon(app_icon)

        self.set_geometry(window, hsplitter)
        window.setWindowTitle(f"CERT UEFI Parser: {self.args.file}")
        self.window = window
        window.show()
        self.exec_()

    def about(self) -> None:
        "Display the 'about this application' help message."
        QMessageBox.about(
            self.window, "About CERT UEFI Parser",
            "<p>CERT UEFI Parser was developed to be an all-singing, all-dancing "
            "parser of files related to UEFI and firmware.  It's intended to be "
            "an easily extensible framework designed to facilitate exploration of "
            "undocumented data structures.</p>"
            "<p>CERT UEFI Parser was developed by the CERT Coordination Center "
            "at the Software Engineering Institute, which is a FFRDC managed "
            "by Carnegie Mellon University.</p>"
            "<p>Copyright 2025 Carnegie Mellon University."
            "<br>See LICENSE file for terms."
            "<br>https://github.com/cmu-sei/cert-uefi-parser</p>")

    def close(self) -> None:
        if self.findDialog:
            self.findDialog.close()

    def clear_tree_selection(self) -> None:
        if self.treeselection is not None:
            self.hexview.removeMetadata(self.treeselection)
            self.treeselection = None
        self.clear_table_selection()

    def clear_table_selection(self) -> None:
        if self.tableselection is not None:
            self.hexview.removeMetadata(self.tableselection)
            self.tableselection = None

    def hexviewChanged(self) -> None:
        with self.processing as processing:
            if processing:
                return
            if self.memory is None:
                return
            cursor = self.hexview.qcursor
            if cursor is None:
                return
            offset = cursor.offset
            index = self.intervals.locate(self.memory, offset)
            if index is None:
                self.treeview.selectionModel().clear()
                self.tableview.selectionModel().clear()
                return None
            treeselection = self.treeview.selectionModel()
            if not treeselection.isSelected(index):
                treeselection.select(index, selectionFlags)
                treeselection.setCurrentIndex(index, selectionFlags)
                self.treeview.scrollTo(index)
            tablemodel = self.tableview.model()
            if tablemodel is None:
                return None
            found = False
            tableselection = self.tableview.selectionModel()
            for row in range(tablemodel.rowCount()):
                term = tablemodel.terms[row][0]
                struct = tablemodel.struct
                offsets = struct._field_offsets.get(term, None)
                if offsets is None:
                    continue
                start = offsets[0]
                end = start + (offsets[1] - offsets[0])
                if start <= offset < end:
                    found = True
                    tindex = tablemodel.index(row, 0)
                    if not tableselection.isSelected(tindex):
                        tableselection.select(tindex, selectionFlags)
                        tableselection.setCurrentIndex(tindex, selectionFlags)
                        self.tableview.scrollTo(tindex)
            if not found:
                tableselection.clear()
                self.clear_table_selection()

    def treeSelectionChanged(self, current: QMIndex, previous: QMIndex) -> None:
        with self.processing as processing:
            self.clear_tree_selection()
            if not current.isValid():
                return
            item = current.internalPointer()
            tablemodel = FirmwareStructureFieldModel(item)
            self.tableview.setModel(tablemodel)
            tableselect = self.tableview.selectionModel()
            tableselect.currentChanged.connect(self.tableSelectionChanged)
            memory, offset, length = item.value.memory_location()
            if memory is not self.memory:
                self.memory = memory
                self.hexview.setDocument(QHexDocument(memory, self.hexview))
            self.treeselection = QHexMetadata(offset, offset + length,
                                              background=QColor("cyan"))
            self.hexview.setMetadata(self.treeselection)
            if not processing:
                self.hexview.move_to_region(offset, offset + length)

    def tableSelectionChanged(self, current: QMIndex, previous: QMIndex) -> None:
        with self.processing as processing:
            self.clear_table_selection()
            if not current.isValid():
                return
            model = current.model()
            assert isinstance(model, FirmwareStructureFieldModel)
            term = model.terms[current.row()][0]
            struct = model.struct
            offsets = struct._field_offsets.get(term, None)
            if offsets is None:
                return
            start = offsets[0]
            end = start + (offsets[1] - offsets[0])
            self.tableselection = QHexMetadata(start, end,
                                               background=QColor("red"))
            self.hexview.setMetadata(self.tableselection)
            if not processing:
                self.hexview.move_to_region(start, end)

    def copyTableValue(self, index: QMIndex) -> None:
        model = index.model()
        assert isinstance(model, FirmwareStructureFieldModel)
        value = ansi_to_plaintext(model.rawdata(index))
        clipboard = self.clipboard()
        if value is None:
            clipboard.clear()
        else:
            clipboard.setText(value, QClipboard.Mode.Clipboard)
            clipboard.setText(value, QClipboard.Mode.Selection)

    def tableContextMenu(self, point: QPoint) -> None:
        index = self.tableview.indexAt(point)
        if not index.isValid():
            return
        menu = QMenu()
        copy = menu.addAction("&Copy")
        copy.triggered.connect(lambda: self.copyTableValue(index))
        menu.exec_(self.tableview.viewport().mapToGlobal(point))

    def current_tree_selection(self) -> QModelIndex:
        index = self.treeview.currentIndex()
        if not index.isValid():
            index = self.treeview.model().index(0, 0)
        return index

    def find_dialog(self) -> None:
        if not self.findDialog:
            self.findDialog = FindDialog(self)
        assert self.findDialog is not None
        self.findDialog.show()
        self.findDialog.raise_()
        self.findDialog.activateWindow()

    def set_geometry(self, window: MainWindow, hsplitter: QSplitter) -> None:
        "Choose an appropriate initial position for the window."

        # Begin by gathering information about the desktop.
        rect = QApplication.primaryScreen().geometry()

        # Because there's usually a ton of information to show, consume most of the
        # primary monitor when opened, but don't literally switch to full screen.
        # The default window will be 80% of the width and height of that monitor.
        w = int(rect.width() * 0.8)
        h = int(rect.height() * 0.8)
        x = rect.x() + int(w * 0.1)
        y = rect.y() + int(h * 0.1)
        window.setGeometry(x, y, w, h)
        # Get the maximum width of the hex view.  Widths larger than this are just kind of
        # wasteful, since the hex view won't utilize more than this width.  The default
        # distribution of the horizontal splitter is half and half.  If the hex view is
        # being allocated more than it needs, return the balance to the tree view widget.
        # The other scenario is that the hex view need just a little more than half of the
        # window width in order to display the full width of teh hex view.  In that case,
        # steal a little space from the tree view, but not more than 10%.  If neither of
        # those scenarios apply, go ahead and split the window in half an let the user
        # figure out what they want to do.
        hex_width = self.hexview.maxViewWidth()
        if hex_width < (w * 0.60):
            hsplitter.setSizes([w - hex_width, hex_width])

# ----------------------------------------------------------------------------------------
def run_gui(struct: FirmwareStructure, args: argparse.Namespace) -> None:
    gui = Gui(struct, args)
    gui.run()

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
