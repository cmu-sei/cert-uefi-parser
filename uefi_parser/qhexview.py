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
A hexdecimal viewer widget.

Derived from https://github.com/Dax89/QHexView by Antonio Davide (Dax89)

The MIT License (MIT)

Copyright (c) 2025 Carnegie Mellon
Copyright (c) 2014 Dax89

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import sys
import math
from enum import Enum, Flag
from typing import Optional, Union

from PySide6 import QtGui, QtWidgets, QtCore
from PySide6.QtCore import Qt, QObject, QPoint, QPointF, QEvent, QLineF
from PySide6.QtWidgets import QWidget, QToolTip, QApplication
from PySide6.QtGui import (
    QColor, QPalette, QPainter, QTextDocument, QTextCharFormat, QTextBlockFormat,
    QTextCursor, QMouseEvent, QKeyEvent, QKeySequence, QResizeEvent, QFocusEvent)

# Shorter aliases for the Enums ColorGroup and ColorRole to avoid long lines.
ColorGroup = QPalette.ColorGroup
ColorRole = QPalette.ColorRole

class QHexFlags(Flag):
    NoFlags = 0
    HSeparator = 1 << 1
    VSeparator = 1 << 2
    StyledHeader = 1 << 3
    StyledAddress = 1 << 4
    NoHeader = 1 << 5
    HighlightAddress = 1 << 6
    HighlightColumn = 1 << 7
    Separators = HSeparator | VSeparator
    Styled = StyledHeader | StyledAddress

class QHexArea(Enum):
    Header = 0
    Address = 1
    Hex = 2
    Ascii = 3
    Extra = 4

class QHexMetadata(object):

    def __init__(self, begin: int, end: int, foreground: Optional[QColor] = None,
                 background: Optional[QColor] = None, comment: Optional[str] = None):
        self.begin = begin
        self.end = end
        self.foreground = foreground
        self.background = background
        self.comment = comment

class QHexPosition(object):

    def __init__(self, line: int, column: int) -> None:
        self.line = line
        self.column = column

    @staticmethod
    def invalid() -> 'QHexPosition':
        return QHexPosition(-1, -1)

    def isValid(self) -> bool:
        return self.line >= 0 and self.column >= 0

    def __eq__(self, other: object) -> bool:
        if isinstance(other, QHexPosition):
            return self.line == other.line and self.column == other.column
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        if isinstance(other, QHexPosition):
            return self.line != other.line or self.column != other.column
        return NotImplemented

    def __str__(self) -> str:
        return "QHexPosition(line=%s, column=%s)" % (self.line, self.column)

class QHexOptions(object):
    "Options controlling the appearance of QHexView"

    # Appearance
    unprintable_char = '.'
    invalid_char = ' '
    address_label: Optional[str] = None
    hex_label: Optional[str] = None
    ascii_label: Optional[str] = None
    base_address = 0
    flags = QHexFlags.NoFlags
    line_length = 0x10
    address_width = 0
    group_length = 1
    scroll_steps = 1

    # Colors & Styles
    line_alternate_background: Optional[QColor] = None
    line_background: Optional[QColor] = None
    header_color: Optional[QColor] = None
    comment_color: Optional[QColor] = None
    separator_color: Optional[QColor] = None

    def hasFlag(self, flag: QHexFlags) -> bool:
        return bool(self.flags & flag)

def offsetToPosition(options: QHexOptions, offset: int) -> QHexPosition:
    return QHexPosition(int(offset / options.line_length), offset % options.line_length)

def positionToOffset(options: QHexOptions, pos: QHexPosition) -> int:
    return options.line_length * pos.line + pos.column

class QHexDocument(QObject):

    # Create Qt Signals.
    dataChanged = QtCore.Signal(object)
    changed = QtCore.Signal()
    reset = QtCore.Signal()
    #modifiedChanged = QtCore.Signal(modified: bool)

    def __init__(self, buffer: Union[bytes, memoryview], parent: QObject):
        super().__init__(parent)
        if not isinstance(buffer, memoryview):
            buffer = memoryview(buffer)
        self.buffer = buffer.cast('B')

        #self.buffer.setParent(self)
        # connect(self.undostack, &QUndoStack::canUndoChanged, this, &QHexDocument::canUndoChanged)
        # connect(self.undostack, &QUndoStack::canRedoChanged, this, &QHexDocument::canRedoChanged)
        # connect(self.undostack, &QUndoStack::cleanChanged, this,
        #    [&](bool clean) { Q_EMIT modifiedChanged(!clean) })

    def __len__(self) -> int:
        return len(self.buffer)

    # BUG? Remove as non-Pythonic?
    def isEmpty(self) -> bool:
        return len(self.buffer) == 0

class QHexCursor(QObject):

    positionChanged = QtCore.Signal()

    def __init__(self, options: QHexOptions, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.options = options
        self.position = QHexPosition(0, 0)
        self.selection = QHexPosition(0, 0)

    def move(self, pos: QHexPosition) -> None:
        if pos.line >= 0:
            self.selection.line = pos.line
        if pos.column >= 0:
            self.selection.column = pos.column
        self.select(pos)

    def select(self, pos: QHexPosition) -> None:
        if pos.line >= 0:
            self.position.line = pos.line
        if pos.column >= 0:
            self.position.column = pos.column
        self.positionChanged.emit()

    @property
    def column(self) -> int:
        return self.position.column

    @property
    def line(self) -> int:
        return self.position.line

    @property
    def offset(self) -> int:
        return positionToOffset(self.options, self.position)

    def selectionStartOffset(self) -> int:
        return self.positionToOffset(self.selectionStart())

    def selectionEndOffset(self) -> int:
        return self.positionToOffset(self.selectionEnd())

    def selectionLength(self) -> int:
        start = self.selectionStartOffset()
        end = self.selectionEndOffset()
        if start == end:
            return 0
        return end - start + 1

    def selectionStart(self) -> QHexPosition:
        if self.position.line < self.selection.line:
            return self.position

        if self.position.line == self.selection.line:
            if self.position.column < self.selection.column:
                return self.position

        return self.selection

    def selectionEnd(self) -> QHexPosition:
        if self.position.line > self.selection.line:
            return self.position

        if self.position.line == self.selection.line:
            if self.position.column > self.selection.column:
                return self.position

        return self.selection

    def hasSelection(self) -> bool:
        return self.position != self.selection

    def isSelected(self, line: int, column: int) -> bool:
        if not self.hasSelection():
            return False

        selstart = self.selectionStart()
        selend = self.selectionEnd()
        if line > selstart.line and line < selend.line:
            return True
        if line == selstart.line and line == selend.line:
            return column >= selstart.column and column <= selend.column
        if line == selstart.line:
            return column >= selstart.column
        if line == selend.line:
            return column <= selend.column
        return False

    def move_offset(self, offset: int) -> None:
        self.move(self.offsetToPosition(offset))

    def select_offset(self, offset: int) -> None:
        self.select(self.offsetToPosition(offset))

    def positionToOffset(self, pos: QHexPosition) -> int:
        return positionToOffset(self.options, pos)

    def offsetToPosition(self, offset: int) -> QHexPosition:
        return offsetToPosition(self.options, offset)

class QHexView(QtWidgets.QAbstractScrollArea):
    """
    Hex view widget.

    :param data: The raw data (bytes or bytearray).
    :param filename: The file name containing the data.
    """

    positionChanged = QtCore.Signal()

    def __init__(self, doc: Optional[bytes], parent: Optional[QWidget] = None):
        # Old libqtio parameters, readonly=True, statusbar=1, columns=16)
        super().__init__(parent)

        self.current_area = QHexArea.Ascii
        self.columns: list[QtCore.QRect] = []
        self.options = QHexOptions()

        self.qcursor = QHexCursor(self.options, self)
        self.hex_document: Optional[QHexDocument] = None
        self.metadata: dict[int, list[QHexMetadata]] = {}

        self.fixed_font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
        if self.fixed_font.styleHint() != QtGui.QFont.StyleHint.TypeWriter:
            self.fixed_font.setFamily("Monospace")  # Force Monospaced font
            self.fixed_font.setStyleHint(QtGui.QFont.StyleHint.TypeWriter)
        self.font_metrics = QtGui.QFontMetricsF(self.fixed_font)
        if doc is None:
            doc = b''
        self.setDocument(QHexDocument(doc, self))

        self.setMouseTracking(True)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.viewport().setCursor(Qt.CursorShape.IBeamCursor)

        p = self.palette()
        p.setBrush(ColorRole.Window, p.base())

        #self.verticalScrollBar().valueChanged.connect(self.viewport().update())
        #self.verticalScrollBar().valueChanged.connect(self.scrolled)
        #self.connect(self.verticalScrollBar(), QtWidgets.QScrollBar.valueChanged,
        #             self, self.viewport().update)

        self.checkState()

        self.qcursor.positionChanged.connect(self.posChange)
        # connect(self.qcursor, &QHexCursor::positionChanged, self, [=]() {
        #     self.ensureVisible()
        #     self.positionChanged.emit()
        # })
        #
        # connect(self.qcursor, &QHexCursor::modeChanged, self, [=]() {
        #     self.viewport().update()
        #     self.modeChanged.emit()
        # })

    #def update_viewport(self):
    #    self.verticalScrollBar().update()
    #def scrolled(self):
    #    log.debug("HexView.verticalScrollBar() valueChanged signal!")
    #    log.debug("User scrolled to line %d" % self.last_scroll_line)

    def posChange(self) -> None:
        #log.debug("HexView positionChanged signal!")
        self.ensureVisible()
        self.positionChanged.emit()
        #log.debug("HexView positionChanged signal emission complete!")

    def ensureVisible(self) -> None:
        if not self.hex_document:
            return

        pos = self.qcursor.position
        vlines = self.visible_lines()

        scroll_line = self.verticalScrollBar().value()

        if pos.line >= (scroll_line + vlines):
            self.verticalScrollBar().setValue(pos.line - vlines + 1)
        elif pos.line < scroll_line:
            self.verticalScrollBar().setValue(pos.line)
        else:
            self.viewport().update()

    def move_to_region(self, start_offset: int, end_offset: int) -> None:
        """
        Scroll the viewport to display the region from start to end.

        If the region is already fully visible in the window, do not
        scroll the window.  If the region fits in the window, but is
        not currently fully visible, positionthe region in the center
        of the window.  If the region does not fit in the window, but
        the start of the region is currently visible, do not scroll
        the window.  If the region does not fit in the window, and the
        start is not currently visible, position the the start in the
        center of the window.
        """
        start_line = offsetToPosition(self.options, start_offset).line
        end_line = offsetToPosition(self.options, end_offset).line

        # Decide whether the region fits, and set a target line for
        # the scroll bar.
        required_lines = end_line - start_line
        visible_lines = self.visible_lines()
        #log.debug("Goto lines %d-%d of %d visible (%d required)" %
        #      (start_line, end_line, visible_lines, required_lines))
        if required_lines > visible_lines:
            if self.is_line_visible(start_line):
                self.qcursor.move_offset(start_offset)
                return
            target_line = start_line - int(visible_lines / 2)
        else:
            if self.is_line_visible(start_line) and self.is_line_visible(end_line):
                self.qcursor.move_offset(start_offset)
                return
            unused_lines = visible_lines - required_lines
            target_line = start_line - int(unused_lines / 2)

        # The region was not completely visible, so we need to scroll
        # to the target line to make it visible (or at least the start
        # of the region).

        # You can't position the scroll bar before the start of the document.
        if target_line < 0:
            target_line = 0

        #log.debug("Scrolling to target line: %s" % target_line)
        self.verticalScrollBar().setValue(target_line)

        # Finally, move the cursor to the start of the region.
        self.qcursor.move_offset(start_offset)

    def is_line_visible(self, line: int) -> bool:
        visible_lines = self.visible_lines()

        scroll_line = self.verticalScrollBar().value()
        #log.debug("Checking is %d is visible in %d-%d" % (
        #    line, scroll_line, scroll_line + visible_lines))
        if line > (scroll_line + visible_lines):
            return False
        elif line < scroll_line:
            return False
        return True

    def showEvent(self, event: QtGui.QShowEvent) -> None:
        super().showEvent(event)
        self.checkAndUpdate(True)

    def paintEvent(self, event: QtGui.QPaintEvent) -> None:
        if self.hex_document is None:
            return
        painter = QPainter(self.viewport())
        self.paint(painter)

    def resizeEvent(self, e: QResizeEvent) -> None:
        self.checkState()
        super().resizeEvent(e)

    def focusInEvent(self, e: QFocusEvent) -> None:
        super().focusInEvent(e)
        if self.hex_document:
            self.viewport().update()

    def focusOutEvent(self, e: QFocusEvent) -> None:
        super().focusOutEvent(e)
        if self.hex_document:
            self.viewport().update()

    def mousePressEvent(self, e: QMouseEvent) -> None:
        super().mousePressEvent(e)
        if not self.hex_document or e.button() != Qt.MouseButton.LeftButton:
            return

        pos = self.positionFromPoint(e.position())
        if not pos.isValid():
            return

        area = self.areaFromPoint(e.position())
        #log.debug("Area: %s" % area)

        match area:
            case QHexArea.Address:
                new_pos = QHexPosition(pos.line, 0)
                self.qcursor.move(new_pos)
            case QHexArea.Hex:
                self.current_area = area
                self.qcursor.move(pos)
            case QHexArea.Ascii:
                self.current_area = area
                self.qcursor.move(pos)
            case _:
                return

        self.viewport().update()

    def mouseMoveEvent(self, e: QMouseEvent) -> None:
        super().mouseMoveEvent(e)
        if self.hex_document is None:
            return

        e.accept()
        area = self.areaFromPoint(e.position())

        match area:
            case QHexArea.Header:
                self.viewport().setCursor(Qt.CursorShape.ArrowCursor)
                return
            case QHexArea.Address:
                self.viewport().setCursor(Qt.CursorShape.ArrowCursor)
            case _:
                self.viewport().setCursor(Qt.CursorShape.IBeamCursor)

        if e.buttons() == Qt.MouseButton.LeftButton:
            pos = self.positionFromPoint(e.position())
            if not pos.isValid():
                return
            if area == QHexArea.Ascii or area == QHexArea.Hex:
                self.current_area = area
                self.qcursor.select(pos)

    def keyPressEvent(self, e: QKeyEvent) -> None:
        handled = False

        if self.hex_document is not None:
            handled = self.keyPressMove(e)
            if not handled:
                handled = self.keyPressAction(e)
            #if not handled:
            #    handled = self.keyPressTextInput(e)

        if handled:
            e.accept()
        else:
            super().keyPressEvent(e)

    def keyPressAction(self, e: QKeyEvent) -> bool:
        if e.modifiers() != Qt.KeyboardModifier.NoModifier:
            if e.matches(QKeySequence.StandardKey.SelectAll):
                # FIXME: Select what exactly?  What is "all"?
                pass
            elif e.matches(QKeySequence.StandardKey.Copy):
                # FIXME: and this works, but only if you drag-select the bytes you want.
                # Otherwise, you get the single byte under the cursor.  This should
                # probably default to something more intelligent... But what exactly?
                self.copy(self.current_area != QHexArea.Ascii)
            else:
                return False
            return True

        return False

    def keyPressMove(self, e: QKeyEvent) -> bool:
        if e.matches(QKeySequence.StandardKey.MoveToNextChar):
            self.moveNext(select=False)
        elif e.matches(QKeySequence.StandardKey.SelectNextChar):
            self.moveNext(select=True)
        elif e.matches(QKeySequence.StandardKey.MoveToPreviousChar):
            self.movePrevious(select=False)
        elif e.matches(QKeySequence.StandardKey.SelectPreviousChar):
            self.movePrevious(select=True)
        elif e.matches(QKeySequence.StandardKey.MoveToNextLine):
            next_line = min(self.lastLine(), self.qcursor.line + 1)
            pos = QHexPosition(next_line, self.qcursor.column)
            self.qcursor.move(pos)
        elif e.matches(QKeySequence.StandardKey.SelectNextLine):
            next_line = min(self.lastLine(), self.qcursor.line + 1)
            pos = QHexPosition(next_line, self.qcursor.column)
            self.qcursor.select(pos)
        elif e.matches(QKeySequence.StandardKey.MoveToPreviousLine):
            pos = QHexPosition(max(0, self.qcursor.line - 1), self.qcursor.column)
            self.qcursor.move(pos)
        elif e.matches(QKeySequence.StandardKey.SelectPreviousLine):
            pos = QHexPosition(max(0, self.qcursor.line - 1), self.qcursor.column)
            self.qcursor.select(pos)
        elif e.matches(QKeySequence.StandardKey.MoveToNextPage):
            page_line = min(self.lastLine(), self.qcursor.line + self.visible_lines())
            pos = QHexPosition(page_line, self.qcursor.column)
            self.qcursor.move(pos)
        elif e.matches(QKeySequence.StandardKey.SelectNextPage):
            page_line = min(self.lastLine(), self.qcursor.line + self.visible_lines())
            pos = QHexPosition(page_line, self.qcursor.column)
            self.qcursor.select(pos)
        elif e.matches(QKeySequence.StandardKey.MoveToPreviousPage):
            pageline = max(0, self.qcursor.line - self.visible_lines())
            pos = QHexPosition(pageline, self.qcursor.column)
            self.qcursor.move(pos)
        elif e.matches(QKeySequence.StandardKey.SelectPreviousPage):
            pageline = max(0, self.qcursor.line - self.visible_lines())
            pos = QHexPosition(pageline, self.qcursor.column)
            self.qcursor.select(pos)
        elif e.matches(QKeySequence.StandardKey.MoveToStartOfDocument):
            self.qcursor.move(QHexPosition(0, 0))
        elif e.matches(QKeySequence.StandardKey.SelectStartOfDocument):
            self.qcursor.select(QHexPosition(0, 0))
        elif e.matches(QKeySequence.StandardKey.MoveToEndOfDocument):
            pos = QHexPosition(self.lastLine(), self.getLastColumn(self.lastLine()))
            self.qcursor.move(pos)
        elif e.matches(QKeySequence.StandardKey.SelectEndOfDocument):
            pos = QHexPosition(self.lastLine(), self.getLastColumn(self.lastLine()))
            self.qcursor.select(pos)
        elif e.matches(QKeySequence.StandardKey.MoveToStartOfLine):
            pos = QHexPosition(self.qcursor.line, 0)
            self.qcursor.move(pos)
        elif e.matches(QKeySequence.StandardKey.SelectStartOfLine):
            pos = QHexPosition(self.qcursor.line, 0)
            self.qcursor.select(pos)
        elif e.matches(QKeySequence.StandardKey.MoveToEndOfLine):
            pos = QHexPosition(self.qcursor.line, self.getLastColumn(self.qcursor.line))
            self.qcursor.move(pos)
        elif e.matches(QKeySequence.StandardKey.SelectEndOfLine):
            pos = QHexPosition(self.qcursor.line, self.getLastColumn(self.qcursor.line))
            self.qcursor.select(pos)
        else:
            return False

        return True

    def moveNext(self, select: bool = False) -> None:
        line = self.qcursor.line
        column = self.qcursor.column

        if column >= self.options.line_length - 1:
            line += 1
            column = 0
        else:
            column += 1

        pos = QHexPosition(min(line, self.lines()),
                           min(column, self.getLastColumn(line)))
        if select:
            self.qcursor.select(pos)
        else:
            self.qcursor.move(pos)

    def movePrevious(self, select: bool = False) -> None:
        line = self.qcursor.line
        column = self.qcursor.column

        if column <= 0:
            if not line:
                return
            line -= 1
            column = len(self.getLine(line)) - 1
        else:
            column -= 1

        pos = QHexPosition(min(line, self.lines()),
                           min(column, self.getLastColumn(line)))
        if select:
            self.qcursor.select(pos)
        else:
            self.qcursor.move(pos)

    def event(self, e: QEvent) -> bool:
        match e.type():
            case QEvent.Type.FontChange:
                self.font_metrics = QtGui.QFontMetricsF(self.font())
                self.checkAndUpdate(True)
                return True
            case QEvent.Type.ToolTip:
                #if (self.hex_document
                #    and (self.current_area == QHexArea.Hex
                #         or self.current_area == QHexArea.Ascii)):
                assert isinstance(e, QtGui.QHelpEvent)
                pos = self.positionFromPoint(QPointF(e.pos()))
                comments = self.get_comments(pos)
                #log.debug("Tooltip at %s: %s" % (pos, comments))
                if comments is not None:
                    QToolTip.showText(e.globalPos(), comments)
                return True

        return super().event(e)

    def areaFromPoint(self, ptf: QPointF) -> QHexArea:
        pt = self.absolutePoint(ptf)
        line = self.verticalScrollBar().value() + pt.y() / self.lineHeight()

        if not self.options.hasFlag(QHexFlags.NoHeader) and not int(line):
            return QHexArea.Header
        if pt.x() < self.hexColumnX():
            return QHexArea.Address
        if pt.x() < self.asciiColumnX():
            return QHexArea.Hex
        if pt.x() < self.endColumnX():
            return QHexArea.Ascii
        return QHexArea.Extra

    def absolutePoint(self, pt: QPointF) -> QPointF:
        return pt + QPoint(self.horizontalScrollBar().value(), 0)

    def positionFromPoint(self, pt: QPointF) -> QHexPosition:
        pos = QHexPosition.invalid()
        abspt = self.absolutePoint(pt)

        match self.areaFromPoint(pt):
            case QHexArea.Hex:
                pos.column = -1

                # BUG! Why can't this be simple like the Ascii area?
                for i in range(len(self.columns)):
                    if self.columns[i].left() > abspt.x():
                        break
                    pos.column = i
            case QHexArea.Ascii:
                x = abspt.x() - self.asciiColumnX()
                pos.column = max(int(x / self.cellWidth()) - 1, 0)
            case QHexArea.Address:
                pos.column = 0
            case QHexArea.Header:
                return QHexPosition.invalid()

        pos.line = int(min(self.verticalScrollBar().value()
                           + (abspt.y() / self.lineHeight()), self.lines()))

        if not self.options.hasFlag(QHexFlags.NoHeader):
            pos.line = max(0, pos.line - 1)

        docline = self.getLine(pos.line)
        pos.column = min(pos.column, len(docline) - 1)

        #log.debug("line: %d, col: %d" % (pos.line, pos.column))
        return pos

    def paint(self, painter: QPainter) -> None:
        doc = QTextDocument()
        doc.setDocumentMargin(0)
        doc.setUndoRedoEnabled(False)
        doc.setDefaultFont(self.fixed_font)

        cursor = QTextCursor(doc)
        self.drawHeader(cursor)
        self.drawDocument(cursor)

        painter.translate(-self.horizontalScrollBar().value(), 0)
        doc.drawContents(painter)
        self.drawSeparators(painter)

    def drawHeader(self, c: QTextCursor) -> None:
        # Don't draw the header if there's no data.
        if not self.hex_document or len(self.hex_document) == 0:
            return

        if self.options.hasFlag(QHexFlags.NoHeader):
            return

        def headerFormat() -> QTextCharFormat:
            cf = QTextCharFormat()
            if self.options.header_color is not None:
                cf.setForeground(self.options.header_color)
            return cf

        cf = headerFormat()
        # RESET_FORMAT(options, cf)
        # address_label = self.options.address_label
        # Really: QHexView.reduced(address_label, this->addressWidth()
        c.insertText(" " * (self.addressWidth() + 2))

        hex_label = self.options.hex_label
        if hex_label is None:
            c.insertText(" ")
            for i in range(0, self.options.line_length, self.options.group_length):
                h = "%02X" % i

                if (self.options.hasFlag(QHexFlags.HighlightColumn)
                        and self.qcursor.column == i):
                    cf.setBackground(self.palette().color(ColorRole.Highlight))
                    cf.setForeground(self.palette().color(ColorRole.HighlightedText))

                c.insertText(h, cf)
                c.insertText(" ", headerFormat())
        else:
            #cfc = int(self.hexColumnWidth() / self.cellWidth())
            #c.insertText(" " + QHexView.reduced(hexlabel, cfc - 1) + " ")
            pass

        ascii_label = self.options.ascii_label

        if ascii_label is None:
            c.insertText(" ")

            for i in range(self.options.line_length):
                a = "%01X" % i
                #QString a = QString.number(i, 16).toUpper()

                if (self.options.hasFlag(QHexFlags.HighlightColumn)
                        and self.qcursor.column == i):
                    cf.setBackground(self.palette().color(ColorRole.Highlight))
                    cf.setForeground(self.palette().color(ColorRole.HighlightedText))

                c.insertText(a, cf)
                cf = headerFormat()
            c.insertText(" ")

        #   cfc1 = self.endColumnX() - self.asciiColumnX() - self.cellWidth()
        #   cfc2 = int(cfc1 / self.cellWidth())
        #   c.insertText(" " + QHexView.reduced(asciilabel, cfc2 - 1) + " ")

        bf = QTextBlockFormat()
        if self.options.hasFlag(QHexFlags.StyledHeader):
            bf.setBackground(self.palette().color(ColorRole.Window))
        c.setBlockFormat(bf)
        c.insertBlock()

    def drawSeparators(self, p: QPainter) -> None:
        if not self.options.hasFlag(QHexFlags.Separators):
            return

        oldpen = p.pen()
        if self.options.separator_color:
            p.setPen(self.options.separator_color)
        else:
            p.setPen(self.palette().color(ColorRole.Dark))

        if self.options.hasFlag(QHexFlags.HSeparator):
            l1 = QLineF(0, self.font_metrics.lineSpacing(),
                        self.endColumnX(), self.font_metrics.lineSpacing())
            p.drawLine(l1)

        if self.options.hasFlag(QHexFlags.VSeparator):
            p.drawLine(QLineF(self.hexColumnX(), 0, self.hexColumnX(), self.height()))
            p.drawLine(QLineF(self.asciiColumnX(), 0, self.asciiColumnX(), self.height()))

        p.setPen(oldpen)

    def drawDocument(self, c: QTextCursor) -> None:
        if not self.hex_document:
            return

        addrformat = QTextCharFormat()
        color = self.palette().color(ColorGroup.Normal, ColorRole.Highlight)
        addrformat.setForeground(color)

        # Iterate over the number of lines in the visible region.  We don't use the index
        # from the loop because we initialize line to the line number from the entire
        # document, and increment it after each iteration.
        line = self.verticalScrollBar().value()
        for _ in range(self.visibleLines()):
            # There aren't any more lines in the input document.
            if line >= self.lines():
                break

            address = line * self.options.line_length + self.baseAddress()
            afmtstr = "%%0%dX" % self.addressWidth()
            addrstr = afmtstr % address

            # Address Part
            acf = QTextCharFormat()
            if self.options.header_color:
                acf.setForeground(self.options.header_color)

            if self.options.hasFlag(QHexFlags.StyledAddress):
                acf.setBackground(self.palette().color(ColorRole.Window))

            if (self.qcursor.line == line
                    and self.options.hasFlag(QHexFlags.HighlightAddress)):
                acf.setBackground(self.palette().color(ColorRole.Highlight))
                acf.setForeground(self.palette().color(ColorRole.HighlightedText))
            c.insertText(" " + addrstr + "  ", acf)

            # Hex Part
            linebytes = self.getLine(line)
            for column in range(self.options.line_length):
                if len(linebytes) == 0 or column >= len(linebytes):
                    s = '  '
                else:
                    s = '%02X' % linebytes[column]

                b = 0
                if column < len(linebytes):
                    b = linebytes[column]
                else:
                    s = (self.options.invalid_char * 2)

                self.drawFormat(c, b, s, QHexArea.Hex, line,
                                column, column < len(linebytes))
                c.insertText(' ', QTextCharFormat())

            c.insertText(' ')

            # Ascii Part
            for column in range(self.options.line_length):
                b = 0
                if len(linebytes) == 0 or column >= len(linebytes):
                    s = ' '
                elif chr(linebytes[column]).isprintable():
                    s = chr(linebytes[column])
                else:
                    s = self.options.unprintable_char

                b = 0
                if column < len(linebytes):
                    b = linebytes[column]
                else:
                    s = self.options.invalid_char

                self.drawFormat(c, b, s, QHexArea.Ascii, line, column,
                                column < len(linebytes))
            line += 1

            bf = QTextBlockFormat()
            if self.options.line_alternate_background and line % 2:
                bf.setBackground(self.options.line_alternate_background)
            elif self.options.line_background and not (line % 2):
                bf.setBackground(self.options.line_background)

            c.setBlockFormat(bf)
            c.insertBlock()
            if self.hex_document.isEmpty():
                break

    def drawFormat(self, c: QTextCursor, b: int, s: str, area: QHexArea,
                   line: int, column: int, applyformat: bool) -> QTextCharFormat:
        cf = QTextCharFormat()
        scf = QTextCharFormat()
        pos = QHexPosition(line, column)

        if applyformat:
            offset = self.qcursor.positionToOffset(pos)

            if line in self.metadata:
                metadataline = self.metadata[line]
                for metadata in metadataline:
                    if offset < metadata.begin or offset >= metadata.end:
                        continue

                    if metadata.foreground is not None:
                        cf.setForeground(metadata.foreground)

                    if metadata.background is not None:
                        cf.setBackground(metadata.background)

                    if metadata.foreground is None and metadata.background is not None:
                        cf.setForeground(self.getReadableColor(metadata.background))

                    # Remove previous metadata's style, if needed
                    if offset == metadata.begin:
                        if metadata.foreground is None:
                            scf.setForeground(Qt.GlobalColor.color1)
                        if metadata.background is None:
                            scf.setBackground(Qt.GlobalColor.transparent)

                    if offset < metadata.end - 1 and column < self.getLastColumn(line):
                        scf = cf

        if self.qcursor.isSelected(line, column):
            offset = self.qcursor.positionToOffset(pos)
            selend = self.qcursor.selectionEndOffset()

            cf.setBackground(self.palette().color(ColorGroup.Normal, ColorRole.Highlight))
            cf.setForeground(self.palette().color(ColorGroup.Normal, ColorRole.HighlightedText))
            if offset < selend and column < self.getLastColumn(line):
                scf = cf

        if self.qcursor.position == pos and self.hasFocus():
            color = QPalette.ColorGroup.Normal

            # BUG Some code simplification is needed here.
            cursorbg = self.palette().color(color, ColorRole.WindowText)
            cursorfg = self.palette().color(color, ColorRole.Base)
            discursorbg = self.palette().color(ColorGroup.Disabled, ColorRole.WindowText)
            discursorfg = self.palette().color(ColorGroup.Disabled, ColorRole.Base)

            fg_color = discursorfg
            bg_color = discursorbg
            if self.current_area == area:
                fg_color = cursorfg
                bg_color = cursorbg

            cf.setBackground(bg_color)
            cf.setForeground(fg_color)
            # Underline cursor?
            #cf.setUnderlineColor(bg_color)
            #cf.setUnderlineStyle(QTextCharFormat.UnderlineStyle.SingleUnderline)

        c.insertText(s, cf)
        return scf

    def getReadableColor(self, c: QColor) -> QColor:
        palette = self.palette()
        if self.isColorLight(c):
            return palette.color(ColorGroup.Normal, ColorRole.WindowText)
        else:
            return palette.color(ColorGroup.Normal, ColorRole.HighlightedText)

    def isColorLight(self, c: QColor) -> bool:
        return math.sqrt((0.299 * c.red() ** 2)
                         + (0.587 * c.green() ** 2)
                         + (0.114 * c.blue() ** 2)) > 127.5

    def setDocument(self, doc: Optional[QHexDocument]) -> None:
        if doc is None:
            doc = QHexDocument(b'', self)
        if doc.parent() is None:
            doc.setParent(self)
        self.metadata = {}
        self.qcursor.move(QHexPosition(0, 0))
        if self.hex_document:
            #disconnect(self.hex_document, QHexDocument.changed, self, None)
            #disconnect(self.hex_document, QHexDocument.dataChanged, self, None)
            #disconnect(self.hex_document, QHexDocument.reset, self, None)
            #disconnect(self.hex_document, QHexDocument.modifiedChanged, self, None)
            pass

        self.hex_document = doc

        #connect(hex_document, &QHexDocument::reset, this, [=]() {
        #    self.qcursor->move(QHexPosition(0, 0))
        #    self.checkAndUpdate(True)
        #})

        #self.hex_document.dataChanged(self.dataChanged)
        #self.hex_document.modifiedChanged(self.modifiedChanged)
        #self.hex_document.changed(lambda: self.checkAndUpdate(true))
        self.checkAndUpdate(True)

    def checkAndUpdate(self, calc_columns: bool = True) -> None:
        self.checkState()
        if calc_columns:
            self.calcColumns()
        self.viewport().update()

    def checkOptions(self) -> None:
        if self.options.group_length > self.options.line_length:
            self.options.group_length = self.options.line_length

        self.options.address_width = max(self.options.address_width,
                                         self.calcAddressWidth())

        # Round to nearest multiple of 2 BUG! Pythonic way is round()?
        self.options.group_length = 2 * round(self.options.group_length / 2)
        #self.options.group_length = 1 << floor(self.options.group_length / 2.0)

        if self.options.group_length <= 1:
            self.options.group_length = 1

        #if not self.options.header_color.isValid():
        if not self.options.header_color:
            self.options.header_color = self.palette().color(
                QPalette.ColorGroup.Normal, QPalette.ColorRole.Highlight)

    def checkState(self) -> None:
        if not self.hex_document:
            return
        self.checkOptions()

        doc_lines = self.lines()
        vis_lines = self.visibleLines(True)
        vscroll_max = doc_lines - vis_lines
        if doc_lines >= vis_lines:
            vscroll_max += 1

        self.verticalScrollBar().setRange(0, max(0, vscroll_max))
        self.verticalScrollBar().setPageStep(vis_lines - 1)
        self.verticalScrollBar().setSingleStep(self.options.scroll_steps)

        vw = 0
        if self.verticalScrollBar().isVisible():
            vw = self.verticalScrollBar().width()

        #static int oldmw = 0  # BUG Why static in C++?  Poor performance?
        #if oldmw:
        oldmw = self.maximumWidth()

        max_width = oldmw
        #if False: # Limits width of hex area to what's required.
        #    max_width = math.ceil(self.endColumnX() + vw + 3)
        self.setMaximumWidth(max_width)

        max_cols = max(0, int(self.endColumnX() - self.width() + vw + 3))
        self.horizontalScrollBar().setRange(0, max_cols)
        self.horizontalScrollBar().setPageStep(self.width())

    def copy(self, hexadecimal: bool = False) -> None:
        if self.hex_document is None:
            return

        # FIXME!  We need a handle to our QApplication here to read the clipboard!
        c = QApplication.clipboard()

        if self.qcursor.hasSelection():
            bin_bytes = self.selectedBytes()
        else:
            bin_bytes = bytes([self.hex_document.buffer[self.qcursor.offset]])

        hex_bytes = " ".join('%02X' % b for b in bin_bytes)
        c.setText(hex_bytes)

    def selectedBytes(self) -> bytes:
        if not self.qcursor.hasSelection():
            return b''
        if self.hex_document is None:
            return b''

        begin = self.qcursor.selectionStartOffset()
        end = self.qcursor.selectionEndOffset()
        return bytes(self.hex_document.buffer[begin:end])

    def baseAddress(self) -> int:
        return self.options.base_address

    def calcAddressWidth(self) -> int:
        if not self.hex_document:
            return 0

        maxaddr = self.options.base_address + len(self.hex_document)
        #if maxaddr <= std::numeric_limits<quint32>::max()):
        #    return 8
        #return QString::number(maxaddr, 16).size()
        return len(str(hex(maxaddr)))

    def calcColumns(self) -> None:
        if not self.hex_document:
            return

        self.columns = []

        x = self.hexColumnX()
        cw = self.cellWidth() * 2

        for i in range(self.options.line_length):
            for j in range(self.options.group_length):
                self.columns.append(QtCore.QRect(int(x), 0, int(cw), 0))
                x += cw
            x += self.cellWidth()

    def visible_lines(self, absolute: bool = False) -> int:
        """
        Return the number of visible lines in the viewport.

        Do NOT include the last partial line in the viewport.
        """
        vl = int(self.viewport().height() / self.lineHeight())
        if not self.options.hasFlag(QHexFlags.NoHeader):
            vl -= 1
        if absolute:
            return vl
        return min(self.lines(), vl)

    def visibleLines(self, absolute: bool = False) -> int:
        "Return the number of visible lines in the viewport."
        vl = math.ceil(self.viewport().height() / self.lineHeight())
        if not self.options.hasFlag(QHexFlags.NoHeader):
            vl -= 1
        if absolute:
            return vl
        return min(self.lines(), vl)

    def lines(self) -> int:
        if not self.hex_document:
            return 0

        lines = math.ceil(len(self.hex_document) / self.options.line_length)
        if (not self.hex_document.isEmpty()) and (not lines):
            return 1
        return lines

    def lineHeight(self) -> float:
        return self.font_metrics.height()

    def lineLength(self) -> int:
        return self.options.line_length

    def getLastColumn(self, line: int) -> int:
        return len(self.getLine(line)) - 1

    def maxViewWidth(self) -> int:
        "Return the approximate width required to display the complete hex view."
        # Count the characters in the address, hex, and ASCII sections of the view.
        char_width = 8 + (16 * 2) + 16
        visible_width = self.font_metrics.boundingRect("0" * char_width).width()
        # Add spaces between hex columns, plus 10 extra spaces because I don't really know
        # how to properly compute the exact width.
        spaces = 16 + 10
        space_width = self.font_metrics.boundingRect(" " * spaces).width()
        # Since the resulting width is at least based on the font metrics, it will
        # presumably be close enough for the purpose of this function which is to choose a
        # default width for the HexView widget.  If we get it wrong, the user can always
        # drag the slider to correct our guess.  There's a more accurate width calculated
        # for the mouse click detection, but that code path is currently dependent on the
        # actual document being viewed, which isn't available at the time that we want to
        # approximate the width width.
        return int(visible_width + space_width)

    def getNCellsWidth(self, n: int) -> float:
        return n * self.cellWidth()

    def addressWidth(self) -> int:
        if (not self.hex_document) or self.options.address_width:
            return self.options.address_width
        return self.calcAddressWidth()

    def hexColumnWidth(self) -> float:
        c = 0
        i = 0
        while i < self.options.line_length:
            c += (2 * self.options.group_length) + 1
            i += self.options.group_length

        return self.getNCellsWidth(c)

    def hexColumnX(self) -> float:
        return self.getNCellsWidth(self.addressWidth() + 2)

    def asciiColumnX(self) -> float:
        return self.hexColumnX() + self.hexColumnWidth() + self.cellWidth()

    def endColumnX(self) -> float:
        n = self.getNCellsWidth(self.options.line_length + 1)
        return self.asciiColumnX() + n + self.cellWidth()

    def cellWidth(self) -> float:
        return self.font_metrics.horizontalAdvance(" ")

    def getLine(self, line: int) -> bytes:
        if self.hex_document:
            llen = self.options.line_length
            offset = line * llen
            return bytes(self.hex_document.buffer[offset:offset + llen])
        return b''

    def lastLine(self) -> int:
        return max(0, self.lines() - 1)

    def positionFromLineCol(self, line: int, col: int) -> int:
        if self.hex_document:
            return min((line * self.options.line_length) + col, len(self.hex_document))

        return 0

    def setMetadata(self, m: QHexMetadata) -> None:
        "Add some metadata to the hex view."
        if not self.options.line_length:
            return

        first_line = int(m.begin / self.options.line_length)
        last_line = int(m.end / self.options.line_length) + 1
        notify = False

        #for(line = first_line; line <= last_line; line++):
        for line in range(first_line, last_line):
            start = 0
            if line == first_line:
                start = m.begin % self.options.line_length

            length = self.options.line_length
            if line == last_line:
                length = (m.end % self.options.line_length) - start

            if length <= 0:
                continue

            notify = True
            if line not in self.metadata:
                self.metadata[line] = []
            self.metadata[line].append(m)

        if notify:
            #Q_EMIT changed()
            pass

    def removeMetadata(self, m: QHexMetadata) -> bool:
        "Remove the requested metadata."
        removed = False
        first_line = int(m.begin / self.options.line_length)
        last_line = int(m.end / self.options.line_length) + 1
        for line in range(first_line, last_line):
            if line in self.metadata and m in self.metadata[line]:
                self.metadata[line].remove(m)
                removed = True
        return removed

    def get_comments(self, pos: QHexPosition) -> Optional[str]:
        if pos.line not in self.metadata:
            return None

        if len(self.metadata[pos.line]) == 0:
            return None

        offset = positionToOffset(self.options, pos)
        comments = []
        for metadata in self.metadata[pos.line]:
            if offset < metadata.begin or offset > metadata.end:
                continue
            if metadata.comment is None:
                continue
            comments.append(metadata.comment)

        return "\n".join(comments)

if __name__ == '__main__':
    # Use this script as the input
    data = open(sys.argv[-1], 'rb').read()
    app = QtWidgets.QApplication()

    view = QHexView(doc=data)
    red = QColor(0xff0000)
    green = QColor(0x00ff00)
    gray = QColor(0x414141)

    # --------------------------------------------------------------------------
    # These work.
    # --------------------------------------------------------------------------
    # Color the range 0x318-0x345.
    view.setMetadata(QHexMetadata(0x318, 0x345, red, gray, "Test Comment!"))

    # Pretend like the hex view begins at address 0x330000 instead of 0x0.
    # view.options.base_address = 0x330000

    # Draw separator lines.
    view.options.flags = QHexFlags.Separators

    # Move to a byte offset in the document.
    view.qcursor.move_offset(0x318)

    view.show()
    sys.exit(app.exec_())

# ----------------------------------------------------------------------------------------
# Local Variables:
# mode: python
# fill-column: 90
# End:
