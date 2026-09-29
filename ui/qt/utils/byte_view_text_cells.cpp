/* byte_view_text_cells.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "byte_view_text_cells.h"

#include <wsutil/str_util.h>
#include <wsutil/utf8_entities.h>

#include <glib.h>

#include <QTextBoundaryFinder>

#include <algorithm>

namespace {
// Drawn under a combining mark that has no base character of its own.
const QChar dotted_circle(0x25cc);
const QString middle_dot = QString::fromUtf8(UTF8_MIDDLE_DOT);
// Code points decoded before looking for a place to split the run.
const int run_chunk_size = 4096;
}

ByteViewTextCells::ByteViewTextCells() :
    encoding_(Ascii)
{
}

void ByteViewTextCells::decode(const QByteArray &data, Encoding encoding)
{
    clear();
    data_ = data;
    encoding_ = encoding;

    if (encoding == Utf8 && !data_.isEmpty()) {
        decodeUtf8();
    }
}

void ByteViewTextCells::clear()
{
    data_.clear();
    cells_.clear();
    text_.clear();
}

int ByteViewTextCells::cellCount() const
{
    if (encoding_ == Utf8) {
        return static_cast<int>(cells_.size());
    }
    return static_cast<int>(data_.size());
}

ByteViewTextCells::Cell ByteViewTextCells::cellAt(int cell_index) const
{
    if (encoding_ != Utf8) {
        return singleByteCell(cell_index);
    }

    const StoredCell &stored = cells_.at(cell_index);
    Cell cell;
    cell.start = stored.start;
    cell.length = stored.length;
    cell.kind = static_cast<CellKind>(stored.kind);
    cell.text = text_.mid(stored.text_pos, stored.text_len);
    return cell;
}

int ByteViewTextCells::cellIndexForByte(int offset) const
{
    if (offset < 0 || offset >= data_.size()) {
        return -1;
    }
    if (encoding_ != Utf8) {
        return offset;
    }

    // Cells are sorted by start; find the last one starting at or before offset.
    auto it = std::upper_bound(cells_.cbegin(), cells_.cend(), offset,
                               [](int value, const StoredCell &cell) { return value < cell.start; });
    return static_cast<int>(it - cells_.cbegin()) - 1;
}

bool ByteViewTextCells::cellForByte(int offset, Cell &cell) const
{
    int cell_index = cellIndexForByte(offset);
    if (cell_index < 0) {
        return false;
    }
    cell = cellAt(cell_index);
    return true;
}

ByteViewTextCells::Cell ByteViewTextCells::singleByteCell(int offset) const
{
    uint8_t c = static_cast<uint8_t>(data_.at(offset));
    if (encoding_ == Ebcdic) {
        c = EBCDIC_to_ASCII1(c);
    }

    Cell cell;
    cell.start = offset;
    cell.length = 1;
    if (g_ascii_isprint(c)) {
        cell.kind = Printable;
        cell.text = QString(QChar::fromLatin1(static_cast<char>(c)));
    } else {
        cell.kind = NonPrintable;
        cell.text = middle_dot;
    }
    return cell;
}

void ByteViewTextCells::decodeUtf8()
{
    const char *bytes = data_.constData();
    const int size = static_cast<int>(data_.size());
    QVector<CodePoint> run;

    // All dot cells share this text.
    text_ = middle_dot;

    int pos = 0;
    while (pos < size) {
        uint32_t uc;
        int length;

        if (bytes[pos] == '\0') {
            // g_utf8_get_char_validated() rejects NUL; it is a valid,
            // non-printable code point here.
            uc = 0;
            length = 1;
        } else {
            gunichar validated = g_utf8_get_char_validated(bytes + pos, size - pos);
            if (validated == (gunichar)-1 || validated == (gunichar)-2) {
                // Not a valid sequence, or truncated by the end of the data.
                appendRun(run);
                run.clear();
                appendDotCell(pos, 1, Invalid);
                pos++;
                continue;
            }
            uc = validated;
            length = static_cast<int>(g_utf8_next_char(bytes + pos) - (bytes + pos));
        }

        // Bound the run so that the temporary storage stays small. Two
        // ASCII characters in a row are always a grapheme boundary, except
        // CR LF.
        if (run.size() >= run_chunk_size && uc < 0x80 && run.last().uc < 0x80 &&
            !(run.last().uc == '\r' && uc == '\n')) {
            appendRun(run);
            run.clear();
        }

        run.append({ pos, length, uc });
        pos += length;
    }
    appendRun(run);
    cells_.squeeze();
    text_.squeeze();
}

void ByteViewTextCells::appendRun(const QVector<CodePoint> &run)
{
    if (run.isEmpty()) {
        return;
    }

    QString text;
    for (const CodePoint &cp : run) {
        char32_t uc32 = cp.uc;
        text.append(QString::fromUcs4(&uc32, 1));
    }

    // Grapheme boundaries come back as positions in the QString, which is
    // UTF-16, so walk the code points alongside: one outside the BMP takes
    // two positions, every other one takes one.
    QTextBoundaryFinder finder(QTextBoundaryFinder::Grapheme, text);
    const int run_size = static_cast<int>(run.size());
    int first = 0;    // First code point of the current cluster.
    int last = 0;     // Code point that starts at text_pos.
    int text_pos = 0;
    for (qsizetype boundary = finder.toNextBoundary(); boundary >= 0; boundary = finder.toNextBoundary()) {
        while (last < run_size && text_pos < boundary) {
            text_pos += QChar::requiresSurrogates(run.at(last).uc) ? 2 : 1;
            last++;
        }
        if (last > first) {
            appendCluster(run, first, last);
        }
        first = last;
    }
    if (first < run_size) {
        appendCluster(run, first, run_size);
    }
}

void ByteViewTextCells::appendCluster(const QVector<CodePoint> &run, int first, int last)
{
    const CodePoint &lead = run.at(first);
    const CodePoint &tail = run.at(last - 1);
    int length = tail.start + tail.length - lead.start;

    // A cluster that starts with something we do not draw (a control or
    // format character, unusual whitespace, ...) is shown code point by
    // code point so that each of them gets a dot. Very long clusters are
    // split the same way.
    if (!isDisplayable(lead.uc) || length > max_cell_bytes) {
        appendCodePoints(run, first, last);
        return;
    }

    appendCell(lead.start, length, Printable, textFor(run, first, last));
}

void ByteViewTextCells::appendCodePoints(const QVector<CodePoint> &run, int first, int last)
{
    for (int i = first; i < last; i++) {
        const CodePoint &cp = run.at(i);
        if (isDisplayable(cp.uc)) {
            appendCell(cp.start, cp.length, Printable, textFor(run, i, i + 1));
        } else {
            appendDotCell(cp.start, cp.length, NonPrintable);
        }
    }
}

void ByteViewTextCells::appendCell(int start, int length, CellKind kind, const QString &text)
{
    StoredCell cell;
    cell.start = start;
    cell.text_pos = static_cast<int>(text_.size());
    cell.length = static_cast<uint16_t>(length);
    cell.text_len = static_cast<uint16_t>(text.size());
    cell.kind = static_cast<uint8_t>(kind);
    cells_.append(cell);
    text_.append(text);
}

void ByteViewTextCells::appendDotCell(int start, int length, CellKind kind)
{
    StoredCell cell;
    cell.start = start;
    cell.text_pos = 0;
    cell.length = static_cast<uint16_t>(length);
    cell.text_len = static_cast<uint16_t>(middle_dot.size());
    cell.kind = static_cast<uint8_t>(kind);
    cells_.append(cell);
}

// Whether a code point gets a glyph of its own. Letters, marks, numbers,
// punctuation, symbols and the ASCII space do; controls, format characters
// (including ZWJ and ZWNJ on their own), surrogates, private use,
// unassigned code points and all other whitespace are shown as a dot so
// that they stay visible.
bool ByteViewTextCells::isDisplayable(uint32_t uc)
{
    if (uc == ' ') {
        return true;
    }
    switch (g_unichar_type(uc)) {
    case G_UNICODE_CONTROL:
    case G_UNICODE_FORMAT:
    case G_UNICODE_SURROGATE:
    case G_UNICODE_PRIVATE_USE:
    case G_UNICODE_UNASSIGNED:
    case G_UNICODE_SPACE_SEPARATOR:
    case G_UNICODE_LINE_SEPARATOR:
    case G_UNICODE_PARAGRAPH_SEPARATOR:
        return false;
    default:
        return true;
    }
}

bool ByteViewTextCells::isMark(uint32_t uc)
{
    switch (g_unichar_type(uc)) {
    case G_UNICODE_SPACING_MARK:
    case G_UNICODE_ENCLOSING_MARK:
    case G_UNICODE_NON_SPACING_MARK:
        return true;
    default:
        return false;
    }
}

QString ByteViewTextCells::textFor(const QVector<CodePoint> &run, int first, int last)
{
    QString text;
    if (isMark(run.at(first).uc)) {
        // A mark without a base character; give it one to sit on.
        text.append(dotted_circle);
    }
    for (int i = first; i < last; i++) {
        char32_t uc32 = run.at(i).uc;
        text.append(QString::fromUcs4(&uc32, 1));
    }
    return text;
}
