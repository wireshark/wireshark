/* byte_view_text.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "byte_view_text.h"

#include <epan/charsets.h>

#include "wireshark_application.h"
#include <QTextCursor>
#include <QTextBlock>
#include <QApplication>
#include <QMouseEvent>

// XXX - Use KHexEdit instead?
// http://api.kde.org/4.x-api/kdelibs-apidocs/interfaces/khexedit/html/index.html

ByteViewText::ByteViewText(QWidget *parent, tvbuff_t *tvb, proto_tree *tree, QTreeWidget *tree_widget, packet_char_enc encoding) :
    QTextEdit(parent),
    tvb_(tvb),
    proto_tree_(tree),
    tree_widget_(tree_widget),
    bold_highlight_(false),
    encoding_(encoding),
    format_(BYTES_HEX),
    p_start_(-1),
    p_end_(-1),
    f_start_(-1),
    f_end_(-1),
    fa_start_(-1),
    fa_end_(-1),
    per_line_(16),
    offset_width_(4)
{
    setReadOnly(true);
    setUndoRedoEnabled(false);
    setLineWrapMode(QTextEdit::NoWrap);
    setState(StateNormal);

    renderBytes();
}

void ByteViewText::setEncoding(packet_char_enc encoding)
{
    encoding_ = encoding;
}

bool ByteViewText::hasDataSource(tvbuff_t *ds_tvb) {
    if (ds_tvb != NULL && ds_tvb == tvb_)
        return true;
    return false;
}

void ByteViewText::setProtocolHighlight(int start, int end)
{
    p_start_ = start;
    p_end_ = end;
}

void ByteViewText::setFieldHighlight(int start, int end, guint32 mask, int mask_le)
{
    Q_UNUSED(mask);
    Q_UNUSED(mask_le);
    f_start_ = start;
    f_end_ = end;
}

void ByteViewText::setFieldAppendixHighlight(int start, int end)
{
    fa_start_ = start;
    fa_end_ = end;
}

void ByteViewText::renderBytes()
{
    int length;
    int start_byte = 0;

    if (!tvb_) {
        clear();
        return;
    }

    // XXX Even with updates and undo disabled this is slow. Instead of clearing
    // and filling in the text each time we should probably fill it in once and
    // use setExtraSelections to set highlighting.
    setUpdatesEnabled(false);

    textCursor().beginEditBlock();
    clear();

    length = tvb_length(tvb_);
    for (int off = 0; off < length; off += per_line_) {
        lineCommon(off);
    }
    textCursor().endEditBlock();

    if (f_start_ > 0 && f_end_ > 0) {
        start_byte = f_start_;
    } else if (p_start_ > 0 && p_end_ > 0) {
        start_byte = p_start_;
    }
    scrollToByte(start_byte);

    setUpdatesEnabled(true);
}

// Private

#define BYTE_VIEW_SEP    8      /* insert a space every BYTE_VIEW_SEP bytes */

void ByteViewText::lineCommon(const int org_off)
{
    static const guchar hexchars[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    const guint8 *pd;
    int len;

    highlight_state state;

    QString str;

    int off;
    guchar c;
    int byten;
    int j;

    g_assert(org_off >= 0);

    if (!tvb_)
        return;
    len = tvb_length(tvb_);
    pd = tvb_get_ptr(tvb_, 0, -1);

    state = StateNormal;
    setState(state);

    /* Print the line number */
    str += QString("%1  ").arg(org_off, offset_width_, 16, QChar('0'));

    /* Print the hex bit */
    for (byten = 0, off = org_off; byten < per_line_; byten++) {
        highlight_state state_cur = StateNormal;
        bool add_space = byten > 0;

        if ((off >= f_start_ && off < f_end_) || (off >= fa_start_ && off < fa_end_)) {
            state_cur = StateField;
        } else if (off >= p_start_ && off < p_end_) {
            state_cur = StateProtocol;
        }

        if (state_cur != state) {
            if (state != StateField && add_space) {
                add_space = false;
                str += ' ';
                /* insert a space every BYTE_VIEW_SEP bytes */
                if ((off % BYTE_VIEW_SEP) == 0)
                    str += ' ';
            }

            if (flushBytes(str) < 0)
                return;
            setState(state_cur);
            state = state_cur;
        }

        if (add_space) {
            str += ' ';
            /* insert a space every BYTE_VIEW_SEP bytes */
            if ((off % BYTE_VIEW_SEP) == 0)
                str += ' ';
        }

        if (off < len) {
            switch (format_) {
            case BYTES_HEX:
                str += hexchars[(pd[off] & 0xf0) >> 4];
                str += hexchars[pd[off] & 0x0f];
                break;
            case BYTES_BITS:
                /* XXX, bitmask */
                for (j = 7; j >= 0; j--)
                    str += (pd[off] & (1 << j)) ? '1' : '0';
                break;
            }
        } else {
            switch (format_) {
            case BYTES_HEX:
                str += "  ";
                break;
            case BYTES_BITS:
                str += "       ";
                break;
            }
        }
        off++;
    }

    if (state != StateNormal) {
        if (flushBytes(str) < 0)
            return;
        setState(StateNormal);
        state = StateNormal;
    }

    /* Print some space at the end of the line */
    str += "   ";

    /* Print the ASCII bit */
    for (byten = 0, off = org_off; byten < per_line_; byten++) {
        highlight_state state_cur = StateNormal;
        bool add_space = byten > 0;

        if ((off >= f_start_ && off < f_end_) || (off >= fa_start_ && off < fa_end_)) {
            state_cur = StateField;
        } else if (off >= p_start_ && off < p_end_) {
            state_cur = StateProtocol;
        }

        if (state_cur != state) {
            if (state != StateField && add_space) {
                add_space = false;
                /* insert a space every BYTE_VIEW_SEP bytes */
                if ((off % BYTE_VIEW_SEP) == 0)
                    str += ' ';
            }

            if (flushBytes(str) < 0)
                return;
            setState(state_cur);
            state = state_cur;
        }

        if (add_space) {
            /* insert a space every BYTE_VIEW_SEP bytes */
            if ((off % BYTE_VIEW_SEP) == 0)
                str += ' ';
        }

        if (off < len) {
            c = (encoding_ == PACKET_CHAR_ENC_CHAR_EBCDIC) ?
                        EBCDIC_to_ASCII1(pd[off]) :
                        pd[off];

            str += g_ascii_isprint(c) ? c : '.';
        } else
            str += ' ';

        off++;
    }

    if (str.length() > 0) {
        if (flushBytes(str) < 0)
            return;
    }

    if (state != StateNormal) {
        setState(StateNormal);
        /* state = StateNormal; */
    }
    append("");
}

void ByteViewText::setState(ByteViewText::highlight_state state)
{
    QPalette pal = wsApp->palette();

    moveCursor(QTextCursor::End);
    setCurrentFont(wsApp->monospaceFont());
    setTextColor(pal.text().color());
    setTextBackgroundColor(pal.base().color());

    switch (state) {
    case StateProtocol:
        setTextBackgroundColor(pal.alternateBase().color());
        break;
    case StateField:
        if (bold_highlight_) {
            setCurrentFont(wsApp->monospaceFont(true));
        } else {
            setTextColor(pal.base().color());
            setTextBackgroundColor(pal.text().color());
        }
        break;
    default:
        break;
    }
}

int ByteViewText::flushBytes(QString &str)
{
    if (str.length() < 1) return 0;

    insertPlainText(str);
    str.clear();
    return str.length();
}

void ByteViewText::scrollToByte(int byte)
{
    QTextCursor cursor(textCursor());
    cursor.setPosition(0);

    cursor.setPosition(byte * cursor.block().length() / per_line_);
    setTextCursor(cursor);
    ensureCursorVisible();
}

int ByteViewText::byteFromRowCol(int row, int col)
{
    /* hex_pos_byte array generated with hex_view_get_byte(0, 0, 0...70) */
    static const int hex_pos_byte[70] = {
        -1, -1,
        0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3,
        4, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7,
        -1,
        8, 8, 8, 9, 9, 9, 10, 10, 10, 11, 11, 11,
        12, 12, 12, 13, 13, 13, 14, 14, 14, 15, 15, 15,
        -1, -1,
        0, 1, 2, 3, 4, 5, 6, 7,
        -1,
        8, 9, 10, 11, 12, 13, 14, 15
    };

    /* bits_pos_byte array generated with bit_view_get_byte(0, 0, 0...84) */
    static const int bits_pos_byte[84] = {
        -1, -1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        -1, -1,
        0, 1, 2, 3, 4, 5, 6, 7
    };

    int off_col = 1;
    int off_row;

    off_row = row * per_line_;

    if (/* char_x < 0 || */ col < offset_width_)
        return -1;
    col -= offset_width_;

    switch (format_) {
        case BYTES_BITS:
            g_return_val_if_fail(col >= 0 && col < (int) G_N_ELEMENTS(bits_pos_byte), -1);
            off_col = bits_pos_byte[col];
            break;

        case BYTES_HEX:
            g_return_val_if_fail(col >= 0 && col < (int) G_N_ELEMENTS(hex_pos_byte), -1);
            off_col = hex_pos_byte[col];
            break;
    }

    if (col == -1)
        return -1;

    return off_row + off_col;
}

void ByteViewText::mousePressEvent (QMouseEvent * event) {
    if (event->button() == Qt::LeftButton) {
        int byte;
        QTextCursor cursor(cursorForPosition(event->pos()));

        byte = byteFromRowCol(cursor.blockNumber(), cursor.columnNumber());
        if (byte >= 0) {
            field_info *fi = proto_find_field_from_offset(proto_tree_, byte, tvb_);

            if (fi && tree_widget_) {
                // XXX - This should probably be a ProtoTree method.
                QTreeWidgetItemIterator iter(tree_widget_);
                while (*iter) {
                    if (fi == (*iter)->data(0, Qt::UserRole).value<field_info *>()) {
                        tree_widget_->setCurrentItem((*iter));
                    }

                    iter++;
                }
            }
        }
    }

    QWidget::mousePressEvent (event);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
