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

// Some code based on QHexView by Even Teran
// https://code.google.com/p/qhexview/

#include "byte_view_text.h"

#include <epan/charsets.h>

#include "color_utils.h"
#include "wireshark_application.h"

#include <QMouseEvent>
#include <QPainter>
#include <QScrollBar>

// To do:
// - Bit view

// We don't obey the gui.hex_dump_highlight_style preference. If you
// would like to add support for this you'll probably have to call
// QPainter::drawText for each individual character.

ByteViewText::ByteViewText(QWidget *parent, tvbuff_t *tvb, proto_tree *tree, QTreeWidget *tree_widget, packet_char_enc encoding) :
    QAbstractScrollArea(parent),
    tvb_(tvb),
    proto_tree_(tree),
    tree_widget_(tree_widget),
    bold_highlight_(false),
    encoding_(encoding),
    format_(BYTES_HEX),
    p_start_(-1),
    p_end_(-1),
    f_start_(0),
    f_end_(0),
    fa_start_(-1),
    fa_end_(-1),
    show_offset_(true),
    show_hex_(true),
    show_ascii_(true),
    row_width_(16)
{
}

void ByteViewText::setEncoding(packet_char_enc encoding)
{
    encoding_ = encoding;
    viewport()->update();
}

bool ByteViewText::hasDataSource(const tvbuff_t *ds_tvb) {
    if (ds_tvb != NULL && ds_tvb == tvb_)
        return true;
    return false;
}

void ByteViewText::setProtocolHighlight(int start, int end)
{
    p_start_ = qMax(0, start);
    p_end_ = qMax(0, end);
    viewport()->update();
}

void ByteViewText::setFieldHighlight(int start, int end, guint32 mask, int mask_le)
{
    Q_UNUSED(mask);
    Q_UNUSED(mask_le);
    f_start_ = qMax(0, start);
    f_end_ = qMax(0, end);
    viewport()->update();
}

void ByteViewText::setFieldAppendixHighlight(int start, int end)
{
    fa_start_ = qMax(0, start);
    fa_end_ = qMax(0, end);
    viewport()->update();
}

void ByteViewText::setMonospaceFont(const QFont &mono_font)
{
    mono_font_ = mono_font;
//    mono_bold_font_ = QFont(mono_font);
//    mono_bold_font_.setBold(true);

    const QFontMetricsF fm(mono_font);
    font_width_  = fm.width('M');
    line_spacing_ = fm.lineSpacing() + 0.5;
    one_em_ = fm.height();
    margin_ = fm.height() / 2;

    setFont(mono_font);

    updateScrollbars();
    viewport()->update();
}

void ByteViewText::paintEvent(QPaintEvent *)
{
    QPainter painter(viewport());
    painter.translate(-horizontalScrollBar()->value() * font_width_, 0);

    // Pixel offset of this row
    int row_y = 0;

    // Starting byte offset
    guint offset = (guint) verticalScrollBar()->value() * row_width_;

    // Clear the area
    painter.fillRect(viewport()->rect(), palette().base());

    // Offset background
    offset_bg_.setColor(ColorUtils::alphaBlend(palette().text(), palette().base(), 0.05));
    offset_bg_.setStyle(Qt::SolidPattern);
    offset_normal_fg_.setColor(ColorUtils::alphaBlend(palette().text(), palette().base(), 0.35));
    offset_field_fg_.setColor(ColorUtils::alphaBlend(palette().text(), palette().base(), 0.6));
    if (show_offset_) {
        QRect offset_rect = QRect(viewport()->rect());
        offset_rect.setWidth(offsetPixels());
        painter.fillRect(offset_rect, offset_bg_);
    }

    if (!tvb_) {
        return;
    }

    // Map window coordinates to byte offsets
    x_pos_to_column_.clear();
    for (guint i = 0; i < row_width_; i++) {
        int sep_width = (i / separator_interval_) * font_width_;
        if (show_hex_) {
            int hex_x = offsetPixels() + margin_ + sep_width + (i * 3 * font_width_);
            for (int j = 0; j <= font_width_ * 2; j++) {
                x_pos_to_column_[hex_x + j] = i;
            }
        }
        if (show_ascii_) {
            int ascii_x = offsetPixels() + hexPixels() + margin_ + sep_width + (i * font_width_);
            for (int j = 0; j <= font_width_; j++) {
                x_pos_to_column_[ascii_x + j] = i;
            }
        }
    }

    // Data rows
    int widget_height = height();
    painter.save();
    while(row_y + line_spacing_ < widget_height && offset < tvb_captured_length(tvb_)) {
        drawOffsetLine(painter, offset, row_y);
        offset += row_width_;
        row_y += line_spacing_;
    }
    painter.restore();
}

void ByteViewText::resizeEvent(QResizeEvent *)
{
    updateScrollbars();
}

void ByteViewText::mousePressEvent (QMouseEvent *event) {
    if (!tvb_ || event->button() != Qt::LeftButton ) {
        return;
    }

    QPoint pt = event->pos();
    int byte = (verticalScrollBar()->value() + (pt.y() / line_spacing_)) * row_width_;
    int x = (horizontalScrollBar()->value() * font_width_) + pt.x();
    int col = x_pos_to_column_.value(x, -1);

    if (col < 0) {
        return;
    }

    byte += col;
    if ((guint) byte > tvb_captured_length(tvb_)) {
        return;
    }

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

// Private

const int ByteViewText::separator_interval_ = 8; // Insert a space after this many bytes

// Draw a line of byte view text for a given offset.
// Text with different styles are split into fragments and passed to
// flushOffsetFragment. Font character widths aren't necessarily whole
// numbers so we track our X coordinate position using using floats.
void ByteViewText::drawOffsetLine(QPainter &painter, const guint offset, const int row_y)
{
    if (!tvb_) {
        return;
    }
    guint tvb_len = tvb_captured_length(tvb_);
    guint max_pos = qMin(offset + row_width_, tvb_len);
    const guint8 *pd = tvb_get_ptr(tvb_, 0, -1);

    static const guchar hexchars[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    QString text;
    highlight_state state = StateNormal, offset_state = StateOffsetNormal;
    qreal hex_x = offsetPixels() + margin_;
    qreal ascii_x = offsetPixels() + hexPixels() + margin_;

    // Hex
    if (show_hex_) {
        for (guint tvb_pos = offset; tvb_pos < max_pos; tvb_pos++) {
            highlight_state hex_state = StateNormal;
            bool add_space = tvb_pos != offset;

            if ((tvb_pos >= f_start_ && tvb_pos < f_end_) || (tvb_pos >= fa_start_ && tvb_pos < fa_end_)) {
                hex_state = StateField;
                offset_state = StateOffsetField;
            } else if (tvb_pos >= p_start_ && tvb_pos < p_end_) {
                hex_state = StateProtocol;
            }

            if (hex_state != state) {
                if ((state == StateNormal || (state == StateProtocol && hex_state == StateField)) && add_space) {
                    add_space = false;
                    text += ' ';
                    /* insert a space every separator_interval_ bytes */
                    if ((tvb_pos % separator_interval_) == 0)
                        text += ' ';
                }
                hex_x += flushOffsetFragment(painter, hex_x, row_y, state, text);
                state = hex_state;
            }

            if (add_space) {
                text += ' ';
                /* insert a space every separator_interval_ bytes */
                if ((tvb_pos % separator_interval_) == 0)
                    text += ' ';
            }

            switch (format_) {
            case BYTES_HEX:
                text += hexchars[(pd[tvb_pos] & 0xf0) >> 4];
                text += hexchars[pd[tvb_pos] & 0x0f];
                break;
            case BYTES_BITS:
                /* XXX, bitmask */
                for (int j = 7; j >= 0; j--)
                    text += (pd[tvb_pos] & (1 << j)) ? '1' : '0';
                break;
            }
        }
    }
    if (text.length() > 0) {
        flushOffsetFragment(painter, hex_x, row_y, state, text);
    }
    state = StateNormal;

    // ASCII
    if (show_ascii_) {
        for (guint tvb_pos = offset; tvb_pos < max_pos; tvb_pos++) {
            highlight_state ascii_state = StateNormal;
            bool add_space = tvb_pos != offset;

            if ((tvb_pos >= f_start_ && tvb_pos < f_end_) || (tvb_pos >= fa_start_ && tvb_pos < fa_end_)) {
                ascii_state = StateField;
                offset_state = StateOffsetField;
            } else if (tvb_pos >= p_start_ && tvb_pos < p_end_) {
                ascii_state = StateProtocol;
            }

            if (ascii_state != state) {
                if ((state == StateNormal || (state == StateProtocol && ascii_state == StateField)) && add_space) {
                    add_space = false;
                    /* insert a space every separator_interval_ bytes */
                    if ((tvb_pos % separator_interval_) == 0)
                        text += ' ';
                }
                ascii_x += flushOffsetFragment(painter, ascii_x, row_y, state, text);
                state = ascii_state;
            }

            if (add_space) {
                /* insert a space every separator_interval_ bytes */
                if ((tvb_pos % separator_interval_) == 0)
                    text += ' ';
            }

            guchar c = (encoding_ == PACKET_CHAR_ENC_CHAR_EBCDIC) ?
                        EBCDIC_to_ASCII1(pd[tvb_pos]) :
                        pd[tvb_pos];

            text += g_ascii_isprint(c) ? c : '.';
        }
    }
    if (text.length() > 0) {
        flushOffsetFragment(painter, ascii_x, row_y, state, text);
    }
    state = StateNormal;

    // Offset. Must be drawn last in order for offset_state to be set.
    if (show_offset_) {
        text = QString("%1").arg(offset, offsetChars(), 16, QChar('0'));
        flushOffsetFragment(painter, margin_, row_y, offset_state, text);
    }
}

// Draws a fragment of byte view text at the specifiec location using colors
// for the specified state. Clears the text and returns the pixel width of the
// drawn text.
qreal ByteViewText::flushOffsetFragment(QPainter &painter, qreal x, int y, highlight_state state, QString &text)
{
    if (text.length() < 1) {
        return 0;
    }
    QFontMetricsF fm(mono_font_);
    qreal width = fm.width(text);
    // Background
    if (state == StateField) {
        painter.fillRect(QRectF(x, y, width, line_spacing_), palette().highlight());
    } else if (state == StateProtocol) {
        painter.fillRect(QRectF(x, y, width, line_spacing_), palette().button());
    }

    // Text
    QBrush text_brush;
    switch (state) {
    case StateNormal:
    default:
        text_brush = palette().text();
        break;
    case StateField:
        text_brush = palette().highlightedText();
        break;
    case StateProtocol:
        text_brush = palette().buttonText();
        break;
    case StateOffsetNormal:
        text_brush = offset_normal_fg_;
        break;
    case StateOffsetField:
        text_brush = offset_field_fg_;
        break;
    }

    painter.setPen(QPen(text_brush.color()));
    painter.drawText(QRectF(x, y, width, line_spacing_), Qt::AlignTop, text);
    text.clear();
    return width;
}

void ByteViewText::scrollToByte(int byte)
{
    verticalScrollBar()->setValue(byte / row_width_);
}

// Offset character width
int ByteViewText::offsetChars()
{
    if (tvb_ && tvb_captured_length(tvb_) > 0xffff) {
        return 8;
    }
    return 4;
}

// Offset pixel width
int ByteViewText::offsetPixels()
{
    if (show_offset_) {
        return offsetChars() * font_width_ + one_em_;
    }
    return 0;
}

// Hex pixel width
int ByteViewText::hexPixels()
{
    if (show_hex_) {
        return (((row_width_ * 3) + ((row_width_ - 1) / separator_interval_)) * font_width_) + one_em_;
    }
    return 0;
}

int ByteViewText::asciiPixels()
{
    if (show_ascii_) {
        return ((row_width_ + ((row_width_ - 1) / separator_interval_)) * font_width_) + one_em_;
    }
    return 0;
}

int ByteViewText::totalPixels()
{
    return offsetPixels() + hexPixels() + asciiPixels();
}

void ByteViewText::updateScrollbars()
{
    const gint length = tvb_ ? tvb_captured_length(tvb_) : 0;
    if (tvb_) {
    }

    qint64 maxval = length / row_width_ + ((length % row_width_) ? 1 : 0) - viewport()->height() / line_spacing_;

    verticalScrollBar()->setRange(0, qMax((qint64)0, maxval));
    horizontalScrollBar()->setRange(0, qMax(0, static_cast<int>((totalPixels() - viewport()->width()) / font_width_)));
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
