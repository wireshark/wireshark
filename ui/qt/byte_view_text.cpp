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

#include <wsutil/utf8_entities.h>

#include <ui/qt/utils/color_utils.h>
#include "wireshark_application.h"
#include "ui/recent.h"

#include <ui/qt/utils/variant_pointer.h>

#include <QActionGroup>
#include <QMouseEvent>
#include <QPainter>
#include <QScrollBar>
#include <QStyle>
#include <QStyleOption>

// To do:
// - Add recent settings and context menu items to show/hide the offset,
//   and ASCII/EBCDIC.
// - Add a UTF-8 and possibly UTF-xx option to the ASCII display.
// - Add "copy bytes as" context menu items.

// We don't obey the gui.hex_dump_highlight_style preference. If you
// would like to add support for this you'll probably have to call
// QPainter::drawText for each individual character.

Q_DECLARE_METATYPE(bytes_view_type)
Q_DECLARE_METATYPE(packet_char_enc)

ByteViewText::ByteViewText(QByteArray data, packet_char_enc encoding, QWidget *parent) :
    QAbstractScrollArea(parent),
    bold_highlight_(false),
    encoding_(encoding),
    hovered_byte_offset_(-1),
    hovered_byte_lock_(false),
    p_bound_(0, 0),
    f_bound_(0, 0),
    fa_bound_(0, 0),
    show_offset_(true),
    show_hex_(true),
    show_ascii_(true),
    row_width_(recent.gui_bytes_view == BYTES_HEX ? 16 : 8),
    one_em_(0),
    font_width_(0),
    line_spacing_(0),
    margin_(0)
{
    data_ = data;

    createContextMenu();

    setMouseTracking(true);

#ifdef Q_OS_MAC
    setAttribute(Qt::WA_MacShowFocusRect, true);
#endif
}

ByteViewText::~ByteViewText()
{
    ctx_menu_.clear();
}

void ByteViewText::createContextMenu()
{
    QActionGroup * format_actions_ = new QActionGroup(this);
    QAction *action;

    action = format_actions_->addAction(tr("Show bytes as hexadecimal"));
    action->setData(qVariantFromValue(BYTES_HEX));
    action->setCheckable(true);
    if (recent.gui_bytes_view == BYTES_HEX) {
        action->setChecked(true);
    }
    action = format_actions_->addAction(tr(UTF8_HORIZONTAL_ELLIPSIS "as bits"));
    action->setData(qVariantFromValue(BYTES_BITS));
    action->setCheckable(true);
    if (recent.gui_bytes_view == BYTES_BITS) {
        action->setChecked(true);
    }

    ctx_menu_.addActions(format_actions_->actions());
    connect(format_actions_, SIGNAL(triggered(QAction*)), this, SLOT(setHexDisplayFormat(QAction*)));

    ctx_menu_.addSeparator();

    QActionGroup * encoding_actions_ = new QActionGroup(this);
    action = encoding_actions_->addAction(tr(UTF8_HORIZONTAL_ELLIPSIS "as ASCII"));
    action->setData(qVariantFromValue(PACKET_CHAR_ENC_CHAR_ASCII));
    action->setCheckable(true);
    if (encoding_ == PACKET_CHAR_ENC_CHAR_ASCII) {
        action->setChecked(true);
    }
    action = encoding_actions_->addAction(tr(UTF8_HORIZONTAL_ELLIPSIS "as EBCDIC"));
    action->setData(qVariantFromValue(PACKET_CHAR_ENC_CHAR_EBCDIC));
    action->setCheckable(true);
    if (encoding_ == PACKET_CHAR_ENC_CHAR_EBCDIC) {
        action->setChecked(true);
    }

    ctx_menu_.addActions(encoding_actions_->actions());
    connect(encoding_actions_, SIGNAL(triggered(QAction*)), this, SLOT(setCharacterEncoding(QAction*)));
}

void ByteViewText::reset()
{
    data_.clear();
}

QByteArray ByteViewText::viewData()
{
    return data_;
}

void ByteViewText::setHighlightStyle(bool bold)
{
    bold_highlight_ = bold;
}

bool ByteViewText::isEmpty() const
{
    return data_.isEmpty();
}

QSize ByteViewText::minimumSizeHint() const
{
    // Allow panel to be shrinked to any size
    return QSize();
}

void ByteViewText::markProtocol(int start, int end)
{
    p_bound_ = QPair<guint, guint>(qMax(0, start), qMax(0, end));
    p_bound_save_ = p_bound_;
    viewport()->update();
}

void ByteViewText::markField(int start, int end)
{
    f_bound_ = QPair<guint, guint>(qMax(0, start), qMax(0, end));
    f_bound_save_ = f_bound_;
    viewport()->update();
}

void ByteViewText::moveToOffset(int pos)
{
    scrollToByte(pos);
    viewport()->update();
}


void ByteViewText::markAppendix(int start, int end)
{
    fa_bound_ = QPair<guint, guint>(qMax(0, start), qMax(0, end));
    fa_bound_save_ = f_bound_;
    viewport()->update();
}

void ByteViewText::setMonospaceFont(const QFont &mono_font)
{
    mono_font_ = mono_font;

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
    painter.setFont(font());

    // Pixel offset of this row
    int row_y = 0;

    // Starting byte offset
    guint offset = (guint) verticalScrollBar()->value() * row_width_;

    // Clear the area
    painter.fillRect(viewport()->rect(), palette().base());

    // Offset background
    offset_normal_fg_.setColor(ColorUtils::alphaBlend(palette().windowText(), palette().window(), 0.35));
    offset_field_fg_.setColor(ColorUtils::alphaBlend(palette().windowText(), palette().window(), 0.65));
    if (show_offset_) {
        QRect offset_rect = QRect(viewport()->rect());
        offset_rect.setWidth(offsetPixels());
        painter.fillRect(offset_rect, palette().window());
    }

    if ( data_.isEmpty() ) {
        return;
    }

    // Map window coordinates to byte offsets
    x_pos_to_column_.clear();
    for (guint i = 0; i < row_width_; i++) {
        int sep_width = (i / separator_interval_) * font_width_;
        if (show_hex_) {
            // Hittable pixels extend 1/2 space on either side of the hex digits
            int pixels_per_byte = (recent.gui_bytes_view == BYTES_HEX ? 3 : 9) * font_width_;
            int hex_x = offsetPixels() + margin_ + sep_width + (i * pixels_per_byte) - (font_width_ / 2);
            for (int j = 0; j <= pixels_per_byte; j++) {
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
    while( (int) (row_y + line_spacing_) < widget_height && (int) offset < (int) data_.count()) {
        drawOffsetLine(painter, offset, row_y);
        offset += row_width_;
        row_y += line_spacing_;
    }
    painter.restore();

    QStyleOptionFocusRect option;
    option.initFrom(this);
    style()->drawPrimitive(QStyle::PE_FrameFocusRect, &option, &painter, this);
}

void ByteViewText::resizeEvent(QResizeEvent *)
{
    updateScrollbars();
}

void ByteViewText::mousePressEvent (QMouseEvent *event) {
    if (isEmpty() || !event || event->button() != Qt::LeftButton) {
        return;
    }

    hovered_byte_lock_ = !hovered_byte_lock_;
    emit byteSelected(byteOffsetAtPixel(event->pos()));
}

void ByteViewText::mouseMoveEvent(QMouseEvent *event)
{
    if (hovered_byte_lock_) {
        return;
    }

    emit byteHovered(byteOffsetAtPixel(event->pos()));

    viewport()->update();
}

void ByteViewText::leaveEvent(QEvent *event)
{
    QString empty;
    emit byteHovered(-1);

    viewport()->update();
    QAbstractScrollArea::leaveEvent(event);
}

void ByteViewText::contextMenuEvent(QContextMenuEvent *event)
{
    ctx_menu_.exec(event->globalPos());
}

// Private

const int ByteViewText::separator_interval_ = 8; // Insert a space after this many bytes

// Draw a line of byte view text for a given offset.
// Text with different styles are split into fragments and passed to
// flushOffsetFragment. Font character widths aren't necessarily whole
// numbers so we track our X coordinate position using using floats.
void ByteViewText::drawOffsetLine(QPainter &painter, const guint offset, const int row_y)
{
    if (isEmpty()) {
        return;
    }
    guint tvb_len = data_.count();
    guint max_pos = qMin(offset + row_width_, tvb_len);

    static const guchar hexchars[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    QString text;
    HighlightMode hl_mode = ModeNormal, offset_mode = ModeOffsetNormal;
    qreal hex_x = offsetPixels() + margin_;
    qreal ascii_x = offsetPixels() + hexPixels() + margin_;

    // Hex
    if (show_hex_) {
        for (guint tvb_pos = offset; tvb_pos < max_pos; tvb_pos++) {
            HighlightMode hex_state = ModeNormal;
            bool add_space = tvb_pos != offset;
            bool draw_hover = tvb_pos == hovered_byte_offset_;

            if ((tvb_pos >= f_bound_.first && tvb_pos < f_bound_.second) || (tvb_pos >= fa_bound_.first && tvb_pos < fa_bound_.second)) {
                hex_state = ModeField;
                offset_mode = ModeOffsetField;
            } else if (tvb_pos >= p_bound_.first && tvb_pos < p_bound_.second) {
                hex_state = ModeProtocol;
            }

            if (hex_state != hl_mode || draw_hover) {
                if ((hl_mode == ModeNormal || (hl_mode == ModeProtocol && hex_state == ModeField) || draw_hover) && add_space) {
                    add_space = false;
                    text += ' ';
                    /* insert a space every separator_interval_ bytes */
                    if ((tvb_pos % separator_interval_) == 0)
                        text += ' ';
                }
                hex_x += flushOffsetFragment(painter, hex_x, row_y, hl_mode, text);
                hl_mode = hex_state;
            }

            if (add_space) {
                text += ' ';
                /* insert a space every separator_interval_ bytes */
                if ((tvb_pos % separator_interval_) == 0)
                    text += ' ';
            }

            switch (recent.gui_bytes_view) {
            case BYTES_HEX:
                text += hexchars[(data_[tvb_pos] & 0xf0) >> 4];
                text += hexchars[data_[tvb_pos] & 0x0f];
                break;
            case BYTES_BITS:
                /* XXX, bitmask */
                for (int j = 7; j >= 0; j--)
                    text += (data_[tvb_pos] & (1 << j)) ? '1' : '0';
                break;
            }
            if (draw_hover) {
                hex_x += flushOffsetFragment(painter, hex_x, row_y, ModeHover, text);
            }
        }
    }
    if (text.length() > 0) {
        flushOffsetFragment(painter, hex_x, row_y, hl_mode, text);
    }
    hl_mode = ModeNormal;

    // ASCII
    if (show_ascii_) {
        for (guint tvb_pos = offset; tvb_pos < max_pos; tvb_pos++) {
            HighlightMode ascii_state = ModeNormal;
            bool add_space = tvb_pos != offset;
            bool highlight_text = tvb_pos == hovered_byte_offset_;

            if ((tvb_pos >= f_bound_.first && tvb_pos < f_bound_.second) || (tvb_pos >= fa_bound_.first && tvb_pos < fa_bound_.second)) {
                ascii_state = ModeField;
                offset_mode = ModeOffsetField;
            } else if (tvb_pos >= p_bound_.first && tvb_pos < p_bound_.second) {
                ascii_state = ModeProtocol;
            }

            if (ascii_state != hl_mode || highlight_text) {
                if ((hl_mode == ModeNormal || (hl_mode == ModeProtocol && ascii_state == ModeField) || highlight_text) && add_space) {
                    add_space = false;
                    /* insert a space every separator_interval_ bytes */
                    if ((tvb_pos % separator_interval_) == 0)
                        text += ' ';
                }
                ascii_x += flushOffsetFragment(painter, ascii_x, row_y, hl_mode, text);
                hl_mode = ascii_state;
            }

            if (add_space) {
                /* insert a space every separator_interval_ bytes */
                if ((tvb_pos % separator_interval_) == 0)
                    text += ' ';
            }

            guchar c = (encoding_ == PACKET_CHAR_ENC_CHAR_EBCDIC) ?
                        EBCDIC_to_ASCII1(data_[tvb_pos]) :
                        data_[tvb_pos];

            text += g_ascii_isprint(c) ? c : '.';
            if (highlight_text) {
                ascii_x += flushOffsetFragment(painter, ascii_x, row_y, ModeHover, text);
            }
        }
    }
    if (text.length() > 0) {
        flushOffsetFragment(painter, ascii_x, row_y, hl_mode, text);
    }

    // Offset. Must be drawn last in order for offset_state to be set.
    if (show_offset_) {
        text = QString("%1").arg(offset, offsetChars(), 16, QChar('0'));
        flushOffsetFragment(painter, margin_, row_y, offset_mode, text);
    }
}

// Draws a fragment of byte view text at the specifiec location using colors
// for the specified state. Clears the text and returns the pixel width of the
// drawn text.
qreal ByteViewText::flushOffsetFragment(QPainter &painter, qreal x, int y, HighlightMode mode, QString &text)
{
    if (text.length() < 1) {
        return 0;
    }
    QFontMetricsF fm(mono_font_);
    qreal width = fm.width(text);
    QRectF area(x, y, width, line_spacing_);
    // Background
    switch (mode) {
    case ModeField:
        painter.fillRect(area, palette().highlight());
        break;
    case ModeProtocol:
        painter.fillRect(area, palette().window());
        break;
    case ModeHover:
        painter.fillRect(area, ColorUtils::byteViewHoverColor(true));
        break;
    default:
        break;
    }

    // Text
    QBrush text_brush;
    switch (mode) {
    case ModeNormal:
    case ModeProtocol:
    default:
        text_brush = palette().windowText();
        break;
    case ModeField:
        text_brush = palette().highlightedText();
        break;
    case ModeOffsetNormal:
        text_brush = offset_normal_fg_;
        break;
    case ModeOffsetField:
        text_brush = offset_field_fg_;
        break;
    case ModeHover:
        text_brush = ColorUtils::byteViewHoverColor(false);
        break;
    }

    painter.setPen(QPen(text_brush.color()));
    painter.drawText(area, Qt::AlignTop, text);
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
    if (! isEmpty() && data_.count() > 0xffff) {
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
        int digits_per_byte = recent.gui_bytes_view == BYTES_HEX ? 3 : 9;
        return (((row_width_ * digits_per_byte) + ((row_width_ - 1) / separator_interval_)) * font_width_) + one_em_;
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
    const int length = data_.count();
    if (length > 0) {
        qint64 maxval = length / row_width_ + ((length % row_width_) ? 1 : 0) - viewport()->height() / line_spacing_;

        verticalScrollBar()->setRange(0, int(qMax((qint64)0, maxval)));
        horizontalScrollBar()->setRange(0, qMax(0, static_cast<int>((totalPixels() - viewport()->width()) / font_width_)));
    }
}

int ByteViewText::byteOffsetAtPixel(QPoint pos)
{
    int byte = (verticalScrollBar()->value() + (pos.y() / line_spacing_)) * row_width_;
    int x = (horizontalScrollBar()->value() * font_width_) + pos.x();
    int col = x_pos_to_column_.value(x, -1);

    if (col < 0) {
        return -1;
    }

    byte += col;
    if (byte > data_.count()) {
        return -1;
    }
    return byte;
}

void ByteViewText::setHexDisplayFormat(QAction *action)
{
    if (!action) {
        return;
    }

    recent.gui_bytes_view = action->data().value<bytes_view_type>();
    row_width_ = recent.gui_bytes_view == BYTES_HEX ? 16 : 8;
    updateScrollbars();
    viewport()->update();
}

void ByteViewText::setCharacterEncoding(QAction *action)
{
    if (!action) {
        return;
    }

    encoding_ = action->data().value<packet_char_enc>();
    viewport()->update();
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
