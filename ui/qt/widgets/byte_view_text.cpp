/* byte_view_text.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// Some code based on QHexView by Evan Teran
// https://github.com/eteran/qhexview/

#include "byte_view_text.h"

#include <epan/charsets.h>

#include <wsutil/utf8_entities.h>

#include <ui/qt/utils/color_utils.h>
#include "main_application.h"
#include "ui/recent.h"

#include <QActionGroup>
#include <QMouseEvent>
#include <QPainter>
#include <QScrollBar>
#include <QStyle>
#include <QStyleOption>
#include <QTextLayout>

// To do:
// - Add recent settings and context menu items to show/hide the offset.
// - Add a UTF-8 and possibly UTF-xx option to the ASCII display.
// - Move more common metrics to DataPrinter.
// - Pre-draw all of our characters and paint our display using pixmap
//   copying? That would make this behave like a terminal screen, which
//   is what we ultimately want.

Q_DECLARE_METATYPE(bytes_view_type)
Q_DECLARE_METATYPE(bytes_encoding_type)
Q_DECLARE_METATYPE(DataPrinter::DumpType)

ByteViewText::ByteViewText(const QByteArray &data, packet_char_enc encoding, QWidget *parent) :
    QAbstractScrollArea(parent),
    layout_(new QTextLayout()),
    data_(data),
    encoding_(encoding),
    hovered_byte_offset_(-1),
    marked_byte_offset_(-1),
    proto_start_(0),
    proto_len_(0),
    field_start_(0),
    field_len_(0),
    field_a_start_(0),
    field_a_len_(0),
    show_offset_(true),
    show_hex_(true),
    show_ascii_(true),
    row_width_(recent.gui_bytes_view == BYTES_HEX ? 16 : 8),
    font_width_(0),
    line_height_(0),
    allow_hover_selection_(false)
{
    layout_->setCacheEnabled(true);

    offset_normal_fg_ = ColorUtils::alphaBlend(palette().windowText(), palette().window(), 0.35);
    offset_field_fg_ = ColorUtils::alphaBlend(palette().windowText(), palette().window(), 0.65);

    createContextMenu();

    setMouseTracking(true);

#ifdef Q_OS_MAC
    setAttribute(Qt::WA_MacShowFocusRect, true);
#endif
}

ByteViewText::~ByteViewText()
{
    ctx_menu_.clear();
    delete(layout_);
}

void ByteViewText::createContextMenu()
{

    action_allow_hover_selection_ = ctx_menu_.addAction(tr("Allow hover highlighting"));
    action_allow_hover_selection_->setCheckable(true);
    action_allow_hover_selection_->setChecked(true);
    connect(action_allow_hover_selection_, &QAction::toggled, this, &ByteViewText::toggleHoverAllowed);
    ctx_menu_.addSeparator();

    QActionGroup * copy_actions = DataPrinter::copyActions(this);
    ctx_menu_.addActions(copy_actions->actions());
    ctx_menu_.addSeparator();

    QActionGroup * format_actions = new QActionGroup(this);
    action_bytes_hex_ = format_actions->addAction(tr("Show bytes as hexadecimal"));
    action_bytes_hex_->setData(QVariant::fromValue(BYTES_HEX));
    action_bytes_hex_->setCheckable(true);

    action_bytes_bits_ = format_actions->addAction(tr("…as bits"));
    action_bytes_bits_->setData(QVariant::fromValue(BYTES_BITS));
    action_bytes_bits_->setCheckable(true);

    ctx_menu_.addActions(format_actions->actions());
    connect(format_actions, &QActionGroup::triggered, this, &ByteViewText::setHexDisplayFormat);

    ctx_menu_.addSeparator();

    QActionGroup * encoding_actions = new QActionGroup(this);
    action_bytes_enc_from_packet_ = encoding_actions->addAction(tr("Show text based on packet"));
    action_bytes_enc_from_packet_->setData(QVariant::fromValue(BYTES_ENC_FROM_PACKET));
    action_bytes_enc_from_packet_->setCheckable(true);

    action_bytes_enc_ascii_ = encoding_actions->addAction(tr("…as ASCII"));
    action_bytes_enc_ascii_->setData(QVariant::fromValue(BYTES_ENC_ASCII));
    action_bytes_enc_ascii_->setCheckable(true);

    action_bytes_enc_ebcdic_ = encoding_actions->addAction(tr("…as EBCDIC"));
    action_bytes_enc_ebcdic_->setData(QVariant::fromValue(BYTES_ENC_EBCDIC));
    action_bytes_enc_ebcdic_->setCheckable(true);

    updateContextMenu();

    ctx_menu_.addActions(encoding_actions->actions());
    connect(encoding_actions, &QActionGroup::triggered, this, &ByteViewText::setCharacterEncoding);
}

void ByteViewText::toggleHoverAllowed(bool checked)
{
    allow_hover_selection_ = ! checked;
    recent.gui_allow_hover_selection = checked;
}

void ByteViewText::updateContextMenu()
{

    action_allow_hover_selection_->setChecked(recent.gui_allow_hover_selection);

    switch (recent.gui_bytes_view) {
    case BYTES_HEX:
        action_bytes_hex_->setChecked(true);
        break;
    case BYTES_BITS:
        action_bytes_bits_->setChecked(true);
        break;
    }

    switch (recent.gui_bytes_encoding) {
    case BYTES_ENC_FROM_PACKET:
        action_bytes_enc_from_packet_->setChecked(true);
        break;
    case BYTES_ENC_ASCII:
        action_bytes_enc_ascii_->setChecked(true);
        break;
    case BYTES_ENC_EBCDIC:
        action_bytes_enc_ebcdic_->setChecked(true);
        break;
    }
}

bool ByteViewText::isEmpty() const
{
    return data_.isEmpty();
}

QSize ByteViewText::minimumSizeHint() const
{
    // Allow panel to shrink to any size
    return QSize();
}

void ByteViewText::markProtocol(int start, int length)
{
    proto_start_ = start;
    proto_len_ = length;
    viewport()->update();
}

void ByteViewText::markField(int start, int length, bool scroll_to)
{
    field_start_ = start;
    field_len_ = length;
    // This might be called as a result of (de)selecting a proto tree
    // item, so take us out of marked mode.
    marked_byte_offset_ = -1;
    if (scroll_to) {
        scrollToByte(start);
    }
    viewport()->update();
}

void ByteViewText::markAppendix(int start, int length)
{
    field_a_start_ = start;
    field_a_len_ = length;
    viewport()->update();
}

void ByteViewText::setMonospaceFont(const QFont &mono_font)
{
    QFont int_font(mono_font);

    setFont(int_font);
    viewport()->setFont(int_font);
    layout_->setFont(int_font);

    updateLayoutMetrics();

    updateScrollbars();
    viewport()->update();
}

void ByteViewText::updateByteViewSettings()
{
    row_width_ = recent.gui_bytes_view == BYTES_HEX ? 16 : 8;

    updateContextMenu();
    updateScrollbars();
    viewport()->update();
}

void ByteViewText::paintEvent(QPaintEvent *)
{
    updateLayoutMetrics();

    QPainter painter(viewport());
    painter.translate(-horizontalScrollBar()->value() * font_width_, 0);

    // Pixel offset of this row
    int row_y = 0;

    // Starting byte offset
    int offset = verticalScrollBar()->value() * row_width_;

    // Clear the area
    painter.fillRect(viewport()->rect(), palette().base());

    // Offset background. We want the entire height to be filled.
    if (show_offset_) {
        QRect offset_rect = QRect(viewport()->rect());
        offset_rect.setWidth(offsetPixels());
        painter.fillRect(offset_rect, palette().window());
    }

    if (data_.isEmpty()) {
        return;
    }

    // Data rows
    int widget_height = height();
    int leading = fontMetrics().leading();
    painter.save();

    x_pos_to_column_.clear();
    while ((int) (row_y + line_height_) < widget_height && offset < (int) data_.count()) {
        drawLine(&painter, offset, row_y);
        offset += row_width_;
        row_y += line_height_ + leading;
    }

    painter.restore();

    // We can't do this in drawLine since the next line might draw over our rect.
    // This looks best when our highlight and background have similar lightnesses.
    // We might want to set a composition mode when that's not the case.
    if (!hover_outlines_.isEmpty()) {
        qreal pen_width = 1.0;
        qreal hover_alpha = 0.6;
        QPen ho_pen;
        QColor ho_color = palette().text().color();
        if (marked_byte_offset_ < 0) {
            hover_alpha = 0.3;
            if (devicePixelRatio() > 1) {
                pen_width = 0.5;
            }
        }
        ho_pen.setWidthF(pen_width);
        ho_color.setAlphaF(hover_alpha);
        ho_pen.setColor(ho_color);

        painter.save();
        painter.setPen(ho_pen);
        painter.setBrush(Qt::NoBrush);
        foreach (QRect ho_rect, hover_outlines_) {
            // These look good on retina and non-retina displays on macOS.
            // We might want to use fontMetrics numbers instead.
            ho_rect.adjust(-1, 0, -1, -1);
            painter.drawRect(ho_rect);
        }
        painter.restore();
    }
    hover_outlines_.clear();

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

    // byteSelected does the following:
    // - Triggers selectedFieldChanged in ProtoTree, which clears the
    //   selection and selects the corresponding (or no) item.
    // - The new tree selection triggers markField, which clobbers
    //   marked_byte_offset_.

    const bool hover_mode = marked_byte_offset_ < 0;
    const int byte_offset = byteOffsetAtPixel(event->pos());
    setUpdatesEnabled(false);
    emit byteSelected(byte_offset);
    if (hover_mode && byte_offset >= 0) {
        // Switch to marked mode.
        hovered_byte_offset_ = -1;
        marked_byte_offset_ = byte_offset;
        viewport()->update();
    } else {
        // Back to hover mode.
        mouseMoveEvent(event);
    }
    setUpdatesEnabled(true);
}

void ByteViewText::mouseMoveEvent(QMouseEvent *event)
{
    if (marked_byte_offset_ >= 0 || allow_hover_selection_ ||
        (!allow_hover_selection_ && event->modifiers() & Qt::ControlModifier)) {
        return;
    }

    hovered_byte_offset_ = byteOffsetAtPixel(event->pos());
    emit byteHovered(hovered_byte_offset_);
    viewport()->update();
}

void ByteViewText::leaveEvent(QEvent *event)
{
    hovered_byte_offset_ = -1;
    emit byteHovered(hovered_byte_offset_);

    viewport()->update();
    QAbstractScrollArea::leaveEvent(event);
}

void ByteViewText::contextMenuEvent(QContextMenuEvent *event)
{
    ctx_menu_.popup(event->globalPos());
}

// Private

const int ByteViewText::separator_interval_ = DataPrinter::separatorInterval();

void ByteViewText::updateLayoutMetrics()
{
    font_width_  = stringWidth("M");
    // We might want to match ProtoTree::rowHeight.
    line_height_ = fontMetrics().height();
}

int ByteViewText::stringWidth(const QString &line)
{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 11, 0))
    return fontMetrics().horizontalAdvance(line);
#else
    return fontMetrics().boundingRect(line).width();
#endif
}

// Draw a line of byte view text for a given offset.
// Text highlighting is handled using QTextLayout::FormatRange.
void ByteViewText::drawLine(QPainter *painter, const int offset, const int row_y)
{
    if (isEmpty()) {
        return;
    }

    // Build our pixel to byte offset vector the first time through.
    bool build_x_pos = x_pos_to_column_.empty() ? true : false;
    int tvb_len = static_cast<int>(data_.count());
    int max_tvb_pos = qMin(offset + row_width_, tvb_len) - 1;
    QList<QTextLayout::FormatRange> fmt_list;

    static const char hexchars[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    QString line;
    HighlightMode offset_mode = ModeOffsetNormal;

    // Offset.
    if (show_offset_) {
        line = QString(" %1 ").arg(offset, offsetChars(false), 16, QChar('0'));
        if (build_x_pos) {
            x_pos_to_column_.fill(-1, stringWidth(line));
        }
    }

    // Hex
    if (show_hex_) {
        int ascii_start = static_cast<int>(line.length()) + DataPrinter::hexChars() + 3;
        // Extra hover space before and after each byte.
        int slop = font_width_ / 2;

        if (build_x_pos) {
            x_pos_to_column_ += QVector<int>().fill(-1, slop);
        }

        for (int tvb_pos = offset; tvb_pos <= max_tvb_pos; tvb_pos++) {
            line += ' ';
            /* insert a space every separator_interval_ bytes */
            if ((tvb_pos != offset) && ((tvb_pos % separator_interval_) == 0)) {
                line += ' ';
                x_pos_to_column_ += QVector<int>().fill(tvb_pos - offset - 1, font_width_);
            }

            switch (recent.gui_bytes_view) {
            case BYTES_HEX:
                line += hexchars[(data_[tvb_pos] & 0xf0) >> 4];
                line += hexchars[data_[tvb_pos] & 0x0f];
                break;
            case BYTES_BITS:
                /* XXX, bitmask */
                for (int j = 7; j >= 0; j--) {
                    line += (data_[tvb_pos] & (1 << j)) ? '1' : '0';
                }
                break;
            }
            if (build_x_pos) {
                x_pos_to_column_ += QVector<int>().fill(tvb_pos - offset, stringWidth(line) - x_pos_to_column_.size() + slop);
            }
            if (tvb_pos == hovered_byte_offset_ || tvb_pos == marked_byte_offset_) {
                int ho_len = recent.gui_bytes_view == BYTES_HEX ? 2 : 8;
                QRect ho_rect = painter->boundingRect(QRect(), Qt::AlignHCenter|Qt::AlignVCenter, line.right(ho_len));
                ho_rect.moveRight(stringWidth(line));
                ho_rect.moveTop(row_y);
                hover_outlines_.append(ho_rect);
            }
        }
        line += QString(ascii_start - line.length(), ' ');
        if (build_x_pos) {
            x_pos_to_column_ += QVector<int>().fill(-1, stringWidth(line) - x_pos_to_column_.size());
        }

        addHexFormatRange(fmt_list, proto_start_, proto_len_, offset, max_tvb_pos, ModeProtocol);
        if (addHexFormatRange(fmt_list, field_start_, field_len_, offset, max_tvb_pos, ModeField)) {
            offset_mode = ModeOffsetField;
        }
        addHexFormatRange(fmt_list, field_a_start_, field_a_len_, offset, max_tvb_pos, ModeField);
    }

    // ASCII
    if (show_ascii_) {
        bool in_non_printable = false;
        int np_start = 0;
        int np_len = 0;
        char c;

        for (int tvb_pos = offset; tvb_pos <= max_tvb_pos; tvb_pos++) {
            /* insert a space every separator_interval_ bytes */
            if ((tvb_pos != offset) && ((tvb_pos % separator_interval_) == 0)) {
                line += ' ';
                if (build_x_pos) {
                    x_pos_to_column_ += QVector<int>().fill(tvb_pos - offset - 1, font_width_ / 2);
                }
            }

            if (recent.gui_bytes_encoding != BYTES_ENC_EBCDIC && encoding_ == PACKET_CHAR_ENC_CHAR_ASCII) {
                c = data_[tvb_pos];
            } else {
                c = EBCDIC_to_ASCII1(data_[tvb_pos]);
            }

            if (g_ascii_isprint(c)) {
                line += c;
                if (in_non_printable) {
                    in_non_printable = false;
                    addAsciiFormatRange(fmt_list, np_start, np_len, offset, max_tvb_pos, ModeNonPrintable);
                }
            } else {
                line += UTF8_MIDDLE_DOT;
                if (!in_non_printable) {
                    in_non_printable = true;
                    np_start = tvb_pos;
                    np_len = 1;
                } else {
                    np_len++;
                }
            }
            if (build_x_pos) {
                x_pos_to_column_ += QVector<int>().fill(tvb_pos - offset, stringWidth(line) - x_pos_to_column_.size());
            }
            if (tvb_pos == hovered_byte_offset_ || tvb_pos == marked_byte_offset_) {
                QRect ho_rect = painter->boundingRect(QRect(), 0, line.right(1));
                ho_rect.moveRight(stringWidth(line));
                ho_rect.moveTop(row_y);
                hover_outlines_.append(ho_rect);
            }
        }
        if (in_non_printable) {
            addAsciiFormatRange(fmt_list, np_start, np_len, offset, max_tvb_pos, ModeNonPrintable);
        }
        addAsciiFormatRange(fmt_list, proto_start_, proto_len_, offset, max_tvb_pos, ModeProtocol);
        if (addAsciiFormatRange(fmt_list, field_start_, field_len_, offset, max_tvb_pos, ModeField)) {
            offset_mode = ModeOffsetField;
        }
        addAsciiFormatRange(fmt_list, field_a_start_, field_a_len_, offset, max_tvb_pos, ModeField);
    }

    // XXX Fields won't be highlighted if neither hex nor ascii are enabled.
    addFormatRange(fmt_list, 0, offsetChars(), offset_mode);

    layout_->clearLayout();
    layout_->clearFormats();
    layout_->setText(line);
    layout_->setFormats(fmt_list.toVector());
    layout_->beginLayout();
    QTextLine tl = layout_->createLine();
    tl.setLineWidth(totalPixels());
    tl.setLeadingIncluded(true);
    layout_->endLayout();
    layout_->draw(painter, QPointF(0.0, row_y));
}

bool ByteViewText::addFormatRange(QList<QTextLayout::FormatRange> &fmt_list, int start, int length, HighlightMode mode)
{
    if (length < 1)
        return false;

    QTextLayout::FormatRange format_range;
    format_range.start = start;
    format_range.length = length;
    switch (mode) {
    case ModeNormal:
        return false;
    case ModeField:
        format_range.format.setBackground(palette().highlight());
        format_range.format.setForeground(palette().highlightedText());
        break;
    case ModeProtocol:
        format_range.format.setBackground(palette().window());
        format_range.format.setForeground(palette().windowText());
        break;
    case ModeOffsetNormal:
        format_range.format.setForeground(offset_normal_fg_);
        break;
    case ModeOffsetField:
        format_range.format.setForeground(offset_field_fg_);
        break;
    case ModeNonPrintable:
        format_range.format.setForeground(offset_normal_fg_);
        break;
    }
    fmt_list << format_range;
    return true;
}

bool ByteViewText::addHexFormatRange(QList<QTextLayout::FormatRange> &fmt_list, int mark_start, int mark_length, int tvb_offset, int max_tvb_pos, ByteViewText::HighlightMode mode)
{
    int mark_end = mark_start + mark_length - 1;
    if (mark_start < 0 || mark_length < 1) return false;
    if (mark_start > max_tvb_pos && mark_end < tvb_offset) return false;

    int chars_per_byte = recent.gui_bytes_view == BYTES_HEX ? 2 : 8;
    int chars_plus_pad = chars_per_byte + 1;
    int byte_start = qMax(tvb_offset, mark_start) - tvb_offset;
    int byte_end = qMin(max_tvb_pos, mark_end) - tvb_offset;
    int fmt_start = offsetChars() + 1 // offset + spacing
            + (byte_start / separator_interval_)
            + (byte_start * chars_plus_pad);
    int fmt_length = offsetChars() + 1 // offset + spacing
            + (byte_end / separator_interval_)
            + (byte_end * chars_plus_pad)
            + chars_per_byte
            - fmt_start;
    return addFormatRange(fmt_list, fmt_start, fmt_length, mode);
}

bool ByteViewText::addAsciiFormatRange(QList<QTextLayout::FormatRange> &fmt_list, int mark_start, int mark_length, int tvb_offset, int max_tvb_pos, ByteViewText::HighlightMode mode)
{
    int mark_end = mark_start + mark_length - 1;
    if (mark_start < 0 || mark_length < 1) return false;
    if (mark_start > max_tvb_pos && mark_end < tvb_offset) return false;

    int byte_start = qMax(tvb_offset, mark_start) - tvb_offset;
    int byte_end = qMin(max_tvb_pos, mark_end) - tvb_offset;
    int fmt_start = offsetChars() + DataPrinter::hexChars() + 3 // offset + hex + spacing
            + (byte_start / separator_interval_)
            + byte_start;
    int fmt_length = offsetChars() + DataPrinter::hexChars() + 3 // offset + hex + spacing
            + (byte_end / separator_interval_)
            + byte_end
            + 1 // Just one character.
            - fmt_start;
    return addFormatRange(fmt_list, fmt_start, fmt_length, mode);
}

void ByteViewText::scrollToByte(int byte)
{
    verticalScrollBar()->setValue(byte / row_width_);
}

// Offset character width
int ByteViewText::offsetChars(bool include_pad)
{
    int padding = include_pad ? 2 : 0;
    if (! isEmpty() && data_.count() > 0xffff) {
        return 8 + padding;
    }
    return 4 + padding;
}

// Offset pixel width
int ByteViewText::offsetPixels()
{
    if (show_offset_) {
        // One pad space before and after
        QString zeroes = QString(offsetChars(), '0');
        return stringWidth(zeroes);
    }
    return 0;
}

// Hex pixel width
int ByteViewText::hexPixels()
{
    if (show_hex_) {
        // One pad space before and after
        QString zeroes = QString(DataPrinter::hexChars() + 2, '0');
        return stringWidth(zeroes);
    }
    return 0;
}

int ByteViewText::asciiPixels()
{
    if (show_ascii_) {
        // Two pad spaces before, one after
        int ascii_chars = (row_width_ + ((row_width_ - 1) / separator_interval_));
        QString zeroes = QString(ascii_chars + 3, '0');
        return stringWidth(zeroes);
    }
    return 0;
}

int ByteViewText::totalPixels()
{
    return offsetPixels() + hexPixels() + asciiPixels();
}

void ByteViewText::copyBytes(bool)
{
    QAction* action = qobject_cast<QAction*>(sender());
    if (!action) {
        return;
    }

    int dump_type = action->data().toInt();

    if (dump_type <= DataPrinter::DP_Binary) {
        DataPrinter printer;
        printer.toClipboard((DataPrinter::DumpType) dump_type, this);
    }
}

// We do chunky (per-character) scrolling because it makes some of the
// math easier. Should we do smooth scrolling?
void ByteViewText::updateScrollbars()
{
    const int length = static_cast<int>(data_.count());
    if (length > 0) {
        int all_lines_height = length / row_width_ + ((length % row_width_) ? 1 : 0) - viewport()->height() / line_height_;

        verticalScrollBar()->setRange(0, qMax(0, all_lines_height));
        horizontalScrollBar()->setRange(0, qMax(0, int((totalPixels() - viewport()->width()) / font_width_)));
    }
}

int ByteViewText::byteOffsetAtPixel(QPoint pos)
{
    int byte = (verticalScrollBar()->value() + (pos.y() / line_height_)) * row_width_;
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

    emit byteViewSettingsChanged();
}

void ByteViewText::setCharacterEncoding(QAction *action)
{
    if (!action) {
        return;
    }

    recent.gui_bytes_encoding = action->data().value<bytes_encoding_type>();

    emit byteViewSettingsChanged();
}
