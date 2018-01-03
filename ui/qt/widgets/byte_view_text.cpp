/* byte_view_text.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "byte_view_text.h"

#include <epan/charsets.h>

#include <wsutil/utf8_entities.h>

#include <ui/qt/utils/color_utils.h>
#include "wireshark_application.h"
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
    line_height_(0)
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
    QAction *action;

    QActionGroup * copy_actions = DataPrinter::copyActions(this);
    ctx_menu_.addActions(copy_actions->actions());
    ctx_menu_.addSeparator();

    QActionGroup * format_actions = new QActionGroup(this);
    action = format_actions->addAction(tr("Show bytes as hexadecimal"));
    action->setData(qVariantFromValue(BYTES_HEX));
    action->setCheckable(true);
    if (recent.gui_bytes_view == BYTES_HEX) {
        action->setChecked(true);
    }
    action = format_actions->addAction(tr(UTF8_HORIZONTAL_ELLIPSIS "as bits"));
    action->setData(qVariantFromValue(BYTES_BITS));
    action->setCheckable(true);
    if (recent.gui_bytes_view == BYTES_BITS) {
        action->setChecked(true);
    }

    ctx_menu_.addActions(format_actions->actions());
    connect(format_actions, SIGNAL(triggered(QAction*)), this, SLOT(setHexDisplayFormat(QAction*)));

    ctx_menu_.addSeparator();

    QActionGroup * encoding_actions = new QActionGroup(this);
    action = encoding_actions->addAction(tr("Show text based on packet"));
    action->setData(qVariantFromValue(BYTES_ENC_FROM_PACKET));
    action->setCheckable(true);
    if (recent.gui_bytes_encoding == BYTES_ENC_FROM_PACKET) {
        action->setChecked(true);
    }
    action = encoding_actions->addAction(tr(UTF8_HORIZONTAL_ELLIPSIS "as ASCII"));
    action->setData(qVariantFromValue(BYTES_ENC_ASCII));
    action->setCheckable(true);
    if (recent.gui_bytes_encoding == BYTES_ENC_ASCII) {
        action->setChecked(true);
    }
    action = encoding_actions->addAction(tr(UTF8_HORIZONTAL_ELLIPSIS "as EBCDIC"));
    action->setData(qVariantFromValue(BYTES_ENC_EBCDIC));
    action->setCheckable(true);
    if (recent.gui_bytes_encoding == BYTES_ENC_EBCDIC) {
        action->setChecked(true);
    }

    ctx_menu_.addActions(encoding_actions->actions());
    connect(encoding_actions, SIGNAL(triggered(QAction*)), this, SLOT(setCharacterEncoding(QAction*)));
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

void ByteViewText::markField(int start, int length)
{
    field_start_ = start;
    field_len_ = length;
    scrollToByte(start);
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
    mono_font_ = mono_font;

    const QFontMetricsF fm(mono_font);
    font_width_  = fm.width('M');

    setFont(mono_font);
    layout_->setFont(mono_font);

    // We should probably use ProtoTree::rowHeight.
    line_height_ = fontMetrics().height();

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
    int offset = verticalScrollBar()->value() * row_width_;

    // Clear the area
    painter.fillRect(viewport()->rect(), palette().base());

    // Offset background. We want the entire height to be filled.
    if (show_offset_) {
        QRect offset_rect = QRect(viewport()->rect());
        offset_rect.setWidth(offsetPixels());
        painter.fillRect(offset_rect, palette().window());
    }

    if ( data_.isEmpty() ) {
        return;
    }

    // Data rows
    int widget_height = height();
    painter.save();

    x_pos_to_column_.clear();
    while( (int) (row_y + line_height_) < widget_height && offset < (int) data_.count()) {
        drawLine(&painter, offset, row_y);
        offset += row_width_;
        row_y += line_height_;
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

    if (marked_byte_offset_ < 0) {
        marked_byte_offset_ = byteOffsetAtPixel(event->pos());
        hovered_byte_offset_ = -1;
    } else {
        marked_byte_offset_ = -1;
        mouseMoveEvent(event);
    }
    emit byteSelected(marked_byte_offset_);
}

void ByteViewText::mouseMoveEvent(QMouseEvent *event)
{
    if (marked_byte_offset_ >= 0) {
        return;
    }

    hovered_byte_offset_ = byteOffsetAtPixel(event->pos());
    emit byteHovered(hovered_byte_offset_);

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

const int ByteViewText::separator_interval_ = DataPrinter::separatorInterval();

// Draw a line of byte view text for a given offset.
// Text highlighting is handled using QTextLayout::FormatRange.
void ByteViewText::drawLine(QPainter *painter, const int offset, const int row_y)
{
    if (isEmpty()) {
        return;
    }

    // Build our pixel to byte offset vector the first time through.
    bool build_x_pos = x_pos_to_column_.empty() ? true : false;
    int tvb_len = data_.count();
    int max_tvb_pos = qMin(offset + row_width_, tvb_len) - 1;
    QList<QTextLayout::FormatRange> fmt_list;

    static const guchar hexchars[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    QString line;
    HighlightMode offset_mode = ModeOffsetNormal;

    // Offset.
    if (show_offset_) {
        line = QString(" %1 ").arg(offset, offsetChars(false), 16, QChar('0'));
        if (build_x_pos) {
            x_pos_to_column_.fill(-1, fontMetrics().width(line));
        }
    }

    // Hex
    if (show_hex_) {
        int ascii_start = line.length() + DataPrinter::hexChars() + 3;
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
                x_pos_to_column_ += QVector<int>().fill(tvb_pos - offset, fontMetrics().width(line) - x_pos_to_column_.size() + slop);
            }
        }
        line += QString(ascii_start - line.length(), ' ');
        if (build_x_pos) {
            x_pos_to_column_ += QVector<int>().fill(-1, fontMetrics().width(line) - x_pos_to_column_.size());
        }

        addHexFormatRange(fmt_list, proto_start_, proto_len_, offset, max_tvb_pos, ModeProtocol);
        if (addHexFormatRange(fmt_list, field_start_, field_len_, offset, max_tvb_pos, ModeField)) {
            offset_mode = ModeOffsetField;
        }
        addHexFormatRange(fmt_list, field_a_start_, field_a_len_, offset, max_tvb_pos, ModeField);
        if (marked_byte_offset_ >= offset && marked_byte_offset_ <= max_tvb_pos) {
            addHexFormatRange(fmt_list, marked_byte_offset_, 1, offset, max_tvb_pos, ModeMarked);
        }
        if (hovered_byte_offset_ >= offset && hovered_byte_offset_ <= max_tvb_pos) {
            addHexFormatRange(fmt_list, hovered_byte_offset_, 1, offset, max_tvb_pos, ModeHover);
        }
    }

    // ASCII
    if (show_ascii_) {
        bool in_non_printable = false;
        int np_start = 0;
        int np_len = 0;
        guchar c;

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
                x_pos_to_column_ += QVector<int>().fill(tvb_pos - offset, fontMetrics().width(line) - x_pos_to_column_.size());
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
        if (marked_byte_offset_ >= offset && marked_byte_offset_ <= max_tvb_pos) {
            addAsciiFormatRange(fmt_list, marked_byte_offset_, 1, offset, max_tvb_pos, ModeMarked);
        }
        if (hovered_byte_offset_ >= offset && hovered_byte_offset_ <= max_tvb_pos) {
            addAsciiFormatRange(fmt_list, hovered_byte_offset_, 1, offset, max_tvb_pos, ModeHover);
        }
    }

    // XXX Fields won't be highlighted if neither hex nor ascii are enabled.
    addFormatRange(fmt_list, 0, offsetChars(), offset_mode);

    layout_->clearLayout();
    layout_->clearAdditionalFormats();
    layout_->setText(line);
    layout_->setAdditionalFormats(fmt_list);
    layout_->beginLayout();
    QTextLine tl = layout_->createLine();
    tl.setLineWidth(totalPixels());
    tl.setPosition(QPointF(0.0, 0.0));
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
    format_range.format.setProperty(QTextFormat::LineHeight, line_height_);
    switch (mode) {
    case ModeNormal:
        return false;
    case ModeField:
        format_range.format.setBackground(palette().highlight());
        break;
    case ModeProtocol:
        format_range.format.setBackground(palette().window());
        break;
    case ModeOffsetNormal:
        format_range.format.setForeground(offset_normal_fg_);
        break;
    case ModeOffsetField:
        format_range.format.setForeground(offset_field_fg_);
        break;
    case ModeHover:
        // QTextCharFormat doesn't appear to let us draw a complete border.
        // This is the next best thing.
        format_range.format.setFontUnderline(true);
        format_range.format.setFontOverline(true);
        break;
    case ModeMarked:
        // XXX Should we get rid of byteViewMarkColor and just draw an
        // overline + underline instead?
        format_range.format.setForeground(ColorUtils::byteViewMarkColor(false));
        format_range.format.setBackground(ColorUtils::byteViewMarkColor(true));
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

    int chars_per_byte = recent.gui_bytes_view == BYTES_HEX ? 3 : 9;
    int byte_start = qMax(tvb_offset, mark_start) - tvb_offset;
    int byte_end = qMin(max_tvb_pos, mark_end) - tvb_offset;
    int fmt_start = offsetChars() + 1 // offset + spacing
            + (byte_start / separator_interval_)
            + (byte_start * chars_per_byte);
    int fmt_length = offsetChars() + 1 // offset + spacing
            + (byte_end / separator_interval_)
            + (byte_end * chars_per_byte)
            + 2 // Both the high and low nibbles.
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
        return fontMetrics().width(zeroes);
    }
    return 0;
}

// Hex pixel width
int ByteViewText::hexPixels()
{
    if (show_hex_) {
        // One pad space before and after
        QString zeroes = QString(DataPrinter::hexChars() + 2, '0');
        return fontMetrics().width(zeroes);
    }
    return 0;
}

int ByteViewText::asciiPixels()
{
    if (show_ascii_) {
        // Two pad spaces before, one after
        int ascii_chars = (row_width_ + ((row_width_ - 1) / separator_interval_));
        QString zeroes = QString(ascii_chars + 3, '0');
        return fontMetrics().width(zeroes);
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
    const int length = data_.count();
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
    row_width_ = recent.gui_bytes_view == BYTES_HEX ? 16 : 8;
    updateScrollbars();
    viewport()->update();
}

void ByteViewText::setCharacterEncoding(QAction *action)
{
    if (!action) {
        return;
    }

    recent.gui_bytes_encoding = action->data().value<bytes_encoding_type>();
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
