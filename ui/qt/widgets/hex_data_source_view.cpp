/* hex_data_source_view.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// Some code based on QHexView by Evan Teran
// https://github.com/eteran/qhexview/

#include "hex_data_source_view.h"

#include <wsutil/str_util.h>

#include <app/application_flavor.h>
#include <wsutil/utf8_entities.h>

#include "main_application.h"
#include "ui/recent.h"

#include <ui/qt/utils/font_manager.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/color_math.h>

#include <QActionGroup>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QScreen>
#include <QScrollBar>
#include <QStyle>
#include <QStyleOption>
#include <QTextLayout>
#include <QToolTip>
#include <QWindow>

// To do:
// - Add recent settings and context menu items to show/hide the offset.
// - Add a UTF-8 and possibly UTF-xx option to the ASCII display.
// - Move more common metrics to DataPrinter.

// Alternative implementations:
// - Pre-draw all of our characters and paint our display using pixmap
//   copying? That would make this behave like a terminal screen, which
//   is what we ultimately want.
// - Use QGraphicsView + QGraphicsScene + QGraphicsTextItem instead?

Q_DECLARE_METATYPE(bytes_view_type)
Q_DECLARE_METATYPE(bytes_encoding_type)
Q_DECLARE_METATYPE(DataPrinter::DumpType)

namespace {
QPoint mouseGlobalPos(const QMouseEvent *event)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    return event->globalPosition().toPoint();
#else
    return event->globalPos();
#endif
}
} // namespace

HexDataSourceView::HexDataSourceView(const QByteArray &data, packet_char_enc encoding, QWidget *parent) :
    BaseDataSourceView(data, parent),
    layout_(new QTextLayout()),
    layout_dirty_(false),
    encoding_(encoding),
    hovered_byte_offset_(-1),
    proto_start_(0),
    proto_len_(0),
    field_start_(0),
    field_len_(0),
    field_a_start_(0),
    field_a_len_(0),
    field_hover_start_(0),
    field_hover_len_(0),
    show_offset_(true),
    show_hex_(true),
    show_ascii_(true),
    row_width_(recent.gui_bytes_view == BYTES_BITS ? 8 : 16),
    em_width_(0),
    line_height_(0),
    allow_hover_selection_(!recent.gui_allow_hover_selection),
    selection_anchor_(-1),
    selection_start_(-1),
    selection_end_(-1),
    selecting_(false),
    context_byte_offset_(-1),
    cursor_byte_(-1),
    hovered_annotation_index_(-1),
    offset_start_byte_(-1),
    offset_end_byte_(-1),
    selected_field_is_protocol_(false),
    selected_field_use_own_range_(false)
{
    layout_->setCacheEnabled(true);

    ThemeManager * theme = ThemeManager::instance();

    offset_normal_fg_ = ColorMath::withAlphaF(theme->color(ThemeManager::PaletteWindowText), 0.35);
    offset_field_fg_ = ColorMath::withAlphaF(theme->color(ThemeManager::PaletteWindowText), 0.65);
    ctx_menu_.setToolTipsVisible(true);

    window()->winId(); // Required for screenChanged? https://phabricator.kde.org/D20171
    connect(window()->windowHandle(), &QWindow::screenChanged, viewport(), [=](const QScreen *) { viewport()->update(); });

    verticalScrollBar()->setFocusPolicy(Qt::NoFocus);
    horizontalScrollBar()->setFocusPolicy(Qt::NoFocus);

    // Own the font: seed it now and follow the FontManager for later changes.
    connect(FontManager::instance(), &FontManager::monospaceFontChanged, this, &HexDataSourceView::setMonospaceFont);
    setMonospaceFont(FontManager::zoomedMonospaceFont());

    setMouseTracking(true);

#ifdef Q_OS_MAC
    setAttribute(Qt::WA_MacShowFocusRect, true);
#endif
}

HexDataSourceView::~HexDataSourceView()
{
    ctx_menu_.clear();
    delete(layout_);
}

void HexDataSourceView::setAnnotations(const QVector<ByteViewAnnotation> &annotations)
{
    annotations_ = annotations;
    hovered_annotation_index_ = -1;
    viewport()->update();
}

bool HexDataSourceView::selectionRange(int *start, int *length) const
{
    if (selection_start_ < 0 || selection_end_ < 0) {
        return false;
    }
    int s = qMin(selection_start_, selection_end_);
    int e = qMax(selection_start_, selection_end_);
    if (start) {
        *start = s;
    }
    if (length) {
        *length = e - s + 1;
    }
    return true;
}

int HexDataSourceView::selectionAnchor() const
{
    return selection_anchor_;
}

int HexDataSourceView::selectionEnd() const
{
    return selection_end_;
}

int HexDataSourceView::contextByteOffset() const
{
    return context_byte_offset_;
}

void HexDataSourceView::setOffsetStart(int byte)
{
    if (byte < 0 || byte >= data_.size()) {
        return;
    }
    offset_start_byte_ = byte;
    viewport()->update();
}

void HexDataSourceView::setOffsetEnd(int byte)
{
    if (byte < 0) {
        offset_end_byte_ = -1;
    } else if (byte >= data_.size()) {
        return;
    } else {
        offset_end_byte_ = byte;
    }
    viewport()->update();
}

void HexDataSourceView::clearOffsetMarkers()
{
    offset_start_byte_ = -1;
    offset_end_byte_ = -1;
    viewport()->update();
}

void HexDataSourceView::createContextMenu()
{

    action_allow_hover_selection_ = ctx_menu_.addAction(tr("Allow hover highlighting"));
    action_allow_hover_selection_->setCheckable(true);
    action_allow_hover_selection_->setChecked(true);
    connect(action_allow_hover_selection_, &QAction::toggled, this, &HexDataSourceView::toggleHoverAllowed);
    ctx_menu_.addSeparator();

    action_add_annotation_ = ctx_menu_.addAction(tr("Add annotation…"));
    connect(action_add_annotation_, &QAction::triggered, this, &HexDataSourceView::requestAddAnnotation);

    action_edit_annotation_ = ctx_menu_.addAction(tr("Edit annotation…"));
    connect(action_edit_annotation_, &QAction::triggered, this, &HexDataSourceView::requestEditAnnotation);

    action_remove_annotation_ = ctx_menu_.addAction(tr("Remove annotation"));
    connect(action_remove_annotation_, &QAction::triggered, this, &HexDataSourceView::requestRemoveAnnotation);

    action_set_offset_start_ = ctx_menu_.addAction(tr("Start byte for offset"));
    connect(action_set_offset_start_, &QAction::triggered, this, &HexDataSourceView::requestSetOffsetStart);

    action_set_offset_end_ = ctx_menu_.addAction(tr("End byte for offset"));
    connect(action_set_offset_end_, &QAction::triggered, this, &HexDataSourceView::requestSetOffsetEnd);

    action_clear_offset_markers_ = ctx_menu_.addAction(tr("Clear offset markers"));
    connect(action_clear_offset_markers_, &QAction::triggered, this, &HexDataSourceView::requestClearOffsetMarkers);

    ctx_menu_.addSeparator();

    QActionGroup * copy_actions = DataPrinter::copyActions(this);
    ctx_menu_.addActions(copy_actions->actions());
    ctx_menu_.addSeparator();

    QActionGroup * format_actions = new QActionGroup(this);
    action_bytes_hex_ = format_actions->addAction(tr("Show bytes as hexadecimal"));
    action_bytes_hex_->setData(QVariant::fromValue(BYTES_HEX));
    action_bytes_hex_->setCheckable(true);

    action_bytes_dec_ = format_actions->addAction(tr("…as decimal"));
    action_bytes_dec_->setData(QVariant::fromValue(BYTES_DEC));
    action_bytes_dec_->setCheckable(true);

    action_bytes_oct_ = format_actions->addAction(tr("…as octal"));
    action_bytes_oct_->setData(QVariant::fromValue(BYTES_OCT));
    action_bytes_oct_->setCheckable(true);

    action_bytes_bits_ = format_actions->addAction(tr("…as bits"));
    action_bytes_bits_->setData(QVariant::fromValue(BYTES_BITS));
    action_bytes_bits_->setCheckable(true);

    ctx_menu_.addActions(format_actions->actions());
    connect(format_actions, &QActionGroup::triggered, this, &HexDataSourceView::setHexDisplayFormat);

    ctx_menu_.addSeparator();

    QActionGroup * encoding_actions = new QActionGroup(this);
    if (application_flavor_is_wireshark()) {
        action_bytes_enc_from_packet_ = encoding_actions->addAction(tr("Show text as frame encoding"));
    } else {
        action_bytes_enc_from_packet_ = encoding_actions->addAction(tr("Show text based on event"));
    }
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
    connect(encoding_actions, &QActionGroup::triggered, this, &HexDataSourceView::setCharacterEncoding);
}

void HexDataSourceView::toggleHoverAllowed(bool checked)
{
    allow_hover_selection_ = ! checked;
    recent.gui_allow_hover_selection = checked;
    if (!checked) {
        hovered_byte_offset_ = -1;
    }
}

void HexDataSourceView::requestAddAnnotation()
{
    emit addAnnotationRequested();
}

void HexDataSourceView::requestEditAnnotation()
{
    emit editAnnotationRequested();
}

void HexDataSourceView::requestRemoveAnnotation()
{
    emit removeAnnotationRequested();
}

void HexDataSourceView::requestSetOffsetStart()
{
    emit offsetStartRequested(context_byte_offset_);
}

void HexDataSourceView::requestSetOffsetEnd()
{
    emit offsetEndRequested(context_byte_offset_);
}

void HexDataSourceView::requestClearOffsetMarkers()
{
    emit offsetMarkersCleared();
}

void HexDataSourceView::updateContextMenu()
{
    if (ctx_menu_.isEmpty()) {
        return;
    }

    action_allow_hover_selection_->setChecked(recent.gui_allow_hover_selection);

    switch (recent.gui_bytes_view) {
    case BYTES_HEX:
        action_bytes_hex_->setChecked(true);
        break;
    case BYTES_BITS:
        action_bytes_bits_->setChecked(true);
        break;
    case BYTES_DEC:
        action_bytes_dec_->setChecked(true);
        break;
    case BYTES_OCT:
        action_bytes_oct_->setChecked(true);
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

    if (action_add_annotation_) {
        int sel_start = -1;
        int sel_length = 0;
        bool has_selection = selectionRange(&sel_start, &sel_length);
        if (!has_selection && context_byte_offset_ >= 0) {
            sel_start = context_byte_offset_;
            sel_length = 1;
            has_selection = true;
        }

        int ann_idx = annotationIndexAt(context_byte_offset_);
        if (ann_idx < 0 && has_selection) {
            ann_idx = annotationIndexIntersecting(sel_start, sel_length);
        }

        action_add_annotation_->setEnabled(has_selection);
        action_edit_annotation_->setEnabled(ann_idx >= 0);
        action_remove_annotation_->setEnabled(ann_idx >= 0);
    }

    if (action_set_offset_start_) {
        bool has_byte = context_byte_offset_ >= 0;
        action_set_offset_start_->setEnabled(has_byte);
        action_set_offset_end_->setEnabled(has_byte);
        action_clear_offset_markers_->setEnabled(offset_start_byte_ >= 0 || offset_end_byte_ >= 0);
    }
}

void HexDataSourceView::markProtocol(int start, int length)
{
    proto_start_ = start;
    proto_len_ = length;
    viewport()->update();
}

void HexDataSourceView::markField(int start, int length, bool scroll_to, bool hover)
{
    if (hover) {
        field_hover_start_ = start;
        field_hover_len_ = length;
    } else {
        field_start_ = start;
        field_len_ = length;
    }
    if (scroll_to) {
        scrollToByte(start);
    }
    viewport()->update();
}

void HexDataSourceView::markAppendix(int start, int length)
{
    field_a_start_ = start;
    field_a_len_ = length;
    viewport()->update();
}

void HexDataSourceView::unmarkField()
{
    proto_start_ = 0;
    proto_len_ = 0;
    field_start_ = 0;
    field_len_ = 0;
    field_a_start_ = 0;
    field_a_len_ = 0;
    selected_field_is_protocol_ = false;
    selected_field_use_own_range_ = false;
    viewport()->update();
}

void HexDataSourceView::setMonospaceFont(const QFont &mono_font)
{
    QFont int_font(mono_font);

    setFont(int_font);
    viewport()->setFont(int_font);
    layout_->setFont(int_font);

    if (isVisible()) {
        updateLayoutMetrics();
        updateScrollbars();
        viewport()->update();
    } else {
        layout_dirty_ = true;
    }
}

void HexDataSourceView::updateByteViewSettings()
{
    row_width_ = recent.gui_bytes_view == BYTES_BITS ? 8 : 16;

    updateContextMenu();
    updateScrollbars();
    viewport()->update();
}

void HexDataSourceView::paintEvent(QPaintEvent *)
{
    updateLayoutMetrics();

    QPainter painter(viewport());
    painter.translate(-horizontalScrollBar()->value() * em_width_, 0);

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
        if (palette().window() == palette().base()) {
            painter.fillRect(offset_rect, palette().alternateBase());
        } else {
            painter.fillRect(offset_rect, palette().window());
        }
    }

    if (data_.isEmpty()) {
        return;
    }

    // Data rows
    int widget_height = height();
    painter.save();

    x_pos_to_column_.clear();
    while ((int) (row_y + line_height_) < widget_height && offset < (int) data_.size()) {
        drawLine(&painter, offset, row_y);
        offset += row_width_;
        row_y += line_height_;
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
        hover_alpha = 0.3;
        if (devicePixelRatio() > 1) {
            pen_width = 0.5;
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

void HexDataSourceView::resizeEvent(QResizeEvent *)
{
    updateScrollbars();
}

void HexDataSourceView::showEvent(QShowEvent *)
{
    if (layout_dirty_) {
        updateLayoutMetrics();
        updateScrollbars();
        viewport()->update();
        layout_dirty_ = false;
    }
}

void HexDataSourceView::mousePressEvent (QMouseEvent *event) {
    if (data_.isEmpty() || !event || event->button() != Qt::LeftButton) {
        return;
    }

    // byteSelected does the following:
    // - Triggers selectedFieldChanged in ProtoTree, which clears the
    //   selection and selects the corresponding (or no) item.

    const int byte_offset = byteOffsetAtPixel(event->pos(), true);
    if (byte_offset < 0) {
        return;
    }

    setFocus(Qt::MouseFocusReason);
    selecting_ = true;
    setUpdatesEnabled(false);
    updateSelection(byte_offset, event->modifiers() & Qt::ShiftModifier, true);
    viewport()->update();
    setUpdatesEnabled(true);
}

void HexDataSourceView::mouseMoveEvent(QMouseEvent *event)
{
    if (!event) {
        return;
    }

    if (selecting_ && (event->buttons() & Qt::LeftButton)) {
        int byte_offset = byteOffsetAtPixel(event->pos(), true);
        if (byte_offset >= 0) {
            updateSelection(byte_offset, true, false);
            viewport()->update();
        }
    }

    updateAnnotationToolTip(byteOffsetAtPixel(event->pos(), true), mouseGlobalPos(event));

    if (allow_hover_selection_ ||
        (!allow_hover_selection_ && event->modifiers() & Qt::ControlModifier)) {
        return;
    }

    hovered_byte_offset_ = byteOffsetAtPixel(event->pos());
    if (hovered_byte_offset_ < 0) {
        field_hover_start_ = 0;
        field_hover_len_ = 0;
    }
    emit byteHovered(hovered_byte_offset_);
    viewport()->update();
}

void HexDataSourceView::mouseReleaseEvent(QMouseEvent *event)
{
    if (event && event->button() == Qt::LeftButton) {
        selecting_ = false;
        int byte_offset = byteOffsetAtPixel(event->pos(), true);
        if (byte_offset >= 0) {
            updateSelection(byte_offset, true, false);
            viewport()->update();
        }
    }

    QAbstractScrollArea::mouseReleaseEvent(event);
}

void HexDataSourceView::leaveEvent(QEvent *event)
{
    field_hover_start_ = 0;
    field_hover_len_ = 0;
    hovered_byte_offset_ = -1;
    emit byteHovered(hovered_byte_offset_);

    viewport()->update();
    hovered_annotation_index_ = -1;
    QToolTip::hideText();
    QAbstractScrollArea::leaveEvent(event);
}

void HexDataSourceView::contextMenuEvent(QContextMenuEvent *event)
{
    if (ctx_menu_.isEmpty()) {
        createContextMenu();
    }
    context_byte_offset_ = byteOffsetAtPixel(event->pos(), true);
    updateContextMenu();
    ctx_menu_.popup(event->globalPos());
}

void HexDataSourceView::keyPressEvent(QKeyEvent *event)
{
    if (!event || data_.isEmpty()) {
        QAbstractScrollArea::keyPressEvent(event);
        return;
    }

    int new_byte = cursor_byte_ >= 0 ? cursor_byte_ : 0;
    bool handled = true;

    switch (event->key()) {
    case Qt::Key_Left:
        new_byte -= 1;
        break;
    case Qt::Key_Right:
        new_byte += 1;
        break;
    case Qt::Key_Up:
        new_byte -= row_width_;
        break;
    case Qt::Key_Down:
        new_byte += row_width_;
        break;
    case Qt::Key_Home:
        new_byte = 0;
        break;
    case Qt::Key_End:
        new_byte = dataSize() - 1;
        break;
    default:
        handled = false;
        break;
    }

    if (!handled) {
        QAbstractScrollArea::keyPressEvent(event);
        return;
    }

    new_byte = qBound(0, new_byte, dataSize() - 1);
    updateSelection(new_byte, event->modifiers() & Qt::ShiftModifier, true);
    scrollToByte(new_byte);
    viewport()->update();
    event->accept();
}

// Private

const int HexDataSourceView::separator_interval_ = DataPrinter::separatorInterval();

void HexDataSourceView::updateLayoutMetrics()
{
    em_width_  = stringWidth("M");
    // We might want to match ProtoTree::rowHeight.
    line_height_ = viewport()->fontMetrics().lineSpacing();
}

int HexDataSourceView::stringWidth(const QString &line)
{
    return viewport()->fontMetrics().horizontalAdvance(line);
}

// Draw a line of byte view text for a given offset.
// Text highlighting is handled using QTextLayout::FormatRange.
void HexDataSourceView::drawLine(QPainter *painter, const int offset, const int row_y)
{
    if (data_.isEmpty()) {
        return;
    }

    // Build our pixel to byte offset vector the first time through.
    bool build_x_pos = x_pos_to_column_.empty() ? true : false;
    int tvb_len = static_cast<int>(data_.size());
    int max_tvb_pos = qMin(offset + row_width_, tvb_len) - 1;
    QList<QTextLayout::FormatRange> fmt_list;
    int sel_start = -1;
    int sel_length = 0;
    bool has_selection = selectionRange(&sel_start, &sel_length);
    QColor sel_bg;
    QColor sel_fg;
    QColor sel_overlay;
    if (has_selection) {
        sel_bg = palette().highlight().color();
        sel_overlay = sel_bg;
        sel_overlay.setAlphaF(qreal(0.35f));
        sel_fg = ColorMath::contrastingText(sel_bg);
    }
    QColor marker_start_bg = ThemeManager::instance()->color(ThemeManager::ExpertNote);
    QColor marker_end_bg = ThemeManager::instance()->color(ThemeManager::ExpertError);
    marker_start_bg.setAlphaF(qreal(0.7f));
    marker_end_bg.setAlphaF(qreal(0.7f));
    auto intersects = [](int a_start, int a_len, int b_start, int b_len) -> bool {
        if (a_len <= 0 || b_len <= 0) {
            return false;
        }
        int a_end = a_start + a_len - 1;
        int b_end = b_start + b_len - 1;
        return a_start <= b_end && a_end >= b_start;
    };

    static const char hexchars[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    QString line;
    HighlightMode offset_mode = ModeOffsetNormal;

    // Offset.
    if (show_offset_) {
        line = QStringLiteral(" %1 ").arg(offset, offsetChars(false), 16, QChar('0'));
        if (build_x_pos) {
            x_pos_to_column_.fill(-1, stringWidth(line));
        }
    }

    // Hex
    if (show_hex_) {
        int ascii_start = static_cast<int>(line.length()) + DataPrinter::hexChars() + 3;
        // Extra hover space before and after each byte.
        int slop = em_width_ / 2;
        unsigned char c;

        if (build_x_pos) {
            x_pos_to_column_ += QVector<int>().fill(-1, slop);
        }

        for (int tvb_pos = offset; tvb_pos <= max_tvb_pos; tvb_pos++) {
            line += ' ';
            /* insert a space every separator_interval_ bytes */
            if ((tvb_pos != offset) && ((tvb_pos % separator_interval_) == 0)) {
                line += ' ';
                x_pos_to_column_ += QVector<int>().fill(tvb_pos - offset - 1, em_width_);
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
            case BYTES_DEC:
                c = data_[tvb_pos];
                line += c < 100 ? ' ' : hexchars[c / 100];
                line += c < 10 ? ' ' : hexchars[(c / 10) % 10];
                line += hexchars[c % 10];
                break;
            case BYTES_OCT:
                line += hexchars[(data_[tvb_pos] & 0xc0) >> 6];
                line += hexchars[(data_[tvb_pos] & 0x38) >> 3];
                line += hexchars[data_[tvb_pos] & 0x07];
                break;
            }
            if (build_x_pos) {
                x_pos_to_column_ += QVector<int>().fill(tvb_pos - offset, stringWidth(line) - x_pos_to_column_.size() + slop);
            }
            if (tvb_pos == hovered_byte_offset_) {
                int ho_len;
                switch (recent.gui_bytes_view) {
                case BYTES_HEX:
                    ho_len = 2;
                    break;
                case BYTES_BITS:
                    ho_len = 8;
                    break;
                case BYTES_DEC:
                case BYTES_OCT:
                    ho_len = 3;
                    break;
                default:
                    ws_assert_not_reached();
                }
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
        addHexFormatRange(fmt_list, field_hover_start_, field_hover_len_, offset, max_tvb_pos, ModeHover);
        if (has_selection) {
            addHexCustomRange(fmt_list, sel_start, sel_length, offset, max_tvb_pos, sel_overlay, sel_fg);
        }
        for (const ByteViewAnnotation &ann : annotations_) {
            if (ann.length <= 0) {
                continue;
            }
            bool overlaps_selection = has_selection && intersects(ann.start, ann.length, sel_start, sel_length);
            bool overlaps_field = intersects(ann.start, ann.length, field_start_, field_len_) ||
                    intersects(ann.start, ann.length, field_a_start_, field_a_len_) ||
                    intersects(ann.start, ann.length, field_hover_start_, field_hover_len_);
            QColor ann_bg = ann.color;
            if (overlaps_selection) {
                QColor blended = ColorMath::withAlphaF(sel_bg, 0.7);
                blended.setAlpha(ann_bg.alpha());
                ann_bg = blended;
            }
            if (overlaps_field) {
                qreal alpha = ann_bg.alphaF();
                ann_bg.setAlphaF(qMax(alpha * qreal(0.65f), qreal(0.35f)));
            }
            addHexCustomRange(fmt_list, ann.start, ann.length, offset, max_tvb_pos, ann_bg,
                              ColorMath::contrastingText(ann_bg));
        }
        if (offset_start_byte_ >= 0) {
            addHexCustomRange(fmt_list, offset_start_byte_, 1, offset, max_tvb_pos,
                              marker_start_bg, ColorMath::contrastingText(marker_start_bg));
        }
        if (offset_end_byte_ >= 0) {
            addHexCustomRange(fmt_list, offset_end_byte_, 1, offset, max_tvb_pos,
                              marker_end_bg, ColorMath::contrastingText(marker_end_bg));
        }
    }

    // ASCII
    if (show_ascii_) {
        bool in_non_printable = false;
        int np_start = 0;
        int np_len = 0;
        char c;
        int bytes_enc;

        for (int tvb_pos = offset; tvb_pos <= max_tvb_pos; tvb_pos++) {
            /* insert a space every separator_interval_ bytes */
            if ((tvb_pos != offset) && ((tvb_pos % separator_interval_) == 0)) {
                line += ' ';
                if (build_x_pos) {
                    x_pos_to_column_ += QVector<int>().fill(tvb_pos - offset - 1, em_width_ / 2);
                }
            }

            if (recent.gui_bytes_encoding == BYTES_ENC_FROM_PACKET) {
                switch (encoding_) {
                case PACKET_CHAR_ENC_CHAR_ASCII:
                    bytes_enc = BYTES_ENC_ASCII;
                    break;
                case PACKET_CHAR_ENC_CHAR_EBCDIC:
                    bytes_enc = BYTES_ENC_EBCDIC;
                    break;
                default:
                    ws_assert_not_reached();
                }
            } else {
                bytes_enc = recent.gui_bytes_encoding;
            }

            switch (bytes_enc) {
            case BYTES_ENC_EBCDIC:
                c = EBCDIC_to_ASCII1(data_[tvb_pos]);
                break;
            case BYTES_ENC_ASCII:
            default:
                c = data_[tvb_pos];
                break;
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
            if (tvb_pos == hovered_byte_offset_) {
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
        addAsciiFormatRange(fmt_list, field_hover_start_, field_hover_len_, offset, max_tvb_pos, ModeHover);
        if (has_selection) {
            addAsciiCustomRange(fmt_list, sel_start, sel_length, offset, max_tvb_pos, sel_overlay, sel_fg);
        }
        for (const ByteViewAnnotation &ann : annotations_) {
            if (ann.length <= 0) {
                continue;
            }
            bool overlaps_selection = has_selection && intersects(ann.start, ann.length, sel_start, sel_length);
            bool overlaps_field = intersects(ann.start, ann.length, field_start_, field_len_) ||
                    intersects(ann.start, ann.length, field_a_start_, field_a_len_) ||
                    intersects(ann.start, ann.length, field_hover_start_, field_hover_len_);
            QColor ann_bg = ann.color;
            if (overlaps_selection) {
                QColor blended = ColorMath::withAlphaF(sel_bg, 0.7);
                blended.setAlpha(ann_bg.alpha());
                ann_bg = blended;
            }
            if (overlaps_field) {
                qreal alpha = ann_bg.alphaF();
                ann_bg.setAlphaF(qMax(alpha * qreal(0.65f), qreal(0.35f)));
            }
            addAsciiCustomRange(fmt_list, ann.start, ann.length, offset, max_tvb_pos, ann_bg,
                                ColorMath::contrastingText(ann_bg));
        }
        if (offset_start_byte_ >= 0) {
            addAsciiCustomRange(fmt_list, offset_start_byte_, 1, offset, max_tvb_pos,
                                marker_start_bg, ColorMath::contrastingText(marker_start_bg));
        }
        if (offset_end_byte_ >= 0) {
            addAsciiCustomRange(fmt_list, offset_end_byte_, 1, offset, max_tvb_pos,
                                marker_end_bg, ColorMath::contrastingText(marker_end_bg));
        }
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

bool HexDataSourceView::addFormatRange(QList<QTextLayout::FormatRange> &fmt_list, int start, int length, HighlightMode mode)
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
        // On the GTK3 platform theme, and possibly others, window() and
        // base() are the same color. Use alternateBase for contrast.
        if (palette().window() == palette().base()) {
            format_range.format.setBackground(palette().alternateBase());
        } else {
            format_range.format.setBackground(palette().window());
            format_range.format.setForeground(palette().windowText());
        }
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
    case ModeHover:
        // TODO: FIX right color
        //format_range.format.setBackground(ThemeManager::instance()->color(ThemeManager::HoverHighlight));
        format_range.format.setForeground(palette().text());
        break;
    }
    fmt_list << format_range;
    return true;
}

bool HexDataSourceView::addHexFormatRange(QList<QTextLayout::FormatRange> &fmt_list, int mark_start, int mark_length, int tvb_offset, int max_tvb_pos, HexDataSourceView::HighlightMode mode)
{
    int mark_end = mark_start + mark_length - 1;
    if (mark_start < 0 || mark_length < 1) return false;
    if (mark_start > max_tvb_pos && mark_end < tvb_offset) return false;

    int chars_per_byte;
    switch (recent.gui_bytes_view) {
    case BYTES_HEX:
        chars_per_byte = 2;
        break;
    case BYTES_BITS:
        chars_per_byte = 8;
        break;
    case BYTES_DEC:
    case BYTES_OCT:
        chars_per_byte = 3;
        break;
    default:
        ws_assert_not_reached();
    }
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

bool HexDataSourceView::addAsciiFormatRange(QList<QTextLayout::FormatRange> &fmt_list, int mark_start, int mark_length, int tvb_offset, int max_tvb_pos, HexDataSourceView::HighlightMode mode)
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

bool HexDataSourceView::addHexCustomRange(QList<QTextLayout::FormatRange> &fmt_list, int mark_start, int mark_length, int tvb_offset, int max_tvb_pos, const QColor &bg, const QColor &fg)
{
    if (mark_start < 0 || mark_length < 1) {
        return false;
    }

    int tvb_len = static_cast<int>(data_.size());
    int mark_end = mark_start + mark_length - 1;
    if (mark_start >= tvb_len) {
        return false;
    }
    mark_end = qMin(mark_end, tvb_len - 1);
    if (mark_start > max_tvb_pos && mark_end < tvb_offset) {
        return false;
    }

    int chars_per_byte;
    switch (recent.gui_bytes_view) {
    case BYTES_HEX:
        chars_per_byte = 2;
        break;
    case BYTES_BITS:
        chars_per_byte = 8;
        break;
    case BYTES_DEC:
    case BYTES_OCT:
        chars_per_byte = 3;
        break;
    default:
        ws_assert_not_reached();
    }
    int chars_plus_pad = chars_per_byte + 1;
    int byte_start = qMax(tvb_offset, mark_start) - tvb_offset;
    int byte_end = qMin(max_tvb_pos, mark_end) - tvb_offset;
    if (byte_end < byte_start) {
        return false;
    }
    int fmt_start = offsetChars() + 1 // offset + spacing
            + (byte_start / separator_interval_)
            + (byte_start * chars_plus_pad);
    int fmt_length = offsetChars() + 1 // offset + spacing
            + (byte_end / separator_interval_)
            + (byte_end * chars_plus_pad)
            + chars_per_byte
            - fmt_start;

    QTextLayout::FormatRange format_range;
    format_range.start = fmt_start;
    format_range.length = fmt_length;
    format_range.format.setBackground(bg);
    format_range.format.setForeground(fg);
    fmt_list << format_range;
    return true;
}

bool HexDataSourceView::addAsciiCustomRange(QList<QTextLayout::FormatRange> &fmt_list, int mark_start, int mark_length, int tvb_offset, int max_tvb_pos, const QColor &bg, const QColor &fg)
{
    if (mark_start < 0 || mark_length < 1) {
        return false;
    }

    int tvb_len = static_cast<int>(data_.size());
    int mark_end = mark_start + mark_length - 1;
    if (mark_start >= tvb_len) {
        return false;
    }
    mark_end = qMin(mark_end, tvb_len - 1);
    if (mark_start > max_tvb_pos && mark_end < tvb_offset) {
        return false;
    }

    int byte_start = qMax(tvb_offset, mark_start) - tvb_offset;
    int byte_end = qMin(max_tvb_pos, mark_end) - tvb_offset;
    if (byte_end < byte_start) {
        return false;
    }
    int fmt_start = offsetChars() + DataPrinter::hexChars() + 3 // offset + hex + spacing
            + (byte_start / separator_interval_)
            + byte_start;
    int fmt_length = offsetChars() + DataPrinter::hexChars() + 3 // offset + hex + spacing
            + (byte_end / separator_interval_)
            + byte_end
            + 1 // Just one character.
            - fmt_start;

    QTextLayout::FormatRange format_range;
    format_range.start = fmt_start;
    format_range.length = fmt_length;
    format_range.format.setBackground(bg);
    format_range.format.setForeground(fg);
    fmt_list << format_range;
    return true;
}

int HexDataSourceView::annotationIndexAt(int byte_offset) const
{
    if (byte_offset < 0) {
        return -1;
    }

    for (auto i = annotations_.size(); i > 0; ) {
        --i;
        const ByteViewAnnotation &ann = annotations_.at(i);
        if (byte_offset >= ann.start && byte_offset < ann.start + ann.length) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

int HexDataSourceView::annotationIndexIntersecting(int start, int length) const
{
    if (start < 0 || length <= 0) {
        return -1;
    }
    int end = start + length - 1;

    for (auto i = annotations_.size(); i > 0; ) {
        --i;
        const ByteViewAnnotation &ann = annotations_.at(i);
        int ann_end = ann.start + ann.length - 1;
        if (ann.start <= end && ann_end >= start) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

void HexDataSourceView::updateSelection(int byte_offset, bool extend, bool emit_signal)
{
    if (byte_offset < 0 || byte_offset >= data_.size()) {
        return;
    }

    if (!extend || selection_anchor_ < 0) {
        selection_anchor_ = byte_offset;
    }

    if (extend) {
        selection_start_ = selection_anchor_;
        selection_end_ = byte_offset;
    } else {
        selection_start_ = byte_offset;
        selection_end_ = byte_offset;
    }
    cursor_byte_ = byte_offset;

    if (emit_signal) {
        emit byteSelected(byte_offset);
    }
}

void HexDataSourceView::updateAnnotationToolTip(int byte_offset, const QPoint &global_pos)
{
    int ann_idx = annotationIndexAt(byte_offset);
    if (ann_idx == hovered_annotation_index_) {
        return;
    }

    hovered_annotation_index_ = ann_idx;
    if (ann_idx < 0) {
        QToolTip::hideText();
        return;
    }

    const QString comment = annotations_.at(ann_idx).comment.trimmed();
    if (comment.isEmpty()) {
        QToolTip::hideText();
        return;
    }

    QToolTip::showText(global_pos, tr("Comment: %1").arg(comment), this);
}

void HexDataSourceView::scrollToByte(int byte)
{
    verticalScrollBar()->setValue(byte / row_width_);
}

// Offset character width
int HexDataSourceView::offsetChars(bool include_pad)
{
    int padding = include_pad ? 2 : 0;
    if (! data_.isEmpty() && data_.size() > 0xffff) {
        return 8 + padding;
    }
    return 4 + padding;
}

// Offset pixel width
int HexDataSourceView::offsetPixels()
{
    if (show_offset_) {
        // One pad space before and after
        QString zeroes = QString(offsetChars(), '0');
        return stringWidth(zeroes);
    }
    return 0;
}

// Hex pixel width
int HexDataSourceView::hexPixels()
{
    if (show_hex_) {
        // One pad space before and after
        QString zeroes = QString(DataPrinter::hexChars() + 2, '0');
        return stringWidth(zeroes);
    }
    return 0;
}

int HexDataSourceView::asciiPixels()
{
    if (show_ascii_) {
        // Two pad spaces before, one after
        int ascii_chars = (row_width_ + ((row_width_ - 1) / separator_interval_));
        QString zeroes = QString(ascii_chars + 3, '0');
        return stringWidth(zeroes);
    }
    return 0;
}

int HexDataSourceView::totalPixels()
{
    return offsetPixels() + hexPixels() + asciiPixels();
}

void HexDataSourceView::copyBytes(bool)
{
    QAction* action = qobject_cast<QAction*>(sender());
    if (!action) {
        return;
    }

    int dump_type = action->data().toInt();

    if (dump_type <= DataPrinter::DP_MimeData) {
        DataPrinter printer;
        printer.toClipboard((DataPrinter::DumpType) dump_type, this);
    }
}

// We do chunky (per-character) scrolling because it makes some of the
// math easier. Should we do smooth scrolling?
void HexDataSourceView::updateScrollbars()
{
    const int length = static_cast<int>(data_.size());
    if (length > 0 && line_height_ > 0 && em_width_ > 0) {
        int all_lines_height = length / row_width_ + ((length % row_width_) ? 1 : 0) - viewport()->height() / line_height_;

        verticalScrollBar()->setRange(0, qMax(0, all_lines_height));
        horizontalScrollBar()->setRange(0, qMax(0, int((totalPixels() - viewport()->width()) / em_width_)));
    }
}

int HexDataSourceView::byteOffsetAtPixel(QPoint pos, bool allow_fuzzy)
{
    if (x_pos_to_column_.isEmpty()) {
        return -1;
    }

    int byte = (verticalScrollBar()->value() + (pos.y() / line_height_)) * row_width_;
    int x = (horizontalScrollBar()->value() * em_width_) + pos.x();
    Q_ASSERT(x_pos_to_column_.size() <= std::numeric_limits<int>::max());
    int size = static_cast<int>(x_pos_to_column_.size());

    if (x < 0 || x >= size) {
        if (!allow_fuzzy) {
            return -1;
        }
        x = qBound(0, x, size - 1);
    }

    int col = x_pos_to_column_.value(x, -1);
    if (col < 0 && allow_fuzzy) {
        int left = x - 1;
        int right = x + 1;
        while (left >= 0 || right < size) {
            if (left >= 0 && x_pos_to_column_[left] >= 0) {
                col = x_pos_to_column_[left];
                break;
            }
            if (right < size && x_pos_to_column_[right] >= 0) {
                col = x_pos_to_column_[right];
                break;
            }
            left--;
            right++;
        }
    }

    if (col < 0) {
        return -1;
    }

    byte += col;
    if (byte < 0 || byte >= data_.size()) {
        return -1;
    }
    return byte;
}

void HexDataSourceView::setHexDisplayFormat(QAction *action)
{
    if (!action) {
        return;
    }

    recent.gui_bytes_view = action->data().value<bytes_view_type>();

    emit byteViewSettingsChanged();
}

void HexDataSourceView::setCharacterEncoding(QAction *action)
{
    if (!action) {
        return;
    }

    recent.gui_bytes_encoding = action->data().value<bytes_encoding_type>();

    emit byteViewSettingsChanged();
}
