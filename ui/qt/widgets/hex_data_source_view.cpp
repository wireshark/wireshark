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
#include <QToolTip>
#include <QWindow>

// To do:
// - Add recent settings and context menu items to show/hide the offset.
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
    return event->globalPosition().toPoint();
}

bool rangesIntersect(int a_start, int a_len, int b_start, int b_len)
{
    if (a_len <= 0 || b_len <= 0) {
        return false;
    }
    int a_end = a_start + a_len - 1;
    int b_end = b_start + b_len - 1;
    return a_start <= b_end && a_end >= b_start;
}

} // namespace

HexDataSourceView::HexDataSourceView(const QByteArray &data, packet_char_enc encoding, QWidget *parent) :
    BaseDataSourceView(data, parent),
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
    selected_field_use_own_range_(false),
    text_cells_dirty_(true)
{
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

    action_bytes_enc_utf8_ = encoding_actions->addAction(tr("…as UTF-8"));
    action_bytes_enc_utf8_->setData(QVariant::fromValue(BYTES_ENC_UTF8));
    action_bytes_enc_utf8_->setCheckable(true);

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
    case BYTES_ENC_UTF8:
        action_bytes_enc_utf8_->setChecked(true);
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
    text_cells_dirty_ = true;

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

    ensureTextCells();

    RowPaintContext ctx;
    ctx.has_selection = selectionRange(&ctx.sel_start, &ctx.sel_length);
    if (ctx.has_selection) {
        ctx.sel_bg = palette().highlight().color();
        ctx.sel_overlay = ctx.sel_bg;
        ctx.sel_overlay.setAlphaF(qreal(0.35f));
        ctx.sel_fg = ColorMath::contrastingText(ctx.sel_bg);
    }
    ctx.marker_start_bg = ThemeManager::instance()->color(ThemeManager::ExpertNote);
    ctx.marker_end_bg = ThemeManager::instance()->color(ThemeManager::ExpertError);
    ctx.marker_start_bg.setAlphaF(qreal(0.7f));
    ctx.marker_end_bg.setAlphaF(qreal(0.7f));
    // Hovering any byte of a multi-byte character hovers all of them.
    if (hovered_byte_offset_ >= 0) {
        ByteViewTextCells::Cell cell;
        if (text_cells_.cellForByte(hovered_byte_offset_, cell)) {
            ctx.hover_start = cell.start;
            ctx.hover_length = cell.length;
        } else {
            ctx.hover_start = hovered_byte_offset_;
            ctx.hover_length = 1;
        }
    }
    ctx.invalid_fg = ThemeManager::instance()->color(ThemeManager::AccentError);

    // Data rows
    int widget_height = height();
    painter.save();

    const int tvb_len = static_cast<int>(data_.size());
    while ((int) (row_y + line_height_) < widget_height && offset < tvb_len) {
        Row row;
        row.offset = offset;
        row.last = qMin(offset + row_width_, tvb_len) - 1;
        row.y = row_y;
        row.styles.reserve(row.last - offset + 1);
        row.gaps.reserve(row.last - offset);
        for (int tvb_pos = offset; tvb_pos <= row.last; tvb_pos++) {
            row.styles.append(byteStyle(tvb_pos, ctx));
            if (tvb_pos < row.last) {
                row.gaps.append(byteStyle(tvb_pos, ctx, 2));
            }
        }
        drawLine(&painter, row, ctx);
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

// Draw one row: the offset column, the hex panel and the text panel. Both
// panels are grids with one cell per byte, so highlights and hit-testing
// are a matter of arithmetic.
void HexDataSourceView::drawLine(QPainter *painter, const Row &row, const RowPaintContext &ctx)
{
    if (show_offset_) {
        drawOffsetColumn(painter, row);
    }
    if (show_hex_) {
        drawHexPanel(painter, row, ctx);
    }
    drawTextPanel(painter, row, ctx);
}

// The offset column, dimmed unless the selected field has bytes on this row.
void HexDataSourceView::drawOffsetColumn(QPainter *painter, const Row &row)
{
    QColor fg = offset_normal_fg_;
    if ((show_hex_ || show_ascii_) && rangesIntersect(field_start_, field_len_, row.offset, row.last - row.offset + 1)) {
        fg = offset_field_fg_;
    }
    QString text = QStringLiteral(" %1 ").arg(row.offset, offsetChars(false), 16, QChar('0'));
    painter->save();
    painter->setPen(fg);
    painter->drawText(QRect(0, row.y, offsetPixels(), line_height_), Qt::AlignLeft | Qt::AlignVCenter, text);
    painter->restore();
}

// The hex panel: one cell per byte holding its digits in the current base.
void HexDataSourceView::drawHexPanel(QPainter *painter, const Row &row, const RowPaintContext &ctx)
{
    const int cols = row.last - row.offset + 1;

    // Backgrounds, for the bytes and for the spaces between them.
    for (int col = 0; col < cols; col++) {
        QRect rect = hexCellRect(col, row.y);
        const QColor &bg = row.styles.at(col).bg;
        if (bg.isValid()) {
            painter->fillRect(rect, bg);
        }
        if (col + 1 < cols && row.gaps.at(col).bg.isValid()) {
            QRect gap(rect.right() + 1, rect.top(), 0, rect.height());
            gap.setRight(hexCellRect(col + 1, row.y).left() - 1);
            painter->fillRect(gap, row.gaps.at(col).bg);
        }
    }

    // Digits.
    painter->save();
    for (int col = 0; col < cols; col++) {
        const int tvb_pos = row.offset + col;
        QRect rect = hexCellRect(col, row.y);
        const QColor &fg = row.styles.at(col).fg;
        painter->setPen(fg.isValid() ? fg : palette().text().color());
        painter->drawText(rect, Qt::AlignLeft | Qt::AlignVCenter, byteText(static_cast<uint8_t>(data_.at(tvb_pos))));
        if (tvb_pos >= ctx.hover_start && tvb_pos < ctx.hover_start + ctx.hover_length) {
            hover_outlines_.append(rect);
        }
    }
    painter->restore();
}

void HexDataSourceView::drawTextPanel(QPainter *painter, const Row &row, const RowPaintContext &ctx)
{
    if (!show_ascii_) {
        return;
    }

    // Backgrounds, one column per byte, so that highlights keep their
    // byte precision inside multi-byte characters. The separator column
    // between two byte groups is colored like the space between bytes.
    for (int col = 0; col < row.styles.size(); col++) {
        QRect rect = textCellRect(col, row.y);
        const QColor &bg = row.styles.at(col).bg;
        if (bg.isValid()) {
            painter->fillRect(rect, bg);
        }
        if (col < row.gaps.size() && (col + 1) % separator_interval_ == 0 && row.gaps.at(col).bg.isValid()) {
            QRect gap(rect.right() + 1, rect.top(), 0, rect.height());
            gap.setRight(textCellRect(col + 1, row.y).left() - 1);
            painter->fillRect(gap, row.gaps.at(col).bg);
        }
    }

    // Glyphs, one per cell. A cell may span several columns and may have
    // started on the previous row.
    painter->save();
    const int cell_count = text_cells_.cellCount();
    for (int idx = text_cells_.cellIndexForByte(row.offset); idx >= 0 && idx < cell_count; idx++) {
        ByteViewTextCells::Cell cell = text_cells_.cellAt(idx);
        if (cell.start > row.last) {
            break;
        }

        int first = qMax(cell.start, row.offset);
        int last = qMin(cell.start + cell.length - 1, row.last);
        if (cell.start == ctx.hover_start) {
            hover_outlines_.append(textSpanRect(first - row.offset, last - row.offset, row.y));
        }

        if (cell.length == 1) {
            painter->setPen(cellTextColor(cell, row.styles.at(first - row.offset), ctx));
            painter->drawText(textCellRect(first - row.offset, row.y), Qt::AlignLeft | Qt::AlignVCenter, cell.text);
        } else {
            drawMultiByteCell(painter, cell, first, last, row, ctx);
        }
    }
    painter->restore();
}

// Draw the part of a multi-byte cell that falls on one row.
//
// The glyph sits over the column of the cell's first byte and a dim "]"
// marks the column of its last byte; the columns between are blank. When
// a row boundary splits the cell the glyph still goes over the first byte,
// running past the end of the row if it has to, and the bracket goes on
// the next row. When the glyph needs every column the cell has (a wide
// character whose bytes were split, say) the bracket is left out, since
// the glyph already fills the cell.
void HexDataSourceView::drawMultiByteCell(QPainter *painter, const ByteViewTextCells::Cell &cell, int first, int last, const Row &row, const RowPaintContext &ctx)
{
    const int first_col = first - row.offset;
    const int last_col = last - row.offset;
    const bool holds_end = last == cell.start + cell.length - 1;
    bool draw_bracket = holds_end;

    if (first == cell.start) {
        const int needed = stringWidth(cell.text);
        QRect glyph_rect = textSpanRect(first_col, last_col, row.y);
        if (holds_end) {
            // Keep the glyph off the bracket column when both fit on this
            // row. The bracket is centered in its column, so the glyph may
            // spill a little into that column without touching it.
            const int spill = em_width_ / 3;
            if (last > first && textSpanRect(first_col, last_col - 1, row.y).width() + spill >= needed) {
                glyph_rect = textSpanRect(first_col, last_col - 1, row.y).adjusted(0, 0, spill, 0);
            } else {
                draw_bracket = false;
            }
        } else {
            // The rest of the row is this cell's anyway: let the glyph run
            // past the last column instead of cutting it.
            glyph_rect.setWidth(qMax(glyph_rect.width(), needed));
        }
        painter->setClipRect(glyph_rect);
        painter->setPen(cellTextColor(cell, row.styles.at(first_col), ctx));
        painter->drawText(glyph_rect, Qt::AlignLeft | Qt::AlignVCenter | Qt::TextDontClip, cell.text);
        painter->setClipping(false);
    }

    if (draw_bracket) {
        const QColor &fg = row.styles.at(last_col).fg;
        painter->setPen(fg.isValid() ? fg : offset_normal_fg_);
        painter->drawText(textCellRect(last_col, row.y), Qt::AlignCenter, QStringLiteral("]"));
    }
}

// The color of a cell's glyph: the highlight text color when one applies,
// otherwise dimmed for non-printable characters, the error color for
// invalid bytes and the normal text color for everything else.
QColor HexDataSourceView::cellTextColor(const ByteViewTextCells::Cell &cell, const ByteStyle &style, const RowPaintContext &ctx)
{
    if (style.fg.isValid()) {
        return style.fg;
    }
    switch (cell.kind) {
    case ByteViewTextCells::NonPrintable:
        return offset_normal_fg_;
    case ByteViewTextCells::Invalid:
        return ctx.invalid_fg;
    default:
        return palette().text().color();
    }
}

HexDataSourceView::ByteStyle HexDataSourceView::byteStyle(int offset, const RowPaintContext &ctx, int length)
{
    auto covers = [offset, length](int start, int len) {
        return len > 0 && start <= offset && offset + length <= start + len;
    };
    ByteStyle style;

    if (covers(proto_start_, proto_len_)) {
        // On the GTK3 platform theme, and possibly others, window() and
        // base() are the same color. Use alternateBase for contrast.
        if (palette().window() == palette().base()) {
            style.bg = palette().alternateBase().color();
        } else {
            style.bg = palette().window().color();
            style.fg = palette().windowText().color();
        }
    }
    if (covers(field_start_, field_len_) || covers(field_a_start_, field_a_len_)) {
        style.bg = palette().highlight().color();
        style.fg = palette().highlightedText().color();
    }
    if (covers(field_hover_start_, field_hover_len_)) {
        style.fg = palette().text().color();
    }
    if (ctx.has_selection && covers(ctx.sel_start, ctx.sel_length)) {
        style.bg = ctx.sel_overlay;
        style.fg = ctx.sel_fg;
    }
    for (const ByteViewAnnotation &ann : annotations_) {
        if (covers(ann.start, ann.length)) {
            style.bg = annotationBackground(ann, ctx);
            style.fg = ColorMath::contrastingText(style.bg);
        }
    }
    if (covers(offset_start_byte_, 1)) {
        style.bg = ctx.marker_start_bg;
        style.fg = ColorMath::contrastingText(ctx.marker_start_bg);
    }
    if (covers(offset_end_byte_, 1)) {
        style.bg = ctx.marker_end_bg;
        style.fg = ColorMath::contrastingText(ctx.marker_end_bg);
    }
    return style;
}

QColor HexDataSourceView::annotationBackground(const ByteViewAnnotation &ann, const RowPaintContext &ctx)
{
    bool overlaps_selection = ctx.has_selection && rangesIntersect(ann.start, ann.length, ctx.sel_start, ctx.sel_length);
    bool overlaps_field = rangesIntersect(ann.start, ann.length, field_start_, field_len_) ||
            rangesIntersect(ann.start, ann.length, field_a_start_, field_a_len_) ||
            rangesIntersect(ann.start, ann.length, field_hover_start_, field_hover_len_);
    QColor ann_bg = ann.color;
    if (overlaps_selection) {
        QColor blended = ColorMath::withAlphaF(ctx.sel_bg, 0.7);
        blended.setAlpha(ann_bg.alpha());
        ann_bg = blended;
    }
    if (overlaps_field) {
        qreal alpha = ann_bg.alphaF();
        ann_bg.setAlphaF(qMax(alpha * qreal(0.65f), qreal(0.35f)));
    }
    return ann_bg;
}

void HexDataSourceView::ensureTextCells()
{
    if (!text_cells_dirty_) {
        return;
    }
    text_cells_.decode(data_, textEncoding());
    text_cells_dirty_ = false;
}

ByteViewTextCells::Encoding HexDataSourceView::textEncoding() const
{
    switch (recent.gui_bytes_encoding) {
    case BYTES_ENC_ASCII:
        return ByteViewTextCells::Ascii;
    case BYTES_ENC_EBCDIC:
        return ByteViewTextCells::Ebcdic;
    case BYTES_ENC_UTF8:
        return ByteViewTextCells::Utf8;
    case BYTES_ENC_FROM_PACKET:
    default:
        return encoding_ == PACKET_CHAR_ENC_CHAR_EBCDIC ? ByteViewTextCells::Ebcdic : ByteViewTextCells::Ascii;
    }
}

// The number of digits a byte takes in the hex panel in the current base.
int HexDataSourceView::hexCharsPerByte()
{
    int chars = 2;
    switch (recent.gui_bytes_view) {
    case BYTES_HEX:
        chars = 2;
        break;
    case BYTES_BITS:
        chars = 8;
        break;
    case BYTES_DEC:
    case BYTES_OCT:
        chars = 3;
        break;
    default:
        ws_assert_not_reached();
    }
    return chars;
}

// A byte's digits in the current base, padded to hexCharsPerByte().
QString HexDataSourceView::byteText(uint8_t c)
{
    switch (recent.gui_bytes_view) {
    case BYTES_BITS:
        return QStringLiteral("%1").arg(c, 8, 2, QChar('0'));
    case BYTES_DEC:
        return QStringLiteral("%1").arg(c, 3, 10, QChar(' '));
    case BYTES_OCT:
        return QStringLiteral("%1").arg(c, 3, 8, QChar('0'));
    case BYTES_HEX:
    default:
        return QStringLiteral("%1").arg(c, 2, 16, QChar('0'));
    }
}

int HexDataSourceView::hexPanelX()
{
    // One pad space after the offset column.
    return offsetPixels() + em_width_;
}

QRect HexDataSourceView::hexCellRect(int col, int row_y)
{
    // Each byte is its digits and a pad space; one extra space every
    // separator_interval_ bytes.
    const int chars = hexCharsPerByte();
    int x = hexPanelX() + (col * (chars + 1) + col / separator_interval_) * em_width_;
    return QRect(x, row_y, chars * em_width_, line_height_);
}

int HexDataSourceView::hexColumnAtX(int x, bool allow_fuzzy)
{
    if (em_width_ <= 0) {
        return -1;
    }
    // A byte's hit region is its digits plus half of the pad space on
    // each side; a separator space hit-tests as the byte before it.
    int rel = x - hexPanelX() + em_width_ / 2;
    if (rel < 0) {
        return allow_fuzzy ? 0 : -1;
    }
    const int byte_units = hexCharsPerByte() + 1;
    const int group_units = separator_interval_ * byte_units + 1;
    int unit = rel / em_width_;
    int col = (unit / group_units) * separator_interval_ + qMin((unit % group_units) / byte_units, separator_interval_ - 1);
    if (col >= row_width_) {
        return allow_fuzzy ? row_width_ - 1 : -1;
    }
    return col;
}

int HexDataSourceView::textPanelX()
{
    // One pad space after the hex panel.
    return offsetPixels() + hexPixels() + em_width_;
}

QRect HexDataSourceView::textCellRect(int col, int row_y)
{
    // One extra column of space every separator_interval_ bytes.
    int x = textPanelX() + (col + col / separator_interval_) * em_width_;
    return QRect(x, row_y, em_width_, line_height_);
}

QRect HexDataSourceView::textSpanRect(int first_col, int last_col, int row_y)
{
    return textCellRect(first_col, row_y).united(textCellRect(last_col, row_y));
}

int HexDataSourceView::textColumnAtX(int x, bool allow_fuzzy)
{
    if (em_width_ <= 0) {
        return -1;
    }
    int rel = x - textPanelX();
    if (rel < 0) {
        return allow_fuzzy ? 0 : -1;
    }
    int unit = rel / em_width_;
    int group_units = separator_interval_ + 1;
    // A separator space hit-tests as the byte before it.
    int col = (unit / group_units) * separator_interval_ + qMin(unit % group_units, separator_interval_ - 1);
    if (col >= row_width_) {
        return allow_fuzzy ? row_width_ - 1 : -1;
    }
    return col;
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

// The panels are grids of em-wide columns, so their widths are column
// counts times em_width_. Measuring strings here instead would run the
// text shaper for every cell rectangle computed while painting.

int HexDataSourceView::offsetPixels()
{
    // One pad space before and after.
    return show_offset_ ? offsetChars() * em_width_ : 0;
}

int HexDataSourceView::hexPixels()
{
    // One pad space before and after.
    return show_hex_ ? (DataPrinter::hexChars() + 2) * em_width_ : 0;
}

int HexDataSourceView::asciiPixels()
{
    // Two pad spaces before, one after.
    int ascii_chars = row_width_ + ((row_width_ - 1) / separator_interval_);
    return show_ascii_ ? (ascii_chars + 3) * em_width_ : 0;
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
    if (data_.isEmpty() || line_height_ <= 0) {
        return -1;
    }

    int byte = (verticalScrollBar()->value() + (pos.y() / line_height_)) * row_width_;
    int x = (horizontalScrollBar()->value() * em_width_) + pos.x();

    int col;
    if (show_ascii_ && x >= textPanelX()) {
        col = textColumnAtX(x, allow_fuzzy);
    } else if (show_hex_) {
        col = hexColumnAtX(x, allow_fuzzy);
    } else {
        col = allow_fuzzy ? 0 : -1;
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
