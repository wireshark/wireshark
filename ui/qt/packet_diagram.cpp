/* packet_diagram.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "packet_diagram.h"

#include "math.h"

#include "epan/epan.h"
#include "epan/epan_dissect.h"

#include "wsutil/utf8_entities.h"

#include "main_application.h"

#include "ui/qt/main_window.h"
#include "ui/qt/capture_file_dialog.h"
#include "ui/qt/utils/proto_node.h"
#include "ui/qt/utils/variant_pointer.h"
#include "ui/recent.h"

#include <QClipboard>
#include <QContextMenuEvent>
#include <QGraphicsItem>
#include <QMenu>
#include <QStyleOptionGraphicsItem>

#if defined(QT_SVG_LIB) && 0
#include <QBuffer>
#include <QMimeData>
#include <QSvgGenerator>
#endif

// Item offsets and lengths
//#define DEBUG_PACKET_DIAGRAM 1

#ifdef DEBUG_PACKET_DIAGRAM
#include <QDebug>
#endif

// "rems" are root em widths, aka the regular font height, similar to rems in CSS.
class DiagramLayout {
public:
    DiagramLayout() :
        bits_per_row_(32),
        small_font_rems_(0.75),
        bit_width_rems_(1.0),
        padding_rems_(0.5),
        span_mark_offset_rems_(0.2)
    {
        setFont(mainApp->font());
    }

    void setFont(QFont font) {
        regular_font_ = font;
        small_font_ = font;
        small_font_.setPointSize(regular_font_.pointSize() * small_font_rems_);

        QFontMetrics fm(regular_font_);
        root_em_ = fm.height();
    }
    void setShowFields(bool show_fields = false) { recent.gui_packet_diagram_field_values = show_fields; }

    int bitsPerRow() const { return bits_per_row_; }
    const QFont regularFont() const { return regular_font_; }
    const QFont smallFont() const { return small_font_; }
    int bitWidth() const { return root_em_ * bit_width_rems_; }
    int lineHeight() const { return root_em_; }
    int hPadding() const { return root_em_ * padding_rems_; }
    int vPadding() const { return root_em_ * padding_rems_; }
    int spanMarkOffset() const { return root_em_ * span_mark_offset_rems_; }
    int rowHeight() const {
        int rows = recent.gui_packet_diagram_field_values ? 2 : 1;
        return ((lineHeight() * rows) + (vPadding() * 2));
    }
    bool showFields() const { return recent.gui_packet_diagram_field_values; }
private:
    int bits_per_row_;
    double small_font_rems_;
    double bit_width_rems_;
    double padding_rems_;
    double span_mark_offset_rems_; // XXX Make this padding_rems_ / 2 instead?
    QFont regular_font_;
    QFont small_font_;
    int root_em_;
};

class FieldInformationGraphicsItem : public QGraphicsPolygonItem
{
public:
    FieldInformationGraphicsItem(field_info *fi, int start_bit, int fi_length, const DiagramLayout *layout, QGraphicsItem *parent = nullptr) :
        QGraphicsPolygonItem(QPolygonF(), parent),
        finfo_(new FieldInformation(fi)),
        representation_("Unknown"),
        start_bit_(start_bit),
        layout_(layout),
        collapsed_len_(fi_length),
        collapsed_row_(-1)
    {
        Q_ASSERT(layout_);

        for (int idx = 0; idx < NumSpanMarks; idx++) {
            span_marks_[idx] = new QGraphicsLineItem(this);
            span_marks_[idx]->hide();
        }

        int bits_per_row = layout_->bitsPerRow();
        int row1_start = start_bit_ % bits_per_row;
        int bits_remain = fi_length;

        int row1_bits = bits_remain;
        if (bits_remain + row1_start > bits_per_row) {
            row1_bits = bits_per_row - row1_start;
            bits_remain -= row1_bits;
            if (row1_start == 0 && bits_remain >= bits_per_row) {
                // Collapse first row
                bits_remain %= bits_per_row;
                collapsed_row_ = 0;
            }
        } else {
            bits_remain = 0;
        }

        int row2_bits = bits_remain;
        if (bits_remain > bits_per_row) {
            row2_bits = bits_per_row;
            bits_remain -= bits_per_row;
            if (bits_remain > bits_per_row) {
                // Collapse second row
                bits_remain %= bits_per_row;
                collapsed_row_ = 1;
            }
        } else {
            bits_remain = 0;
        }
        int row3_bits = bits_remain;

        collapsed_len_ = row1_bits + row2_bits + row3_bits;

        QRectF rr1, rr2, rr3;
        QRectF row_rect = QRectF(row1_start, 0, row1_bits, 1);
        unit_shape_ = QPolygonF(row_rect);
        rr1 = row_rect;
        unit_tr_ = row_rect;

        if (row2_bits > 0) {
            row_rect = QRectF(0, 1, row2_bits, 1);
            unit_shape_ = unit_shape_.united(QPolygonF(row_rect));
            rr2 = row_rect;
            if (row2_bits > row1_bits) {
                unit_tr_ = row_rect;
            }

            if (row3_bits > 0) {
                row_rect = QRectF(0, 2, row3_bits, 1);
                unit_shape_ = unit_shape_.united(QPolygonF(row_rect));
                rr3 = row_rect;
            }
            QPainterPath pp;
            pp.addPolygon(unit_shape_);
            unit_shape_ = pp.simplified().toFillPolygon();
        }

        updateLayout();

        if (finfo_->isValid()) {
            setToolTip(QString("%1 (%2) = %3")
                       .arg(finfo_->headerInfo().name)
                       .arg(finfo_->headerInfo().abbreviation)
                       .arg(finfo_->toString()));
            setData(Qt::UserRole, VariantPointer<field_info>::asQVariant(finfo_->fieldInfo()));
            representation_ = fi->rep->representation;
        } else {
            setToolTip(QObject::tr("Gap in dissection"));
        }
    }

    ~FieldInformationGraphicsItem()
    {
        delete finfo_;
    }

    int collapsedLength() { return collapsed_len_; }

    void setPos(qreal x, qreal y) {
        QGraphicsPolygonItem::setPos(x, y);
        updateLayout();
    }

    int maxLeftY() {
        qreal rel_len = (start_bit_ % layout_->bitsPerRow()) + collapsed_len_;
        QPointF pt = mapToParent(QPointF(0, ceil(rel_len / layout_->bitsPerRow()) * layout_->rowHeight()));
        return pt.y();
    }

    int maxRightY() {
        qreal rel_len = (start_bit_ % layout_->bitsPerRow()) + collapsed_len_;
        QPointF pt = mapToParent(QPointF(0, floor(rel_len / layout_->bitsPerRow()) * layout_->rowHeight()));
        return pt.y();
    }

    void paint(QPainter *painter, const QStyleOptionGraphicsItem *option, QWidget *) {

        painter->setPen(Qt::NoPen);
        painter->save();
        if (!finfo_->isValid()) {
            QBrush brush = QBrush(option->palette.text().color(), Qt::BDiagPattern);
            painter->setBrush(brush);
        } else if (isSelected()) {
            painter->setBrush(option->palette.highlight().color());
        }
        painter->drawPolygon(polygon());
        painter->restore();

        // Lower and inner right borders
        painter->setPen(option->palette.text().color());
        QPolygonF shape = polygon();
        for (int idx = 1; idx < unit_shape_.size(); idx++) {
            QPointF u_start = unit_shape_[idx - 1];
            QPointF u_end = unit_shape_[idx];
            QPointF start, end;
            bool draw_line = false;

            if (u_start.y() > 0 && u_start.y() == u_end.y()) {
                draw_line = true;
            } else if (u_start.x() > 0 && u_start.x() < layout_->bitsPerRow() && u_start.x() == u_end.x()) {
                draw_line = true;
            }
            if (draw_line) {
                start = shape[idx - 1];
                end = shape[idx];
                painter->drawLine(start, end);
            }
        }

        if (!finfo_->isValid()) {
            return;
        }

        // Field label(s)
        QString label;
        if (finfo_->headerInfo().type == FT_NONE) {
            label = representation_;
        } else {
            label = finfo_->headerInfo().name;
        }
        paintLabel(painter, label, scaled_tr_);

        if (layout_->showFields()) {
            label = finfo_->toString();
            paintLabel(painter, label, scaled_tr_.adjusted(0, scaled_tr_.height(), 0, scaled_tr_.height()));
        }
    }

private:
    enum SpanMark {
        TopLeft,
        BottomLeft,
        TopRight,
        BottomRight,
        NumSpanMarks
    };
    FieldInformation *finfo_;
    QString representation_;
    int start_bit_;
    const DiagramLayout *layout_;
    int collapsed_len_;
    int collapsed_row_;
    QPolygonF unit_shape_;
    QRectF unit_tr_;
    QRectF scaled_tr_;
    QGraphicsLineItem *span_marks_[NumSpanMarks];

    void updateLayout() {
        QTransform xform;

        xform.scale(layout_->bitWidth(), layout_->rowHeight());
        setPolygon(xform.map(unit_shape_));
        scaled_tr_ = xform.mapRect(unit_tr_);
        scaled_tr_.adjust(layout_->hPadding(), layout_->vPadding(), -layout_->hPadding(), -layout_->vPadding());
        scaled_tr_.setHeight(layout_->lineHeight());

        // Collapsed / span marks
        for (int idx = 0; idx < NumSpanMarks; idx++) {
            span_marks_[idx]->hide();
        }
        if (collapsed_row_ >= 0) {
            QRectF bounding_rect = polygon().boundingRect();
            qreal center_y = bounding_rect.top() + (layout_->rowHeight() * collapsed_row_) + (layout_->rowHeight() / 2);
            qreal mark_w = layout_->bitWidth() / 3; // Each mark side to center
            QLineF span_l = QLineF(-mark_w, mark_w / 2, mark_w, -mark_w / 2);
            for (int idx = 0; idx < NumSpanMarks; idx++) {
                QPointF center;
                switch (idx) {
                case TopLeft:
                    center = QPointF(bounding_rect.left(), center_y - layout_->spanMarkOffset());
                    break;
                case BottomLeft:
                    center = QPointF(bounding_rect.left(), center_y + layout_->spanMarkOffset());
                    break;
                case TopRight:
                    center = QPointF(bounding_rect.right(), center_y - layout_->spanMarkOffset());
                    break;
                case BottomRight:
                    center = QPointF(bounding_rect.right(), center_y + layout_->spanMarkOffset());
                    break;
                }

                span_marks_[idx]->setLine(span_l.translated(center));
                span_marks_[idx]->setZValue(zValue() - 0.1);
                span_marks_[idx]->show();
            }
        }
    }

    void paintLabel(QPainter *painter, QString label, QRectF label_rect) {
        QFontMetrics fm = QFontMetrics(layout_->regularFont());

        painter->setFont(layout_->regularFont());
#if (QT_VERSION >= QT_VERSION_CHECK(5, 11, 0))
        int label_w = fm.horizontalAdvance(label);
#else
        int label_w = fm.width(label);
#endif
        if (label_w > label_rect.width()) {
            painter->setFont(layout_->smallFont());
            fm = QFontMetrics(layout_->smallFont());
#if (QT_VERSION >= QT_VERSION_CHECK(5, 11, 0))
            label_w = fm.horizontalAdvance(label);
#else
            label_w = fm.width(label);
#endif
            if (label_w > label_rect.width()) {
                // XXX Use parent+ItemClipsChildrenToShape or setScale instead?
                label = fm.elidedText(label, Qt::ElideRight, label_rect.width());
            }
        }
        painter->drawText(label_rect, Qt::AlignCenter, label);
    }
};

PacketDiagram::PacketDiagram(QWidget *parent) :
    QGraphicsView(parent),
    layout_(new DiagramLayout),
    cap_file_(nullptr),
    root_node_(nullptr),
    selected_field_(nullptr),
    y_pos_(0)
{
    setAccessibleName(tr("Packet diagram"));

    setRenderHint(QPainter::Antialiasing);

    // XXX Move to setMonospaceFont similar to ProtoTree
    layout_->setFont(font());

    connect(mainApp, &MainApplication::appInitialized, this, &PacketDiagram::connectToMainWindow);
    connect(mainApp, &MainApplication::zoomRegularFont, this, &PacketDiagram::setFont);

    resetScene();
}

PacketDiagram::~PacketDiagram()
{
    delete layout_;
}

void PacketDiagram::setRootNode(proto_node *root_node)
{
    // As https://doc.qt.io/qt-5/qgraphicsscene.html#clear says, this
    // "Removes and deletes all items from the scene, but otherwise leaves
    // the state of the scene unchanged."
    // This means that the scene rect grows but doesn't shrink, which is
    // useful in our case because it gives us a cheap way to retain our
    // scroll position between packets.
    scene()->clear();
    selected_field_ = nullptr;
    y_pos_ = 0;

    root_node_ = root_node;
    if (!isVisible() || !root_node) {
        return;
    }

    ProtoNode parent_node(root_node_);
    if (!parent_node.isValid()) {
        return;
    }

    ProtoNode::ChildIterator kids = parent_node.children();
    while (kids.element().isValid())
    {
        proto_node *tl_node = kids.element().protoNode();
        kids.next();

        // Exclude all ("Frame") and nothing
        if (tl_node->finfo->start == 0 && tl_node->finfo->length == (int) tvb_captured_length(cap_file_->edt->tvb)) {
            continue;
        }
        if (tl_node->finfo->length < 1) {
            continue;
        }
        addDiagram(tl_node);
    }
}

void PacketDiagram::clear()
{
    setRootNode(nullptr);
}

void PacketDiagram::setCaptureFile(capture_file *cf)
{
    // For use by the main view, set the capture file which will later have a
    // dissection (EDT) ready.
    // The packet dialog sets a fixed EDT context and MUST NOT use this.
    cap_file_ = cf;

    if (!cf) {
        resetScene();
    }
}

void PacketDiagram::setFont(const QFont &font)
{
    layout_->setFont(font);
    resetScene(false);
}

void PacketDiagram::selectedFieldChanged(FieldInformation *finfo)
{
    setSelectedField(finfo ? finfo->fieldInfo() : nullptr);
}

void PacketDiagram::selectedFrameChanged(QList<int> frames)
{
    if (frames.count() == 1 && cap_file_ && cap_file_->edt && cap_file_->edt->tree) {
        setRootNode(cap_file_->edt->tree);
    } else {
        // Clear the proto tree contents as they have become invalid.
        setRootNode(nullptr);
    }
}

bool PacketDiagram::event(QEvent *event)
{
    switch (event->type()) {
    case QEvent::ApplicationPaletteChange:
        resetScene(false);
        break;
    default:
        break;

    }
    return QGraphicsView::event(event);
}

void PacketDiagram::contextMenuEvent(QContextMenuEvent *event)
{
    if (!event) {
        return;
    }

    QAction *action;
    QMenu *ctx_menu = new QMenu(this);
    ctx_menu->setAttribute(Qt::WA_DeleteOnClose);

    action = ctx_menu->addAction(tr("Show Field Values"));
    action->setCheckable(true);
    action->setChecked(layout_->showFields());
    connect(action, &QAction::toggled, this, &PacketDiagram::showFieldsToggled);

    ctx_menu->addSeparator();

    action = ctx_menu->addAction(tr("Save Diagram As…"));
    connect(action, &QAction::triggered, this, &PacketDiagram::saveAsTriggered);

    action = ctx_menu->addAction(tr("Copy as Raster Image"));
    connect(action, &QAction::triggered, this, &PacketDiagram::copyAsRasterTriggered);

#if defined(QT_SVG_LIB) && !defined(Q_OS_MAC)
    action = ctx_menu->addAction(tr("…as SVG"));
    connect(action, &QAction::triggered, this, &PacketDiagram::copyAsSvgTriggered);
#endif

    ctx_menu->popup(event->globalPos());
}

void PacketDiagram::connectToMainWindow()
{
    MainWindow *main_window = qobject_cast<MainWindow *>(mainApp->mainWindow());
    if (!main_window) {
        return;
    }
    connect(main_window, &MainWindow::setCaptureFile, this, &PacketDiagram::setCaptureFile);
    connect(main_window, &MainWindow::fieldSelected, this, &PacketDiagram::selectedFieldChanged);
    connect(main_window, &MainWindow::framesSelected, this, &PacketDiagram::selectedFrameChanged);

    connect(this, &PacketDiagram::fieldSelected, main_window, &MainWindow::fieldSelected);
}

void PacketDiagram::sceneSelectionChanged()
{
    field_info *sel_fi = nullptr;
    if (! scene()->selectedItems().isEmpty()) {
        sel_fi = VariantPointer<field_info>::asPtr(scene()->selectedItems().first()->data(Qt::UserRole));
    }

    if (sel_fi) {
        FieldInformation finfo(sel_fi, this);
        emit fieldSelected(&finfo);
    } else {
        emit fieldSelected(nullptr);
    }
}

void PacketDiagram::resetScene(bool reset_root)
{
    // As noted in setRootNode, scene()->clear() doesn't clear everything.
    // Do a "hard" clear, which resets our various rects and scroll position.
    if (scene()) {
        delete scene();
    }
    viewport()->update();
    QGraphicsScene *new_scene = new QGraphicsScene();
    setScene(new_scene);
    connect(new_scene, &QGraphicsScene::selectionChanged, this, &PacketDiagram::sceneSelectionChanged);
    setRootNode(reset_root ? nullptr : root_node_);
}

struct DiagramItemSpan {
    field_info *finfo;
    int start_bit;
    int length;
};

void PacketDiagram::addDiagram(proto_node *tl_node)
{
    QGraphicsItem *item;
    QGraphicsSimpleTextItem *t_item;
    int bits_per_row = layout_->bitsPerRow();
    int bit_width = layout_->bitWidth();
    int diag_w = bit_width * layout_->bitsPerRow();
    qreal x = layout_->hPadding();

    // Title
    t_item = scene()->addSimpleText(tl_node->finfo->hfinfo->name);
    t_item->setFont(layout_->regularFont());
    t_item->setPos(0, y_pos_);
    y_pos_ += layout_->lineHeight() + (bit_width / 4);

    int border_top = y_pos_;

    // Bit scale + tick marks
    QList<int> tick_nums;
    for (int tn = 0 ; tn < layout_->bitsPerRow(); tn += 16) {
        tick_nums << tn << tn + 15;
    }
    qreal y_bottom = y_pos_ + bit_width;
    QGraphicsItem *tl_item = scene()->addLine(x, y_bottom, x + diag_w, y_bottom);
    QFontMetrics sfm = QFontMetrics(layout_->smallFont());
#if (QT_VERSION >= QT_VERSION_CHECK(5, 11, 0))
    int space_w = sfm.horizontalAdvance(' ');
#else
    int space_w = sfm.width(' ');
#endif
#ifdef Q_OS_WIN
    // t_item->boundingRect() has a pixel of space on the left on my (gcc)
    // Windows VM.
    int tl_adjust = 1;
#else
    int tl_adjust = 0;
#endif

    for (int tick_n = 0; tick_n < bits_per_row; tick_n++) {
        x = layout_->hPadding() + (tick_n * bit_width);
        qreal y_top = y_pos_ + (tick_n % 8 == 0 ? 0 : bit_width / 2);
        if (tick_n > 0) {
            scene()->addLine(x, y_top, x, y_bottom);
        }

        if (tick_nums.contains(tick_n)) {
            t_item = scene()->addSimpleText(QString::number(tick_n));
            t_item->setFont(layout_->smallFont());
            if (tick_n % 2 == 0) {
                t_item->setPos(x + space_w - tl_adjust, y_pos_);
            } else {
                t_item->setPos(x + bit_width - space_w - t_item->boundingRect().width() - tl_adjust, y_pos_);
            }
            // Does the placement above look funny on your system? Try
            // uncommenting the lines below.
            // QGraphicsRectItem *br_item = scene()->addRect(t_item->boundingRect(), QPen(palette().highlight().color()));
            // br_item->setPos(t_item->pos());
        }
    }
    y_pos_ = y_bottom;
    x = layout_->hPadding();

    // Collect our top-level fields
    int last_start_bit = -1;
    int max_l_y = y_bottom;
    QList<DiagramItemSpan>item_spans;
    for (proto_item *cur_item = tl_node->first_child; cur_item; cur_item = cur_item->next) {
        if (proto_item_is_generated(cur_item) || proto_item_is_hidden(cur_item)) {
            continue;
        }

        field_info *fi = cur_item->finfo;
        int start_bit = ((fi->start - tl_node->finfo->start) * 8) + FI_GET_BITS_OFFSET(fi);
        int length = FI_GET_BITS_SIZE(fi) ? FI_GET_BITS_SIZE(fi) : fi->length * 8;

        if (start_bit <= last_start_bit || length <= 0) {
#ifdef DEBUG_PACKET_DIAGRAM
            qDebug() << "Skipping item" << fi->hfinfo->abbrev << start_bit << last_start_bit << length;
#endif
            continue;
        }
        last_start_bit = start_bit;

        if (item_spans.size() > 0) {
            DiagramItemSpan prev_span = item_spans.last();
            // Get rid of overlaps.
            if (prev_span.start_bit + prev_span.length > start_bit) {
#ifdef DEBUG_PACKET_DIAGRAM
                qDebug() << "Resized prev" << prev_span.finfo->hfinfo->abbrev << prev_span.start_bit << prev_span.length << "->" << start_bit - prev_span.start_bit;
#endif
                prev_span.length = start_bit - prev_span.start_bit;
            }
            if (prev_span.length < 1) {
#ifdef DEBUG_PACKET_DIAGRAM
                qDebug() << "Removed prev" << prev_span.finfo->hfinfo->abbrev << prev_span.start_bit << prev_span.length;
                item_spans.removeLast();
                if (item_spans.size() < 1) {
                    continue;
                }
                prev_span = item_spans.last();
#endif
            }
            // Fill in gaps.
            if (prev_span.start_bit + prev_span.length < start_bit) {
#ifdef DEBUG_PACKET_DIAGRAM
                qDebug() << "Adding gap" << prev_span.finfo->hfinfo->abbrev << prev_span.start_bit << prev_span.length << start_bit;
#endif
                int gap_start = prev_span.start_bit + prev_span.length;
                DiagramItemSpan gap_span = { nullptr, gap_start, start_bit - gap_start };
                item_spans << gap_span;
            }
        }

        DiagramItemSpan item_span = { cur_item->finfo, start_bit, length };
        item_spans << item_span;
    }

    qreal z_value = tl_item->zValue();
    int start_bit = 0;
    for (int idx = 0; idx < item_spans.size(); idx++) {
        DiagramItemSpan *item_span = &item_spans[idx];

        int y_off = (start_bit / bits_per_row) * layout_->rowHeight();
        // Stack each item behind the previous one.
        z_value -= .01;
        FieldInformationGraphicsItem *fi_item = new FieldInformationGraphicsItem(item_span->finfo, start_bit, item_span->length, layout_);
        start_bit += fi_item->collapsedLength();
        fi_item->setPos(x, y_bottom + y_off);
        fi_item->setFlag(QGraphicsItem::ItemIsSelectable);
        fi_item->setAcceptedMouseButtons(Qt::LeftButton);
        fi_item->setZValue(z_value);
        scene()->addItem(fi_item);

        y_pos_ = fi_item->maxRightY();
        max_l_y = fi_item->maxLeftY();
    }

    // Left & right borders
    scene()->addLine(x, border_top, x, max_l_y);
    scene()->addLine(x + diag_w, border_top, x + diag_w, y_pos_);

    // Inter-diagram margin
    y_pos_ = max_l_y + bit_width;

    // Set the proper color. Needed for dark mode on macOS + Qt 5.15.0 at least, possibly other cases.
    foreach (item, scene()->items()) {
        QGraphicsSimpleTextItem *t_item = qgraphicsitem_cast<QGraphicsSimpleTextItem *>(item);
        if (t_item) {
            t_item->setBrush(palette().text().color());
        }
        QGraphicsLineItem *l_item = qgraphicsitem_cast<QGraphicsLineItem *>(item);
        if (l_item) {
            l_item->setPen(palette().text().color());
        }
    }
}

void PacketDiagram::setSelectedField(field_info *fi)
{
    QSignalBlocker blocker(this);
    FieldInformationGraphicsItem *fi_item;

    foreach (QGraphicsItem *item, scene()->items()) {
        if (item->isSelected()) {
            item->setSelected(false);
        }
        if (fi && VariantPointer<field_info>::asPtr(item->data(Qt::UserRole)) == fi) {
            fi_item = qgraphicsitem_cast<FieldInformationGraphicsItem *>(item);
            if (fi_item) {
                fi_item->setSelected(true);
            }
        }
    }
}

QImage PacketDiagram::exportToImage()
{
    // Create a hi-res 2x scaled image.
    int scale = 2;
    QRect rr = QRect(0, 0, sceneRect().size().width() * scale, sceneRect().size().height() * scale);
    QImage raster_diagram = QImage(rr.size(), QImage::Format_ARGB32);
    QPainter raster_painter(&raster_diagram);

    raster_painter.setRenderHint(QPainter::Antialiasing);
    raster_painter.fillRect(rr, palette().base().color());
    scene()->render(&raster_painter);

    raster_painter.end();

    return raster_diagram;
}

#if defined(QT_SVG_LIB) && 0
QByteArray PacketDiagram::exportToSvg()
{
    QRect sr = QRect(0, 0, sceneRect().size().width(), sceneRect().size().height());
    QBuffer svg_buf;
    QSvgGenerator svg_diagram;
    svg_diagram.setSize(sr.size());
    svg_diagram.setViewBox(sr);
    svg_diagram.setOutputDevice(&svg_buf);

    QPainter svg_painter(&svg_diagram);
    svg_painter.fillRect(sr, palette().base().color());
    scene()->render(&svg_painter);

    svg_painter.end();

    return svg_buf.buffer();
}
#endif

void PacketDiagram::showFieldsToggled(bool checked)
{
    layout_->setShowFields(checked);
    setRootNode(root_node_);
    /* Viewport needs to be update to avoid residues being shown */
    viewport()->update();
}

// XXX - We have similar code in tcp_stream_dialog and io_graph_dialog. Should this be a common routine?
void PacketDiagram::saveAsTriggered()
{
    QString file_name, extension;
    QDir path(mainApp->lastOpenDir());
    QString png_filter = tr("Portable Network Graphics (*.png)");
    QString bmp_filter = tr("Windows Bitmap (*.bmp)");
    // Gaze upon my beautiful graph with lossy artifacts!
    QString jpeg_filter = tr("JPEG File Interchange Format (*.jpeg *.jpg)");
    QStringList fl = QStringList() << png_filter << bmp_filter << jpeg_filter;
#if defined(QT_SVG_LIB) && 0
    QString svg_filter = tr("Scalable Vector Graphics (*.svg)");
    fl << svg_filter;
#endif
    QString filter = fl.join(";;");

    file_name = WiresharkFileDialog::getSaveFileName(this, mainApp->windowTitleString(tr("Save Graph As…")),
                                             path.canonicalPath(), filter, &extension);

    if (file_name.length() > 0) {
        bool save_ok = false;
        if (extension.compare(png_filter) == 0) {
            QImage raster_diagram = exportToImage();
            save_ok = raster_diagram.save(file_name, "PNG");
        } else if (extension.compare(bmp_filter) == 0) {
            QImage raster_diagram = exportToImage();
            save_ok = raster_diagram.save(file_name, "BMP");
        } else if (extension.compare(jpeg_filter) == 0) {
            QImage raster_diagram = exportToImage();
            save_ok = raster_diagram.save(file_name, "JPG");
        }
#if defined(QT_SVG_LIB) && 0
        else if (extension.compare(svg_filter) == 0) {
            QByteArray svg_diagram = exportToSvg();
            QFile file(file_name);
            if (file.open(QIODevice::WriteOnly)) {
                save_ok = file.write(svg_diagram) > 0;
                file.close();
            }
        }
#endif
        // else error dialog?
        if (save_ok) {
            mainApp->setLastOpenDirFromFilename(file_name);
        }
    }
}

void PacketDiagram::copyAsRasterTriggered()
{
    QImage raster_diagram = exportToImage();
    mainApp->clipboard()->setImage(raster_diagram);
}

#if defined(QT_SVG_LIB) && !defined(Q_OS_MAC) && 0
void PacketDiagram::copyAsSvgTriggered()
{
    QByteArray svg_ba = exportToSvg();

    // XXX It looks like we have to use/subclass QMacPasteboardMime in
    // order for this to work on macOS.
    // It might be easier to just do "Save As" instead.
    QMimeData *md = new QMimeData();
    md->setData("image/svg+xml", svg_buf);
    mainApp->clipboard()->setMimeData(md);
}
#endif
