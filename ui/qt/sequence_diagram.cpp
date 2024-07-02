/* sequence_diagram.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "sequence_diagram.h"

#include "epan/addr_resolv.h"
#include "epan/sequence_analysis.h"
#include "epan/column.h"

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/widgets/qcp_axis_ticker_elided.h>
#include "ui/recent.h"

#include <QFont>
#include <QFontMetrics>
#include <QPalette>
#include <QPen>
#include <QPointF>

const int max_comment_em_width_ = 20;

// UML-like network node sequence diagrams.
// https://developer.ibm.com/articles/the-sequence-diagram/

WSCPSeqData::WSCPSeqData() :
  key(0),
  value(NULL)
{
}

WSCPSeqData::WSCPSeqData(double key, struct _seq_analysis_item *value) :
  key(key),
  value(value)
{
}

SequenceDiagram::SequenceDiagram(QCPAxis *keyAxis, QCPAxis *valueAxis, QCPAxis *commentAxis) :
    QCPAbstractPlottable(keyAxis, valueAxis),
    key_axis_(keyAxis),
    value_axis_(valueAxis),
    comment_axis_(commentAxis),
    data_(NULL),
    sainfo_(NULL),
    selected_packet_(0),
    selected_key_(-1.0)
{
    data_ = new WSCPSeqDataMap();
    // xaxis (value): Address
    // yaxis (key): Time
    // yaxis2 (comment): Extra info ("Comment" in GTK+)

//    valueAxis->setAutoTickStep(false);

    /* The comments are not numbers, don't try to pretty print exponentials. */
    commentAxis->setNumberFormat("f");
    QList<QCPAxis *> axes;
    axes << value_axis_ << key_axis_ << comment_axis_;
    QPen no_pen(Qt::NoPen);
    foreach (QCPAxis *axis, axes) {
        QSharedPointer<QCPAxisTicker> ticker(new QCPAxisTickerText);
        axis->setTicker(ticker);
        axis->setSubTickPen(no_pen);
        axis->setTickPen(no_pen);
        axis->setSelectedTickPen(no_pen);
    }

    QSharedPointer<QCPAxisTicker> ticker(new QCPAxisTickerElided(comment_axis_));
    comment_axis_->setTicker(ticker);

    value_axis_->grid()->setVisible(false);

    key_axis_->setRangeReversed(true);
    key_axis_->grid()->setVisible(false);

    comment_axis_->setRangeReversed(true);
    comment_axis_->grid()->setVisible(false);

    QFont comment_font = comment_axis_->tickLabelFont();
    comment_font.setPointSizeF(comment_font.pointSizeF() * 0.8);
    smooth_font_size(comment_font);
    comment_axis_->setTickLabelFont(comment_font);
    comment_axis_->setSelectedTickLabelFont(QFont(comment_font.family(), comment_font.pointSizeF(), QFont::Bold));

    // By default QCPAxisRect auto resizes, which creates some slight but
    // noticeable horizontal movement when scrolling vertically. Prevent that.
    key_axis_->axisRect()->setAutoMargins(QCP::msTop | QCP::msBottom);
    int time_margin = QFontMetrics(key_axis_->tickLabelFont()).horizontalAdvance(get_column_longest_string(COL_CLS_TIME));
    int comment_margin = QFontMetrics(comment_font).height() * (max_comment_em_width_ + 1); // Add 1 as using the exact elided width is slightly too narrow
    key_axis_->axisRect()->setMargins(QMargins(time_margin, 0, comment_margin, 0));

    //             frame_label
    // port_src -----------------> port_dst

//    setTickVectorLabels
    //    valueAxis->setTickLabelRotation(30);
}

SequenceDiagram::~SequenceDiagram()
{
    delete data_;
}

int SequenceDiagram::adjacentPacket(bool next)
{
    int adjacent_packet = -1;
    WSCPSeqDataMap::const_iterator it;

    if (data_->size() < 1) return adjacent_packet;

    if (selected_packet_ < 1) {
        if (next) {
            it = data_->constBegin();
        } else {
            it = data_->constEnd();
            --it;
        }
        selected_key_ = it.value().key;
        return it.value().value->frame_number;
    }

    if (next) {
        for (it = data_->constBegin(); it != data_->constEnd(); ++it) {
            if (it.value().value->frame_number == selected_packet_) {
                ++it;
                if (it != data_->constEnd()) {
                    adjacent_packet = it.value().value->frame_number;
                    selected_key_ = it.value().key;
                }
                break;
            }
        }
    } else {
        it = data_->constEnd();
        --it;
        while (it != data_->constBegin()) {
            uint32_t prev_frame = it.value().value->frame_number;
            --it;
            if (prev_frame == selected_packet_) {
                adjacent_packet = it.value().value->frame_number;
                selected_key_ = it.value().key;
                break;
            }
        }
    }

    return adjacent_packet;
}

void SequenceDiagram::setData(_seq_analysis_info *sainfo)
{
    data_->clear();
    sainfo_ = sainfo;
    if (!sainfo) return;

    double cur_key = 0.0;
    QVector<double> key_ticks, val_ticks;
    QVector<QString> key_labels, val_labels, com_labels;
    char* addr_str;

    for (GList *cur = g_queue_peek_nth_link(sainfo->items, 0); cur; cur = gxx_list_next(cur)) {
        seq_analysis_item_t *sai = gxx_list_data(seq_analysis_item_t *, cur);
        if (sai->display) {
            WSCPSeqData new_data;

            new_data.key = cur_key;
            new_data.value = sai;
            data_->insert(new_data.key, new_data);

            key_ticks.append(cur_key);
            key_labels.append(sai->time_str);

            com_labels.append(sai->comment);

            cur_key++;
        }
    }

    for (unsigned int i = 0; i < sainfo_->num_nodes; i++) {
        val_ticks.append(i);
        addr_str = address_to_display(Q_NULLPTR, &(sainfo_->nodes[i]));
        val_labels.append(addr_str);
        if (i % 2 == 0) {
            val_labels.last().append("\n");
        }

        wmem_free(Q_NULLPTR, addr_str);
    }

    QSharedPointer<QCPAxisTickerText> key_ticker = qSharedPointerCast<QCPAxisTickerText>(keyAxis()->ticker());
    key_ticker->setTicks(key_ticks, key_labels);
    QSharedPointer<QCPAxisTickerText> value_ticker = qSharedPointerCast<QCPAxisTickerText>(valueAxis()->ticker());
    value_ticker->setTicks(val_ticks, val_labels);
    QSharedPointer<QCPAxisTickerText> comment_ticker = qSharedPointerCast<QCPAxisTickerText>(comment_axis_->ticker());
    comment_ticker->setTicks(key_ticks, com_labels);
}

void SequenceDiagram::setSelectedPacket(int selected_packet)
{
    selected_key_ = -1;
    if (selected_packet > 0) {
        selected_packet_ = selected_packet;
    } else {
        selected_packet_ = 0;
    }
    mParentPlot->replot();
}

_seq_analysis_item *SequenceDiagram::itemForPosY(int ypos)
{
    double key_pos = qRound(key_axis_->pixelToCoord(ypos));

    if (key_pos >= 0 && key_pos < data_->size()) {
        return data_->value(key_pos).value;
    }
    return NULL;
}

bool SequenceDiagram::inComment(QPoint pos) const
{
    return pos.x() >= (comment_axis_->axisRect()->right()
                        + comment_axis_->padding()
                        + comment_axis_->tickLabelPadding()
                        + comment_axis_->offset());
}

QString SequenceDiagram::elidedComment(const QString &text) const
{
    QSharedPointer<QCPAxisTickerElided> comment_ticker = qSharedPointerCast<QCPAxisTickerElided>(comment_axis_->ticker());
    return comment_ticker->elidedText(text);
}

double SequenceDiagram::selectTest(const QPointF &pos, bool, QVariant *) const
{
    double key_pos = qRound(key_axis_->pixelToCoord(pos.y()));

    if (key_pos >= 0 && key_pos < data_->size()) {
        return 1.0;
    }

    return -1.0;
}

void SequenceDiagram::draw(QCPPainter *painter)
{
    QPen fg_pen;
    qreal alpha = 0.50;

    // Lifelines (node lines). Will likely be overdrawn below.
    painter->save();
    painter->setOpacity(alpha);
    fg_pen = pen();
    fg_pen.setStyle(Qt::DashLine);
    painter->setPen(fg_pen);
    for (int ll_x = value_axis_->range().lower; ll_x < value_axis_->range().upper; ll_x++) {
        // Only draw where we have arrows.
        if (ll_x < 0 || ll_x >= value_axis_->tickVector().size()) continue;
        QPoint ll_start(coordsToPixels(key_axis_->range().upper, ll_x).toPoint());
        QPoint ll_end(coordsToPixels(key_axis_->range().lower, ll_x).toPoint());
        painter->drawLine(ll_start, ll_end);
    }
    painter->restore();
    fg_pen = pen();

    WSCPSeqDataMap::const_iterator it;
    for (it = data_->constBegin(); it != data_->constEnd(); ++it) {
        double cur_key = it.key();
        seq_analysis_item_t *sai = it.value().value;
        QColor bg_color;

        if (sai->frame_number == selected_packet_) {
            QPalette sel_pal;
            fg_pen.setColor(sel_pal.color(QPalette::HighlightedText));
            bg_color = sel_pal.color(QPalette::Highlight);
            selected_key_ = cur_key;
        } else if ((sai->has_color_filter) && (recent.packet_list_colorize)) {
            fg_pen.setColor(QColor().fromRgb(sai->fg_color));
            bg_color = QColor().fromRgb(sai->bg_color);
        } else {
            fg_pen.setColor(Qt::black);
            bg_color = ColorUtils::sequenceColor(sai->conv_num);
        }

        // Highlighted background
//        painter->save();
        QRect bg_rect(
                    QPoint(coordsToPixels(cur_key - 0.5, value_axis_->range().lower).toPoint()),
                    QPoint(coordsToPixels(cur_key + 0.5, value_axis_->range().upper).toPoint()));
        if (bg_color.isValid()) {
            painter->fillRect(bg_rect, bg_color);
        }
//        painter->restore();

        // Highlighted lifelines
        painter->save();
        QPen hl_pen = fg_pen;
        hl_pen.setStyle(Qt::DashLine);
        painter->setPen(hl_pen);
        painter->setOpacity(alpha);
        for (int ll_x = value_axis_->range().lower; ll_x < value_axis_->range().upper; ll_x++) {
            // Only draw where we have arrows.
            if (ll_x < 0 || ll_x >= value_axis_->tickVector().size()) continue;
            QPoint ll_start(coordsToPixels(cur_key - 0.5, ll_x).toPoint());
            QPoint ll_end(coordsToPixels(cur_key + 0.5, ll_x).toPoint());
            hl_pen.setDashOffset(bg_rect.top() - ll_start.x());
            painter->drawLine(ll_start, ll_end);
        }
        painter->restore();

        if (cur_key < key_axis_->range().lower || cur_key > key_axis_->range().upper) {
            continue;
        }
        if (sai->dst_node > sai->src_node && (sai->dst_node < value_axis_->range().lower || sai->src_node > value_axis_->range().upper)) {
            continue;
        }
        if (sai->src_node > sai->dst_node && (sai->src_node < value_axis_->range().lower || sai->dst_node > value_axis_->range().upper)) {
            continue;
        }

        // Message
        if (pen().style() != Qt::NoPen && pen().color().alpha() != 0) {
            painter->save();

            QFontMetrics cfm(comment_axis_->tickLabelFont());
            double en_w = cfm.height() / 2.0;
            int dir_mul = (sai->src_node < sai->dst_node) ? 1 : -1;
            double ah_size = (cfm.height() / 5) * dir_mul;
            QPoint arrow_start(coordsToPixels(cur_key, sai->src_node).toPoint());
            arrow_start.setY(arrow_start.y() + (en_w / 2));
            QPoint arrow_end(coordsToPixels(cur_key, sai->dst_node).toPoint());
            arrow_end.setY(arrow_start.y());
            QLine arrow_line(arrow_start, arrow_end);
            QPolygon arrow_head;
            arrow_head
                    << QPoint(arrow_end.x() - (ah_size*3), arrow_end.y() - ah_size)
                    << arrow_end
                    << QPoint(arrow_end.x() - (ah_size*3), arrow_end.y() + ah_size);

            painter->setBrush(fg_pen.color());
            painter->setPen(fg_pen);
            painter->drawLine(arrow_line);
            painter->drawPolygon(arrow_head);

            double comment_start = (sai->src_node < sai->dst_node)
                    ? arrow_start.x() : arrow_end.x();
            double arrow_width = (arrow_end.x() - arrow_start.x()) * dir_mul;
            QString arrow_label = cfm.elidedText(sai->frame_label, Qt::ElideRight, arrow_width);
            int arrow_label_width = 0;
            arrow_label_width = cfm.horizontalAdvance(arrow_label);
            QPoint text_pt(comment_start + ((arrow_width - arrow_label_width) / 2),
                          arrow_start.y() - (en_w / 2));

            painter->setFont(comment_axis_->tickLabelFont());
            painter->drawText(text_pt, arrow_label);

            if (sai->port_src && sai->port_dst) {
                int left_x = dir_mul > 0 ? arrow_start.x() : arrow_end.x();
                int right_x = dir_mul > 0 ? arrow_end.x() : arrow_start.x();
                QString port_left = QString::number(dir_mul > 0 ? sai->port_src : sai->port_dst);
                QString port_right = QString::number(dir_mul > 0 ? sai->port_dst : sai->port_src);
                int port_left_width = 0;
                port_left_width = cfm.horizontalAdvance(port_left);
                text_pt = QPoint(left_x - en_w - port_left_width, arrow_start.y() + (en_w / 2));
                painter->drawText(text_pt, port_left);

                text_pt.setX(right_x + en_w);
                painter->drawText(text_pt, port_right);
            }
            painter->restore();
        }
    }
}

void SequenceDiagram::drawLegendIcon(QCPPainter *, const QRectF &) const
{
}

QCPRange SequenceDiagram::getKeyRange(bool &validRange, QCP::SignDomain) const
{
    QCPRange range;
    bool valid = false;

    WSCPSeqDataMap::const_iterator it = data_->constBegin();
    while (it != data_->constEnd()) {
        double cur_key = it.key();
        if (!valid) {
            range.lower = range.upper = cur_key;
            valid = true;
        } else if (cur_key < range.lower) {
            range.lower = cur_key;
        } else if (cur_key > range.upper) {
            range.upper = cur_key;
        }
        ++it;
    }
    validRange = valid;
    return range;
}

QCPRange SequenceDiagram::getValueRange(bool &validRange, QCP::SignDomain, const QCPRange &) const
{
    QCPRange range;
    bool valid = false;

    if (sainfo_) {
        range.lower = 0;
        range.upper = data_->size();
        valid = true;
    }
    validRange = valid;
    return range;
}
