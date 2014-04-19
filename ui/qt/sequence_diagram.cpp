/* sequence_diagram.cpp
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

#include "sequence_diagram.h"

#include "epan/addr_resolv.h"

#include "qt_ui_utils.h"

#include <QFont>
#include <QFontMetrics>
#include <QPalette>
#include <QPen>
#include <QPointF>

#include <QDebug>

const int max_comment_em_width_ = 20;

// UML-like network node sequence diagrams.
// http://www.ibm.com/developerworks/rational/library/3101.html

WSCPSeqData::WSCPSeqData() :
  key(0),
  value(NULL)
{
}

WSCPSeqData::WSCPSeqData(double key, seq_analysis_item_t *value) :
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
    selected_packet_(0)
{
    data_ = new WSCPSeqDataMap();
    // xaxis (value): Address
    // yaxis (key): Time
    // yaxis2 (comment): Extra info ("Comment" in GTK+)

//    valueAxis->setAutoTickStep(false);
    QList<QCPAxis *> axes;
    axes << value_axis_ << key_axis_ << comment_axis_;
    foreach (QCPAxis *axis, axes) {
        axis->setAutoTicks(false);
        axis->setTickStep(1.0);
        axis->setAutoTickLabels(false);
        axis->setTicks(false);
        axis->setBasePen(QPen(Qt::NoPen));
    }

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
    //             frame_label
    // port_src -----------------> port_dst

//    setTickVectorLabels
    //    valueAxis->setTickLabelRotation(30);
}

void SequenceDiagram::setData(seq_analysis_info_t *sainfo)
{
    data_->clear();

    WSCPSeqData new_data;
    double cur_key = 0.0;
    QVector<double> key_ticks, val_ticks;
    QVector<QString> key_labels, val_labels, com_labels;
    QFontMetrics com_fm(comment_axis_->tickLabelFont());
    int elide_w = com_fm.height() * max_comment_em_width_;

    for (GList *cur = g_list_first(sainfo->list); cur; cur = g_list_next(cur)) {
        seq_analysis_item_t *sai = (seq_analysis_item_t *) cur->data;

        new_data.key = cur_key;
        new_data.value = sai;
        data_->insertMulti(new_data.key, new_data);

        key_ticks.append(cur_key);
        key_labels.append(sai->time_str);

        com_labels.append(com_fm.elidedText(sai->comment, Qt::ElideRight, elide_w));

        cur_key++;
    }
    sainfo_ = sainfo;

    for (unsigned int i = 0; i < sainfo_->num_nodes; i++) {
        val_ticks.append(i);
        val_labels.append(ep_address_to_display(&(sainfo_->nodes[i])));
        if (i % 2 == 0) {
            val_labels.last().append("\n");
        }
    }
    keyAxis()->setTickVector(key_ticks);
    keyAxis()->setTickVectorLabels(key_labels);
    valueAxis()->setTickVector(val_ticks);
    valueAxis()->setTickVectorLabels(val_labels);
    comment_axis_->setTickVector(key_ticks);
    comment_axis_->setTickVectorLabels(com_labels);
}

void SequenceDiagram::setSelectedPacket(int selected_packet)
{
    if (selected_packet > 0) {
        selected_packet_ = selected_packet;
    } else {
        selected_packet_ = 0;
    }
    mParentPlot->replot();
}

seq_analysis_item_t *SequenceDiagram::itemForPosY(int ypos)
{
    double key_pos = qRound(key_axis_->pixelToCoord(ypos));

    if (key_pos >= 0 && key_pos < data_->size()) {
        return data_->value(key_pos).value;
    }
    return NULL;
}

double SequenceDiagram::selectTest(const QPointF &pos, bool onlySelectable, QVariant *details) const
{
    Q_UNUSED(details);
    Q_UNUSED(onlySelectable);

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

    // Lifelines (node lines)
    painter->save();
    painter->setOpacity(alpha);
    fg_pen = mainPen();
    fg_pen.setStyle(Qt::DashLine);
    painter->setPen(fg_pen);
    for (int ll_x = value_axis_->range().lower; ll_x < value_axis_->range().upper; ll_x++) {
        QPoint ll_start(coordsToPixels(key_axis_->range().upper, ll_x).toPoint());
        QPoint ll_end(coordsToPixels(key_axis_->range().lower, ll_x).toPoint());
        painter->drawLine(ll_start, ll_end);
    }
    painter->restore();
    fg_pen = mainPen();

    WSCPSeqDataMap::const_iterator it;
    for (it = data_->constBegin(); it != data_->constEnd(); ++it) {
        double cur_key = it.key();
        seq_analysis_item_t *sai = (seq_analysis_item_t *) it.value().value;
        QPen fg_pen(mainPen());

        if (sai->fd->num == selected_packet_) {
            // Highlighted background
            painter->save();
            QRect bg_rect(
                        QPoint(coordsToPixels(cur_key - 0.5, value_axis_->range().lower).toPoint()),
                        QPoint(coordsToPixels(cur_key + 0.5, value_axis_->range().upper).toPoint()));
            QPalette sel_pal;
            painter->fillRect(bg_rect, sel_pal.brush(QPalette::Highlight));
            fg_pen.setColor(sel_pal.color(QPalette::HighlightedText));

            // Highlighted lifelines
            painter->save();
            QPen hl_pen = fg_pen;
            hl_pen.setStyle(Qt::DashLine);
            painter->setPen(hl_pen);
            painter->setOpacity(alpha);
            for (int ll_x = value_axis_->range().lower; ll_x < value_axis_->range().upper; ll_x++) {
                QPoint ll_start(coordsToPixels(cur_key - 0.5, ll_x).toPoint());
                QPoint ll_end(coordsToPixels(cur_key + 0.5, ll_x).toPoint());
                hl_pen.setDashOffset(bg_rect.top() - ll_start.x());
                painter->drawLine(ll_start, ll_end);
            }
            painter->restore();

            painter->restore();
        }

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
        if (mainPen().style() != Qt::NoPen && mainPen().color().alpha() != 0) {
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
            QPoint text_pt(comment_start + ((arrow_width - cfm.width(arrow_label)) / 2),
                          arrow_start.y() - (en_w / 2));

            painter->setFont(comment_axis_->tickLabelFont());
            painter->drawText(text_pt, arrow_label);

            if (sai->port_src && sai->port_dst) {
                QString port_num = QString::number(sai->port_src);
                text_pt = QPoint(arrow_start.x() - en_w - (cfm.width(port_num) * dir_mul),
                                arrow_start.y() + (en_w / 2));
                painter->drawText(text_pt, port_num);

                port_num = QString::number(sai->port_dst);
                text_pt.setX(arrow_end.x() - en_w + (cfm.width(port_num) * dir_mul));
                painter->drawText(text_pt, port_num);
            }
            painter->restore();
        }
    }
}

void SequenceDiagram::drawLegendIcon(QCPPainter *painter, const QRectF &rect) const
{
    Q_UNUSED(painter);
    Q_UNUSED(rect);
}

QCPRange SequenceDiagram::getKeyRange(bool &validRange, QCPAbstractPlottable::SignDomain inSignDomain) const
{
    Q_UNUSED(inSignDomain);
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

QCPRange SequenceDiagram::getValueRange(bool &validRange, QCPAbstractPlottable::SignDomain inSignDomain) const
{
    Q_UNUSED(inSignDomain);
    QCPRange range;
    bool valid = false;

    if (sainfo_) {
        range.lower = 0;
        range.upper = sainfo_->num_nodes;
        valid = true;
    }
    validRange = valid;
    return range;
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
