/* sequence_dialog.cpp
 *
 * $Id$
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

#include "sequence_dialog.h"
#include "ui_sequence_dialog.h"

#include "epan/addr_resolv.h"

#include "wsutil/nstime.h"

#include <QFontMetrics>
#include <QPoint>

#include <QDebug>

// To do:
// - Save as
//   - Add UTF8 to text dump
// - Context menu
// - Selection highlighting
// - Keyboard shortcuts
// - ...

SequenceDialog::SequenceDialog(QWidget *parent, capture_file *cf, SequenceType type) :
    QDialog(parent),
    ui(new Ui::SequenceDialog),
    cap_file_(cf),
    num_items_(0),
    packet_num_(0),
    node_label_w_(20)
{
    ui->setupUi(this);
    QCustomPlot *sp = ui->sequencePlot;

    seq_diagram_ = new SequenceDiagram(sp->yAxis, sp->xAxis2, sp->yAxis2);
    sp->addPlottable(seq_diagram_);
    sp->axisRect()->setRangeDragAxes(sp->xAxis2, sp->yAxis);

    sp->xAxis->setVisible(false);
    sp->xAxis->setPadding(0);
    sp->xAxis->setLabelPadding(0);
    sp->xAxis->setTickLabelPadding(0);
    sp->xAxis2->setVisible(true);
    sp->yAxis2->setVisible(true);

    one_em_ = QFontMetrics(sp->yAxis->labelFont()).height();
    ui->horizontalScrollBar->setSingleStep(100 / one_em_);
    ui->verticalScrollBar->setSingleStep(100 / one_em_);

    sp->setInteractions(QCP::iRangeDrag);

    ui->gridLayout->setSpacing(0);
    connect(sp->yAxis, SIGNAL(rangeChanged(QCPRange)), sp->yAxis2, SLOT(setRange(QCPRange)));

    memset (&seq_analysis_, 0, sizeof(seq_analysis_));

    ui->showComboBox->setCurrentIndex(0);
    ui->addressComboBox->setCurrentIndex(0);

    QComboBox *fcb = ui->flowComboBox;
    fcb->addItem(ui->actionFlowAny->text(), SEQ_ANALYSIS_ANY);
    fcb->addItem(ui->actionFlowTcp->text(), SEQ_ANALYSIS_TCP);

    switch (type) {
    case any:
        seq_analysis_.type = SEQ_ANALYSIS_ANY;
        ui->flowComboBox->setCurrentIndex(SEQ_ANALYSIS_ANY);
        break;
    case tcp:
        seq_analysis_.type = SEQ_ANALYSIS_TCP;
        ui->flowComboBox->setCurrentIndex(SEQ_ANALYSIS_TCP);
        break;
    case voip:
        seq_analysis_.type = SEQ_ANALYSIS_VOIP;
        ui->flowComboBox->hide();
        ui->flowLabel->hide();
        break;
    }
    seq_analysis_.all_packets = TRUE;

    if (parent) {
        resize(parent->width(), parent->height() * 4 / 5);
    }

    connect(ui->horizontalScrollBar, SIGNAL(valueChanged(int)), this, SLOT(hScrollBarChanged(int)));
    connect(ui->verticalScrollBar, SIGNAL(valueChanged(int)), this, SLOT(vScrollBarChanged(int)));
    connect(sp->xAxis2, SIGNAL(rangeChanged(QCPRange)), this, SLOT(xAxisChanged(QCPRange)));
    connect(sp->yAxis, SIGNAL(rangeChanged(QCPRange)), this, SLOT(yAxisChanged(QCPRange)));
    connect(sp, SIGNAL(mousePress(QMouseEvent*)), this, SLOT(diagramClicked(QMouseEvent*)));
    connect(sp, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
    connect(sp, SIGNAL(mouseRelease(QMouseEvent*)), this, SLOT(mouseReleased(QMouseEvent*)));

    fillDiagram();
}

SequenceDialog::~SequenceDialog()
{
    delete ui;
}

void SequenceDialog::setCaptureFile(capture_file *cf)
{
    if (!cf) { // We only want to know when the file closes.
        cap_file_ = NULL;
    }
}

void SequenceDialog::showEvent(QShowEvent *event)
{
    Q_UNUSED(event);
    resetAxes();
}

void SequenceDialog::resizeEvent(QResizeEvent *event)
{
    Q_UNUSED(event);
    resetAxes(true);
}

void SequenceDialog::mouseReleaseEvent(QMouseEvent *event)
{
    mouseReleased(event);
}

void SequenceDialog::hScrollBarChanged(int value)
{
    if (qAbs(ui->sequencePlot->xAxis2->range().center()-value/100.0) > 0.01) {
      ui->sequencePlot->xAxis2->setRange(value/100.0, ui->sequencePlot->xAxis2->range().size(), Qt::AlignCenter);
      ui->sequencePlot->replot();
    }
}

void SequenceDialog::vScrollBarChanged(int value)
{
    if (qAbs(ui->sequencePlot->yAxis->range().center()-value/100.0) > 0.01) {
      ui->sequencePlot->yAxis->setRange(value/100.0, ui->sequencePlot->yAxis->range().size(), Qt::AlignCenter);
      ui->sequencePlot->replot();
    }
}

void SequenceDialog::xAxisChanged(QCPRange range)
{
    ui->horizontalScrollBar->setValue(qRound(range.center()*100.0));
    ui->horizontalScrollBar->setPageStep(qRound(range.size()*100.0));
}

void SequenceDialog::yAxisChanged(QCPRange range)
{
    ui->verticalScrollBar->setValue(qRound(range.center()*100.0));
    ui->verticalScrollBar->setPageStep(qRound(range.size()*100.0));
}

void SequenceDialog::diagramClicked(QMouseEvent *event)
{
    QCustomPlot *sp = ui->sequencePlot;

//    if (event->button() == Qt::RightButton) {
//        // XXX We should find some way to get streamPlot to handle a
//        // contextMenuEvent instead.
//        ctx_menu_.exec(event->globalPos());
//    } else  if (mouse_drags_) {
        if (sp->axisRect()->rect().contains(event->pos())) {
            sp->setCursor(QCursor(Qt::ClosedHandCursor));
        }
        on_actionGoToPacket_triggered();
//    } else {
//        if (!rubber_band_) {
//            rubber_band_ = new QRubberBand(QRubberBand::Rectangle, ui->streamPlot);
//        }
//        rb_origin_ = event->pos();
//        rubber_band_->setGeometry(QRect(rb_origin_, QSize()));
//        rubber_band_->show();
//    }
}

void SequenceDialog::mouseMoved(QMouseEvent *event)
{
    QCustomPlot *sp = ui->sequencePlot;
    Qt::CursorShape shape = Qt::ArrowCursor;
    if (event) {
        if (event->buttons().testFlag(Qt::LeftButton)) {
            shape = Qt::ClosedHandCursor;
        } else {
            if (sp->axisRect()->rect().contains(event->pos())) {
                shape = Qt::OpenHandCursor;
            }
        }
    }
    sp->setCursor(QCursor(shape));

    packet_num_ = 0;
    QString hint;
    if (event) {
        seq_analysis_item_t *sai = seq_diagram_->itemForPosY(event->pos().y());
        if (sai) {
            packet_num_ = sai->fd->num;
            hint = QString("Packet %1: %2").arg(packet_num_).arg(sai->comment);
        }
    }

    if (hint.isEmpty()) {
        hint += QString("%1 nodes, %2 items").arg(seq_analysis_.num_nodes).arg(num_items_);
    }

    hint.prepend("<small><i>");
    hint.append("</i></small>");
    ui->hintLabel->setText(hint);
}

void SequenceDialog::mouseReleased(QMouseEvent *event)
{
    Q_UNUSED(event);
    if (ui->sequencePlot->cursor().shape() == Qt::ClosedHandCursor) {
        ui->sequencePlot->setCursor(QCursor(Qt::OpenHandCursor));
    }
}

void SequenceDialog::fillDiagram()
{
    QCustomPlot *sp = ui->sequencePlot;

    sequence_analysis_list_free(&seq_analysis_);
    sequence_analysis_list_get(cap_file_, &seq_analysis_);
    num_items_ = sequence_analysis_get_nodes(&seq_analysis_);

    seq_diagram_->setData(&seq_analysis_);

    QFontMetrics vfm = QFontMetrics(sp->xAxis2->labelFont());
    node_label_w_ = 0;
    for (guint i = 0; i < seq_analysis_.num_nodes; i++) {
        int label_w = vfm.width(get_addr_name(&(seq_analysis_.nodes[i])));
        if (node_label_w_ < label_w) {
            node_label_w_ = label_w;
        }
    }
    node_label_w_ = (node_label_w_ * 3 / 4) + one_em_;

    mouseMoved(NULL);
    resetAxes();

    // XXX QCustomPlot doesn't seem to draw any sort of focus indicator.
    sp->setFocus();
}

void SequenceDialog::resetAxes(bool keep_lower)
{
    QCustomPlot *sp = ui->sequencePlot;
    // Allow space for labels on the top and port numbers on the left.
    double top_pos = -1.0, left_pos = -0.5;
    if (keep_lower) {
        top_pos = sp->yAxis->range().lower;
        left_pos = sp->xAxis2->range().lower;
    }

    double range_ratio = sp->xAxis2->axisRect()->width() / node_label_w_;
    sp->xAxis2->setRange(left_pos, range_ratio + left_pos);

    range_ratio = sp->yAxis->axisRect()->height() / (one_em_ * 1.5);
    sp->yAxis->setRange(top_pos, range_ratio + top_pos);

    double rmin = sp->xAxis2->range().size() / 2;
    ui->horizontalScrollBar->setRange((rmin - 0.5) * 100, (seq_analysis_.num_nodes - 0.5 - rmin) * 100);
    xAxisChanged(sp->xAxis2->range());

    rmin = (sp->yAxis->range().size() / 2);
    ui->verticalScrollBar->setRange((rmin - 1.0) * 100, (num_items_ - 0.5 - rmin) * 100);
    yAxisChanged(sp->yAxis->range());

    sp->replot();
}

void SequenceDialog::on_resetButton_clicked()
{
    resetAxes();
}

void SequenceDialog::on_actionGoToPacket_triggered()
{
    if (cap_file_ && packet_num_ > 0) {
        emit goToPacket(packet_num_);
    }
}

void SequenceDialog::on_showComboBox_currentIndexChanged(int index)
{
    if (index == 0) {
        seq_analysis_.all_packets = TRUE;
    } else {
        seq_analysis_.all_packets = FALSE;
    }

    if (isVisible()) fillDiagram();
}

void SequenceDialog::on_flowComboBox_currentIndexChanged(int index)
{
    if (index < 0) return;
    seq_analysis_.type = static_cast<seq_analysis_type>(ui->flowComboBox->itemData(index).toInt());

    if (isVisible()) fillDiagram();
}

void SequenceDialog::on_addressComboBox_currentIndexChanged(int index)
{
    if (index == 0) {
        seq_analysis_.any_addr = TRUE;
    } else {
        seq_analysis_.any_addr = FALSE;
    }

    if (isVisible()) fillDiagram();
}
