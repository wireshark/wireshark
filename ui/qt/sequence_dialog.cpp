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

#include "wsutil/nstime.h"

#include <QFontMetrics>

#include <QDebug>

// To do:
// - Fix horizontal scrolling
// - Save as
// - Sequence item labels
// - Scroll bars
// - Selection
// - Keyboard shortcuts
// - ...

SequenceDialog::SequenceDialog(QWidget *parent, capture_file *cf, SequenceType type) :
    QDialog(parent),
    ui(new Ui::SequenceDialog),
    cap_file_(cf)
{
    ui->setupUi(this);
    QCustomPlot *sp = ui->sequencePlot;

    seq_diagram_ = new SequenceDiagram(ui->sequencePlot->yAxis, ui->sequencePlot->xAxis2,
                                       ui->sequencePlot->yAxis2);
    sp->addPlottable(seq_diagram_);

    sp->xAxis->setVisible(false);
    sp->xAxis2->setVisible(true);
    sp->yAxis2->setVisible(true);

    one_em_ = QFontMetrics(sp->yAxis->labelFont()).height();

    sp->setInteractions(QCP::iRangeDrag);

    connect(sp->yAxis, SIGNAL(rangeChanged(QCPRange)), sp->yAxis2, SLOT(setRange(QCPRange)));

    memset (&seq_analysis_, 0, sizeof(seq_analysis_));
    switch (type) {
    case any:
        seq_analysis_.type = SEQ_ANALYSIS_ANY;
        break;
    case tcp:
        seq_analysis_.type = SEQ_ANALYSIS_TCP;
        break;
    case voip:
        seq_analysis_.type = SEQ_ANALYSIS_VOIP;
        break;
    }
    seq_analysis_.all_packets = TRUE;

    if (parent) {
        resize(parent->width(), parent->height() * 4 / 5);
    }

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

void SequenceDialog::fillDiagram()
{
    QCustomPlot *sp = ui->sequencePlot;

    sequence_analysis_list_free(&seq_analysis_);
    sequence_analysis_list_get(cap_file_, &seq_analysis_);
    sequence_analysis_get_nodes(&seq_analysis_);

    seq_diagram_->setData(&seq_analysis_);
//    ui->sequencePlot->rescaleAxes();
    sp->replot();

    resetAxes();
//    tracer_->setGraph(base_graph_);

    // XXX QCustomPlot doesn't seem to draw any sort of focus indicator.
    sp->setFocus();
}

void SequenceDialog::resetAxes(bool keep_lower)
{
    QCustomPlot *sp = ui->sequencePlot;
    double top_pos = -1.0;
    if (keep_lower) {
        top_pos = sp->yAxis->range().lower;
    }

    sp->xAxis->moveRange(sp->xAxis->range().lower * -1);

    double range_ratio = sp->yAxis->axisRect()->height() / one_em_;
    sp->yAxis->setRange(top_pos, range_ratio + top_pos);

    sp->replot();
}

void SequenceDialog::on_resetButton_clicked()
{
    resetAxes();
}
