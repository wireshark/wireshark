/* sequence_dialog.cpp
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
#include <ui_sequence_dialog.h>

#include "epan/addr_resolv.h"

#include <wsutil/utf8_entities.h>

#include "wsutil/nstime.h"

#include "sequence_diagram.h"
#include "wireshark_application.h"

#include <QDir>
#include <QFileDialog>
#include <QFontMetrics>
#include <QPoint>

// To do:
// - Add UTF8 to text dump
// - Save to XMI? http://www.umlgraph.org/
// - Time: abs vs delta
// - Hide nodes
// - Clickable time + comments?
// - Incorporate packet comments?
// - Change line_style to seq_type (i.e. draw ACKs dashed)
// - Create WSGraph subclasses with common behavior.
// - Help button and text

SequenceDialog::SequenceDialog(QWidget &parent, CaptureFile &cf, seq_analysis_info_t *sainfo) :
    WiresharkDialog(parent, cf),
    ui(new Ui::SequenceDialog),
    sainfo_(sainfo),
    num_items_(0),
    packet_num_(0),
    node_label_w_(20)
{
    ui->setupUi(this);
    QCustomPlot *sp = ui->sequencePlot;
    setWindowSubtitle(sainfo ? tr("Call Flow") : tr("Flow"));

    if (!sainfo_) {
        sainfo_ = sequence_analysis_info_new();
        sainfo_->type = SEQ_ANALYSIS_ANY;
        sainfo_->all_packets = TRUE;
    } else {
        num_items_ = sequence_analysis_get_nodes(sainfo_);
    }

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

    ctx_menu_.addAction(ui->actionReset);
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionMoveRight10);
    ctx_menu_.addAction(ui->actionMoveLeft10);
    ctx_menu_.addAction(ui->actionMoveUp10);
    ctx_menu_.addAction(ui->actionMoveDown10);
    ctx_menu_.addAction(ui->actionMoveRight1);
    ctx_menu_.addAction(ui->actionMoveLeft1);
    ctx_menu_.addAction(ui->actionMoveUp1);
    ctx_menu_.addAction(ui->actionMoveDown1);
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionGoToPacket);

    ui->showComboBox->blockSignals(true);
    ui->showComboBox->setCurrentIndex(0);
    ui->showComboBox->blockSignals(false);
    ui->addressComboBox->blockSignals(true);
    ui->addressComboBox->setCurrentIndex(0);
    ui->addressComboBox->blockSignals(false);

    QComboBox *fcb = ui->flowComboBox;
    fcb->addItem(ui->actionFlowAny->text(), SEQ_ANALYSIS_ANY);
    fcb->addItem(ui->actionFlowTcp->text(), SEQ_ANALYSIS_TCP);

    ui->flowComboBox->blockSignals(true);
    ui->flowComboBox->setCurrentIndex(sainfo_->type);

    if (sainfo_->type == SEQ_ANALYSIS_VOIP) {
        ui->controlFrame->hide();
    } else {
        ui->flowComboBox->blockSignals(false);
    }

    QPushButton *save_bt = ui->buttonBox->button(QDialogButtonBox::Save);
    save_bt->setText(tr("Save As" UTF8_HORIZONTAL_ELLIPSIS));

    // XXX Use recent settings instead
    resize(parent.width(), parent.height() * 4 / 5);

    connect(ui->horizontalScrollBar, SIGNAL(valueChanged(int)), this, SLOT(hScrollBarChanged(int)));
    connect(ui->verticalScrollBar, SIGNAL(valueChanged(int)), this, SLOT(vScrollBarChanged(int)));
    connect(sp->xAxis2, SIGNAL(rangeChanged(QCPRange)), this, SLOT(xAxisChanged(QCPRange)));
    connect(sp->yAxis, SIGNAL(rangeChanged(QCPRange)), this, SLOT(yAxisChanged(QCPRange)));
    connect(sp, SIGNAL(mousePress(QMouseEvent*)), this, SLOT(diagramClicked(QMouseEvent*)));
    connect(sp, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
    connect(sp, SIGNAL(mouseRelease(QMouseEvent*)), this, SLOT(mouseReleased(QMouseEvent*)));
    connect(this, SIGNAL(goToPacket(int)), seq_diagram_, SLOT(setSelectedPacket(int)));

    disconnect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));

    fillDiagram();
}

SequenceDialog::~SequenceDialog()
{
    if (sainfo_->type != SEQ_ANALYSIS_VOIP) {
        sequence_analysis_info_free(sainfo_);
    }
    delete ui;
}

void SequenceDialog::updateWidgets()
{
}

void SequenceDialog::showEvent(QShowEvent *)
{
    resetAxes();
}

void SequenceDialog::resizeEvent(QResizeEvent *)
{
    resetAxes(true);
}

void SequenceDialog::keyPressEvent(QKeyEvent *event)
{
    int pan_pixels = event->modifiers() & Qt::ShiftModifier ? 1 : 10;

    // XXX - Copy some shortcuts from tcp_stream_dialog.cpp
    switch(event->key()) {
    case Qt::Key_Right:
    case Qt::Key_L:
        panAxes(pan_pixels, 0);
        break;
    case Qt::Key_Left:
    case Qt::Key_H:
        panAxes(-1 * pan_pixels, 0);
        break;
    case Qt::Key_Up:
    case Qt::Key_K:
        panAxes(0, pan_pixels);
        break;
    case Qt::Key_Down:
    case Qt::Key_J:
        panAxes(0, -1 * pan_pixels);
        break;

    case Qt::Key_0:
    case Qt::Key_ParenRight:    // Shifted 0 on U.S. keyboards
    case Qt::Key_R:
    case Qt::Key_Home:
        resetAxes();
        break;

    case Qt::Key_G:
        on_actionGoToPacket_triggered();
        break;
    }

    QDialog::keyPressEvent(event);
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

    if (event->button() == Qt::RightButton) {
        // XXX We should find some way to get sequenceDiagram to handle a
        // contextMenuEvent instead.
        ctx_menu_.exec(event->globalPos());
    } else if (sp->axisRect()->rect().contains(event->pos())) {
        sp->setCursor(QCursor(Qt::ClosedHandCursor));
    }
    on_actionGoToPacket_triggered();
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
        if (!sainfo_) {
            hint += tr("No data");
        } else {
            hint += tr("%Ln node(s)", "", sainfo_->num_nodes) + QString(", ")
                    + tr("%Ln item(s)", "", num_items_);
        }
    }

    hint.prepend("<small><i>");
    hint.append("</i></small>");
    ui->hintLabel->setText(hint);
}

void SequenceDialog::mouseReleased(QMouseEvent *)
{
    if (ui->sequencePlot->cursor().shape() == Qt::ClosedHandCursor) {
        ui->sequencePlot->setCursor(QCursor(Qt::OpenHandCursor));
    }
}

void SequenceDialog::on_buttonBox_accepted()
{
    QString file_name, extension;
    QDir path(wsApp->lastOpenDir());
    QString pdf_filter = tr("Portable Document Format (*.pdf)");
    QString png_filter = tr("Portable Network Graphics (*.png)");
    QString bmp_filter = tr("Windows Bitmap (*.bmp)");
    // Gaze upon my beautiful graph with lossy artifacts!
    QString jpeg_filter = tr("JPEG File Interchange Format (*.jpeg *.jpg)");
    QString ascii_filter = tr("ASCII (*.txt)");

    QString filter = QString("%1;;%2;;%3;;%4")
            .arg(pdf_filter)
            .arg(png_filter)
            .arg(bmp_filter)
            .arg(jpeg_filter);
    if (!file_closed_) {
        filter.append(QString(";;%5").arg(ascii_filter));
    }

    file_name = QFileDialog::getSaveFileName(this, wsApp->windowTitleString(tr("Save Graph As" UTF8_HORIZONTAL_ELLIPSIS)),
                                             path.canonicalPath(), filter, &extension);

    if (file_name.length() > 0) {
        bool save_ok = false;
        if (extension.compare(pdf_filter) == 0) {
            save_ok = ui->sequencePlot->savePdf(file_name);
        } else if (extension.compare(png_filter) == 0) {
            save_ok = ui->sequencePlot->savePng(file_name);
        } else if (extension.compare(bmp_filter) == 0) {
            save_ok = ui->sequencePlot->saveBmp(file_name);
        } else if (extension.compare(jpeg_filter) == 0) {
            save_ok = ui->sequencePlot->saveJpg(file_name);
        } else if (extension.compare(ascii_filter) == 0 && !file_closed_ && sainfo_) {
            save_ok = sequence_analysis_dump_to_file(file_name.toUtf8().constData(), sainfo_, cap_file_.capFile(), 0);
        }
        // else error dialog?
        if (save_ok) {
            path = QDir(file_name);
            wsApp->setLastOpenDir(path.canonicalPath().toUtf8().constData());
        }
    }
}

void SequenceDialog::fillDiagram()
{
    if (!sainfo_ || file_closed_) return;

    QCustomPlot *sp = ui->sequencePlot;

    if (sainfo_->type == SEQ_ANALYSIS_VOIP) {
        seq_diagram_->setData(sainfo_);
    } else {
        seq_diagram_->clearData();
        sequence_analysis_list_free(sainfo_);
        sequence_analysis_list_get(cap_file_.capFile(), sainfo_);
        num_items_ = sequence_analysis_get_nodes(sainfo_);
        seq_diagram_->setData(sainfo_);
    }

    QFontMetrics vfm = QFontMetrics(sp->xAxis2->labelFont());
    char* addr_str;
    node_label_w_ = 0;
    for (guint i = 0; i < sainfo_->num_nodes; i++) {
        addr_str = (char*)address_to_display(NULL, &(sainfo_->nodes[i]));
        int label_w = vfm.width(addr_str);
        if (node_label_w_ < label_w) {
            node_label_w_ = label_w;
        }
        wmem_free(NULL, addr_str);
    }
    node_label_w_ = (node_label_w_ * 3 / 4) + one_em_;

    mouseMoved(NULL);
    resetAxes();

    // XXX QCustomPlot doesn't seem to draw any sort of focus indicator.
    sp->setFocus();
}

void SequenceDialog::panAxes(int x_pixels, int y_pixels)
{
    QCustomPlot *sp = ui->sequencePlot;
    double h_pan = 0.0;
    double v_pan = 0.0;

    h_pan = sp->xAxis2->range().size() * x_pixels / sp->xAxis2->axisRect()->width();
    v_pan = sp->yAxis->range().size() * y_pixels / sp->yAxis->axisRect()->height();
    // The GTK+ version won't pan unless we're zoomed. Should we do the same here?
    if (h_pan) {
        sp->xAxis2->moveRange(h_pan);
        sp->replot();
    }
    if (v_pan) {
        sp->yAxis->moveRange(v_pan);
        sp->replot();
    }
}

void SequenceDialog::resetAxes(bool keep_lower)
{
    if (!sainfo_) return;

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
    ui->horizontalScrollBar->setRange((rmin - 0.5) * 100, (sainfo_->num_nodes - 0.5 - rmin) * 100);
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
    if (!file_closed_ && packet_num_ > 0) {
        emit goToPacket(packet_num_);
    }
}

void SequenceDialog::on_showComboBox_currentIndexChanged(int index)
{
    if (!sainfo_) return;

    if (index == 0) {
        sainfo_->all_packets = TRUE;
    } else {
        sainfo_->all_packets = FALSE;
    }
    fillDiagram();
}

void SequenceDialog::on_flowComboBox_currentIndexChanged(int index)
{
    if (!sainfo_ || sainfo_->type == SEQ_ANALYSIS_VOIP || index < 0) return;

    sainfo_->type = static_cast<seq_analysis_type>(ui->flowComboBox->itemData(index).toInt());
    fillDiagram();
}

void SequenceDialog::on_addressComboBox_currentIndexChanged(int index)
{
    if (!sainfo_) return;

    if (index == 0) {
        sainfo_->any_addr = TRUE;
    } else {
        sainfo_->any_addr = FALSE;
    }
    fillDiagram();
}

void SequenceDialog::on_actionReset_triggered()
{
    on_resetButton_clicked();
}

void SequenceDialog::on_actionMoveRight10_triggered()
{
    panAxes(10, 0);
}

void SequenceDialog::on_actionMoveLeft10_triggered()
{
    panAxes(-10, 0);
}

void SequenceDialog::on_actionMoveUp10_triggered()
{
    panAxes(0, 10);
}

void SequenceDialog::on_actionMoveDown10_triggered()
{
    panAxes(0, -10);
}

void SequenceDialog::on_actionMoveRight1_triggered()
{
    panAxes(1, 0);
}

void SequenceDialog::on_actionMoveLeft1_triggered()
{
    panAxes(-1, 0);
}

void SequenceDialog::on_actionMoveUp1_triggered()
{
    panAxes(0, 1);
}

void SequenceDialog::on_actionMoveDown1_triggered()
{
    panAxes(0, -1);
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
