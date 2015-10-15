/* lte_rlc_graph_dialog.cpp
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

#include "lte_rlc_graph_dialog.h"
#include <ui_lte_rlc_graph_dialog.h>

#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>

#include <epan/tvbuff-int.h>
#include <epan/tvbuff.h>
#include <frame_tvbuff.h>

#include "tango_colors.h"

#include <QMenu>
#include <QRubberBand>

#include "qt_ui_utils.h"
#include "wireshark_application.h"
#include "simple_dialog.h"

#include "globals.h"

#include <epan/dissectors/packet-rlc-lte.h>

#include <ui/tap-rlc-graph.h>

// TODO:
// - better handling of zooming (select area like TCP and/or Jim's patch for 1 dimension at a time)
// - get launched from RLC stats for a pre-known channel
// - how to avoid panning or zooming out to -ve (x or y axis)
// - goto packet functionality when click on segments

const QRgb graph_color_ack =         tango_sky_blue_4;    // Blue for ACK lines
const QRgb graph_color_nack =        tango_scarlet_red_3; // Red for NACKs

// Size of selectable packet points in the base graph
const double pkt_point_size_ = 3.0;


// Constructor.
LteRlcGraphDialog::LteRlcGraphDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::LteRlcGraphDialog),
    mouse_drags_(true),
    rubber_band_(NULL)
{
    ui->setupUi(this);

    // XXX Use recent settings instead
    resize(parent.width() * 4 / 5, parent.height() * 3 / 4);

    QCustomPlot *rp = ui->rlcPlot;
    rp->xAxis->setLabel(tr("Time"));
    rp->yAxis->setLabel(tr("Sequence Number"));

    // TODO: don't want all of these...
    ctx_menu_ = new QMenu(this);
    ctx_menu_->addAction(ui->actionZoomIn);
    ctx_menu_->addAction(ui->actionZoomOut);
    ctx_menu_->addAction(ui->actionReset);
    ctx_menu_->addSeparator();
    ctx_menu_->addAction(ui->actionMoveRight10);
    ctx_menu_->addAction(ui->actionMoveLeft10);
    ctx_menu_->addAction(ui->actionMoveUp10);
    ctx_menu_->addAction(ui->actionMoveUp100);
    ctx_menu_->addAction(ui->actionMoveDown10);
    ctx_menu_->addAction(ui->actionMoveDown100);
    ctx_menu_->addAction(ui->actionMoveRight1);
    ctx_menu_->addAction(ui->actionMoveLeft1);
    ctx_menu_->addAction(ui->actionMoveUp1);
    ctx_menu_->addAction(ui->actionMoveDown1);
//    ctx_menu_.addSeparator();
//    ctx_menu_->addAction(ui->actionGoToPacket);
    ctx_menu_->addSeparator();
    ctx_menu_->addAction(ui->actionDragZoom);
//    ctx_menu_->addAction(ui->actionToggleTimeOrigin);
    ctx_menu_->addAction(ui->actionCrosshairs);

    // Zero out this struct.
    memset(&graph_, 0, sizeof(graph_));

    // If no channel chosen already, try to use currently selected frame.
    findChannel();

    // Set window title here.
    if (graph_.channelSet) {
        QString dlg_title = tr("LTE RLC Graph (UE=%1 chan=%2%3 %4 - %5)")
                                 .arg(graph_.ueid)
                                 .arg((graph_.channelType == CHANNEL_TYPE_SRB) ? "SRB" : "DRB")
                                 .arg(graph_.channelId)
                                 .arg((graph_.direction == DIRECTION_UPLINK) ? "UL" : "DL")
                                 .arg((graph_.rlcMode == RLC_UM_MODE) ? "UM" : "AM");
        setWindowTitle(dlg_title);
    }
    else {
        setWindowTitle(tr("LTE RLC Graph - no channel selected"));
    }

    // Set colours/styles for each of the traces on the graph.
    QCustomPlot *sp = ui->rlcPlot;
    base_graph_ = sp->addGraph(); // All: Selectable segments
    base_graph_->setPen(QPen(QBrush(Qt::black), 0.25));

    reseg_graph_ = sp->addGraph();
    reseg_graph_->setPen(QPen(QBrush(Qt::lightGray), 0.25));

    acks_graph_ = sp->addGraph();
    acks_graph_->setPen(QPen(QBrush(graph_color_ack), 1.0));

    nacks_graph_ = sp->addGraph();
    nacks_graph_->setPen(QPen(QBrush(graph_color_nack), 0.25));

    connect(rp, SIGNAL(mousePress(QMouseEvent*)), this, SLOT(graphClicked(QMouseEvent*)));
    connect(rp, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
    connect(rp, SIGNAL(mouseRelease(QMouseEvent*)), this, SLOT(mouseReleased(QMouseEvent*)));

    // Extract the data that the graph can use.
    fillGraph();
}

// Destructor
LteRlcGraphDialog::~LteRlcGraphDialog()
{
    delete ui;
}

// See if the given segment matches the channel this graph is plotting.
bool LteRlcGraphDialog::compareHeaders(rlc_segment *seg)
{
    return compare_rlc_headers(graph_.ueid, graph_.channelType,
                               graph_.channelId, graph_.rlcMode, graph_.direction,
                               seg->ueid, seg->channelType,
                               seg->channelId, seg->rlcMode, seg->direction,
                               seg->isControlPDU);
}

// Look for channel to plot based upon currently selected frame.
void LteRlcGraphDialog::findChannel()
{
    char *err_string = NULL;
    gboolean free_err_string = FALSE;
    rlc_graph_segment_list_free(&graph_);
    if (!rlc_graph_segment_list_get(cap_file_.capFile(), &graph_, graph_.channelSet,
                                    &err_string, &free_err_string)) {
        // Pop up an error box to report error.
        simple_error_message_box("%s", err_string);
        if (free_err_string) {
            g_free(err_string);
        }
    }
}

// Fill in graph data based upon what was read into the rlc_graph struct.
void LteRlcGraphDialog::fillGraph()
{
    QCustomPlot *sp = ui->rlcPlot;

    // We should always have 4 graphs, but cover case if no channel was chosen.
    if (sp->graphCount() < 1) {
        return;
    }

    base_graph_->setLineStyle(QCPGraph::lsNone);       // dot
    reseg_graph_->setLineStyle(QCPGraph::lsNone);      // dot
    acks_graph_->setLineStyle(QCPGraph::lsStepLeft);   // to get step effect...
    nacks_graph_->setLineStyle(QCPGraph::lsNone);      // dot, but bigger.

    // Will show all graphs with data we find.
    for (int i = 0; i < sp->graphCount(); i++) {
        sp->graph(i)->clearData();
        sp->graph(i)->setVisible(true);
    }

    // NACKs are shown bigger than others.
    base_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc, pkt_point_size_));
    reseg_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc, pkt_point_size_));
    acks_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc, pkt_point_size_));
    nacks_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc, pkt_point_size_*2));

    // Map timestamps -> segments in first pass.
    time_stamp_map_.clear();
    for (struct rlc_segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        if (!compareHeaders(seg)) {
            continue;
        }
        double ts = seg->rel_secs + seg->rel_usecs / 1000000.0;

        time_stamp_map_.insertMulti(ts, seg);
    }

    // Now sequence numbers.
    QVector<double> seq_time, seq,
                    reseg_seq_time, reseg_seq,
                    acks_time, acks,
                    nacks_time, nacks;
    for (struct rlc_segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        double ts = seg->rel_secs + seg->rel_usecs / 1000000.0;
        if (compareHeaders(seg)) {
            if (!seg->isControlPDU) {
                // Data
                if (seg->isResegmented) {
                    reseg_seq_time.append(ts);
                    reseg_seq.append(seg->SN);
                }
                else {
                    seq_time.append(ts);
                    seq.append(seg->SN);
                }
            }
            else {
                // Status (ACKs/NACKs)
                acks_time.append(ts);
                acks.append(seg->ACKNo-1);
                for (int n=0; n < seg->noOfNACKs; n++) {
                    nacks_time.append(ts);
                    nacks.append(seg->NACKs[n]);
                }
            }
        }
    }

    // Add the data from the graphs.
    base_graph_->setData(seq_time, seq);
    reseg_graph_->setData(reseg_seq_time, reseg_seq);
    acks_graph_->setData(acks_time, acks);
    nacks_graph_->setData(nacks_time, nacks);

    sp->setEnabled(true);

    // Auto-size...
    mouseMoved(NULL);
    resetAxes();

    // XXX QCustomPlot doesn't seem to draw any sort of focus indicator.
    sp->setFocus();
}

// Copied from TCP graphs, seems like a kludge to get the graph resized immediately after it is built...
void LteRlcGraphDialog::showEvent(QShowEvent *)
{
    resetAxes();
}

// Respond to a key press.
void LteRlcGraphDialog::keyPressEvent(QKeyEvent *event)
{
    int pan_pixels = event->modifiers() & Qt::ShiftModifier ? 1 : 10;

    switch(event->key()) {
    case Qt::Key_Minus:
    case Qt::Key_Underscore:    // Shifted minus on U.S. keyboards
    case Qt::Key_O:             // GTK+
    case Qt::Key_R:
        zoomAxes(false);
        break;
    case Qt::Key_Plus:
    case Qt::Key_Equal:         // Unshifted plus on U.S. keyboards
    case Qt::Key_I:             // GTK+
        zoomAxes(true);
        break;

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

    case Qt::Key_PageUp:
        panAxes(0, 20 * pan_pixels);
        break;
    case Qt::Key_PageDown:
        panAxes(0, -20 * pan_pixels);
        break;

    case Qt::Key_Space:
//        toggleTracerStyle();
        break;

    case Qt::Key_0:
    case Qt::Key_ParenRight:    // Shifted 0 on U.S. keyboards
    case Qt::Key_Home:
        resetAxes();
        break;

    case Qt::Key_G:
//        on_actionGoToPacket_triggered();
        break;
    case Qt::Key_T:
//        on_actionToggleTimeOrigin_triggered();
        break;
    case Qt::Key_Z:
        on_actionDragZoom_triggered();
        break;
    }

    WiresharkDialog::keyPressEvent(event);
}

void LteRlcGraphDialog::zoomAxes(bool in)
{
    QCustomPlot *rp = ui->rlcPlot;
    double h_factor = rp->axisRect()->rangeZoomFactor(Qt::Horizontal);
    double v_factor = rp->axisRect()->rangeZoomFactor(Qt::Vertical);

    if (!in) {
        h_factor = pow(h_factor, -1);
        v_factor = pow(v_factor, -1);
    }

    rp->xAxis->scaleRange(h_factor, rp->xAxis->range().center());
    rp->yAxis->scaleRange(v_factor, rp->yAxis->range().center());
    rp->replot();
}

void LteRlcGraphDialog::panAxes(int x_pixels, int y_pixels)
{
    QCustomPlot *rp = ui->rlcPlot;
    double h_pan = 0.0;
    double v_pan = 0.0;

    h_pan = rp->xAxis->range().size() * x_pixels / rp->xAxis->axisRect()->width();
    v_pan = rp->yAxis->range().size() * y_pixels / rp->yAxis->axisRect()->height();
    // The GTK+ version won't pan unless we're zoomed. Should we do the same here?
    if (h_pan) {
        rp->xAxis->moveRange(h_pan);
        rp->replot();
    }
    if (v_pan) {
        rp->yAxis->moveRange(v_pan);
        rp->replot();
    }
}

// Don't accidentally zoom into a 1x1 rect if you happen to click on the graph
// in zoom mode.
const int min_zoom_pixels_ = 20;
QRectF LteRlcGraphDialog::getZoomRanges(QRect zoom_rect)
{
    QRectF zoom_ranges = QRectF();

    if (zoom_rect.width() < min_zoom_pixels_ && zoom_rect.height() < min_zoom_pixels_) {
        return zoom_ranges;
    }

    QCustomPlot *rp = ui->rlcPlot;
    QRect zr = zoom_rect.normalized();
    QRect ar = rp->axisRect()->rect();
    if (ar.intersects(zr)) {
        QRect zsr = ar.intersected(zr);
        zoom_ranges.setX(rp->xAxis->range().lower
                         + rp->xAxis->range().size() * (zsr.left() - ar.left()) / ar.width());
        zoom_ranges.setWidth(rp->xAxis->range().size() * zsr.width() / ar.width());

        // QRects grow down
        zoom_ranges.setY(rp->yAxis->range().lower
                         + rp->yAxis->range().size() * (ar.bottom() - zsr.bottom()) / ar.height());
        zoom_ranges.setHeight(rp->yAxis->range().size() * zsr.height() / ar.height());
    }
    return zoom_ranges;
}

void LteRlcGraphDialog::graphClicked(QMouseEvent *event)
{
    QCustomPlot *rp = ui->rlcPlot;

    if (event->button() == Qt::RightButton) {
        // XXX We should find some way to get rlcPlot to handle a
        // contextMenuEvent instead.
        ctx_menu_->exec(event->globalPos());
    } else  if (mouse_drags_) {
        if (rp->axisRect()->rect().contains(event->pos())) {
            rp->setCursor(QCursor(Qt::ClosedHandCursor));
        }
//        on_actionGoToPacket_triggered();
    } else {
        if (!rubber_band_) {
            rubber_band_ = new QRubberBand(QRubberBand::Rectangle, rp);
        }
        rb_origin_ = event->pos();
        rubber_band_->setGeometry(QRect(rb_origin_, QSize()));
        rubber_band_->show();
    }
    rp->setFocus();
}

void LteRlcGraphDialog::mouseMoved(QMouseEvent *event)
{
    QCustomPlot *rp = ui->rlcPlot;
    QString hint;
    Qt::CursorShape shape = Qt::ArrowCursor;

    if (event) {
        if (event->buttons().testFlag(Qt::LeftButton)) {
            if (mouse_drags_) {
                shape = Qt::ClosedHandCursor;
            } else {
                shape = Qt::CrossCursor;
            }
        } else if (rp->axisRect()->rect().contains(event->pos())) {
            if (mouse_drags_) {
                shape = Qt::OpenHandCursor;
            } else {
                shape = Qt::CrossCursor;
            }
        }
        rp->setCursor(QCursor(shape));
    }

    if (mouse_drags_) {
//        double ts = 0;
//        packet_num_ = 0;
//        int interval_packet = -1;

//        if (event && tracer_->graph()) {
//            tracer_->setGraphKey(rp->xAxis->pixelToCoord(event->pos().x()));
//            ts = tracer_->position->key();

//            QTreeWidgetItem *ti = ui->graphTreeWidget->topLevelItem(0);
//            IOGraph *iog = NULL;
//            if (ti) {
//                iog = ti->data(name_col_, Qt::UserRole).value<IOGraph *>();
//                interval_packet = iog->packetFromTime(ts);
//            }
//        }

//        if (interval_packet < 0) {
//            hint += tr("Hover over the graph for details.");
//        } else {
//            QString msg = tr("No packets in interval");
//            QString val;
//            if (interval_packet > 0) {
//                packet_num_ = (guint32) interval_packet;
//                msg = tr("%1 %2")
//                        .arg(!file_closed_ ? tr("Click to select packet") : tr("Packet"))
//                        .arg(packet_num_);
//                val = " = " + QString::number(tracer_->position->value(), 'g', 4);
//            }
//            hint += tr("%1 (%2s%3).")
//                    .arg(msg)
//                    .arg(QString::number(ts, 'g', 4))
//                    .arg(val);
//        }
        rp->replot();
    } else {
        if (event && rubber_band_ && rubber_band_->isVisible()) {
            rubber_band_->setGeometry(QRect(rb_origin_, event->pos()).normalized());
            QRectF zoom_ranges = getZoomRanges(QRect(rb_origin_, event->pos()));
            if (zoom_ranges.width() > 0.0 && zoom_ranges.height() > 0.0) {
                hint += tr("Release to zoom, x = %1 to %2, y = %3 to %4")
                        .arg(zoom_ranges.x())
                        .arg(zoom_ranges.x() + zoom_ranges.width())
                        .arg(zoom_ranges.y())
                        .arg(zoom_ranges.y() + zoom_ranges.height());
            } else {
                hint += tr("Unable to select range.");
            }
        } else {
            hint += tr("Click to select a portion of the graph.");
        }
    }

    hint.prepend("<small><i>");
    hint.append("</i></small>");
    ui->hintLabel->setText(hint);
}

void LteRlcGraphDialog::mouseReleased(QMouseEvent *event)
{
    QCustomPlot *rp = ui->rlcPlot;
    if (rubber_band_) {
        rubber_band_->hide();
        if (!mouse_drags_) {
            QRectF zoom_ranges = getZoomRanges(QRect(rb_origin_, event->pos()));
            if (zoom_ranges.width() > 0.0 && zoom_ranges.height() > 0.0) {
                rp->xAxis->setRangeLower(zoom_ranges.x());
                rp->xAxis->setRangeUpper(zoom_ranges.x() + zoom_ranges.width());
                rp->yAxis->setRangeLower(zoom_ranges.y());
                rp->yAxis->setRangeUpper(zoom_ranges.y() + zoom_ranges.height());
                rp->replot();
            }
        }
    } else if (rp->cursor().shape() == Qt::ClosedHandCursor) {
        rp->setCursor(QCursor(Qt::OpenHandCursor));
    }
}

void LteRlcGraphDialog::resetAxes()
{
    QCustomPlot *rp = ui->rlcPlot;

    QCPRange x_range = rp->xAxis->scaleType() == QCPAxis::stLogarithmic ?
                rp->xAxis->range().sanitizedForLogScale() : rp->xAxis->range();

    double pixel_pad = 10.0; // per side

    rp->rescaleAxes(true);
    base_graph_->rescaleValueAxis(false, true);

    double axis_pixels = rp->xAxis->axisRect()->width();
    rp->xAxis->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, x_range.center());

    axis_pixels = rp->yAxis->axisRect()->height();
    rp->yAxis->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, rp->yAxis->range().center());

    rp->replot();
}

void LteRlcGraphDialog::on_actionReset_triggered()
{
    resetAxes();
}

void LteRlcGraphDialog::on_actionZoomIn_triggered()
{
    zoomAxes(true);
}

void LteRlcGraphDialog::on_actionZoomOut_triggered()
{
    zoomAxes(false);
}

void LteRlcGraphDialog::on_actionMoveUp10_triggered()
{
    panAxes(0, 10);
}

void LteRlcGraphDialog::on_actionMoveUp100_triggered()
{
    panAxes(0, 100);
}

void LteRlcGraphDialog::on_actionMoveLeft10_triggered()
{
    panAxes(-10, 0);
}

void LteRlcGraphDialog::on_actionMoveRight10_triggered()
{
    panAxes(10, 0);
}

void LteRlcGraphDialog::on_actionMoveDown10_triggered()
{
    panAxes(0, -10);
}

void LteRlcGraphDialog::on_actionMoveDown100_triggered()
{
    panAxes(0, -100);
}

void LteRlcGraphDialog::on_actionMoveUp1_triggered()
{
    panAxes(0, 1);
}

void LteRlcGraphDialog::on_actionMoveLeft1_triggered()
{
    panAxes(-1, 0);
}

void LteRlcGraphDialog::on_actionMoveRight1_triggered()
{
    panAxes(1, 0);
}

void LteRlcGraphDialog::on_actionMoveDown1_triggered()
{
    panAxes(0, -1);
}

void LteRlcGraphDialog::on_actionDragZoom_triggered()
{
//    if (mouse_drags_) {
//        ui->zoomRadioButton->toggle();
//    } else {
//        ui->dragRadioButton->toggle();
//    }
}


// No need to register tap listeners here.  This is done
// in calls to the common functions in ui/tap-rlc-graph.c

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
