/* lte_rlc_graph_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#include <ui/qt/utils/tango_colors.h>

#include <QMenu>
#include <QRubberBand>

#include <wsutil/utf8_entities.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include "main_application.h"
#include "simple_dialog.h"
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <epan/dissectors/packet-rlc-lte.h>

#include <ui/tap-rlc-graph.h>


const QRgb graph_color_ack =         tango_sky_blue_4;    // Blue for ACK lines
const QRgb graph_color_nack =        tango_scarlet_red_3; // Red for NACKs

// Size of selectable packet points in the base graph
const double pkt_point_size_ = 3.0;


// Constructor.
LteRlcGraphDialog::LteRlcGraphDialog(QWidget &parent, CaptureFile &cf, bool channelKnown) :
    WiresharkDialog(parent, cf),
    ui(new Ui::LteRlcGraphDialog),
    mouse_drags_(true),
    rubber_band_(NULL),
    base_graph_(NULL),
    reseg_graph_(NULL),
    acks_graph_(NULL),
    nacks_graph_(NULL),
    tracer_(NULL),
    packet_num_(0)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 3 / 4);

    QCustomPlot *rp = ui->rlcPlot;
    rp->xAxis->setLabel(tr("Time"));
    rp->yAxis->setLabel(tr("Sequence Number"));

    // TODO: couldn't work out how to tell rp->xAxis not to label fractions of a SN...

    ui->dragRadioButton->setChecked(mouse_drags_);

    ctx_menu_ = new QMenu(this);
    ctx_menu_->addAction(ui->actionZoomIn);
    ctx_menu_->addAction(ui->actionZoomInX);
    ctx_menu_->addAction(ui->actionZoomInY);
    ctx_menu_->addAction(ui->actionZoomOut);
    ctx_menu_->addAction(ui->actionZoomOutX);
    ctx_menu_->addAction(ui->actionZoomOutY);
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
    ctx_menu_->addSeparator();
    ctx_menu_->addAction(ui->actionGoToPacket);
    ctx_menu_->addSeparator();
    ctx_menu_->addAction(ui->actionDragZoom);
//    ctx_menu_->addAction(ui->actionToggleTimeOrigin);
    ctx_menu_->addAction(ui->actionCrosshairs);
    ctx_menu_->addSeparator();
    ctx_menu_->addAction(ui->actionSwitchDirection);
    set_action_shortcuts_visible_in_context_menu(ctx_menu_->actions());

    // Zero out this struct.
    memset(&graph_, 0, sizeof(graph_));

    // If channel is known, details will be supplied by setChannelInfo().
    if (!channelKnown) {
        completeGraph();
    }
}

// Destructor
LteRlcGraphDialog::~LteRlcGraphDialog()
{
    delete ui;
}

// Set the channel information that this graph should show.
void LteRlcGraphDialog::setChannelInfo(guint16 ueid, guint8 rlcMode,
                                       guint16 channelType, guint16 channelId, guint8 direction,
                                       bool maybe_empty)
{
    graph_.ueid = ueid;
    graph_.rlcMode = rlcMode;
    graph_.channelType = channelType;
    graph_.channelId = channelId;
    graph_.channelSet = TRUE;
    graph_.direction = direction;

    completeGraph(maybe_empty);
}

// Once channel details are known, complete the graph with details that depend upon the channel.
void LteRlcGraphDialog::completeGraph(bool may_be_empty)
{
    QCustomPlot *rp = ui->rlcPlot;

    // If no channel chosen already, try to use currently selected frame.
    findChannel(may_be_empty);

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

    // Create tracer
    tracer_ = new QCPItemTracer(sp);
    tracer_->setVisible(false);
    toggleTracerStyle(true);

    // Change label on save/export button.
    QPushButton *save_bt = ui->buttonBox->button(QDialogButtonBox::Save);
    save_bt->setText(tr("Save As…"));

    // Don't want to connect again after first time. - causes mouse handlers to get called
    // multiple times.
    if (!may_be_empty) {
        connect(rp, SIGNAL(mousePress(QMouseEvent*)), this, SLOT(graphClicked(QMouseEvent*)));
        connect(rp, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
        connect(rp, SIGNAL(mouseRelease(QMouseEvent*)), this, SLOT(mouseReleased(QMouseEvent*)));
    }
    disconnect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
    this->setResult(QDialog::Accepted);

    // Extract the data that the graph can use.
    fillGraph();
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
void LteRlcGraphDialog::findChannel(bool may_fail)
{
    // Temporarily disconnect mouse move signals.
    QCustomPlot *rp = ui->rlcPlot;
    disconnect(rp, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));

    char *err_string = NULL;

    // Rescan for channel data.
    rlc_graph_segment_list_free(&graph_);
    if (!rlc_graph_segment_list_get(cap_file_.capFile(), &graph_, graph_.channelSet,
                                    &err_string)) {
        if (may_fail) {
            g_free(err_string);
        } else {
            // Pop up an error box to report error.
            simple_error_message_box("%s", err_string);
            g_free(err_string);
            return;
        }
    }

    // Reconnect mouse move signal.
    connect(rp, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
}

// Fill in graph data based upon what was read into the rlc_graph struct.
void LteRlcGraphDialog::fillGraph()
{
    QCustomPlot *sp = ui->rlcPlot;

    // We should always have 4 graphs, but cover case if no channel was chosen.
    if (sp->graphCount() < 1) {
        return;
    }

    tracer_->setGraph(NULL);

    base_graph_->setLineStyle(QCPGraph::lsNone);       // dot
    reseg_graph_->setLineStyle(QCPGraph::lsNone);      // dot
    acks_graph_->setLineStyle(QCPGraph::lsStepLeft);   // to get step effect...
    nacks_graph_->setLineStyle(QCPGraph::lsNone);      // dot, but bigger.

    // Will show all graphs with data we find.
    for (int i = 0; i < sp->graphCount(); i++) {
        sp->graph(i)->data()->clear();
        sp->graph(i)->setVisible(true);
    }

    // N.B. ssDisc is really too slow. TODO: work out how to turn off aliasing, or experiment
    // with ssCustom.  Other styles tried didn't look right.
    // GTK version was speeded up noticibly by turning down aliasing level...
    base_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc, pkt_point_size_));
    reseg_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc, pkt_point_size_));
    acks_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc, pkt_point_size_));
    // NACKs are shown bigger than others.
    nacks_graph_->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc, pkt_point_size_*2));

    // Map timestamps -> segments in first pass.
    time_stamp_map_.clear();
    for (struct rlc_segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        if (!compareHeaders(seg)) {
            continue;
        }
        double ts = seg->rel_secs + seg->rel_usecs / 1000000.0;

        time_stamp_map_.insert(ts, seg);
    }

    // Now sequence numbers.
    QVector<double> seq_time, seq,
                    reseg_seq_time, reseg_seq,
                    acks_time, acks,
                    nacks_time, nacks;
    for (struct rlc_segment *seg = graph_.segments; seg != NULL; seg = seg->next) {
        double ts = seg->rel_secs + (seg->rel_usecs / 1000000.0);
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

    // This is why, in mouseMoved(), we only match the entries
    // corresponding to data segments (base_graph_)...
    tracer_->setGraph(base_graph_);

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
    int pan_pixels = (event->modifiers() & Qt::ShiftModifier) ? 1 : 10;

    switch(event->key()) {
    case Qt::Key_Minus:
    case Qt::Key_Underscore:    // Shifted minus on U.S. keyboards
    case Qt::Key_O:             // GTK+
        zoomAxes(false);
        break;
    case Qt::Key_Plus:
    case Qt::Key_Equal:         // Unshifted plus on U.S. keyboards
    case Qt::Key_I:             // GTK+
        zoomAxes(true);
        break;

    case Qt::Key_X:             // Zoom X axis only
        if (event->modifiers() & Qt::ShiftModifier) {
            zoomXAxis(false);   // upper case X -> Zoom out
        } else {
            zoomXAxis(true);    // lower case x -> Zoom in
        }
        break;
    case Qt::Key_Y:             // Zoom Y axis only
        if (event->modifiers() & Qt::ShiftModifier) {
            zoomYAxis(false);   // upper case Y -> Zoom out
        } else {
            zoomYAxis(true);    // lower case y -> Zoom in
        }
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
        toggleTracerStyle(false);
        break;

    case Qt::Key_0:
    case Qt::Key_ParenRight:    // Shifted 0 on U.S. keyboards
    case Qt::Key_Home:
	case Qt::Key_R:
        resetAxes();
        break;

    case Qt::Key_G:
        on_actionGoToPacket_triggered();
        break;
    case Qt::Key_T:
//        on_actionToggleTimeOrigin_triggered();
        break;
    case Qt::Key_Z:
        on_actionDragZoom_triggered();
        break;

    case Qt::Key_D:
        on_actionSwitchDirection_triggered();
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

    if (in) {
        // Don't want to zoom in *too* far on y axis.
        if (rp->yAxis->range().size() < 10) {
            return;
        }
    }
    else {
        // Don't want to zoom out *too* far on y axis.
        if (rp->yAxis->range().size() > (65536+10)) {
            return;
        }
    }

    rp->xAxis->scaleRange(h_factor, rp->xAxis->range().center());
    rp->yAxis->scaleRange(v_factor, rp->yAxis->range().center());
    rp->replot(QCustomPlot::rpQueuedReplot);
}

void LteRlcGraphDialog::zoomXAxis(bool in)
{
    QCustomPlot *rp = ui->rlcPlot;
    double h_factor = rp->axisRect()->rangeZoomFactor(Qt::Horizontal);

    if (!in) {
        h_factor = pow(h_factor, -1);
    }

    rp->xAxis->scaleRange(h_factor, rp->xAxis->range().center());
    rp->replot(QCustomPlot::rpQueuedReplot);
}

void LteRlcGraphDialog::zoomYAxis(bool in)
{
    QCustomPlot *rp = ui->rlcPlot;
    double v_factor = rp->axisRect()->rangeZoomFactor(Qt::Vertical);

    if (in) {
        // Don't want to zoom in *too* far on y axis.
        if (rp->yAxis->range().size() < 10) {
            return;
        }
    }
    else {
        // Don't want to zoom out *too* far on y axis.
        if (rp->yAxis->range().size() > (65536+10)) {
            return;
        }
    }

    if (!in) {
        v_factor = pow(v_factor, -1);
    }

    rp->yAxis->scaleRange(v_factor, rp->yAxis->range().center());
    rp->replot(QCustomPlot::rpQueuedReplot);
}

void LteRlcGraphDialog::panAxes(int x_pixels, int y_pixels)
{
    QCustomPlot *rp = ui->rlcPlot;
    double h_pan = 0.0;
    double v_pan = 0.0;

    // Don't scroll up beyond max range, or below 0
    if (((y_pixels > 0) && (rp->yAxis->range().upper > 65536)) ||
        ((y_pixels < 0) && (rp->yAxis->range().lower < 0))) {
        return;
    }
    // Don't scroll left beyond 0.  Arguably should be time of first segment.
    if ((x_pixels < 0) && (rp->xAxis->range().lower < 0)) {
        return;
    }

    h_pan = rp->xAxis->range().size() * x_pixels / rp->xAxis->axisRect()->width();
    v_pan = rp->yAxis->range().size() * y_pixels / rp->yAxis->axisRect()->height();

    // The GTK+ version won't pan unless we're zoomed. Should we do the same here?
    if (h_pan) {
        rp->xAxis->moveRange(h_pan);
        rp->replot(QCustomPlot::rpQueuedReplot);
    }
    if (v_pan) {
        rp->yAxis->moveRange(v_pan);
        rp->replot(QCustomPlot::rpQueuedReplot);
    }
}

// Given a selected rect in pixels, work out what this should be in graph units.
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
#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
        ctx_menu_->popup(event->globalPosition().toPoint());
#else
        ctx_menu_->popup(event->globalPos());
#endif
    } else  if (mouse_drags_) {
        if (rp->axisRect()->rect().contains(event->pos())) {
            rp->setCursor(QCursor(Qt::ClosedHandCursor));
        }
        on_actionGoToPacket_triggered();
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
    Qt::CursorShape shape = Qt::ArrowCursor;

    // Set the cursor shape.
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

    // Trying to let 'hint' grow efficiently.  Still pretty slow for a dense graph...
    QString hint;
    hint.reserve(128);
    hint = "<small><i>";

    if (mouse_drags_) {
        double tr_key = tracer_->position->key();
        struct rlc_segment *packet_seg = NULL;
        packet_num_ = 0;

        // XXX If we have multiple packets with the same timestamp tr_key
        // may not return the packet we want. It might be possible to fudge
        // unique keys using nextafter().
        if (event && tracer_->graph() && tracer_->position->axisRect()->rect().contains(event->pos())) {
            packet_seg = time_stamp_map_.value(tr_key, NULL);
        }

        if (!packet_seg) {
            tracer_->setVisible(false);
            hint += "Hover over the graph for details. </i></small>";
            ui->hintLabel->setText(hint);
            ui->rlcPlot->replot(QCustomPlot::rpQueuedReplot);
            return;
        }

        tracer_->setVisible(true);
        packet_num_ = packet_seg->num;
        // N.B. because tracer only looks up entries in base_graph_,
        // we know that packet_seg will be a data segment, so no need to check
        // iscontrolPDU or isResegmented fields.
        hint += tr("%1 %2 (%3s seq %4 len %5)")
                .arg(cap_file_.capFile() ? tr("Click to select packet") : tr("Packet"))
                .arg(packet_num_)
                .arg(QString::number(packet_seg->rel_secs + (packet_seg->rel_usecs / 1000000.0), 'g', 4))
                .arg(packet_seg->SN)
                .arg(packet_seg->pduLength);
        tracer_->setGraphKey(ui->rlcPlot->xAxis->pixelToCoord(event->pos().x()));
        // Redrawing the whole graph is making the update *very* slow!
        // TODO: Is there a way just to draw the parts that may have changed?
        // In the GTK version, we displayed the stored pixbuf and draw temporary items on top...
        rp->replot(QCustomPlot::rpQueuedReplot);

    } else {
        if (event && rubber_band_ && rubber_band_->isVisible()) {
            // Work out zoom based upon selected region (in pixels).
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

    hint.append("</i></small>");
    ui->hintLabel->setText(hint);
}

void LteRlcGraphDialog::mouseReleased(QMouseEvent *event)
{
    QCustomPlot *rp = ui->rlcPlot;
    if (rubber_band_) {
        rubber_band_->hide();
        if (!mouse_drags_) {
            // N.B. work out range to zoom to *before* resetting axes.
            QRectF zoom_ranges = getZoomRanges(QRect(rb_origin_, event->pos()));
            resetAxes();
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

    rp->replot(QCustomPlot::rpQueuedReplot);
}

void LteRlcGraphDialog::on_actionGoToPacket_triggered()
{
    if (tracer_->visible() && cap_file_.capFile() && (packet_num_ > 0)) {
        // Signal to the packetlist which frame we want to show.
        emit goToPacket(packet_num_);
    }
}

void LteRlcGraphDialog::on_actionCrosshairs_triggered()
{
    toggleTracerStyle(false);
}

void LteRlcGraphDialog::toggleTracerStyle(bool force_default)
{
    if (!tracer_->visible() && !force_default) {
        return;
    }

    QPen sp_pen = ui->rlcPlot->graph(0)->pen();
    QCPItemTracer::TracerStyle tstyle = QCPItemTracer::tsCrosshair;
    QPen tr_pen = QPen(tracer_->pen());
    QColor tr_color = sp_pen.color();

    if (force_default || tracer_->style() != QCPItemTracer::tsCircle) {
        tstyle = QCPItemTracer::tsCircle;
        tr_color.setAlphaF(1.0);
        tr_pen.setWidthF(1.5);
    } else {
        tr_color.setAlphaF(0.5);
        tr_pen.setWidthF(1.0);
    }

    tracer_->setStyle(tstyle);
    tr_pen.setColor(tr_color);
    tracer_->setPen(tr_pen);
    ui->rlcPlot->replot();
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

void LteRlcGraphDialog::on_actionSwitchDirection_triggered()
{
    // Channel settings exactly the same, except change direction.
    // N.B. do not fail and close if there are no packets in opposite direction.
    setChannelInfo(graph_.ueid,
                   graph_.rlcMode,
                   graph_.channelType,
                   graph_.channelId,
                   !graph_.direction,
                   true /* maybe_empty */);
}



// Switch between zoom/drag.
void LteRlcGraphDialog::on_actionDragZoom_triggered()
{
    if (mouse_drags_) {
        ui->zoomRadioButton->toggle();
    } else {
        ui->dragRadioButton->toggle();
    }
}

void LteRlcGraphDialog::on_dragRadioButton_toggled(bool checked)
{
    if (checked) {
        mouse_drags_ = true;
    }
    ui->rlcPlot->setInteractions(QCP::iRangeDrag | QCP::iRangeZoom);
}

void LteRlcGraphDialog::on_zoomRadioButton_toggled(bool checked)
{
    if (checked) mouse_drags_ = false;
    ui->rlcPlot->setInteractions(QCP::Interactions());
}

void LteRlcGraphDialog::on_resetButton_clicked()
{
    resetAxes();
}

void LteRlcGraphDialog::on_otherDirectionButton_clicked()
{
    on_actionSwitchDirection_triggered();
}

// Prompt for filename/format to save graph to.
// N.B. Copied from tcp_stream_dialog.cpp
void LteRlcGraphDialog::on_buttonBox_accepted()
{
    QString file_name, extension;
    QDir path(mainApp->lastOpenDir());
    QString pdf_filter = tr("Portable Document Format (*.pdf)");
    QString png_filter = tr("Portable Network Graphics (*.png)");
    QString bmp_filter = tr("Windows Bitmap (*.bmp)");
    // Gaze upon my beautiful graph with lossy artifacts!
    QString jpeg_filter = tr("JPEG File Interchange Format (*.jpeg *.jpg)");
    QString filter = QString("%1;;%2;;%3;;%4")
            .arg(pdf_filter)
            .arg(png_filter)
            .arg(bmp_filter)
            .arg(jpeg_filter);

    file_name = WiresharkFileDialog::getSaveFileName(this, mainApp->windowTitleString(tr("Save Graph As…")),
                                             path.canonicalPath(), filter, &extension);

    if (file_name.length() > 0) {
        bool save_ok = false;
        if (extension.compare(pdf_filter) == 0) {
            save_ok = ui->rlcPlot->savePdf(file_name);
        } else if (extension.compare(png_filter) == 0) {
            save_ok = ui->rlcPlot->savePng(file_name);
        } else if (extension.compare(bmp_filter) == 0) {
            save_ok = ui->rlcPlot->saveBmp(file_name);
        } else if (extension.compare(jpeg_filter) == 0) {
            save_ok = ui->rlcPlot->saveJpg(file_name);
        }
        // else error dialog?
        if (save_ok) {
            mainApp->setLastOpenDirFromFilename(file_name);
        }
    }
}


// No need to register tap listeners here.  This is done
// in calls to the common functions in ui/tap-rlc-graph.c
