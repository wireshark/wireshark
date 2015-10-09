/* tcp_stream_dialog.h
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

#ifndef TCP_STREAM_DIALOG_H
#define TCP_STREAM_DIALOG_H

#include <config.h>

#include <glib.h>

#include <file.h>

#include <epan/dissectors/packet-tcp.h>

#include "ui/tap-tcp-stream.h"

#include "qcustomplot.h"
#include <QDialog>
#include <QMenu>
#include <QRubberBand>

namespace Ui {
class TCPStreamDialog;
}

class TCPStreamDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TCPStreamDialog(QWidget *parent = 0, capture_file *cf = NULL, tcp_graph_type graph_type = GRAPH_TSEQ_TCPTRACE);
    ~TCPStreamDialog();

signals:
    void goToPacket(int packet_num);

public slots:
    void setCaptureFile(capture_file *cf);

protected:
    void showEvent(QShowEvent *event);
    void keyPressEvent(QKeyEvent *event);
    void mouseReleaseEvent(QMouseEvent *event);

private:
    Ui::TCPStreamDialog *ui;
    capture_file *cap_file_;
    QMap<double, struct segment *> time_stamp_map_;
    double ts_offset_;
    bool ts_origin_conn_;
    QMap<double, struct segment *> sequence_num_map_;
    double seq_offset_;
    bool seq_origin_zero_;
    struct tcp_graph graph_;
    QCPPlotTitle *title_;
    QString stream_desc_;
    QCPGraph *base_graph_; // Clickable packets
    QCPGraph *tput_graph_;
    QCPGraph *seg_graph_;
    QCPGraph *ack_graph_;
    QCPGraph *rwin_graph_;
    QCPItemTracer *tracer_;
    QRectF axis_bounds_;
    guint32 packet_num_;
    QTransform y_axis_xfrm_;
    bool mouse_drags_;
    QRubberBand *rubber_band_;
    QPoint rb_origin_;
    QMenu ctx_menu_;

    int num_dsegs_;
    int num_acks_;
    int num_sack_ranges_;

    void findStream();
    void fillGraph();
    void zoomAxes(bool in);
    void zoomXAxis(bool in);
    void zoomYAxis(bool in);
    void panAxes(int x_pixels, int y_pixels);
    void resetAxes();
    void fillStevens();
    void fillTcptrace();
    void fillThroughput();
    void fillRoundTripTime();
    void fillWindowScale();
    QString streamDescription();
    bool compareHeaders(struct segment *seg);
    void toggleTracerStyle(bool force_default = false);
    QRectF getZoomRanges(QRect zoom_rect);

private slots:
    void graphClicked(QMouseEvent *event);
    void axisClicked(QCPAxis *axis, QCPAxis::SelectablePart part, QMouseEvent *event);
    void mouseMoved(QMouseEvent *event);
    void mouseReleased(QMouseEvent *event);
    void transformYRange(const QCPRange &y_range1);
    void on_buttonBox_accepted();
    void on_graphTypeComboBox_currentIndexChanged(int index);
    void on_resetButton_clicked();
    void on_streamNumberSpinBox_valueChanged(int new_stream);
    void on_otherDirectionButton_clicked();
    void on_dragRadioButton_toggled(bool checked);
    void on_zoomRadioButton_toggled(bool checked);
    void on_actionZoomIn_triggered();
    void on_actionZoomInX_triggered();
    void on_actionZoomInY_triggered();
    void on_actionZoomOut_triggered();
    void on_actionZoomOutX_triggered();
    void on_actionZoomOutY_triggered();
    void on_actionReset_triggered();
    void on_actionMoveRight10_triggered();
    void on_actionMoveLeft10_triggered();
    void on_actionMoveUp10_triggered();
    void on_actionMoveDown10_triggered();
    void on_actionMoveRight1_triggered();
    void on_actionMoveLeft1_triggered();
    void on_actionMoveUp1_triggered();
    void on_actionMoveDown1_triggered();
    void on_actionNextStream_triggered();
    void on_actionPreviousStream_triggered();
    void on_actionSwitchDirection_triggered();
    void on_actionGoToPacket_triggered();
    void on_actionDragZoom_triggered();
    void on_actionToggleSequenceNumbers_triggered();
    void on_actionToggleTimeOrigin_triggered();
    void on_actionRoundTripTime_triggered();
    void on_actionThroughput_triggered();
    void on_actionStevens_triggered();
    void on_actionTcptrace_triggered();
    void on_actionWindowScaling_triggered();
};

#endif // TCP_STREAM_DIALOG_H

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
