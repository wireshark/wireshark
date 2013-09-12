/* tcp_stream_dialog.h
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

#ifndef TCP_STREAM_DIALOG_H
#define TCP_STREAM_DIALOG_H

#include "config.h"

#include <glib.h>

#include <file.h>

#include <epan/dissectors/packet-tcp.h>

#include "ui/tap-tcp-stream.h"

#include "qcustomplot.h"
#include <QDialog>
#include <QRubberBand>

namespace Ui {
class TCPStreamDialog;
}

class TCPStreamDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TCPStreamDialog(QWidget *parent = 0, capture_file *cf = NULL, tcp_graph_type graph_type = GRAPH_TSEQ_STEVENS);
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
    QCPItemTracer *tracer_;
    QRectF axis_bounds_;
    guint32 packet_num_;
    QTransform y_axis_xfrm_;
    bool mouse_drags_;
    QRubberBand *rubber_band_;
    QPoint rb_origin_;

    int num_dsegs_;
    int num_acks_;
    int num_sack_ranges_;

    void fillGraph();
    void resetAxes();
    void fillStevens();
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
    void on_prevStreamPushButton_clicked();
    void on_nextStreamPushButton_clicked();
    void on_otherDirectionButton_clicked();
    void on_dragRadioButton_toggled(bool checked);
    void on_selectRadioButton_toggled(bool checked);
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
