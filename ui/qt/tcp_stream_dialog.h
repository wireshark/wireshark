/* tcp_stream_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TCP_STREAM_DIALOG_H
#define TCP_STREAM_DIALOG_H

#include <config.h>

#include <glib.h>

#include <file.h>

#include <epan/dissectors/packet-tcp.h>

#include "ui/tap-tcp-stream.h"

#include "geometry_state_dialog.h"

#include <ui/qt/widgets/qcustomplot.h>
#include <QMenu>
#include <QRubberBand>
#include <QTimer>

namespace Ui {
class TCPStreamDialog;
class QCPErrorBarsNotSelectable;
}

class QCPErrorBarsNotSelectable : public QCPErrorBars
{
    Q_OBJECT

public:
    explicit QCPErrorBarsNotSelectable(QCPAxis *keyAxis, QCPAxis *valueAxis);
    virtual ~QCPErrorBarsNotSelectable();

    virtual double selectTest(const QPointF &pos, bool onlySelectable, QVariant *details = 0) const Q_DECL_OVERRIDE;
};

class TCPStreamDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit TCPStreamDialog(QWidget *parent = 0, capture_file *cf = NULL, tcp_graph_type graph_type = GRAPH_TSEQ_TCPTRACE);
    ~TCPStreamDialog();

signals:
    void goToPacket(int packet_num);

public slots:
    void setCaptureFile(capture_file *cf);
    void updateGraph();

protected:
    void showEvent(QShowEvent *event);
    void keyPressEvent(QKeyEvent *event);
    void mousePressEvent(QMouseEvent *event);
    void mouseReleaseEvent(QMouseEvent *event);

private:
    Ui::TCPStreamDialog *ui;
    capture_file *cap_file_;
    QMultiMap<double, struct segment *> time_stamp_map_;
    double ts_offset_;
    bool ts_origin_conn_;
    QMap<double, struct segment *> sequence_num_map_;
    double seq_offset_;
    bool seq_origin_zero_;
    struct tcp_graph graph_;
    QCPTextElement *title_;
    QString stream_desc_;
    QCPGraph *base_graph_; // Clickable packets
    QCPGraph *tput_graph_;
    QCPGraph *goodput_graph_;
    QCPGraph *seg_graph_;
    QCPErrorBars *seg_eb_;
    QCPGraph *ack_graph_;
    QCPGraph *sack_graph_;
    QCPErrorBars *sack_eb_;
    QCPGraph *sack2_graph_;
    QCPErrorBars *sack2_eb_;
    QCPGraph *rwin_graph_;
    QCPGraph *dup_ack_graph_;
    QCPGraph *zero_win_graph_;
    QCPItemTracer *tracer_;
    QRectF axis_bounds_;
    guint32 packet_num_;
    QTransform y_axis_xfrm_;
    bool mouse_drags_;
    QRubberBand *rubber_band_;
    QPoint rb_origin_;
    QMenu ctx_menu_;

    class GraphUpdater {
    public:
        GraphUpdater(TCPStreamDialog *dialog) :
            dialog_(dialog),
            graph_update_timer_(NULL),
            reset_axes_(false) {}
        void triggerUpdate(int timeout, bool reset_axes = false);
        void clearPendingUpdate();
        void doUpdate();
        bool hasPendingUpdate() { return graph_update_timer_ != NULL; }
    private:
        TCPStreamDialog *dialog_;
        QTimer *graph_update_timer_;
        bool reset_axes_;
    };
    friend class GraphUpdater;
    GraphUpdater graph_updater_;

    int num_dsegs_;
    int num_acks_;
    int num_sack_ranges_;

    double ma_window_size_;

    void findStream();
    void fillGraph(bool reset_axes = true, bool set_focus = true);
    void showWidgetsForGraphType();
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
    void on_streamNumberSpinBox_editingFinished();
    void on_maWindowSizeSpinBox_valueChanged(double new_ma_size);
    void on_maWindowSizeSpinBox_editingFinished();
    void on_selectSACKsCheckBox_stateChanged(int state);
    void on_otherDirectionButton_clicked();
    void on_dragRadioButton_toggled(bool checked);
    void on_zoomRadioButton_toggled(bool checked);
    void on_bySeqNumberCheckBox_stateChanged(int state);
    void on_showSegLengthCheckBox_stateChanged(int state);
    void on_showThroughputCheckBox_stateChanged(int state);
    void on_showGoodputCheckBox_stateChanged(int state);
    void on_showRcvWinCheckBox_stateChanged(int state);
    void on_showBytesOutCheckBox_stateChanged(int state);
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
    void on_buttonBox_helpRequested();
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
