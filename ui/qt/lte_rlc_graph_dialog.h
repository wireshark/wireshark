/* lte_rlc_graph_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LTE_RLC_GRAPH_DIALOG_H
#define LTE_RLC_GRAPH_DIALOG_H

#include "wireshark_dialog.h"
#include <ui/tap-rlc-graph.h>

#include <ui/qt/widgets/qcustomplot.h>

class QMenu;
class QRubberBand;

namespace Ui {
class LteRlcGraphDialog;
}

class LteRlcGraphDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    // TODO: will need to add another constructor option to give channel explicitly,
    // rather than find in currently selected packet, for when launch graph from
    // RLC statistics dialog.
    explicit LteRlcGraphDialog(QWidget &parent, CaptureFile &cf, bool channelKnown);
    ~LteRlcGraphDialog();

    void setChannelInfo(guint16 ueid, guint8 rlcMode,
                        guint16 channelType, guint16 channelId, guint8 direction,
                        bool maybe_empty=false);

signals:
    void goToPacket(int packet_num);

protected:
    void showEvent(QShowEvent *event);
    void keyPressEvent(QKeyEvent *event);

private:
    Ui::LteRlcGraphDialog *ui;
    bool mouse_drags_;
    QRubberBand *rubber_band_;
    QPoint rb_origin_;
    QMenu *ctx_menu_;

    // Data gleaned directly from tapping packets (shared with gtk impl)
    struct rlc_graph graph_;

    // Data
    QMultiMap<double, struct rlc_segment *> time_stamp_map_;
    QMap<double, struct rlc_segment *> sequence_num_map_;

    QCPGraph *base_graph_; // Clickable packets
    QCPGraph *reseg_graph_;
    QCPGraph *acks_graph_;
    QCPGraph *nacks_graph_;
    QCPItemTracer *tracer_;
    guint32 packet_num_;

    void completeGraph(bool may_be_empty=false);

    bool compareHeaders(rlc_segment *seg);

    void findChannel(bool may_fail=false);
    void fillGraph();

    void zoomAxes(bool in);
    void zoomXAxis(bool in);
    void zoomYAxis(bool in);

    void panAxes(int x_pixels, int y_pixels);
    QRectF getZoomRanges(QRect zoom_rect);

    void toggleTracerStyle(bool force_default);

private slots:
    void graphClicked(QMouseEvent *event);
    void mouseMoved(QMouseEvent *event);
    void mouseReleased(QMouseEvent *event);
    void resetAxes();

    void on_dragRadioButton_toggled(bool checked);
    void on_zoomRadioButton_toggled(bool checked);
    void on_resetButton_clicked();
    void on_otherDirectionButton_clicked();

    void on_actionReset_triggered();
    void on_actionZoomIn_triggered();
    void on_actionZoomOut_triggered();
    void on_actionMoveUp10_triggered();
    void on_actionMoveLeft10_triggered();
    void on_actionMoveRight10_triggered();
    void on_actionMoveDown10_triggered();
    void on_actionMoveUp1_triggered();
    void on_actionMoveLeft1_triggered();
    void on_actionMoveRight1_triggered();
    void on_actionMoveDown1_triggered();
    void on_actionDragZoom_triggered();
    void on_actionMoveUp100_triggered();
    void on_actionMoveDown100_triggered();
    void on_actionGoToPacket_triggered();
    void on_actionCrosshairs_triggered();
    void on_actionSwitchDirection_triggered();

    void on_buttonBox_accepted();
};

#endif // LTE_RLC_GRAPH_DIALOG_H

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
