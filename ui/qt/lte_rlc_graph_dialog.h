/* lte_rlc_graph_dialog.h
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

#ifndef LTE_RLC_GRAPH_DIALOG_H
#define LTE_RLC_GRAPH_DIALOG_H

#include "wireshark_dialog.h"
#include <ui/tap-rlc-graph.h>

#include "qcustomplot.h"

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
    explicit LteRlcGraphDialog(QWidget &parent, CaptureFile &cf);
    ~LteRlcGraphDialog();

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
    QMap<double, struct rlc_segment *> time_stamp_map_;
    QMap<double, struct rlc_segment *> sequence_num_map_;

    QCPGraph *base_graph_; // Clickable packets
    QCPGraph *reseg_graph_;
    QCPGraph *acks_graph_;
    QCPGraph *nacks_graph_;

    bool compareHeaders(rlc_segment *seg);

    void findChannel();
    void fillGraph();

    void zoomAxes(bool in);
    void panAxes(int x_pixels, int y_pixels);
    QRectF getZoomRanges(QRect zoom_rect);

private slots:
    void graphClicked(QMouseEvent *event);
    void mouseMoved(QMouseEvent *event);
    void mouseReleased(QMouseEvent *event);
    void resetAxes();

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
