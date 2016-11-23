/* sequence_dialog.h
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

#ifndef SEQUENCE_DIALOG_H
#define SEQUENCE_DIALOG_H

#include <config.h>

#include <glib.h>

#include "cfile.h"

#include "epan/packet.h"

#include "ui/tap-sequence-analysis.h"

#include "qcustomplot.h"
#include "wireshark_dialog.h"

#include <QMenu>

namespace Ui {
class SequenceDialog;
}

class SequenceDiagram;

class SequenceInfo
{
public:
    SequenceInfo(seq_analysis_info_t *sainfo = NULL);
    seq_analysis_info_t * sainfo() { return sainfo_;}
    void ref() { count_++; }
    void unref() { if (--count_ == 0) delete this; }
private:
    ~SequenceInfo();
    seq_analysis_info_t *sainfo_;
    unsigned int count_;
};

class SequenceDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit SequenceDialog(QWidget &parent, CaptureFile &cf, SequenceInfo *info = NULL);
    ~SequenceDialog();

protected:
    void showEvent(QShowEvent *event);
    void resizeEvent(QResizeEvent *event);
    void keyPressEvent(QKeyEvent *event);

private slots:
    void updateWidgets();
    void hScrollBarChanged(int value);
    void vScrollBarChanged(int value);
    void xAxisChanged(QCPRange range);
    void yAxisChanged(QCPRange range);
    void diagramClicked(QMouseEvent *event);
    void mouseMoved(QMouseEvent *event);
    void mouseWheeled(QWheelEvent *event);

    void fillDiagram();

    void on_buttonBox_accepted();
    void on_resetButton_clicked();
    void on_actionGoToPacket_triggered();
    void on_actionGoToNextPacket_triggered() { goToAdjacentPacket(true); }
    void on_actionGoToPreviousPacket_triggered() { goToAdjacentPacket(false); }
    void on_showComboBox_activated(int index);
    void on_flowComboBox_activated(int index);
    void on_addressComboBox_activated(int index);
    void on_actionReset_triggered();
    void on_actionMoveRight10_triggered();
    void on_actionMoveLeft10_triggered();
    void on_actionMoveUp10_triggered();
    void on_actionMoveDown10_triggered();
    void on_actionMoveRight1_triggered();
    void on_actionMoveLeft1_triggered();
    void on_actionMoveUp1_triggered();
    void on_actionMoveDown1_triggered();
    void on_actionZoomIn_triggered();
    void on_actionZoomOut_triggered();

private:
    Ui::SequenceDialog *ui;
    SequenceDiagram *seq_diagram_;
    SequenceInfo *info_;
    int num_items_;
    guint32 packet_num_;
    double one_em_;
    int sequence_w_;
    QMenu ctx_menu_;
    QCPItemText *key_text_;
    QCPItemText *comment_text_;

    void zoomXAxis(bool in);
    void panAxes(int x_pixels, int y_pixels);
    void resetAxes(bool keep_lower = false);
    void goToAdjacentPacket(bool next);
};

#endif // SEQUENCE_DIALOG_H

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
