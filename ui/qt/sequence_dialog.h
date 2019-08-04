/* sequence_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SEQUENCE_DIALOG_H
#define SEQUENCE_DIALOG_H

#include <config.h>

#include <glib.h>

#include "cfile.h"

#include "epan/packet.h"
#include "epan/sequence_analysis.h"

#include <ui/qt/widgets/qcustomplot.h>
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
    void resetView();

    void on_buttonBox_accepted();
    void on_actionGoToPacket_triggered();
    void on_actionGoToNextPacket_triggered() { goToAdjacentPacket(true); }
    void on_actionGoToPreviousPacket_triggered() { goToAdjacentPacket(false); }
    void on_displayFilterCheckBox_toggled(bool checked);
    void on_flowComboBox_activated(int index);
    void on_addressComboBox_activated(int index);
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

    static gboolean addFlowSequenceItem(const void *key, void *value, void *userdata);
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
