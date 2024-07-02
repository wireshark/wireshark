/** @file
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

#include "cfile.h"

#include "epan/packet.h"
#include "epan/sequence_analysis.h"

#include <ui/qt/widgets/qcustomplot.h>
#include "wireshark_dialog.h"
#include "rtp_stream_dialog.h"

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
    explicit SequenceDialog(QWidget &parent, CaptureFile &cf, SequenceInfo *info = NULL, bool voipFeatures = false);
    ~SequenceDialog();

protected:
    bool event(QEvent *event);
    void showEvent(QShowEvent *event);
    void resizeEvent(QResizeEvent *event);
    void keyPressEvent(QKeyEvent *event);

signals:
    void rtpStreamsDialogSelectRtpStreams(QVector<rtpstream_id_t *> stream_infos);
    void rtpStreamsDialogDeselectRtpStreams(QVector<rtpstream_id_t *> stream_infos);
    void rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *> stream_ids);

private slots:
    void updateWidgets();
    void hScrollBarChanged(int value);
    void vScrollBarChanged(int value);
    void xAxisChanged(QCPRange range);
    void yAxisChanged(QCPRange range);
    void showContextMenu(const QPoint &pos);
    void diagramClicked(QMouseEvent *event);
    void axisDoubleClicked(QCPAxis *axis, QCPAxis::SelectablePart part, QMouseEvent *event);
    void mouseReleased(QMouseEvent *event);
    void mouseMoved(QMouseEvent *event);
    void mouseWheeled(QWheelEvent *event);

    void fillDiagram();
    void resetView();
    void exportDiagram();
    void layoutAxisLabels();

    void addressChanged(int index);
    void displayFilterCheckBoxToggled(bool checked);

    void on_buttonBox_clicked(QAbstractButton *button);
    void on_actionGoToPacket_triggered();
    void on_actionGoToNextPacket_triggered() { goToAdjacentPacket(true); }
    void on_actionGoToPreviousPacket_triggered() { goToAdjacentPacket(false); }
    void on_flowComboBox_activated(int index);
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
    void on_actionSelectRtpStreams_triggered();
    void on_actionDeselectRtpStreams_triggered();
    void on_buttonBox_helpRequested();

    void rtpPlayerReplace();
    void rtpPlayerAdd();
    void rtpPlayerRemove();

private:
    Ui::SequenceDialog *ui;
    SequenceDiagram *seq_diagram_;
    SequenceInfo *info_;
    int num_items_;
    uint32_t packet_num_;
    double one_em_;
    int sequence_w_;
    bool axis_pressed_;
    QPushButton *reset_button_;
    QToolButton *player_button_;
    QPushButton *export_button_;
    QMenu ctx_menu_;
    QCPItemText *key_text_;
    QCPItemText *comment_text_;
    seq_analysis_item_t *current_rtp_sai_selected_;     // Used for passing current sai to rtp processing
    seq_analysis_item_t *current_rtp_sai_hovered_;     // Used for passing current sai to rtp processing
    QPointer<RtpStreamDialog> rtp_stream_dialog_;       // Singleton pattern used
    bool voipFeaturesEnabled;

    void enableVoIPFeatures();
    void zoomXAxis(bool in);
    void panAxes(int x_pixels, int y_pixels);
    void resetAxes(bool keep_lower = false);
    void goToAdjacentPacket(bool next);

    static bool addFlowSequenceItem(const void *key, void *value, void *userdata);

    void processRtpStream(bool select);
    QVector<rtpstream_id_t *>getSelectedRtpIds();
};

#endif // SEQUENCE_DIALOG_H
