/* rtp_stream_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTP_STREAM_DIALOG_H
#define RTP_STREAM_DIALOG_H

#include "wireshark_dialog.h"

#include "ui/rtp_stream.h"
#include "rtp_player_dialog.h"

#include <QAbstractButton>
#include <QMenu>

namespace Ui {
class RtpStreamDialog;
}

class RtpStreamDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit RtpStreamDialog(QWidget &parent, CaptureFile &cf);
    ~RtpStreamDialog();
    void selectRtpStream(QVector<rtpstream_id_t *> stream_ids);
    void deselectRtpStream(QVector<rtpstream_id_t *> stream_ids);

signals:
    // Tells the packet list to redraw. An alternative might be to add a
    // cf_packet_marked callback to file.[ch] but that's synchronous and
    // might incur too much overhead.
    void packetsMarked();
    void updateFilter(QString filter, bool force = false);
    void goToPacket(int packet_num);
    void rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_info_t *> stream_infos);
    void rtpPlayerDialogAddRtpStreams(QVector<rtpstream_info_t *> stream_infos);
    void rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_info_t *> stream_infos);
    void rtpAnalysisDialogReplaceRtpStreams(QVector<rtpstream_id_t *> stream_infos);
    void rtpAnalysisDialogAddRtpStreams(QVector<rtpstream_id_t *> stream_infos);
    void rtpAnalysisDialogRemoveRtpStreams(QVector<rtpstream_id_t *> stream_infos);

public slots:
    void displayFilterSuccess(bool success);
    void rtpPlayerReplace();
    void rtpPlayerAdd();
    void rtpPlayerRemove();
    void rtpAnalysisReplace();
    void rtpAnalysisAdd();
    void rtpAnalysisRemove();

protected:
    bool eventFilter(QObject *obj, QEvent *event);
    void captureFileClosing();
    void captureFileClosed();

private:
    Ui::RtpStreamDialog *ui;
    rtpstream_tapinfo_t tapinfo_;
    QPushButton *find_reverse_button_;
    QPushButton *prepare_button_;
    QPushButton *export_button_;
    QPushButton *copy_button_;
    QPushButton *analyze_button_;
    QPushButton *player_button_;
    QMenu ctx_menu_;
    bool need_redraw_;
    QList<rtpstream_id_t> last_selected_;

    static void tapReset(rtpstream_tapinfo_t *tapinfo);
    static void tapDraw(rtpstream_tapinfo_t *tapinfo);
    static void tapMarkPacket(rtpstream_tapinfo_t *tapinfo, frame_data *fd);

    void updateStreams();
    void updateWidgets();
    void showPlayer();

    void setRtpStreamSelection(rtpstream_id_t *id, bool state);

    QList<QVariant> streamRowData(int row) const;
    void freeLastSelected();
    void invertSelection();
    QVector<rtpstream_info_t *>getSelectedRtpStreams();
    QVector<rtpstream_id_t *>getSelectedRtpStreamIDs();

private slots:
    void showStreamMenu(QPoint pos);
    void on_actionCopyAsCsv_triggered();
    void on_actionCopyAsYaml_triggered();
    void on_actionFindReverseNormal_triggered();
    void on_actionFindReversePair_triggered();
    void on_actionFindReverseSingle_triggered();
    void on_actionGoToSetup_triggered();
    void on_actionMarkPackets_triggered();
    void on_actionPrepareFilter_triggered();
    void on_streamTreeWidget_itemSelectionChanged();
    void on_buttonBox_helpRequested();
    void on_actionExportAsRtpDump_triggered();
    void captureEvent(CaptureEvent e);
    void on_displayFilterCheckBox_toggled(bool checked);
    void on_todCheckBox_toggled(bool checked);
    void on_actionSelectAll_triggered();
    void on_actionSelectInvert_triggered();
    void on_actionSelectNone_triggered();
    void on_actionAnalyze_triggered();
};

#endif // RTP_STREAM_DIALOG_H
