/* rtp_analysis_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTP_ANALYSIS_DIALOG_H
#define RTP_ANALYSIS_DIALOG_H

#include <config.h>

#include <glib.h>

#include "epan/address.h"

#include "ui/rtp_stream.h"
#include "ui/tap-rtp-common.h"
#include "ui/tap-rtp-analysis.h"

#include <QAbstractButton>
#include <QMenu>
#include <QFile>

#include "wireshark_dialog.h"

namespace Ui {
class RtpAnalysisDialog;
}

class QCPGraph;
class QTemporaryFile;

class RtpAnalysisDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit RtpAnalysisDialog(QWidget &parent, CaptureFile &cf, rtpstream_info_t *stream_fwd = 0, rtpstream_info_t *stream_rev = 0);
    ~RtpAnalysisDialog();

signals:
    void goToPacket(int packet_num);

protected:
    virtual void captureFileClosing();

protected slots:
    virtual void updateWidgets();

private slots:
    void on_actionGoToPacket_triggered();
    void on_actionNextProblem_triggered();
    void on_fJitterCheckBox_toggled(bool checked);
    void on_fDiffCheckBox_toggled(bool checked);
    void on_fDeltaCheckBox_toggled(bool checked);
    void on_rJitterCheckBox_toggled(bool checked);
    void on_rDiffCheckBox_toggled(bool checked);
    void on_rDeltaCheckBox_toggled(bool checked);
    void on_actionSaveAudioUnsync_triggered();
    void on_actionSaveForwardAudioUnsync_triggered();
    void on_actionSaveReverseAudioUnsync_triggered();
    void on_actionSaveAudioSyncStream_triggered();
    void on_actionSaveForwardAudioSyncStream_triggered();
    void on_actionSaveReverseAudioSyncStream_triggered();
    void on_actionSaveAudioSyncFile_triggered();
    void on_actionSaveForwardAudioSyncFile_triggered();
    void on_actionSaveReverseAudioSyncFile_triggered();
    void on_actionSaveCsv_triggered();
    void on_actionSaveForwardCsv_triggered();
    void on_actionSaveReverseCsv_triggered();
    void on_actionSaveGraph_triggered();
    void on_buttonBox_clicked(QAbstractButton *button);
    void on_buttonBox_helpRequested();
    void showStreamMenu(QPoint pos);
    void graphClicked(QMouseEvent *event);

private:
    Ui::RtpAnalysisDialog *ui;
    enum StreamDirection { dir_both_, dir_forward_, dir_reverse_ };
    enum SyncType { sync_unsync_, sync_sync_stream_, sync_sync_file_ };

    /* Save Audio Errors */
    bool sae_stopped_;
    bool sae_file_error_;
    bool sae_unsupported_codec_;
    bool sae_unsupported_rate_;
    bool sae_other_error_;

    int num_streams_;

    rtpstream_info_t fwd_statinfo_;
    rtpstream_info_t rev_statinfo_;

    QPushButton *player_button_;

    QTemporaryFile *fwd_tempfile_;
    QTemporaryFile *rev_tempfile_;

    // Graph data for QCustomPlot
    QList<QCPGraph *>graphs_;
    QVector<double> fwd_time_vals_;
    QVector<double> fwd_jitter_vals_;
    QVector<double> fwd_diff_vals_;
    QVector<double> fwd_delta_vals_;

    QVector<double> rev_time_vals_;
    QVector<double> rev_jitter_vals_;
    QVector<double> rev_diff_vals_;
    QVector<double> rev_delta_vals_;

    rtpstream_tapinfo_t tapinfo_;
    QString err_str_;
    tap_rtp_error_type_t save_payload_error_;

    QMenu stream_ctx_menu_;
    QMenu graph_ctx_menu_;

    void findStreams();

    // Tap callbacks
    static void tapReset(void *tapinfo_ptr);
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *rtpinfo_ptr);
    static void tapDraw(void *tapinfo_ptr);

    void resetStatistics();
    void addPacket(bool forward, packet_info *pinfo, const struct _rtp_info *rtpinfo);
    void savePayload(QTemporaryFile *tmpfile, tap_rtp_stat_t *statinfo, packet_info *pinfo, const struct _rtp_info *rtpinfo);
    void updateStatistics();
    void updateGraph();

    void showPlayer();

    size_t convert_payload_to_samples(unsigned int payload_type, const gchar *payload_type_names[256], QTemporaryFile *tempfile, uint8_t *pd_out, size_t expected_nchars, struct _GHashTable *decoders_hash);
    bool saveAudioAUSilence(size_t total_len, QFile *save_file, gboolean *stop_flag);
    bool saveAudioAUUnidir(tap_rtp_stat_t &statinfo, const gchar *payload_type_names[256], QTemporaryFile *tempfile, QFile *save_file, int64_t header_end, gboolean *stop_flag, gboolean interleave, size_t prefix_silence);
    bool saveAudioAUBidir(tap_rtp_stat_t &fwd_statinfo, tap_rtp_stat_t &rev_statinfo, const gchar *fwd_payload_type_names[256], const gchar *rev_payload_type_names[256], QTemporaryFile *fwd_tempfile, QTemporaryFile *rev_tempfile, QFile *save_file, int64_t header_end, gboolean *stop_flag, size_t prefix_silence_fwd, size_t prefix_silence_rev);
    bool saveAudioAU(StreamDirection direction, QFile *save_file, gboolean *stop_flag, RtpAnalysisDialog::SyncType sync);
    bool saveAudioRAW(StreamDirection direction, QFile *save_file, gboolean *stop_flag);
    void saveAudio(StreamDirection direction, RtpAnalysisDialog::SyncType sync);
    void saveCsv(StreamDirection direction);

    uint32_t processNode(proto_node *ptree_node, header_field_info *hfinformation, const gchar* proto_field, bool *ok);
    uint32_t getIntFromProtoTree(proto_tree *protocol_tree, const gchar *proto_name, const gchar *proto_field, bool *ok);

    bool eventFilter(QObject*, QEvent* event);

    void clearSAEErrors();
    bool isSAEOK();
};

#endif // RTP_ANALYSIS_DIALOG_H

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
