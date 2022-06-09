/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IAX2_ANALYSIS_DIALOG_H
#define IAX2_ANALYSIS_DIALOG_H

// The GTK+ UI checks for multiple RTP streams, and if found opens the RTP
// stream dialog. That seems to violate the principle of least surprise.
// Migrate the code but disable it.
// #define IAX2_RTP_STREAM_CHECK

#include <config.h>

#include <glib.h>

#include <epan/address.h>

#include "ui/tap-iax2-analysis.h"
#include "ui/rtp_stream_id.h"

#include <QAbstractButton>
#include <QMenu>

#include "wireshark_dialog.h"

namespace Ui {
class Iax2AnalysisDialog;
}

class QCPGraph;
class QTemporaryFile;

typedef enum {
    TAP_IAX2_NO_ERROR,
    TAP_IAX2_NO_PACKET_SELECTED,
    TAP_IAX2_WRONG_LENGTH,
    TAP_IAX2_FILE_IO_ERROR
} iax2_error_type_t;


class Iax2AnalysisDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit Iax2AnalysisDialog(QWidget &parent, CaptureFile &cf);
    ~Iax2AnalysisDialog();

signals:
    void goToPacket(int packet_num);

protected slots:
    virtual void updateWidgets();

private slots:
    void on_actionGoToPacket_triggered();
    void on_actionNextProblem_triggered();
    void on_fJitterCheckBox_toggled(bool checked);
    void on_fDiffCheckBox_toggled(bool checked);
    void on_rJitterCheckBox_toggled(bool checked);
    void on_rDiffCheckBox_toggled(bool checked);
    void on_actionSaveAudio_triggered();
    void on_actionSaveForwardAudio_triggered();
    void on_actionSaveReverseAudio_triggered();
    void on_actionSaveCsv_triggered();
    void on_actionSaveForwardCsv_triggered();
    void on_actionSaveReverseCsv_triggered();
    void on_actionSaveGraph_triggered();
    void on_buttonBox_helpRequested();
    void showStreamMenu(QPoint pos);
    void graphClicked(QMouseEvent *event);

private:
    Ui::Iax2AnalysisDialog *ui;
    enum StreamDirection { dir_both_, dir_forward_, dir_reverse_ };

    rtpstream_id_t fwd_id_;
    rtpstream_id_t rev_id_;

    tap_iax2_stat_t fwd_statinfo_;
    tap_iax2_stat_t rev_statinfo_;

    QTemporaryFile *fwd_tempfile_;
    QTemporaryFile *rev_tempfile_;

    // Graph data for QCustomPlot
    QList<QCPGraph *>graphs_;
    QVector<double> fwd_time_vals_;
    QVector<double> fwd_jitter_vals_;
    QVector<double> fwd_diff_vals_;

    QVector<double> rev_time_vals_;
    QVector<double> rev_jitter_vals_;
    QVector<double> rev_diff_vals_;

    QString err_str_;
    iax2_error_type_t save_payload_error_;

    QMenu stream_ctx_menu_;
    QMenu graph_ctx_menu_;

    // Tap callbacks
    static void tapReset(void *tapinfo_ptr);
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, struct epan_dissect *, const void *iax2info_ptr, tap_flags_t flags);
    static void tapDraw(void *tapinfo_ptr);

    void resetStatistics();
    void addPacket(bool forward, packet_info *pinfo, const struct _iax2_info_t *iax2info);
    void savePayload(QTemporaryFile *tmpfile, packet_info *pinfo, const struct _iax2_info_t *iax2info);
    void updateStatistics();
    void updateGraph();

    void saveAudio(StreamDirection direction);
    void saveCsv(StreamDirection direction);

#if 0
    guint32 processNode(proto_node *ptree_node, header_field_info *hfinformation, const gchar* proto_field, bool *ok);
    guint32 getIntFromProtoTree(proto_tree *protocol_tree, const gchar *proto_name, const gchar *proto_field, bool *ok);
#endif

    bool eventFilter(QObject*, QEvent* event);
};

#endif // IAX2_ANALYSIS_DIALOG_H
