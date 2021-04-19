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

#include <QMenu>
#include <QTreeWidget>
#include <QLabel>
#include <QFile>
#include <QCheckBox>
#include <QHBoxLayout>

#include "wireshark_dialog.h"

namespace Ui {
class RtpAnalysisDialog;
}

class QCPGraph;
class QTemporaryFile;
class QDialogButtonBox;

typedef struct {
    rtpstream_info_t stream;
    QVector<double> *time_vals;
    QVector<double> *jitter_vals;
    QVector<double> *diff_vals;
    QVector<double> *delta_vals;
    QTreeWidget *tree_widget;
    QLabel *statistics_label;
    QString *tab_name;
    QCPGraph *jitter_graph;
    QCPGraph *diff_graph;
    QCPGraph *delta_graph;
    QHBoxLayout *graphHorizontalLayout;
    QCheckBox *stream_checkbox;
    QCheckBox *jitter_checkbox;
    QCheckBox *diff_checkbox;
    QCheckBox *delta_checkbox;
} tab_info_t;

class RtpAnalysisDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit RtpAnalysisDialog(QWidget &parent, CaptureFile &cf);
    ~RtpAnalysisDialog();
    /**
     * @brief Common routine to add a "Analyze" button to a QDialogButtonBox.
     * @param button_box Caller's QDialogButtonBox.
     * @return The new "Analyze" button.
     */
    static QPushButton *addAnalyzeButton(QDialogButtonBox *button_box, QDialog *dialog);

    /** Replace/Add/Remove an RTP streams to analyse.
     * Requires array of rtpstream_id_t.
     *
     * @param stream_ids structs with rtpstream_id
     */
    void replaceRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void addRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void removeRtpStreams(QVector<rtpstream_id_t *> stream_ids);

signals:
    void goToPacket(int packet_num);
    void rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_info_t *> stream_infos);
    void rtpPlayerDialogAddRtpStreams(QVector<rtpstream_info_t *> stream_infos);
    void rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_info_t *> stream_infos);
    void updateFilter(QString filter, bool force = false);

public slots:
    void rtpPlayerReplace();
    void rtpPlayerAdd();
    void rtpPlayerRemove();

protected slots:
    virtual void updateWidgets();

private slots:
    void on_actionGoToPacket_triggered();
    void on_actionNextProblem_triggered();
    void on_actionSaveOneCsv_triggered();
    void on_actionSaveAllCsv_triggered();
    void on_actionSaveGraph_triggered();
    void on_buttonBox_helpRequested();
    void showStreamMenu(QPoint pos);
    void graphClicked(QMouseEvent *event);
    void closeTab(int index);
    void rowCheckboxChanged(int checked);
    void singleCheckboxChanged(int checked);
    void on_actionPrepareFilterOne_triggered();
    void on_actionPrepareFilterAll_triggered();

private:
    Ui::RtpAnalysisDialog *ui;
    enum StreamDirection { dir_all_, dir_one_ };
    int tab_seq;

    QVector<tab_info_t *> tabs_;
    QMultiHash<guint, tab_info_t *> tab_hash_;

    QPushButton *player_button_;

    // Graph data for QCustomPlot
    QList<QCPGraph *>graphs_;

    QString err_str_;

    QMenu stream_ctx_menu_;
    QMenu graph_ctx_menu_;

    // Tap callbacks
    static void tapReset(void *tapinfo_ptr);
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *rtpinfo_ptr);
    static void tapDraw(void *tapinfo_ptr);

    void resetStatistics();
    void addPacket(tab_info_t *tab, packet_info *pinfo, const struct _rtp_info *rtpinfo);
    void updateStatistics();
    void updateGraph();

    void saveCsvData(QFile *save_file, QTreeWidget *tree);
    void saveCsv(StreamDirection direction);

    bool eventFilter(QObject*, QEvent* event);

    QVector<rtpstream_info_t *>getSelectedRtpStreams();
    int addTabUI(tab_info_t *new_tab);
    tab_info_t *getTabInfoForCurrentTab();
    void deleteTabInfo(tab_info_t *tab_info);
    void clearLayout(QLayout *layout);
    void addRtpStreamsPrivate(QVector<rtpstream_id_t *> stream_ids);
};

#endif // RTP_ANALYSIS_DIALOG_H
