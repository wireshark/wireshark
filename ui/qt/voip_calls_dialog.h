/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef VOIP_CALLS_DIALOG_H
#define VOIP_CALLS_DIALOG_H

#include <config.h>

#include <glib.h>
#include <mutex>

#include "cfile.h"

#include "ui/voip_calls.h"
#include "ui/rtp_stream.h"
#include "ui/rtp_stream_id.h"

#include <ui/qt/models/voip_calls_info_model.h>
#include <ui/qt/models/cache_proxy_model.h>
#include "ui/rtp_stream_id.h"
#include "wireshark_dialog.h"

#include <QMenu>
#include <QAbstractButton>
#include <QPushButton>
#include <QToolButton>

class SequenceInfo;

namespace Ui {
class VoipCallsDialog;
}

// Singleton by https://refactoring.guru/design-patterns/singleton/cpp/example#example-1
class VoipCallsDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * Returns singleton
     */
    static VoipCallsDialog *openVoipCallsDialogVoip(QWidget &parent, CaptureFile &cf, QObject *packet_list);
    static VoipCallsDialog *openVoipCallsDialogSip(QWidget &parent, CaptureFile &cf, QObject *packet_list);

    /**
     * Should not be clonnable and assignable
     */
    VoipCallsDialog(VoipCallsDialog &other) = delete;
    void operator=(const VoipCallsDialog &) = delete;

signals:
    void updateFilter(QString filter, bool force = false);
    void captureFileChanged(capture_file *cf);
    void goToPacket(int packet_num);
    void rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void rtpStreamsDialogSelectRtpStreams(QVector<rtpstream_id_t *> stream_ids);
    void rtpStreamsDialogDeselectRtpStreams(QVector<rtpstream_id_t *> stream_ids);

public slots:
    void displayFilterSuccess(bool success);
    void rtpPlayerReplace();
    void rtpPlayerAdd();
    void rtpPlayerRemove();

protected:
    explicit VoipCallsDialog(QWidget &parent, CaptureFile &cf, bool all_flows = false);
    ~VoipCallsDialog();

    void contextMenuEvent(QContextMenuEvent *event);
    virtual void removeTapListeners();
    void captureFileClosing();
    void captureFileClosed();
    bool eventFilter(QObject *obj, QEvent *event);

protected slots:
    void changeEvent(QEvent* event);

private:
    // We have two singletones - one for all protocols, one for sip protocol
    static VoipCallsDialog *pinstance_voip_;
    static VoipCallsDialog *pinstance_sip_;
    bool all_flows_;
    static std::mutex init_mutex_;

    Ui::VoipCallsDialog *ui;
    VoipCallsInfoModel *call_infos_model_;
    CacheProxyModel *cache_model_;
    QSortFilterProxyModel *sorted_model_;

    QWidget &parent_;
    voip_calls_tapinfo_t tapinfo_;
    SequenceInfo *sequence_info_;
    QPushButton *prepare_button_;
    QPushButton *sequence_button_;
    QToolButton *player_button_;
    QPushButton *copy_button_;
    bool voip_calls_tap_listeners_removed_;
    GQueue* shown_callsinfos_; /* queue with all shown calls (voip_calls_info_t) */

    // Tap callbacks
    static void tapReset(void *tapinfo_ptr);
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *data, tap_flags_t flags);
    static void tapDraw(void *tapinfo_ptr);
    static gint compareCallNums(gconstpointer a, gconstpointer b);

    void updateCalls();
    void prepareFilter();
    void showSequence();
    void showPlayer();
    void removeAllCalls();
    void invertSelection();

    QList<QVariant> streamRowData(int row) const;
    QVector<rtpstream_id_t *>getSelectedRtpIds();

private slots:
    void selectAll();
    void selectNone();
    void copyAsCSV();
    void copyAsYAML();
    void switchTimeOfDay();
    void on_callTreeView_activated(const QModelIndex &index);
    void on_buttonBox_clicked(QAbstractButton *button);
    void on_buttonBox_helpRequested();
    void updateWidgets();
    void captureEvent(CaptureEvent e);
    void on_displayFilterCheckBox_toggled(bool checked);
    void on_actionSelectAll_triggered();
    void on_actionSelectInvert_triggered();
    void on_actionSelectNone_triggered();
    void on_actionSelectRtpStreams_triggered();
    void on_actionDeselectRtpStreams_triggered();
};

#endif // VOIP_CALLS_DIALOG_H
