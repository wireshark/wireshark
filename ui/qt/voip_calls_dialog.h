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

#include <mutex>

#include <epan/cfile.h>

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

// Singleton by [https://refactoring.guru/design-patterns/singleton/cpp/example#example-1](https://refactoring.guru/design-patterns/singleton/cpp/example#example-1)

/**
 * @brief Dialog for displaying and managing VoIP and SIP calls.
 */
class VoipCallsDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Returns singleton instance for VoIP calls.
     * @param parent The parent widget.
     * @param cf The capture file.
     * @param packet_list Pointer to the packet list object.
     * @return Pointer to the singleton VoipCallsDialog instance.
     */
    static VoipCallsDialog *openVoipCallsDialogVoip(QWidget &parent, CaptureFile &cf, QObject *packet_list);

    /**
     * @brief Returns singleton instance for SIP calls.
     * @param parent The parent widget.
     * @param cf The capture file.
     * @param packet_list Pointer to the packet list object.
     * @return Pointer to the singleton VoipCallsDialog instance.
     */
    static VoipCallsDialog *openVoipCallsDialogSip(QWidget &parent, CaptureFile &cf, QObject *packet_list);

    /**
     * @brief Should not be cloneable
     */
    VoipCallsDialog(VoipCallsDialog &other) = delete;

    /**
     * @brief Should not be assignable
     */
    void operator=(const VoipCallsDialog &) = delete;

signals:
    /**
     * @brief Signal emitted to update the display filter.
     * @param filter The display filter string to apply.
     * @param force True to force the filter application.
     */
    void updateFilter(QString filter, bool force = false);

    /**
     * @brief Signal emitted when the capture file changes.
     * @param cf Pointer to the new capture file.
     */
    void captureFileChanged(capture_file *cf);

    /**
     * @brief Signal emitted to navigate to a specific packet.
     * @param packet_num The packet number to jump to.
     */
    void goToPacket(int packet_num);

    /**
     * @brief Signal emitted to request replacing RTP streams in the player dialog.
     * @param stream_ids The RTP streams to replace.
     */
    void rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Signal emitted to request adding RTP streams to the player dialog.
     * @param stream_ids The RTP streams to add.
     */
    void rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Signal emitted to request removing RTP streams from the player dialog.
     * @param stream_ids The RTP streams to remove.
     */
    void rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Signal emitted to request selecting specific RTP streams in the streams dialog.
     * @param stream_ids The RTP streams to select.
     */
    void rtpStreamsDialogSelectRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Signal emitted to request deselecting specific RTP streams in the streams dialog.
     * @param stream_ids The RTP streams to deselect.
     */
    void rtpStreamsDialogDeselectRtpStreams(QVector<rtpstream_id_t *> stream_ids);

public slots:
    /**
     * @brief Slot to trigger replacing streams in the RTP player.
     */
    void rtpPlayerReplace();

    /**
     * @brief Slot to trigger adding streams to the RTP player.
     */
    void rtpPlayerAdd();

    /**
     * @brief Slot to trigger removing streams from the RTP player.
     */
    void rtpPlayerRemove();

protected:
    /**
     * @brief Constructs a new VoipCallsDialog object. Protected to enforce singleton pattern.
     * @param parent The parent widget.
     * @param cf The capture file context.
     * @param all_flows True if tracking all flows, false for specific SIP flows.
     */
    explicit VoipCallsDialog(QWidget &parent, CaptureFile &cf, bool all_flows = false);

    /**
     * @brief Destroys the VoipCallsDialog object.
     */
    ~VoipCallsDialog();

    /**
     * @brief Handles context menu events.
     * @param event The context menu event.
     */
    void contextMenuEvent(QContextMenuEvent *event);

    /**
     * @brief Safely removes all tap listeners used by the dialog.
     */
    virtual void removeTapListeners();

    /**
     * @brief Handles operations required just before the capture file closes.
     */
    void captureFileClosing();

    /**
     * @brief Handles cleanup after the capture file is fully closed.
     */
    void captureFileClosed();

    /**
     * @brief Event filter for capturing specific events.
     * @param obj The watched object.
     * @param event The intercepted event.
     * @return True if the event was filtered, false otherwise.
     */
    bool eventFilter(QObject *obj, QEvent *event);

protected slots:
    /**
     * @brief Handles generic state change events.
     * @param event The change event.
     */
    void changeEvent(QEvent* event);

private:
    // We have two singletones - one for all protocols, one for sip protocol
    /** @brief The singleton instance pointer for all VoIP calls. */
    static VoipCallsDialog *pinstance_voip_;

    /** @brief The singleton instance pointer for SIP calls. */
    static VoipCallsDialog *pinstance_sip_;

    /** @brief Flag indicating if all flows are active. */
    bool all_flows_;

    /** @brief Mutex for thread-safe initialization. */
    static std::mutex init_mutex_;

    /** @brief Pointer to the UI object for this dialog. */
    Ui::VoipCallsDialog *ui;

    /** @brief The model holding VoIP calls information. */
    VoipCallsInfoModel *call_infos_model_;

    /** @brief The cache proxy model. */
    CacheProxyModel *cache_model_;

    /** @brief The sort and filter proxy model for sorting calls. */
    QSortFilterProxyModel *sorted_model_;

    /** @brief Reference to the parent widget. */
    QWidget &parent_;

    /** @brief The tap context information for VoIP calls. */
    voip_calls_tapinfo_t tapinfo_;

    /** @brief Pointer to sequence analysis info. */
    SequenceInfo *sequence_info_;

    /** @brief Push button to prepare filters. */
    QPushButton *prepare_button_;

    /** @brief Push button to show sequence diagram. */
    QPushButton *sequence_button_;

    /** @brief Tool button for RTP player options. */
    QToolButton *player_button_;

    /** @brief Push button to copy data. */
    QPushButton *copy_button_;

    /** @brief Flag indicating if tap listeners have already been removed. */
    bool voip_calls_tap_listeners_removed_;

    /** @brief Queue containing all displayed calls (voip_calls_info_t). */
    GQueue* shown_callsinfos_;

    // Tap callbacks
    /**
     * @brief Callback to reset collected tap data.
     * @param tapinfo_ptr Pointer to the tap info context.
     */
    static void tapReset(void *tapinfo_ptr);

    /**
     * @brief Callback to process intercepted packets.
     * @return Tap packet status.
     */
    static tap_packet_status tapPacket(void *, packet_info *, epan_dissect_t *, const void *, tap_flags_t);

    /**
     * @brief Callback to update the GUI with new tap data.
     * @param tapinfo_ptr Pointer to the tap info context.
     */
    static void tapDraw(void *tapinfo_ptr);

    /**
     * @brief Comparator function to order call numbers.
     * @param a Pointer to the first element.
     * @param b Pointer to the second element.
     * @return Integer indicating relative order.
     */
    static int compareCallNums(const void *a, const void *b);

    /**
     * @brief Refreshes the calls list in the dialog.
     */
    void updateCalls();

    /**
     * @brief Prepares and emits the display filter for the selected calls.
     */
    void prepareFilter();

    /**
     * @brief Displays the sequence diagram for the selected calls.
     */
    void showSequence();

    /**
     * @brief Displays the RTP player dialog for the selected calls.
     */
    void showPlayer();

    /**
     * @brief Clears and removes all calls from the view.
     */
    void removeAllCalls();

    /**
     * @brief Inverts the current selection in the call list.
     */
    void invertSelection();

    /**
     * @brief Retrieves data items for a specific row in the stream list.
     * @param row The row index.
     * @return A list of variant data elements for the row.
     */
    QList<QVariant> streamRowData(int row) const;

    /**
     * @brief Gathers all selected RTP stream IDs.
     * @return A vector containing pointers to the selected RTP IDs.
     */
    QVector<rtpstream_id_t *>getSelectedRtpIds();

private slots:
    /**
     * @brief Selects all calls in the view.
     */
    void selectAll();

    /**
     * @brief Deselects all calls in the view.
     */
    void selectNone();

    /**
     * @brief Copies the selected calls data as CSV.
     */
    void copyAsCSV();

    /**
     * @brief Copies the selected calls data as YAML.
     */
    void copyAsYAML();

    /**
     * @brief Toggles the time of day display mode.
     */
    void switchTimeOfDay();

    /**
     * @brief Handles activation of a call item in the tree view.
     * @param index The activated model index.
     */
    void on_callTreeView_activated(const QModelIndex &index);

    /**
     * @brief Handles clicks on the dialog button box.
     * @param button The clicked button.
     */
    void on_buttonBox_clicked(QAbstractButton *button);

    /**
     * @brief Handles requests for help from the button box.
     */
    void on_buttonBox_helpRequested();

    /**
     * @brief Updates the enabled state of the dialog widgets based on selection.
     */
    void updateWidgets();

    /**
     * @brief Handles events related to the capture process.
     * @param e The capture event.
     */
    void captureEvent(CaptureEvent e);

    /**
     * @brief Handles toggling the display filter checkbox.
     * @param checked True if checked, false otherwise.
     */
    void displayFilterCheckBoxToggled(bool checked);

    /**
     * @brief Handles the 'Select All' action.
     */
    void on_actionSelectAll_triggered();

    /**
     * @brief Handles the 'Invert Selection' action.
     */
    void on_actionSelectInvert_triggered();

    /**
     * @brief Handles the 'Select None' action.
     */
    void on_actionSelectNone_triggered();

    /**
     * @brief Handles the action to select specific RTP streams.
     */
    void on_actionSelectRtpStreams_triggered();

    /**
     * @brief Handles the action to deselect specific RTP streams.
     */
    void on_actionDeselectRtpStreams_triggered();
};

#endif // VOIP_CALLS_DIALOG_H
