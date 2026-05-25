/** @file
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

#include <mutex>

#include "ui/rtp_stream.h"
#include "rtp_player_dialog.h"

#include <QToolButton>
#include <QMenu>

namespace Ui {
class RtpStreamDialog;
}

/**
 * @brief Singleton dialog for viewing and managing RTP streams.
 * Singleton pattern based on https://refactoring.guru/design-patterns/singleton/cpp/example#example-1
 */
class RtpStreamDialog : public RtpBaseDialog
{
    Q_OBJECT

public:
    /**
     * @brief Opens or retrieves the singleton instance of the RTP Stream Dialog.
     * @param parent The parent widget.
     * @param cf The capture file.
     * @param packet_list Pointer to the packet list object.
     * @return Pointer to the singleton RtpStreamDialog instance.
     */
    static RtpStreamDialog *openRtpStreamDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list);

    /**
     * @brief Should not be cloneable.
     */
    RtpStreamDialog(RtpStreamDialog &other) = delete;

    /**
     * @brief Should not be assignable.
     */
    void operator=(const RtpStreamDialog &) = delete;

    /**
     * @brief Selects specific RTP streams.
     * Caller must provide ids which are immutable to recap.
     * @param stream_ids A vector of RTP stream IDs to select.
     */
    void selectRtpStream(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Deselects specific RTP streams.
     * Caller must provide ids which are immutable to recap.
     * @param stream_ids A vector of RTP stream IDs to deselect.
     */
    void deselectRtpStream(QVector<rtpstream_id_t *> stream_ids);

signals:
    // Tells the packet list to redraw. An alternative might be to add a
    // cf_packet_marked callback to file.[ch] but that's synchronous and
    // might incur too much overhead.
    /**
     * @brief Signal emitted when packets are marked.
     */
    void packetsMarked();

    /**
     * @brief Signal emitted to update the display filter.
     * @param filter The new filter string.
     * @param force True to force the update.
     */
    void updateFilter(QString filter, bool force = false);

    /**
     * @brief Signal emitted to navigate to a specific packet.
     * @param packet_num The packet number.
     */
    void goToPacket(int packet_num);

    /**
     * @brief Signal emitted to request replacing streams in the RTP Player.
     * @param stream_ids The stream IDs to replace.
     */
    void rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Signal emitted to request adding streams to the RTP Player.
     * @param stream_ids The stream IDs to add.
     */
    void rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Signal emitted to request removing streams from the RTP Player.
     * @param stream_ids The stream IDs to remove.
     */
    void rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Signal emitted to request replacing streams in the RTP Analysis dialog.
     * @param stream_infos The stream IDs to replace.
     */
    void rtpAnalysisDialogReplaceRtpStreams(QVector<rtpstream_id_t *> stream_infos);

    /**
     * @brief Signal emitted to request adding streams to the RTP Analysis dialog.
     * @param stream_infos The stream IDs to add.
     */
    void rtpAnalysisDialogAddRtpStreams(QVector<rtpstream_id_t *> stream_infos);

    /**
     * @brief Signal emitted to request removing streams from the RTP Analysis dialog.
     * @param stream_infos The stream IDs to remove.
     */
    void rtpAnalysisDialogRemoveRtpStreams(QVector<rtpstream_id_t *> stream_infos);

public slots:
    /**
     * @brief Slot to trigger replacing streams in the player.
     */
    void rtpPlayerReplace();

    /**
     * @brief Slot to trigger adding streams to the player.
     */
    void rtpPlayerAdd();

    /**
     * @brief Slot to trigger removing streams from the player.
     */
    void rtpPlayerRemove();

    /**
     * @brief Slot to trigger replacing streams in analysis.
     */
    void rtpAnalysisReplace() override;

    /**
     * @brief Slot to trigger adding streams to analysis.
     */
    void rtpAnalysisAdd() override;

    /**
     * @brief Slot to trigger removing streams from analysis.
     */
    void rtpAnalysisRemove() override;

protected:
    /**
     * @brief Constructs an RtpStreamDialog. Protected to enforce singleton pattern.
     * @param parent The parent widget.
     * @param cf The associated capture file.
     */
    explicit RtpStreamDialog(QWidget &parent, CaptureFile &cf);

    /**
     * @brief Destroys the RtpStreamDialog.
     */
    ~RtpStreamDialog();

    /**
     * @brief Event filter for intercepting events from child widgets.
     * @param obj The watched object.
     * @param event The intercepted event.
     * @return True if the event was handled, false otherwise.
     */
    bool eventFilter(QObject *obj, QEvent *event) override;

    /**
     * @brief Handles operations before the capture file finishes closing.
     */
    void captureFileClosing() override;

    /**
     * @brief Handles cleanup after the capture file is fully closed.
     */
    void captureFileClosed() override;

private:
    /** @brief The singleton instance pointer. */
    static RtpStreamDialog *pinstance_;

    /** @brief Mutex for thread-safe initialization. */
    static std::mutex mutex_;

    /** @brief Pointer to the UI object for this dialog. */
    Ui::RtpStreamDialog *ui;

    /** @brief The tap context information for RTP streams. */
    rtpstream_tapinfo_t tapinfo_;

    /** @brief Toolbar button to find reverse streams. */
    QToolButton *find_reverse_button_;

    /** @brief Push button to prepare a filter. */
    QPushButton *prepare_button_;

    /** @brief Push button to export data. */
    QPushButton *export_button_;

    /** @brief Push button to copy data. */
    QPushButton *copy_button_;

    /** @brief Toolbar button to open the analysis dialog. */
    QToolButton *analyze_button_;

    /** @brief Toolbar button to open the player dialog. */
    QToolButton *player_button_;

    /** @brief The context menu for the stream list. */
    QMenu ctx_menu_;

    /** @brief Flag indicating if a redraw is needed. */
    bool need_redraw_;

    /** @brief Cache of previously selected RTP stream IDs. */
    QList<rtpstream_id_t> last_selected_;

    /**
     * @brief Tap callback to reset collected tap data.
     * @param tapinfo Pointer to the RTP tap info context.
     */
    static void tapReset(rtpstream_tapinfo_t *tapinfo);

    /**
     * @brief Tap callback to process and draw collected data.
     * @param tapinfo Pointer to the RTP tap info context.
     */
    static void tapDraw(rtpstream_tapinfo_t *tapinfo);

    /**
     * @brief Tap callback to mark a specific packet.
     * @param tapinfo Pointer to the RTP tap info context.
     * @param fd The frame data to mark.
     */
    static void tapMarkPacket(rtpstream_tapinfo_t *tapinfo, frame_data *fd);

    /**
     * @brief Refreshes the display of the streams list.
     */
    void updateStreams();

    /**
     * @brief Updates the enabled/disabled state of UI widgets.
     */
    void updateWidgets() override;

    /**
     * @brief Shows or raises the RTP player dialog.
     */
    void showPlayer();

    /**
     * @brief Modifies the selection state of a specific RTP stream.
     * @param id The stream ID.
     * @param state True to select, false to deselect.
     */
    void setRtpStreamSelection(rtpstream_id_t *id, bool state);

    /**
     * @brief Retrieves all data items for a given row.
     * @param row The row index.
     * @return A list of variants containing the row's data.
     */
    QList<QVariant> streamRowData(int row) const;

    /**
     * @brief Clears the cache of the last selected stream items.
     */
    void freeLastSelected();

    /**
     * @brief Inverts the active selection in the stream list.
     */
    void invertSelection();

    /**
     * @brief Gathers a list of all currently selected RTP IDs.
     * @return A vector of rtpstream_id_t pointers.
     */
    QVector<rtpstream_id_t *>getSelectedRtpIds();

private slots:
    /**
     * @brief Slot to display the context menu for the stream list.
     * @param pos The position for the context menu.
     */
    void showStreamMenu(QPoint pos);

    /**
     * @brief Handles the "Copy as CSV" action.
     */
    void on_actionCopyAsCsv_triggered();

    /**
     * @brief Handles the "Copy as YAML" action.
     */
    void on_actionCopyAsYaml_triggered();

    /**
     * @brief Handles the default "Find Reverse" action.
     */
    void on_actionFindReverseNormal_triggered();

    /**
     * @brief Handles the "Find Reverse Pair" action.
     */
    void on_actionFindReversePair_triggered();

    /**
     * @brief Handles the "Find Reverse Single" action.
     */
    void on_actionFindReverseSingle_triggered();

    /**
     * @brief Handles the "Go to Setup Packet" action.
     */
    void on_actionGoToSetup_triggered();

    /**
     * @brief Handles the "Mark Packets" action.
     */
    void on_actionMarkPackets_triggered();

    /**
     * @brief Handles the "Prepare Filter" action.
     */
    void on_actionPrepareFilter_triggered();

    /**
     * @brief Handles selection changes in the stream tree widget.
     */
    void on_streamTreeWidget_itemSelectionChanged();

    /**
     * @brief Handles requests for dialog help.
     */
    void on_buttonBox_helpRequested();

    /**
     * @brief Handles exporting selected streams as RTP dump files.
     */
    void on_actionExportAsRtpDump_triggered();

    /**
     * @brief Handles capture state events.
     * @param e The capture event.
     */
    void captureEvent(CaptureEvent e);

    /**
     * @brief Handles toggling the "Display Filter" checkbox.
     * @param checked The new checked state.
     */
    void displayFilterCheckBoxToggled(bool checked);

    /**
     * @brief Handles toggling the "Time of Day" (TOD) checkbox.
     * @param checked The new checked state.
     */
    void on_todCheckBox_toggled(bool checked);

    /**
     * @brief Selects all streams in the tree widget.
     */
    void on_actionSelectAll_triggered();

    /**
     * @brief Inverts the stream selection in the tree widget.
     */
    void on_actionSelectInvert_triggered();

    /**
     * @brief Deselects all streams in the tree widget.
     */
    void on_actionSelectNone_triggered();

    /**
     * @brief Handles the "Analyze" action.
     */
    void on_actionAnalyze_triggered();
};

#endif // RTP_STREAM_DIALOG_H
