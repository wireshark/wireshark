/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTP_PLAYER_DIALOG_H
#define RTP_PLAYER_DIALOG_H

#include "config.h"

#include <mutex>

#include "ui/rtp_stream.h"

#include "wireshark_dialog.h"
#include "rtp_audio_stream.h"

#include <QWidget>
#include <QMap>
#include <QMultiHash>
#include <QTreeWidgetItem>
#include <QMetaType>
#include <ui/qt/widgets/qcustomplot.h>

#ifdef QT_MULTIMEDIA_LIB
# include <QAudioDevice>
#endif

namespace Ui {
class RtpPlayerDialog;
}

class QCPItemStraightLine;
class QDialogButtonBox;
class QMenu;
class RtpAudioStream;
class QCPAxisTicker;
class QCPAxisTickerDateTime;

/**
 * @brief Defines the audio formats available for saving.
 */
typedef enum {
    save_audio_none,    /**< No audio format or save canceled. */
    save_audio_au,      /**< Sun AU audio format. */
    save_audio_wav      /**< Microsoft WAV audio format. */
} save_audio_t;

/**
 * @brief Defines the payload formats available for saving.
 */
typedef enum {
    save_payload_none,  /**< No payload format or save canceled. */
    save_payload_data   /**< Raw payload data format. */
} save_payload_t;

/**
 * @brief Defines the modes available for saving audio or payload data.
 */
typedef enum {
    save_mode_from_cursor,  /**< Save starting from the current playback cursor. */
    save_mode_sync_stream,  /**< Save synchronized streams. */
    save_mode_sync_file     /**< Save synchronized to the capture file timing. */
} save_mode_t;

/**
 * @brief Base class for RTP related dialogs providing common functionality.
 */
class RtpBaseDialog : public WiresharkDialog
{
    Q_OBJECT
protected:
    /**
     * @brief Constructs an RtpBaseDialog.
     * @param parent The parent widget.
     * @param cf The associated capture file.
     */
    explicit RtpBaseDialog(QWidget &parent, CaptureFile &cf) : WiresharkDialog(parent, cf) {}

#ifdef QT_MULTIMEDIA_LIB
public slots:
    /**
     * @brief Pure virtual slot to handle replacing RTP streams for analysis.
     */
    virtual void rtpAnalysisReplace() = 0;

    /**
     * @brief Pure virtual slot to handle adding RTP streams for analysis.
     */
    virtual void rtpAnalysisAdd() = 0;

    /**
     * @brief Pure virtual slot to handle removing RTP streams for analysis.
     */
    virtual void rtpAnalysisRemove() = 0;
#endif // QT_MULTIMEDIA_LIB
};

/**
 * @brief Singleton dialog for playing and analyzing RTP audio streams.
 * Singleton pattern based on https://refactoring.guru/design-patterns/singleton/cpp/example#example-1
 */
class RtpPlayerDialog : public RtpBaseDialog
{
    Q_OBJECT
#ifdef QT_MULTIMEDIA_LIB
    Q_PROPERTY(QString currentOutputDeviceName READ currentOutputDeviceName)
#endif

public:
    /**
     * @brief Opens or retrieves the singleton instance of the RTP Player Dialog.
     * @param parent The parent widget.
     * @param cf The capture file containing the streams.
     * @param packet_list Pointer to the packet list object.
     * @param capture_running True if a capture is currently running.
     * @return Pointer to the singleton RtpPlayerDialog instance.
     */
    static RtpPlayerDialog *openRtpPlayerDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list, bool capture_running);

    /**
     * @brief Should not be cloneable.
     */
    RtpPlayerDialog(RtpPlayerDialog &other) = delete;

    /**
     * @brief Should not be assignable.
     */
    void operator=(const RtpPlayerDialog &) = delete;

    /**
     * @brief Common routine to add a "Play call" button to a QDialogButtonBox.
     * @param button_box Caller's QDialogButtonBox.
     * @param dialog The dialog the button belongs to.
     * @return Pointer to the new "Play call" QToolButton.
     */
    static QToolButton *addPlayerButton(QDialogButtonBox *button_box, QDialog *dialog);

#ifdef QT_MULTIMEDIA_LIB
    /**
     * @brief Accepts the dialog, generally closing it.
     */
    void accept() override;

    /**
     * @brief Rejects the dialog, generally closing it without taking action.
     */
    void reject() override;

    /**
     * @brief Sets playback markers on the graph.
     */
    void setMarkers();

    /** Replace/Add/Remove an RTP streams to play.
     * Requires array of rtpstream_info_t.
     * Each item must have filled items: src_addr, src_port, dest_addr,
     *  dest_port, ssrc, packet_count, setup_frame_number, and start_rel_time.
     *
     * @param stream_ids struct with rtpstream info
     */
    void replaceRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Adds RTP streams to the player.
     * @param stream_ids A vector of RTP stream IDs to add.
     */
    void addRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Removes RTP streams from the player.
     * @param stream_ids A vector of RTP stream IDs to remove.
     */
    void removeRtpStreams(QVector<rtpstream_id_t *> stream_ids);

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
     * @param filter The filter string to apply.
     * @param force True to force the filter application.
     */
    void updateFilter(QString filter, bool force = false);

    /**
     * @brief Signal emitted to navigate to a specific packet.
     * @param packet_num The packet number to navigate to.
     */
    void goToPacket(int packet_num);

    /**
     * @brief Signal emitted to request replacing streams in the RTP Analysis dialog.
     * @param stream_infos A vector of RTP stream IDs to replace.
     */
    void rtpAnalysisDialogReplaceRtpStreams(QVector<rtpstream_id_t *> stream_infos);

    /**
     * @brief Signal emitted to request adding streams in the RTP Analysis dialog.
     * @param stream_infos A vector of RTP stream IDs to add.
     */
    void rtpAnalysisDialogAddRtpStreams(QVector<rtpstream_id_t *> stream_infos);

    /**
     * @brief Signal emitted to request removing streams from the RTP Analysis dialog.
     * @param stream_infos A vector of RTP stream IDs to remove.
     */
    void rtpAnalysisDialogRemoveRtpStreams(QVector<rtpstream_id_t *> stream_infos);

public slots:
    /**
     * @brief Slot to handle replacing RTP streams for analysis.
     */
    void rtpAnalysisReplace() override;

    /**
     * @brief Slot to handle adding RTP streams for analysis.
     */
    void rtpAnalysisAdd() override;

    /**
     * @brief Slot to handle removing RTP streams from analysis.
     */
    void rtpAnalysisRemove() override;

#endif
protected:
    /**
     * @brief Constructs an RtpPlayerDialog. Protected to enforce singleton pattern.
     * @param parent The parent widget.
     * @param cf The associated capture file.
     * @param capture_running True if a capture is currently running.
     */
    explicit RtpPlayerDialog(QWidget &parent, CaptureFile &cf, bool capture_running);
#ifdef QT_MULTIMEDIA_LIB
    /**
     * @brief Destroys the RtpPlayerDialog.
     */
    ~RtpPlayerDialog();

    /**
     * @brief Handles the show event for the dialog.
     */
    virtual void showEvent(QShowEvent *) override;

    /**
     * @brief Handles the context menu event.
     * @param event The context menu event.
     */
    void contextMenuEvent(QContextMenuEvent *event) override;

    /**
     * @brief Filters events for objects installed with this event filter.
     * @param obj The watched object.
     * @param event The intercepted event.
     * @return True if the event was handled, false otherwise.
     */
    bool eventFilter(QObject *obj, QEvent *event) override;

private slots:
    /** Retap the capture file, reading RTP packets that match the
     * streams added using ::addRtpStream.
     */
    void retapPackets();

    /**
     * @brief Handles capture events.
     * @param e The capture event.
     */
    void captureEvent(CaptureEvent e);

    /** Clear, decode, and redraw each stream.
     */
    void rescanPackets(bool rescale_axes = false);

    /**
     * @brief Creates the main plot area.
     * @param rescale_axes True to automatically rescale the axes to fit data.
     */
    void createPlot(bool rescale_axes = false);

    /**
     * @brief Updates widget states based on current data and selections.
     */
    void updateWidgets() override;

    /**
     * @brief Handles an item being entered (e.g. mouse hover).
     * @param item The tree widget item.
     * @param column The column index.
     */
    void itemEntered(QTreeWidgetItem *item, int column);

    /**
     * @brief Handles mouse movement over the plot area.
     * @param event The mouse event.
     */
    void mouseMovePlot(QMouseEvent *event);

    /**
     * @brief Triggers a deferred update based on mouse position.
     */
    void mouseMoveUpdate();

    /**
     * @brief Displays the context menu for the graph.
     * @param pos The position for the menu.
     */
    void showGraphContextMenu(const QPoint &pos);

    /**
     * @brief Handles clicks on the graph background.
     * @param event The mouse event.
     */
    void graphClicked(QMouseEvent *event);

    /**
     * @brief Handles double-clicks on the graph.
     * @param event The mouse event.
     */
    void graphDoubleClicked(QMouseEvent *event);

    /**
     * @brief Handles clicks directly on a plotted item.
     * @param plottable The plottable item that was clicked.
     * @param dataIndex The index of the clicked data point.
     * @param event The mouse event.
     */
    void plotClicked(QCPAbstractPlottable *plottable, int dataIndex, QMouseEvent *event);

    /**
     * @brief Updates the hint label text based on current state.
     */
    void updateHintLabel();

    /**
     * @brief Resets the X-axis range to its default.
     */
    void resetXAxis();

    /**
     * @brief Updates the drawn graphs.
     */
    void updateGraphs();

    /**
     * @brief Slot called when a stream finishes playing.
     * @param stream The stream that finished.
     * @param error Any error that occurred during playback.
     */
    void playFinished(RtpAudioStream *stream, QAudio::Error error);

    /**
     * @brief Sets the current play position cursor.
     * @param secs The play position in seconds.
     */
    void setPlayPosition(double secs);

    /**
     * @brief Displays a playback error message.
     * @param playback_error The error string.
     */
    void setPlaybackError(const QString playback_error);

    /**
     * @brief Changes the audio routing for a specific item.
     * @param ti The tree widget item.
     * @param new_audio_routing The new routing state.
     */
    void changeAudioRoutingOnItem(QTreeWidgetItem *ti, AudioRouting new_audio_routing);

    /**
     * @brief Changes the audio routing for all selected items.
     * @param new_audio_routing The new routing state.
     */
    void changeAudioRouting(AudioRouting new_audio_routing);

    /**
     * @brief Inverts the mute state of a specific item.
     * @param ti The tree widget item.
     */
    void invertAudioMutingOnItem(QTreeWidgetItem *ti);

    /**
     * @brief Handles clicks on the "Play" button.
     */
    void on_playButton_clicked();

    /**
     * @brief Handles clicks on the "Pause" button.
     */
    void on_pauseButton_clicked();

    /**
     * @brief Handles clicks on the "Stop" button.
     */
    void on_stopButton_clicked();

    /**
     * @brief Handles the "Reset" action to clear playback state.
     */
    void on_actionReset_triggered();

    /**
     * @brief Handles the "Zoom In" action on the graph.
     */
    void on_actionZoomIn_triggered();

    /**
     * @brief Handles the "Zoom Out" action on the graph.
     */
    void on_actionZoomOut_triggered();

    /**
     * @brief Handles moving the view left by 10 units.
     */
    void on_actionMoveLeft10_triggered();

    /**
     * @brief Handles moving the view right by 10 units.
     */
    void on_actionMoveRight10_triggered();

    /**
     * @brief Handles moving the view left by 1 unit.
     */
    void on_actionMoveLeft1_triggered();

    /**
     * @brief Handles moving the view right by 1 unit.
     */
    void on_actionMoveRight1_triggered();

    /**
     * @brief Handles the "Go to Packet" action for the selected item.
     */
    void on_actionGoToPacket_triggered();

    /**
     * @brief Handles navigating to the setup packet from the plot context.
     */
    void on_actionGoToSetupPacketPlot_triggered();

    /**
     * @brief Handles navigating to the setup packet from the tree context.
     */
    void on_actionGoToSetupPacketTree_triggered();

    /**
     * @brief Handles removing the selected stream.
     */
    void on_actionRemoveStream_triggered();

    /**
     * @brief Routes selected audio to Play (Both).
     */
    void on_actionAudioRoutingP_triggered();

    /**
     * @brief Routes selected audio to the Left channel.
     */
    void on_actionAudioRoutingL_triggered();

    /**
     * @brief Routes selected audio to Left/Right alternately.
     */
    void on_actionAudioRoutingLR_triggered();

    /**
     * @brief Routes selected audio to the Right channel.
     */
    void on_actionAudioRoutingR_triggered();

    /**
     * @brief Mutes the selected audio stream.
     */
    void on_actionAudioRoutingMute_triggered();

    /**
     * @brief Unmutes the selected audio stream.
     */
    void on_actionAudioRoutingUnmute_triggered();

    /**
     * @brief Inverts the mute state for the selected stream.
     */
    void on_actionAudioRoutingMuteInvert_triggered();

    /**
     * @brief Handles selection changes in the stream tree widget.
     */
    void on_streamTreeWidget_itemSelectionChanged();

    /**
     * @brief Handles double-clicks on items in the stream tree widget.
     * @param item The double-clicked item.
     * @param column The column index.
     */
    void on_streamTreeWidget_itemDoubleClicked(QTreeWidgetItem *item, const int column);

    /**
     * @brief Handles changes in the output audio device selection.
     */
    void on_outputDeviceComboBox_currentTextChanged(const QString &);

    /**
     * @brief Handles changes in the output audio rate selection.
     * @param rate_string The newly selected audio rate string.
     */
    void on_outputAudioRate_currentTextChanged(const QString &rate_string);

    /**
     * @brief Handles value changes in the jitter buffer spinbox.
     */
    void on_jitterSpinBox_valueChanged(double);

    /**
     * @brief Handles changes in the timing mode selection.
     */
    void on_timingComboBox_currentIndexChanged(int);

    /**
     * @brief Handles the Time-of-Day checkbox toggle state.
     * @param checked True if TOD format is selected.
     */
    void on_todCheckBox_toggled(bool checked);

    /**
     * @brief Handles editing completion for the visual sample rate spinbox.
     */
    void on_visualSRSpinBox_editingFinished();

    /**
     * @brief Handles requests for dialog help.
     */
    void on_buttonBox_helpRequested();

    /**
     * @brief Selects all streams in the tree widget.
     */
    void on_actionSelectAll_triggered();

    /**
     * @brief Inverts the current selection in the tree widget.
     */
    void on_actionSelectInvert_triggered();

    /**
     * @brief Deselects all streams in the tree widget.
     */
    void on_actionSelectNone_triggered();

    /**
     * @brief Callback triggered for audio output notifications.
     */
    void outputNotify();

    /**
     * @brief Triggers audio playback from the action menu.
     */
    void on_actionPlay_triggered();

    /**
     * @brief Triggers stopping audio playback from the action menu.
     */
    void on_actionStop_triggered();

    /**
     * @brief Triggers saving audio starting from the cursor position.
     */
    void on_actionSaveAudioFromCursor_triggered();

    /**
     * @brief Triggers saving synchronized audio streams.
     */
    void on_actionSaveAudioSyncStream_triggered();

    /**
     * @brief Triggers saving audio synchronized to the capture file timing.
     */
    void on_actionSaveAudioSyncFile_triggered();

    /**
     * @brief Triggers saving the raw payload data.
     */
    void on_actionSavePayload_triggered();

    /**
     * @brief Selects all inaudible (muted) streams in the tree widget.
     */
    void on_actionSelectInaudible_triggered();

    /**
     * @brief Deselects all inaudible (muted) streams in the tree widget.
     */
    void on_actionDeselectInaudible_triggered();

    /**
     * @brief Prepares the display filter based on current selections.
     */
    void on_actionPrepareFilter_triggered();

    /**
     * @brief Initiates reading capture data from the underlying file.
     */
    void on_actionReadCapture_triggered();

    /**
     * @brief Handles state changes in the audio sink.
     */
    void sinkStateChanged();

#endif
private:
    /** @brief The singleton instance pointer. */
    static RtpPlayerDialog *pinstance_;

    /** @brief Mutex for thread-safe initialization. */
    static std::mutex init_mutex_;

    /** @brief Mutex for synchronization during run-time execution. */
    static std::mutex run_mutex_;

#ifdef QT_MULTIMEDIA_LIB
    /** @brief Pointer to the UI object for this dialog. */
    Ui::RtpPlayerDialog *ui;

    /** @brief Context menu for the plot graph area. */
    QMenu *graph_ctx_menu_;

    /** @brief Context menu for the stream list tree widget. */
    QMenu *list_ctx_menu_;

    /** @brief Relative start time of the very first stream. */
    double first_stream_rel_start_time_;

    /** @brief Absolute start time of the very first stream. */
    double first_stream_abs_start_time_;

    /** @brief Relative end time of the very first stream (used for streams_length_ calculation). */
    double first_stream_rel_stop_time_;

    /** @brief Total duration between the start of the first stream and the end of the last. */
    double streams_length_;

    /** @brief Time position of the start marker (relative to capture start). */
    double start_marker_time_;

    /** @brief Copy of the start marker time captured when play started. */
    double start_marker_time_play_;

    /** @brief Vertical line item indicating the current playback position. */
    QCPItemStraightLine *cur_play_pos_;

    /** @brief Vertical line item indicating the start marker position. */
    QCPItemStraightLine *start_marker_pos_;

    /** @brief Holds error strings generated during playback. */
    QString playback_error_;

    /** @brief Ticker used for numeric X-axis values. */
    QSharedPointer<QCPAxisTicker> number_ticker_;

    /** @brief Ticker used for DateTime-formatted X-axis values. */
    QSharedPointer<QCPAxisTickerDateTime> datetime_ticker_;

    /** @brief Flag indicating if stereo output is available on the device. */
    bool stereo_available_;

    /** @brief List of RTP streams currently playing audio. */
    QList<RtpAudioStream *> playing_streams_;

    /** @brief Audio sink used as a timing marker. */
    QAudioSink *marker_stream_;

    /** @brief Timer triggering periodic update notifications. */
    QTimer notify_timer_;

    /** @brief Offset difference used to shift play cursor to the correct place. */
    qint64 notify_timer_start_diff_;
    /** @brief Requested sample rate for the marker stream. */
    quint32 marker_stream_requested_out_rate_;

    /** @brief Pointer to the last selected tree widget item. */
    QTreeWidgetItem *last_ti_;

    /** @brief State flag to check if the tap listener has been removed. */
    bool listener_removed_;

    /** @brief Push button used to read capture data. */
    QPushButton *read_btn_;

    /** @brief Toolbar button for filtering inaudible streams. */
    QToolButton *inaudible_btn_;

    /** @brief Toolbar button for triggering analysis functions. */
    QToolButton *analyze_btn_;

    /** @brief Push button to prepare display filters. */
    QPushButton *prepare_btn_;

    /** @brief Push button for exporting payload data. */
    QPushButton *export_btn_;

    /** @brief Hash map of internal streams indexed by unsigned keys. */
    QMultiHash<unsigned, RtpAudioStream *> stream_hash_;

    /** @brief Flag to temporarily block plot redraws. */
    bool block_redraw_;

    /** @brief Mutex-like counter to lock the UI during intense operations. */
    int lock_ui_;

    /** @brief Flag indicating if reading from capture is enabled. */
    bool read_capture_enabled_;

    /** @brief Total time duration skipped due to silence. */
    double silence_skipped_time_;

    /** @brief Timer used to defer mouse updates. */
    QTimer *mouse_update_timer_;

    /** @brief Current tracked mouse position. */
    QPoint mouse_pos_;

//  const QString streamKey(const rtpstream_info_t *rtpstream);
//  const QString streamKey(const packet_info *pinfo, const struct _rtp_info *rtpinfo);

    // Tap callbacks
//  static void tapReset(void *tapinfo_ptr);

    /**
     * @brief Core tap callback for intercepting RTP packets.
     * @param tapinfo_ptr Pointer to the dialog's tap context.
     * @param pinfo Packet info structure.
     * @param rtpinfo_ptr Pointer to the specific RTP info block.
     * @param flags Tap flags.
     * @return Tap packet status indicating what to do next.
     */
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *rtpinfo_ptr, tap_flags_t flags);

    /**
     * @brief Post-tap drawing callback.
     * @param tapinfo_ptr Pointer to the dialog's tap context.
     */
    static void tapDraw(void *tapinfo_ptr);

    /**
     * @brief Integrates an incoming RTP packet into the proper audio stream.
     * @param pinfo Packet info structure.
     * @param rtpinfo Pointer to the parsed RTP info block.
     */
    void addPacket(packet_info *pinfo, const struct _rtp_info *rtpinfo);

    /**
     * @brief Adjusts the zoom level of the X-axis.
     * @param in True to zoom in, false to zoom out.
     */
    void zoomXAxis(bool in);

    /**
     * @brief Pans the X-axis view left or right.
     * @param x_pixels Number of pixels to pan.
     */
    void panXAxis(int x_pixels);

    /**
     * @brief Formats a time value into a human-readable string.
     * @param f_time The time in seconds.
     * @return The formatted time string.
     */
    const QString getFormatedTime(double f_time);

    /**
     * @brief Gets a formatted string for the time currently under the mouse hover.
     * @return The formatted hover time string.
     */
    const QString getFormatedHoveredTime();

    /**
     * @brief Retrieves the packet index currently being hovered over.
     * @return The packet index, or a negative value if not hovering on one.
     */
    int getHoveredPacket();

    /**
     * @brief Retrieves the name of the currently selected audio output device.
     * @return The output device name.
     */
    QString currentOutputDeviceName();

    /**
     * @brief Gets the exact time position of the start play marker.
     * @return The marker time in seconds.
     */
    double getStartPlayMarker();

    /**
     * @brief Repaints the start play marker on the plot based on current values.
     */
    void drawStartPlayMarker();

    /**
     * @brief Assigns a new time value to the start play marker.
     * @param new_time The new marker time in seconds.
     */
    void setStartPlayMarker(double new_time);

    /**
     * @brief Updates tracking metrics related to stream start and stop times.
     * @param rtpstream The RTP stream info to process.
     * @param is_first Flag indicating if this is the first tracked stream.
     */
    void updateStartStopTime(rtpstream_info_t *rtpstream, bool is_first);

    /**
     * @brief Updates the visual formatting of an item depending on its routing.
     * @param ti The tree widget item.
     * @param audio_routing The assigned audio routing configuration.
     */
    void formatAudioRouting(QTreeWidgetItem *ti, AudioRouting audio_routing);

    /**
     * @brief Tests if the current hardware and software context supports stereo audio.
     * @return True if stereo is available, false otherwise.
     */
    bool isStereoAvailable();

    /**
     * @brief Retrieves an audio output instance configured for silence (marker timing).
     * @return Pointer to a QAudioSink.
     */
    QAudioSink *getSilenceAudioOutput();

    /**
     * @brief Obtains the underlying QAudioDevice structure based on user selection.
     * @return The configured audio device.
     */
    QAudioDevice getCurrentDeviceInfo();

    /**
     * @brief Finds a tree widget item located at specific UI coordinates.
     * @param point The point to query.
     * @return Pointer to the matched item, or nullptr.
     */
    QTreeWidgetItem *findItemByCoords(QPoint point);

    /**
     * @brief Locates the tree widget item corresponding to a specific plottable object.
     * @param plottable The target QCPAbstractPlottable.
     * @return Pointer to the associated item, or nullptr.
     */
    QTreeWidgetItem *findItem(QCPAbstractPlottable *plottable);

    /**
     * @brief Applies highlight logic to a tree item and optionally scrolls to it.
     * @param ti The target tree item.
     * @param scroll True to scroll the list so the item is visible.
     */
    void handleItemHighlight(QTreeWidgetItem *ti, bool scroll);

    /**
     * @brief Toggles the visual highlight state of a tree item.
     * @param ti The target tree item.
     * @param highlight True to highlight, false to unhighlight.
     */
    void highlightItem(QTreeWidgetItem *ti, bool highlight);

    /**
     * @brief Inverts the active selection of streams within the tree.
     */
    void invertSelection();

    /**
     * @brief Logic to navigate to the setup packet associated with the given tree item.
     * @param ti The target tree item.
     */
    void handleGoToSetupPacket(QTreeWidgetItem *ti);

    /**
     * @brief Adds a single parsed RTP stream structure to the internal view.
     * @param id The RTP stream identifier.
     */
    void addSingleRtpStream(rtpstream_id_t *id);

    /**
     * @brief Destroys and removes a row representation from the list.
     * @param ti The item to remove.
     */
    void removeRow(QTreeWidgetItem *ti);

    /**
     * @brief Populates the audio rate combobox menu based on device capabilities.
     */
    void fillAudioRateMenu();

    /**
     * @brief Resets and stops the timing marker stream to clean up resources.
     */
    void cleanupMarkerStream();

    /**
     * @brief Writes a Sun AU format audio header to the provided file.
     * @param save_file The file to write into.
     * @param channels The number of audio channels.
     * @param audio_rate The sample rate.
     * @return The number of bytes written.
     */
    qint64 saveAudioHeaderAU(QFile *save_file, quint32 channels, unsigned audio_rate);

    /**
     * @brief Writes a Microsoft WAV format audio header to the provided file.
     * @param save_file The file to write into.
     * @param channels The number of audio channels.
     * @param audio_rate The sample rate.
     * @param samples The total count of audio samples.
     * @return The number of bytes written.
     */
    qint64 saveAudioHeaderWAV(QFile *save_file, quint32 channels, unsigned audio_rate, qint64 samples);

    /**
     * @brief Generates and writes raw silence samples out to a file.
     * @param out_file The output target file.
     * @param samples The quantity of silence samples to produce.
     * @param stream_count The count of parallel streams determining amplitude adjustment.
     * @return True if successful, false otherwise.
     */
    bool writeAudioSilenceSamples(QFile *out_file, qint64 samples, int stream_count);

    /**
     * @brief Extracts audio samples from RTP streams and writes them sequentially.
     * @param out_file The target file.
     * @param streams The collection of streams to extract data from.
     * @param big_endian Flag indicating whether to write bytes in big-endian format.
     * @return True if successful, false otherwise.
     */
    bool writeAudioStreamsSamples(QFile *out_file, QVector<RtpAudioStream *> streams, bool big_endian);

    /**
     * @brief Prompts the user to select an audio format and file path for saving audio.
     * @param file_path Reference to store the chosen path.
     * @return The chosen audio format enum.
     */
    save_audio_t selectFileAudioFormatAndName(QString *file_path);

    /**
     * @brief Prompts the user to select a payload format and file path for saving payload.
     * @param file_path Reference to store the chosen path.
     * @return The chosen payload format enum.
     */
    save_payload_t selectFilePayloadFormatAndName(QString *file_path);

    /**
     * @brief Returns a collection of streams that are actively selected and unmuted.
     * @return A vector of RtpAudioStream pointers.
     */
    QVector<RtpAudioStream *>getSelectedAudibleNonmutedAudioStreams();

    /**
     * @brief High-level orchestration for executing an audio save operation.
     * @param save_mode The selected save mode parameter.
     */
    void saveAudio(save_mode_t save_mode);

    /**
     * @brief High-level orchestration for executing a payload save operation.
     */
    void savePayload();

    /**
     * @brief Increments the UI lock counter, preventing interactive edits.
     */
    void lockUI();

    /**
     * @brief Decrements the UI lock counter, optionally restoring interactivity.
     */
    void unlockUI();

    /**
     * @brief Iterates the tree view to select or deselect inaudible streams.
     * @param select True to select, false to deselect.
     */
    void selectInaudible(bool select);

    /**
     * @brief Aggregates the RTP IDs representing the currently selected tree rows.
     * @return A vector of rtpstream_id_t pointers.
     */
    QVector<rtpstream_id_t *>getSelectedRtpStreamIDs();

    /**
     * @brief Refreshes column data based on previously tapped packet info.
     */
    void fillTappedColumns();

#else // QT_MULTIMEDIA_LIB
private:
    /** @brief Pointer to the UI object for this dialog (when multimedia is disabled). */
    Ui::RtpPlayerDialog *ui;
#endif // QT_MULTIMEDIA_LIB
};

#endif // RTP_PLAYER_DIALOG_H
