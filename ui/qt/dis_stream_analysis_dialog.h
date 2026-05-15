/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DIS_STREAM_ANALYSIS_DIALOG_H
#define DIS_STREAM_ANALYSIS_DIALOG_H

#include <mutex>

#include <QDialogButtonBox>
#include <QTreeWidget>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>

#ifdef QT_MULTIMEDIA_LIB
#include <QAudio>
#endif

#include "capture_file.h"
#include "wireshark_dialog.h"

#include "ui/tap-dis-common.h"

class QComboBox;
class QCustomPlot;
class QCPItemStraightLine;
class QMouseEvent;

/**
 * @brief A dialog for analyzing and interacting with DIS (Distributed Interactive Simulation) streams.
 */
class DisStreamAnalysisDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Opens or retrieves the singleton instance of the DisStreamAnalysisDialog.
     * @param parent The parent widget.
     * @param cf The capture file being analyzed.
     * @param packet_list A pointer to the application's packet list object.
     * @return A pointer to the dialog instance.
     */
    static DisStreamAnalysisDialog *openDisStreamAnalysisDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list);

    /**
     * @brief Selects and loads a specific DIS stream for analysis.
     * @param stream_info Pointer to the DIS stream information structure.
     */
    void selectStream(disstream_info_t *stream_info);

    /**
     * @brief Deleted copy constructor to enforce singleton pattern.
     * @param other The object to copy from.
     */
    DisStreamAnalysisDialog(DisStreamAnalysisDialog &other) = delete;

    /**
     * @brief Deleted assignment operator to enforce singleton pattern.
     * @param other The object to assign from.
     */
    void operator=(const DisStreamAnalysisDialog &) = delete;

signals:
    /**
     * @brief Signal emitted to navigate the main UI to a specific packet number.
     * @param packet_num The packet number to jump to.
     */
    void goToPacket(int packet_num);

protected:
    /**
     * @brief Constructs a new DisStreamAnalysisDialog (protected for singleton usage).
     * @param parent The parent widget.
     * @param cf The capture file being analyzed.
     * @param packet_list A pointer to the application's packet list object.
     */
    explicit DisStreamAnalysisDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list);

    /**
     * @brief Destroys the DisStreamAnalysisDialog.
     */
    ~DisStreamAnalysisDialog();

    /**
     * @brief Slot triggered when the capture file begins closing.
     */
    void captureFileClosing() override;

    /**
     * @brief Slot triggered when the capture file is fully closed.
     */
    void captureFileClosed() override;

private:
    /** The singleton instance of the dialog. */
    static DisStreamAnalysisDialog *pinstance_;

    /** Mutex to ensure thread-safe creation of the singleton. */
    static std::mutex mutex_;

    /** Combo box for selecting different DIS streams. */
    QComboBox *stream_combo_;

    /** Custom plot widget for displaying stream audio or data characteristics. */
    QCustomPlot *audio_plot_;

    /** Tree widget listing individual packets in the stream. */
    QTreeWidget *packet_tree_;

    /** Label showing the duration of the stream. */
    QLabel *duration_label_;

    /** Label showing the number of packets in the stream. */
    QLabel *packets_label_;

    /** Label showing the signal strength/quality. */
    QLabel *signal_label_;

    /** Label showing the transmitter (TX) identifier. */
    QLabel *tx_label_;

    /** Label showing lost packet statistics. */
    QLabel *lost_label_;

    /** Label showing jitter statistics. */
    QLabel *jitter_label_;

    /** Label showing delta time statistics between packets. */
    QLabel *delta_label_;

    /** Label showing the detected codec, if applicable. */
    QLabel *codec_label_;

    /** Label displaying contextual hints or instructions. */
    QLabel *hint_label_;

    /** Progress bar tracking audio playback progress. */
    QProgressBar *playback_progress_;

    /** Label displaying current playback time formatting. */
    QLabel *playback_time_label_;

    /** Button box containing standard dialog actions. */
    QDialogButtonBox *button_box_;

    /** Button to start or pause playback. */
    QPushButton *play_button_;

    /** Button to stop playback. */
    QPushButton *stop_button_;

    /** Button to trigger navigation to a selected packet. */
    QPushButton *goto_button_;

    /** Graphical marker line indicating the playback start position. */
    QCPItemStraightLine *start_marker_pos_;

    /** Graphical marker line indicating the current playback position. */
    QCPItemStraightLine *playback_marker_pos_;

    /** Time value corresponding to the start marker. */
    double start_marker_time_;

    /** Time value corresponding to the playback marker. */
    double playback_marker_time_;

    /** Flag indicating if the plot or UI needs redrawing. */
    bool need_redraw_;

    /** Flag indicating if a specific stream has been requested for loading. */
    bool have_requested_stream_;

    /** The ID of the specifically requested stream. */
    disstream_id_t requested_stream_id_;

    /** Pointer to the application's packet list object. */
    QObject *packet_list_;

#ifdef QT_MULTIMEDIA_LIB
    /** Pointer to the internal class managing audio streaming. */
    class DisAudioStream *audio_stream_;
#endif

    /** Data structure tracking tap information for DIS streams. */
    disstream_tapinfo_t tapinfo_;

    /**
     * @brief Callback function to reset tap data.
     * @param tapinfo Pointer to the tap info structure.
     */
    static void tapReset(disstream_tapinfo_t *tapinfo);

    /**
     * @brief Callback function to trigger drawing/updating based on tap data.
     * @param tapinfo Pointer to the tap info structure.
     */
    static void tapDraw(disstream_tapinfo_t *tapinfo);

    /**
     * @brief Retrieves the currently selected stream's information.
     * @return Pointer to the active stream info structure.
     */
    disstream_info_t *selectedStream() const;

    /**
     * @brief Updates the list of available streams in the combo box.
     */
    void updateStreams();

    /**
     * @brief Updates the states and text of the dialog's widgets.
     */
    void updateWidgets() override;

    /**
     * @brief Recalculates and updates the statistical analysis for the selected stream.
     */
    void updateAnalysis();

    /**
     * @brief Populates the tree widget with the selected stream's packets.
     */
    void updatePacketRows();

    /**
     * @brief Refreshes the custom plot visual data.
     */
    void updatePlot();

    /**
     * @brief Updates the text of the hint label based on current context.
     */
    void updateHintLabel();

    /**
     * @brief Calculates the start time based on user selection in the plot.
     * @return The selected start time in seconds.
     */
    double selectedStartTime() const;

    /**
     * @brief Sets the internal time value for the playback start marker.
     * @param new_time The time to set in seconds.
     */
    void setStartPlayMarker(double new_time);

    /**
     * @brief Visually renders the playback start marker on the plot.
     */
    void drawStartPlayMarker();

    /**
     * @brief Sets the internal time value and visibility for the current playback marker.
     * @param new_time The time to set in seconds.
     * @param visible True to show the marker, false to hide it.
     */
    void setPlaybackMarker(double new_time, bool visible);

    /**
     * @brief Visually renders the current playback marker on the plot.
     */
    void drawPlaybackMarker();

private slots:
    /**
     * @brief Slot triggered when the selected stream in the combo box changes.
     * @param index The index of the newly selected stream.
     */
    void onStreamChanged(int index);

    /**
     * @brief Slot triggered when the Go To Packet button is clicked.
     */
    void onGoToPacket();

    /**
     * @brief Slot triggered when a packet row in the tree widget is double-clicked or activated.
     * @param item The activated tree item.
     * @param column The column activated.
     */
    void onPacketRowActivated(QTreeWidgetItem *item, int column);

    /**
     * @brief Slot triggered when the custom plot is double-clicked.
     * @param event The mouse event details.
     */
    void onGraphDoubleClicked(QMouseEvent *event);

#ifdef QT_MULTIMEDIA_LIB
    /**
     * @brief Slot triggered to play or pause the audio stream.
     */
    void onPlayPauseStream();

    /**
     * @brief Slot triggered to stop the audio stream.
     */
    void onStopStream();

    /**
     * @brief Slot triggered when audio playback progress advances.
     * @param position_secs The current position in seconds.
     * @param duration_secs The total duration in seconds.
     */
    void onPlaybackProgress(double position_secs, double duration_secs);

    /**
     * @brief Slot triggered when the audio playback state changes.
     * @param state The new audio state.
     */
    void onPlaybackStateChanged(QAudio::State state _U_);
#endif

    /**
     * @brief Slot triggered when a capture event occurs (e.g., file opened/closed).
     * @param e The capture event details.
     */
    void onCaptureEvent(CaptureEvent e);
};

#endif /* DIS_STREAM_ANALYSIS_DIALOG_H */
