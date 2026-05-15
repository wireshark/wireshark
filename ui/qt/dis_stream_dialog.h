/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DIS_STREAM_DIALOG_H
#define DIS_STREAM_DIALOG_H

#include <mutex>

#include <QDialogButtonBox>
#include <QLabel>
#include <QPushButton>
#include <QTreeWidget>
#ifdef QT_MULTIMEDIA_LIB
#include <QAudio>
#endif

#include "capture_file.h"
#include "wireshark_dialog.h"

#include "ui/tap-dis-common.h"

#include "dis_stream_analysis_dialog.h"

/**
 * @brief A dialog for viewing and managing DIS (Distributed Interactive Simulation) streams from a capture file.
 */
class DisStreamDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Opens or retrieves the singleton instance of the DisStreamDialog.
     * @param parent The parent widget.
     * @param cf The capture file being analyzed.
     * @param packet_list A pointer to the application's packet list object.
     * @return A pointer to the dialog instance.
     */
    static DisStreamDialog *openDisStreamDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list);

    /**
     * @brief Deleted copy constructor to enforce singleton pattern.
     * @param other The object to copy from.
     */
    DisStreamDialog(DisStreamDialog &other) = delete;

    /**
     * @brief Deleted assignment operator to enforce singleton pattern.
     * @param other The object to assign from.
     */
    void operator=(const DisStreamDialog &) = delete;

signals:
    /**
     * @brief Signal emitted to update the application's display filter.
     * @param filter The new filter string.
     * @param force True to force the application even if unchanged, defaults to false.
     */
    void updateFilter(QString filter, bool force = false);

    /**
     * @brief Signal emitted to navigate the main UI to a specific packet number.
     * @param packet_num The packet number to jump to.
     */
    void goToPacket(int packet_num);

protected:
    /**
     * @brief Constructs a new DisStreamDialog (protected for singleton usage).
     * @param parent The parent widget.
     * @param cf The capture file being analyzed.
     * @param packet_list A pointer to the application's packet list object.
     */
    explicit DisStreamDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list);

    /**
     * @brief Destroys the DisStreamDialog.
     */
    ~DisStreamDialog();

    /**
     * @brief Slot triggered when the capture file begins closing.
     */
    void captureFileClosing() override;

    /**
     * @brief Slot triggered when the capture file is fully closed.
     */
    void captureFileClosed() override;

private:
    /**
     * @brief A customized tree widget item for representing a DIS stream, supporting custom sorting.
     */
    class DisStreamTreeWidgetItem : public QTreeWidgetItem {
    public:
        using QTreeWidgetItem::QTreeWidgetItem;
        /**
         * @brief Custom less-than operator for sorting columns accurately.
         * @param other The item to compare against.
         * @return True if this item is considered "less than" the other item.
         */
        bool operator<(const QTreeWidgetItem &other) const override;
    };

    /** The singleton instance of the dialog. */
    static DisStreamDialog *pinstance_;

    /** Mutex to ensure thread-safe creation of the singleton. */
    static std::mutex mutex_;

    /** Tree widget displaying the list of available streams. */
    QTreeWidget *stream_tree_;

    /** Button box containing standard dialog actions. */
    QDialogButtonBox *button_box_;

    /** Button used to prepare a display filter for the selected stream. */
    QPushButton *filter_button_;

    /** Button to start playback of the selected stream's audio. */
    QPushButton *play_button_;

    /** Button to stop playback of the stream's audio. */
    QPushButton *stop_button_;

    /** Button to open the detailed analysis dialog for the selected stream. */
    QPushButton *analyze_button_;

    /** Flag indicating whether the stream list needs to be redrawn. */
    bool need_redraw_;

    /** Pointer to the application's packet list object. */
    QObject *packet_list_;

#ifdef QT_MULTIMEDIA_LIB
    /** Pointer to the internal class managing audio streaming. */
    class DisAudioStream *audio_stream_;
#endif

    /** Data structure tracking tap information for DIS streams. */
    disstream_tapinfo_t tapinfo_;

    /**
     * @brief Callback function to reset tap data when starting or restarting capture.
     * @param tapinfo Pointer to the tap info structure.
     */
    static void tapReset(disstream_tapinfo_t *tapinfo);

    /**
     * @brief Callback function to trigger UI updates based on gathered tap data.
     * @param tapinfo Pointer to the tap info structure.
     */
    static void tapDraw(disstream_tapinfo_t *tapinfo);

    /**
     * @brief Retrieves the information structure for the currently selected stream.
     * @return Pointer to the active stream info structure.
     */
    disstream_info_t *selectedStream() const;

    /**
     * @brief Updates the tree widget with the latest stream data.
     */
    void updateStreams();

    /**
     * @brief Updates the states (enabled/disabled) of the dialog's widgets based on current selection.
     */
    void updateWidgets() override;

private slots:
    /**
     * @brief Slot triggered when the selection in the stream tree widget changes.
     */
    void onStreamSelectionChanged();

    /**
     * @brief Slot triggered when a stream item is double-clicked.
     * @param item The double-clicked tree item.
     * @param column The column clicked.
     */
    void onStreamItemDoubleClicked(QTreeWidgetItem *item, int column);

    /**
     * @brief Slot triggered to prepare and apply a display filter for the selected stream.
     */
    void onPrepareFilter();

    /**
     * @brief Slot triggered to open the detailed analysis dialog for the selected stream.
     */
    void onAnalyzeStream();

#ifdef QT_MULTIMEDIA_LIB
    /**
     * @brief Slot triggered to begin audio playback of the selected stream.
     */
    void onPlayStream();

    /**
     * @brief Slot triggered to stop audio playback.
     */
    void onStopStream();

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

#endif /* DIS_STREAM_DIALOG_H */
