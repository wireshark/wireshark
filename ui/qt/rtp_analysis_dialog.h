/** @file
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

#include <mutex>

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
#include <QToolButton>

#include "wireshark_dialog.h"

namespace Ui {
class RtpAnalysisDialog;
}

class QCPGraph;
class QTemporaryFile;
class QDialogButtonBox;

class PacketList;
class RtpBaseDialog;

/**
 * @brief Structure to hold information and UI elements for an RTP stream analysis tab.
 */
typedef struct {
    /** The RTP stream information. */
    rtpstream_info_t stream;

    /** Pointer to a vector of time values for the graph. */
    QVector<double> *time_vals;

    /** Pointer to a vector of jitter values for the graph. */
    QVector<double> *jitter_vals;

    /** Pointer to a vector of difference values for the graph. */
    QVector<double> *diff_vals;

    /** Pointer to a vector of delta values for the graph. */
    QVector<double> *delta_vals;

    /** Pointer to the tree widget displaying packet statistics. */
    QTreeWidget *tree_widget;

    /** Pointer to the label displaying summary statistics. */
    QLabel *statistics_label;

    /** Pointer to the string holding the name of the tab. */
    QString *tab_name;

    /** Pointer to the graph representing jitter. */
    QCPGraph *jitter_graph;

    /** Pointer to the graph representing differences. */
    QCPGraph *diff_graph;

    /** Pointer to the graph representing deltas. */
    QCPGraph *delta_graph;

    /** Pointer to the horizontal layout containing the graphs. */
    QHBoxLayout *graphHorizontalLayout;

    /** Pointer to the checkbox for the stream visibility. */
    QCheckBox *stream_checkbox;

    /** Pointer to the checkbox for jitter graph visibility. */
    QCheckBox *jitter_checkbox;

    /** Pointer to the checkbox for difference graph visibility. */
    QCheckBox *diff_checkbox;

    /** Pointer to the checkbox for delta graph visibility. */
    QCheckBox *delta_checkbox;
} tab_info_t;

/**
 * @brief Singleton dialog for analyzing RTP streams.
 */
// Singleton by https://refactoring.guru/design-patterns/singleton/cpp/example#example-1
class RtpAnalysisDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Returns singleton instance of the RTP analysis dialog.
     * @param parent The parent widget.
     * @param cf The capture file.
     * @param packet_list The packet list.
     * @return Pointer to the singleton RtpAnalysisDialog instance.
     */
    static RtpAnalysisDialog *openRtpAnalysisDialog(QWidget &parent, CaptureFile &cf, PacketList *packet_list);

    /**
     * @brief Should not be cloneable.
     * @param other The dialog to copy from.
     */
    RtpAnalysisDialog(RtpAnalysisDialog &other) = delete;

    /**
     * @brief Should not be assignable.
     */
    void operator=(const RtpAnalysisDialog &) = delete;

    /**
     * @brief Common routine to add a "Analyze" button to a QDialogButtonBox.
     * @param button_box Caller's QDialogButtonBox.
     * @param dialog Pointer to the RtpBaseDialog.
     * @return The new "Analyze" button.
     */
    static QToolButton *addAnalyzeButton(QDialogButtonBox *button_box, RtpBaseDialog *dialog);

    /**
     * @brief Replace an RTP streams to analyse.
     * Requires array of rtpstream_id_t.
     *
     * @param stream_ids structs with rtpstream_id
     */
    void replaceRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Add RTP streams to analyse.
     * Requires array of rtpstream_id_t.
     *
     * @param stream_ids structs with rtpstream_id
     */
    void addRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Remove RTP streams to analyse.
     * Requires array of rtpstream_id_t.
     *
     * @param stream_ids structs with rtpstream_id
     */
    void removeRtpStreams(QVector<rtpstream_id_t *> stream_ids);

signals:
    /**
     * @brief Signal emitted to go to a specific packet number.
     * @param packet_num The target packet number.
     */
    void goToPacket(int packet_num);

    /**
     * @brief Signal emitted to replace RTP streams in the RTP player dialog.
     * @param stream_ids Vector of stream IDs to replace.
     */
    void rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Signal emitted to add RTP streams in the RTP player dialog.
     * @param stream_ids Vector of stream IDs to add.
     */
    void rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Signal emitted to remove RTP streams in the RTP player dialog.
     * @param stream_ids Vector of stream IDs to remove.
     */
    void rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Signal emitted to update the display filter.
     * @param filter The filter string.
     * @param force True to force the update, false otherwise.
     */
    void updateFilter(QString filter, bool force = false);

public slots:
    /**
     * @brief Slot to handle replacing streams in the RTP player.
     */
    void rtpPlayerReplace();

    /**
     * @brief Slot to handle adding streams to the RTP player.
     */
    void rtpPlayerAdd();

    /**
     * @brief Slot to handle removing streams from the RTP player.
     */
    void rtpPlayerRemove();

protected slots:
    /**
     * @brief Updates the UI widgets.
     */
    virtual void updateWidgets();

protected:
    /**
     * @brief Constructs a new RtpAnalysisDialog.
     * @param parent The parent widget.
     * @param cf The capture file.
     */
    explicit RtpAnalysisDialog(QWidget &parent, CaptureFile &cf);

    /**
     * @brief Destroys the RtpAnalysisDialog.
     */
    ~RtpAnalysisDialog();

private slots:
    /**
     * @brief Slot triggered when the "Go To Packet" action is activated.
     */
    void on_actionGoToPacket_triggered();

    /**
     * @brief Slot triggered when the "Next Problem" action is activated.
     */
    void on_actionNextProblem_triggered();

    /**
     * @brief Slot triggered when the "Save One CSV" action is activated.
     */
    void on_actionSaveOneCsv_triggered();

    /**
     * @brief Slot triggered when the "Save All CSV" action is activated.
     */
    void on_actionSaveAllCsv_triggered();

    /**
     * @brief Slot triggered when the "Save Graph" action is activated.
     */
    void on_actionSaveGraph_triggered();

    /**
     * @brief Slot triggered when help is requested from the button box.
     */
    void on_buttonBox_helpRequested();

    /**
     * @brief Shows the stream context menu at the given position.
     * @param pos The position to show the menu at.
     */
    void showStreamMenu(QPoint pos);

    /**
     * @brief Shows the graph context menu at the given position.
     * @param pos The position to show the menu at.
     */
    void showGraphMenu(const QPoint &pos);

    /**
     * @brief Slot triggered when the graph is clicked.
     * @param event The mouse event.
     */
    void graphClicked(QMouseEvent *event);

    /**
     * @brief Closes the tab at the given index.
     * @param index The index of the tab to close.
     */
    void closeTab(int index);

    /**
     * @brief Slot triggered when a row checkbox changes state.
     * @param checked The new check state.
     */
    void rowCheckboxChanged(int checked);

    /**
     * @brief Slot triggered when a single checkbox changes state.
     * @param checked The new check state.
     */
    void singleCheckboxChanged(int checked);

    /**
     * @brief Slot triggered when the "Prepare Filter One" action is activated.
     */
    void on_actionPrepareFilterOne_triggered();

    /**
     * @brief Slot triggered when the "Prepare Filter All" action is activated.
     */
    void on_actionPrepareFilterAll_triggered();

private:
    /** Pointer to the singleton instance. */
    static RtpAnalysisDialog *pinstance_;

    /** Mutex for thread-safe initialization. */
    static std::mutex init_mutex_;

    /** Mutex for thread-safe execution. */
    static std::mutex run_mutex_;

    /** Pointer to the generated UI class. */
    Ui::RtpAnalysisDialog *ui;

    /**
     * @brief Enumeration defining the direction for stream operations.
     */
    enum StreamDirection {
        dir_all_, /**< All streams. */
        dir_one_  /**< Single stream. */
    };

    /** Sequence number for tab indexing. */
    int tab_seq;

    /** Vector of pointers to tab information structures. */
    QVector<tab_info_t *> tabs_;

    /** Hash map mapping unsigned identifiers to tab info structures. */
    QMultiHash<unsigned, tab_info_t *> tab_hash_;

    /** Pointer to the player tool button. */
    QToolButton *player_button_;

    /** Graph data for QCustomPlot. */
    QList<QCPGraph *>graphs_;

    /** String holding the latest error message. */
    QString err_str_;

    /** Context menu for the stream list. */
    QMenu stream_ctx_menu_;

    /** Context menu for the graphs. */
    QMenu graph_ctx_menu_;

    /**
     * @brief Tap callback to reset the tap info.
     * @param tapinfo_ptr Pointer to the tap info.
     */
    static void tapReset(void *tapinfo_ptr);

    /**
     * @brief Tap callback to process an incoming packet.
     * @param tapinfo_ptr Pointer to the tap info.
     * @param pinfo Pointer to the packet info.
     * @param rtpinfo_ptr Pointer to the RTP info.
     * @param flags Tap flags.
     * @return The status of the tap packet processing.
     */
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *rtpinfo_ptr, tap_flags_t flags);

    /**
     * @brief Tap callback to draw the results.
     * @param tapinfo_ptr Pointer to the tap info.
     */
    static void tapDraw(void *tapinfo_ptr);

    /**
     * @brief Resets the accumulated statistics.
     */
    void resetStatistics();

    /**
     * @brief Adds packet data to the specified tab.
     * @param tab Pointer to the tab info.
     * @param pinfo Pointer to the packet info.
     * @param rtpinfo Pointer to the RTP info.
     */
    void addPacket(tab_info_t *tab, packet_info *pinfo, const struct _rtp_info *rtpinfo);

    /**
     * @brief Updates the statistics display.
     */
    void updateStatistics();

    /**
     * @brief Updates the graph display.
     */
    void updateGraph();

    /**
     * @brief Saves the CSV header to a file.
     * @param save_file Pointer to the file to save to.
     * @param tree Pointer to the tree widget providing the data.
     */
    void saveCsvHeader(QFile *save_file, QTreeWidget *tree);

    /**
     * @brief Saves the CSV data rows to a file.
     * @param save_file Pointer to the file to save to.
     * @param tree Pointer to the tree widget providing the data.
     */
    void saveCsvData(QFile *save_file, QTreeWidget *tree);

    /**
     * @brief Triggers the save CSV process for the specified stream direction.
     * @param direction The stream direction to save.
     */
    void saveCsv(StreamDirection direction);

    /**
     * @brief Event filter for intercepting events on target objects.
     * @param event The event being filtered.
     * @return True if the event was filtered out, false otherwise.
     */
    bool eventFilter(QObject*, QEvent* event);

    /**
     * @brief Retrieves the IDs of the currently selected RTP streams.
     * @return Vector of pointers to RTP stream IDs.
     */
    QVector<rtpstream_id_t *>getSelectedRtpIds();

    /**
     * @brief Adds a new tab UI for the given tab info.
     * @param new_tab Pointer to the new tab info structure.
     * @return The index of the newly added tab.
     */
    int addTabUI(tab_info_t *new_tab);

    /**
     * @brief Gets the tab info structure for the currently active tab.
     * @return Pointer to the active tab info.
     */
    tab_info_t *getTabInfoForCurrentTab();

    /**
     * @brief Deletes and cleans up a tab info structure.
     * @param tab_info Pointer to the tab info to delete.
     */
    void deleteTabInfo(tab_info_t *tab_info);

    /**
     * @brief Recursively clears a QLayout and its widgets.
     * @param layout Pointer to the layout to clear.
     */
    void clearLayout(QLayout *layout);

    /**
     * @brief Private helper method to add RTP streams.
     * @param stream_ids Vector of stream IDs to add.
     */
    void addRtpStreamsPrivate(QVector<rtpstream_id_t *> stream_ids);
};

#endif // RTP_ANALYSIS_DIALOG_H
