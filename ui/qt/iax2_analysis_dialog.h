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

/**
 * @brief Enumerates the possible error types encountered during IAX2 stream analysis.
 */
typedef enum {
    TAP_IAX2_NO_ERROR,           /**< No error occurred. */
    TAP_IAX2_NO_PACKET_SELECTED, /**< No packet was selected for analysis. */
    TAP_IAX2_WRONG_LENGTH,       /**< A packet with an incorrect length was encountered. */
    TAP_IAX2_FILE_IO_ERROR       /**< A file input/output error occurred during saving. */
} iax2_error_type_t;


/**
 * @brief A dialog for analyzing IAX2 audio streams and displaying jitter/difference statistics.
 */
class Iax2AnalysisDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new Iax2AnalysisDialog.
     * @param parent The parent widget.
     * @param cf The capture file containing the IAX2 streams.
     */
    explicit Iax2AnalysisDialog(QWidget &parent, CaptureFile &cf);

    /**
     * @brief Destroys the Iax2AnalysisDialog.
     */
    ~Iax2AnalysisDialog();

signals:
    /**
     * @brief Signal emitted to navigate to a specific packet in the main display.
     * @param packet_num The target packet number.
     */
    void goToPacket(int packet_num);

protected slots:
    /**
     * @brief Updates the dialog's widgets based on the current data and selection state.
     */
    virtual void updateWidgets() override;

private slots:
    /**
     * @brief Slot triggered to go to the currently selected packet.
     */
    void on_actionGoToPacket_triggered();

    /**
     * @brief Slot triggered to jump to the next identified problem in the stream.
     */
    void on_actionNextProblem_triggered();

    /**
     * @brief Slot triggered when the forward jitter checkbox is toggled.
     * @param checked True if the graph should display forward jitter.
     */
    void on_fJitterCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the forward difference checkbox is toggled.
     * @param checked True if the graph should display forward difference.
     */
    void on_fDiffCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the reverse jitter checkbox is toggled.
     * @param checked True if the graph should display reverse jitter.
     */
    void on_rJitterCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the reverse difference checkbox is toggled.
     * @param checked True if the graph should display reverse difference.
     */
    void on_rDiffCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered to save audio for both directions.
     */
    void on_actionSaveAudio_triggered();

    /**
     * @brief Slot triggered to save audio for the forward direction only.
     */
    void on_actionSaveForwardAudio_triggered();

    /**
     * @brief Slot triggered to save audio for the reverse direction only.
     */
    void on_actionSaveReverseAudio_triggered();

    /**
     * @brief Slot triggered to save statistics as CSV for both directions.
     */
    void on_actionSaveCsv_triggered();

    /**
     * @brief Slot triggered to save statistics as CSV for the forward direction.
     */
    void on_actionSaveForwardCsv_triggered();

    /**
     * @brief Slot triggered to save statistics as CSV for the reverse direction.
     */
    void on_actionSaveReverseCsv_triggered();

    /**
     * @brief Slot triggered to save the current graph as an image.
     */
    void on_actionSaveGraph_triggered();

    /**
     * @brief Slot triggered when help is requested from the button box.
     */
    void on_buttonBox_helpRequested();

    /**
     * @brief Shows the context menu for the stream list.
     * @param pos The position to show the menu.
     */
    void showStreamMenu(QPoint pos);

    /**
     * @brief Shows the context menu for the graph view.
     * @param pos The position to show the menu.
     */
    void showGraphMenu(const QPoint &pos);

    /**
     * @brief Handles mouse clicks on the graph area.
     * @param event The mouse event containing click details.
     */
    void graphClicked(QMouseEvent *event);

private:
    /** Pointer to the generated UI elements. */
    Ui::Iax2AnalysisDialog *ui;

    /**
     * @brief Defines the direction of the stream for saving or exporting operations.
     */
    enum StreamDirection {
        dir_both_,     /**< Both forward and reverse directions. */
        dir_forward_,  /**< Forward direction only. */
        dir_reverse_   /**< Reverse direction only. */
    };

    /** Identifier for the forward RTP/IAX2 stream. */
    rtpstream_id_t fwd_id_;

    /** Identifier for the reverse RTP/IAX2 stream. */
    rtpstream_id_t rev_id_;

    /** Statistical information for the forward stream. */
    tap_iax2_stat_t fwd_statinfo_;

    /** Statistical information for the reverse stream. */
    tap_iax2_stat_t rev_statinfo_;

    /** Temporary file holding the forward stream audio payload. */
    QTemporaryFile *fwd_tempfile_;

    /** Temporary file holding the reverse stream audio payload. */
    QTemporaryFile *rev_tempfile_;

    /** List of graph objects displayed on the QCustomPlot. */
    QList<QCPGraph *>graphs_;

    /** Time values for the forward stream graph. */
    QVector<double> fwd_time_vals_;

    /** Jitter values for the forward stream graph. */
    QVector<double> fwd_jitter_vals_;

    /** Difference values for the forward stream graph. */
    QVector<double> fwd_diff_vals_;

    /** Time values for the reverse stream graph. */
    QVector<double> rev_time_vals_;

    /** Jitter values for the reverse stream graph. */
    QVector<double> rev_jitter_vals_;

    /** Difference values for the reverse stream graph. */
    QVector<double> rev_diff_vals_;

    /** String holding the latest error message, if any. */
    QString err_str_;

    /** The error status from the last payload save operation. */
    iax2_error_type_t save_payload_error_;

    /** Context menu for the stream list widget. */
    QMenu stream_ctx_menu_;

    /** Context menu for the graph widget. */
    QMenu graph_ctx_menu_;

    // Tap callbacks

    /**
     * @brief Callback used by register_tap_listener to reset tap data.
     * @param tapinfo_ptr Pointer to the dialog's tap context.
     */
    static void tapReset(void *tapinfo_ptr);

    /**
     * @brief Callback used by register_tap_listener when a packet is processed.
     * @param tapinfo_ptr Pointer to the dialog's tap context.
     * @param pinfo Pointer to the packet info structure.
     * @param iax2info_ptr Pointer to the specific IAX2 info from the dissector.
     * @param flags Tap flags.
     * @return The status of the tap packet processing.
     */
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, struct epan_dissect *, const void *iax2info_ptr, tap_flags_t flags);

    /**
     * @brief Callback used by register_tap_listener to draw or update results.
     * @param tapinfo_ptr Pointer to the dialog's tap context.
     */
    static void tapDraw(void *tapinfo_ptr);

    /**
     * @brief Resets the internally tracked statistics and graph data.
     */
    void resetStatistics();

    /**
     * @brief Adds packet data to the stream statistics.
     * @param forward True if the packet belongs to the forward stream.
     * @param pinfo Pointer to the packet info structure.
     * @param iax2info Pointer to the IAX2 protocol info.
     */
    void addPacket(bool forward, packet_info *pinfo, const struct _iax2_info_t *iax2info);

    /**
     * @brief Saves the payload of an IAX2 packet into a temporary file.
     * @param tmpfile Pointer to the temporary file to write into.
     * @param pinfo Pointer to the packet info structure.
     * @param iax2info Pointer to the IAX2 protocol info.
     */
    void savePayload(QTemporaryFile *tmpfile, packet_info *pinfo, const struct _iax2_info_t *iax2info);

    /**
     * @brief Updates the statistical displays with the gathered data.
     */
    void updateStatistics();

    /**
     * @brief Updates and redraws the graph using the collected data vectors.
     */
    void updateGraph();

    /**
     * @brief Prompts the user and saves the audio payload to a file.
     * @param direction The direction(s) of the stream to save.
     */
    void saveAudio(StreamDirection direction);

    /**
     * @brief Prompts the user and saves the stream statistics to a CSV file.
     * @param direction The direction(s) of the stream statistics to save.
     */
    void saveCsv(StreamDirection direction);

#if 0
    /**
     * @brief (Disabled) Processes a protocol node to extract integer values.
     * @param ptree_node The protocol tree node.
     * @param hfinformation The header field information.
     * @param proto_field The specific protocol field string to look for.
     * @param ok Pointer to a boolean set to true if extraction succeeds.
     * @return The extracted integer value.
     */
    uint32_t processNode(proto_node *ptree_node, header_field_info *hfinformation, const char* proto_field, bool *ok);

    /**
     * @brief (Disabled) Retrieves an integer value directly from the protocol tree.
     * @param protocol_tree The protocol tree.
     * @param proto_name The protocol name string.
     * @param proto_field The specific protocol field string.
     * @param ok Pointer to a boolean set to true if extraction succeeds.
     * @return The extracted integer value.
     */
    uint32_t getIntFromProtoTree(proto_tree *protocol_tree, const char *proto_name, const char *proto_field, bool *ok);
#endif

    /**
     * @brief Filters events for the dialog, capturing specific interactions like custom graph scaling.
     * @param event The event to filter.
     * @return True if the event was handled and should be stopped, false otherwise.
     */
    bool eventFilter(QObject*, QEvent* event) override;
};

#endif // IAX2_ANALYSIS_DIALOG_H
