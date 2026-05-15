/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FOLLOW_STREAM_DIALOG_H
#define FOLLOW_STREAM_DIALOG_H

#include <config.h>

#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "file.h"

#include "epan/follow.h"

#include "wireshark_dialog.h"

#include <QFile>
#include <QMap>
#include <QPushButton>
#include <QTextCodec>

namespace Ui {
class FollowStreamDialog;
}

/**
 * @brief A dialog window for viewing the contents of a network stream.
 */
class FollowStreamDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new FollowStreamDialog.
     * @param parent The parent widget.
     * @param cf The capture file containing the stream data.
     * @param proto_id The protocol ID of the stream to follow.
     */
    explicit FollowStreamDialog(QWidget &parent, CaptureFile &cf, int proto_id);

    /**
     * @brief Destroys the FollowStreamDialog.
     */
    ~FollowStreamDialog();

    /**
     * @brief Adds a map of character encodings to the dialog's codec selection.
     * @param codecMap A map of codec names to their QTextCodec pointers.
     */
    void addCodecs(const QMap<QString, QTextCodec *> &codecMap);

    /**
     * @brief Initiates the stream following process.
     * @param previous_filter An optional previous display filter to restore later.
     * @param use_stream_index True to follow using a specific stream index rather than the selected packet.
     * @param stream_num The specific stream number to follow (if use_stream_index is true).
     * @param sub_stream_num The specific sub-stream number (e.g., HTTP2 streams within a TCP connection).
     * @return True if the stream was successfully followed, false otherwise.
     */
    bool follow(QString previous_filter = QString(), bool use_stream_index = false, unsigned stream_num = 0, unsigned sub_stream_num = 0);

protected:
    /**
     * @brief Filters events for the dialog text display.
     * @param obj The object that generated the event.
     * @param event The event to filter.
     * @return True if the event was handled, false otherwise.
     */
    bool eventFilter(QObject *obj, QEvent *event);

    /**
     * @brief Handles key press events in the dialog.
     * @param event The key event.
     */
    void keyPressEvent(QKeyEvent *event);

    /**
     * @brief Slot triggered when the underlying capture file is closed.
     */
    void captureFileClosed();

    /**
     * @brief Generates a hint label based on the current packet.
     * @param pkt The packet number.
     * @return The formatted hint string.
     */
    virtual QString labelHint(int pkt = 0);

    /**
     * @brief Gets the number of packets sent by the client.
     * @return The client packet count.
     */
    int client_packet_count() const { return client_packet_count_; }

    /**
     * @brief Gets the number of packets sent by the server.
     * @return The server packet count.
     */
    int server_packet_count() const { return server_packet_count_; }

    /**
     * @brief Gets the number of direction changes (turns) in the stream.
     * @return The number of turns.
     */
    int turns() const { return turns_; }

    /**
     * @brief Retrieves the core follow_info structure.
     * @return A reference to the follow_info_t struct.
     */
    const follow_info_t& followInfo() const { return follow_info_; }

    /**
     * @brief Gets the string representation for the server-to-client direction.
     * @return The direction string.
     */
    virtual QString serverToClientString() const;

    /**
     * @brief Gets the string representation for the client-to-server direction.
     * @return The direction string.
     */
    virtual QString clientToServerString() const;

    /**
     * @brief Gets the string representation for both directions.
     * @return The direction string.
     */
    virtual QString bothDirectionsString() const;


private slots:
    /**
     * @brief Slot triggered when the selected character set changes.
     * @param idx The new character set index.
     */
    void cbCharsetCurrentIndexChanged(int idx);

    /**
     * @brief Slot triggered when the time delta display combobox changes.
     * @param idx The new index.
     */
    void deltaComboBoxCurrentIndexChanged(int idx);

    /**
     * @brief Slot triggered when the traffic direction filter changes.
     * @param idx The new direction index.
     */
    void cbDirectionsCurrentIndexChanged(int idx);

    /**
     * @brief Slot triggered when the Find button is clicked.
     */
    void bFindClicked();

    /**
     * @brief Slot triggered when the Return key is pressed in the Find line edit.
     */
    void leFindReturnPressed();

    /**
     * @brief Slot triggered when the Help button is clicked.
     */
    void helpButton();

    /**
     * @brief Slot triggered when the Back button is clicked.
     */
    void backButton();

    /**
     * @brief Slot triggered to close the dialog.
     */
    void close();

    /**
     * @brief Slot triggered to apply a filter excluding the current stream.
     */
    void filterOut();

    /**
     * @brief Slot triggered to toggle regex search mode.
     * @param use_regex True to enable regex search, false for plain text.
     */
    void useRegexFind(bool use_regex);

    /**
     * @brief Executes a text search within the stream display.
     * @param go_back True to search backward, false to search forward.
     */
    void findText(bool go_back = true);

    /**
     * @brief Slot triggered to save the stream contents to a file.
     */
    void saveAs();

    /**
     * @brief Slot triggered to print the stream contents.
     */
    void printStream();

    /**
     * @brief Updates the hint label based on the current text cursor position.
     * @param pkt The packet number.
     */
    void fillHintLabel(int pkt = 0);

    /**
     * @brief Selects the corresponding packet in the main window based on the text cursor.
     * @param pkt The packet number.
     */
    void goToPacketForTextPos(int pkt = 0);

    /**
     * @brief Slot triggered when the stream number spin box changes.
     * @param stream_num The new stream number.
     */
    void streamNumberSpinBoxValueChanged(int stream_num);

    /**
     * @brief Slot triggered when the sub-stream number spin box changes.
     * @param sub_stream_num The new sub-stream number.
     */
    void subStreamNumberSpinBoxValueChanged(int sub_stream_num);

    /**
     * @brief Slot triggered when the dialog is rejected.
     */
    void buttonBoxRejected();

signals:
    /**
     * @brief Signal emitted to update the main display filter.
     * @param filter The new display filter.
     * @param force True to force the filter application.
     */
    void updateFilter(QString filter, bool force);

    /**
     * @brief Signal emitted to navigate to a specific packet in the main window.
     * @param packet_num The packet number to jump to.
     */
    void goToPacket(int packet_num);

private:
    /**
     * @brief Callback used by register_tap_listener to reset the stream state.
     * @param tapData Pointer to the tap data.
     */
    static void resetStream(void *tapData);

    /**
     * @brief Hides or removes UI controls related to stream selection if not applicable.
     */
    void removeStreamControls();

    /**
     * @brief Resets the internal state of the stream display.
     */
    void resetStream(void);

    /**
     * @brief Updates the states of the dialog widgets based on processing status.
     * @param follow_in_progress True if the stream is currently being analyzed.
     */
    void updateWidgets(bool follow_in_progress);

    /**
     * @brief Updates the states of the dialog widgets.
     */
    void updateWidgets() { updateWidgets(false); } // Needed for WiresharkDialog?

    /**
     * @brief Appends a buffer of stream data to the text display.
     * @param buffer The byte array containing the data.
     * @param nchars The number of characters to display.
     * @param is_from_server True if the data originated from the server.
     * @param packet_num The packet number containing this data.
     * @param abs_ts The absolute timestamp of the packet.
     * @param global_pos Pointer to the global character position tracker.
     */
    void showBuffer(QByteArray &buffer, size_t nchars, bool is_from_server,
                uint32_t packet_num, nstime_t abs_ts, uint32_t *global_pos);

    /**
     * @brief Triggers reading of the stream data.
     */
    void readStream();

    /**
     * @brief Reads the stream data utilizing the specific registered follower.
     */
    void readFollowStream();

    /**
     * @brief Orchestrates the entire follow stream extraction and display process.
     */
    void followStream();

    /**
     * @brief Adds raw text to the display window.
     * @param text The string to append.
     * @param is_from_server True if the text originated from the server.
     * @param packet_num The associated packet number.
     * @param colorize True to apply directional coloring to the text.
     */
    void addText(QString text, bool is_from_server, uint32_t packet_num, bool colorize = true);

    /** Pointer to the generated UI elements. */
    Ui::FollowStreamDialog  *ui;

    /** Pointer to the "Filter Out" button. */
    QPushButton             *b_filter_out_;

    /** Pointer to the "Find" button. */
    QPushButton             *b_find_;

    /** Pointer to the "Print" button. */
    QPushButton             *b_print_;

    /** Pointer to the "Save As" button. */
    QPushButton             *b_save_;

    /** Pointer to the "Back" button. */
    QPushButton             *b_back_;

    /** The core structure holding information about the followed stream. */
    follow_info_t           follow_info_;

    /** Pointer to the specific protocol's stream follower functions. */
    register_follow_t*      follower_;

    /** The display filter active before the dialog was opened. */
    QString                 previous_filter_;

    /** The filter string used to exclude this stream. */
    QString                 filter_out_filter_;

    /** The filter string representing this specific stream. */
    QString                 output_filter_;

    /** Counter for buffers received from the client. */
    int                     client_buffer_count_;

    /** Counter for buffers received from the server. */
    int                     server_buffer_count_;

    /** Counter for packets sent by the client. */
    int                     client_packet_count_;

    /** Counter for packets sent by the server. */
    int                     server_packet_count_;

    /** The packet number of the last processed packet. */
    uint32_t                last_packet_;

    /** Flag indicating if the last processed data was from the server. */
    bool                    last_from_server_;

    /** Timestamp of the last processed data segment. */
    nstime_t                last_ts_;

    /** Counter for how many times the stream changes direction. */
    int                     turns_;

    /** Flag indicating if the find operation uses regular expressions. */
    bool                    use_regex_find_;

    /** Flag indicating if the dialog is in the process of closing/terminating. */
    bool                    terminating_;

    /** The previously selected sub-stream number. */
    int                     previous_sub_stream_num_;
};

#endif // FOLLOW_STREAM_DIALOG_H
