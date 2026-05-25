/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FOLLOW_STREAM_TEXT_H
#define FOLLOW_STREAM_TEXT_H

#include <QPlainTextEdit>

/**
 * @brief A custom plain text edit widget for displaying followed stream data.
 */
class FollowStreamText : public QPlainTextEdit
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new FollowStreamText widget.
     * @param parent The parent widget, defaults to 0.
     */
    explicit FollowStreamText(QWidget *parent = 0);

    /**
     * @brief Checks if the displayed text was truncated due to length limits.
     * @return True if the text is truncated, false otherwise.
     */
    bool isTruncated() const { return truncated_; }

    /**
     * @brief Adds a segment of text to the display.
     * @param text The text to add.
     * @param is_from_server True if the text came from the server, false if from the client.
     * @param packet_num The packet number associated with the text.
     * @param colorize True to apply directional colors to the text.
     * @param marked True if the text represents marked packets or specific metadata.
     */
    void addText(QString text, bool is_from_server, uint32_t packet_num, bool colorize, bool marked);

    /**
     * @brief Adds a delta time metadata string to the display.
     * @param delta The delta time value to add.
     */
    void addDeltaTime(double delta);

    /**
     * @brief Retrieves the packet number corresponding to the current cursor position.
     * @return The packet number.
     */
    int currentPacket() const;

protected:
    /**
     * @brief Handles mouse move events to track packet selection.
     * @param event The mouse event.
     */
    void mouseMoveEvent(QMouseEvent *event) override;

    /**
     * @brief Handles mouse press events to select specific packets.
     * @param event The mouse event.
     */
    void mousePressEvent(QMouseEvent *event) override;

    /**
     * @brief Handles events when the mouse leaves the widget.
     * @param event The leave event.
     */
    void leaveEvent(QEvent *event) override;

signals:
    /**
     * @brief Signal emitted when the mouse hovers over text belonging to a specific packet.
     * @param packet_num The packet number hovered over.
     */
    void mouseMovedToPacket(int packet_num);

    /**
     * @brief Signal emitted when text belonging to a specific packet is clicked.
     * @param packet_num The packet number that was clicked.
     */
    void mouseClickedOnPacket(int packet_num);

public slots:
    /**
     * @brief Clears the text display and internal mapping.
     */
    void clear();

private:
    /**
     * @brief Maps a character position in the text edit to its corresponding packet number.
     * @param text_pos The character position index.
     * @return The associated packet number.
     */
    int textPosToPacket(int text_pos) const;

    /**
     * @brief Adds a truncation message and marks the document as truncated.
     * @param cur_pos The current position where truncation occurred.
     */
    void addTruncated(int cur_pos);

    /** The maximum length of the document before truncation occurs. */
    static const int        max_document_length_;

    /** Flag indicating if the document has been truncated. */
    bool                    truncated_;

    /** Mapping of text cursor positions to packet numbers. */
    QMap<int, uint32_t>     text_pos_to_packet_;

    /** The foreground color used for metadata information. */
    QColor                  metainfo_fg_;
};

#endif // FOLLOW_STREAM_TEXT_H
