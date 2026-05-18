/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SHOW_PACKET_BYTES_DIALOG_H
#define SHOW_PACKET_BYTES_DIALOG_H

#include <config.h>
#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <epan/tvbuff.h>
#include "wireshark_dialog.h"

#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QTextCodec>

namespace Ui {
class ShowPacketBytesDialog;
class ShowPacketBytesTextEdit;
}

/**
 * @brief Describes a single decompression algorithm available in the
 *        "Decode As" list of ShowPacketBytesDialog.
 */
struct uncompress_list_t {
    QString name;                                               /**< Human-readable name of the decompression algorithm. */
    tvbuff_t *(*function)(tvbuff_t *, unsigned, unsigned);     /**< Decompression function pointer; takes a tvbuff and offset/length, returns a new tvbuff. */
};


/**
 * @brief Dialog that displays the raw bytes of a selected packet field,
 *        with configurable decode and display transformations (codecs,
 *        decompression, image rendering, hex dump, etc.) and text search.
 */
class ShowPacketBytesDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a ShowPacketBytesDialog for the currently selected field.
     * @param parent Reference to the parent widget.
     * @param cf     Capture file providing the packet data.
     */
    explicit ShowPacketBytesDialog(QWidget &parent, CaptureFile &cf);

    /**
     * @brief Destroys the dialog and releases all associated resources.
     */
    ~ShowPacketBytesDialog();

    /**
     * @brief Populates the character-encoding combo box with the supplied codecs.
     * @param codecMap Map of codec display names to QTextCodec pointers.
     */
    void addCodecs(const QMap<QString, QTextCodec *> &codecMap);

protected:
    /**
     * @brief Intercepts events on watched objects; used to detect text selection
     *        changes in the display widget.
     * @param obj   Object that received the event.
     * @param event The event to filter.
     * @return @c true to suppress the event; @c false to pass it on.
     */
    bool eventFilter(QObject *obj, QEvent *event);

    /**
     * @brief Handles key press events; maps Ctrl+F to the find field and
     *        Enter/Return to findText().
     * @param event The key event to process.
     */
    void keyPressEvent(QKeyEvent *event);

private slots:
    /**
     * @brief Updates the byte range start offset and refreshes the display.
     * @param value New start byte offset (0-based).
     */
    void on_sbStart_valueChanged(int value);

    /**
     * @brief Updates the byte range end offset and refreshes the display.
     * @param value New end byte offset (inclusive, 0-based).
     */
    void on_sbEnd_valueChanged(int value);

    /**
     * @brief Applies the selected decode transformation (e.g. decompression,
     *        quoted-printable, ROT13) and refreshes the display.
     * @param idx New combo-box index.
     */
    void on_cbDecodeAs_currentIndexChanged(int idx);

    /**
     * @brief Switches the display format (ASCII, hex dump, image, etc.) and
     *        refreshes the display widget.
     * @param idx New combo-box index.
     */
    void on_cbShowAs_currentIndexChanged(int idx);

    /**
     * @brief Triggers a forward text search when Enter is pressed in the find field.
     */
    void on_leFind_returnPressed();

    /**
     * @brief Executes a text search in the current direction when the Find button
     *        is clicked.
     */
    void on_bFind_clicked();

    /**
     * @brief Closes the dialog when the Cancel/Close button is activated.
     */
    void on_buttonBox_rejected();

    /**
     * @brief Restricts the displayed bytes to the range [@p start, @p end] as
     *        selected in the display widget.
     * @param start Start index of the selected byte range.
     * @param end   End index of the selected byte range (inclusive).
     */
    void showSelected(int start, int end);

    /**
     * @brief Switches the find mode between plain-text and regular-expression search.
     * @param use_regex @c true to enable regex find; @c false for plain-text.
     */
    void useRegexFind(bool use_regex);

    /**
     * @brief Searches the display widget for the current find expression.
     * @param go_back @c true to wrap around to the end when the search reaches
     *                the bottom; @c false to stop at the last match.
     */
    void findText(bool go_back = true);

    /** @brief Opens the context-sensitive help page for this dialog. */
    void helpButton();

    /** @brief Sends the current display content to the system printer. */
    void printBytes();

    /** @brief Copies the current display content to the system clipboard. */
    void copyBytes();

    /** @brief Opens a file-save dialog and writes the raw or decoded bytes to disk. */
    void saveAs();

private:
    /**
     * @brief Sets both the start and end byte offsets without triggering
     *        redundant refreshes.
     * @param start New start offset.
     * @param end   New end offset.
     */
    void setStartAndEnd(int start, int end);

    /**
     * @brief Returns whether the "Show Selected" action should be enabled based
     *        on the current selection state.
     * @return @c true if a valid sub-range is selected.
     */
    bool enableShowSelected();

    /**
     * @brief Refreshes the enabled/disabled state of all UI controls.
     */
    void updateWidgets();

    /**
     * @brief Updates the hint label text to reflect the current byte range and
     *        any decode/display warnings.
     */
    void updateHintLabel();

    /**
     * @brief Replaces non-printable bytes in @p ba with placeholder characters.
     * @param ba        Byte array to sanitise in-place.
     * @param handle_CR @c true to convert bare CR characters to CRLF.
     */
    void sanitizeBuffer(QByteArray &ba, bool handle_CR);

    /**
     * @brief Replaces each byte in @p ba with its Unicode control-picture symbol
     *        for display in the symbolised view.
     * @param ba Byte array to transform in-place.
     */
    void symbolizeBuffer(QByteArray &ba);

    /**
     * @brief Decodes a quoted-printable encoded byte sequence into a QByteArray.
     * @param bytes  Pointer to the raw quoted-printable encoded data.
     * @param length Number of bytes to decode.
     * @return Decoded byte array.
     */
    QByteArray decodeQuotedPrintable(const uint8_t *bytes, int length);

    /**
     * @brief Applies ROT13 substitution to every ASCII letter in @p ba.
     * @param ba Byte array to transform in-place.
     */
    void rot13(QByteArray &ba);

    /**
     * @brief Rebuilds @c field_bytes_ from the currently selected protocol-tree
     *        field and triggers a display refresh.
     * @param initialization @c true when called during dialog construction to
     *                       suppress animated transitions.
     */
    void updateFieldBytes(bool initialization = false);

    /**
     * @brief Applies the active decode transformation to @c field_bytes_ and
     *        updates the display widget with the result.
     */
    void updatePacketBytes();

    Ui::ShowPacketBytesDialog *ui; /**< Qt Designer-generated UI object for this dialog. */

    tvbuff_t   *tvb_;            /**< Tvbuff for the currently displayed field data. */
    QByteArray  field_bytes_;    /**< Raw bytes of the selected protocol-tree field. */
    QString     hint_label_;     /**< Current hint/status text shown below the display area. */
    QString     decode_as_name_; /**< Display name of the active decode transformation. */
    QPushButton *print_button_;  /**< "Print" button in the button box. */
    QPushButton *copy_button_;   /**< "Copy" button in the button box. */
    QPushButton *save_as_button_;/**< "Save As" button in the button box. */
    bool        use_regex_find_; /**< @c true when regex mode is active for the find operation. */
    int         start_;          /**< Current start byte offset within field_bytes_. */
    int         end_;            /**< Current end byte offset within field_bytes_ (inclusive). */
    QImage      image_;          /**< Decoded image, valid when the display mode is set to image. */
};


/**
 * @brief QTextEdit subclass used inside ShowPacketBytesDialog that adds a
 *        context menu with "Show Selected Bytes" and "Show All Bytes" actions.
 */
class ShowPacketBytesTextEdit : public QTextEdit
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a ShowPacketBytesTextEdit.
     * @param parent Optional parent widget.
     */
    explicit ShowPacketBytesTextEdit(QWidget *parent = nullptr);

    /**
     * @brief Destroys the text edit widget.
     */
    ~ShowPacketBytesTextEdit() { }

    /**
     * @brief Enables or disables the "Show Selected Bytes" context menu action.
     * @param enabled @c true to enable the action when text is selected.
     */
    void setShowSelectedEnabled(bool enabled) { show_selected_enabled_ = enabled; }

    /**
     * @brief Enables or disables the entire context menu.
     * @param enabled @c true to show the context menu on right-click.
     */
    void setMenusEnabled(bool enabled) { menus_enabled_ = enabled; }

signals:
    /**
     * @brief Emitted when the user chooses "Show Selected Bytes", carrying the
     *        character positions of the selection within the displayed text.
     * @param start Start character position of the selection.
     * @param end   End character position of the selection (exclusive).
     */
    void showSelected(int start, int end);

private slots:
    /**
     * @brief Presents a context menu with "Show Selected Bytes" and "Show All Bytes"
     *        actions at the cursor position.
     * @param event The context menu event.
     */
    void contextMenuEvent(QContextMenuEvent *event);

    /**
     * @brief Emits showSelected() with the current text-cursor selection bounds.
     */
    void showSelected();

    /**
     * @brief Emits showSelected() with bounds that encompass the entire content,
     *        restoring the full byte range.
     */
    void showAll();

private:
    bool show_selected_enabled_; /**< @c true when the "Show Selected Bytes" action may be enabled. */
    bool menus_enabled_;         /**< @c true when the context menu should be displayed. */
};

#endif // SHOW_PACKET_BYTES_DIALOG_H
