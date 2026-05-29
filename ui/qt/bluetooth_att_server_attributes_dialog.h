/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef BLUETOOTH_ATT_SERVER_ATTRIBUTES_DIALOG_H
#define BLUETOOTH_ATT_SERVER_ATTRIBUTES_DIALOG_H

#include <config.h>

#include "wireshark_dialog.h"
#include <epan/cfile.h>

#include "epan/tap.h"

#include <QMenu>

class QAbstractButton;
class QPushButton;
class QTreeWidgetItem;

/**
 * @brief Bundles the callbacks and UI context required to drive a generic tap listener.
 */
typedef struct _tapinfo_t {
    tap_reset_cb  tap_reset;   /**< Callback invoked to reset accumulated tap data before a new pass. */
    tap_packet_cb tap_packet;  /**< Callback invoked once per matching packet to accumulate tap data. */
    void         *ui;          /**< Opaque pointer to the UI widget or context that consumes the tap data. */
} tapinfo_t;

namespace Ui {
class BluetoothAttServerAttributesDialog;
}

class QTreeWidgetItem;
/**
 * @brief A dialog that displays ATT server attribute data from a Bluetooth capture.
 */
class BluetoothAttServerAttributesDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Construct a BluetoothAttServerAttributesDialog.
     * @param parent The parent widget (passed to WiresharkDialog).
     * @param cf     The capture file whose packets are being analyzed.
     */
    explicit BluetoothAttServerAttributesDialog(QWidget &parent, CaptureFile &cf);

    /** @brief Destructor. */
    ~BluetoothAttServerAttributesDialog();

public slots:

signals:
    /**
     * @brief Emitted when the display filter should be updated.
     * @param filter The new filter expression string.
     * @param force  If true, apply the filter even if it is unchanged.
     */
    void updateFilter(QString filter, bool force = false);

    /**
     * @brief Emitted when the underlying capture file has changed.
     * @param cf Pointer to the new capture file structure.
     */
    void captureFileChanged(capture_file *cf);

    /**
     * @brief Emitted when the packet list should navigate to a specific packet.
     * @param packet_num The 1-based packet number to navigate to.
     */
    void goToPacket(int packet_num);


protected:
    /**
     * @brief Handle key press events.
     * @param event The key event.
     */
    void keyPressEvent(QKeyEvent *event);

    /**
     * @brief Called when the associated capture file is closed.
     */
    void captureFileClosed();


protected slots:
    /**
     * @brief Handle change events such as language or palette changes.
     * @param event The change event.
     */
    void changeEvent(QEvent *event);

private:
    Ui::BluetoothAttServerAttributesDialog *ui;

    tapinfo_t tapinfo_;      /**< Tap listener state for the ATT server attributes tap. */
    QMenu context_menu_;     /**< Context menu shown on right-click in the table. */

    /**
     * @brief Tap reset callback — clears all collected attribute data.
     * @param tapinfo_ptr Pointer to the @c tapinfo_t for this dialog.
     */
    static void tapReset(void *tapinfo_ptr);

    /**
     * @brief Tap packet callback — processes one dissected packet.
     *
     * @param tapinfo_ptr Pointer to the @c tapinfo_t for this dialog.
     * @param pinfo       Packet metadata for the current packet.
     * @param data        Tap-specific data carrying the ATT attribute record.
     * @param flags       Tap flags for the current packet.
     * @return TAP_PACKET_REDRAW if the display should be refreshed, otherwise
     *         TAP_PACKET_DONT_REDRAW.
     */
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo,
                                       epan_dissect_t *, const void *data,
                                       tap_flags_t flags);

private slots:
    /**
     * @brief Navigate to the source packet when a table row is activated.
     * @param item    The activated tree widget item.
     */
    void on_tableTreeWidget_itemActivated(QTreeWidgetItem *item, int);

    /**
     * @brief Handle button box button clicks (e.g. Close, Help).
     * @param button The button that was clicked.
     */
    void on_buttonBox_clicked(QAbstractButton *button);

    /** @brief Toggle the marked state of the cell under the context menu cursor. */
    void on_actionMark_Unmark_Cell_triggered();

    /** @brief Toggle the marked state of all cells in the selected row. */
    void on_actionMark_Unmark_Row_triggered();

    /** @brief Copy the text of the cell under the context menu cursor to the clipboard. */
    void on_actionCopy_Cell_triggered();

    /** @brief Copy all cells of the selected rows to the clipboard as tab-separated text. */
    void on_actionCopy_Rows_triggered();

    /** @brief Copy all rows in the table to the clipboard as tab-separated text. */
    void on_actionCopy_All_triggered();

    /** @brief Save the table contents as an image file chosen via a file dialog. */
    void on_actionSave_as_image_triggered();

    /**
     * @brief Show the context menu at the given position in the table.
     * @param pos The position of the right-click, in table-widget coordinates.
     */
    void tableContextMenu(const QPoint &pos);

    /**
     * @brief Update the displayed data when the capture interface selection changes.
     * @param index The index of the newly selected interface in the interface combo box.
     */
    void interfaceCurrentIndexChanged(int index);

    /**
     * @brief Update the displayed data when the Bluetooth device selection changes.
     * @param index The index of the newly selected device in the device combo box.
     */
    void deviceCurrentIndexChanged(int index);

#if QT_VERSION >= QT_VERSION_CHECK(6, 7, 0)
    /**
     * @brief Show or hide duplicate attribute rows based on the checkbox state.
     *
     * @param state The new check state of the "Remove duplicates" checkbox.
     */
    void removeDuplicatesStateChanged(Qt::CheckState state);
#else
    /**
     * @brief Show or hide duplicate attribute rows based on the checkbox state.
     *
     * @param state The new check state of the "Remove duplicates" checkbox
     *              (Qt::Checked or Qt::Unchecked).
     */
    void removeDuplicatesStateChanged(int state);
#endif
};

#endif // BLUETOOTH_ATT_SERVER_ATTRIBUTES_DIALOG_H
