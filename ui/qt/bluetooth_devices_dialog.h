/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef BLUETOOTH_DEVICES_DIALOG_H
#define BLUETOOTH_DEVICES_DIALOG_H

#include "config.h"

#include "wireshark_dialog.h"
#include <epan/cfile.h>
#include "packet_list.h"

#include "epan/tap.h"

#include <QMenu>

class QAbstractButton;
class QPushButton;
class QTreeWidgetItem;

/**
 * @brief Tap info block driving the Bluetooth Devices dialog's live packet feed.
 *
 * Registered with the Wireshark tap framework to receive reset and per-packet
 * callbacks for all captured Bluetooth frames, populating the full device list.
 */
typedef struct _bluetooth_devices_tapinfo_t {
    tap_reset_cb   tap_reset;  /**< Callback invoked to clear the full device list between captures. */
    tap_packet_cb  tap_packet; /**< Callback invoked once per Bluetooth packet to update the device list. */
    void          *ui;         /**< Opaque pointer to the owning UI widget (typically a @c BluetoothDevicesDialog). */
} bluetooth_devices_tapinfo_t;

namespace Ui {
class BluetoothDevicesDialog;
}

/**
 * @brief A dialog that displays Bluetooth device information from a live or
 *        saved capture.
 */
class BluetoothDevicesDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Construct a BluetoothDevicesDialog.
     * @param parent      The parent widget (passed to WiresharkDialog).
     * @param cf          The capture file whose packets are being analyzed.
     * @param packet_list The packet list used to navigate to individual packets.
     */
    explicit BluetoothDevicesDialog(QWidget &parent, CaptureFile &cf, PacketList *packet_list);
    /** @brief Destroy the BluetoothDevicesDialog. */
    ~BluetoothDevicesDialog();

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
     *
     * Processes shortcuts such as Ctrl+F for find and Escape to close.
     * @param event The key event.
     */
    void keyPressEvent(QKeyEvent *event);

    /**
     * @brief Called when the associated capture file is closed.
     *
     * Clears the device table and disables controls that require an open file.
     */
    void captureFileClosed();

protected slots:
    /**
     * @brief Handle change events such as language or palette changes.
     * @param event The change event.
     */
    void changeEvent(QEvent* event);

private:
    Ui::BluetoothDevicesDialog *ui;     /**< The UI for the dialog. */
    PacketList *packet_list_;           /**< Packet list used for goToPacket navigation. */

    bluetooth_devices_tapinfo_t tapinfo_; /**< Tap listener state for the bluetooth_devices tap. */
    QMenu context_menu_;                /**< Context menu shown on right-click in the table. */

    /**
     * @brief Tap reset callback — clears all collected device data.
     *
     * Called by the tap framework before a retap to reset accumulated state.
     * @param tapinfo_ptr Pointer to the @c bluetooth_devices_tapinfo_t for this dialog.
     */
    static void tapReset(void *tapinfo_ptr);

    /**
     * @brief Tap packet callback — processes one dissected packet.
     *
     * Called by the tap framework for each packet that matches the
     * @c bluetooth_devices tap. Extracts device information and adds or
     * updates the corresponding row in the table.
     *
     * @param tapinfo_ptr Pointer to the @c bluetooth_devices_tapinfo_t for this dialog.
     * @param pinfo       Packet metadata for the current packet.
     * @param data        Tap-specific data carrying the Bluetooth device record.
     * @param flags       Tap flags for the current packet.
     * @return TAP_PACKET_REDRAW if the display should be refreshed, otherwise
     *         TAP_PACKET_DONT_REDRAW.
     */
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *data, tap_flags_t flags);

private slots:
    /**
     * @brief Navigate to the source packet when a table row is activated.
     * @param item   The activated tree widget item.
     */
    void on_tableTreeWidget_itemActivated(QTreeWidgetItem *item, int);

    /**
     * @brief Handle button box button clicks (e.g., Close, Help).
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
     * @brief Navigate to the source packet when a table row is double-clicked.
     * @param item   The double-clicked tree widget item.
     * @param column The column that was double-clicked.
     */
    void tableItemDoubleClicked(QTreeWidgetItem *item, int column);

    /**
     * @brief Update the displayed device data when the capture interface selection changes.
     * @param index The index of the newly selected interface in the interface combo box.
     */
    void interfaceCurrentIndexChanged(int index);

    /**
     * @brief Show or hide intermediate HCI event rows based on the checkbox state.
     * @param state The new check state of the "Show information steps" checkbox
     *              (Qt::Checked or Qt::Unchecked).
     */
    void showInformationStepsChanged(int state);
};

#endif // BLUETOOTH_DEVICES_DIALOG_H
