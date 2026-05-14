/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef BLUETOOTH_DEVICE_DIALOG_H
#define BLUETOOTH_DEVICE_DIALOG_H

#include "config.h"

#include "wireshark_dialog.h"
#include <epan/cfile.h>

#include "epan/tap.h"

#include "epan/dissectors/packet-bluetooth.h"

#include <QMenu>
#include <QTableWidget>

class QAbstractButton;
class QPushButton;
class QTreeWidgetItem;

typedef struct _bluetooth_device_tapinfo_t {
    tap_reset_cb    tap_reset;
    tap_packet_cb   tap_packet;
    QString         bdAddr;
    uint32_t        interface_id;
    uint32_t        adapter_id;
    bool            is_local;
    void           *ui;
    unsigned       *changes;
} bluetooth_device_tapinfo_t;

typedef struct _bluetooth_item_data_t {
        uint32_t interface_id;
        uint32_t adapter_id;
        uint32_t frame_number;
        int      changes;
} bluetooth_item_data_t;

namespace Ui {
class BluetoothDeviceDialog;
}

/**
 * @brief Dialog displaying detail information about a Bluetooth device.
 */
class BluetoothDeviceDialog : public WiresharkDialog
{
    Q_OBJECT


public:
    /**
     * @brief Construct a BluetoothDeviceDialog.
     *
     * @param parent       The parent widget.
     * @param cf           The capture file.
     * @param bdAddr       The Bluetooth device address to display.
     * @param name         The display name of the device.
     * @param interface_id The interface ID the device was seen on.
     * @param adapter_id   The adapter ID the device was seen on.
     * @param is_local     Whether the device is the local adapter.
     */
    explicit BluetoothDeviceDialog(QWidget &parent, CaptureFile &cf, QString bdAddr, QString name, uint32_t interface_id, uint32_t adapter_id, bool is_local);

    /** @brief Destroy the BluetoothDeviceDialog. */
    ~BluetoothDeviceDialog();

public slots:

signals:
    /** @brief Emitted when the display filter should be updated.
     *  @param filter The new filter string.
     *  @param force  Whether to force the update even if unchanged. */
    void updateFilter(QString &filter, bool force = false);

    /** @brief Emitted when the capture file changes.
     *  @param cf The new capture file. */
    void captureFileChanged(capture_file *cf);

    /** @brief Emitted when the view should navigate to a specific packet.
     *  @param packet_num The packet number to navigate to. */
    void goToPacket(int packet_num);


protected:
    /** @brief Handle key press events.
     *  @param event The key event. */
    void keyPressEvent(QKeyEvent *event);

    /** @brief Handle capture file closing. */
    void captureFileClosing();

protected slots:
    /** @brief Handle change events such as language changes.
     *  @param event The change event. */
    void changeEvent(QEvent* event);

private:
    Ui::BluetoothDeviceDialog *ui;

    bluetooth_device_tapinfo_t   tapinfo_;  /**< Tap info structure for this dialog. */
    QMenu        context_menu_;             /**< Right-click context menu. */
    unsigned     changes_;                  /**< Number of value changes detected. */

    /** @brief Tap reset callback; clears accumulated tap data.
     *  @param tapinfo_ptr Pointer to the @c bluetooth_device_tapinfo_t. */
    static void     tapReset(void *tapinfo_ptr);

    /** @brief Tap packet callback; processes each matching packet.
     *  @param tapinfo_ptr Pointer to the @c bluetooth_device_tapinfo_t.
     *  @param pinfo       The packet info.
     *  @param data        Protocol-specific tap data.
     *  @param flags       Tap flags for the current packet.
     *  @return The tap packet status. */
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *data, tap_flags_t flags);

    /** @brief Update a table cell if the value has changed, incrementing the
     *  change counter if so.
     *  @param tableWidget The table widget containing the cell.
     *  @param value       The new value string.
     *  @param row         The row index of the cell to update.
     *  @param changes     The change counter to increment on a change.
     *  @param pinfo       The packet info for the frame that caused the change. */
    static void updateChanges(QTableWidget *tableWidget, QString value, const int row, unsigned *changes, packet_info *pinfo);

    /** @brief Save tap data into a table widget item for later use.
     *  @param item       The table widget item to annotate.
     *  @param tap_device The Bluetooth device tap data.
     *  @param pinfo      The packet info for the associated frame. */
    static void saveItemData(QTableWidgetItem *item, bluetooth_device_tap_t *tap_device, packet_info *pinfo);

private slots:
    /** @brief Set the dialog title from the device address and name.
     *  @param bdAddr The Bluetooth device address.
     *  @param name   The device name. */
    void setTitle(QString bdAddr, QString name);

    /** @brief Handle activation of a table item (e.g. double-click).
     *  @param item The activated table widget item. */
    void on_tableWidget_itemActivated(QTableWidgetItem *item);

    /** @brief Handle button box button clicks.
     *  @param button The button that was clicked. */
    void on_buttonBox_clicked(QAbstractButton *button);

    /** @brief Toggle the marked state of the currently selected cell. */
    void on_actionMark_Unmark_Cell_triggered();

    /** @brief Toggle the marked state of the currently selected row. */
    void on_actionMark_Unmark_Row_triggered();

    /** @brief Copy the currently selected cell value to the clipboard. */
    void on_actionCopy_Cell_triggered();

    /** @brief Copy the currently selected rows to the clipboard. */
    void on_actionCopy_Rows_triggered();

    /** @brief Copy all table contents to the clipboard. */
    void on_actionCopy_All_triggered();

    /** @brief Save the table contents as an image file. */
    void on_actionSave_as_image_triggered();

    /** @brief Show the context menu at the given position.
     *  @param pos The position at which to show the menu. */
    void tableContextMenu(const QPoint &pos);

    /** @brief Handle a change in the selected interface.
     *  @param index The new interface combo box index. */
    void interfaceCurrentIndexChanged(int index);

    /** @brief Handle a change in the show-information-steps checkbox.
     *  @param state The new checkbox state. */
    void showInformationStepsChanged(int state);
};

#endif // BLUETOOTH_DEVICE_DIALOG_H
