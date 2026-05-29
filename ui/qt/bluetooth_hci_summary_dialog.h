/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef BLUETOOTH_HCI_SUMMARY_DIALOG_H
#define BLUETOOTH_HCI_SUMMARY_DIALOG_H

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
 * @brief Registers the tap callbacks and UI context for the Bluetooth HCI summary tap.
 */
typedef struct _bluetooth_hci_summary_tapinfo_t {
    tap_reset_cb    tap_reset;  /**< Callback invoked to reset the HCI summary tap state at the start of a new capture or retap. */
    tap_packet_cb   tap_packet; /**< Callback invoked for each HCI packet delivered to the tap. */
    void           *ui;         /**< Opaque pointer to the UI context or window associated with this tap instance. */
} bluetooth_hci_summary_tapinfo_t;

namespace Ui {
class BluetoothHciSummaryDialog;
}

/**
 * @brief Dialog displaying a summary of Bluetooth HCI traffic.
 */
class BluetoothHciSummaryDialog : public WiresharkDialog
{
    Q_OBJECT


public:
    /**
     * @brief Construct a BluetoothHciSummaryDialog.
     *
     * @param parent The parent widget.
     * @param cf     The capture file.
     */
    explicit BluetoothHciSummaryDialog(QWidget &parent, CaptureFile &cf);

    /** @brief Destroy the BluetoothHciSummaryDialog. */
    ~BluetoothHciSummaryDialog();

public slots:

signals:
    /** @brief Emitted when the display filter should be updated.
     *  @param filter The new filter string.
     *  @param force  Whether to force the update even if unchanged. */
    void updateFilter(QString filter, bool force = false);

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

    /** @brief Handle capture file closed. */
    void captureFileClosed();

protected slots:
    /** @brief Handle change events such as language changes.
     *  @param event The change event. */
    void changeEvent(QEvent* event);

private:
    Ui::BluetoothHciSummaryDialog *ui;

    bluetooth_hci_summary_tapinfo_t   tapinfo_;  /**< Tap info structure for this dialog. */
    QMenu        context_menu_;                  /**< Right-click context menu. */

    QTreeWidgetItem  *item_link_control_;           /**< Tree item for Link Control commands. */
    QTreeWidgetItem  *item_link_policy_;            /**< Tree item for Link Policy commands. */
    QTreeWidgetItem  *item_controller_and_baseband_; /**< Tree item for Controller and Baseband commands. */
    QTreeWidgetItem  *item_informational_;          /**< Tree item for Informational commands. */
    QTreeWidgetItem  *item_status_parameters_;      /**< Tree item for Status Parameters commands. */
    QTreeWidgetItem  *item_testing_;                /**< Tree item for Testing commands. */
    QTreeWidgetItem  *item_low_energy_;             /**< Tree item for Low Energy commands. */
    QTreeWidgetItem  *item_logo_testing_;           /**< Tree item for Logo Testing commands. */
    QTreeWidgetItem  *item_vendor_;                 /**< Tree item for Vendor-specific commands. */
    QTreeWidgetItem  *item_unknown_ogf_;            /**< Tree item for unknown OGF commands. */
    QTreeWidgetItem  *item_events_;                 /**< Tree item for HCI events. */
    QTreeWidgetItem  *item_status_;                 /**< Tree item for status values. */
    QTreeWidgetItem  *item_reason_;                 /**< Tree item for reason codes. */
    QTreeWidgetItem  *item_hardware_errors_;        /**< Tree item for hardware error events. */

    /** @brief Tap reset callback; clears accumulated tap data.
     *  @param tapinfo_ptr Pointer to the @c bluetooth_hci_summary_tapinfo_t. */
    static void     tapReset(void *tapinfo_ptr);

    /** @brief Tap packet callback; processes each matching packet.
     *  @param tapinfo_ptr Pointer to the @c bluetooth_hci_summary_tapinfo_t.
     *  @param pinfo       The packet info.
     *  @param data        Protocol-specific tap data.
     *  @param flags       Tap flags for the current packet.
     *  @return The tap packet status. */
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *data, tap_flags_t flags);


private slots:
    /** @brief Recursively copy tree items into a string for clipboard export.
     *  @param item        The tree item to copy.
     *  @param copy        The string to append the copied text to.
     *  @param ident_level The current indentation level. */
    void recursiveCopyTreeItems(QTreeWidgetItem *item, QString &copy, int ident_level);

    /** @brief Handle activation of a tree item (e.g. double-click).
     *  @param item The activated tree widget item. */
    void on_tableTreeWidget_itemActivated(QTreeWidgetItem *item, int);

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

    /** @brief Handle expansion of a tree item.
     *  @param item The tree widget item that was expanded. */
    void tableItemExpanded(QTreeWidgetItem *item);

    /** @brief Handle collapse of a tree item.
     *  @param item The tree widget item that was collapsed. */
    void tableItemCollapsed(QTreeWidgetItem *item);

    /** @brief Handle a change in the selected interface.
     *  @param index The new interface combo box index. */
    void interfaceCurrentIndexChanged(int index);

    /** @brief Handle a change in the selected adapter.
     *  @param index The new adapter combo box index. */
    void adapterCurrentIndexChanged(int index);

    /** @brief Handle acceptance of the display filter line edit. */
    void displayFilterLineEditAccepted();

    /** @brief Handle changes to the results filter line edit.
     *  @param text The current filter text. */
    void resultsFilterLineEditChanged(const QString &text);
};

#endif // BLUETOOTH_HCI_SUMMARY_DIALOG_H
