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

#include <glib.h>

#include "wireshark_dialog.h"
#include "cfile.h"
#include "packet_list.h"

#include "epan/tap.h"

#include <QMenu>

class QAbstractButton;
class QPushButton;
class QTreeWidgetItem;

typedef struct _bluetooth_hci_summary_tapinfo_t {
    tap_reset_cb    tap_reset;
    tap_packet_cb   tap_packet;
    void           *ui;
} bluetooth_hci_summary_tapinfo_t;

namespace Ui {
class BluetoothHciSummaryDialog;
}

class BluetoothHciSummaryDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit BluetoothHciSummaryDialog(QWidget &parent, CaptureFile &cf);
    ~BluetoothHciSummaryDialog();

public slots:

signals:
    void updateFilter(QString filter, bool force = false);
    void captureFileChanged(capture_file *cf);
    void goToPacket(int packet_num);

protected:
    void keyPressEvent(QKeyEvent *event);
    void captureFileClosing();
    void captureFileClosed();

protected slots:
    void changeEvent(QEvent* event);

private:
    Ui::BluetoothHciSummaryDialog *ui;

    bluetooth_hci_summary_tapinfo_t   tapinfo_;
    QMenu        context_menu_;

    QTreeWidgetItem  *item_link_control_;
    QTreeWidgetItem  *item_link_policy_;
    QTreeWidgetItem  *item_controller_and_baseband_;
    QTreeWidgetItem  *item_informational_;
    QTreeWidgetItem  *item_status_parameters_;
    QTreeWidgetItem  *item_testing_;
    QTreeWidgetItem  *item_low_energy_;
    QTreeWidgetItem  *item_logo_testing_;
    QTreeWidgetItem  *item_vendor_;
    QTreeWidgetItem  *item_unknown_ogf_;
    QTreeWidgetItem  *item_events_;
    QTreeWidgetItem  *item_status_;
    QTreeWidgetItem  *item_reason_;
    QTreeWidgetItem  *item_hardware_errors_;

    static void     tapReset(void *tapinfo_ptr);
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *data, tap_flags_t flags);

private slots:
    void recursiveCopyTreeItems(QTreeWidgetItem *item, QString &copy, int ident_level);
    void on_tableTreeWidget_itemActivated(QTreeWidgetItem *item, int);
    void on_buttonBox_clicked(QAbstractButton *button);
    void on_actionMark_Unmark_Cell_triggered();
    void on_actionMark_Unmark_Row_triggered();
    void on_actionCopy_Cell_triggered();
    void on_actionCopy_Rows_triggered();
    void on_actionCopy_All_triggered();
    void on_actionSave_as_image_triggered();
    void tableContextMenu(const QPoint &pos);
    void tableItemExpanded(QTreeWidgetItem *item);
    void tableItemCollapsed(QTreeWidgetItem *item);
    void interfaceCurrentIndexChanged(int index);
    void adapterCurrentIndexChanged(int index);
    void displayFilterLineEditAccepted();
    void resultsFilterLineEditChanged(const QString &text);
};

#endif // BLUETOOTH_HCI_SUMMARY_DIALOG_H
