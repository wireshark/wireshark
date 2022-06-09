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

#include <glib.h>

#include "wireshark_dialog.h"
#include "cfile.h"
#include "packet_list.h"

#include "epan/tap.h"

#include <QMenu>

class QAbstractButton;
class QPushButton;
class QTreeWidgetItem;

typedef struct _bluetooth_devices_tapinfo_t {
    tap_reset_cb    tap_reset;
    tap_packet_cb   tap_packet;
    void           *ui;
} bluetooth_devices_tapinfo_t;

namespace Ui {
class BluetoothDevicesDialog;
}

class BluetoothDevicesDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit BluetoothDevicesDialog(QWidget &parent, CaptureFile &cf, PacketList *packet_list);
    ~BluetoothDevicesDialog();

public slots:

signals:
    void updateFilter(QString filter, bool force = false);
    void captureFileChanged(capture_file *cf);
    void goToPacket(int packet_num);

protected:
    void keyPressEvent(QKeyEvent *event);
    void captureFileClosed();

protected slots:
    void changeEvent(QEvent* event);

private:
    Ui::BluetoothDevicesDialog *ui;
    PacketList *packet_list_;

    bluetooth_devices_tapinfo_t   tapinfo_;
    QMenu        context_menu_;

    static void     tapReset(void *tapinfo_ptr);
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *data, tap_flags_t flags);

private slots:
    void on_tableTreeWidget_itemActivated(QTreeWidgetItem *item, int);
    void on_buttonBox_clicked(QAbstractButton *button);
    void on_actionMark_Unmark_Cell_triggered();
    void on_actionMark_Unmark_Row_triggered();
    void on_actionCopy_Cell_triggered();
    void on_actionCopy_Rows_triggered();
    void on_actionCopy_All_triggered();
    void on_actionSave_as_image_triggered();
    void tableContextMenu(const QPoint &pos);
    void tableItemDoubleClicked(QTreeWidgetItem *item, int column);
    void interfaceCurrentIndexChanged(int index);
    void showInformationStepsChanged(int state);
};

#endif // BLUETOOTH_DEVICES_DIALOG_H
