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

#include <glib.h>

#include "wireshark_dialog.h"
#include "cfile.h"

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
    guint32         interface_id;
    guint32         adapter_id;
    gboolean        is_local;
    void           *ui;
    guint          *changes;
} bluetooth_device_tapinfo_t;

typedef struct _bluetooth_item_data_t {
        guint32  interface_id;
        guint32  adapter_id;
        guint32  frame_number;
        gint     changes;
} bluetooth_item_data_t;

namespace Ui {
class BluetoothDeviceDialog;
}

class BluetoothDeviceDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit BluetoothDeviceDialog(QWidget &parent, CaptureFile &cf, QString bdAddr, QString name, guint32 interface_id, guint32 adapter_id, gboolean is_local);
    ~BluetoothDeviceDialog();

public slots:

signals:
    void updateFilter(QString &filter, bool force = false);
    void captureFileChanged(capture_file *cf);
    void goToPacket(int packet_num);

protected:
    void keyPressEvent(QKeyEvent *event);
    void captureFileClosing();

protected slots:
    void changeEvent(QEvent* event);

private:
    Ui::BluetoothDeviceDialog *ui;

    bluetooth_device_tapinfo_t   tapinfo_;
    QMenu        context_menu_;
    guint        changes_;

    static void     tapReset(void *tapinfo_ptr);
    static tap_packet_status tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *data, tap_flags_t flags);
    static void updateChanges(QTableWidget *tableWidget, QString value, const int row, guint *changes, packet_info *pinfo);
    static void saveItemData(QTableWidgetItem *item, bluetooth_device_tap_t *tap_device, packet_info *pinfo);

private slots:
    void setTitle(QString bdAddr, QString name);
    void on_tableWidget_itemActivated(QTableWidgetItem *item);
    void on_buttonBox_clicked(QAbstractButton *button);
    void on_actionMark_Unmark_Cell_triggered();
    void on_actionMark_Unmark_Row_triggered();
    void on_actionCopy_Cell_triggered();
    void on_actionCopy_Rows_triggered();
    void on_actionCopy_All_triggered();
    void on_actionSave_as_image_triggered();
    void tableContextMenu(const QPoint &pos);
    void interfaceCurrentIndexChanged(int index);
    void showInformationStepsChanged(int state);
};

#endif // BLUETOOTH_DEVICE_DIALOG_H
