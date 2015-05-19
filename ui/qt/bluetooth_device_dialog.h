/* bluetooth_device_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

protected slots:
    void changeEvent(QEvent* event);

private:
    Ui::BluetoothDeviceDialog *ui;

    bluetooth_device_tapinfo_t   tapinfo_;
    QMenu        context_menu_;
    guint        changes_;

    static void     tapReset(void *tapinfo_ptr);
    static gboolean tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *data);
    static void updateChanges(QTableWidget *tableWidget, QString value, const int row, guint *changes, packet_info *pinfo);
    static void saveItemData(QTableWidgetItem *item, bluetooth_device_tap_t *tap_device, packet_info *pinfo);

private slots:
    void captureFileClosing();
    void setTitle(QString bdAddr, QString name);
    void on_tableWidget_itemActivated(QTableWidgetItem *item);
    void on_buttonBox_clicked(QAbstractButton *button);
    void on_actionCopy_Cell_triggered();
    void on_actionCopy_Rows_triggered();
    void on_actionCopy_All_triggered();
    void on_actionSave_as_image_triggered();
    void tableContextMenu(const QPoint &pos);
    void interfaceCurrentIndexChanged(int index);
    void showInformationStepsChanged(int state);
};

#endif // BLUETOOTH_DEVICE_DIALOG_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
