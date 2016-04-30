/* bluetooth_devices_dialog.h
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

protected slots:
    void changeEvent(QEvent* event);

private:
    Ui::BluetoothDevicesDialog *ui;
    PacketList *packet_list_;

    bluetooth_devices_tapinfo_t   tapinfo_;
    QMenu        context_menu_;

    static void     tapReset(void *tapinfo_ptr);
    static gboolean tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *data);

private slots:
    void captureFileClosing();
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
