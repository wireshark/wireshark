/* bluetooth_devices_dialog.cpp
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

#include "bluetooth_devices_dialog.h"
#include <ui_bluetooth_devices_dialog.h>

#include "bluetooth_device_dialog.h"

#include "epan/epan.h"
#include "epan/addr_resolv.h"
#include "epan/to_str.h"
#include "epan/epan_dissect.h"
#include "epan/dissectors/packet-bluetooth.h"
#include "epan/dissectors/packet-bthci_evt.h"

#include "ui/simple_dialog.h"

#include <QClipboard>
#include <QContextMenuEvent>
#include <QPushButton>
#include <QTreeWidget>
#include <QFileDialog>

static const int column_number_bd_addr = 0;
static const int column_number_bd_addr_oui = 1;
static const int column_number_name = 2;
static const int column_number_lmp_version = 3;
static const int column_number_lmp_subversion = 4;
static const int column_number_manufacturer = 5;
static const int column_number_hci_version = 6;
static const int column_number_hci_revision = 7;
static const int column_number_is_local_adapter = 8;

typedef struct _item_data_t {
        guint32  interface_id;
        guint32  adapter_id;
        guint32  frame_number;
} item_data_t;

Q_DECLARE_METATYPE(item_data_t *)

static gboolean
bluetooth_device_tap_packet(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *edt, const void* data)
{
    bluetooth_devices_tapinfo_t *tapinfo = (bluetooth_devices_tapinfo_t *) tapinfo_ptr;

    if (tapinfo->tap_packet)
        tapinfo->tap_packet(tapinfo, pinfo, edt, data);

    return TRUE;
}

static void
bluetooth_device_tap_reset(void *tapinfo_ptr)
{
    bluetooth_devices_tapinfo_t *tapinfo = (bluetooth_devices_tapinfo_t *) tapinfo_ptr;

    if (tapinfo->tap_reset)
        tapinfo->tap_reset(tapinfo);
}

BluetoothDevicesDialog::BluetoothDevicesDialog(QWidget &parent, CaptureFile &cf, PacketList *packet_list) :
    WiresharkDialog(parent, cf),
    ui(new Ui::BluetoothDevicesDialog)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 2 / 3);

    packet_list_ = packet_list;

    connect(ui->tableTreeWidget, SIGNAL(customContextMenuRequested(const QPoint &)), this, SLOT(tableContextMenu(const QPoint &)));
    connect(ui->tableTreeWidget, SIGNAL(itemDoubleClicked(QTreeWidgetItem *, int)), this, SLOT(tableItemDoubleClicked(QTreeWidgetItem *, int)));
    connect(ui->interfaceComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(interfaceCurrentIndexChanged(int)));
    connect(ui->showInformationStepsCheckBox, SIGNAL(stateChanged(int)), this, SLOT(showInformationStepsChanged(int)));

    ui->tableTreeWidget->sortByColumn(column_number_bd_addr, Qt::AscendingOrder);

    context_menu_.addActions(QList<QAction *>() << ui->actionCopy_Cell);
    context_menu_.addActions(QList<QAction *>() << ui->actionCopy_Rows);
    context_menu_.addActions(QList<QAction *>() << ui->actionCopy_All);
    context_menu_.addActions(QList<QAction *>() << ui->actionSave_as_image);

    tapinfo_.tap_packet = tapPacket;
    tapinfo_.tap_reset  = tapReset;
    tapinfo_.ui = this;

    registerTapListener("bluetooth.device", &tapinfo_, NULL,
                        0,
                        bluetooth_device_tap_reset,
                        bluetooth_device_tap_packet,
                        NULL
                        );
    ui->hintLabel->setText(ui->hintLabel->text().arg(0));

    cap_file_.retapPackets();
}


BluetoothDevicesDialog::~BluetoothDevicesDialog()
{
    delete ui;
}


void BluetoothDevicesDialog::captureFileClosing()
{
    ui->interfaceComboBox->setEnabled(FALSE);
    ui->showInformationStepsCheckBox->setEnabled(FALSE);

    WiresharkDialog::captureFileClosing();
}


void BluetoothDevicesDialog::changeEvent(QEvent *event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            ui->retranslateUi(this);
            break;
        default:
            break;
        }
    }
    QDialog::changeEvent(event);
}


void BluetoothDevicesDialog::keyPressEvent(QKeyEvent *)
{
/* NOTE: Do nothing, but in real it "takes focus" from button_box so allow user
 * to use Enter button to jump to frame from tree widget */
}


void BluetoothDevicesDialog::tableContextMenu(const QPoint &pos)
{
    context_menu_.exec(ui->tableTreeWidget->viewport()->mapToGlobal(pos));
}

void BluetoothDevicesDialog::tableItemDoubleClicked(QTreeWidgetItem *item, int column _U_)
{
    item_data_t            *item_data;
    BluetoothDeviceDialog  *bluetooth_device_dialog;

    item_data = item->data(0, Qt::UserRole).value<item_data_t *>();
    bluetooth_device_dialog = new BluetoothDeviceDialog(*this, cap_file_, item->text(column_number_bd_addr), item->text(column_number_name), item_data->interface_id, item_data->adapter_id, !item->text(column_number_is_local_adapter).isEmpty());
    connect(bluetooth_device_dialog, SIGNAL(goToPacket(int)),
            packet_list_, SLOT(goToPacket(int)));
    bluetooth_device_dialog->show();
}

void BluetoothDevicesDialog::on_actionCopy_Cell_triggered()
{
    QClipboard             *clipboard = QApplication::clipboard();
    QString                 copy;

    copy = QString(ui->tableTreeWidget->currentItem()->text(ui->tableTreeWidget->currentColumn()));

    clipboard->setText(copy);
}


void BluetoothDevicesDialog::on_actionCopy_Rows_triggered()
{
    QClipboard                         *clipboard = QApplication::clipboard();
    QString                             copy;
    QList<QTreeWidgetItem *>            items;
    QList<QTreeWidgetItem *>::iterator  i_item;

    items =  ui->tableTreeWidget->selectedItems();

    for (i_item = items.begin(); i_item != items.end(); ++i_item) {
        copy += QString("%1  %2  %3  %4  %5  %6  %7  %8  %9\n")
                .arg((*i_item)->text(column_number_bd_addr), -20)
                .arg((*i_item)->text(column_number_bd_addr_oui), -20)
                .arg((*i_item)->text(column_number_name), -30)
                .arg((*i_item)->text(column_number_lmp_version), -20)
                .arg((*i_item)->text(column_number_lmp_subversion), -20)
                .arg((*i_item)->text(column_number_manufacturer), -30)
                .arg((*i_item)->text(column_number_hci_version), -20)
                .arg((*i_item)->text(column_number_hci_revision), -20)
                .arg((*i_item)->text(column_number_is_local_adapter), -20);
    }

    clipboard->setText(copy);
}

void BluetoothDevicesDialog::tapReset(void *tapinfo_ptr)
{
    bluetooth_devices_tapinfo_t *tapinfo = (bluetooth_devices_tapinfo_t *) tapinfo_ptr;
    BluetoothDevicesDialog  *bluetooth_devices_dialog = static_cast<BluetoothDevicesDialog *>(tapinfo->ui);

    bluetooth_devices_dialog->ui->tableTreeWidget->clear();
}

gboolean BluetoothDevicesDialog::tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *data)
{
    bluetooth_devices_tapinfo_t  *tapinfo    = static_cast<bluetooth_devices_tapinfo_t *>(tapinfo_ptr);
    BluetoothDevicesDialog       *dialog     = static_cast<BluetoothDevicesDialog *>(tapinfo->ui);
    bluetooth_device_tap_t       *tap_device = static_cast<bluetooth_device_tap_t *>(const_cast<void *>(data));
    QString                       bd_addr;
    QString                       bd_addr_oui;
    const gchar                  *manuf;
    QTreeWidgetItem              *item = NULL;

    if (dialog->file_closed_)
        return FALSE;

    if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID) {
        gchar       *interface;
        const char  *interface_name;

        interface_name = epan_get_interface_name(pinfo->epan, pinfo->phdr->interface_id);
        interface = wmem_strdup_printf(wmem_packet_scope(), "%u: %s", pinfo->phdr->interface_id, interface_name);

        if (dialog->ui->interfaceComboBox->findText(interface) == -1)
            dialog->ui->interfaceComboBox->addItem(interface);

        if (interface && dialog->ui->interfaceComboBox->currentIndex() > 0) {
            if (dialog->ui->interfaceComboBox->currentText() != interface)
            return TRUE;
        }
    }

    if (tap_device->has_bd_addr) {
        bd_addr.sprintf("%02x:%02x:%02x:%02x:%02x:%02x", tap_device->bd_addr[0], tap_device->bd_addr[1], tap_device->bd_addr[2], tap_device->bd_addr[3], tap_device->bd_addr[4], tap_device->bd_addr[5]);

        manuf = get_ether_name(tap_device->bd_addr);
        if (manuf) {
            int pos;

            bd_addr_oui = QString(manuf);
            pos = bd_addr_oui.indexOf('_');
            if (pos < 0) {
                manuf = NULL;
            } else {
                bd_addr_oui.remove(pos, bd_addr_oui.size());
            }
        }

        if (!manuf)
            bd_addr_oui = "";
    }

    if (dialog->ui->showInformationStepsCheckBox->checkState() != Qt::Checked) {
        QTreeWidgetItemIterator i_item(dialog->ui->tableTreeWidget);

        while (*i_item) {
            QTreeWidgetItem *current_item = static_cast<QTreeWidgetItem*>(*i_item);
            item_data_t *item_data = current_item->data(0, Qt::UserRole).value<item_data_t *>();

            if ((tap_device->has_bd_addr && current_item->text(column_number_bd_addr) == bd_addr) ||
                    (tap_device->is_local &&
                    item_data->interface_id == tap_device->interface_id &&
                    item_data->adapter_id == tap_device->adapter_id &&
                    !current_item->text(column_number_is_local_adapter).isEmpty())) {
                item = current_item;
                break;
            }
            ++i_item;
        }
    }

    if (!item) {
        item = new QTreeWidgetItem(dialog->ui->tableTreeWidget);
        item->setText(column_number_bd_addr, bd_addr);
        item->setText(column_number_bd_addr_oui, bd_addr_oui);
        if (tap_device->is_local) {
            item->setText(column_number_is_local_adapter,  tr("true"));
        }

        item_data_t *item_data = wmem_new(wmem_file_scope(), item_data_t);
        item_data->interface_id = tap_device->interface_id;
        item_data->adapter_id = tap_device->adapter_id;
        item_data->frame_number = pinfo->num;
        item->setData(0, Qt::UserRole, QVariant::fromValue<item_data_t *>(item_data));
    }

    if (tap_device->type == BLUETOOTH_DEVICE_BD_ADDR) {
        item->setText(column_number_bd_addr, bd_addr);
        item->setText(column_number_bd_addr_oui, bd_addr_oui);
    }

    if (tap_device->type == BLUETOOTH_DEVICE_NAME) {
        item->setText(column_number_name,  tap_device->data.name);
    }

    if (tap_device->type == BLUETOOTH_DEVICE_LOCAL_ADAPTER)
        item->setText(column_number_is_local_adapter,  tr("true"));

    if (tap_device->type == BLUETOOTH_DEVICE_LOCAL_VERSION) {
        item->setText(column_number_hci_version,    val_to_str_const(tap_device->data.local_version.hci_version, bthci_evt_hci_version, "Unknown 0x%02x"));
        item->setText(column_number_hci_revision,   QString("").sprintf("%u", tap_device->data.local_version.hci_revision));
        item->setText(column_number_lmp_version,    val_to_str_const(tap_device->data.local_version.lmp_version, bthci_evt_lmp_version, "Unknown 0x%02x"));
        item->setText(column_number_lmp_subversion, QString("").sprintf("%u", tap_device->data.local_version.lmp_subversion));
        item->setText(column_number_manufacturer,   val_to_str_ext_const(tap_device->data.local_version.manufacturer, &bluetooth_company_id_vals_ext, "Unknown 0x%04x"));
    }
    if (tap_device->type == BLUETOOTH_DEVICE_REMOTE_VERSION) {
        item->setText(column_number_lmp_version,    val_to_str_const(tap_device->data.remote_version.lmp_version, bthci_evt_lmp_version, "Unknown 0x%02x"));
        item->setText(column_number_lmp_subversion, QString("").sprintf("%u", tap_device->data.remote_version.lmp_subversion));
        item->setText(column_number_manufacturer,   val_to_str_ext_const(tap_device->data.remote_version.manufacturer, &bluetooth_company_id_vals_ext, "Unknown 0x%04x"));
    }

    for (int i = 0; i < dialog->ui->tableTreeWidget->columnCount(); i++) {
        dialog->ui->tableTreeWidget->resizeColumnToContents(i);
    }

    dialog->ui->hintLabel->setText(QString(tr("%1 items; Right click for more option; Double click for device details")).arg(dialog->ui->tableTreeWidget->topLevelItemCount()));

    return TRUE;
}

void BluetoothDevicesDialog::interfaceCurrentIndexChanged(int)
{
    cap_file_.retapPackets();
}

void BluetoothDevicesDialog::showInformationStepsChanged(int)
{
    cap_file_.retapPackets();
}

void BluetoothDevicesDialog::on_tableTreeWidget_itemActivated(QTreeWidgetItem *item, int)
{
    if (file_closed_)
        return;

    item_data_t *item_data = item->data(0, Qt::UserRole).value<item_data_t *>();

    emit goToPacket(item_data->frame_number);

}

void BluetoothDevicesDialog::on_actionCopy_All_triggered()
{
    QClipboard              *clipboard = QApplication::clipboard();
    QString                  copy;
    QTreeWidgetItemIterator  i_item(ui->tableTreeWidget);
    QTreeWidgetItem         *item;

    item = ui->tableTreeWidget->headerItem();

    copy += QString("%1  %2  %3  %4  %5  %6  %7  %8  %9\n")
            .arg(item->text(column_number_bd_addr), -20)
            .arg(item->text(column_number_bd_addr_oui), -20)
            .arg(item->text(column_number_name), -30)
            .arg(item->text(column_number_lmp_version), -20)
            .arg(item->text(column_number_lmp_subversion), -20)
            .arg(item->text(column_number_manufacturer), -30)
            .arg(item->text(column_number_hci_version), -20)
            .arg(item->text(column_number_hci_revision), -20)
            .arg(item->text(column_number_is_local_adapter), -20);

    while (*i_item) {
        item = static_cast<QTreeWidgetItem*>(*i_item);
        copy += QString("%1  %2  %3  %4  %5  %6  %7  %8  %9\n")
                .arg(item->text(column_number_bd_addr), -20)
                .arg(item->text(column_number_bd_addr_oui), -20)
                .arg(item->text(column_number_name), -30)
                .arg(item->text(column_number_lmp_version), -20)
                .arg(item->text(column_number_lmp_subversion), -20)
                .arg(item->text(column_number_manufacturer), -30)
                .arg(item->text(column_number_hci_version), -20)
                .arg(item->text(column_number_hci_revision), -20)
                .arg(item->text(column_number_is_local_adapter), -20);
        ++i_item;
    }

    clipboard->setText(copy);
}

void BluetoothDevicesDialog::on_actionSave_as_image_triggered()
{
    QPixmap image;

    QString fileName = QFileDialog::getSaveFileName(this,
            tr("Save Table Image"),
            "bluetooth_devices_table.png",
            tr("PNG Image (*.png)"));

    if (fileName.isEmpty()) return;

    image = QPixmap::grabWidget(ui->tableTreeWidget);
    image.save(fileName, "PNG");
}

void BluetoothDevicesDialog::on_buttonBox_clicked(QAbstractButton *)
{
/*    if (button == foo_button_) */
}

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
