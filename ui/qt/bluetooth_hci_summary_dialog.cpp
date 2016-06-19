/* bluetooth_hci_summary_dialog.cpp
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

#include "bluetooth_hci_summary_dialog.h"
#include <ui_bluetooth_hci_summary_dialog.h>

#include "epan/epan.h"
#include "epan/addr_resolv.h"
#include "epan/to_str.h"
#include "epan/epan_dissect.h"
#include "epan/dissectors/packet-bluetooth.h"
#include "epan/dissectors/packet-bthci_cmd.h"
#include "epan/dissectors/packet-bthci_evt.h"

#include "ui/simple_dialog.h"

#include <QClipboard>
#include <QContextMenuEvent>
#include <QPushButton>
#include <QTreeWidget>
#include <QFileDialog>

static const int column_number_name = 0;
static const int column_number_ogf = 1;
static const int column_number_ocf = 2;
static const int column_number_opcode = 3;
static const int column_number_event = 4;
static const int column_number_status = 5;
static const int column_number_reason = 6;
static const int column_number_hardware_error = 7;
static const int column_number_occurrence = 8;

typedef struct _item_data_t {
        guint32  interface_id;
        guint32  adapter_id;
        guint32  frame_number;
} item_data_t;

Q_DECLARE_METATYPE(item_data_t *)

static gboolean
bluetooth_device_tap_packet(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *edt, const void* data)
{
    bluetooth_hci_summary_tapinfo_t *tapinfo = (bluetooth_hci_summary_tapinfo_t *) tapinfo_ptr;

    if (tapinfo->tap_packet)
        tapinfo->tap_packet(tapinfo, pinfo, edt, data);

    return TRUE;
}

static void
bluetooth_device_tap_reset(void *tapinfo_ptr)
{
    bluetooth_hci_summary_tapinfo_t *tapinfo = (bluetooth_hci_summary_tapinfo_t *) tapinfo_ptr;

    if (tapinfo->tap_reset)
        tapinfo->tap_reset(tapinfo);
}

static void
bluetooth_devices_tap(void *data)
{
    GString *error_string;

    error_string = register_tap_listener("bluetooth.hci_summary", data, NULL,
            0,
            bluetooth_device_tap_reset,
            bluetooth_device_tap_packet,
            NULL
            );

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }
}


BluetoothHciSummaryDialog::BluetoothHciSummaryDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::BluetoothHciSummaryDialog)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 2 / 3);

    connect(ui->tableTreeWidget, SIGNAL(customContextMenuRequested(const QPoint &)), this, SLOT(tableContextMenu(const QPoint &)));
    connect(ui->tableTreeWidget, SIGNAL(itemExpanded(QTreeWidgetItem *)), this, SLOT(tableItemExpanded(QTreeWidgetItem *)));
    connect(ui->tableTreeWidget, SIGNAL(itemCollapsed(QTreeWidgetItem *)), this, SLOT(tableItemCollapsed(QTreeWidgetItem *)));

    connect(ui->interfaceComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(interfaceCurrentIndexChanged(int)));
    connect(ui->adapterComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(adapterCurrentIndexChanged(int)));

    for (int i = 0; i < ui->tableTreeWidget->columnCount(); i++) {
        ui->tableTreeWidget->resizeColumnToContents(i);
    }

    context_menu_.addActions(QList<QAction *>() << ui->actionCopy_Cell);
    context_menu_.addActions(QList<QAction *>() << ui->actionCopy_Rows);
    context_menu_.addActions(QList<QAction *>() << ui->actionCopy_All);
    context_menu_.addActions(QList<QAction *>() << ui->actionSave_as_image);

    tapinfo_.tap_packet = tapPacket;
    tapinfo_.tap_reset  = tapReset;
    tapinfo_.ui = this;

    item_link_control_            = ui->tableTreeWidget->topLevelItem(0);
    item_link_policy_             = ui->tableTreeWidget->topLevelItem(1);
    item_controller_and_baseband_ = ui->tableTreeWidget->topLevelItem(2);
    item_informational_           = ui->tableTreeWidget->topLevelItem(3);
    item_status_parameters_       = ui->tableTreeWidget->topLevelItem(4);
    item_testing_                 = ui->tableTreeWidget->topLevelItem(5);
    item_low_energy_              = ui->tableTreeWidget->topLevelItem(6);
    item_logo_testing_            = ui->tableTreeWidget->topLevelItem(7);
    item_vendor_                  = ui->tableTreeWidget->topLevelItem(8);
    item_unknown_ogf_             = ui->tableTreeWidget->topLevelItem(9);
    item_events_                  = ui->tableTreeWidget->topLevelItem(10);
    item_status_                  = ui->tableTreeWidget->topLevelItem(11);
    item_reason_                  = ui->tableTreeWidget->topLevelItem(12);
    item_hardware_errors_         = ui->tableTreeWidget->topLevelItem(13);

    bluetooth_devices_tap(&tapinfo_);

    cap_file_.retapPackets();
}


BluetoothHciSummaryDialog::~BluetoothHciSummaryDialog()
{
    delete ui;

    remove_tap_listener(&tapinfo_);
}


void BluetoothHciSummaryDialog::captureFileClosing()
{
    remove_tap_listener(&tapinfo_);

    ui->interfaceComboBox->setEnabled(FALSE);
    ui->adapterComboBox->setEnabled(FALSE);

    WiresharkDialog::captureFileClosing();
}


void BluetoothHciSummaryDialog::changeEvent(QEvent *event)
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


void BluetoothHciSummaryDialog::keyPressEvent(QKeyEvent *)
{
/* NOTE: Do nothing, but in real it "takes focus" from button_box so allow user
 * to use Enter button to jump to frame from tree widget */
}


void BluetoothHciSummaryDialog::tableContextMenu(const QPoint &pos)
{
    context_menu_.exec(ui->tableTreeWidget->viewport()->mapToGlobal(pos));
}

void BluetoothHciSummaryDialog::tableItemExpanded(QTreeWidgetItem *)
{
    for (int i = 0; i < ui->tableTreeWidget->columnCount(); i++) {
        ui->tableTreeWidget->resizeColumnToContents(i);
    }
}

void BluetoothHciSummaryDialog::tableItemCollapsed(QTreeWidgetItem *)
{
    for (int i = 0; i < ui->tableTreeWidget->columnCount(); i++) {
        ui->tableTreeWidget->resizeColumnToContents(i);
    }
}

void BluetoothHciSummaryDialog::on_actionCopy_Cell_triggered()
{
    QClipboard             *clipboard = QApplication::clipboard();
    QString                 copy;

    copy = QString(ui->tableTreeWidget->currentItem()->text(ui->tableTreeWidget->currentColumn()));

    clipboard->setText(copy);
}


void BluetoothHciSummaryDialog::on_actionCopy_Rows_triggered()
{
    QClipboard                         *clipboard = QApplication::clipboard();
    QString                             copy;
    QList<QTreeWidgetItem *>            items;
    QList<QTreeWidgetItem *>::iterator  i_item;

    items =  ui->tableTreeWidget->selectedItems();

    for (i_item = items.begin(); i_item != items.end(); ++i_item) {
        copy += QString("%1  %2  %3  %4  %5  %6  %7  %8  %9\n")
                .arg((*i_item)->text(column_number_name), -60)
                .arg((*i_item)->text(column_number_ogf), -10)
                .arg((*i_item)->text(column_number_ocf), -10)
                .arg((*i_item)->text(column_number_opcode), -10)
                .arg((*i_item)->text(column_number_event), -10)
                .arg((*i_item)->text(column_number_status), -10)
                .arg((*i_item)->text(column_number_reason), -10)
                .arg((*i_item)->text(column_number_hardware_error), -15)
                .arg((*i_item)->text(column_number_occurrence), -10);
    }

    clipboard->setText(copy);
}

void BluetoothHciSummaryDialog::tapReset(void *tapinfo_ptr)
{
    bluetooth_hci_summary_tapinfo_t *tapinfo = (bluetooth_hci_summary_tapinfo_t *) tapinfo_ptr;
    BluetoothHciSummaryDialog  *dialog = static_cast<BluetoothHciSummaryDialog *>(tapinfo->ui);

    dialog->item_link_control_->takeChildren();
    dialog->item_link_control_->setText(column_number_occurrence, "0");

    dialog->item_link_policy_->takeChildren();
    dialog->item_link_policy_->setText(column_number_occurrence, "0");

    dialog->item_controller_and_baseband_->takeChildren();
    dialog->item_controller_and_baseband_->setText(column_number_occurrence, "0");

    dialog->item_informational_->takeChildren();
    dialog->item_informational_->setText(column_number_occurrence, "0");

    dialog->item_status_parameters_->takeChildren();
    dialog->item_status_parameters_->setText(column_number_occurrence, "0");

    dialog->item_testing_->takeChildren();
    dialog->item_testing_->setText(column_number_occurrence, "0");

    dialog->item_low_energy_->takeChildren();
    dialog->item_low_energy_->setText(column_number_occurrence, "0");

    dialog->item_logo_testing_->takeChildren();
    dialog->item_logo_testing_->setText(column_number_occurrence, "0");

    dialog->item_vendor_->takeChildren();
    dialog->item_vendor_->setText(column_number_occurrence, "0");

    dialog->item_unknown_ogf_->takeChildren();
    dialog->item_unknown_ogf_->setText(column_number_occurrence, "0");

    dialog->item_events_->takeChildren();
    dialog->item_events_->setText(column_number_occurrence, "0");

    dialog->item_status_->takeChildren();
    dialog->item_status_->setText(column_number_occurrence, "0");

    dialog->item_reason_->takeChildren();
    dialog->item_reason_->setText(column_number_occurrence, "0");

    dialog->item_hardware_errors_->takeChildren();
    dialog->item_hardware_errors_->setText(column_number_occurrence, "0");
}

gboolean BluetoothHciSummaryDialog::tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *data)
{
    bluetooth_hci_summary_tapinfo_t  *tapinfo    = static_cast<bluetooth_hci_summary_tapinfo_t *>(tapinfo_ptr);
    BluetoothHciSummaryDialog        *dialog     = static_cast<BluetoothHciSummaryDialog *>(tapinfo->ui);
    bluetooth_hci_summary_tap_t      *tap_hci    = static_cast<bluetooth_hci_summary_tap_t *>(const_cast<void *>(data));
    QTreeWidgetItem                  *main_item  = NULL;
    QTreeWidgetItem                  *item       = NULL;
    QTreeWidgetItem                  *frame_item = NULL;
    item_data_t                      *item_data  = NULL;
    QString                           adapter;
    QString  name;

    if (dialog->file_closed_)
        return FALSE;

    name = tr("Unknown");

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

    adapter = QString(tr("Adapter %1")).arg(tap_hci->adapter_id);

    if (dialog->ui->adapterComboBox->findText(adapter) == -1) {
        dialog->ui->adapterComboBox->addItem(adapter);
    }

    if (dialog->ui->adapterComboBox->currentIndex() > 0) {
        if (dialog->ui->adapterComboBox->currentText() != adapter)
        return TRUE;
    }

    switch (tap_hci->type) {
    case BLUETOOTH_HCI_SUMMARY_OPCODE:
    case BLUETOOTH_HCI_SUMMARY_EVENT_OPCODE:
    case BLUETOOTH_HCI_SUMMARY_VENDOR_OPCODE:
    case BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT_OPCODE:
        switch (tap_hci->ogf) {
        case HCI_OGF_LINK_CONTROL:
            main_item = dialog->item_link_control_;
            break;
        case HCI_OGF_LINK_POLICY:
            main_item = dialog->item_link_policy_;
            break;
        case HCI_OGF_HOST_CONTROLLER:
            main_item = dialog->item_controller_and_baseband_;
            break;
        case HCI_OGF_INFORMATIONAL:
            main_item = dialog->item_informational_;
            break;
        case HCI_OGF_STATUS:
            main_item = dialog->item_status_parameters_;
            break;
        case HCI_OGF_TESTING:
            main_item = dialog->item_testing_;
            break;
        case HCI_OGF_LOW_ENERGY:
            main_item = dialog->item_low_energy_;
            break;
        case HCI_OGF_LOGO_TESTING:
            main_item = dialog->item_logo_testing_;
            break;
        case HCI_OGF_VENDOR_SPECIFIC:
            main_item = dialog->item_vendor_;
            break;
        default:
            main_item = dialog->item_unknown_ogf_;
        }

        for (int i_item = 0; i_item < main_item->childCount(); i_item +=1) {
            if (main_item->child(i_item)->text(column_number_opcode) == QString("").sprintf("0x%04X", tap_hci->ogf << 10 | tap_hci->ocf)) {
                item = main_item->child(i_item);
                if (tap_hci->type == BLUETOOTH_HCI_SUMMARY_VENDOR_OPCODE && tap_hci->name) {
                    item->setText(column_number_name, tap_hci->name);
                    item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() - 1));
                }
                break;
            }
        }

        if (!item) {
            item = new QTreeWidgetItem();
            if (tap_hci->name)
                name = tap_hci->name;

            item->setText(column_number_name, name);
            item->setText(column_number_ogf, QString("").sprintf("0x%02X", tap_hci->ogf));
            item->setText(column_number_ocf, QString("").sprintf("0x%04X", tap_hci->ocf));
            item->setText(column_number_opcode, QString("").sprintf("0x%04X", tap_hci->ogf << 10 | tap_hci->ocf));
            if (tap_hci->type == BLUETOOTH_HCI_SUMMARY_OPCODE)
                item->setText(column_number_occurrence, "0");
            else
                item->setText(column_number_occurrence, "1");

            main_item->addChild(item);
            main_item->sortChildren(column_number_opcode, Qt::AscendingOrder);

            main_item->setText(column_number_occurrence, QString::number(main_item->text(column_number_occurrence).toInt() + 1));
        }

        if (tap_hci->type != BLUETOOTH_HCI_SUMMARY_EVENT_OPCODE && tap_hci->type != BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT_OPCODE)
            item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() + 1));

        /* I believe bthci_cmd/bthci_evt already add frame item */
        if (tap_hci->type == BLUETOOTH_HCI_SUMMARY_VENDOR_OPCODE ||
                tap_hci->type == BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT_OPCODE)
            break;

        frame_item = new QTreeWidgetItem();
        frame_item->setText(column_number_name, QString(tr("Frame %1")).arg(pinfo->num));
        frame_item->setText(column_number_ogf, QString("").sprintf("0x%02X", tap_hci->ogf));
        frame_item->setText(column_number_ocf, QString("").sprintf("0x%04X", tap_hci->ocf));
        frame_item->setText(column_number_opcode, QString("").sprintf("0x%04X", tap_hci->ogf << 10 | tap_hci->ocf));
        if (tap_hci->type == BLUETOOTH_HCI_SUMMARY_EVENT_OPCODE)
            frame_item->setText(column_number_event, QString("").sprintf("0x%02X", tap_hci->event));
        item->addChild(frame_item);

        item_data = wmem_new(wmem_file_scope(), item_data_t);
        item_data->interface_id = tap_hci->interface_id;
        item_data->adapter_id   = tap_hci->adapter_id;
        item_data->frame_number = pinfo->num;
        frame_item->setData(0, Qt::UserRole, QVariant::fromValue<item_data_t *>(item_data));

        break;
    case BLUETOOTH_HCI_SUMMARY_EVENT:
    case BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT:
        main_item = dialog->item_events_;

        for (int i_item = 0; i_item < main_item->childCount(); i_item +=1) {
            if (main_item->child(i_item)->text(column_number_event) == QString("").sprintf("0x%02X", tap_hci->event)) {
                item = main_item->child(i_item);
                if (tap_hci->type == BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT && tap_hci->name)
                    item->setText(column_number_name, tap_hci->name);
                break;
            }
        }

        if (!item) {
            QString  name;

            item = new QTreeWidgetItem();
            if (tap_hci->name)
                name = tap_hci->name;

            item->setText(column_number_name, name);
            item->setText(column_number_event, QString("").sprintf("0x%02X", tap_hci->event));

            main_item->addChild(item);
            main_item->sortChildren(column_number_event, Qt::AscendingOrder);
            main_item->setText(column_number_occurrence, QString::number(main_item->text(column_number_occurrence).toInt() + 1));
        }

        item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() + 1));

        /* I believe bthci_cmd/bthci_evt already add frame item */
        if (tap_hci->type == BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT)
            break;

        frame_item = new QTreeWidgetItem();
        frame_item->setText(column_number_name, QString(tr("Frame %1")).arg(pinfo->num));
        frame_item->setText(column_number_event, QString("").sprintf("0x%02X", tap_hci->event));
        item->addChild(frame_item);

        item_data = wmem_new(wmem_file_scope(), item_data_t);
        item_data->interface_id = tap_hci->interface_id;
        item_data->adapter_id   = tap_hci->adapter_id;
        item_data->frame_number = pinfo->num;
        frame_item->setData(0, Qt::UserRole, QVariant::fromValue<item_data_t *>(item_data));

        break;
    case BLUETOOTH_HCI_SUMMARY_STATUS:
        main_item = dialog->item_status_;

        for (int i_item = 0; i_item < main_item->childCount(); i_item +=1) {
            if (main_item->child(i_item)->text(column_number_status) == QString("").sprintf("0x%02X", tap_hci->status)) {
                item = main_item->child(i_item);
                break;
            }
        }

        if (!item) {
            if (tap_hci->name)
                name = tap_hci->name;

            item = new QTreeWidgetItem();
            item->setText(column_number_name, name);
            item->setText(column_number_status, QString("").sprintf("0x%02X", tap_hci->status));

            main_item->addChild(item);
            main_item->sortChildren(column_number_event, Qt::AscendingOrder);
            main_item->setText(column_number_occurrence, QString::number(main_item->text(column_number_occurrence).toInt() + 1));
        }

        item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() + 1));

        frame_item = new QTreeWidgetItem();
        frame_item->setText(column_number_name, QString(tr("Frame %1")).arg(pinfo->num));
        frame_item->setText(column_number_status, QString("").sprintf("0x%02X", tap_hci->status));
        item->addChild(frame_item);

        item_data = wmem_new(wmem_file_scope(), item_data_t);
        item_data->interface_id = tap_hci->interface_id;
        item_data->adapter_id   = tap_hci->adapter_id;
        item_data->frame_number = pinfo->num;
        frame_item->setData(0, Qt::UserRole, QVariant::fromValue<item_data_t *>(item_data));

        break;
    case BLUETOOTH_HCI_SUMMARY_STATUS_PENDING:
        main_item = dialog->item_status_;

        for (int i_item = 0; i_item < main_item->childCount(); i_item +=1) {
            if (main_item->child(i_item)->text(column_number_status) == QString("").sprintf("%u", tap_hci->status)) {
                item = main_item->child(i_item);
                break;
            }
        }

        if (!item) {
            item = new QTreeWidgetItem();
            item->setText(column_number_name, tr("Pending"));
            item->setText(column_number_status, QString("").sprintf("%u", tap_hci->status));

            main_item->addChild(item);
            main_item->sortChildren(column_number_event, Qt::AscendingOrder);
            main_item->setText(column_number_occurrence, QString::number(main_item->text(column_number_occurrence).toInt() + 1));
        }

        item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() + 1));

        frame_item = new QTreeWidgetItem();
        frame_item->setText(column_number_name, QString(tr("Frame %1")).arg(pinfo->num));
        frame_item->setText(column_number_status, QString("").sprintf("%u", tap_hci->status));
        item->addChild(frame_item);

        item_data = wmem_new(wmem_file_scope(), item_data_t);
        item_data->interface_id = tap_hci->interface_id;
        item_data->adapter_id   = tap_hci->adapter_id;
        item_data->frame_number = pinfo->num;
        frame_item->setData(0, Qt::UserRole, QVariant::fromValue<item_data_t *>(item_data));

        break;
    case BLUETOOTH_HCI_SUMMARY_REASON:
        main_item = dialog->item_reason_;

        for (int i_item = 0; i_item < main_item->childCount(); i_item +=1) {
            if (main_item->child(i_item)->text(column_number_reason) == QString("").sprintf("0x%02X", tap_hci->reason)) {
                item = main_item->child(i_item);
                break;
            }
        }

        if (!item) {
            if (tap_hci->name)
                name = tap_hci->name;

            item = new QTreeWidgetItem();
            item->setText(column_number_name, name);
            item->setText(column_number_reason, QString("").sprintf("0x%02X", tap_hci->reason));

            main_item->addChild(item);
            main_item->sortChildren(column_number_event, Qt::AscendingOrder);
            main_item->setText(column_number_occurrence, QString::number(main_item->text(column_number_occurrence).toInt() + 1));
        }

        item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() + 1));

        frame_item = new QTreeWidgetItem();
        frame_item->setText(column_number_name, QString(tr("Frame %1")).arg(pinfo->num));
        frame_item->setText(column_number_reason, QString("").sprintf("0x%02X", tap_hci->reason));
        item->addChild(frame_item);

        item_data = wmem_new(wmem_file_scope(), item_data_t);
        item_data->interface_id = tap_hci->interface_id;
        item_data->adapter_id   = tap_hci->adapter_id;
        item_data->frame_number = pinfo->num;
        frame_item->setData(0, Qt::UserRole, QVariant::fromValue<item_data_t *>(item_data));

        break;
    case BLUETOOTH_HCI_SUMMARY_HARDWARE_ERROR:
        main_item = dialog->item_hardware_errors_;

        for (int i_item = 0; i_item < main_item->childCount(); i_item +=1) {
            if (main_item->child(i_item)->text(column_number_hardware_error) == QString("").sprintf("0x%02X", tap_hci->hardware_error)) {
                item = main_item->child(i_item);
                break;
            }
        }

        if (!item) {
            item = new QTreeWidgetItem();
            item->setText(column_number_name, QString("").sprintf("Hardware error 0x%02X", tap_hci->hardware_error));
            item->setText(column_number_hardware_error, QString("").sprintf("0x%02X", tap_hci->hardware_error));

            main_item->addChild(item);
            main_item->sortChildren(column_number_event, Qt::AscendingOrder);
            main_item->setText(column_number_occurrence, QString::number(main_item->text(column_number_occurrence).toInt() + 1));
        }

        item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() + 1));

        frame_item = new QTreeWidgetItem();
        frame_item->setText(column_number_name, QString(tr("Frame %1")).arg(pinfo->num));
        frame_item->setText(column_number_hardware_error, QString("").sprintf("0x%02X", tap_hci->hardware_error));
        item->addChild(frame_item);

        item_data = wmem_new(wmem_file_scope(), item_data_t);
        item_data->interface_id = tap_hci->interface_id;
        item_data->adapter_id   = tap_hci->adapter_id;
        item_data->frame_number = pinfo->num;
        frame_item->setData(0, Qt::UserRole, QVariant::fromValue<item_data_t *>(item_data));

        break;
    }

    for (int i = 0; i < dialog->ui->tableTreeWidget->columnCount(); i++) {
        dialog->ui->tableTreeWidget->resizeColumnToContents(i);
    }

    return TRUE;
}

void BluetoothHciSummaryDialog::interfaceCurrentIndexChanged(int)
{
    cap_file_.retapPackets();
}

void BluetoothHciSummaryDialog::adapterCurrentIndexChanged(int)
{
    cap_file_.retapPackets();
}

void BluetoothHciSummaryDialog::on_tableTreeWidget_itemActivated(QTreeWidgetItem *item, int)
{
    if (file_closed_)
        return;

    item_data_t *item_data = item->data(0, Qt::UserRole).value<item_data_t *>();

    if (item_data)
        emit goToPacket(item_data->frame_number);
}


void BluetoothHciSummaryDialog::recursiveCopyTreeItems(QTreeWidgetItem *item, QString &copy, int ident_level)
{
    QTreeWidgetItem *child_item;

    if (!item->isExpanded()) return;

    for (int i_item = 0; i_item < item->childCount(); i_item += 1) {
        child_item = item->child(i_item);

        copy.append(QString("    ").repeated(ident_level));
        copy += QString("%1  %2  %3  %4  %5  %6  %7  %8  %9\n")
                .arg(child_item->text(column_number_name), -60 + 4 * ident_level)
                .arg(child_item->text(column_number_ogf), -10)
                .arg(child_item->text(column_number_ocf), -10)
                .arg(child_item->text(column_number_opcode), -10)
                .arg(child_item->text(column_number_event), -10)
                .arg(child_item->text(column_number_status), -10)
                .arg(child_item->text(column_number_reason), -10)
                .arg(child_item->text(column_number_hardware_error), -15)
                .arg(child_item->text(column_number_occurrence), -10);

        recursiveCopyTreeItems(child_item, copy, ident_level + 1);
    }
}

void BluetoothHciSummaryDialog::on_actionCopy_All_triggered()
{
    QClipboard             *clipboard = QApplication::clipboard();
    QString                 copy;
    QTreeWidgetItem        *item;

    item = ui->tableTreeWidget->headerItem();

    copy += QString("%1  %2  %3  %4  %5  %6  %7  %8  %9\n")
            .arg(item->text(column_number_name), -60)
            .arg(item->text(column_number_ogf), -10)
            .arg(item->text(column_number_ocf), -10)
            .arg(item->text(column_number_opcode), -10)
            .arg(item->text(column_number_event), -10)
            .arg(item->text(column_number_status), -10)
            .arg(item->text(column_number_reason), -10)
            .arg(item->text(column_number_hardware_error), -15)
            .arg(item->text(column_number_occurrence), -10);

    for (int i_item = 0; i_item < ui->tableTreeWidget->topLevelItemCount(); ++i_item) {
        item = ui->tableTreeWidget->topLevelItem(i_item);

        copy += QString("%1  %2  %3  %4  %5  %6  %7  %8  %9\n")
                .arg(item->text(column_number_name), -60)
                .arg(item->text(column_number_ogf), -10)
                .arg(item->text(column_number_ocf), -10)
                .arg(item->text(column_number_opcode), -10)
                .arg(item->text(column_number_event), -10)
                .arg(item->text(column_number_status), -10)
                .arg(item->text(column_number_reason), -10)
                .arg(item->text(column_number_hardware_error), -15)
                .arg(item->text(column_number_occurrence), -10);

        recursiveCopyTreeItems(ui->tableTreeWidget->topLevelItem(i_item), copy, 1);
    }

    clipboard->setText(copy);
}

void BluetoothHciSummaryDialog::on_actionSave_as_image_triggered()
{
    QPixmap image;

    QString fileName = QFileDialog::getSaveFileName(this,
            tr("Save Table Image"),
            "bluetooth_hci_summary.png",
            tr("PNG Image (*.png)"));

    if (fileName.isEmpty()) return;

    image = QPixmap::grabWidget(ui->tableTreeWidget);
    image.save(fileName, "PNG");
}

void BluetoothHciSummaryDialog::on_buttonBox_clicked(QAbstractButton *)
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
