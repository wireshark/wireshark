/* bluetooth_hci_summary_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "bluetooth_hci_summary_dialog.h"
#include <ui_bluetooth_hci_summary_dialog.h>

#include "bluetooth_device_dialog.h"

#include <ui/qt/utils/color_utils.h>

#include "epan/epan.h"
#include "epan/addr_resolv.h"
#include "epan/to_str.h"
#include "epan/epan_dissect.h"
#include "epan/prefs.h"
#include "epan/dissectors/packet-bluetooth.h"
#include "epan/dissectors/packet-bthci_cmd.h"
#include "epan/dissectors/packet-bthci_evt.h"

#include <ui/qt/utils/variant_pointer.h>

#include "ui/simple_dialog.h"
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QClipboard>
#include <QContextMenuEvent>
#include <QPushButton>
#include <QTreeWidget>

static const int column_number_name = 0;
static const int column_number_ogf = 1;
static const int column_number_ocf = 2;
static const int column_number_opcode = 3;
static const int column_number_event = 4;
static const int column_number_subevent = 5;
static const int column_number_status = 6;
static const int column_number_reason = 7;
static const int column_number_hardware_error = 8;
static const int column_number_occurrence = 9;

static tap_packet_status
bluetooth_hci_summary_tap_packet(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *edt, const void* data, tap_flags_t flags)
{
    bluetooth_hci_summary_tapinfo_t *tapinfo = (bluetooth_hci_summary_tapinfo_t *) tapinfo_ptr;

    if (tapinfo->tap_packet)
        tapinfo->tap_packet(tapinfo, pinfo, edt, data, flags);

    return TAP_PACKET_REDRAW;
}

static void
bluetooth_hci_summary_tap_reset(void *tapinfo_ptr)
{
    bluetooth_hci_summary_tapinfo_t *tapinfo = (bluetooth_hci_summary_tapinfo_t *) tapinfo_ptr;

    if (tapinfo->tap_reset)
        tapinfo->tap_reset(tapinfo);
}

static void
bluetooth_hci_summary_tap_init(void *data)
{
    GString *error_string;

    error_string = register_tap_listener("bluetooth.hci_summary", data, NULL,
            0,
            bluetooth_hci_summary_tap_reset,
            bluetooth_hci_summary_tap_packet,
            NULL,
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
    connect(ui->displayFilterLineEdit, SIGNAL(returnPressed()), this, SLOT(displayFilterLineEditAccepted()));
    connect(ui->resultsFilterLineEdit, SIGNAL(textChanged(const QString &)), this, SLOT(resultsFilterLineEditChanged(const QString &)));

    for (int i = 0; i < ui->tableTreeWidget->columnCount(); i++) {
        ui->tableTreeWidget->resizeColumnToContents(i);
    }

    ui->tableTreeWidget->setStyleSheet("QTreeView::item:hover{background-color:lightyellow; color:black;}");

    context_menu_.addActions(QList<QAction *>() << ui->actionMark_Unmark_Cell);
    context_menu_.addActions(QList<QAction *>() << ui->actionMark_Unmark_Row);
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

    bluetooth_hci_summary_tap_init(&tapinfo_);

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

    WiresharkDialog::captureFileClosing();
}


void BluetoothHciSummaryDialog::captureFileClosed()
{
    ui->interfaceComboBox->setEnabled(FALSE);
    ui->adapterComboBox->setEnabled(FALSE);

    WiresharkDialog::captureFileClosed();
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


void BluetoothHciSummaryDialog::keyPressEvent(QKeyEvent *event)
{
/* NOTE: Do nothing*, but in real it "takes focus" from button_box so allow user
 * to use Enter button to jump to frame from tree widget */
/* * - reimplement shortcuts from contex menu */

   if (event->modifiers() & Qt::ControlModifier && event->key()== Qt::Key_M)
        on_actionMark_Unmark_Row_triggered();
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

void BluetoothHciSummaryDialog::on_actionMark_Unmark_Cell_triggered()
{
    QBrush fg;
    QBrush bg;

    if (ui->tableTreeWidget->currentItem()->background(ui->tableTreeWidget->currentColumn()) == QBrush(ColorUtils::fromColorT(&prefs.gui_marked_bg))) {
        fg = QBrush();
        bg = QBrush();
    } else {
        fg = QBrush(ColorUtils::fromColorT(&prefs.gui_marked_fg));
        bg = QBrush(ColorUtils::fromColorT(&prefs.gui_marked_bg));
    }

    ui->tableTreeWidget->currentItem()->setForeground(ui->tableTreeWidget->currentColumn(), fg);
    ui->tableTreeWidget->currentItem()->setBackground(ui->tableTreeWidget->currentColumn(), bg);
}

void BluetoothHciSummaryDialog::on_actionMark_Unmark_Row_triggered()
{
    QBrush fg;
    QBrush bg;
    bool   is_marked = TRUE;

    for (int i = 0; i < ui->tableTreeWidget->columnCount(); i += 1) {
        if (ui->tableTreeWidget->currentItem()->background(i) != QBrush(ColorUtils::fromColorT(&prefs.gui_marked_bg)))
            is_marked = FALSE;
    }

    if (is_marked) {
        fg = QBrush();
        bg = QBrush();
    } else {
        fg = QBrush(ColorUtils::fromColorT(&prefs.gui_marked_fg));
        bg = QBrush(ColorUtils::fromColorT(&prefs.gui_marked_bg));
    }

    for (int i = 0; i < ui->tableTreeWidget->columnCount(); i += 1) {
        ui->tableTreeWidget->currentItem()->setForeground(i, fg);
        ui->tableTreeWidget->currentItem()->setBackground(i, bg);
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
                .arg((*i_item)->text(column_number_subevent), -10)
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

tap_packet_status BluetoothHciSummaryDialog::tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *data, tap_flags_t)
{
    bluetooth_hci_summary_tapinfo_t  *tapinfo    = static_cast<bluetooth_hci_summary_tapinfo_t *>(tapinfo_ptr);
    BluetoothHciSummaryDialog        *dialog     = static_cast<BluetoothHciSummaryDialog *>(tapinfo->ui);
    bluetooth_hci_summary_tap_t      *tap_hci    = static_cast<bluetooth_hci_summary_tap_t *>(const_cast<void *>(data));
    QTreeWidgetItem                  *main_item  = NULL;
    QTreeWidgetItem                  *item       = NULL;
    QTreeWidgetItem                  *frame_item = NULL;
    QTreeWidgetItem                  *meta_item  = NULL;
    bluetooth_item_data_t            *item_data  = NULL;
    QString                           adapter;
    QString  name;

    if (dialog->file_closed_)
        return TAP_PACKET_DONT_REDRAW;

    if (pinfo->rec->rec_type != REC_TYPE_PACKET)
        return TAP_PACKET_DONT_REDRAW;

    name = tr("Unknown");

    if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID) {
        gchar       *interface;
        const char  *interface_name;

        interface_name = epan_get_interface_name(pinfo->epan, pinfo->rec->rec_header.packet_header.interface_id);
        interface = wmem_strdup_printf(pinfo->pool, "%u: %s", pinfo->rec->rec_header.packet_header.interface_id, interface_name);

        if (dialog->ui->interfaceComboBox->findText(interface) == -1)
            dialog->ui->interfaceComboBox->addItem(interface);

        if (interface && dialog->ui->interfaceComboBox->currentIndex() > 0) {
            if (dialog->ui->interfaceComboBox->currentText() != interface)
                return TAP_PACKET_REDRAW;
        }
    }

    adapter = QString(tr("Adapter %1")).arg(tap_hci->adapter_id);

    if (dialog->ui->adapterComboBox->findText(adapter) == -1) {
        dialog->ui->adapterComboBox->addItem(adapter);
    }

    if (dialog->ui->adapterComboBox->currentIndex() > 0) {
        if (dialog->ui->adapterComboBox->currentText() != adapter)
            return TAP_PACKET_REDRAW;
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
            if (main_item->child(i_item)->text(column_number_opcode) ==
                    QString("0x%1").arg(tap_hci->ogf << 10 | tap_hci->ocf, 4, 16, QChar('0'))) {
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
            item->setText(column_number_ogf, QString("0x%1").arg(tap_hci->ogf, 2, 16, QChar('0')));
            item->setText(column_number_ocf, QString("0x%1").arg(tap_hci->ocf, 4, 16, QChar('0')));
            item->setText(column_number_opcode,
                          QString("0x%1").arg(tap_hci->ogf << 10 | tap_hci->ocf, 4, 16, QChar('0')));
            if (tap_hci->type == BLUETOOTH_HCI_SUMMARY_OPCODE)
                item->setText(column_number_occurrence, "0");
            else
                item->setText(column_number_occurrence, "1");

            main_item->addChild(item);
            item->setHidden(!name.contains(dialog->ui->resultsFilterLineEdit->text(), Qt::CaseInsensitive));
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
        frame_item->setText(column_number_ogf, QString("0x%1").arg(tap_hci->ogf, 2, 16, QChar('0')));
        frame_item->setText(column_number_ocf, QString("0x%1").arg(tap_hci->ocf, 4, 16, QChar('0')));
        frame_item->setText(column_number_opcode, QString("0x%1")
                            .arg(tap_hci->ogf << 10 | tap_hci->ocf, 4, 16, QChar('0')));
        if (tap_hci->type == BLUETOOTH_HCI_SUMMARY_EVENT_OPCODE)
            frame_item->setText(column_number_event, QString("0x%1").arg(tap_hci->event, 2, 16, QChar('0')));
        item->addChild(frame_item);

        item_data = wmem_new(wmem_file_scope(), bluetooth_item_data_t);
        item_data->interface_id = tap_hci->interface_id;
        item_data->adapter_id   = tap_hci->adapter_id;
        item_data->frame_number = pinfo->num;
        frame_item->setData(0, Qt::UserRole, VariantPointer<bluetooth_item_data_t>::asQVariant(item_data));

        break;
    case BLUETOOTH_HCI_SUMMARY_EVENT:
    case BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT:
        main_item = dialog->item_events_;

        for (int i_item = 0; i_item < main_item->childCount(); i_item +=1) {
            if (main_item->child(i_item)->text(column_number_event) ==
                    QString("0x%1").arg(tap_hci->event, 2, 16, QChar('0'))) {
                item = main_item->child(i_item);
                if (tap_hci->type == BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT && tap_hci->name)
                    item->setText(column_number_name, tap_hci->name);
                break;
            }
        }

        if (!item) {
            item = new QTreeWidgetItem();
            if (tap_hci->name)
                name = tap_hci->name;

            item->setText(column_number_name, name);
            item->setText(column_number_event, QString("0x%1").arg(tap_hci->event, 2, 16, QChar('0')));
            item->setText(column_number_occurrence, QString::number(0));

            main_item->addChild(item);
            item->setHidden(!name.contains(dialog->ui->resultsFilterLineEdit->text(), Qt::CaseInsensitive));
            main_item->sortChildren(column_number_event, Qt::AscendingOrder);
            main_item->setText(column_number_occurrence, QString::number(main_item->text(column_number_occurrence).toInt() + 1));
        }

        /* I believe bthci_cmd/bthci_evt already add frame item */
        if (tap_hci->type == BLUETOOTH_HCI_SUMMARY_VENDOR_EVENT)
            break;

        if (tap_hci->event == 0x3E) { /* LE Meta */
            int i_item;
            for (i_item = 0; i_item < item->childCount(); i_item +=1) {
                if (item->child(i_item)->text(column_number_name) != QString(tr("Unknown")))
                    continue;
            }

            if (i_item >= item->childCount()) {
                frame_item = new QTreeWidgetItem();
                frame_item->setText(column_number_name, QString(tr("Unknown")));
                frame_item->setText(column_number_occurrence, QString::number(1));
                item->addChild(frame_item);
                item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() + 1));

                item = frame_item;
            } else {
                item = item->child(i_item);
                item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() + 1));
            }
        } else {
            item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() + 1));
        }

        frame_item = new QTreeWidgetItem();
        frame_item->setText(column_number_name, QString(tr("Frame %1")).arg(pinfo->num));
        frame_item->setText(column_number_event, QString("0x%1").arg(tap_hci->event, 2, 16, QChar('0')));
        item->addChild(frame_item);

        item_data = wmem_new(wmem_file_scope(), bluetooth_item_data_t);
        item_data->interface_id = tap_hci->interface_id;
        item_data->adapter_id   = tap_hci->adapter_id;
        item_data->frame_number = pinfo->num;
        frame_item->setData(0, Qt::UserRole, VariantPointer<bluetooth_item_data_t>::asQVariant(item_data));

        break;
    case BLUETOOTH_HCI_SUMMARY_SUBEVENT:
        main_item = dialog->item_events_;

        meta_item = NULL;

        for (int i_item = 0; i_item < main_item->childCount(); i_item +=1) {
            if (main_item->child(i_item)->text(column_number_event) !=
                    QString("0x%1").arg(tap_hci->event, 2, 16, QChar('0'))) {
                continue;
            }

            meta_item = main_item->child(i_item);
            break;
        }

        if (meta_item == NULL)
            break;

        item = NULL;

        for (int i_item = 0; i_item < meta_item->childCount(); i_item +=1) {
            if (meta_item->child(i_item)->text(column_number_subevent) !=
                    QString("0x%1").arg(tap_hci->subevent, 2, 16, QChar('0'))) {
                continue;
            }

            item = meta_item->child(i_item);
            item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() + 1));

            break;
        }

        if (item == NULL) {
            item = new QTreeWidgetItem();
            item->setText(column_number_name, tap_hci->name);
            item->setText(column_number_subevent, QString("0x%1").arg(tap_hci->subevent, 2, 16, QChar('0')));
            item->setText(column_number_occurrence, QString::number(1));

            meta_item->addChild(item);
            meta_item->setText(column_number_occurrence, QString::number(meta_item->text(column_number_occurrence).toInt() + 1));
            meta_item->sortChildren(column_number_subevent, Qt::AscendingOrder);
        }

        frame_item = new QTreeWidgetItem();
        frame_item->setText(column_number_name, QString(tr("Frame %1")).arg(pinfo->num));
        frame_item->setText(column_number_event, QString("0x%1").arg(tap_hci->event, 2, 16, QChar('0')));
        frame_item->setText(column_number_subevent, QString("0x%1").arg(tap_hci->subevent, 2, 16, QChar('0')));

        item_data = wmem_new(wmem_file_scope(), bluetooth_item_data_t);
        item_data->interface_id = tap_hci->interface_id;
        item_data->adapter_id   = tap_hci->adapter_id;
        item_data->frame_number = pinfo->num;

        frame_item->setData(0, Qt::UserRole, VariantPointer<bluetooth_item_data_t>::asQVariant(item_data));

        item->addChild(frame_item);

        /* Remove item that is known now */
        for (int i_item = 0; i_item < meta_item->childCount(); i_item +=1) {
            if (meta_item->child(i_item)->text(column_number_name) != QString(tr("Unknown")))
                continue;

            item = meta_item->child(i_item);
            for (int ii_item = 0; ii_item < item->childCount(); ii_item +=1) {
                if (item->child(ii_item)->text(column_number_name) != QString(tr("Frame %1")).arg(pinfo->num))
                    continue;

                delete item->child(ii_item);
                item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() - 1));
                if (item->childCount() == 0) {
                    delete item;
                    meta_item->setText(column_number_occurrence, QString::number(meta_item->text(column_number_occurrence).toInt() - 1));
                }

                break;
            }
            break;
        }

        break;
    case BLUETOOTH_HCI_SUMMARY_STATUS:
        main_item = dialog->item_status_;

        for (int i_item = 0; i_item < main_item->childCount(); i_item +=1) {
            if (main_item->child(i_item)->text(column_number_status) ==
                    QString("0x%1").arg(tap_hci->status, 2, 16, QChar('0'))) {
                item = main_item->child(i_item);
                break;
            }
        }

        if (!item) {
            if (tap_hci->name)
                name = tap_hci->name;

            item = new QTreeWidgetItem();
            item->setText(column_number_name, name);
            item->setText(column_number_status, QString("0x%1").arg(tap_hci->status, 2, 16, QChar('0')));

            main_item->addChild(item);
            item->setHidden(!name.contains(dialog->ui->resultsFilterLineEdit->text(), Qt::CaseInsensitive));
            main_item->sortChildren(column_number_event, Qt::AscendingOrder);
            main_item->setText(column_number_occurrence, QString::number(main_item->text(column_number_occurrence).toInt() + 1));
        }

        item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() + 1));

        frame_item = new QTreeWidgetItem();
        frame_item->setText(column_number_name, QString(tr("Frame %1")).arg(pinfo->num));
        frame_item->setText(column_number_status, QString("0x%1").arg(tap_hci->status, 2, 16, QChar('0')));
        item->addChild(frame_item);

        item_data = wmem_new(wmem_file_scope(), bluetooth_item_data_t);
        item_data->interface_id = tap_hci->interface_id;
        item_data->adapter_id   = tap_hci->adapter_id;
        item_data->frame_number = pinfo->num;
        frame_item->setData(0, Qt::UserRole, VariantPointer<bluetooth_item_data_t>::asQVariant(item_data));

        break;
    case BLUETOOTH_HCI_SUMMARY_STATUS_PENDING:
        main_item = dialog->item_status_;

        for (int i_item = 0; i_item < main_item->childCount(); i_item +=1) {
            if (main_item->child(i_item)->text(column_number_status) == QString::number(tap_hci->status)) {
                item = main_item->child(i_item);
                break;
            }
        }

        if (!item) {
            item = new QTreeWidgetItem();
            item->setText(column_number_name, tr("Pending"));
            item->setText(column_number_status, QString::number(tap_hci->status));

            main_item->addChild(item);
            item->setHidden(!name.contains(dialog->ui->resultsFilterLineEdit->text(), Qt::CaseInsensitive));
            main_item->sortChildren(column_number_event, Qt::AscendingOrder);
            main_item->setText(column_number_occurrence, QString::number(main_item->text(column_number_occurrence).toInt() + 1));
        }

        item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() + 1));

        frame_item = new QTreeWidgetItem();
        frame_item->setText(column_number_name, QString(tr("Frame %1")).arg(pinfo->num));
        frame_item->setText(column_number_status, QString::number(tap_hci->status));
        item->addChild(frame_item);

        item_data = wmem_new(wmem_file_scope(), bluetooth_item_data_t);
        item_data->interface_id = tap_hci->interface_id;
        item_data->adapter_id   = tap_hci->adapter_id;
        item_data->frame_number = pinfo->num;
        frame_item->setData(0, Qt::UserRole, VariantPointer<bluetooth_item_data_t>::asQVariant(item_data));

        break;
    case BLUETOOTH_HCI_SUMMARY_REASON:
        main_item = dialog->item_reason_;

        for (int i_item = 0; i_item < main_item->childCount(); i_item +=1) {
            if (main_item->child(i_item)->text(column_number_reason) ==
                    QString("0x%1").arg(tap_hci->reason, 2, 16, QChar('0'))) {
                item = main_item->child(i_item);
                break;
            }
        }

        if (!item) {
            if (tap_hci->name)
                name = tap_hci->name;

            item = new QTreeWidgetItem();
            item->setText(column_number_name, name);
            item->setText(column_number_reason, QString("0x%1").arg(tap_hci->reason, 2, 16, QChar('0')));

            main_item->addChild(item);
            item->setHidden(!name.contains(dialog->ui->resultsFilterLineEdit->text(), Qt::CaseInsensitive));
            main_item->sortChildren(column_number_event, Qt::AscendingOrder);
            main_item->setText(column_number_occurrence, QString::number(main_item->text(column_number_occurrence).toInt() + 1));
        }

        item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() + 1));

        frame_item = new QTreeWidgetItem();
        frame_item->setText(column_number_name, QString(tr("Frame %1")).arg(pinfo->num));
        frame_item->setText(column_number_reason, QString("0x%1").arg(tap_hci->reason, 2, 16, QChar('0')));
        item->addChild(frame_item);

        item_data = wmem_new(wmem_file_scope(), bluetooth_item_data_t);
        item_data->interface_id = tap_hci->interface_id;
        item_data->adapter_id   = tap_hci->adapter_id;
        item_data->frame_number = pinfo->num;
        frame_item->setData(0, Qt::UserRole, VariantPointer<bluetooth_item_data_t>::asQVariant(item_data));

        break;
    case BLUETOOTH_HCI_SUMMARY_HARDWARE_ERROR:
        main_item = dialog->item_hardware_errors_;

        for (int i_item = 0; i_item < main_item->childCount(); i_item +=1) {
            if (main_item->child(i_item)->text(column_number_hardware_error) ==
                    QString("0x%1").arg(tap_hci->hardware_error, 2, 16, QChar('0'))) {
                item = main_item->child(i_item);
                break;
            }
        }

        if (!item) {
            item = new QTreeWidgetItem();
            const QString error = QString("0x%1").arg(tap_hci->hardware_error, 2, 16, QChar('0'));
            item->setText(column_number_name, QString("Hardware error %1").arg(error));
            item->setText(column_number_hardware_error, error);

            main_item->addChild(item);
            item->setHidden(!name.contains(dialog->ui->resultsFilterLineEdit->text(), Qt::CaseInsensitive));
            main_item->sortChildren(column_number_event, Qt::AscendingOrder);
            main_item->setText(column_number_occurrence, QString::number(main_item->text(column_number_occurrence).toInt() + 1));
        }

        item->setText(column_number_occurrence, QString::number(item->text(column_number_occurrence).toInt() + 1));

        frame_item = new QTreeWidgetItem();
        frame_item->setText(column_number_name, QString(tr("Frame %1")).arg(pinfo->num));
        frame_item->setText(column_number_hardware_error, QString("0x%1").arg(tap_hci->hardware_error, 2, 16, QChar('0')));
        item->addChild(frame_item);

        item_data = wmem_new(wmem_file_scope(), bluetooth_item_data_t);
        item_data->interface_id = tap_hci->interface_id;
        item_data->adapter_id   = tap_hci->adapter_id;
        item_data->frame_number = pinfo->num;
        frame_item->setData(0, Qt::UserRole, VariantPointer<bluetooth_item_data_t>::asQVariant(item_data));

        break;
    }

    for (int i = 0; i < dialog->ui->tableTreeWidget->columnCount(); i++) {
        dialog->ui->tableTreeWidget->resizeColumnToContents(i);
    }

    return TAP_PACKET_REDRAW;
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

    bluetooth_item_data_t *item_data = VariantPointer<bluetooth_item_data_t>::asPtr(item->data(0, Qt::UserRole));

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
                .arg(child_item->text(column_number_subevent), -10)
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

    copy += QString("%1  %2  %3  %4  %5  %6  %7  %8  %9  %10\n")
            .arg(item->text(column_number_name), -60)
            .arg(item->text(column_number_ogf), -10)
            .arg(item->text(column_number_ocf), -10)
            .arg(item->text(column_number_opcode), -10)
            .arg(item->text(column_number_event), -10)
            .arg(item->text(column_number_subevent), -10)
            .arg(item->text(column_number_status), -10)
            .arg(item->text(column_number_reason), -10)
            .arg(item->text(column_number_hardware_error), -15)
            .arg(item->text(column_number_occurrence), -10);

    for (int i_item = 0; i_item < ui->tableTreeWidget->topLevelItemCount(); ++i_item) {
        item = ui->tableTreeWidget->topLevelItem(i_item);

        copy += QString("%1  %2  %3  %4  %5  %6  %7  %8  %9  %10\n")
                .arg(item->text(column_number_name), -60)
                .arg(item->text(column_number_ogf), -10)
                .arg(item->text(column_number_ocf), -10)
                .arg(item->text(column_number_opcode), -10)
                .arg(item->text(column_number_event), -10)
                .arg(item->text(column_number_subevent), -10)
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

    QString fileName = WiresharkFileDialog::getSaveFileName(this,
            tr("Save Table Image"),
            "bluetooth_hci_summary.png",
            tr("PNG Image (*.png)"));

    if (fileName.isEmpty()) return;

    image = ui->tableTreeWidget->grab();
    image.save(fileName, "PNG");
}

void BluetoothHciSummaryDialog::on_buttonBox_clicked(QAbstractButton *)
{
/*    if (button == foo_button_) */
}

void BluetoothHciSummaryDialog::displayFilterLineEditAccepted()
{
    GString *error_string;

    remove_tap_listener(&tapinfo_);
    error_string = register_tap_listener("bluetooth.hci_summary", &tapinfo_,
            ui->displayFilterLineEdit->text().toUtf8().constData(),
            0,
            bluetooth_hci_summary_tap_reset,
            bluetooth_hci_summary_tap_packet,
            NULL,
            NULL
            );

    if (error_string != NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "%s", error_string->str);
        g_string_free(error_string, TRUE);
    }

    cap_file_.retapPackets();
}

void BluetoothHciSummaryDialog::resultsFilterLineEditChanged(const QString &text)
{
    for (int i_item = 0; i_item < ui->tableTreeWidget->topLevelItemCount(); ++i_item) {
        QTreeWidgetItem *item = ui->tableTreeWidget->topLevelItem(i_item);

        for (int i_child = 0; i_child < item->childCount(); i_child += 1) {
            QTreeWidgetItem *child_item = item->child(i_child);
            QString name = child_item->text(column_number_name);
            child_item->setHidden(!name.contains(text, Qt::CaseInsensitive));
        }
    }
}
