/* bluetooth_att_server_attributes_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "bluetooth_att_server_attributes_dialog.h"
#include <ui_bluetooth_att_server_attributes_dialog.h>

#include <ui/qt/utils/color_utils.h>

#include "epan/epan.h"
#include "epan/to_str.h"
#include "epan/epan_dissect.h"
#include "epan/prefs.h"
#include "epan/dissectors/packet-bluetooth.h"
#include "epan/dissectors/packet-btatt.h"

#include "ui/simple_dialog.h"

#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QClipboard>
#include <QContextMenuEvent>
#include <QPushButton>
#include <QTreeWidget>

static const int column_number_handle = 0;
static const int column_number_uuid = 1;
static const int column_number_uuid_name = 2;

static tap_packet_status
btatt_handle_tap_packet(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *edt, const void* data, tap_flags_t flags)
{
    tapinfo_t *tapinfo = (tapinfo_t *) tapinfo_ptr;

    if (tapinfo->tap_packet)
        tapinfo->tap_packet(tapinfo, pinfo, edt, data, flags);

    return TAP_PACKET_REDRAW;
}

static void
btatt_handle_tap_reset(void *tapinfo_ptr)
{
    tapinfo_t *tapinfo = (tapinfo_t *) tapinfo_ptr;

    if (tapinfo->tap_reset)
        tapinfo->tap_reset(tapinfo);
}

BluetoothAttServerAttributesDialog::BluetoothAttServerAttributesDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::BluetoothAttServerAttributesDialog)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 2 / 3);

    connect(ui->tableTreeWidget, &QTreeWidget::customContextMenuRequested, this, &BluetoothAttServerAttributesDialog::tableContextMenu);
    connect(ui->interfaceComboBox, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &BluetoothAttServerAttributesDialog::interfaceCurrentIndexChanged);
    connect(ui->deviceComboBox, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &BluetoothAttServerAttributesDialog::deviceCurrentIndexChanged);
    connect(ui->removeDuplicatesCheckBox, &QCheckBox::stateChanged, this, &BluetoothAttServerAttributesDialog::removeDuplicatesStateChanged);

    ui->tableTreeWidget->sortByColumn(column_number_handle, Qt::AscendingOrder);

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

    registerTapListener("btatt.handles", &tapinfo_, NULL,
                        0,
                        btatt_handle_tap_reset,
                        btatt_handle_tap_packet,
                        NULL
                        );

    cap_file_.retapPackets();
}


BluetoothAttServerAttributesDialog::~BluetoothAttServerAttributesDialog()
{
    delete ui;
}


void BluetoothAttServerAttributesDialog::captureFileClosed()
{
    ui->interfaceComboBox->setEnabled(FALSE);
    ui->deviceComboBox->setEnabled(FALSE);
    ui->removeDuplicatesCheckBox->setEnabled(FALSE);

    WiresharkDialog::captureFileClosed();
}


void BluetoothAttServerAttributesDialog::changeEvent(QEvent *event)
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


void BluetoothAttServerAttributesDialog::keyPressEvent(QKeyEvent *event)
{
/* NOTE: Do nothing*, but in real it "takes focus" from button_box so allow user
 * to use Enter button to jump to frame from tree widget */
/* * - reimplement shortcuts from contex menu */

   if (event->modifiers() & Qt::ControlModifier && event->key()== Qt::Key_M)
        on_actionMark_Unmark_Row_triggered();
}


void BluetoothAttServerAttributesDialog::tableContextMenu(const QPoint &pos)
{
    context_menu_.popup(ui->tableTreeWidget->viewport()->mapToGlobal(pos));
}


void BluetoothAttServerAttributesDialog::on_actionMark_Unmark_Cell_triggered()
{
    QTreeWidgetItem *current_item = ui->tableTreeWidget->currentItem();
    if (!current_item)
        return;

    QBrush fg;
    QBrush bg;

    if (current_item->background(ui->tableTreeWidget->currentColumn()) == QBrush(ColorUtils::fromColorT(&prefs.gui_marked_bg))) {
        fg = QBrush();
        bg = QBrush();
    } else {
        fg = QBrush(ColorUtils::fromColorT(&prefs.gui_marked_fg));
        bg = QBrush(ColorUtils::fromColorT(&prefs.gui_marked_bg));
    }

    current_item->setForeground(ui->tableTreeWidget->currentColumn(), fg);
    current_item->setBackground(ui->tableTreeWidget->currentColumn(), bg);
}


void BluetoothAttServerAttributesDialog::on_actionMark_Unmark_Row_triggered()
{
    QTreeWidgetItem *current_item = ui->tableTreeWidget->currentItem();
    if (!current_item)
        return;

    QBrush fg;
    QBrush bg;
    bool   is_marked = TRUE;

    for (int i = 0; i < ui->tableTreeWidget->columnCount(); i += 1) {
        if (current_item->background(i) != QBrush(ColorUtils::fromColorT(&prefs.gui_marked_bg)))
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
        current_item->setForeground(i, fg);
        current_item->setBackground(i, bg);
    }
}


void BluetoothAttServerAttributesDialog::on_actionCopy_Cell_triggered()
{
    QTreeWidgetItem *current_item = ui->tableTreeWidget->currentItem();
    if (!current_item)
        return;

    QClipboard *clipboard = QApplication::clipboard();
    QString     copy;

    copy = QString(current_item->text(ui->tableTreeWidget->currentColumn()));

    clipboard->setText(copy);
}


void BluetoothAttServerAttributesDialog::on_actionCopy_Rows_triggered()
{
    QClipboard                         *clipboard = QApplication::clipboard();
    QString                             copy;
    QList<QTreeWidgetItem *>            items;
    QList<QTreeWidgetItem *>::iterator  i_item;

    items =  ui->tableTreeWidget->selectedItems();

    for (i_item = items.begin(); i_item != items.end(); ++i_item) {
        copy += QString("%1  %2  %3\n")
                .arg((*i_item)->text(column_number_handle), -6)
                .arg((*i_item)->text(column_number_uuid), -32)
                .arg((*i_item)->text(column_number_uuid_name));

    }

    clipboard->setText(copy);
}

void BluetoothAttServerAttributesDialog::tapReset(void *tapinfo_ptr)
{
    tapinfo_t *tapinfo = (tapinfo_t *) tapinfo_ptr;
    BluetoothAttServerAttributesDialog  *bluetooth_att_server_attributes_dialog = static_cast<BluetoothAttServerAttributesDialog *>(tapinfo->ui);


    bluetooth_att_server_attributes_dialog->ui->tableTreeWidget->clear();
}


tap_packet_status BluetoothAttServerAttributesDialog::tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *data, tap_flags_t)
{
    tapinfo_t                           *tapinfo     = static_cast<tapinfo_t *>(tapinfo_ptr);
    BluetoothAttServerAttributesDialog  *dialog      = static_cast<BluetoothAttServerAttributesDialog *>(tapinfo->ui);
    tap_handles_t                       *tap_handles = static_cast<tap_handles_t *>(const_cast<void *>(data));
    QString                              handle;
    QString                              uuid;
    QString                              uuid_name;
    gchar                               *addr = NULL;

    if (dialog->file_closed_)
        return TAP_PACKET_DONT_REDRAW;

    if (pinfo->rec->rec_type != REC_TYPE_PACKET)
        return TAP_PACKET_DONT_REDRAW;

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

    if (pinfo->p2p_dir == P2P_DIR_SENT || pinfo->p2p_dir == P2P_DIR_RECV)
        addr = address_to_str(pinfo->pool, &pinfo->src);

    if (addr && dialog->ui->deviceComboBox->findText(addr) == -1) {
        dialog->ui->deviceComboBox->addItem(addr);
    }

    if (addr && dialog->ui->deviceComboBox->currentIndex() > 0) {
        if (dialog->ui->deviceComboBox->currentText() != addr)
            return TAP_PACKET_REDRAW;
    }

    handle = QString("0x%1").arg(tap_handles->handle, 4, 16, QChar('0'));
    uuid = QString(print_numeric_bluetooth_uuid(&tap_handles->uuid));
    uuid_name = QString(print_bluetooth_uuid(&tap_handles->uuid));

    if (dialog->ui->removeDuplicatesCheckBox->checkState() == Qt::Checked) {
        QTreeWidgetItemIterator i_item(dialog->ui->tableTreeWidget);

        while (*i_item) {
            QTreeWidgetItem *item = static_cast<QTreeWidgetItem*>(*i_item);

            if (item->text(column_number_handle) == handle &&
                    item->text(column_number_uuid) == uuid &&
                    item->text(column_number_uuid_name) == uuid_name)
                return TAP_PACKET_REDRAW;
            ++i_item;
        }
    }

    QTreeWidgetItem *item = new QTreeWidgetItem(dialog->ui->tableTreeWidget);
    item->setText(column_number_handle, handle);
    item->setText(column_number_uuid, uuid);
    item->setText(column_number_uuid_name,  uuid_name);
    item->setData(0, Qt::UserRole, QVariant::fromValue(pinfo->num));

    for (int i = 0; i < dialog->ui->tableTreeWidget->columnCount(); i++) {
        dialog->ui->tableTreeWidget->resizeColumnToContents(i);
    }

    return TAP_PACKET_REDRAW;
}

void BluetoothAttServerAttributesDialog::interfaceCurrentIndexChanged(int)
{
    cap_file_.retapPackets();
}


void BluetoothAttServerAttributesDialog::deviceCurrentIndexChanged(int)
{
    cap_file_.retapPackets();
}


void BluetoothAttServerAttributesDialog::removeDuplicatesStateChanged(int)
{
    cap_file_.retapPackets();
}



void BluetoothAttServerAttributesDialog::on_tableTreeWidget_itemActivated(QTreeWidgetItem *item, int)
{
    if (file_closed_)
        return;

    guint32 frame_number = item->data(0, Qt::UserRole).value<guint32>();

    emit goToPacket(frame_number);
}


void BluetoothAttServerAttributesDialog::on_actionCopy_All_triggered()
{
    QClipboard             *clipboard = QApplication::clipboard();
    QString                 copy;
    QTreeWidgetItemIterator i_item(ui->tableTreeWidget);

    copy = QString("%1  %2  %3\n")
            .arg(ui->tableTreeWidget->headerItem()->text(column_number_handle), -6)
            .arg(ui->tableTreeWidget->headerItem()->text(column_number_uuid), -32)
            .arg(ui->tableTreeWidget->headerItem()->text(column_number_uuid_name));

    while (*i_item) {
        QTreeWidgetItem *item = static_cast<QTreeWidgetItem*>(*i_item);
        copy += QString("%1  %2  %3\n")
                .arg(item->text(column_number_handle), -6)
                .arg(item->text(column_number_uuid), -32)
                .arg(item->text(column_number_uuid_name));
        ++i_item;
    }

    clipboard->setText(copy);
}

void BluetoothAttServerAttributesDialog::on_actionSave_as_image_triggered()
{
    QPixmap image;

    QString fileName = WiresharkFileDialog::getSaveFileName(this, tr("Save Table Image"),
                           "att_server_attributes_table.png",
                           tr("PNG Image (*.png)"));

    if (fileName.isEmpty()) return;

    image = ui->tableTreeWidget->grab();
    image.save(fileName, "PNG");
}

void BluetoothAttServerAttributesDialog::on_buttonBox_clicked(QAbstractButton *)
{
/*    if (button == foo_button_) */
}
