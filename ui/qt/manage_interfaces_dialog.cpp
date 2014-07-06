/* manage_interfaces_dialog.cpp
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

#include "config.h"
#include <glib.h>
#include "manage_interfaces_dialog.h"
#include "ui_manage_interfaces_dialog.h"
#include "epan/prefs.h"
#include "ui/last_open_dir.h"
#include "capture_opts.h"
#include "ui/capture_globals.h"
#include "ui/qt/capture_interfaces_dialog.h"
#include "ui/iface_lists.h"
#include "ui/preference_utils.h"

#ifdef HAVE_LIBPCAP
#include <QFileDialog>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QCheckBox>

ManageInterfacesDialog::ManageInterfacesDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ManageInterfacesDialog)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC
    ui->addButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->delButton->setAttribute(Qt::WA_MacSmallSize, true);
#endif
    ui->pipeList->setItemDelegateForColumn(0, &new_pipe_item_delegate_);
    new_pipe_item_delegate_.setTable(ui->pipeList);
    showPipes();
    connect(this, SIGNAL(ifsChanged()), parent, SIGNAL(ifsChanged()));

    showLocalInterfaces();

#if !defined(HAVE_PCAP_REMOTE)
    ui->tabWidget->removeTab(2);
#endif
}

ManageInterfacesDialog::~ManageInterfacesDialog()
{
    delete ui;
}


void ManageInterfacesDialog::showPipes()
{
    ui->pipeList->setRowCount(0);

    if (global_capture_opts.all_ifaces->len > 0) {
        interface_t device;

        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);

            /* Continue if capture device is hidden */
            if (device.hidden || device.type != IF_PIPE) {
                continue;
            }
            ui->pipeList->setRowCount(ui->pipeList->rowCount()+1);
            QString output = QString(device.display_name);
            ui->pipeList->setItem(ui->pipeList->rowCount()-1, INTERFACE, new QTableWidgetItem(output));
        }
    }
}

void ManageInterfacesDialog::on_addButton_clicked()
{
    ui->pipeList->setRowCount(ui->pipeList->rowCount() + 1);
    QTableWidgetItem *widget = new QTableWidgetItem(QString(tr("New Pipe")));
    ui->pipeList->setItem(ui->pipeList->rowCount() - 1 , 0, widget);
}


void ManageInterfacesDialog::on_buttonBox_accepted()
{
    interface_t device;
    gchar *pipe_name;

    for (int row = 0; row < ui->pipeList->rowCount(); row++) {
        pipe_name = g_strdup(ui->pipeList->item(row,0)->text().toUtf8().constData());
        if (!strcmp(pipe_name, "New pipe") || !strcmp(pipe_name, "")) {
            g_free(pipe_name);
            return;
        }
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
          device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
          if (strcmp(pipe_name, device.name) == 0) {
            g_free(pipe_name);
            return;
          }
        }
        device.name         = g_strdup(pipe_name);
        device.display_name = g_strdup_printf("%s", device.name);
        device.hidden       = FALSE;
        device.selected     = TRUE;
        device.type         = IF_PIPE;
        device.pmode        = global_capture_opts.default_options.promisc_mode;
        device.has_snaplen  = global_capture_opts.default_options.has_snaplen;
        device.snaplen      = global_capture_opts.default_options.snaplen;
        device.cfilter      = g_strdup(global_capture_opts.default_options.cfilter);
        device.addresses    = g_strdup("");
        device.no_addresses = 0;
        device.last_packets = 0;
        device.links        = NULL;
    #if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
        device.buffer       = DEFAULT_CAPTURE_BUFFER_SIZE;
    #endif
        device.active_dlt = -1;
        device.locked = FALSE;
        device.if_info.name = g_strdup(pipe_name);
        device.if_info.friendly_name = NULL;
        device.if_info.vendor_description = NULL;
        device.if_info.addrs = NULL;
        device.if_info.loopback = FALSE;
        device.if_info.type = IF_PIPE;
    #if defined(HAVE_PCAP_CREATE)
        device.monitor_mode_enabled = FALSE;
        device.monitor_mode_supported = FALSE;
    #endif
        global_capture_opts.num_selected++;
        g_array_append_val(global_capture_opts.all_ifaces, device);

        g_free(pipe_name);
    }
    emit ifsChanged();
}



void ManageInterfacesDialog::on_delButton_clicked()
{
    interface_t device;
    bool found = false;
    QList<QTableWidgetItem*> selected = ui->pipeList->selectedItems();
    if (selected.length() == 0) {
        QMessageBox::warning(this, tr("Error"),
                             tr("No interface selected."));
        return;
    }
    QString pipename = selected[0]->text();
    for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        /* Continue if capture device is hidden or not a pipe*/
        if (device.hidden || device.type != IF_PIPE) {
            continue;
        }
        if (pipename.compare(device.name)) {
            continue;
        }
        global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
        ui->pipeList->removeRow(selected[0]->row());
        found = true;
        break;
    }
    if (found)
        emit ifsChanged();
    else  /* pipe has not been saved yet */
        ui->pipeList->removeRow(selected[0]->row());
}

void ManageInterfacesDialog::showLocalInterfaces()
{
    guint i;
    interface_t device;
    QString output;
    Qt::ItemFlags eFlags;
    gchar *pr_descr = g_strdup("");
    char *comment = NULL;

    ui->localList->setRowCount(0);
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (device.local && device.type != IF_PIPE && device.type != IF_STDIN) {
            ui->localList->setRowCount(ui->localList->rowCount()+1);
            QTableWidgetItem *item = new QTableWidgetItem("");
            item->setCheckState(device.hidden?Qt::Checked:Qt::Unchecked);
            ui->localList->setItem(ui->localList->rowCount()-1, HIDE, item);
            ui->localList->setColumnWidth(HIDE, 40);
#ifdef _WIN32
            output = QString(device.friendly_name);
            ui->localList->setItem(ui->localList->rowCount()-1, FRIENDLY, new QTableWidgetItem(output));
            eFlags = ui->localList->item(ui->localList->rowCount()-1, FRIENDLY)->flags();
            eFlags &= Qt::NoItemFlags;
            eFlags |= Qt::ItemIsSelectable | Qt::ItemIsEnabled;
            ui->localList->item(ui->localList->rowCount()-1, FRIENDLY)->setFlags(eFlags);
#else
            ui->localList->setColumnHidden(FRIENDLY, true);
#endif
            output = QString(device.name);
            ui->localList->setItem(ui->localList->rowCount()-1, LOCAL_NAME, new QTableWidgetItem(output));
            output = QString("");
            eFlags = ui->localList->item(ui->localList->rowCount()-1, FRIENDLY)->flags();
            eFlags &= Qt::NoItemFlags;
            eFlags |= Qt::ItemIsSelectable | Qt::ItemIsEnabled;
            ui->localList->item(ui->localList->rowCount()-1, LOCAL_NAME)->setFlags(eFlags);

            comment = capture_dev_user_descr_find(device.name);
            if (comment)
                output = QString(comment);
            ui->localList->setItem(ui->localList->rowCount()-1, COMMENT, new QTableWidgetItem(output));
        } else {
          continue;
        }
    }
    g_free(pr_descr);
}

void ManageInterfacesDialog::saveLocalHideChanges(QTableWidgetItem* item)
{
    guint i;
    interface_t device;

    if (item->column() != HIDE) {
        return;
    }
    QTableWidgetItem* nameItem = ui->localList->item(item->row(), LOCAL_NAME);

    if (!nameItem) {
        return;
    }

    QString name = nameItem->text();
    /* See if this is the currently selected capturing device */

    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (name.compare(device.name)) {
            continue;
        }
        device.hidden = (item->checkState()==Qt::Checked?true:false);
        global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
        g_array_insert_val(global_capture_opts.all_ifaces, i, device);
    }
}

void ManageInterfacesDialog::saveLocalCommentChanges(QTableWidgetItem* item)
{
    guint i;
    interface_t device;

    if (item->column() != COMMENT) {
        return;
    }
    QTableWidgetItem* nameItem = ui->localList->item(item->row(), LOCAL_NAME);

    if (!nameItem) {
        return;
    }

    QString name = nameItem->text();
    QString comment = ui->localList->item(item->row(), COMMENT)->text();
    /* See if this is the currently selected capturing device */

    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (name.compare(device.name)) {
            continue;
        }
        if (!comment.compare("")) {
            device.display_name = g_strdup_printf("%s", name.toUtf8().constData());
        } else {
            device.display_name = g_strdup_printf("%s: %s", comment.toUtf8().constData(), name.toUtf8().constData());
        }
        global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
        g_array_insert_val(global_capture_opts.all_ifaces, i, device);
    }
}


void ManageInterfacesDialog::checkBoxChanged(QTableWidgetItem* item)
{
    guint i;
    interface_t device;

    if (item->column() != HIDE) {
        return;
    }
    QTableWidgetItem* nameItem = ui->localList->item(item->row(), LOCAL_NAME);

    if (!nameItem) {
        return;
    }

    QString name = nameItem->text();
    /* See if this is the currently selected capturing device */

    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (name.compare(device.name)) {
            continue;
        }
        if (prefs.capture_device && strstr(prefs.capture_device, device.name) && item->checkState() == Qt::Checked) {
            /* Don't allow current interface to be hidden */
            QMessageBox::warning(this, tr("Error"),
                                 tr("Default interface cannot be hidden."));
            item->setCheckState(Qt::Unchecked);
            return;
        }
    }
}

void ManageInterfacesDialog::on_localButtonBox_accepted()
{
    gchar *new_hide;
    gchar *new_comment = NULL;
    QString name;
    gchar *tmp_descr = NULL;

    if (global_capture_opts.all_ifaces->len > 0) {
        new_hide = (gchar*)g_malloc0(MAX_VAL_LEN);
        for (int row = 0; row < ui->localList->rowCount(); row++) {
            QTableWidgetItem* hitem = ui->localList->item(row, HIDE);
            checkBoxChanged(hitem);
            if (hitem->checkState() == Qt::Checked) {
                name = ui->localList->item(row, LOCAL_NAME)->text();
                g_strlcat (new_hide, ",", MAX_VAL_LEN);
                g_strlcat (new_hide, name.toUtf8().constData(), MAX_VAL_LEN);
            }
            saveLocalHideChanges(hitem);
        }
        /* write new "hidden" string to preferences */
        g_free(prefs.capture_devices_hide);
        prefs.capture_devices_hide = new_hide;
        hide_interface(g_strdup(new_hide));

        new_comment = (gchar*)g_malloc0(MAX_VAL_LEN);
        for (int row = 0; row < ui->localList->rowCount(); row++) {
            name = ui->localList->item(row, LOCAL_NAME)->text();
            QTableWidgetItem* citem = ui->localList->item(row, COMMENT);
            if (citem->text().compare("")) {
                g_strlcat (new_comment, ",", MAX_VAL_LEN);
                tmp_descr = g_strdup_printf("%s(%s)", name.toUtf8().constData(), citem->text().toUtf8().constData());
                g_strlcat (new_comment, tmp_descr, MAX_VAL_LEN);
                g_free(tmp_descr);
            }
            saveLocalCommentChanges(citem);
        }
        /* write new description string to preferences */
        if (prefs.capture_devices_descr)
            g_free(prefs.capture_devices_descr);
        prefs.capture_devices_descr = new_comment;
    }

    /* save changes to the preferences file */
    if (!prefs.gui_use_pref_save) {
        prefs_main_write();
    }
    emit ifsChanged();
}


NewFileDelegate::NewFileDelegate(QObject *parent)
    : QStyledItemDelegate(parent)
{
}


NewFileDelegate::~NewFileDelegate()
{
}


QWidget* NewFileDelegate::createEditor( QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index ) const
{
    Q_UNUSED(option);
    Q_UNUSED(index);

    QWidget * widg = new QWidget(parent);
    QHBoxLayout *hbox = new QHBoxLayout(widg);
    widg->setLayout(hbox);
    QLineEdit *le = new QLineEdit(widg);
    QPushButton *pb = new QPushButton(widg);
    pb->setText(QString(tr("Browse...")));
    le->setText(table->currentItem()->text());
    hbox->addWidget(le);
    hbox->addWidget(pb);
    hbox->setMargin(0);

    connect(le, SIGNAL(textEdited(const QString &)), this, SLOT(setTextField(const QString &)));
    connect(le, SIGNAL(editingFinished()), this, SLOT(stopEditor()));
    connect(pb, SIGNAL(pressed()), this, SLOT(browse_button_clicked()));
    return widg;
}

void NewFileDelegate::setTextField(const QString &text)
{
    table->currentItem()->setText(text);
}

void NewFileDelegate::stopEditor()
{
   closeEditor(table->cellWidget(table->currentRow(), 0));
}

void NewFileDelegate::browse_button_clicked()
{
    char *open_dir = NULL;

    switch (prefs.gui_fileopen_style) {

    case FO_STYLE_LAST_OPENED:
        open_dir = get_last_open_dir();
        break;

    case FO_STYLE_SPECIFIED:
        if (prefs.gui_fileopen_dir[0] != '\0')
            open_dir = prefs.gui_fileopen_dir;
        break;
    }
    QString file_name = QFileDialog::getOpenFileName(table, tr("Open Pipe"), open_dir);
    closeEditor(table->cellWidget(table->currentRow(), 0));
    table->currentItem()->setText(file_name);
}

#endif /* HAVE_LIBPCAP */
//
// Editor modelines  -  http://www.wireshark.org/tools/modelines.html
//
// Local variables:
// c-basic-offset: 4
// tab-width: 4
// indent-tabs-mode: nil
// End:
//
// vi: set shiftwidth=4 tabstop=4 expandtab:
// :indentSize=4:tabSize=4:noTabs=true:
//
