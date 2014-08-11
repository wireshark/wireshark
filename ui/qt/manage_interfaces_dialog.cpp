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
#include "epan/to_str.h"
#include "ui/last_open_dir.h"
#include "capture_opts.h"
#include "ui/capture_globals.h"
#include "ui/qt/capture_interfaces_dialog.h"
#ifdef HAVE_PCAP_REMOTE
#include "ui/qt/remote_capture_dialog.h"
#include "ui/qt/remote_settings_dialog.h"
#endif
#include "ui/iface_lists.h"
#include "ui/preference_utils.h"
#include "ui/ui_util.h"

#ifdef HAVE_LIBPCAP
#include <QFileDialog>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QCheckBox>

enum {
    col_p_pipe_
};

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
#ifdef HAVE_PCAP_REMOTE
    connect(this, SIGNAL(remoteAdded(GList*, remote_options*)), this, SLOT(addRemoteInterfaces(GList*, remote_options*)));
    connect(this, SIGNAL(remoteSettingsChanged(interface_t *)), this, SLOT(setRemoteSettings(interface_t *)));
#endif
    showLocalInterfaces();

#if !defined(HAVE_PCAP_REMOTE)
    ui->tabWidget->removeTab(2);
#else
    ui->remoteList->setHeaderLabels(QStringList() << "Host" << "Hide" << "Name");
    ui->remoteList->header()->setDefaultAlignment(Qt::AlignCenter);
    ui->remoteList->setColumnWidth(HIDDEN, 50);
    ui->remoteSettings->setEnabled(false);
    showRemoteInterfaces();
    connect(ui->remoteList, SIGNAL(itemClicked(QTreeWidgetItem*, int)), this, SLOT(remoteSelectionChanged(QTreeWidgetItem*, int)));
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
            ui->pipeList->setItem(ui->pipeList->rowCount()-1, col_p_pipe_, new QTableWidgetItem(output));
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
            eFlags = ui->localList->item(ui->localList->rowCount()-1, LOCAL_NAME)->flags();
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
    gchar *new_hide = g_strdup("");
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

#ifdef HAVE_PCAP_REMOTE
void ManageInterfacesDialog::remoteSelectionChanged(QTreeWidgetItem* item, int col)
{
    Q_UNUSED(item);

    if (col != 0 && item->isSelected()) {
        ui->remoteSettings->setEnabled(true);
    } else if (col == 0) {
        ui->remoteSettings->setEnabled(false);
    }
}

void ManageInterfacesDialog::addRemoteInterfaces(GList* rlist, remote_options *roptions)
{
    GList *if_entry, *lt_entry;
    if_info_t *if_info;
    char *if_string = NULL;
    gchar *descr, *str = NULL, *link_type_name = NULL;;
    if_capabilities_t *caps;
    gint linktype_count;
    bool monitor_mode, found = false;
    GSList *curr_addr;
    int ips = 0;
    guint i;
    if_addr_t *addr;
    data_link_info_t *data_link_info;
    GString *ip_str;
    link_row *linkr = NULL;
    interface_t device;

    guint num_interfaces = global_capture_opts.all_ifaces->len;
    for (if_entry = g_list_first(rlist); if_entry != NULL; if_entry = g_list_next(if_entry)) {
        if_info = (if_info_t *)if_entry->data;
        for (i = 0; i < num_interfaces; i++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (device.hidden)
                continue;
            if (strcmp(device.name, if_info->name) == 0) {
                found = TRUE;
                break;
            }
        }
        if (found) {
            found = FALSE;
            continue;
        }
        ip_str = g_string_new("");
        str = "";
        ips = 0;
        device.name = g_strdup(if_info->name);
        /* Is this interface hidden and, if so, should we include it
           anyway? */
        descr = capture_dev_user_descr_find(if_info->name);
        if (descr != NULL) {
            /* Yes, we have a user-supplied description; use it. */
            if_string = g_strdup_printf("%s: %s", descr, if_info->name);
            g_free(descr);
        } else {
            /* No, we don't have a user-supplied description; did we get
               one from the OS or libpcap? */
            if (if_info->vendor_description != NULL) {
                /* Yes - use it. */
                if_string = g_strdup_printf("%s: %s", if_info->vendor_description, if_info->name);
            } else {
                /* No. */
                if_string = g_strdup(if_info->name);
            }
        } /* else descr != NULL */
        if (if_info->loopback) {
            device.display_name = g_strdup_printf("%s (loopback)", if_string);
        } else {
            device.display_name = g_strdup(if_string);
        }
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
        if ((device.buffer = capture_dev_user_buffersize_find(if_string)) == -1) {
            device.buffer = global_capture_opts.default_options.buffer_size;
        }
#endif
        if ((device.pmode = capture_dev_user_pmode_find(if_string)) == -1) {
            device.pmode = global_capture_opts.default_options.promisc_mode;
        }
        device.has_snaplen = global_capture_opts.default_options.has_snaplen;
        if ((device.snaplen = capture_dev_user_snaplen_find(if_string)) == -1) {
            device.snaplen = global_capture_opts.default_options.snaplen;
        }
        device.cfilter = g_strdup(global_capture_opts.default_options.cfilter);
        monitor_mode = prefs_capture_device_monitor_mode(if_string);
        caps = capture_get_if_capabilities(if_string, monitor_mode, NULL, main_window_update);
        for (; (curr_addr = g_slist_nth(if_info->addrs, ips)) != NULL; ips++) {
            if (ips != 0) {
                g_string_append(ip_str, "\n");
            }
            addr = (if_addr_t *)curr_addr->data;
            switch (addr->ifat_type) {
            case IF_AT_IPv4:
                g_string_append(ip_str, ip_to_str((guint8 *)&addr->addr.ip4_addr));
                break;
            case IF_AT_IPv6:
                g_string_append(ip_str,  ip6_to_str((struct e_in6_addr *)&addr->addr.ip6_addr));
                break;
            default:
                /* In case we add non-IP addresses */
                break;
            }
        } /* for curr_addr */
        linktype_count = 0;
        device.links = NULL;
        if (caps != NULL) {
#ifdef HAVE_PCAP_CREATE
            device.monitor_mode_enabled = monitor_mode;
            device.monitor_mode_supported = caps->can_set_rfmon;
#endif
            for (lt_entry = caps->data_link_types; lt_entry != NULL; lt_entry = g_list_next(lt_entry)) {
                data_link_info = (data_link_info_t *)lt_entry->data;
                linkr = (link_row *)g_malloc(sizeof(link_row));
                /*
                 * For link-layer types libpcap/WinPcap doesn't know about, the
                 * name will be "DLT n", and the description will be null.
                 * We mark those as unsupported, and don't allow them to be
                 * used.
                 */
                if (data_link_info->description != NULL) {
                    str = g_strdup_printf("%s", data_link_info->description);
                    linkr->dlt = data_link_info->dlt;
                } else {
                    str = g_strdup_printf("%s (not supported)", data_link_info->name);
                    linkr->dlt = -1;
                }
                if (linktype_count == 0) {
                    link_type_name = g_strdup(str);
                    device.active_dlt = data_link_info->dlt;
                }
                linkr->name = g_strdup(str);
                g_free(str);
                device.links = g_list_append(device.links, linkr);
                linktype_count++;
            } /* for link_types */
        } else {
#if defined(HAVE_PCAP_CREATE)
            device.monitor_mode_enabled = FALSE;
            device.monitor_mode_supported = FALSE;
#endif
            device.active_dlt = -1;
            link_type_name = g_strdup("default");
        }
        device.addresses = g_strdup(ip_str->str);
        device.no_addresses = ips;
        device.remote_opts.src_type= roptions->src_type;
        if (device.remote_opts.src_type == CAPTURE_IFREMOTE) {
            device.local = FALSE;
        }
        device.remote_opts.remote_host_opts.remote_host = g_strdup(roptions->remote_host_opts.remote_host);
        device.remote_opts.remote_host_opts.remote_port = g_strdup(roptions->remote_host_opts.remote_port);
        device.remote_opts.remote_host_opts.auth_type = roptions->remote_host_opts.auth_type;
        device.remote_opts.remote_host_opts.auth_username = g_strdup(roptions->remote_host_opts.auth_username);
        device.remote_opts.remote_host_opts.auth_password = g_strdup(roptions->remote_host_opts.auth_password);
        device.remote_opts.remote_host_opts.datatx_udp = roptions->remote_host_opts.datatx_udp;
        device.remote_opts.remote_host_opts.nocap_rpcap = roptions->remote_host_opts.nocap_rpcap;
        device.remote_opts.remote_host_opts.nocap_local = roptions->remote_host_opts.nocap_local;
#ifdef HAVE_PCAP_SETSAMPLING
        device.remote_opts.sampling_method = roptions->sampling_method;
        device.remote_opts.sampling_param = roptions->sampling_param;
#endif
        device.selected = TRUE;
        global_capture_opts.num_selected++;
        g_array_append_val(global_capture_opts.all_ifaces, device);
        g_string_free(ip_str, TRUE);
    } /*for*/
    showRemoteInterfaces();
}

void ManageInterfacesDialog::on_remoteButtonBox_accepted()
{
    QTreeWidgetItemIterator it(ui->remoteList);

    while(*it) {
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if ((*it)->text(2).compare(device.name))
                continue;
            device.hidden = ((*it)->checkState(1)==Qt::Checked?true:false);
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
            g_array_insert_val(global_capture_opts.all_ifaces, i, device);
        }
        ++it;
    }
    emit ifsChanged();
}

void ManageInterfacesDialog::on_delRemote_clicked()
{
    QList<QTreeWidgetItem*> selected = ui->remoteList->selectedItems();
    if (selected.length() == 0) {
        QMessageBox::warning(this, tr("Error"),
                             tr("No host selected. Select the host to be removed."));
        return;
    }
    QString host = selected[0]->text(0);
    int index = ui->remoteList->indexOfTopLevelItem(selected[0]);
    QTreeWidgetItem *top = ui->remoteList->takeTopLevelItem(index);
    int numChildren = top->childCount();
    for (int i = 0; i < numChildren; i++) {
        QTreeWidgetItem *child = top->child(i);
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (child->text(2).compare(device.name))
                continue;
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
        }
    }
    ui->remoteList->removeItemWidget(top, 0);
    fflush(stdout);
}

void ManageInterfacesDialog::on_addRemote_clicked()
{
    RemoteCaptureDialog *dlg = new RemoteCaptureDialog(this);
    dlg->show();
}

void ManageInterfacesDialog::showRemoteInterfaces()
{
    guint i;
    interface_t device;
    gchar *host = g_strdup("");
    QTreeWidgetItem *child;

    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (!device.local) {
            QTreeWidgetItem *itm;
            if (strcmp(host, device.remote_opts.remote_host_opts.remote_host)) {
                host = g_strdup(device.remote_opts.remote_host_opts.remote_host);
                itm = new QTreeWidgetItem(ui->remoteList);
                itm->setText(HOST, host);
                child = new QTreeWidgetItem(itm);
                child->setCheckState(HIDDEN, device.hidden?Qt::Checked:Qt::Unchecked);
                child->setText(REMOTE_NAME, QString(device.name));
            } else {
                child = new QTreeWidgetItem(itm);
                child->setCheckState(HIDDEN, device.hidden?Qt::Checked:Qt::Unchecked);
                child->setText(REMOTE_NAME, QString(device.name));
            }
        }
    }
}

void ManageInterfacesDialog::on_remoteSettings_clicked()
{
    guint i = 0;
    interface_t device;

    QList<QTreeWidgetItem*> selected = ui->remoteList->selectedItems();
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (!device.local) {
            if (selected[0]->text(2).compare(device.name)) {
               continue;
            } else {
                RemoteSettingsDialog *dlg = new RemoteSettingsDialog(this, &device);
                dlg->show();
                break;
            }
        }
    }
}

void ManageInterfacesDialog::setRemoteSettings(interface_t *iface)
{
    for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (!device.local) {
            if (strcmp(iface->name, device.name)) {
                continue;
            }
            device.remote_opts.remote_host_opts.nocap_rpcap = iface->remote_opts.remote_host_opts.nocap_rpcap;
            device.remote_opts.remote_host_opts.datatx_udp = iface->remote_opts.remote_host_opts.datatx_udp;
#ifdef HAVE_PCAP_SETSAMPLING
            device.remote_opts.sampling_method = iface->remote_opts.sampling_method;
            device.remote_opts.sampling_param = iface->remote_opts.sampling_param;
#endif //HAVE_PCAP_SETSAMPLING
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
            g_array_insert_val(global_capture_opts.all_ifaces, i, device);
        }
    }
}
#endif

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
