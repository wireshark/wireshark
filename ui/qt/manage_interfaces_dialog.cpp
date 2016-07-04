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

#include <glib.h>
#include "manage_interfaces_dialog.h"
#include <ui_manage_interfaces_dialog.h>
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
#include <wsutil/utf8_entities.h>

#include "qt_ui_utils.h"

#include "wireshark_application.h"

#include <QDebug>

#ifdef HAVE_LIBPCAP
#include <QCheckBox>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QStandardItemModel>
#include <QTreeWidgetItemIterator>

// To do:
// - Check the validity of pipes and remote interfaces and provide feedback
//   via hintLabel.
// - We might want to move PathChooserDelegate to its own module and use it in
//   other parts of the application such as the general preferences and UATs.
//   Qt Creator has a much more elaborate version from which we might want
//   to draw inspiration.

enum {
    col_p_pipe_
};

enum
{
    col_l_show_,
    col_l_friendly_name_,
    col_l_local_name_,
    col_l_comment_
};

enum
{
    col_r_show_,
    col_r_host_dev_
};

enum {
    tab_local_,
    tab_pipe_,
    tab_remote_
};

ManageInterfacesDialog::ManageInterfacesDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::ManageInterfacesDialog)
{
    ui->setupUi(this);
    loadGeometry();

#ifdef Q_OS_MAC
    ui->addPipe->setAttribute(Qt::WA_MacSmallSize, true);
    ui->addPipe->setAttribute(Qt::WA_MacSmallSize, true);
    ui->addRemote->setAttribute(Qt::WA_MacSmallSize, true);
    ui->delRemote->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    int one_em = fontMetrics().height();

    ui->localList->setColumnWidth(col_l_show_, one_em * 3);
#ifndef Q_OS_WIN
    ui->localList->setColumnHidden(col_l_friendly_name_, true);
#endif
    ui->localList->setEditTriggers(QAbstractItemView::NoEditTriggers);

    ui->pipeList->setItemDelegateForColumn(col_p_pipe_, &new_pipe_item_delegate_);
    new_pipe_item_delegate_.setTree(ui->pipeList);

    showPipes();
    showLocalInterfaces();

#if defined(HAVE_PCAP_REMOTE)
    // The default indentation (20) means our checkboxes are shifted too far on Windows.
    // Assume that our disclosure and checkbox controls are square, or at least fit within an em.
    ui->remoteList->setIndentation(one_em);
    ui->remoteList->setColumnWidth(col_r_show_, one_em * 4);
    ui->remoteSettings->setEnabled(false);
    showRemoteInterfaces();
#else
    ui->remoteTab->setEnabled(false);
#endif

    connect(ui->tabWidget, SIGNAL(currentChanged(int)), this, SLOT(updateWidgets()));
    connect(this, SIGNAL(ifsChanged()), parent, SIGNAL(ifsChanged()));
    connect(ui->localList, SIGNAL(itemDoubleClicked(QTreeWidgetItem *, int)), this, SLOT(localListItemDoubleClicked(QTreeWidgetItem *, int)));

#ifdef HAVE_PCAP_REMOTE
    connect(this, SIGNAL(remoteAdded(GList*, remote_options*)), this, SLOT(addRemoteInterfaces(GList*, remote_options*)));
    connect(this, SIGNAL(remoteSettingsChanged(interface_t *)), this, SLOT(setRemoteSettings(interface_t *)));
    connect(ui->remoteList, SIGNAL(itemClicked(QTreeWidgetItem*, int)), this, SLOT(remoteSelectionChanged(QTreeWidgetItem*, int)));
#endif

    ui->tabWidget->setCurrentIndex(tab_local_);
    updateWidgets();
}

ManageInterfacesDialog::~ManageInterfacesDialog()
{
    delete ui;
}

void ManageInterfacesDialog::updateWidgets()
{
    QString hint;

    if (ui->pipeList->selectedItems().length() > 0) {
        ui->delPipe->setEnabled(true);
    } else {
        ui->delPipe->setEnabled(false);
    }

#ifdef HAVE_PCAP_REMOTE
    bool enable_del_remote = false;
    bool enable_remote_settings = false;
    QTreeWidgetItem *item = ui->remoteList->currentItem();

    if (item) {
        if (item->childCount() < 1) { // Leaf
            enable_remote_settings = true;
        } else {
            enable_del_remote = true;
        }
    }
    ui->delRemote->setEnabled(enable_del_remote);
    ui->remoteSettings->setEnabled(enable_remote_settings);
#endif

    switch (ui->tabWidget->currentIndex()) {
    case tab_pipe_:
        hint = tr("This version of Wireshark does not save pipe settings.");
        break;
    case tab_remote_:
#ifdef HAVE_PCAP_REMOTE
        hint = tr("This version of Wireshark does not save remote settings.");
#else
        hint = tr("This version of Wireshark does not support remote interfaces.");
#endif
        break;
    default:
        break;
    }

    hint.prepend("<small><i>");
    hint.append("</i></small>");
    ui->hintLabel->setText(hint);
}

void ManageInterfacesDialog::showPipes()
{
    ui->pipeList->clear();

    if (global_capture_opts.all_ifaces->len > 0) {
        interface_t device;

        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);

            /* Continue if capture device is hidden */
            if (device.hidden || device.type != IF_PIPE) {
                continue;
            }
            QTreeWidgetItem *item = new QTreeWidgetItem(ui->pipeList);
            item->setFlags(item->flags() | Qt::ItemIsEditable);
            item->setText(col_p_pipe_, device.display_name);
        }
    }
}

void ManageInterfacesDialog::on_buttonBox_accepted()
{
    pipeAccepted();
    localAccepted();
#ifdef HAVE_PCAP_REMOTE
    remoteAccepted();
#endif
    prefs_main_write();
    emit ifsChanged();
}

const QString new_pipe_default_ = QObject::tr("New Pipe");
void ManageInterfacesDialog::on_addPipe_clicked()
{
    QTreeWidgetItem *item = new QTreeWidgetItem(ui->pipeList);
    item->setText(col_p_pipe_, new_pipe_default_);
    item->setFlags(item->flags() | Qt::ItemIsEditable);
    ui->pipeList->setCurrentItem(item);
    ui->pipeList->editItem(item, col_p_pipe_);
}

void ManageInterfacesDialog::pipeAccepted()
{
    interface_t device;

    // First clear the current pipes
    for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        /* Continue if capture device is hidden or not a pipe */
        if (device.hidden || device.type != IF_PIPE) {
            continue;
        }
        global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
        capture_opts_free_interface_t(&device);
    }

    // Next rebuild a fresh list
    QTreeWidgetItemIterator it(ui->pipeList);
    while (*it) {
        QString pipe_name = (*it)->text(col_p_pipe_);
        if (pipe_name.isEmpty() || pipe_name == new_pipe_default_) {
            ++it;
            continue;
        }

        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            // Instead of just deleting the device we might want to add a hint label
            // and let the user know what's going to happen.
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (pipe_name.compare(device.name) == 0) { // Duplicate
                ++it;
                continue;
            }
        }

        memset(&device, 0, sizeof(device));
        device.name         = qstring_strdup(pipe_name);
        device.display_name = g_strdup(device.name);
        device.hidden       = FALSE;
        device.selected     = TRUE;
        device.type         = IF_PIPE;
        device.pmode        = global_capture_opts.default_options.promisc_mode;
        device.has_snaplen  = global_capture_opts.default_options.has_snaplen;
        device.snaplen      = global_capture_opts.default_options.snaplen;
        device.cfilter      = g_strdup(global_capture_opts.default_options.cfilter);
        device.addresses    = NULL;
        device.no_addresses = 0;
        device.last_packets = 0;
        device.links        = NULL;
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
        device.buffer       = DEFAULT_CAPTURE_BUFFER_SIZE;
#endif
        device.active_dlt = -1;
        device.locked = FALSE;
        device.if_info.name = g_strdup(device.name);
        device.if_info.friendly_name = NULL;
        device.if_info.vendor_description = NULL;
        device.if_info.addrs = NULL;
        device.if_info.loopback = FALSE;
        device.if_info.type = IF_PIPE;
#ifdef HAVE_EXTCAP
        device.if_info.extcap = NULL;
        device.external_cap_args_settings = NULL;
#endif
#if defined(HAVE_PCAP_CREATE)
        device.monitor_mode_enabled = FALSE;
        device.monitor_mode_supported = FALSE;
#endif
        global_capture_opts.num_selected++;
        g_array_append_val(global_capture_opts.all_ifaces, device);
        ++it;
    }
}

void ManageInterfacesDialog::on_delPipe_clicked()
{
    // We're just managing a list of strings at this point.
    delete ui->pipeList->currentItem();
}

void ManageInterfacesDialog::on_pipeList_currentItemChanged(QTreeWidgetItem *, QTreeWidgetItem *)
{
    updateWidgets();
}

void ManageInterfacesDialog::showLocalInterfaces()
{
    guint i;
    interface_t device;
    gchar *pr_descr = g_strdup("");
    char *comment = NULL;

    ui->localList->clear();
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (device.local && device.type != IF_PIPE && device.type != IF_STDIN) {
            QTreeWidgetItem *item = new QTreeWidgetItem(ui->localList);
            item->setFlags(item->flags() | Qt::ItemIsEditable);
            if (prefs.capture_device && strstr(prefs.capture_device, device.name)) {
                // Force the default device to be checked.
                item->setFlags(item->flags() ^ Qt::ItemIsUserCheckable);
                item->setCheckState(col_l_show_, Qt::Checked);
            } else {
                item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
                item->setCheckState(col_l_show_, device.hidden ? Qt::Unchecked : Qt::Checked);
            }
#ifdef _WIN32
            item->setText(col_l_friendly_name_, device.friendly_name);
#endif
            item->setText(col_l_local_name_, device.name);

            comment = capture_dev_user_descr_find(device.name);
            if (comment) {
                item->setText(col_l_comment_, comment);
                g_free(comment);
            } else if (device.if_info.vendor_description) {
                item->setText(col_l_comment_, device.if_info.vendor_description);
            }
        } else {
            continue;
        }
    }
    g_free(pr_descr);
}

void ManageInterfacesDialog::saveLocalHideChanges(QTreeWidgetItem *item)
{
    guint i;
    interface_t device;

    if (!item) {
        return;
    }

    QString name = item->text(col_l_local_name_);
    /* See if this is the currently selected capturing device */

    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (name.compare(device.name)) {
            continue;
        }
        device.hidden = (item->checkState(col_l_show_) == Qt::Checked ? false : true);
        global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
        g_array_insert_val(global_capture_opts.all_ifaces, i, device);
    }
}

void ManageInterfacesDialog::saveLocalCommentChanges(QTreeWidgetItem* item)
{
    guint i;
    interface_t device;

    if (!item) {
        return;
    }

    QString name = item->text(col_l_local_name_);
    QString comment = item->text(col_l_comment_);
    /* See if this is the currently selected capturing device */

    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (name.compare(device.name)) {
            continue;
        }

        g_free(device.display_name);
        device.display_name = get_iface_display_name(comment.toUtf8().constData(), &device.if_info);
        global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
        g_array_insert_val(global_capture_opts.all_ifaces, i, device);
    }
}

#if 0 // Not needed?
void ManageInterfacesDialog::checkBoxChanged(QTreeWidgetItem* item)
{
    guint i;
    interface_t device;

    if (!item) {
        return;
    }

    QString name = item->text(col_l_local_name_);
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
#endif // checkBoxChanged not needed?

void ManageInterfacesDialog::localAccepted()
{

    if (global_capture_opts.all_ifaces->len > 0) {
        QStringList hide_list;
        QStringList comment_list;
        QTreeWidgetItemIterator it(ui->localList);
        while (*it) {
            if ((*it)->checkState(col_l_show_) != Qt::Checked) {
                hide_list << (*it)->text(col_l_local_name_);
            }

            if (!(*it)->text(col_l_local_name_).isEmpty()) {
                comment_list << QString("%1(%2)").arg((*it)->text(col_l_local_name_)).arg((*it)->text(col_l_comment_));
            }

            saveLocalHideChanges(*it);
            saveLocalCommentChanges(*it);
            ++it;
        }
        /* write new "hidden" string to preferences */
        g_free(prefs.capture_devices_hide);
        gchar *new_hide = qstring_strdup(hide_list.join(","));
        prefs.capture_devices_hide = new_hide;
        hide_interface(g_strdup(new_hide));

        /* write new description string to preferences */
        if (prefs.capture_devices_descr)
            g_free(prefs.capture_devices_descr);
        prefs.capture_devices_descr = qstring_strdup(comment_list.join(","));
    }
}

void ManageInterfacesDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_CAPTURE_MANAGE_INTERFACES_DIALOG);
}

void ManageInterfacesDialog::localListItemDoubleClicked(QTreeWidgetItem * item, int column)
{
    if (column == col_l_comment_) {
        ui->localList->editItem(item, column);
    }
}

#ifdef HAVE_PCAP_REMOTE
void ManageInterfacesDialog::remoteSelectionChanged(QTreeWidgetItem*, int)
{
    updateWidgets();
}

void ManageInterfacesDialog::addRemoteInterfaces(GList* rlist, remote_options *roptions)
{
    GList *if_entry, *lt_entry;
    if_info_t *if_info;
    char *if_string = NULL;
    gchar *descr, *str = NULL, *link_type_name = NULL, *auth_str;
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
        auth_str = NULL;
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
        ips = 0;
        memset(&device, 0, sizeof(device));
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
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
        if ((device.buffer = capture_dev_user_buffersize_find(if_string)) == -1) {
            device.buffer = global_capture_opts.default_options.buffer_size;
        }
#endif
        if (!capture_dev_user_pmode_find(if_string, &device.pmode)) {
            device.pmode = global_capture_opts.default_options.promisc_mode;
        }
        if (!capture_dev_user_snaplen_find(if_string, &device.has_snaplen,
                                           &device.snaplen)) {
            device.has_snaplen = global_capture_opts.default_options.has_snaplen;
            device.snaplen = global_capture_opts.default_options.snaplen;
        }
        device.cfilter = g_strdup(global_capture_opts.default_options.cfilter);
        monitor_mode = prefs_capture_device_monitor_mode(if_string);
#ifdef HAVE_PCAP_REMOTE
        if (roptions->remote_host_opts.auth_type == CAPTURE_AUTH_PWD) {
            auth_str = g_strdup_printf("%s:%s", roptions->remote_host_opts.auth_username,
                                       roptions->remote_host_opts.auth_password);
        }
#endif
        caps = capture_get_if_capabilities(if_string, monitor_mode, auth_str, NULL, main_window_update);
        g_free(auth_str);
        for (; (curr_addr = g_slist_nth(if_info->addrs, ips)) != NULL; ips++) {
            address addr_str;
            char* temp_addr_str = NULL;
            if (ips != 0) {
                g_string_append(ip_str, "\n");
            }
            addr = (if_addr_t *)curr_addr->data;
            switch (addr->ifat_type) {
            case IF_AT_IPv4:
                set_address(&addr_str, AT_IPv4, 4, &addr->addr.ip4_addr);
                temp_addr_str = (char*)address_to_str(NULL, &addr_str);
                g_string_append(ip_str, temp_addr_str);
                break;
            case IF_AT_IPv6:
                set_address(&addr_str, AT_IPv6, 16, addr->addr.ip6_addr);
                temp_addr_str = (char*)address_to_str(NULL, &addr_str);
                g_string_append(ip_str, temp_addr_str);
                break;
            default:
                /* In case we add non-IP addresses */
                break;
            }
            wmem_free(NULL, temp_addr_str);
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
                    str = g_strdup(data_link_info->description);
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

// We don't actually store these. When we do we should make sure they're stored
// securely using CryptProtectData, the OS X Keychain, GNOME Keyring, KWallet, etc.
void ManageInterfacesDialog::remoteAccepted()
{
    QTreeWidgetItemIterator it(ui->remoteList);

    while(*it) {
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if ((*it)->text(col_r_host_dev_).compare(device.name))
                continue;
            device.hidden = ((*it)->checkState(col_r_show_) == Qt::Checked ? false : true);
            global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
            g_array_insert_val(global_capture_opts.all_ifaces, i, device);
        }
        ++it;
    }
}

void ManageInterfacesDialog::on_remoteList_currentItemChanged(QTreeWidgetItem *, QTreeWidgetItem *)
{
    updateWidgets();
}

void ManageInterfacesDialog::on_remoteList_itemClicked(QTreeWidgetItem *item, int column)
{
    if (!item || column != col_r_show_) {
        return;
    }

    for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (!device.local) {
            if (item->text(col_r_host_dev_).compare(device.name))
                continue;
            device.hidden = (item->checkState(col_r_show_) == Qt::Checked ? false : true);
        }
    }
}

void ManageInterfacesDialog::on_delRemote_clicked()
{
    QTreeWidgetItem* item = ui->remoteList->currentItem();
    if (!item) {
        return;
    }

    for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (item->text(col_r_host_dev_).compare(device.remote_opts.remote_host_opts.remote_host))
            continue;
        global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
    }
    delete item;
    fflush(stdout); // ???
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
    QTreeWidgetItem *item = NULL;

    // We assume that remote interfaces are grouped by host.
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        QTreeWidgetItem *child;
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (!device.local) {
            if (!item || item->text(col_r_host_dev_).compare(device.remote_opts.remote_host_opts.remote_host) != 0) {
                item = new QTreeWidgetItem(ui->remoteList);
                item->setText(col_r_host_dev_, device.remote_opts.remote_host_opts.remote_host);
                item->setExpanded(true);
            }
            child = new QTreeWidgetItem(item);
            child->setCheckState(col_r_show_, device.hidden ? Qt::Unchecked : Qt::Checked);
            child->setText(col_r_host_dev_, QString(device.name));
        }
    }
}

void ManageInterfacesDialog::on_remoteSettings_clicked()
{
    guint i = 0;
    interface_t device;
    QTreeWidgetItem* item = ui->remoteList->currentItem();
    if (!item) {
        return;
    }

    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (!device.local) {
            if (item->text(col_r_host_dev_).compare(device.name)) {
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
#endif // HAVE_PCAP_REMOTE

PathChooserDelegate::PathChooserDelegate(QObject *parent)
    : QStyledItemDelegate(parent), tree_(NULL), path_item_(NULL), path_editor_(NULL), path_le_(NULL)
{
}

PathChooserDelegate::~PathChooserDelegate()
{
}

QWidget* PathChooserDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &) const
{
    QTreeWidgetItem *item = tree_->currentItem();
    if (!item) {
        return NULL;
    }
    path_item_ = item;

    path_editor_ = new QWidget(parent);
    QHBoxLayout *hbox = new QHBoxLayout(path_editor_);
    path_editor_->setLayout(hbox);
    path_le_ = new QLineEdit(path_editor_);
    QPushButton *pb = new QPushButton(path_editor_);

    path_le_->setText(item->text(col_p_pipe_));
    pb->setText(QString(tr("Browse" UTF8_HORIZONTAL_ELLIPSIS)));

    hbox->setContentsMargins(0, 0, 0, 0);
    hbox->addWidget(path_le_);
    hbox->addWidget(pb);
    hbox->setSizeConstraint(QLayout::SetMinimumSize);

    // Grow the item to match the editor. According to the QAbstractItemDelegate
    // documenation we're supposed to reimplement sizeHint but this seems to work.
    QSize size = option.rect.size();
    size.setHeight(qMax(option.rect.height(), hbox->sizeHint().height()));
    item->setData(col_p_pipe_, Qt::SizeHintRole, size);

    path_le_->selectAll();
    path_editor_->setFocusProxy(path_le_);
    path_editor_->setFocusPolicy(path_le_->focusPolicy());

    connect(path_le_, SIGNAL(destroyed()), this, SLOT(stopEditor()));
    connect(pb, SIGNAL(pressed()), this, SLOT(browse_button_clicked()));
    return path_editor_;
}

void PathChooserDelegate::updateEditorGeometry(QWidget *editor, const QStyleOptionViewItem &option, const QModelIndex &) const
{
    QRect rect = option.rect;

    // Make sure the editor doesn't get squashed.
    editor->adjustSize();
    rect.setHeight(qMax(option.rect.height(), editor->height()));
    editor->setGeometry(rect);
}

void PathChooserDelegate::stopEditor()
{
    path_item_->setData(col_p_pipe_, Qt::SizeHintRole, QVariant());
    path_item_->setText(col_p_pipe_, path_le_->text());
}

void PathChooserDelegate::browse_button_clicked()
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
    QString file_name = QFileDialog::getOpenFileName(tree_, tr("Open Pipe"), open_dir);
    if (!file_name.isEmpty()) {
        path_le_->setText(file_name);
    }
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
