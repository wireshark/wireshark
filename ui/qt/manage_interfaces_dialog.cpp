/* manage_interfaces_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include "manage_interfaces_dialog.h"
#include <ui_manage_interfaces_dialog.h>

#include "epan/prefs.h"
#include "epan/to_str.h"
#include "capture_opts.h"
#include "ui/capture_globals.h"
#include "ui/qt/capture_options_dialog.h"
#include <ui/qt/models/interface_tree_cache_model.h>
#include <ui/qt/models/interface_sort_filter_model.h>
#ifdef HAVE_PCAP_REMOTE
#include "ui/qt/remote_capture_dialog.h"
#include "ui/qt/remote_settings_dialog.h"
#include "caputils/capture-pcap-util.h"
#include "ui/recent.h"
#endif
#include "ui/iface_lists.h"
#include "ui/preference_utils.h"
#include "ui/ws_ui_util.h"
#include <wsutil/utf8_entities.h>

#include <ui/qt/utils/qt_ui_utils.h>

#include "wireshark_application.h"

#include <QDebug>

#include "ui/capture_ui_utils.h"

#include <ui/qt/models/path_chooser_delegate.h>

#include <QCheckBox>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QStandardItemModel>
#include <QTreeWidgetItemIterator>
#include <QMessageBox>

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
    col_r_show_,
    col_r_host_dev_
};

enum {
    tab_local_,
    tab_pipe_,
    tab_remote_
};

#ifdef HAVE_PCAP_REMOTE
static void populateExistingRemotes(gpointer key, gpointer value, gpointer user_data)
{
    ManageInterfacesDialog *dialog = (ManageInterfacesDialog*)user_data;
    const gchar *host = (const gchar *)key;
    struct remote_host *remote_host = (struct remote_host *)value;
    remote_options global_remote_opts;
    int err;
    gchar *err_str;

    global_remote_opts.src_type = CAPTURE_IFREMOTE;
    global_remote_opts.remote_host_opts.remote_host = g_strdup(host);
    global_remote_opts.remote_host_opts.remote_port = g_strdup(remote_host->remote_port);
    global_remote_opts.remote_host_opts.auth_type = remote_host->auth_type;
    global_remote_opts.remote_host_opts.auth_username = g_strdup(remote_host->auth_username);
    global_remote_opts.remote_host_opts.auth_password = g_strdup(remote_host->auth_password);
    global_remote_opts.remote_host_opts.datatx_udp  = FALSE;
    global_remote_opts.remote_host_opts.nocap_rpcap = TRUE;
    global_remote_opts.remote_host_opts.nocap_local = FALSE;
#ifdef HAVE_PCAP_SETSAMPLING
    global_remote_opts.sampling_method = CAPTURE_SAMP_NONE;
    global_remote_opts.sampling_param  = 0;
#endif
    GList *rlist = get_remote_interface_list(global_remote_opts.remote_host_opts.remote_host,
                                              global_remote_opts.remote_host_opts.remote_port,
                                              global_remote_opts.remote_host_opts.auth_type,
                                              global_remote_opts.remote_host_opts.auth_username,
                                              global_remote_opts.remote_host_opts.auth_password,
                                              &err, &err_str);
    if (rlist == NULL) {
        switch (err) {
        case 0:
            QMessageBox::warning(dialog, QObject::tr("Error"), QObject::tr("No remote interfaces found."));
            break;
        case CANT_GET_INTERFACE_LIST:
            QMessageBox::critical(dialog, QObject::tr("Error"), err_str);
            break;
        case DONT_HAVE_PCAP:
            QMessageBox::critical(dialog, QObject::tr("Error"), QObject::tr("PCAP not found"));
            break;
        default:
            QMessageBox::critical(dialog, QObject::tr("Error"), QObject::tr("Unknown error"));
            break;
        }
        return;
    }

    emit dialog->remoteAdded(rlist, &global_remote_opts);
}
#endif /* HAVE_PCAP_REMOTE */

ManageInterfacesDialog::ManageInterfacesDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::ManageInterfacesDialog)
{
    ui->setupUi(this);
    loadGeometry();
    setAttribute(Qt::WA_DeleteOnClose, true);

    ui->addPipe->setStockIcon("list-add");
    ui->delPipe->setStockIcon("list-remove");
    ui->addRemote->setStockIcon("list-add");
    ui->delRemote->setStockIcon("list-remove");

#ifdef Q_OS_MAC
    ui->addPipe->setAttribute(Qt::WA_MacSmallSize, true);
    ui->delPipe->setAttribute(Qt::WA_MacSmallSize, true);
    ui->addRemote->setAttribute(Qt::WA_MacSmallSize, true);
    ui->delRemote->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    sourceModel = new InterfaceTreeCacheModel(this);

    proxyModel = new InterfaceSortFilterModel(this);
    QList<InterfaceTreeColumns> columns;
    columns.append(IFTREE_COL_HIDDEN);
    columns.append(IFTREE_COL_DESCRIPTION);
    columns.append(IFTREE_COL_NAME);
    columns.append(IFTREE_COL_COMMENT);
    proxyModel->setColumns(columns);
    proxyModel->setSourceModel(sourceModel);
    proxyModel->setFilterHidden(false);
    proxyModel->setFilterByType(false);

    ui->localView->setModel(proxyModel);
    ui->localView->resizeColumnToContents(proxyModel->mapSourceToColumn(IFTREE_COL_HIDDEN));
    ui->localView->resizeColumnToContents(proxyModel->mapSourceToColumn(IFTREE_COL_NAME));

    pipeProxyModel = new InterfaceSortFilterModel(this);
    columns.clear();
    columns.append(IFTREE_COL_PIPE_PATH);
    pipeProxyModel->setColumns(columns);
    pipeProxyModel->setSourceModel(sourceModel);
    pipeProxyModel->setFilterHidden(true);
    pipeProxyModel->setFilterByType(true, true);
    pipeProxyModel->setInterfaceTypeVisible(IF_PIPE, false);
    ui->pipeView->setModel(pipeProxyModel);
    ui->delPipe->setEnabled(pipeProxyModel->rowCount() > 0);

    ui->pipeView->setItemDelegateForColumn(
            pipeProxyModel->mapSourceToColumn(IFTREE_COL_PIPE_PATH), new PathChooserDelegate()
            );
    connect(ui->pipeView->selectionModel(),
            SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)), this,
            SLOT(onSelectionChanged(const QItemSelection &, const QItemSelection &)));

#if defined(HAVE_PCAP_REMOTE)
    // The default indentation (20) means our checkboxes are shifted too far on Windows.
    // Assume that our disclosure and checkbox controls are square, or at least fit within an em.
    int one_em = fontMetrics().height();
    ui->remoteList->setIndentation(one_em);
    ui->remoteList->setColumnWidth(col_r_show_, one_em * 4);
    ui->remoteSettings->setEnabled(false);
    showRemoteInterfaces();
#else
    ui->tabWidget->removeTab(tab_remote_);
#endif

    connect(ui->tabWidget, SIGNAL(currentChanged(int)), this, SLOT(updateWidgets()));
    connect(this, SIGNAL(ifsChanged()), parent, SIGNAL(ifsChanged()));

#ifdef HAVE_PCAP_REMOTE
    connect(this, SIGNAL(remoteAdded(GList*, remote_options*)), this, SLOT(addRemoteInterfaces(GList*, remote_options*)));
    connect(this, SIGNAL(remoteSettingsChanged(interface_t *)), this, SLOT(setRemoteSettings(interface_t *)));
    connect(ui->remoteList, SIGNAL(itemClicked(QTreeWidgetItem*, int)), this, SLOT(remoteSelectionChanged(QTreeWidgetItem*, int)));
    recent_remote_host_list_foreach(populateExistingRemotes, this);
#endif

    ui->tabWidget->setCurrentIndex(tab_local_);
    updateWidgets();
}

ManageInterfacesDialog::~ManageInterfacesDialog()
{
    delete ui;
}

void ManageInterfacesDialog::onSelectionChanged(const QItemSelection &sel, const QItemSelection &)
{
    ui->delPipe->setEnabled(sel.count() > 0);
}

void ManageInterfacesDialog::updateWidgets()
{
    QString hint;

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

void ManageInterfacesDialog::on_buttonBox_accepted()
{
#ifdef HAVE_LIBPCAP
    sourceModel->save();
#endif
#ifdef HAVE_PCAP_REMOTE
    remoteAccepted();
#endif
    prefs_main_write();
    wsApp->refreshLocalInterfaces();
    emit ifsChanged();
}

#ifdef HAVE_LIBPCAP
void ManageInterfacesDialog::on_addPipe_clicked()
{
    interface_t device;

    memset(&device, 0, sizeof(device));
    device.name = qstring_strdup(tr("New Pipe"));
    device.display_name = g_strdup(device.name);
    device.hidden       = FALSE;
    device.selected     = TRUE;
    device.pmode        = global_capture_opts.default_options.promisc_mode;
    device.has_snaplen  = global_capture_opts.default_options.has_snaplen;
    device.snaplen      = global_capture_opts.default_options.snaplen;
    device.cfilter      = g_strdup(global_capture_opts.default_options.cfilter);
    device.timestamp_type = g_strdup(global_capture_opts.default_options.timestamp_type);
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
    device.buffer       = DEFAULT_CAPTURE_BUFFER_SIZE;
#endif
    device.active_dlt = -1;
    device.if_info.name = g_strdup(device.name);
    device.if_info.type = IF_PIPE;

    sourceModel->addDevice(&device);

    updateWidgets();
}

void ManageInterfacesDialog::on_delPipe_clicked()
{
    /* Get correct selection and tell the source model to delete the itm. pipe view only
     * displays IF_PIPE devices, therefore this will only delete pipes, and this is set
     * to only select single items. */
    QModelIndex selIndex = ui->pipeView->selectionModel()->selectedIndexes().at(0);

    sourceModel->deleteDevice(pipeProxyModel->mapToSource(selIndex));
    updateWidgets();
}
#endif

void ManageInterfacesDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_CAPTURE_MANAGE_INTERFACES_DIALOG);
}

#ifdef HAVE_PCAP_REMOTE
void ManageInterfacesDialog::remoteSelectionChanged(QTreeWidgetItem*, int)
{
    updateWidgets();
}

void ManageInterfacesDialog::updateRemoteInterfaceList(GList* rlist, remote_options* roptions)
{
    GList *if_entry, *lt_entry;
    if_info_t *if_info;
    char *if_string = NULL;
    gchar *descr, *auth_str;
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
    guint num_interfaces;

    num_interfaces = global_capture_opts.all_ifaces->len;
    for (if_entry = g_list_first(rlist); if_entry != NULL; if_entry = gxx_list_next(if_entry)) {
        auth_str = NULL;
        if_info = gxx_list_data(if_info_t *, if_entry);
#if 0
        add_interface_to_remote_list(if_info);
#endif
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
        device.if_info.name = g_strdup("Don't crash on bug 13448");
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
        device.timestamp_type = g_strdup(global_capture_opts.default_options.timestamp_type);
        monitor_mode = prefs_capture_device_monitor_mode(if_string);
        if (roptions->remote_host_opts.auth_type == CAPTURE_AUTH_PWD) {
            auth_str = g_strdup_printf("%s:%s", roptions->remote_host_opts.auth_username,
                                       roptions->remote_host_opts.auth_password);
        }
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
            for (lt_entry = caps->data_link_types; lt_entry != NULL; lt_entry = gxx_list_next(lt_entry)) {
                data_link_info = gxx_list_data(data_link_info_t *, lt_entry);
                linkr = new link_row;
                /*
                 * For link-layer types libpcap/WinPcap/Npcap doesn't know
                 * about, the name will be "DLT n", and the description will
                 * be null.
                 * We mark those as unsupported, and don't allow them to be
                 * used.
                 */
                if (data_link_info->description != NULL) {
                    linkr->name = g_strdup(data_link_info->description);
                    linkr->dlt = data_link_info->dlt;
                } else {
                    linkr->name = g_strdup_printf("%s (not supported)", data_link_info->name);
                    linkr->dlt = -1;
                }
                if (linktype_count == 0) {
                    device.active_dlt = data_link_info->dlt;
                }
                device.links = g_list_append(device.links, linkr);
                linktype_count++;
            } /* for link_types */
        } else {
#if defined(HAVE_PCAP_CREATE)
            device.monitor_mode_enabled = FALSE;
            device.monitor_mode_supported = FALSE;
#endif
            device.active_dlt = -1;
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
}

void ManageInterfacesDialog::addRemoteInterfaces(GList* rlist, remote_options *roptions)
{
    updateRemoteInterfaceList(rlist, roptions);
    showRemoteInterfaces();
}

// We don't actually store these. When we do we should make sure they're stored
// securely using CryptProtectData, the macOS Keychain, GNOME Keyring, KWallet, etc.
void ManageInterfacesDialog::remoteAccepted()
{
    QTreeWidgetItemIterator it(ui->remoteList);

    while (*it) {
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if ((*it)->text(col_r_host_dev_).compare(device->name))
                continue;
            device->hidden = ((*it)->checkState(col_r_show_) == Qt::Checked ? false : true);
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
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (!device->local) {
            if (item->text(col_r_host_dev_).compare(device->name))
                continue;
            device->hidden = (item->checkState(col_r_show_) == Qt::Checked ? false : true);
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
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (item->text(col_r_host_dev_).compare(device->remote_opts.remote_host_opts.remote_host))
            continue;
        capture_opts_free_interface_t(device);
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
    interface_t *device;
    QTreeWidgetItem *item = NULL;

    // We assume that remote interfaces are grouped by host.
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        QTreeWidgetItem *child;
        device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (!device->local) {
            if (!item || item->text(col_r_host_dev_).compare(device->remote_opts.remote_host_opts.remote_host) != 0) {
                item = new QTreeWidgetItem(ui->remoteList);
                item->setText(col_r_host_dev_, device->remote_opts.remote_host_opts.remote_host);
                item->setExpanded(true);
            }
            child = new QTreeWidgetItem(item);
            child->setCheckState(col_r_show_, device->hidden ? Qt::Unchecked : Qt::Checked);
            child->setText(col_r_host_dev_, QString(device->name));
        }
    }
}

void ManageInterfacesDialog::on_remoteSettings_clicked()
{
    guint i = 0;
    interface_t *device;
    QTreeWidgetItem* item = ui->remoteList->currentItem();
    if (!item) {
        return;
    }

    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (!device->local) {
            if (item->text(col_r_host_dev_).compare(device->name)) {
               continue;
            } else {
                RemoteSettingsDialog *dlg = new RemoteSettingsDialog(this, device);
                dlg->show();
                break;
            }
        }
    }
}

void ManageInterfacesDialog::setRemoteSettings(interface_t *iface)
{
    for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (!device->local) {
            if (strcmp(iface->name, device->name)) {
                continue;
            }
            device->remote_opts.remote_host_opts.nocap_rpcap = iface->remote_opts.remote_host_opts.nocap_rpcap;
            device->remote_opts.remote_host_opts.datatx_udp = iface->remote_opts.remote_host_opts.datatx_udp;
#ifdef HAVE_PCAP_SETSAMPLING
            device->remote_opts.sampling_method = iface->remote_opts.sampling_method;
            device->remote_opts.sampling_param = iface->remote_opts.sampling_param;
#endif //HAVE_PCAP_SETSAMPLING
        }
    }
}
#endif // HAVE_PCAP_REMOTE

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
