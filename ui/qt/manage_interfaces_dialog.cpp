/* manage_interfaces_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <wireshark.h>
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
#include "capture/capture-pcap-util.h"
#include "ui/recent.h"
#include "wsutil/filesystem.h"
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#endif
#include "ui/iface_lists.h"
#include "ui/preference_utils.h"
#include "ui/ws_ui_util.h"
#include <wsutil/utf8_entities.h>

#include <ui/qt/utils/qt_ui_utils.h>

#include "main_application.h"

#include <QDebug>

#include "ui/capture_ui_utils.h"

#include <ui/qt/models/path_selection_delegate.h>

#include <QCheckBox>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QStandardItemModel>
#include <QTreeWidgetItemIterator>
#include <QMessageBox>

// To do:
// - Check the validity of pipes and remote interfaces and provide feedback
//   via hintLabel.
// - We might want to move PathSelectionDelegate to its own module and use it in
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
#define REMOTE_HOSTS_FILE "remote_hosts.json"

void ManageInterfacesDialog::addRemote(const QVariantMap&& remoteHostMap)
{
    remote_options global_remote_opts;
    int err;
    char* err_str;

    global_remote_opts.src_type = CAPTURE_IFREMOTE;
    global_remote_opts.remote_host_opts.remote_host = qstring_strdup(remoteHostMap["host"].toString());
    global_remote_opts.remote_host_opts.remote_port = qstring_strdup(remoteHostMap["port"].toString());
    global_remote_opts.remote_host_opts.auth_type = static_cast<capture_auth>(remoteHostMap["auth"].toInt());
    global_remote_opts.remote_host_opts.auth_username = qstring_strdup(remoteHostMap["username"].toString());
    global_remote_opts.remote_host_opts.auth_password = qstring_strdup(remoteHostMap["password"].toString());
    global_remote_opts.remote_host_opts.datatx_udp = false;
    global_remote_opts.remote_host_opts.nocap_rpcap = true;
    global_remote_opts.remote_host_opts.nocap_local = false;
#ifdef HAVE_PCAP_SETSAMPLING
    global_remote_opts.sampling_method = CAPTURE_SAMP_NONE;
    global_remote_opts.sampling_param = 0;
#endif

    // This doesn't handle CAPTURE_AUTH_PWD because we don't store the password
    // XXX: Don't these strings get leaked? I think that they're dup'ed again
    // later. Same for in RemoteCaptureDialog::apply_remote()

    GList* rlist = get_remote_interface_list(global_remote_opts.remote_host_opts.remote_host,
        global_remote_opts.remote_host_opts.remote_port,
        global_remote_opts.remote_host_opts.auth_type,
        global_remote_opts.remote_host_opts.auth_username,
        global_remote_opts.remote_host_opts.auth_password,
        &err, &err_str);

    if (rlist == NULL) {
        switch (err) {
        case 0:
            QMessageBox::warning(this, QObject::tr("Error"), QObject::tr("No remote interfaces found."));
            break;
        case CANT_GET_INTERFACE_LIST:
            QMessageBox::critical(this, QObject::tr("Error"), err_str);
            break;
        case DONT_HAVE_PCAP:
            QMessageBox::critical(this, QObject::tr("Error"), QObject::tr("PCAP not found"));
            break;
        default:
            QMessageBox::critical(this, QObject::tr("Error"), QObject::tr("Unknown error"));
            break;
        }
        return;
    }
    // XXX: If the connection fails we won't add it, so it won't get saved to
    // load automatically next time (but will perhaps still be in recent.)
    // That's mostly a feature not a bug, but we might want support for
    // currently disabled remote hosts.

    emit remoteAdded(rlist, &global_remote_opts);
}

void ManageInterfacesDialog::populateExistingRemotes()
{
    const char* cfile = REMOTE_HOSTS_FILE;

    /* Try personal config file first */
    QString fileName = gchar_free_to_qstring(get_persconffile_path(cfile, true));

    if (fileName.isEmpty() || !QFileInfo::exists(fileName)) {
        return;
    }

    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }

    QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    if (!document.isArray()) {
        return;
    }

    foreach(QJsonValue value, document.array()) {
        addRemote(value.toObject().toVariantMap());
    }

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
#ifdef HAVE_PCAP_REMOTE
    proxyModel->setRemoteDisplay(false);
#endif
    proxyModel->setFilterByType(false);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);

    ui->localView->setModel(proxyModel);
    ui->localView->resizeColumnToContents(proxyModel->mapSourceToColumn(IFTREE_COL_HIDDEN));
    ui->localView->resizeColumnToContents(proxyModel->mapSourceToColumn(IFTREE_COL_NAME));
    ui->localView->header()->setSortIndicator(-1, Qt::AscendingOrder);
    ui->localView->setSortingEnabled(true);

    pipeProxyModel = new InterfaceSortFilterModel(this);
    columns.clear();
    columns.append(IFTREE_COL_PIPE_PATH);
    pipeProxyModel->setColumns(columns);
    pipeProxyModel->setSourceModel(sourceModel);
    pipeProxyModel->setFilterHidden(true);
#ifdef HAVE_PCAP_REMOTE
    pipeProxyModel->setRemoteDisplay(false);
#endif
    pipeProxyModel->setFilterByType(true, true);
    pipeProxyModel->setInterfaceTypeVisible(IF_PIPE, false);
    ui->pipeView->setModel(pipeProxyModel);
    ui->delPipe->setEnabled(pipeProxyModel->rowCount() > 0);

    ui->pipeView->setItemDelegateForColumn(pipeProxyModel->mapSourceToColumn(IFTREE_COL_PIPE_PATH), new PathSelectionDelegate(this));
     connect(ui->pipeView->selectionModel(), &QItemSelectionModel::selectionChanged, this, [=](const QItemSelection &sel, const QItemSelection &) {
        ui->delPipe->setEnabled(sel.count() > 0);
    });

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
    populateExistingRemotes();
#endif

    ui->tabWidget->setCurrentIndex(tab_local_);
    updateWidgets();
}

ManageInterfacesDialog::~ManageInterfacesDialog()
{
    if (result() == QDialog::Accepted) {
#ifdef HAVE_LIBPCAP
        sourceModel->save();
#endif
#ifdef HAVE_PCAP_REMOTE
        remoteAccepted();
#endif
        prefs_main_write();
        mainApp->refreshLocalInterfaces();
        emit ifsChanged();
    }

    delete ui;
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

#ifdef HAVE_LIBPCAP
void ManageInterfacesDialog::on_addPipe_clicked()
{
    interface_t device;

    memset(&device, 0, sizeof(device));
    device.name = qstring_strdup(tr("New Pipe"));
    device.display_name = g_strdup(device.name);
    device.hidden       = false;
    device.selected     = true;
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
    mainApp->helpTopicAction(HELP_CAPTURE_MANAGE_INTERFACES_DIALOG);
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
    char *descr, *auth_str;
    if_capabilities_t *caps;
    int linktype_count;
    bool monitor_mode, found = false;
    GSList *curr_addr;
    int ips = 0;
    unsigned i;
    if_addr_t *addr;
    data_link_info_t *data_link_info;
    GString *ip_str;
    link_row *linkr = NULL;
    interface_t device;
    unsigned num_interfaces;

    // Add any (remote) interface in rlist to the global list of all
    // interfaces.
    // Most of this is copied from scan_local_interfaces_filtered, but
    // some of it doesn't make sense for remote interfaces (yet?) - we
    // can't, for example, control monitor mode.
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
                found = true;
                break;
            }
        }
        if (found) {
            found = false;
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
            if_string = ws_strdup_printf("%s: %s", descr, if_info->name);
            g_free(descr);
        } else {
            /* No, we don't have a user-supplied description; did we get
               one from the OS or libpcap? */
            if (if_info->vendor_description != NULL) {
                /* Yes - use it. */
                if_string = ws_strdup_printf("%s: %s", if_info->vendor_description, if_info->name);
            } else {
                /* No. */
                if_string = g_strdup(if_info->name);
            }
        } /* else descr != NULL */
        if (if_info->loopback) {
            device.display_name = ws_strdup_printf("%s (loopback)", if_string);
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
            auth_str = ws_strdup_printf("%s:%s", roptions->remote_host_opts.auth_username,
                                       roptions->remote_host_opts.auth_password);
        }
        caps = capture_get_if_capabilities(if_string, monitor_mode, auth_str, NULL, NULL, main_window_update);
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
            GList *lt_list = caps->data_link_types;
#ifdef HAVE_PCAP_CREATE
            device.monitor_mode_enabled = monitor_mode && caps->can_set_rfmon;
            device.monitor_mode_supported = caps->can_set_rfmon;
            if (device.monitor_mode_enabled) {
                lt_list = caps->data_link_types_rfmon;
            }
#endif
            for (lt_entry = lt_list; lt_entry != NULL; lt_entry = gxx_list_next(lt_entry)) {
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
                    linkr->name = ws_strdup_printf("%s (not supported)", data_link_info->name);
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
            device.monitor_mode_enabled = false;
            device.monitor_mode_supported = false;
#endif
            device.active_dlt = -1;
        }
        device.addresses = g_strdup(ip_str->str);
        device.no_addresses = ips;
        device.remote_opts.src_type= roptions->src_type;
        if (device.remote_opts.src_type == CAPTURE_IFREMOTE) {
            device.local = false;
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
        device.selected = true;
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
    QJsonArray hostArray;

    while (*it) {
        if ((*it)->parent() == nullptr) {
            QVariant v = (*it)->data(0, Qt::UserRole);
            if (v.canConvert<QJsonObject>()) {
                hostArray.append(v.toJsonValue());
            }
        }

        for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if ((*it)->text(col_r_host_dev_).compare(device->name))
                continue;
            device->hidden = ((*it)->checkState(col_r_show_) == Qt::Checked ? false : true);
        }
        ++it;
    }

    const char* cfile = REMOTE_HOSTS_FILE;
    /* Try personal config file first */
    QString fileName = gchar_free_to_qstring(get_persconffile_path(cfile, true));

    if (fileName.isEmpty()) {
        return;
    }

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly)) {
        return;
    }

    file.write(QJsonDocument(hostArray).toJson(QJsonDocument::Compact));
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

    for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
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

    for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
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
    unsigned i;
    interface_t *device;
    QTreeWidgetItem * item = nullptr;

    // We assume that remote interfaces are grouped by host.
    for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        QTreeWidgetItem * child = nullptr;
        device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (!device->local) {

            // check if the QTreeWidgetItem for that interface already exists
            QList<QTreeWidgetItem*> items = ui->remoteList->findItems(QString(device->name), Qt::MatchCaseSensitive | Qt::MatchFixedString, col_r_host_dev_);
            if (items.count() > 0)
               continue;

            // create or find the QTreeWidgetItem for the remote host configuration
            QString parentName = QString(device->remote_opts.remote_host_opts.remote_host);
            items = ui->remoteList->findItems(parentName, Qt::MatchCaseSensitive | Qt::MatchFixedString, col_r_host_dev_);
            if (items.count() == 0) {
                item = new QTreeWidgetItem(ui->remoteList);
                item->setText(col_r_host_dev_, parentName);
                QJsonObject remote_host{
                    {"host", parentName},
                    {"port", device->remote_opts.remote_host_opts.remote_port},
                    {"auth_type", device->remote_opts.remote_host_opts.auth_type},
                    {"username", device->remote_opts.remote_host_opts.auth_username},
                    // {"password", device->remote_opts.remote_host_opts.auth_password},
                    // We should find some way to store the password in a
                    // credential manager (cf. #17949 for extcap) and
                    // reference it
                    };
                item->setData(0, Qt::UserRole, remote_host);
                item->setExpanded(true);
            }
            else {
                item = items.at(0);
            }

            items = ui->remoteList->findItems(QString(device->name), Qt::MatchCaseSensitive | Qt::MatchFixedString | Qt::MatchRecursive, col_r_host_dev_);
            if (items.count() == 0)
            {
                child = new QTreeWidgetItem(item);
                child->setCheckState(col_r_show_, device->hidden ? Qt::Unchecked : Qt::Checked);
                child->setText(col_r_host_dev_, QString(device->name));
            }
        }
    }
}

void ManageInterfacesDialog::on_remoteSettings_clicked()
{
    unsigned i = 0;
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
    for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
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
