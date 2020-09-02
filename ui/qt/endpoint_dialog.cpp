/* endpoint_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "endpoint_dialog.h"

#include <epan/maxmind_db.h>

#include <epan/prefs.h>

#include "ui/recent.h"
#include "ui/traffic_table_ui.h"

#include "wsutil/file_util.h"
#include "wsutil/pint.h"
#include "wsutil/str_util.h"
#include <wsutil/utf8_entities.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>
#include "wireshark_application.h"

#include <QCheckBox>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QMessageBox>
#include <QPushButton>
#include <QUrl>
#include <QTemporaryFile>

static const QString table_name_ = QObject::tr("Endpoint");
EndpointDialog::EndpointDialog(QWidget &parent, CaptureFile &cf, int cli_proto_id, const char *filter) :
    TrafficTableDialog(parent, cf, filter, table_name_)
{
#ifdef HAVE_MAXMINDDB
    map_bt_ = buttonBox()->addButton(tr("Map"), QDialogButtonBox::ActionRole);
    map_bt_->setToolTip(tr("Draw IPv4 or IPv6 endpoints on a map."));
    connect(trafficTableTabWidget(), &QTabWidget::currentChanged, this, &EndpointDialog::tabChanged);

    QMenu *map_menu_ = new QMenu(map_bt_);
    QAction *action;
    action = map_menu_->addAction(tr("Open in browser"));
    connect(action, &QAction::triggered, this, &EndpointDialog::openMap);
    action = map_menu_->addAction(tr("Save As" UTF8_HORIZONTAL_ELLIPSIS));
    connect(action, &QAction::triggered, this, &EndpointDialog::saveMap);
    map_bt_->setMenu(map_menu_);
#endif
    addProgressFrame(&parent);

    QList<int> endp_protos;
    for (GList *endp_tab = recent.endpoint_tabs; endp_tab; endp_tab = endp_tab->next) {
        int proto_id = proto_get_id_by_short_name((const char *)endp_tab->data);
        if (proto_id > -1 && !endp_protos.contains(proto_id)) {
            endp_protos.append(proto_id);
        }
    }

    if (endp_protos.isEmpty()) {
        endp_protos = defaultProtos();
    }

    // Bring the command-line specified type to the front.
    if ((cli_proto_id > 0) && (get_conversation_by_proto_id(cli_proto_id))) {
        endp_protos.removeAll(cli_proto_id);
        endp_protos.prepend(cli_proto_id);
    }

    // QTabWidget selects the first item by default.
    foreach (int endp_proto, endp_protos) {
        addTrafficTable(get_conversation_by_proto_id(endp_proto));
    }

    fillTypeMenu(endp_protos);

    QPushButton *close_bt = buttonBox()->button(QDialogButtonBox::Close);
    if (close_bt) {
        close_bt->setDefault(true);
    }

    updateWidgets();
//    currentTabChanged();

    cap_file_.delayedRetapPackets();
}

EndpointDialog::~EndpointDialog()
{
    prefs_clear_string_list(recent.endpoint_tabs);
    recent.endpoint_tabs = NULL;

    EndpointTreeWidget *cur_tree = qobject_cast<EndpointTreeWidget *>(trafficTableTabWidget()->currentWidget());
    foreach (QAction *ea, traffic_type_menu_.actions()) {
        int proto_id = ea->data().value<int>();
        if (proto_id_to_tree_.contains(proto_id) && ea->isChecked()) {
            char *title = g_strdup(proto_get_protocol_short_name(find_protocol_by_id(proto_id)));
            if (proto_id_to_tree_[proto_id] == cur_tree) {
                recent.endpoint_tabs = g_list_prepend(recent.endpoint_tabs, title);
            } else {
                recent.endpoint_tabs = g_list_append(recent.endpoint_tabs, title);
            }
        }
    }
}

void EndpointDialog::captureFileClosing()
{
    // Keep the dialog around but disable any controls that depend
    // on a live capture file.
    for (int i = 0; i < trafficTableTabWidget()->count(); i++) {
        EndpointTreeWidget *cur_tree = qobject_cast<EndpointTreeWidget *>(trafficTableTabWidget()->widget(i));
        disconnect(cur_tree, SIGNAL(filterAction(QString,FilterAction::Action,FilterAction::ActionType)),
                   this, SIGNAL(filterAction(QString,FilterAction::Action,FilterAction::ActionType)));
    }
    displayFilterCheckBox()->setEnabled(false);
    enabledTypesPushButton()->setEnabled(false);
    TrafficTableDialog::captureFileClosing();
}

bool EndpointDialog::addTrafficTable(register_ct_t *table)
{
    int proto_id = get_conversation_proto_id(table);

    if (!table || proto_id_to_tree_.contains(proto_id)) {
        return false;
    }

    EndpointTreeWidget *endp_tree = new EndpointTreeWidget(this, table);

    proto_id_to_tree_[proto_id] = endp_tree;
    const char* table_name = proto_get_protocol_short_name(find_protocol_by_id(proto_id));

    trafficTableTabWidget()->addTab(endp_tree, table_name);

    connect(endp_tree, SIGNAL(titleChanged(QWidget*,QString)),
            this, SLOT(setTabText(QWidget*,QString)));
    connect(endp_tree, SIGNAL(filterAction(QString,FilterAction::Action,FilterAction::ActionType)),
            this, SIGNAL(filterAction(QString,FilterAction::Action,FilterAction::ActionType)));
    connect(nameResolutionCheckBox(), SIGNAL(toggled(bool)),
            endp_tree, SLOT(setNameResolutionEnabled(bool)));
#ifdef HAVE_MAXMINDDB
    connect(endp_tree, &EndpointTreeWidget::geoIPStatusChanged,
            this, &EndpointDialog::tabChanged);
#endif

    // XXX Move to ConversationTreeWidget ctor?
    QByteArray filter_utf8;
    const char *filter = NULL;
    if (displayFilterCheckBox()->isChecked()) {
        filter = cap_file_.capFile()->dfilter;
    } else if (!filter_.isEmpty()) {
        filter_utf8 = filter_.toUtf8();
        filter = filter_utf8.constData();
    }

    endp_tree->trafficTreeHash()->user_data = endp_tree;

    registerTapListener(proto_get_protocol_filter_name(proto_id), endp_tree->trafficTreeHash(), filter, 0,
                        EndpointTreeWidget::tapReset,
                        get_hostlist_packet_func(table),
                        EndpointTreeWidget::tapDraw);
    return true;
}

#ifdef HAVE_MAXMINDDB
void EndpointDialog::tabChanged()
{
    EndpointTreeWidget *cur_tree = qobject_cast<EndpointTreeWidget *>(trafficTableTabWidget()->currentWidget());
    map_bt_->setEnabled(cur_tree && cur_tree->hasGeoIPData());
}

QUrl EndpointDialog::createMap(bool json_only)
{
    EndpointTreeWidget *cur_tree = qobject_cast<EndpointTreeWidget *>(trafficTableTabWidget()->currentWidget());
    if (!cur_tree) {
        return QUrl();
    }

    // Construct list of hosts with a valid MMDB entry.
    QTreeWidgetItemIterator it(cur_tree);
    GPtrArray *hosts_arr = g_ptr_array_new();
    while (*it) {
        const mmdb_lookup_t *geo = VariantPointer<const mmdb_lookup_t>::asPtr((*it)->data(0, Qt::UserRole + 1));
        if (maxmind_db_has_coords(geo)) {
            hostlist_talker_t *host = VariantPointer<hostlist_talker_t>::asPtr((*it)->data(0, Qt::UserRole));
            g_ptr_array_add(hosts_arr, (gpointer)host);
        }
        ++it;
    }
    if (hosts_arr->len == 0) {
        QMessageBox::warning(this, tr("Map file error"), tr("No endpoints available to map"));
        g_ptr_array_free(hosts_arr, TRUE);
        return QUrl();
    }
    g_ptr_array_add(hosts_arr, NULL);
    hostlist_talker_t **hosts = (hostlist_talker_t **)g_ptr_array_free(hosts_arr, FALSE);

    QTemporaryFile tf("ipmapXXXXXX.html");
    if (!tf.open()) {
        QMessageBox::warning(this, tr("Map file error"), tr("Unable to create temporary file"));
        g_free(hosts);
        return QUrl();
    }

    //
    // XXX - At least with Qt 5.12 retrieving the name only works when
    // it has been retrieved at least once when the file is open.
    //
    QString tempfilename = tf.fileName();
    int fd = tf.handle();
    //
    // XXX - QFileDevice.handle() can return -1, but can QTemporaryFile.handle()
    // do so if QTemporaryFile.open() has succeeded?
    //
    if (fd == -1) {
        QMessageBox::warning(this, tr("Map file error"), tr("Unable to create temporary file"));
        g_free(hosts);
        return QUrl();
    }
    FILE* fp = ws_fdopen(fd, "wb");
    if (fp == NULL) {
        QMessageBox::warning(this, tr("Map file error"), tr("Unable to create temporary file"));
        g_free(hosts);
        return QUrl();
    }

    gchar *err_str;
    if (!write_endpoint_geoip_map(fp, json_only, hosts, &err_str)) {
        QMessageBox::warning(this, tr("Map file error"), err_str);
        g_free(err_str);
        g_free(hosts);
        fclose(fp);
        return QUrl();
    }
    g_free(hosts);
    if (fclose(fp) == EOF) {
        QMessageBox::warning(this, tr("Map file error"), g_strerror(errno));
        return QUrl();
    }

    tf.setAutoRemove(false);
    return QUrl::fromLocalFile(tf.fileName());
}

void EndpointDialog::openMap()
{
    QUrl map_file = createMap(false);
    if (!map_file.isEmpty()) {
        QDesktopServices::openUrl(map_file);
    }
}

void EndpointDialog::saveMap()
{
    QString destination_file =
        WiresharkFileDialog::getSaveFileName(this, tr("Save Endpoints Map"),
                "ipmap.html",
                "HTML files (*.html);;GeoJSON files (*.json)");
    if (destination_file.isEmpty()) {
        return;
    }
    QUrl map_file = createMap(destination_file.endsWith(".json"));
    if (!map_file.isEmpty()) {
        QString source_file = map_file.toLocalFile();
        QFile::remove(destination_file);
        if (!QFile::rename(source_file, destination_file)) {
            QMessageBox::warning(this, tr("Map file error"),
                    tr("Failed to save map file %1.").arg(destination_file));
            QFile::remove(source_file);
        }
    }
}
#endif

void EndpointDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_STATS_ENDPOINTS_DIALOG);
}

void init_endpoint_table(struct register_ct* ct, const char *filter)
{
    wsApp->emitStatCommandSignal("Endpoints", filter, GINT_TO_POINTER(get_conversation_proto_id(ct)));
}

// EndpointTreeWidgetItem
// TrafficTableTreeWidgetItem / QTreeWidgetItem subclass that allows sorting

static const char *data_none_ = UTF8_EM_DASH;

class EndpointTreeWidgetItem : public TrafficTableTreeWidgetItem
{
public:
    EndpointTreeWidgetItem(GArray *conv_array, guint conv_idx, bool *resolve_names_ptr) :
        TrafficTableTreeWidgetItem(NULL),
        conv_array_(conv_array),
        conv_idx_(conv_idx),
        resolve_names_ptr_(resolve_names_ptr)
    {}

    hostlist_talker_t *hostlistTalker() {
        return &g_array_index(conv_array_, hostlist_talker_t, conv_idx_);
    }

    virtual QVariant data(int column, int role) const {
        if (role == Qt::DisplayRole) {
            // Column text cooked representation.
            hostlist_talker_t *endp_item = &g_array_index(conv_array_, hostlist_talker_t, conv_idx_);

            bool resolve_names = false;
            if (resolve_names_ptr_ && *resolve_names_ptr_) resolve_names = true;
            switch (column) {
            case ENDP_COLUMN_PACKETS:
                return QString("%L1").arg(endp_item->tx_frames + endp_item->rx_frames);
            case ENDP_COLUMN_BYTES:
                return gchar_free_to_qstring(format_size(endp_item->tx_bytes + endp_item->rx_bytes, format_size_unit_none|format_size_prefix_si));
            case ENDP_COLUMN_PKT_AB:
                return QString("%L1").arg(endp_item->tx_frames);
            case ENDP_COLUMN_BYTES_AB:
                return gchar_free_to_qstring(format_size(endp_item->tx_bytes, format_size_unit_none|format_size_prefix_si));
            case ENDP_COLUMN_PKT_BA:
                return QString("%L1").arg(endp_item->rx_frames);
            case ENDP_COLUMN_BYTES_BA:
                return gchar_free_to_qstring(format_size(endp_item->rx_bytes, format_size_unit_none|format_size_prefix_si));
            default:
                QVariant col_data = colData(column, resolve_names);
                if (col_data.isValid()) return col_data;
                return QVariant(data_none_);
            }
        }
        if (role == Qt::UserRole) {
            hostlist_talker_t *endp_item = &g_array_index(conv_array_, hostlist_talker_t, conv_idx_);
            return VariantPointer<hostlist_talker_t>::asQVariant(endp_item);
        }
        if (role == Qt::UserRole + 1) {
            return VariantPointer<const mmdb_lookup_t>::asQVariant(mmdbLookup());
        }
        return QTreeWidgetItem::data(column, role);
    }

    const mmdb_lookup_t *mmdbLookup() const {
        hostlist_talker_t *endp_item = &g_array_index(conv_array_, hostlist_talker_t, conv_idx_);
        const mmdb_lookup_t *mmdb_lookup = NULL;
        if (endp_item->myaddress.type == AT_IPv4) {
            mmdb_lookup = maxmind_db_lookup_ipv4((const ws_in4_addr *) endp_item->myaddress.data);
        } else if (endp_item->myaddress.type == AT_IPv6) {
            mmdb_lookup = maxmind_db_lookup_ipv6((const ws_in6_addr *) endp_item->myaddress.data);
        }
        return mmdb_lookup && mmdb_lookup->found ? mmdb_lookup : NULL;
    }

    // Column text raw representation.
    // Return a string, qulonglong, double, or invalid QVariant representing the raw column data.
    QVariant colData(int col, bool resolve_names) const {
        hostlist_talker_t *endp_item = &g_array_index(conv_array_, hostlist_talker_t, conv_idx_);
        const mmdb_lookup_t *mmdb_lookup = mmdbLookup();

        switch (col) {
        case ENDP_COLUMN_ADDR:
        {
            char* addr_str = get_conversation_address(NULL, &endp_item->myaddress, resolve_names);
            QString q_addr_str(addr_str);
            wmem_free(NULL, addr_str);
            return q_addr_str;
        }
        case ENDP_COLUMN_PORT:
            if (resolve_names) {
                char* port_str = get_conversation_port(NULL, endp_item->port, endp_item->etype, resolve_names);
                QString q_port_str(port_str);
                wmem_free(NULL, port_str);
                return q_port_str;
            } else {
                return quint32(endp_item->port);
            }
        case ENDP_COLUMN_PACKETS:
            return quint64(endp_item->tx_frames + endp_item->rx_frames);
        case ENDP_COLUMN_BYTES:
            return quint64(endp_item->tx_bytes + endp_item->rx_bytes);
        case ENDP_COLUMN_PKT_AB:
            return quint64(endp_item->tx_frames);
        case ENDP_COLUMN_BYTES_AB:
            return quint64(endp_item->tx_bytes);
        case ENDP_COLUMN_PKT_BA:
            return quint64(endp_item->rx_frames);
        case ENDP_COLUMN_BYTES_BA:
            return quint64(endp_item->rx_bytes);
        case ENDP_COLUMN_GEO_COUNTRY:
            if (mmdb_lookup && mmdb_lookup->country) {
                return QVariant(mmdb_lookup->country);
            }
            return QVariant();
        case ENDP_COLUMN_GEO_CITY:
            if (mmdb_lookup && mmdb_lookup->city) {
                return QVariant(mmdb_lookup->city);
            }
            return QVariant();
        case ENDP_COLUMN_GEO_AS_NUM:
            if (mmdb_lookup && mmdb_lookup->as_number) {
                return QVariant(mmdb_lookup->as_number);
            }
            return QVariant();
        case ENDP_COLUMN_GEO_AS_ORG:
            if (mmdb_lookup && mmdb_lookup->as_org) {
                return QVariant(mmdb_lookup->as_org);
            }
            return QVariant();

        default:
            return QVariant();
        }
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        const EndpointTreeWidgetItem *other_row = static_cast<const EndpointTreeWidgetItem *>(&other);
        hostlist_talker_t *endp_item = &g_array_index(conv_array_, hostlist_talker_t, conv_idx_);
        hostlist_talker_t *other_item = &g_array_index(other_row->conv_array_, hostlist_talker_t, other_row->conv_idx_);

        int sort_col = treeWidget()->sortColumn();

        switch(sort_col) {
        case ENDP_COLUMN_ADDR:
            return cmp_address(&endp_item->myaddress, &other_item->myaddress) < 0 ? true : false;
        case ENDP_COLUMN_PORT:
            return endp_item->port < other_item->port;
        case ENDP_COLUMN_PACKETS:
            return (endp_item->tx_frames + endp_item->rx_frames) < (other_item->tx_frames + other_item->rx_frames);
        case ENDP_COLUMN_BYTES:
            return (endp_item->tx_bytes + endp_item->rx_bytes) < (other_item->tx_bytes + other_item->rx_bytes);
        case ENDP_COLUMN_PKT_AB:
            return endp_item->tx_frames < other_item->tx_frames;
        case ENDP_COLUMN_BYTES_AB:
            return endp_item->tx_bytes < other_item->tx_bytes;
        case ENDP_COLUMN_PKT_BA:
            return endp_item->rx_frames < other_item->rx_frames;
        case ENDP_COLUMN_BYTES_BA:
            return endp_item->rx_bytes < other_item->rx_bytes;
        case ENDP_COLUMN_GEO_COUNTRY:
        case ENDP_COLUMN_GEO_CITY:
        case ENDP_COLUMN_GEO_AS_ORG:
        {
            QString this_str = data(sort_col, Qt::DisplayRole).toString();
            QString other_str = other_row->data(sort_col, Qt::DisplayRole).toString();
            return (this_str < other_str);
        }
        case ENDP_COLUMN_GEO_AS_NUM:
        {
            // Valid values first, similar to strings above.
            bool ok;
            unsigned this_asn = colData(sort_col, false).toUInt(&ok);
            if (!ok) this_asn = UINT_MAX;
            unsigned other_asn = other_row->colData(sort_col, false).toUInt(&ok);
            if (!ok) other_asn = UINT_MAX;
            return (this_asn < other_asn);
        }
        default:
            return false;
        }
    }
private:
    GArray *conv_array_;
    guint conv_idx_;
    bool *resolve_names_ptr_;
};

//
// EndpointTreeWidget
// TrafficTableTreeWidget / QTreeWidget subclass that allows tapping
//

EndpointTreeWidget::EndpointTreeWidget(QWidget *parent, register_ct_t *table) :
    TrafficTableTreeWidget(parent, table),
#ifdef HAVE_MAXMINDDB
    has_geoip_data_(false),
#endif
    table_address_type_(AT_NONE)
{
    setColumnCount(ENDP_NUM_COLUMNS);
    setUniformRowHeights(true);

    QString proto_filter_name = proto_get_protocol_filter_name(get_conversation_proto_id(table_));
    if (proto_filter_name == "ip") {
        table_address_type_ = AT_IPv4;
    } else if (proto_filter_name == "ipv6") {
        table_address_type_ = AT_IPv6;
    }
    if (get_conversation_hide_ports(table_)) {
        hideColumn(ENDP_COLUMN_PORT);
    } else if (proto_filter_name == "ncp") {
        headerItem()->setText(ENDP_COLUMN_PORT, endp_conn_title);
    }

    int column_count = ENDP_NUM_COLUMNS;
    if (table_address_type_ == AT_IPv4 || table_address_type_ == AT_IPv6) {
        column_count = ENDP_NUM_GEO_COLUMNS;
    }
    for (int col = 0; col < column_count; col++) {
        headerItem()->setText(col, endp_column_titles[col]);
    }


    int one_en = fontMetrics().height() / 2;
    for (int i = 0; i < columnCount(); i++) {
        switch (i) {
        case ENDP_COLUMN_ADDR:
            setColumnWidth(i, one_en * (int) strlen("000.000.000.000"));
            break;
        case ENDP_COLUMN_PORT:
            setColumnWidth(i, one_en * (int) strlen("000000"));
            break;
        case ENDP_COLUMN_PACKETS:
        case ENDP_COLUMN_PKT_AB:
        case ENDP_COLUMN_PKT_BA:
            setColumnWidth(i, one_en * (int) strlen("00,000"));
            break;
        case ENDP_COLUMN_BYTES:
        case ENDP_COLUMN_BYTES_AB:
        case ENDP_COLUMN_BYTES_BA:
            setColumnWidth(i, one_en * (int) strlen("000,000"));
            break;
        default:
            setColumnWidth(i, one_en * 15); // Geolocation
        }
    }

    QMenu *submenu;

    FilterAction::Action cur_action = FilterAction::ActionApply;
    submenu = ctx_menu_.addMenu(FilterAction::actionName(cur_action));
    foreach (FilterAction::ActionType at, FilterAction::actionTypes()) {
        FilterAction *fa = new FilterAction(submenu, cur_action, at);
        submenu->addAction(fa);
        connect(fa, SIGNAL(triggered()), this, SLOT(filterActionTriggered()));
    }

    cur_action = FilterAction::ActionPrepare;
    submenu = ctx_menu_.addMenu(FilterAction::actionName(cur_action));
    foreach (FilterAction::ActionType at, FilterAction::actionTypes()) {
        FilterAction *fa = new FilterAction(submenu, cur_action, at);
        submenu->addAction(fa);
        connect(fa, SIGNAL(triggered()), this, SLOT(filterActionTriggered()));
    }

    cur_action = FilterAction::ActionFind;
    submenu = ctx_menu_.addMenu(FilterAction::actionName(cur_action));
    foreach (FilterAction::ActionType at, FilterAction::actionTypes()) {
        FilterAction *fa = new FilterAction(submenu, cur_action, at);
        submenu->addAction(fa);
        connect(fa, SIGNAL(triggered()), this, SLOT(filterActionTriggered()));
    }

    cur_action = FilterAction::ActionColorize;
    submenu = ctx_menu_.addMenu(FilterAction::actionName(cur_action));
    foreach (FilterAction::ActionType at, FilterAction::actionTypes()) {
        FilterAction *fa = new FilterAction(submenu, cur_action, at);
        submenu->addAction(fa);
        connect(fa, SIGNAL(triggered()), this, SLOT(filterActionTriggered()));
    }

    updateItems();

}

EndpointTreeWidget::~EndpointTreeWidget()
{
    reset_hostlist_table_data(&hash_);
}

void EndpointTreeWidget::tapReset(void *conv_hash_ptr)
{
    conv_hash_t *hash = (conv_hash_t*)conv_hash_ptr;
    EndpointTreeWidget *endp_tree = qobject_cast<EndpointTreeWidget *>((EndpointTreeWidget *)hash->user_data);
    if (!endp_tree) return;

    endp_tree->clear();
    reset_hostlist_table_data(&endp_tree->hash_);
}

void EndpointTreeWidget::tapDraw(void *conv_hash_ptr)
{
    conv_hash_t *hash = (conv_hash_t*)conv_hash_ptr;
    EndpointTreeWidget *endp_tree = qobject_cast<EndpointTreeWidget *>((EndpointTreeWidget *)hash->user_data);
    if (!endp_tree) return;

    endp_tree->updateItems();
}

void EndpointTreeWidget::updateItems()
{
    bool resize = topLevelItemCount() < resizeThreshold();
    title_ = proto_get_protocol_short_name(find_protocol_by_id(get_conversation_proto_id(table_)));

    if (hash_.conv_array && hash_.conv_array->len > 0) {
        title_.append(QString(" %1 %2").arg(UTF8_MIDDLE_DOT).arg(hash_.conv_array->len));
    }
    emit titleChanged(this, title_);

    if (!hash_.conv_array) {
        return;
    }

    setSortingEnabled(false);

    QList<QTreeWidgetItem *>new_items;
    for (int i = topLevelItemCount(); i < (int) hash_.conv_array->len; i++) {
        EndpointTreeWidgetItem *etwi = new EndpointTreeWidgetItem(hash_.conv_array, i, &resolve_names_);
        new_items << etwi;

        for (int col = 0; col < columnCount(); col++) {
            if (col != ENDP_COLUMN_ADDR && col < ENDP_NUM_COLUMNS) {
                etwi->setTextAlignment(col, Qt::AlignRight);
            }
        }

#ifdef HAVE_MAXMINDDB
        // Assume that an asynchronous MMDB lookup has completed before (for
        // example, in the dissection tree). If so, then we do not have to check
        // all previous items for availability of any MMDB result.
        if (!has_geoip_data_ && maxmind_db_has_coords(etwi->mmdbLookup())) {
            has_geoip_data_ = true;
            emit geoIPStatusChanged();
        }
#endif
    }
    addTopLevelItems(new_items);
    setSortingEnabled(true);

    if (resize) {
        for (int col = 0; col < columnCount(); col++) {
            resizeColumnToContents(col);
        }
    }
}

void EndpointTreeWidget::filterActionTriggered()
{
    EndpointTreeWidgetItem *etwi = static_cast<EndpointTreeWidgetItem *>(currentItem());
    FilterAction *fa = qobject_cast<FilterAction *>(QObject::sender());

    if (!fa || !etwi) {
        return;
    }

    hostlist_talker_t *endp_item = etwi->hostlistTalker();
    if (!endp_item) {
        return;
    }

    QString filter = get_hostlist_filter(endp_item);
    emit filterAction(filter, fa->action(), fa->actionType());
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
