/* endpoint_dialog.cpp
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

#include "endpoint_dialog.h"

#ifdef HAVE_GEOIP
#include <GeoIP.h>
#include <epan/geoip_db.h>
#include <wsutil/pint.h>
#endif

#include <epan/prefs.h>

#include "ui/recent.h"
#include "ui/traffic_table_ui.h"

#include "wsutil/str_util.h"

#include "qt_ui_utils.h"
#include "wireshark_application.h"

#include <QCheckBox>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QMessageBox>
#include <QPushButton>
#include <QUrl>

const QString table_name_ = QObject::tr("Endpoint");
EndpointDialog::EndpointDialog(QWidget &parent, CaptureFile &cf, int cli_proto_id, const char *filter) :
    TrafficTableDialog(parent, cf, filter, table_name_)
{
#ifdef HAVE_GEOIP
    map_bt_ = buttonBox()->addButton(tr("Map"), QDialogButtonBox::ActionRole);
    map_bt_->setToolTip(tr("Draw IPv4 or IPv6 endpoints on a map."));
    connect(map_bt_, SIGNAL(clicked()), this, SLOT(createMap()));

    connect(trafficTableTabWidget(), SIGNAL(currentChanged(int)), this, SLOT(tabChanged()));
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
    if (get_conversation_by_proto_id(cli_proto_id)) {
        endp_protos.removeAll(cli_proto_id);
        endp_protos.prepend(cli_proto_id);
    }

    // QTabWidget selects the first item by default.
    foreach (int endp_proto, endp_protos) {
        addTrafficTable(get_conversation_by_proto_id(endp_proto));
    }

    fillTypeMenu(endp_protos);

#ifdef HAVE_GEOIP
    tabChanged();
#endif
    itemSelectionChanged();

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
        disconnect(cur_tree, SIGNAL(filterAction(QString&,FilterAction::Action,FilterAction::ActionType)),
                   this, SIGNAL(filterAction(QString&,FilterAction::Action,FilterAction::ActionType)));
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

    connect(endp_tree, SIGNAL(itemSelectionChanged()),
            this, SLOT(itemSelectionChanged()));
    connect(endp_tree, SIGNAL(titleChanged(QWidget*,QString)),
            this, SLOT(setTabText(QWidget*,QString)));
    connect(endp_tree, SIGNAL(filterAction(QString&,FilterAction::Action,FilterAction::ActionType)),
            this, SIGNAL(filterAction(QString&,FilterAction::Action,FilterAction::ActionType)));
    connect(nameResolutionCheckBox(), SIGNAL(toggled(bool)),
            endp_tree, SLOT(setNameResolutionEnabled(bool)));

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

#ifdef HAVE_GEOIP
    connect(endp_tree, SIGNAL(geoIPStatusChanged()), this, SLOT(tabChanged()));
#endif
    return true;
}

#ifdef HAVE_GEOIP
void EndpointDialog::tabChanged()
{
    EndpointTreeWidget *cur_tree = qobject_cast<EndpointTreeWidget *>(trafficTableTabWidget()->currentWidget());
    map_bt_->setEnabled(cur_tree && cur_tree->hasGeoIPData());
}

void EndpointDialog::createMap()
{
    EndpointTreeWidget *cur_tree = qobject_cast<EndpointTreeWidget *>(trafficTableTabWidget()->currentWidget());
    if (!cur_tree) {
        return;
    }

    gchar *err_str;
    gchar *map_path = create_endpoint_geoip_map(cur_tree->trafficTreeHash()->conv_array, &err_str);
    if (!map_path) {
        QMessageBox::warning(this, tr("Map file error"), err_str);
        g_free(err_str);
        return;
    }
    QDesktopServices::openUrl(QUrl::fromLocalFile(gchar_free_to_qstring(map_path)));
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

const int ei_col_ = 0;
const int pkts_col_ = 1;

const char *geoip_none_ = "-";

class EndpointTreeWidgetItem : public TrafficTableTreeWidgetItem
{
public:
    EndpointTreeWidgetItem(QTreeWidget *tree) : TrafficTableTreeWidgetItem(tree)  {}
    EndpointTreeWidgetItem(QTreeWidget *parent, const QStringList &strings)
                   : TrafficTableTreeWidgetItem (parent, strings)  {}

    // Set column text to its cooked representation.
    void update(gboolean resolve_names) {
        hostlist_talker_t *endp_item = data(ei_col_, Qt::UserRole).value<hostlist_talker_t *>();
        bool ok;
        quint64 cur_packets = data(pkts_col_, Qt::UserRole).toULongLong(&ok);
        char *addr_str, *port_str;

        if (!endp_item) {
            return;
        }

        quint64 packets = endp_item->tx_frames + endp_item->rx_frames;
        if (ok && cur_packets == packets) {
            return;
        }

        addr_str = get_conversation_address(NULL, &endp_item->myaddress, resolve_names);
        port_str = get_conversation_port(NULL, endp_item->port, endp_item->ptype, resolve_names);
        setText(ENDP_COLUMN_ADDR, addr_str);
        setText(ENDP_COLUMN_PORT, port_str);
        wmem_free(NULL, addr_str);
        wmem_free(NULL, port_str);

        QString col_str;

        col_str = QString("%L1").arg(packets);
        setText(ENDP_COLUMN_PACKETS, col_str);
        col_str = gchar_free_to_qstring(format_size(endp_item->tx_bytes + endp_item->rx_bytes, format_size_unit_none|format_size_prefix_si));
        setText(ENDP_COLUMN_BYTES, col_str);
        col_str = QString("%L1").arg(endp_item->tx_frames);
        setText(ENDP_COLUMN_PKT_AB, QString::number(endp_item->tx_frames));
        col_str = gchar_free_to_qstring(format_size(endp_item->tx_bytes, format_size_unit_none|format_size_prefix_si));
        setText(ENDP_COLUMN_BYTES_AB, col_str);
        col_str = QString("%L1").arg(endp_item->rx_frames);
        setText(ENDP_COLUMN_PKT_BA, QString::number(endp_item->rx_frames));
        col_str = gchar_free_to_qstring(format_size(endp_item->rx_bytes, format_size_unit_none|format_size_prefix_si));
        setText(ENDP_COLUMN_BYTES_BA, col_str);
        setData(pkts_col_, Qt::UserRole, qVariantFromValue(packets));

#ifdef HAVE_GEOIP
        /* Filled in from the GeoIP config, if any */
        EndpointTreeWidget *ep_tree = qobject_cast<EndpointTreeWidget *>(treeWidget());
        if (ep_tree) {
            for (int col = ENDP_NUM_COLUMNS; col < ep_tree->columnCount(); col++) {
                char *col_text = NULL;
                foreach (unsigned db, ep_tree->columnToDb(col)) {
                    if (endp_item->myaddress.type == AT_IPv4) {
                        col_text = geoip_db_lookup_ipv4(db, pntoh32(endp_item->myaddress.data), NULL);
                    } else if (endp_item->myaddress.type == AT_IPv6) {
                        const struct e_in6_addr *addr = (const struct e_in6_addr *) endp_item->myaddress.data;
                        col_text = geoip_db_lookup_ipv6(db, *addr, NULL);
                    }
                    if (col_text) {
                        break;
                    }
                }
                setText(col, col_text ? col_text : geoip_none_);
                wmem_free(NULL, col_text);
            }
        }
#endif
    }

    // Return a string, qulonglong, double, or invalid QVariant representing the raw column data.
    QVariant colData(int col, bool resolve_names) const {
        hostlist_talker_t *endp_item = data(ei_col_, Qt::UserRole).value<hostlist_talker_t *>();

        if (!endp_item) {
            return QVariant();
        }

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
                char* port_str = get_conversation_port(NULL, endp_item->port, endp_item->ptype, resolve_names);
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
#ifdef HAVE_GEOIP
        default:
        {
            bool ok;

            double dval = text(col).toDouble(&ok);
            if (ok) { // Assume lat / lon
                return dval;
            }

            qulonglong ullval = text(col).toULongLong(&ok);
            if (ok) { // Assume uint
                return ullval;
            }

            qlonglong llval = text(col).toLongLong(&ok);
            if (ok) { // Assume int
                return llval;
            }

            return text(col);
            break;
        }
#else
        default:
            return QVariant();
#endif
        }
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        hostlist_talker_t *endp_item = data(ei_col_, Qt::UserRole).value<hostlist_talker_t *>();
        hostlist_talker_t *other_item = other.data(ei_col_, Qt::UserRole).value<hostlist_talker_t *>();

        if (!endp_item || !other_item) {
            return false;
        }

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
#ifdef HAVE_GEOIP
        default:
        {
            double ei_val, oi_val;
            bool ei_ok, oi_ok;
            ei_val = text(sort_col).toDouble(&ei_ok);
            oi_val = other.text(sort_col).toDouble(&oi_ok);

            if (ei_ok && oi_ok) { // Assume lat / lon
                return ei_val < oi_val;
            } else {
                // XXX Fall back to string comparison. We might want to try sorting naturally
                // using QCollator instead.
                return text(sort_col) < other.text(sort_col);
            }
            break;
        }
#else
        default:
            return false;
#endif
        }
    }

};

//
// EndpointTreeWidget
// TrafficTableTreeWidget / QTreeWidget subclass that allows tapping
//

EndpointTreeWidget::EndpointTreeWidget(QWidget *parent, register_ct_t *table) :
    TrafficTableTreeWidget(parent, table)
#ifdef HAVE_GEOIP
  , has_geoip_data_(false)
#endif
{
    setColumnCount(ENDP_NUM_COLUMNS);

    for (int i = 0; i < ENDP_NUM_COLUMNS; i++) {
        headerItem()->setText(i, endp_column_titles[i]);
    }

    if (get_conversation_hide_ports(table_)) {
        hideColumn(ENDP_COLUMN_PORT);
    } else if (!strcmp(proto_get_protocol_filter_name(get_conversation_proto_id(table_)), "ncp")) {
        headerItem()->setText(ENDP_COLUMN_PORT, endp_conn_title);
    }

#ifdef HAVE_GEOIP
    QMap<QString, int> db_name_to_col;
    for (unsigned db = 0; db < geoip_db_num_dbs(); db++) {
        QString db_name = geoip_db_name(db);
        int col = db_name_to_col.value(db_name, -1);

        if (col < 0) {
            col = columnCount();
            setColumnCount(col + 1);
            headerItem()->setText(col, db_name);
            hideColumn(col);
            db_name_to_col[db_name] = col;
        }
        col_to_db_[col] << db;
    }
#endif

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
            setColumnWidth(i, one_en * (int) strlen("-00.000000")); // GeoIP
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
    EndpointTreeWidget *endp_tree = static_cast<EndpointTreeWidget *>(hash->user_data);
    if (!endp_tree) return;

    endp_tree->clear();
    reset_hostlist_table_data(&endp_tree->hash_);
}

void EndpointTreeWidget::tapDraw(void *conv_hash_ptr)
{
    conv_hash_t *hash = (conv_hash_t*)conv_hash_ptr;
    EndpointTreeWidget *endp_tree = static_cast<EndpointTreeWidget *>(hash->user_data);
    if (!endp_tree) return;

    endp_tree->updateItems();
}

void EndpointTreeWidget::updateItems()
{
    title_ = proto_get_protocol_short_name(find_protocol_by_id(get_conversation_proto_id(table_)));

    if (hash_.conv_array && hash_.conv_array->len > 0) {
        title_.append(QString(" %1 %2").arg(UTF8_MIDDLE_DOT).arg(hash_.conv_array->len));
    }
    emit titleChanged(this, title_);

    if (!hash_.conv_array) {
        return;
    }

#ifdef HAVE_GEOIP
    if (topLevelItemCount() < 1 && hash_.conv_array->len > 0) {
        hostlist_talker_t *endp_item = &g_array_index(hash_.conv_array, hostlist_talker_t, 0);
        if (endp_item->myaddress.type == AT_IPv4 || endp_item->myaddress.type == AT_IPv6) {
            for (unsigned i = 0; i < geoip_db_num_dbs(); i++) {
                showColumn(ENDP_NUM_COLUMNS + i);
            }
            has_geoip_data_ = true;
            emit geoIPStatusChanged();
        }
    }
#endif

    setSortingEnabled(false);
    for (int i = topLevelItemCount(); i < (int) hash_.conv_array->len; i++) {
        EndpointTreeWidgetItem *etwi = new EndpointTreeWidgetItem(this);
        hostlist_talker_t *endp_item = &g_array_index(hash_.conv_array, hostlist_talker_t, i);
        etwi->setData(ei_col_, Qt::UserRole, qVariantFromValue(endp_item));
        addTopLevelItem(etwi);

        for (int col = 0; col < columnCount(); col++) {
            if (col != ENDP_COLUMN_ADDR && col < ENDP_NUM_COLUMNS) {
                etwi->setTextAlignment(col, Qt::AlignRight);
            }
        }
    }
    QTreeWidgetItemIterator iter(this);
    while (*iter) {
        EndpointTreeWidgetItem *ei = static_cast<EndpointTreeWidgetItem *>(*iter);
        ei->update(resolve_names_);
        ++iter;
    }
    setSortingEnabled(true);

    for (int col = 0; col < columnCount(); col++) {
        resizeColumnToContents(col);
    }
}

void EndpointTreeWidget::filterActionTriggered()
{
    EndpointTreeWidgetItem *etwi = static_cast<EndpointTreeWidgetItem *>(currentItem());
    FilterAction *fa = qobject_cast<FilterAction *>(QObject::sender());

    if (!fa || !etwi) {
        return;
    }

    hostlist_talker_t *endp_item = etwi->data(ei_col_, Qt::UserRole).value<hostlist_talker_t *>();
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
