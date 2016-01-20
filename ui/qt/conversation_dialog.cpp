/* conversation_dialog.cpp
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

#include "conversation_dialog.h"

#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>

#include "ui/recent.h"
#include "ui/tap-tcp-stream.h"
#include "ui/traffic_table_ui.h"

#include "wsutil/str_util.h"

#include "qt_ui_utils.h"
#include "wireshark_application.h"

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QPushButton>

// To do:
// - https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6727
//   - Wide last column?
//   + No arrows on unsorted columns
//   - Add follow stream to context menu
//   + Change "A <- B" to "B -> A"
// - Improper wildcard handling https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8010
// - TShark consolidation https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6310
// - Display filter entry?
// - Add follow, copy & graph actions to context menu.

// Bugs:
// - Name resolution doesn't do anything if its preference is disabled.
// - Columns don't resize correctly.
// - Closing the capture file clears conversation data.

// Fixed bugs:
// - Friendly unit displays https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=9231
// - Misleading bps calculation https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8703

const QString table_name_ = QObject::tr("Conversation");
ConversationDialog::ConversationDialog(QWidget &parent, CaptureFile &cf, int cli_proto_id, const char *filter) :
    TrafficTableDialog(parent, cf, filter, table_name_)
{
    follow_bt_ = buttonBox()->addButton(tr("Follow Stream" UTF8_HORIZONTAL_ELLIPSIS), QDialogButtonBox::ActionRole);
    follow_bt_->setToolTip(tr("Follow a TCP or UDP stream."));
    connect(follow_bt_, SIGNAL(clicked()), this, SLOT(followStream()));

    graph_bt_ = buttonBox()->addButton(tr("Graph" UTF8_HORIZONTAL_ELLIPSIS), QDialogButtonBox::ActionRole);
    graph_bt_->setToolTip(tr("Graph a TCP conversation."));
    connect(graph_bt_, SIGNAL(clicked()), this, SLOT(graphTcp()));

    addProgressFrame(&parent);

    QList<int> conv_protos;
    for (GList *conv_tab = recent.conversation_tabs; conv_tab; conv_tab = conv_tab->next) {
        int proto_id = proto_get_id_by_short_name((const char *)conv_tab->data);
        if (proto_id > -1 && !conv_protos.contains(proto_id)) {
            conv_protos.append(proto_id);
        }
    }

    if (conv_protos.isEmpty()) {
        conv_protos = defaultProtos();
    }

    // Bring the command-line specified type to the front.
    if (get_conversation_by_proto_id(cli_proto_id)) {
        conv_protos.removeAll(cli_proto_id);
        conv_protos.prepend(cli_proto_id);
    }

    // QTabWidget selects the first item by default.
    foreach (int conv_proto, conv_protos) {
        addTrafficTable(get_conversation_by_proto_id(conv_proto));
    }

    fillTypeMenu(conv_protos);

    updateWidgets();
    itemSelectionChanged();

    cap_file_.delayedRetapPackets();
}

ConversationDialog::~ConversationDialog()
{
    prefs_clear_string_list(recent.conversation_tabs);
    recent.conversation_tabs = NULL;

    ConversationTreeWidget *cur_tree = qobject_cast<ConversationTreeWidget *>(trafficTableTabWidget()->currentWidget());
    foreach (QAction *ca, traffic_type_menu_.actions()) {
        int proto_id = ca->data().value<int>();
        if (proto_id_to_tree_.contains(proto_id) && ca->isChecked()) {
            char *title = g_strdup(proto_get_protocol_short_name(find_protocol_by_id(proto_id)));
            if (proto_id_to_tree_[proto_id] == cur_tree) {
                recent.conversation_tabs = g_list_prepend(recent.conversation_tabs, title);
            } else {
                recent.conversation_tabs = g_list_append(recent.conversation_tabs, title);
            }
        }
    }
}

void ConversationDialog::captureFileClosing()
{
    // Keep the dialog around but disable any controls that depend
    // on a live capture file.
    for (int i = 0; i < trafficTableTabWidget()->count(); i++) {
        ConversationTreeWidget *cur_tree = qobject_cast<ConversationTreeWidget *>(trafficTableTabWidget()->widget(i));
        disconnect(cur_tree, SIGNAL(filterAction(QString&,FilterAction::Action,FilterAction::ActionType)),
                   this, SIGNAL(filterAction(QString&,FilterAction::Action,FilterAction::ActionType)));
    }
    displayFilterCheckBox()->setEnabled(false);
    enabledTypesPushButton()->setEnabled(false);
    follow_bt_->setEnabled(false);
    graph_bt_->setEnabled(false);
    TrafficTableDialog::captureFileClosing();
}

bool ConversationDialog::addTrafficTable(register_ct_t* table)
{
    int proto_id = get_conversation_proto_id(table);

    if (!table || proto_id_to_tree_.contains(proto_id)) {
        return false;
    }

    ConversationTreeWidget *conv_tree = new ConversationTreeWidget(this, table);

    proto_id_to_tree_[proto_id] = conv_tree;
    const char* table_name = proto_get_protocol_short_name(find_protocol_by_id(proto_id));

    trafficTableTabWidget()->addTab(conv_tree, table_name);

    connect(conv_tree, SIGNAL(itemSelectionChanged()),
            this, SLOT(itemSelectionChanged()));
    connect(conv_tree, SIGNAL(titleChanged(QWidget*,QString)),
            this, SLOT(setTabText(QWidget*,QString)));
    connect(conv_tree, SIGNAL(filterAction(QString&,FilterAction::Action,FilterAction::ActionType)),
            this, SIGNAL(filterAction(QString&,FilterAction::Action,FilterAction::ActionType)));
    connect(nameResolutionCheckBox(), SIGNAL(toggled(bool)),
            conv_tree, SLOT(setNameResolutionEnabled(bool)));

    // XXX Move to ConversationTreeWidget ctor?
    QByteArray filter_utf8;
    const char *filter = NULL;
    if (displayFilterCheckBox()->isChecked()) {
        filter = cap_file_.capFile()->dfilter;
    } else if (!filter_.isEmpty()) {
        filter_utf8 = filter_.toUtf8();
        filter = filter_utf8.constData();
    }

    conv_tree->trafficTreeHash()->user_data = conv_tree;

    registerTapListener(proto_get_protocol_filter_name(proto_id), conv_tree->trafficTreeHash(), filter, 0,
                        ConversationTreeWidget::tapReset,
                        get_conversation_packet_func(table),
                        ConversationTreeWidget::tapDraw);

    return true;
}

conv_item_t *ConversationDialog::currentConversation()
{
    ConversationTreeWidget *cur_tree = qobject_cast<ConversationTreeWidget *>(trafficTableTabWidget()->currentWidget());

    if (!cur_tree || cur_tree->selectedItems().count() < 1) {
        return NULL;
    }

    return cur_tree->selectedItems()[0]->data(0, Qt::UserRole).value<conv_item_t *>();
}

void ConversationDialog::followStream()
{
    if (file_closed_) {
        return;
    }

    conv_item_t *conv_item = currentConversation();
    if (!conv_item) {
        return;
    }

    QString filter;
    follow_type_t ftype = FOLLOW_TCP;
    switch (conv_item->ptype) {
    case PT_TCP:
        filter = QString("tcp.stream eq %1").arg(conv_item->conv_id);
        break;
    case PT_UDP:
        filter = QString("udp.stream eq %1").arg(conv_item->conv_id);
        ftype = FOLLOW_UDP;
        break;
    default:
        break;
    }

    if (filter.length() < 1) {
        return;
    }

    emit filterAction(filter, FilterAction::ActionApply, FilterAction::ActionTypePlain);
    emit openFollowStreamDialog(ftype);
}

void ConversationDialog::graphTcp()
{
    if (file_closed_) {
        return;
    }

    conv_item_t *conv_item = currentConversation();
    if (!conv_item) {
        return;
    }

    // XXX The GTK+ code opens the TCP Stream dialog. We might want
    // to open the IO Graph dialog instead.
    QString filter;
    if (conv_item->ptype == PT_TCP) {
        filter = QString("tcp.stream eq %1").arg(conv_item->conv_id);
    } else {
        return;
    }

    // Apply the filter for this conversation.
    emit filterAction(filter, FilterAction::ActionApply, FilterAction::ActionTypePlain);
    // This action will now find a packet from the intended conversation/stream.
    openTcpStreamGraph(GRAPH_TSEQ_TCPTRACE);
}

void ConversationDialog::itemSelectionChanged()
{
    bool copy_enable = trafficTableTabWidget()->currentWidget() ? true : false;
    bool follow_enable = false, graph_enable = false;
    conv_item_t *conv_item = currentConversation();

    if (!file_closed_ && conv_item) {
        switch (conv_item->ptype) {
        case PT_TCP:
            graph_enable = true;
            // Fall through
        case PT_UDP:
            follow_enable = true;
            break;
        default:
            break;
        }
    }

    copy_bt_->setEnabled(copy_enable);
    follow_bt_->setEnabled(follow_enable);
    graph_bt_->setEnabled(graph_enable);
}

void ConversationDialog::on_nameResolutionCheckBox_toggled(bool)
{
    updateWidgets();
}

void ConversationDialog::on_displayFilterCheckBox_toggled(bool checked)
{
    if (file_closed_) {
        return;
    }

    QByteArray filter_utf8;
    const char *filter = NULL;
    if (checked) {
        filter = cap_file_.capFile()->dfilter;
    } else if (!filter_.isEmpty()) {
        filter_utf8 = filter_.toUtf8();
        filter = filter_utf8.constData();
    }

    for (int i = 0; i < trafficTableTabWidget()->count(); i++) {
        set_tap_dfilter(trafficTableTabWidget()->widget(i), filter);
    }

    cap_file_.retapPackets();
}

void ConversationDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_STATS_CONVERSATIONS_DIALOG);
}

void init_conversation_table(struct register_ct* ct, const char *filter)
{
    wsApp->emitStatCommandSignal("Conversations", filter, GINT_TO_POINTER(get_conversation_proto_id(ct)));
}


// ConversationTreeWidgetItem
// TrafficTableTreeWidgetItem / QTreeWidgetItem subclass that allows sorting

// Minimum bandwidth calculation duration
// https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8703
const double min_bw_calc_duration_ = 5 / 1000.0; // seconds
const QString bps_na_ = QObject::tr("N/A");

const int ci_col_ = 0;
const int pkts_col_ = 1;
class ConversationTreeWidgetItem : public TrafficTableTreeWidgetItem
{
public:
    ConversationTreeWidgetItem(QTreeWidget *tree) : TrafficTableTreeWidgetItem(tree)  {}
    ConversationTreeWidgetItem(QTreeWidget *parent, const QStringList &strings)
                   : TrafficTableTreeWidgetItem (parent, strings)  {}

    // Set column text to its cooked representation.
    void update(gboolean resolve_names) {
        conv_item_t *conv_item = data(ci_col_, Qt::UserRole).value<conv_item_t *>();
        bool ok;
        quint64 cur_packets = data(pkts_col_, Qt::UserRole).toULongLong(&ok);
        char *src_addr, *dst_addr, *src_port, *dst_port;

        if (!conv_item) {
            return;
        }

        quint64 packets = conv_item->tx_frames + conv_item->rx_frames;
        if (ok && cur_packets == packets) {
            return;
        }

        src_addr = get_conversation_address(NULL, &conv_item->src_address, resolve_names);
        dst_addr = get_conversation_address(NULL, &conv_item->dst_address, resolve_names);
        src_port = get_conversation_port(NULL, conv_item->src_port, conv_item->ptype, resolve_names);
        dst_port = get_conversation_port(NULL, conv_item->dst_port, conv_item->ptype, resolve_names);
        setText(CONV_COLUMN_SRC_ADDR, src_addr);
        setText(CONV_COLUMN_SRC_PORT, src_port);
        setText(CONV_COLUMN_DST_ADDR, dst_addr);
        setText(CONV_COLUMN_DST_PORT, dst_port);
        wmem_free(NULL, src_addr);
        wmem_free(NULL, dst_addr);
        wmem_free(NULL, src_port);
        wmem_free(NULL, dst_port);

        double duration = nstime_to_sec(&conv_item->stop_time) - nstime_to_sec(&conv_item->start_time);
        QString col_str, bps_ab = bps_na_, bps_ba = bps_na_;

        col_str = QString("%L1").arg(packets);
        setText(CONV_COLUMN_PACKETS, col_str);
        col_str = gchar_free_to_qstring(format_size(conv_item->tx_bytes + conv_item->rx_bytes, format_size_unit_none|format_size_prefix_si));
        setText(CONV_COLUMN_BYTES, col_str);
        col_str = QString("%L1").arg(conv_item->tx_frames);
        setText(CONV_COLUMN_PKT_AB, QString::number(conv_item->tx_frames));
        col_str = gchar_free_to_qstring(format_size(conv_item->tx_bytes, format_size_unit_none|format_size_prefix_si));
        setText(CONV_COLUMN_BYTES_AB, col_str);
        col_str = QString("%L1").arg(conv_item->rx_frames);
        setText(CONV_COLUMN_PKT_BA, QString::number(conv_item->rx_frames));
        col_str = gchar_free_to_qstring(format_size(conv_item->rx_bytes, format_size_unit_none|format_size_prefix_si));
        setText(CONV_COLUMN_BYTES_BA, col_str);
        setText(CONV_COLUMN_START, QString::number(nstime_to_sec(&conv_item->start_time), 'f', 9));
        setText(CONV_COLUMN_DURATION, QString::number(duration, 'f', 6));
        if (duration > min_bw_calc_duration_) {
            bps_ab = gchar_free_to_qstring(format_size((gint64) conv_item->tx_bytes * 8 / duration, format_size_unit_none|format_size_prefix_si));
            bps_ba = gchar_free_to_qstring(format_size((gint64) conv_item->rx_bytes * 8 / duration, format_size_unit_none|format_size_prefix_si));
        }
        setText(CONV_COLUMN_BPS_AB, bps_ab);
        setText(CONV_COLUMN_BPS_BA, bps_ba);
        setData(pkts_col_, Qt::UserRole, qVariantFromValue(packets));
    }

    // Return a QString, qulonglong, double, or invalid QVariant representing the raw column data.
    QVariant colData(int col, bool resolve_names) const {
        conv_item_t *conv_item = data(ci_col_, Qt::UserRole).value<conv_item_t *>();

        if (!conv_item) {
            return QVariant();
        }

        double duration = nstime_to_sec(&conv_item->stop_time) - nstime_to_sec(&conv_item->start_time);
        double bps_ab = 0, bps_ba = 0;
        if (duration > min_bw_calc_duration_) {
            bps_ab = conv_item->tx_bytes * 8 / duration;
            bps_ba = conv_item->rx_bytes * 8 / duration;
        }

        switch (col) {
        case CONV_COLUMN_SRC_ADDR:
            {
            char* addr_str = get_conversation_address(NULL, &conv_item->src_address, resolve_names);
            QString q_addr_str(addr_str);
            wmem_free(NULL, addr_str);
            return q_addr_str;
            }
        case CONV_COLUMN_SRC_PORT:
            if (resolve_names) {
                char* port_str = get_conversation_port(NULL, conv_item->src_port, conv_item->ptype, resolve_names);
                QString q_port_str(port_str);
                wmem_free(NULL, port_str);
                return q_port_str;
            } else {
                return quint32(conv_item->src_port);
            }
        case CONV_COLUMN_DST_ADDR:
            {
            char* addr_str = get_conversation_address(NULL, &conv_item->dst_address, resolve_names);
            QString q_addr_str(addr_str);
            wmem_free(NULL, addr_str);
            return q_addr_str;
            }
        case CONV_COLUMN_DST_PORT:
            if (resolve_names) {
                char* port_str = get_conversation_port(NULL, conv_item->dst_port, conv_item->ptype, resolve_names);
                QString q_port_str(port_str);
                wmem_free(NULL, port_str);
                return q_port_str;
            } else {
                return quint32(conv_item->dst_port);
            }
        case CONV_COLUMN_PACKETS:
            return quint64(conv_item->tx_frames + conv_item->rx_frames);
        case CONV_COLUMN_BYTES:
            return quint64(conv_item->tx_bytes + conv_item->rx_bytes);
        case CONV_COLUMN_PKT_AB:
            return quint64(conv_item->tx_frames);
        case CONV_COLUMN_BYTES_AB:
            return quint64(conv_item->tx_bytes);
        case CONV_COLUMN_PKT_BA:
            return quint64(conv_item->rx_frames);
        case CONV_COLUMN_BYTES_BA:
            return quint64(conv_item->rx_bytes);
        case CONV_COLUMN_START:
            return nstime_to_sec(&conv_item->start_time);
        case CONV_COLUMN_DURATION:
            return duration;
        case CONV_COLUMN_BPS_AB:
            return bps_ab;
        case CONV_COLUMN_BPS_BA:
            return bps_ba;
        default:
            return QVariant();
        }
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        conv_item_t *conv_item = data(ci_col_, Qt::UserRole).value<conv_item_t *>();
        conv_item_t *other_item = other.data(ci_col_, Qt::UserRole).value<conv_item_t *>();

        if (!conv_item || !other_item) {
            return false;
        }

        int sort_col = treeWidget()->sortColumn();
        double conv_duration = nstime_to_sec(&conv_item->stop_time) - nstime_to_sec(&conv_item->start_time);
        double other_duration = nstime_to_sec(&other_item->stop_time) - nstime_to_sec(&other_item->start_time);

        switch(sort_col) {
        case CONV_COLUMN_SRC_ADDR:
            return cmp_address(&conv_item->src_address, &other_item->src_address) < 0 ? true : false;
        case CONV_COLUMN_SRC_PORT:
            return conv_item->src_port < other_item->src_port;
        case CONV_COLUMN_DST_ADDR:
            return cmp_address(&conv_item->dst_address, &other_item->dst_address) < 0 ? true : false;
        case CONV_COLUMN_DST_PORT:
            return conv_item->dst_port < other_item->dst_port;
        case CONV_COLUMN_PACKETS:
            return (conv_item->tx_frames + conv_item->rx_frames) < (other_item->tx_frames + other_item->rx_frames);
        case CONV_COLUMN_BYTES:
            return (conv_item->tx_bytes + conv_item->rx_bytes) < (other_item->tx_bytes + other_item->rx_bytes);
        case CONV_COLUMN_PKT_AB:
            return conv_item->tx_frames < other_item->tx_frames;
        case CONV_COLUMN_BYTES_AB:
            return conv_item->tx_bytes < other_item->tx_bytes;
        case CONV_COLUMN_PKT_BA:
            return conv_item->rx_frames < other_item->rx_frames;
        case CONV_COLUMN_BYTES_BA:
            return conv_item->rx_bytes < other_item->rx_bytes;
        case CONV_COLUMN_START:
            return nstime_to_sec(&conv_item->start_time) < nstime_to_sec(&other_item->start_time);
        case CONV_COLUMN_DURATION:
            return conv_duration < other_duration;
        case CONV_COLUMN_BPS_AB:
            return conv_item->tx_bytes / conv_duration < other_item->tx_bytes / other_duration;
        case CONV_COLUMN_BPS_BA:
            return conv_item->rx_bytes / conv_duration < other_item->rx_bytes / other_duration;
        default:
            return false;
        }
    }
};

// ConversationTreeWidget
// TrafficTableTreeWidget / QTreeWidget subclass that allows tapping

ConversationTreeWidget::ConversationTreeWidget(QWidget *parent, register_ct_t* table) :
    TrafficTableTreeWidget(parent, table)
{
    setColumnCount(CONV_NUM_COLUMNS);

    for (int i = 0; i < CONV_NUM_COLUMNS; i++) {
        headerItem()->setText(i, conv_column_titles[i]);
    }

    if (get_conversation_hide_ports(table_)) {
        hideColumn(CONV_COLUMN_SRC_PORT);
        hideColumn(CONV_COLUMN_DST_PORT);
    } else if (!strcmp(proto_get_protocol_filter_name(get_conversation_proto_id(table_)), "ncp")) {
        headerItem()->setText(CONV_COLUMN_SRC_PORT, conv_conn_a_title);
        headerItem()->setText(CONV_COLUMN_DST_PORT, conv_conn_b_title);
    }

    int one_en = fontMetrics().height() / 2;
    for (int i = 0; i < CONV_NUM_COLUMNS; i++) {
        switch (i) {
        case CONV_COLUMN_SRC_ADDR:
        case CONV_COLUMN_DST_ADDR:
            setColumnWidth(i, one_en * (int) strlen("000.000.000.000"));
            break;
        case CONV_COLUMN_SRC_PORT:
        case CONV_COLUMN_DST_PORT:
            setColumnWidth(i, one_en * (int) strlen("000000"));
            break;
        case CONV_COLUMN_PACKETS:
        case CONV_COLUMN_PKT_AB:
        case CONV_COLUMN_PKT_BA:
            setColumnWidth(i, one_en * (int) strlen("00,000"));
            break;
        case CONV_COLUMN_BYTES:
        case CONV_COLUMN_BYTES_AB:
        case CONV_COLUMN_BYTES_BA:
            setColumnWidth(i, one_en * (int) strlen("000,000"));
            break;
        case CONV_COLUMN_START:
            setColumnWidth(i, one_en * (int) strlen("00.000"));
            break;
        case CONV_COLUMN_DURATION:
            setColumnWidth(i, one_en * (int) strlen("00.000000"));
            break;
        case CONV_COLUMN_BPS_AB:
        case CONV_COLUMN_BPS_BA:
            setColumnWidth(i, one_en * (int) strlen("000 k"));
            break;
        default:
            setColumnWidth(i, one_en * 5);
        }
    }

    QMenu *submenu;

    initDirectionMap();

    FilterAction::Action cur_action = FilterAction::ActionApply;
    submenu = ctx_menu_.addMenu(FilterAction::actionName(cur_action));
    foreach (FilterAction::ActionType at, FilterAction::actionTypes()) {
        QMenu *subsubmenu = submenu->addMenu(FilterAction::actionTypeName(at));
        foreach (FilterAction::ActionDirection ad, FilterAction::actionDirections()) {
            FilterAction *fa = new FilterAction(subsubmenu, cur_action, at, ad);
            subsubmenu->addAction(fa);
            connect(fa, SIGNAL(triggered()), this, SLOT(filterActionTriggered()));
        }
    }

    cur_action = FilterAction::ActionPrepare;
    submenu = ctx_menu_.addMenu(FilterAction::actionName(cur_action));
    foreach (FilterAction::ActionType at, FilterAction::actionTypes()) {
        QMenu *subsubmenu = submenu->addMenu(FilterAction::actionTypeName(at));
        foreach (FilterAction::ActionDirection ad, FilterAction::actionDirections()) {
            FilterAction *fa = new FilterAction(subsubmenu, cur_action, at, ad);
            subsubmenu->addAction(fa);
            connect(fa, SIGNAL(triggered()), this, SLOT(filterActionTriggered()));
        }
    }

    cur_action = FilterAction::ActionFind;
    submenu = ctx_menu_.addMenu(FilterAction::actionName(cur_action));
    foreach (FilterAction::ActionDirection ad, FilterAction::actionDirections()) {
        FilterAction *fa = new FilterAction(submenu, cur_action, FilterAction::ActionTypePlain, ad);
        submenu->addAction(fa);
        connect(fa, SIGNAL(triggered()), this, SLOT(filterActionTriggered()));
    }

    cur_action = FilterAction::ActionColorize;
    submenu = ctx_menu_.addMenu(FilterAction::actionName(cur_action));
    foreach (FilterAction::ActionDirection ad, FilterAction::actionDirections()) {
        FilterAction *fa = new FilterAction(submenu, cur_action, FilterAction::ActionTypePlain, ad);
        submenu->addAction(fa);
        connect(fa, SIGNAL(triggered()), this, SLOT(filterActionTriggered()));
    }

    updateItems();
}

ConversationTreeWidget::~ConversationTreeWidget() {
    reset_conversation_table_data(&hash_);
}

// Callbacks for register_tap_listener
void ConversationTreeWidget::tapReset(void *conv_hash_ptr)
{
    conv_hash_t *hash = (conv_hash_t*)conv_hash_ptr;
    ConversationTreeWidget *conv_tree = static_cast<ConversationTreeWidget *>(hash->user_data);
    if (!conv_tree) return;

    conv_tree->clear();
    reset_conversation_table_data(&conv_tree->hash_);
}

void ConversationTreeWidget::tapDraw(void *conv_hash_ptr)
{
    conv_hash_t *hash = (conv_hash_t*)conv_hash_ptr;
    ConversationTreeWidget *conv_tree = static_cast<ConversationTreeWidget *>(hash->user_data);
    if (!conv_tree) return;

    conv_tree->updateItems();
}

QMap<FilterAction::ActionDirection, conv_direction_e> fad_to_cd_;

void ConversationTreeWidget::initDirectionMap()
{
    if (fad_to_cd_.size() > 0) {
        return;
    }

    fad_to_cd_[FilterAction::ActionDirectionAToFromB] = CONV_DIR_A_TO_FROM_B;
    fad_to_cd_[FilterAction::ActionDirectionAToB] = CONV_DIR_A_TO_B;
    fad_to_cd_[FilterAction::ActionDirectionAFromB] = CONV_DIR_A_FROM_B;
    fad_to_cd_[FilterAction::ActionDirectionAToFromAny] = CONV_DIR_A_TO_FROM_ANY;
    fad_to_cd_[FilterAction::ActionDirectionAToAny] = CONV_DIR_A_TO_ANY;
    fad_to_cd_[FilterAction::ActionDirectionAFromAny] = CONV_DIR_A_FROM_ANY;
    fad_to_cd_[FilterAction::ActionDirectionAnyToFromB] = CONV_DIR_ANY_TO_FROM_B;
    fad_to_cd_[FilterAction::ActionDirectionAnyToB] = CONV_DIR_ANY_TO_B;
    fad_to_cd_[FilterAction::ActionDirectionAnyFromB] = CONV_DIR_ANY_FROM_B;
}

void ConversationTreeWidget::updateItems() {
    title_ = proto_get_protocol_short_name(find_protocol_by_id(get_conversation_proto_id(table_)));

    if (hash_.conv_array && hash_.conv_array->len > 0) {
        title_.append(QString(" %1 %2").arg(UTF8_MIDDLE_DOT).arg(hash_.conv_array->len));
    }
    emit titleChanged(this, title_);

    if (!hash_.conv_array) {
        return;
    }

    setSortingEnabled(false);
    for (int i = topLevelItemCount(); i < (int) hash_.conv_array->len; i++) {
        ConversationTreeWidgetItem *ctwi = new ConversationTreeWidgetItem(this);
        conv_item_t *conv_item = &g_array_index(hash_.conv_array, conv_item_t, i);
        ctwi->setData(ci_col_, Qt::UserRole, qVariantFromValue(conv_item));
        addTopLevelItem(ctwi);

        for (int col = 0; col < columnCount(); col++) {
            switch (col) {
            case CONV_COLUMN_SRC_ADDR:
            case CONV_COLUMN_DST_ADDR:
            break;
            default:
                ctwi->setTextAlignment(col, Qt::AlignRight);
                break;
            }
        }
    }
    QTreeWidgetItemIterator iter(this);
    while (*iter) {
        ConversationTreeWidgetItem *ci = static_cast<ConversationTreeWidgetItem *>(*iter);
        ci->update(resolve_names_);
        ++iter;
    }
    setSortingEnabled(true);

    for (int col = 0; col < columnCount(); col++) {
        resizeColumnToContents(col);
    }
}

void ConversationTreeWidget::filterActionTriggered()
{
    ConversationTreeWidgetItem *ctwi = static_cast<ConversationTreeWidgetItem *>(currentItem());
    FilterAction *fa = qobject_cast<FilterAction *>(QObject::sender());

    if (!fa || !ctwi) {
        return;
    }

    conv_item_t *conv_item = ctwi->data(ci_col_, Qt::UserRole).value<conv_item_t *>();
    if (!conv_item) {
        return;
    }

    char* tmp_str = get_conversation_filter(conv_item, fad_to_cd_[fa->actionDirection()]);
    QString filter(tmp_str);

    g_free(tmp_str);
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
