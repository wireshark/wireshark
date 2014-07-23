/* conversation_tree_widget.cpp
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

#include "conversation_tree_widget.h"

#include <epan/addr_resolv.h>
#include <epan/to_str.h>

#include <epan/dissectors/packet-eth.h>
#include <epan/dissectors/packet-fc.h>
#include <epan/dissectors/packet-fddi.h>
#include <epan/dissectors/packet-ip.h>
#include <epan/dissectors/packet-ipv6.h>
#include <epan/dissectors/packet-ipx.h>
#include <epan/dissectors/packet-jxta.h>
#include <epan/dissectors/packet-ncp-int.h>
#include <epan/dissectors/packet-rsvp.h>
#include <epan/dissectors/packet-sctp.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-tr.h>
#include <epan/dissectors/packet-udp.h>
#include <epan/dissectors/packet-ieee80211.h>

#include <ui/utf8_entities.h>

#include <wsutil/str_util.h>

#include "wireshark_application.h"

#include "qt_ui_utils.h"

#include <QContextMenuEvent>
#include <QTreeWidgetItemIterator>

// QTreeWidget subclass that allows tapping

// Minimum bandwidth calculation duration
// https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8703
const double min_bw_calc_duration_ = 5 / 1000.0; // seconds
const QString bps_na_ = QObject::tr("N/A");

QMap<FilterAction::ActionDirection, conv_direction_e> fad_to_cd_;

// QTreeWidgetItem subclass that allows sorting
const int ci_col_ = 0;
const int pkts_col_ = 1;
class ConversationTreeWidgetItem : public QTreeWidgetItem
{
public:
    ConversationTreeWidgetItem(QTreeWidget *tree) : QTreeWidgetItem(tree)  {}
    ConversationTreeWidgetItem(QTreeWidget * parent, const QStringList & strings)
                   : QTreeWidgetItem (parent,strings)  {}

    // Set column text to its cooked representation.
    void update(gboolean resolve_names) {
        conv_item_t *conv_item = data(ci_col_, Qt::UserRole).value<conv_item_t *>();
        bool ok;
        quint64 cur_packets = data(pkts_col_, Qt::UserRole).toULongLong(&ok);

        if (!conv_item) {
            return;
        }

        quint64 packets = conv_item->tx_frames + conv_item->rx_frames;
        if (ok && cur_packets == packets) {
            return;
        }

        setText(CONV_COLUMN_SRC_ADDR, get_conversation_address(&conv_item->src_address, resolve_names));
        setText(CONV_COLUMN_SRC_PORT, get_conversation_port(conv_item->src_port, conv_item->ptype, resolve_names));
        setText(CONV_COLUMN_DST_ADDR, get_conversation_address(&conv_item->dst_address, resolve_names));
        setText(CONV_COLUMN_DST_PORT, get_conversation_port(conv_item->dst_port, conv_item->ptype, resolve_names));

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

    // Return a string, qulonglong, double, or invalid QVariant representing the raw column data.
    QVariant colData(int col, bool resolve_names) {
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
            return get_conversation_address(&conv_item->src_address, resolve_names);
        case CONV_COLUMN_SRC_PORT:
            if (resolve_names) {
                return get_conversation_port(conv_item->src_port, conv_item->ptype, resolve_names);
            } else {
                return quint32(conv_item->src_port);
            }
        case CONV_COLUMN_DST_ADDR:
            return get_conversation_address(&conv_item->dst_address, resolve_names);
        case CONV_COLUMN_DST_PORT:
            if (resolve_names) {
                return get_conversation_port(conv_item->dst_port, conv_item->ptype, resolve_names);
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

private:
};

ConversationTreeWidget::ConversationTreeWidget(QWidget *parent, register_ct_t* table) :
    QTreeWidget(parent),
    table_(table),
    hash_(),
    resolve_names_(false)
{
    setRootIsDecorated(false);
    sortByColumn(0, Qt::AscendingOrder);

    setColumnCount(CONV_NUM_COLUMNS);

    for (int i = 0; i < CONV_NUM_COLUMNS; i++) {
        headerItem()->setText(i, column_titles[i]);
    }

    if (get_conversation_hide_ports(table_)) {
        hideColumn(CONV_COLUMN_SRC_PORT);
        hideColumn(CONV_COLUMN_DST_PORT);
    } else if (!strcmp(proto_get_protocol_filter_name(get_conversation_proto_id(table_)), "ncp")) {
        headerItem()->setText(CONV_COLUMN_SRC_PORT, conn_a_title);
        headerItem()->setText(CONV_COLUMN_DST_PORT, conn_b_title);
    }

    int one_en = fontMetrics().height() / 2;
    for (int i = 0; i < CONV_NUM_COLUMNS; i++) {
        switch (i) {
        case CONV_COLUMN_SRC_ADDR:
        case CONV_COLUMN_DST_ADDR:
            setColumnWidth(i, one_en * strlen("000.000.000.000"));
            break;
        case CONV_COLUMN_SRC_PORT:
        case CONV_COLUMN_DST_PORT:
            setColumnWidth(i, one_en * strlen("000000"));
            break;
        case CONV_COLUMN_PACKETS:
        case CONV_COLUMN_PKT_AB:
        case CONV_COLUMN_PKT_BA:
            setColumnWidth(i, one_en * strlen("00,000"));
            break;
        case CONV_COLUMN_BYTES:
        case CONV_COLUMN_BYTES_AB:
        case CONV_COLUMN_BYTES_BA:
            setColumnWidth(i, one_en * strlen("000,000"));
            break;
        case CONV_COLUMN_START:
            setColumnWidth(i, one_en * strlen("00.000"));
            break;
        case CONV_COLUMN_DURATION:
            setColumnWidth(i, one_en * strlen("00.000000"));
            break;
        case CONV_COLUMN_BPS_AB:
        case CONV_COLUMN_BPS_BA:
            setColumnWidth(i, one_en * strlen("000 k"));
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

    connect(wsApp, SIGNAL(addressResolutionChanged()), this, SLOT(updateItems()));
}

ConversationTreeWidget::~ConversationTreeWidget() {
    remove_tap_listener(&hash_);
    reset_conversation_table_data(&hash_);
}

// Callbacks for register_tap_listener
void ConversationTreeWidget::tapReset(void *conv_tree_ptr)
{
    conv_hash_t *hash = (conv_hash_t*)conv_tree_ptr;
    ConversationTreeWidget *conv_tree = static_cast<ConversationTreeWidget *>(hash->user_data);
    if (!conv_tree) return;

    conv_tree->clear();
    reset_conversation_table_data(&conv_tree->hash_);
}

void ConversationTreeWidget::tapDraw(void *conv_tree_ptr)
{
    conv_hash_t *hash = (conv_hash_t*)conv_tree_ptr;
    ConversationTreeWidget *conv_tree = static_cast<ConversationTreeWidget *>(hash->user_data);
    if (!conv_tree) return;

    conv_tree->updateItems();
}

QList<QVariant> ConversationTreeWidget::rowData(int row)
{
    QList<QVariant> row_data;

    for (int col = 0; col < columnCount(); col++) {
        if (isColumnHidden(col) || row >= topLevelItemCount()) {
            continue;
        }
        if (row < 0) {
            row_data << headerItem()->text(col);
        } else {
            ConversationTreeWidgetItem *ci = static_cast<ConversationTreeWidgetItem *>(topLevelItem(row));
            if (ci) {
                row_data << ci->colData(col, resolve_names_);
            }
        }
    }
    return row_data;
}

void ConversationTreeWidget::setNameResolutionEnabled(bool enable)
{
    if (resolve_names_ != enable) {
        resolve_names_ = enable;
        updateItems();
    }
}

void ConversationTreeWidget::contextMenuEvent(QContextMenuEvent *event)
{
    bool enable = selectedItems().count() > 0 ? true : false;

    foreach (QMenu *submenu, ctx_menu_.findChildren<QMenu*>()) {
        submenu->setEnabled(enable);
    }

    ctx_menu_.exec(event->globalPos());
}

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
    if (selectedItems().count() < 1) {
        return;
    }

    FilterAction *fa = qobject_cast<FilterAction *>(QObject::sender());
    ConversationTreeWidgetItem *ctwi = static_cast<ConversationTreeWidgetItem *>(selectedItems()[0]);
    if (!fa || !ctwi) {
        return;
    }

    conv_item_t *conv_item = ctwi->data(ci_col_, Qt::UserRole).value<conv_item_t *>();
    if (!conv_item) {
        return;
    }

    QString filter = get_conversation_filter(conv_item, fad_to_cd_[fa->actionDirection()]);
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
