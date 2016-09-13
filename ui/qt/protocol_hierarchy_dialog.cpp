/* protocol_hierarchy_dialog.cpp
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

#include "protocol_hierarchy_dialog.h"
#include <ui_protocol_hierarchy_dialog.h>

#include "cfile.h"

#include "ui/proto_hier_stats.h"
#include <wsutil/utf8_entities.h>

#include "qt_ui_utils.h"
#include "wireshark_application.h"

#include <QClipboard>
#include <QPushButton>
#include <QTextStream>
#include <QTreeWidgetItemIterator>

/*
 * @file Protocol Hierarchy Statistics dialog
 *
 * Displays tree of protocols with various statistics
 * Allows filtering on tree items
 */

// To do:
// - Make "Copy as YAML" output a tree?
// - Add time series data to ph_stats_node_t and draw sparklines.

const int protocol_col_ = 0;
const int pct_packets_col_ = 1;
const int packets_col_ = 2;
const int pct_bytes_col_ = 3;
const int bytes_col_ = 4;
const int bandwidth_col_ = 5;
const int end_packets_col_ = 6;
const int end_bytes_col_ = 7;
const int end_bandwidth_col_ = 8;

Q_DECLARE_METATYPE(ph_stats_t*)

class ProtocolHierarchyTreeWidgetItem : public QTreeWidgetItem
{
public:
    ProtocolHierarchyTreeWidgetItem(QTreeWidgetItem *parent, ph_stats_node_t& ph_stats_node) :
        QTreeWidgetItem(parent),
        total_packets_(ph_stats_node.num_pkts_total),
        last_packets_(ph_stats_node.num_pkts_last),
        total_bytes_(ph_stats_node.num_bytes_total),
        last_bytes_(ph_stats_node.num_bytes_last),
        percent_packets_(0),
        percent_bytes_(0),
        bits_s_(0.0),
        end_bits_s_(0.0)
    {
        filter_name_ = ph_stats_node.hfinfo->abbrev;

        if (!parent) return;
        ph_stats_t *ph_stats = parent->treeWidget()->invisibleRootItem()->data(0, Qt::UserRole).value<ph_stats_t*>();

        if (!ph_stats || ph_stats->tot_packets < 1) return;
        percent_packets_ = total_packets_ * 100.0 / ph_stats->tot_packets;
        percent_bytes_ = total_bytes_ * 100.0 / ph_stats->tot_bytes;

        double seconds = ph_stats->last_time - ph_stats->first_time;

        if (seconds > 0.0) {
            bits_s_ = total_bytes_ * 8.0 / seconds;
            end_bits_s_ = last_bytes_ * 8.0 / seconds;
        }

        setText(protocol_col_, ph_stats_node.hfinfo->name);
        setData(pct_packets_col_, Qt::UserRole, percent_packets_);
        setText(packets_col_, QString::number(total_packets_));
        setData(pct_bytes_col_, Qt::UserRole, percent_bytes_);
        setText(bytes_col_, QString::number(total_bytes_));
        setText(bandwidth_col_, seconds > 0.0 ? bits_s_to_qstring(bits_s_) : UTF8_EM_DASH);
        setText(end_packets_col_, QString::number(last_packets_));
        setText(end_bytes_col_, QString::number(last_bytes_));
        setText(end_bandwidth_col_, seconds > 0.0 ? bits_s_to_qstring(end_bits_s_) : UTF8_EM_DASH);
    }

    // Return a QString, int, double, or invalid QVariant representing the raw column data.
    QVariant colData(int col) const {
        switch(col) {
        case protocol_col_:
            return text(col);
        case (pct_packets_col_):
            return percent_packets_;
        case (packets_col_):
            return total_packets_;
        case (pct_bytes_col_):
            return percent_bytes_;
        case (bytes_col_):
            return total_bytes_;
        case (bandwidth_col_):
            return bits_s_;
        case (end_packets_col_):
            return last_packets_;
        case (end_bytes_col_):
            return last_bytes_;
        case (end_bandwidth_col_):
            return end_bits_s_;
        default:
            break;
        }
        return QVariant();
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        const ProtocolHierarchyTreeWidgetItem &other_phtwi = dynamic_cast<const ProtocolHierarchyTreeWidgetItem&>(other);

        switch (treeWidget()->sortColumn()) {
        case pct_packets_col_:
            return percent_packets_ < other_phtwi.percent_packets_;
        case packets_col_:
            return total_packets_ < other_phtwi.total_packets_;
        case pct_bytes_col_:
            return percent_packets_ < other_phtwi.percent_packets_;
        case bytes_col_:
            return total_bytes_ < other_phtwi.total_bytes_;
        case bandwidth_col_:
            return bits_s_ < other_phtwi.bits_s_;
        case end_packets_col_:
            return last_packets_ < other_phtwi.last_packets_;
        case end_bytes_col_:
            return last_bytes_ < other_phtwi.last_bytes_;
        case end_bandwidth_col_:
            return end_bits_s_ < other_phtwi.end_bits_s_;
        default:
            break;
        }

        // Fall back to string comparison
        return QTreeWidgetItem::operator <(other);
    }

    const QString filterName(void) { return filter_name_; }

private:
    QString filter_name_;
    unsigned total_packets_;
    unsigned last_packets_;
    unsigned total_bytes_;
    unsigned last_bytes_;

    double percent_packets_;
    double percent_bytes_;
    double bits_s_;
    double end_bits_s_;
};

ProtocolHierarchyDialog::ProtocolHierarchyDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::ProtocolHierarchyDialog)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 4 / 5);
    setWindowSubtitle(tr("Protocol Hierarchy Statistics"));

    ui->hierStatsTreeWidget->setItemDelegateForColumn(pct_packets_col_, &percent_bar_delegate_);
    ui->hierStatsTreeWidget->setItemDelegateForColumn(pct_bytes_col_, &percent_bar_delegate_);
    ph_stats_t *ph_stats = ph_stats_new(cap_file_.capFile());
    if (ph_stats) {
        ui->hierStatsTreeWidget->invisibleRootItem()->setData(0, Qt::UserRole, qVariantFromValue(ph_stats));
        g_node_children_foreach(ph_stats->stats_tree, G_TRAVERSE_ALL, addTreeNode, ui->hierStatsTreeWidget->invisibleRootItem());
        ph_stats_free(ph_stats);
    }

    ui->hierStatsTreeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->hierStatsTreeWidget, SIGNAL(customContextMenuRequested(QPoint)),
                SLOT(showProtoHierMenu(QPoint)));

    ui->hierStatsTreeWidget->setSortingEnabled(true);
    ui->hierStatsTreeWidget->expandAll();

    for (int i = 0; i < ui->hierStatsTreeWidget->columnCount(); i++) {
        ui->hierStatsTreeWidget->resizeColumnToContents(i);
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

    FilterAction *fa = new FilterAction(&ctx_menu_, FilterAction::ActionFind);
    ctx_menu_.addAction(fa);
    connect(fa, SIGNAL(triggered()), this, SLOT(filterActionTriggered()));

    fa = new FilterAction(&ctx_menu_, FilterAction::ActionColorize);
    ctx_menu_.addAction(fa);
    connect(fa, SIGNAL(triggered()), this, SLOT(filterActionTriggered()));

    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionCopyAsCsv);
    ctx_menu_.addAction(ui->actionCopyAsYaml);

    copy_button_ = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ApplyRole);

    QMenu *copy_menu = new QMenu();
    QAction *ca;
    ca = copy_menu->addAction(tr("as CSV"));
    ca->setToolTip(ui->actionCopyAsCsv->toolTip());
    connect(ca, SIGNAL(triggered()), this, SLOT(on_actionCopyAsCsv_triggered()));
    ca = copy_menu->addAction(tr("as YAML"));
    ca->setToolTip(ui->actionCopyAsYaml->toolTip());
    connect(ca, SIGNAL(triggered()), this, SLOT(on_actionCopyAsYaml_triggered()));
    copy_button_->setMenu(copy_menu);

    QPushButton *close_bt = ui->buttonBox->button(QDialogButtonBox::Close);
    if (close_bt) {
        close_bt->setDefault(true);
    }

    display_filter_ = cap_file_.capFile()->dfilter;
    updateWidgets();
}

ProtocolHierarchyDialog::~ProtocolHierarchyDialog()
{
    delete ui;
}

void ProtocolHierarchyDialog::showProtoHierMenu(QPoint pos)
{
    bool enable = ui->hierStatsTreeWidget->currentItem() != NULL && !file_closed_ ? true : false;

    foreach (QMenu *submenu, ctx_menu_.findChildren<QMenu*>()) {
        submenu->setEnabled(enable);
    }
    foreach (QAction *action, ctx_menu_.actions()) {
        if (action != ui->actionCopyAsCsv && action != ui->actionCopyAsYaml) {
            action->setEnabled(enable);
        }
    }

    ctx_menu_.popup(ui->hierStatsTreeWidget->viewport()->mapToGlobal(pos));
}

void ProtocolHierarchyDialog::filterActionTriggered()
{
    ProtocolHierarchyTreeWidgetItem *phti = static_cast<ProtocolHierarchyTreeWidgetItem *>(ui->hierStatsTreeWidget->currentItem());
    FilterAction *fa = qobject_cast<FilterAction *>(QObject::sender());

    if (!fa || !phti) {
        return;
    }
    QString filter_name(phti->filterName());

    emit filterAction(filter_name, fa->action(), fa->actionType());
}

void ProtocolHierarchyDialog::addTreeNode(GNode *node, gpointer data)
{
    ph_stats_node_t *stats = (ph_stats_node_t *)node->data;
    if (!stats) return;

    QTreeWidgetItem *parent_ti = static_cast<QTreeWidgetItem *>(data);
    if (!parent_ti) return;

    ProtocolHierarchyTreeWidgetItem *phti = new ProtocolHierarchyTreeWidgetItem(parent_ti, *stats);

    g_node_children_foreach(node, G_TRAVERSE_ALL, addTreeNode, phti);

}

void ProtocolHierarchyDialog::updateWidgets()
{
    QString hint = "<small><i>";
    if (display_filter_.isEmpty()) {
        hint += tr("No display filter.");
    } else {
        hint += tr("Display filter: %1").arg(display_filter_);
    }
    hint += "</i></small>";
    ui->hintLabel->setText(hint);

    WiresharkDialog::updateWidgets();
}

QList<QVariant> ProtocolHierarchyDialog::protoHierRowData(QTreeWidgetItem *item) const
{
    QList<QVariant> row_data;

    for (int col = 0; col < ui->hierStatsTreeWidget->columnCount(); col++) {
        if (!item) {
            row_data << ui->hierStatsTreeWidget->headerItem()->text(col);
        } else {
            ProtocolHierarchyTreeWidgetItem *phti = static_cast<ProtocolHierarchyTreeWidgetItem*>(item);
            if (phti) {
                row_data << phti->colData(col);
            }
        }
    }
    return row_data;
}

void ProtocolHierarchyDialog::on_actionCopyAsCsv_triggered()
{
    QString csv;
    QTextStream stream(&csv, QIODevice::Text);
    QTreeWidgetItemIterator iter(ui->hierStatsTreeWidget);
    bool first = true;

    while (*iter) {
        QStringList separated_value;
        QTreeWidgetItem *item = first ? NULL : (*iter);

        foreach (QVariant v, protoHierRowData(item)) {
            if (!v.isValid()) {
                separated_value << "\"\"";
            } else if ((int) v.type() == (int) QMetaType::QString) {
                separated_value << QString("\"%1\"").arg(v.toString());
            } else {
                separated_value << v.toString();
            }
        }
        stream << separated_value.join(",") << endl;

        if (!first) ++iter;
        first = false;
    }
    wsApp->clipboard()->setText(stream.readAll());
}

void ProtocolHierarchyDialog::on_actionCopyAsYaml_triggered()
{
    QString yaml;
    QTextStream stream(&yaml, QIODevice::Text);
    QTreeWidgetItemIterator iter(ui->hierStatsTreeWidget);
    bool first = true;

    stream << "---" << endl;
    while (*iter) {
        QTreeWidgetItem *item = first ? NULL : (*iter);

        stream << "-" << endl;
        foreach (QVariant v, protoHierRowData(item)) {
            stream << " - " << v.toString() << endl;
        }
        if (!first) ++iter;
        first = false;
    }
    wsApp->clipboard()->setText(stream.readAll());
}

void ProtocolHierarchyDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_STATS_PROTO_HIERARCHY_DIALOG);
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
