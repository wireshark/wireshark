/* protocol_hierarchy_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "protocol_hierarchy_dialog.h"
#include <ui_protocol_hierarchy_dialog.h>

#include "cfile.h"

#include "ui/proto_hier_stats.h"

#include <ui/qt/utils/variant_pointer.h>

#include <wsutil/utf8_entities.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include "main_application.h"

#include <epan/proto.h>
#include <epan/disabled_protos.h>

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
const int pdus_col_ = 9;

struct addTreeNodeData {
    QSet<QString> *protos;
    QTreeWidgetItem *widget;
};

class ProtocolHierarchyTreeWidgetItem : public QTreeWidgetItem
{
public:
    ProtocolHierarchyTreeWidgetItem(QTreeWidgetItem *parent, ph_stats_node_t& ph_stats_node) :
        QTreeWidgetItem(parent),
        total_packets_(ph_stats_node.num_pkts_total),
        total_pdus_(ph_stats_node.num_pdus_total),
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
        ph_stats_t *ph_stats = VariantPointer<ph_stats_t>::asPtr(parent->treeWidget()->invisibleRootItem()->data(0, Qt::UserRole));

        if (!ph_stats || ph_stats->tot_packets < 1) return;
        percent_packets_ = total_packets_ * 100.0 / ph_stats->tot_packets;
        percent_bytes_ = total_bytes_ * 100.0 / ph_stats->tot_bytes;

        double seconds = ph_stats->last_time - ph_stats->first_time;

        if (seconds > 0.0) {
            bits_s_ = total_bytes_ * 8.0 / seconds;
            end_bits_s_ = last_bytes_ * 8.0 / seconds;
        }

        setText(protocol_col_, ph_stats_node.hfinfo->name);
        setToolTip(protocol_col_, QString("%1").arg(ph_stats_node.hfinfo->abbrev));
        setData(pct_packets_col_, Qt::UserRole, percent_packets_);
        setText(packets_col_, QString::number(total_packets_));
        setData(pct_bytes_col_, Qt::UserRole, percent_bytes_);
        setText(bytes_col_, QString::number(total_bytes_));
        setText(bandwidth_col_, seconds > 0.0 ? bits_s_to_qstring(bits_s_) : UTF8_EM_DASH);
        setText(end_packets_col_, QString::number(last_packets_));
        setText(end_bytes_col_, QString::number(last_bytes_));
        setText(end_bandwidth_col_, seconds > 0.0 ? bits_s_to_qstring(end_bits_s_) : UTF8_EM_DASH);
        setText(pdus_col_, QString::number(total_pdus_));
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
        case (pdus_col_):
            return total_pdus_;
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
        case pdus_col_:
            return total_pdus_ < other_phtwi.total_pdus_;
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
    unsigned total_pdus_;
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
        ui->hierStatsTreeWidget->invisibleRootItem()->setData(0, Qt::UserRole, VariantPointer<ph_stats_t>::asQVariant(ph_stats));
        addTreeNodeData atnd { &used_protos_, ui->hierStatsTreeWidget->invisibleRootItem() };
        g_node_children_foreach(ph_stats->stats_tree, G_TRAVERSE_ALL, addTreeNode, (void *)&atnd);
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

    QPushButton *copy_button = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ApplyRole);

    QMenu *copy_menu = new QMenu(copy_button);
    QAction *ca;
    ca = copy_menu->addAction(tr("as CSV"));
    ca->setToolTip(ui->actionCopyAsCsv->toolTip());
    connect(ca, &QAction::triggered, this, &ProtocolHierarchyDialog::on_actionCopyAsCsv_triggered);
    ca = copy_menu->addAction(tr("as YAML"));
    ca->setToolTip(ui->actionCopyAsYaml->toolTip());
    connect(ca, &QAction::triggered, this, &ProtocolHierarchyDialog::on_actionCopyAsYaml_triggered);
    copy_button->setMenu(copy_menu);
    connect(ca, SIGNAL(triggered()), this, SLOT(on_actionCopyAsYaml_triggered()));
    ca = copy_menu->addAction(tr("protocol short names"));
    ca->setToolTip(ui->actionCopyProtoList->toolTip());
    connect(ca, SIGNAL(triggered()), this, SLOT(on_actionCopyProtoList_triggered()));
    copy_button->setMenu(copy_menu);

    QPushButton *protos_button = ui->buttonBox->addButton(tr("Protocols"), QDialogButtonBox::ApplyRole);
    QMenu *protos_menu = new QMenu(protos_button);
    proto_disable_ = protos_menu->addAction(tr("Disable unused"));
    proto_disable_->setToolTip(ui->actionDisableProtos->toolTip());
    connect(proto_disable_, SIGNAL(triggered()), this, SLOT(on_actionDisableProtos_triggered()));
    proto_revert_ = protos_menu->addAction(tr("Revert changes"));
    proto_revert_->setToolTip(ui->actionRevertProtos->toolTip());
    connect(proto_revert_, SIGNAL(triggered()), this, SLOT(on_actionRevertProtos_triggered()));
    protos_button->setMenu(protos_menu);

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

void ProtocolHierarchyDialog::addTreeNode(GNode *node, void *data)
{
    ph_stats_node_t *stats = (ph_stats_node_t *)node->data;
    if (!stats) return;

    addTreeNodeData *atndp = (addTreeNodeData *)data;
    QTreeWidgetItem *parent_ti = atndp->widget;
    if (!parent_ti) return;

    atndp->protos->insert(QString(stats->hfinfo->abbrev));

    ProtocolHierarchyTreeWidgetItem *phti = new ProtocolHierarchyTreeWidgetItem(parent_ti, *stats);
    addTreeNodeData atnd { atndp->protos, phti };

    g_node_children_foreach(node, G_TRAVERSE_ALL, addTreeNode, (void *)&atnd);

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

    proto_revert_->setEnabled(enabled_protos_unsaved_changes());

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
            } else if (v.userType() == QMetaType::QString) {
                separated_value << QString("\"%1\"").arg(v.toString());
            } else {
                separated_value << v.toString();
            }
        }
        stream << separated_value.join(",") << '\n';

        if (!first) ++iter;
        first = false;
    }
    mainApp->clipboard()->setText(stream.readAll());
}

void ProtocolHierarchyDialog::on_actionCopyAsYaml_triggered()
{
    QString yaml;
    QTextStream stream(&yaml, QIODevice::Text);
    QTreeWidgetItemIterator iter(ui->hierStatsTreeWidget);
    bool first = true;

    stream << "---" << '\n';
    while (*iter) {
        QTreeWidgetItem *item = first ? NULL : (*iter);

        stream << "-" << '\n';
        foreach (QVariant v, protoHierRowData(item)) {
            stream << " - " << v.toString() << '\n';
        }
        if (!first) ++iter;
        first = false;
    }
    mainApp->clipboard()->setText(stream.readAll());
}

void ProtocolHierarchyDialog::on_actionCopyProtoList_triggered()
{
    QString plist;
    QTextStream stream(&plist, QIODevice::Text);
    bool first = true;
    QSetIterator<QString> iter(used_protos_);
    while (iter.hasNext()) {
        if (!first) stream << ',';
        stream << iter.next();
        first = false;
    }
    mainApp->clipboard()->setText(stream.readAll());
}

void ProtocolHierarchyDialog::on_actionDisableProtos_triggered()
{
    proto_disable_all();

    QSetIterator<QString> iter(used_protos_);
    while (iter.hasNext()) {
        proto_enable_proto_by_name(iter.next().toStdString().c_str());
    }
    /* Note that we aren't saving the changes here; they only apply
     * to the current dissection.
     * (Though if the user goes to the Enabled Protocols dialog and
     * makes changes, these changes as well as the user's will be saved.)
     */
    proto_revert_->setEnabled(enabled_protos_unsaved_changes());

    QString hint = "<small><i>"
        + tr("Unused protocols have been disabled.")
        + "</i></small>";
    ui->hintLabel->setText(hint);

    // If we've done everything right, nothing should change.
    //wsApp->emitAppSignal(WiresharkApplication::PacketDissectionChanged);
}

void ProtocolHierarchyDialog::on_actionRevertProtos_triggered()
{
    proto_reenable_all();
    read_enabled_and_disabled_lists();

    proto_revert_->setEnabled(enabled_protos_unsaved_changes());
    QString hint = "<small><i>"
        + tr("Protocol changes have been reverted.")
        + "</i></small>";
    ui->hintLabel->setText(hint);

    // If we've done everything right, nothing should change.
    //wsApp->emitAppSignal(WiresharkApplication::PacketDissectionChanged);
}

void ProtocolHierarchyDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_STATS_PROTO_HIERARCHY_DIALOG);
}
