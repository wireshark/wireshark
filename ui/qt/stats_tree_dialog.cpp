/* stats_tree_dialog.cpp
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

#include "stats_tree_dialog.h"

#include "file.h"

#include "epan/stats_tree_priv.h"

#include "qt_ui_utils.h"

#include <QHeaderView>
#include <QMessageBox>
#include <QTreeWidget>
#include <QTreeWidgetItemIterator>

const int item_col_ = 0;

Q_DECLARE_METATYPE(stat_node *)

const int sn_type_ = 1000;
class StatsTreeWidgetItem : public QTreeWidgetItem
{
public:
    StatsTreeWidgetItem(int type = sn_type_) : QTreeWidgetItem (type)
    {
        for (int col = 1; col < columnCount(); col++) {
            setTextAlignment(col, Qt::AlignRight);
        }
    }
    bool operator< (const QTreeWidgetItem &other) const
    {
        stat_node *thisnode = data(item_col_, Qt::UserRole).value<stat_node *>();
        stat_node *othernode = other.data(item_col_, Qt::UserRole).value<stat_node *>();
        Qt::SortOrder order = treeWidget()->header()->sortIndicatorOrder();
        int result;

        result = stats_tree_sort_compare(thisnode, othernode, treeWidget()->sortColumn(),
                                         order==Qt::DescendingOrder);
        if (order==Qt::DescendingOrder) {
            result = -result;
        }
        return result < 0;
    }
};

StatsTreeDialog::StatsTreeDialog(QWidget &parent, CaptureFile &cf, const char *cfg_abbr) :
    TapParameterDialog(parent, cf),
    st_(NULL),
    st_cfg_(NULL)
{
    loadGeometry(800, height(), cfg_abbr);
    st_cfg_ = stats_tree_get_cfg_by_abbr(cfg_abbr);
    memset(&cfg_pr_, 0, sizeof(struct _tree_cfg_pres));

    if (!st_cfg_) {
        QMessageBox::critical(this, tr("Configuration not found"),
                             tr("Unable to find configuration for %1.").arg(cfg_abbr));
        QMetaObject::invokeMethod(this, "reject", Qt::QueuedConnection);
    }
}

StatsTreeDialog::~StatsTreeDialog()
{
    if (st_) {
        stats_tree_free(st_);
    }
}

// Adds a node to the QTreeWidget
// Note: We're passing QTreeWidgetItem pointers as st_node_pres pointers
void StatsTreeDialog::setupNode(stat_node* node)
{
    if (!node || !node->st || !node->st->cfg || !node->st->cfg->pr
            || !node->st->cfg->pr->st_dlg) return;
    StatsTreeDialog *st_dlg = node->st->cfg->pr->st_dlg;

    QTreeWidgetItem *ti = new StatsTreeWidgetItem(), *parent = NULL;

    ti->setText(item_col_, node->name);
    ti->setData(item_col_, Qt::UserRole, qVariantFromValue(node));
    node->pr = (st_node_pres *) ti;
    if (node->parent && node->parent->pr) {
        parent = (QTreeWidgetItem *) node->parent->pr;
        parent->setExpanded(true);
    }
    if (parent) {
        parent->addChild(ti);
    } else {
        st_dlg->statsTreeWidget()->addTopLevelItem(ti);
    }
    st_dlg->statsTreeWidget()->resizeColumnToContents(item_col_);
}

void StatsTreeDialog::fillTree()
{
    if (!st_cfg_ || file_closed_) return;

    QString display_name = gchar_free_to_qstring(stats_tree_get_displayname(st_cfg_->name));

    // The GTK+ UI appends "Stats Tree" to the window title. If we do the same
    // here we should expand the name completely, e.g. to "Statistics Tree".
    setWindowSubtitle(display_name);

    st_cfg_->pr = &cfg_pr_;
    cfg_pr_.st_dlg = this;

    if (st_) {
        stats_tree_free(st_);
    }
    QString display_filter = displayFilter();
    st_ = stats_tree_new(st_cfg_, NULL, display_filter.toUtf8().constData());

    // Add number of columns for this stats_tree
    QStringList header_labels;
    for (int count = 0; count<st_->num_columns; count++) {
        header_labels.push_back(stats_tree_get_column_name(count));
    }
    statsTreeWidget()->setColumnCount(header_labels.count());
    statsTreeWidget()->setHeaderLabels(header_labels);
    statsTreeWidget()->setSortingEnabled(false);

    if (!registerTapListener(st_cfg_->tapname,
                             st_,
                             st_->filter,
                             st_cfg_->flags,
                             resetTap,
                             stats_tree_packet,
                             drawTreeItems)) {
        reject(); // XXX Stay open instead?
        return;
    }

    cap_file_.retapPackets();
    drawTreeItems(st_);

    statsTreeWidget()->setSortingEnabled(true);
    removeTapListeners();

    st_cfg_->pr = NULL;
}

void StatsTreeDialog::resetTap(void *st_ptr)
{
    stats_tree *st = (stats_tree *) st_ptr;
    if (!st || !st->cfg || !st->cfg->pr || !st->cfg->pr->st_dlg) return;

    st->cfg->pr->st_dlg->statsTreeWidget()->clear();
    st->cfg->init(st);
}

void StatsTreeDialog::drawTreeItems(void *st_ptr)
{
    stats_tree *st = (stats_tree *) st_ptr;
    if (!st || !st->cfg || !st->cfg->pr || !st->cfg->pr->st_dlg) return;
    TapParameterDialog *st_dlg = st->cfg->pr->st_dlg;
    QTreeWidgetItemIterator iter(st_dlg->statsTreeWidget());
    int node_count = 0;

    while (*iter) {
        stat_node *node = (*iter)->data(item_col_, Qt::UserRole).value<stat_node *>();
        if (node) {
            gchar **valstrs = stats_tree_get_values_from_node(node);
            for (int count = 0; count<st->num_columns; count++) {
                (*iter)->setText(count,valstrs[count]);
                g_free(valstrs[count]);
            }
            (*iter)->setExpanded((node->parent==(&st->root)) &&
                                 (!(node->st_flags&ST_FLG_DEF_NOEXPAND)));
            g_free(valstrs);
        }
        node_count++;
        ++iter;
    }

    st_dlg->drawTreeItems();
}

QByteArray StatsTreeDialog::getTreeAsString(st_format_type format)
{
    GString *str_tree;

    // produce output in selected format using current sort information
    str_tree = stats_tree_format_as_str(st_, format, statsTreeWidget()->sortColumn(),
                statsTreeWidget()->header()->sortIndicatorOrder()==Qt::DescendingOrder);

    return gstring_free_to_qbytearray(str_tree);
}

extern "C" {
void
register_tap_listener_qt_stats_tree_stat(void)
{
    stats_tree_presentation(NULL,
                StatsTreeDialog::setupNode,
                NULL, NULL);
}
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
