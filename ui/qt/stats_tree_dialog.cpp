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
#include "ui_stats_tree_dialog.h"

#include "file.h"

#include "epan/stats_tree_priv.h"
#include "wsutil/file_util.h"
#include "ui/last_open_dir.h"

#include "wireshark_application.h"

#include <QClipboard>
#include <QMessageBox>
#include <QTreeWidget>
#include <QTreeWidgetItemIterator>
#include <QFileDialog>

// The GTK+ counterpart uses tap_param_dlg, which we don't use. If we
// need tap parameters we should probably create a TapParameterDialog
// class based on QDialog and subclass it here.

// To do:
// - Add help
// - Update to match bug 9452 / r53657

#include <QDebug>

const int item_col_     = 0;

const int expand_all_threshold_ = 100; // Arbitrary

Q_DECLARE_METATYPE(stat_node *)

class StatsTreeWidgetItem : public QTreeWidgetItem
{
public:
    StatsTreeWidgetItem(int type = Type) : QTreeWidgetItem (type) {}
    bool operator< (const QTreeWidgetItem &other) const
    {
        stat_node *thisnode = data(item_col_, Qt::UserRole).value<stat_node *>();
        stat_node *othernode = other.data(item_col_, Qt::UserRole).value<stat_node *>();
        Qt::SortOrder order = treeWidget()->header()->sortIndicatorOrder();
        int result;

        result = stats_tree_sort_compare(thisnode, othernode, treeWidget()->sortColumn(),
                                         order==Qt::DescendingOrder);
        if (order==Qt::DescendingOrder) {
            result= -result;
        }
        return result < 0;
    }
};

StatsTreeDialog::StatsTreeDialog(QWidget *parent, capture_file *cf, const char *cfg_abbr) :
    QDialog(parent),
    ui(new Ui::StatsTreeDialog),
    st_(NULL),
    st_cfg_(NULL),
    cap_file_(cf)
{
    ui->setupUi(this);
    st_cfg_ = stats_tree_get_cfg_by_abbr(cfg_abbr);

    if (!st_cfg_) {
        QMessageBox::critical(this, tr("Configuration not found"),
                             tr("Unable to find configuration for %1.").arg(cfg_abbr));
        QMetaObject::invokeMethod(this, "reject", Qt::QueuedConnection);
    }

    ui->statsTreeWidget->addAction(ui->actionCopyToClipboard);
    ui->statsTreeWidget->addAction(ui->actionSaveAs);
    ui->statsTreeWidget->setContextMenuPolicy(Qt::ActionsContextMenu);

    QPushButton *button;
    button = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    connect(button, SIGNAL(clicked()), this, SLOT(on_actionCopyToClipboard_triggered()));

    button = ui->buttonBox->addButton(tr("Save as..."), QDialogButtonBox::ActionRole);
    connect(button, SIGNAL(clicked()), this, SLOT(on_actionSaveAs_triggered()));

    fillTree();
}

StatsTreeDialog::~StatsTreeDialog()
{
    if (st_) {
        stats_tree_free(st_);
    }
    delete ui;
}

void StatsTreeDialog::setCaptureFile(capture_file *cf)
{
    if (!cf) { // We only want to know when the file closes.
        cap_file_ = NULL;
        ui->displayFilterLineEdit->setEnabled(false);
        ui->applyFilterButton->setEnabled(false);
    }
}

void StatsTreeDialog::fillTree()
{
    GString *error_string;
    if (!st_cfg_) return;

    gchar* display_name_temp = stats_tree_get_displayname(st_cfg_->name);
    QString display_name(display_name_temp);
    g_free(display_name_temp);

    setWindowTitle(display_name + tr(" Stats Tree"));

    if (!cap_file_) return;

    if (st_cfg_->in_use) {
        QMessageBox::warning(this, tr("%1 already open").arg(display_name),
                             tr("Each type of tree can only be generated one at time."));
        reject();
    }

    st_cfg_->in_use = TRUE;
    st_cfg_->pr = &cfg_pr_;
    cfg_pr_.st_dlg = this;

    if (st_) {
        stats_tree_free(st_);
    }
    st_ = stats_tree_new(st_cfg_, NULL, ui->displayFilterLineEdit->text().toUtf8().constData());

    // Add number of columns for this stats_tree
    QStringList headerLabels;
    for (int count = 0; count<st_->num_columns; count++) {
        headerLabels.push_back(stats_tree_get_column_name(count));
    }
    ui->statsTreeWidget->setColumnCount(headerLabels.count());
    ui->statsTreeWidget->setHeaderLabels(headerLabels);
    resize(st_->num_columns*80+80, height());
    for (int count = 0; count<st_->num_columns; count++) {
        headerLabels.push_back(stats_tree_get_column_name(count));
    }
    ui->statsTreeWidget->setSortingEnabled(false);

    error_string = register_tap_listener(st_cfg_->tapname,
                          st_,
                          st_->filter,
                          st_cfg_->flags,
                          resetTap,
                          stats_tree_packet,
                          drawTreeItems);
    if (error_string) {
        QMessageBox::critical(this, tr("%1 failed to attach to tap").arg(display_name),
                             error_string->str);
        g_string_free(error_string, TRUE);
        reject();
    }

    cf_retap_packets(cap_file_);
    drawTreeItems(st_);

    ui->statsTreeWidget->setSortingEnabled(true);
    remove_tap_listener(st_);

    st_cfg_->in_use = FALSE;
    st_cfg_->pr = NULL;
}

void StatsTreeDialog::resetTap(void *st_ptr)
{
    stats_tree *st = (stats_tree *) st_ptr;
    if (!st || !st->cfg || !st->cfg->pr || !st->cfg->pr->st_dlg) return;

    st->cfg->pr->st_dlg->ui->statsTreeWidget->clear();
    st->cfg->init(st);
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
        st_dlg->ui->statsTreeWidget->addTopLevelItem(ti);
    }
    st_dlg->ui->statsTreeWidget->resizeColumnToContents(item_col_);
}

void StatsTreeDialog::drawTreeItems(void *st_ptr)
{
    stats_tree *st = (stats_tree *) st_ptr;
    if (!st || !st->cfg || !st->cfg->pr || !st->cfg->pr->st_dlg) return;
    StatsTreeDialog *st_dlg = st->cfg->pr->st_dlg;
    QTreeWidgetItemIterator iter(st_dlg->ui->statsTreeWidget);
    int node_count = 0;

    while (*iter) {
        stat_node *node = (*iter)->data(item_col_, Qt::UserRole).value<stat_node *>();
        if (node) {
            gchar    **valstrs = stats_tree_get_values_from_node(node);
            for (int count = 0; count<st->num_columns; count++) {
                (*iter)->setText(count,valstrs[count]);
                g_free(valstrs[count]);
            }
            (*iter)->setExpanded( (node->parent==(&st->root)) &&
                                  (!(node->st_flags&ST_FLG_DEF_NOEXPAND)) );
            g_free(valstrs);
        }
        node_count++;
        ++iter;
    }
    if (node_count < expand_all_threshold_) {
        st_dlg->ui->statsTreeWidget->expandAll();
    }

    for (int count = 0; count<st->num_columns; count++) {
        st_dlg->ui->statsTreeWidget->resizeColumnToContents(count);
    }
}

void StatsTreeDialog::on_applyFilterButton_clicked()
{
    fillTree();
}

void StatsTreeDialog::on_actionCopyToClipboard_triggered()
{
    GString* s= stats_tree_format_as_str(st_ ,ST_FORMAT_PLAIN, ui->statsTreeWidget->sortColumn(),
                ui->statsTreeWidget->header()->sortIndicatorOrder()==Qt::DescendingOrder);
    wsApp->clipboard()->setText(s->str);
    g_string_free(s,TRUE);
}

void StatsTreeDialog::on_actionSaveAs_triggered()
{
    QString selectedFilter;
    st_format_type file_type;
    const char *file_ext;
    FILE *f;
    GString *str_tree;
    bool success= false;
    int last_errno;

    QFileDialog SaveAsDialog(this, tr("Wireshark: Save stats tree as ..."), get_last_open_dir());
    SaveAsDialog.setNameFilter(tr("Plain text file (*.txt);;"
                                    "Comma separated values (*.csv);;"
                                    "XML document (*.xml);;"
                                    "YAML document (*.yaml)"));
    SaveAsDialog.selectNameFilter(tr("Plain text file (*.txt)"));
    SaveAsDialog.setAcceptMode(QFileDialog::AcceptSave);
    if (!SaveAsDialog.exec()) {
        return;
    }
    selectedFilter= SaveAsDialog.selectedNameFilter();
    if (selectedFilter.contains("*.yaml", Qt::CaseInsensitive)) {
        file_type= ST_FORMAT_YAML;
        file_ext = ".yaml";
    }
    else if (selectedFilter.contains("*.xml", Qt::CaseInsensitive)) {
        file_type= ST_FORMAT_XML;
        file_ext = ".xml";
    }
    else if (selectedFilter.contains("*.csv", Qt::CaseInsensitive)) {
        file_type= ST_FORMAT_CSV;
        file_ext = ".csv";
    }
    else {
        file_type= ST_FORMAT_PLAIN;
        file_ext = ".txt";
    }

    // Get selected filename and add extension of necessary
    QString file_name = SaveAsDialog.selectedFiles()[0];
    if (!file_name.endsWith(file_ext, Qt::CaseInsensitive)) {
        file_name.append(file_ext);
    }

    // produce output in selected format using current sort information
    str_tree=stats_tree_format_as_str(st_ ,file_type, ui->statsTreeWidget->sortColumn(),
                ui->statsTreeWidget->header()->sortIndicatorOrder()==Qt::DescendingOrder);

    // actually save the file
    f= ws_fopen (file_name.toUtf8().constData(),"w");
    last_errno= errno;
    if (f) {
        if (fputs(str_tree->str, f)!=EOF) {
            success= true;
        }
        last_errno= errno;
        fclose(f);
    }
    if (!success) {
        QMessageBox::warning(this, tr("Error saving file %1").arg(file_name),
                             g_strerror (last_errno));
    }

    g_string_free(str_tree, TRUE);
}

extern "C" {
void
register_tap_listener_stats_tree_stat(void)
{

    stats_tree_presentation(NULL,
                StatsTreeDialog::setupNode,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL);
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
