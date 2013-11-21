/* stats_tree_dialog.cpp
 *
 * $Id$
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

#include "wireshark_application.h"

#include <QClipboard>
#include <QMessageBox>
#include <QTreeWidget>
#include <QTreeWidgetItemIterator>

// The GTK+ counterpart uses tap_param_dlg, which we don't use. If we
// need tap parameters we should probably create a TapParameterDialog
// class based on QDialog and subclass it here.

// To do:
// - Add help

#include <QDebug>

const int item_col_     = 0;
const int count_col_    = 1;
const int rate_col_     = 2;
const int percent_col_  = 3;

Q_DECLARE_METATYPE(stat_node *);

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

    ui->statsTreeWidget->addAction(ui->actionCopyAsCSV);
    ui->statsTreeWidget->addAction(ui->actionCopyAsYAML);
    ui->statsTreeWidget->setContextMenuPolicy(Qt::ActionsContextMenu);

    QPushButton *copy_as_bt;
    copy_as_bt = ui->buttonBox->addButton(tr("Copy as CSV"), QDialogButtonBox::ActionRole);
    connect(copy_as_bt, SIGNAL(clicked()), this, SLOT(on_actionCopyAsCSV_triggered()));

    copy_as_bt = ui->buttonBox->addButton(tr("Copy as YAML"), QDialogButtonBox::ActionRole);
    connect(copy_as_bt, SIGNAL(clicked()), this, SLOT(on_actionCopyAsYAML_triggered()));

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

    setWindowTitle(st_cfg_->name + tr(" Stats Tree"));

    if (!cap_file_) return;

    if (st_cfg_->in_use) {
        QMessageBox::warning(this, tr("%1 already open").arg(st_cfg_->name),
                             tr("Each type of tree can only be generated one at at time."));
        reject();
    }

    st_cfg_->in_use = TRUE;
    st_cfg_->pr = &cfg_pr_;
    cfg_pr_.st_dlg = this;

    st_ = stats_tree_new(st_cfg_, NULL, ui->displayFilterLineEdit->text().toUtf8().constData());

    error_string = register_tap_listener(st_cfg_->tapname,
                          st_,
                          st_->filter,
                          st_cfg_->flags,
                          resetTap,
                          stats_tree_packet,
                          drawTreeItems);
    if (error_string) {
        QMessageBox::critical(this, tr("%1 failed to attach to tap").arg(st_cfg_->name),
                             error_string->str);
        g_string_free(error_string, TRUE);
        reject();
    }

    cf_retap_packets(cap_file_);
    drawTreeItems(st_);
    remove_tap_listener(st_);

    stats_tree_free(st_);
    st_ = NULL;
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

    QTreeWidgetItem *ti = new QTreeWidgetItem(), *parent = NULL;

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

    while (*iter) {
        gchar value[NUM_BUF_SIZE];
        gchar rate[NUM_BUF_SIZE];
        gchar percent[NUM_BUF_SIZE];
        stat_node *node = (*iter)->data(item_col_, Qt::UserRole).value<stat_node *>();
        if (node) {
            stats_tree_get_strs_from_node(node, value, rate,
                              percent);
            (*iter)->setText(count_col_, value);
            (*iter)->setText(rate_col_, rate);
            (*iter)->setText(percent_col_, percent);
        }
        ++iter;
    }
    st_dlg->ui->statsTreeWidget->resizeColumnToContents(count_col_);
    st_dlg->ui->statsTreeWidget->resizeColumnToContents(rate_col_);
    st_dlg->ui->statsTreeWidget->resizeColumnToContents(percent_col_);
}

void StatsTreeDialog::on_applyFilterButton_clicked()
{
    fillTree();
}

void StatsTreeDialog::on_actionCopyAsCSV_triggered()
{
    QTreeWidgetItemIterator iter(ui->statsTreeWidget);
    QString clip = QString("%1,%2,%3,%4\n")
            .arg(ui->statsTreeWidget->headerItem()->text(item_col_))
            .arg(ui->statsTreeWidget->headerItem()->text(count_col_))
            .arg(ui->statsTreeWidget->headerItem()->text(rate_col_))
            .arg(ui->statsTreeWidget->headerItem()->text(percent_col_));

    while (*iter) {
        clip += QString("\"%1\",\"%2\",\"%3\",\"%4\"\n")
                .arg((*iter)->text(item_col_))
                .arg((*iter)->text(count_col_))
                .arg((*iter)->text(rate_col_))
                .arg((*iter)->text(percent_col_));
        ++iter;
    }
    wsApp->clipboard()->setText(clip);
}

void StatsTreeDialog::on_actionCopyAsYAML_triggered()
{
    QTreeWidgetItemIterator iter(ui->statsTreeWidget);
    QString clip;

    while (*iter) {
        QString indent;
        if ((*iter)->parent()) {
            QTreeWidgetItem *parent = (*iter)->parent();
            while (parent) {
                indent += "  ";
                parent = parent->parent();
            }
            clip += indent + "- description: \"" + (*iter)->text(item_col_) + "\"\n";
            indent += "  ";
            clip += indent + "count: " + (*iter)->text(count_col_) + "\n";
            clip += indent + "rate_ms: " + (*iter)->text(rate_col_) + "\n";
            clip += indent + "percent: " + (*iter)->text(percent_col_) + "\n";
        } else {
            // Top level
            clip += "description: \"" + (*iter)->text(item_col_) + "\"\n";
            clip += "count: " + (*iter)->text(count_col_) + "\n";
            clip += "rate_ms: " + (*iter)->text(rate_col_) + "\n";
        }
        if ((*iter)->childCount() > 0) {
            clip += indent + "items:\n";
        }
        ++iter;
    }
    wsApp->clipboard()->setText(clip);
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
