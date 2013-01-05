/* preferences_dialog.cpp
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

#include "config.h"

#include <glib.h>

#include "color.h"
#include "packet-range.h"

#include <epan/prefs.h>
#include <epan/prefs-int.h>

#include "preferences_dialog.h"
#include "ui_preferences_dialog.h"

#include <QMessageBox>
#include <QDebug>

extern "C" {
// Callbacks prefs routines

static guint
fill_advanced_prefs(module_t *module, gpointer root_ptr)
{
    QTreeWidgetItem *root_item = static_cast<QTreeWidgetItem *>(root_ptr);

    if (!module || !root_item) return 1;

    if (module->numprefs < 1 && !prefs_module_has_submodules(module)) return 0;

    QString module_title;
//    if (module->parent == NULL)
        module_title = module->title;
//    else
//        module_title = QString(module->parent->title) +": "+ module->title;

    QTreeWidgetItem *tl_item = new QTreeWidgetItem(root_item);
    tl_item->setText(0, module_title);
    tl_item->setToolTip(0, module->description);
    tl_item->setFirstColumnSpanned(true);

    QList<QTreeWidgetItem *>tl_children;
    for (GList *pref_l = module->prefs; pref_l && pref_l->data; pref_l = g_list_next(pref_l)) {
        pref_t *pref = (pref_t *) pref_l->data;

        if (pref->type == PREF_OBSOLETE || pref->type == PREF_STATIC_TEXT) continue;
        const char *type_name = prefs_pref_type_name(pref);
        if (!type_name) continue;

        QTreeWidgetItem *item = new QTreeWidgetItem();
        QString full_name = QString(module->name ? module->name : module->parent->name) + "." + pref->name;
        QFont font = item->font(0);
        char *type_desc = prefs_pref_type_description(pref);
        char *cur_value = prefs_pref_to_str(pref, false);
        char *default_value = prefs_pref_to_str(pref, true);
        bool is_default = false;
        bool is_editable = true;

        if (pref->type == PREF_UAT) {
            is_editable = false;
        } else {
            if (prefs_pref_is_default(pref)) is_default = true;
        }

        item->setText(0, full_name);
        item->setToolTip(0, pref->description);
        item->setText(1, is_default ? "Default" : "Changed");
        item->setToolTip(1, "Has this value been changed?");
        item->setText(2, type_name);
        item->setToolTip(2, type_desc);
        item->setText(3, QString(cur_value).replace(QRegExp("\n\t"), " "));
        item->setToolTip(3, QString("Default: ") + default_value);
        g_free(type_desc);
        g_free(cur_value);
        g_free(default_value);

        font.setBold(!is_default);

        if (!is_editable) {
            item->setFlags(item->flags() ^ Qt::ItemIsEnabled);
        }
        font.setItalic(!is_editable);
        item->setFont(0, font);

        item->setFont(0, font);
        item->setFont(1, font);
        item->setFont(2, font);
        item->setFont(3, font);
        tl_children << item;
    }
    tl_item->addChildren(tl_children);

    if(prefs_module_has_submodules(module))
        return prefs_modules_foreach_submodules(module, fill_advanced_prefs, tl_item);

    return 0;
}


} // extern "C"

const int appearance_item_ = 0;
const int protocols_item_  = 4;
const int statistics_item_ = 5;
const int advanced_item_   = 6;

PreferencesDialog::PreferencesDialog(QWidget *parent) :
    QDialog(parent),
    pd_ui_(new Ui::PreferencesDialog)
{
    pd_ui_->setupUi(this);
    QTreeWidgetItem tmp_item;

    pd_ui_->advancedTree->setUpdatesEnabled(false);
    prefs_modules_foreach_submodules(NULL, fill_advanced_prefs, (gpointer) &tmp_item);
    pd_ui_->advancedTree->invisibleRootItem()->addChildren(tmp_item.takeChildren());
    pd_ui_->advancedTree->expandAll();
    pd_ui_->advancedTree->setSortingEnabled(true);
    pd_ui_->advancedTree->sortByColumn(0, Qt::AscendingOrder);
    pd_ui_->advancedTree->setColumnWidth(0, pd_ui_->advancedTree->width() * 2 / 5);
    pd_ui_->advancedTree->resizeColumnToContents(1);
    pd_ui_->advancedTree->resizeColumnToContents(2);
    pd_ui_->advancedTree->setColumnWidth(3, pd_ui_->advancedTree->width() * 3 / 5);
    pd_ui_->advancedTree->setUpdatesEnabled(true);

    pd_ui_->splitter->setStretchFactor(0, 1);
    pd_ui_->splitter->setStretchFactor(1, 5);

    pd_ui_->prefsTree->invisibleRootItem()->child(appearance_item_)->setExpanded(true);
    pd_ui_->prefsTree->invisibleRootItem()->child(advanced_item_)->setSelected(true);
}

PreferencesDialog::~PreferencesDialog()
{
    delete pd_ui_;
}

void PreferencesDialog::showEvent(QShowEvent *evt)
{
    Q_UNUSED(evt);
    QStyleOption style_opt;
    int new_prefs_tree_width =  pd_ui_->prefsTree->style()->subElementRect(QStyle::SE_TreeViewDisclosureItem, &style_opt).left();
    QList<int> sizes = pd_ui_->splitter->sizes();

    pd_ui_->prefsTree->resizeColumnToContents(0);
    new_prefs_tree_width += pd_ui_->prefsTree->columnWidth(0);
    sizes[1] += sizes[0] - new_prefs_tree_width;
    sizes[0] = new_prefs_tree_width;
    pd_ui_->splitter->setSizes(sizes);
    pd_ui_->splitter->setStretchFactor(0, 0);
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
