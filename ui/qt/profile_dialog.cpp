/* profile_dialog.cpp
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

#include "wsutil/filesystem.h"
#include "epan/prefs.h"

#include "ui/profile.h"

#include "profile_dialog.h"
#include "ui_profile_dialog.h"
#include "wireshark_application.h"
#include "color_utils.h"

#include <QBrush>
#include <QDir>
#include <QFont>
#include <QMessageBox>
#include <QUrl>

Q_DECLARE_METATYPE(GList *)

ProfileDialog::ProfileDialog(QWidget *parent) :
    QDialog(parent),
    pd_ui_(new Ui::ProfileDialog),
    ok_button_(NULL)
{
    GList *fl_entry;
    profile_def *profile;
    const gchar *profile_name = get_profile_name();

    pd_ui_->setupUi(this);
    ok_button_ = pd_ui_->buttonBox->button(QDialogButtonBox::Ok);

    // XXX - Use NSImageNameAddTemplate and NSImageNameRemoveTemplate to set stock
    // icons on OS X.
    // Are there equivalent stock icons on Windows?
#ifdef Q_OS_MAC
    pd_ui_->newToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    pd_ui_->deleteToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    pd_ui_->copyToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    pd_ui_->pathLabel->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    init_profile_list();
    fl_entry = edited_profile_list();
    pd_ui_->profileTreeWidget->blockSignals(true);
    while (fl_entry && fl_entry->data) {
        profile = (profile_def *) fl_entry->data;
        QTreeWidgetItem *item = new QTreeWidgetItem(pd_ui_->profileTreeWidget);
        item->setText(0, profile->name);
        item->setData(0, Qt::UserRole, qVariantFromValue(fl_entry));

        if (profile->is_global || profile->status == PROF_STAT_DEFAULT) {
            QFont ti_font = item->font(0);
            ti_font.setItalic(true);
            item->setFont(0, ti_font);
        } else {
            if (profile->name && strcmp(profile_name, profile->name) == 0) {
                pd_ui_->profileTreeWidget->setCurrentItem(item);
            }
            item->setFlags(item->flags() | Qt::ItemIsEditable);
        }

        fl_entry = g_list_next(fl_entry);
    }
    pd_ui_->profileTreeWidget->blockSignals(false);

    connect(pd_ui_->profileTreeWidget->itemDelegate(), SIGNAL(closeEditor(QWidget*, QAbstractItemDelegate::EndEditHint)),
            this, SLOT(editingFinished()));
    pd_ui_->profileTreeWidget->setCurrentItem(pd_ui_->profileTreeWidget->topLevelItem(0));
    updateWidgets();
}

ProfileDialog::~ProfileDialog()
{
    delete pd_ui_;
    empty_profile_list (TRUE);
}

int ProfileDialog::execAction(ProfileDialog::ProfileAction profile_action)
{
    int ret = QDialog::Accepted;
    QTreeWidgetItem *item;

    switch (profile_action) {
    case ShowProfiles:
        ret = exec();
        break;
    case NewProfile:
        on_newToolButton_clicked();
        ret = exec();
        break;
    case EditCurrentProfile:
        item = pd_ui_->profileTreeWidget->currentItem();
        if (item) {
            pd_ui_->profileTreeWidget->editItem(item, 0);
        }
        ret = exec();
        break;
    case DeleteCurrentProfile:
        if (delete_current_profile()) {
            wsApp->setConfigurationProfile (NULL);
        }
        break;
    default:
        g_assert_not_reached();
        break;
    }
    return ret;
}

void ProfileDialog::updateWidgets()
{
    QTreeWidgetItem *item = pd_ui_->profileTreeWidget->currentItem();
    bool enable_new = false;
    bool enable_del = false;
    bool enable_copy = false;
    bool enable_ok = true;
    profile_def *current_profile = NULL;

    if (item) {
        current_profile = (profile_def *) item->data(0, Qt::UserRole).value<GList *>()->data;
        enable_new = true;
        enable_copy = true;
        if (!current_profile->is_global && current_profile->status != PROF_STAT_DEFAULT) {
            enable_del = true;
        }
    }

    if (current_profile) {
        QString profile_path = current_profile->is_global ? get_global_profiles_dir() : get_profiles_dir();
        if (current_profile->status != PROF_STAT_DEFAULT) {
            profile_path.append(QDir::separator()).append(current_profile->name);
        }
        pd_ui_->pathLabel->setText(profile_path);
        pd_ui_->pathLabel->setUrl(QUrl::fromLocalFile(profile_path).toString());
        pd_ui_->pathLabel->setToolTip(tr("Go to") + profile_path);
        pd_ui_->pathLabel->setEnabled(true);
    } else {
        pd_ui_->pathLabel->clear();
    }

    if (pd_ui_->profileTreeWidget->topLevelItemCount() > 0) {
        profile_def *profile;
        for (int i = 0; i < pd_ui_->profileTreeWidget->topLevelItemCount(); i++) {
            item = pd_ui_->profileTreeWidget->topLevelItem(i);
            profile = (profile_def *) item->data(0, Qt::UserRole).value<GList *>()->data;
            if (profile->is_global) continue;
            if (current_profile && !current_profile->is_global && profile != current_profile && strcmp(profile->name, current_profile->name) == 0) {
                item->setToolTip(0, tr("A profile already exists with that name."));
                item->setBackground(0, ColorUtils::fromColorT(&prefs.gui_text_invalid));
                enable_ok = false;
            } else {
                item->setBackground(0, QBrush());
            }
        }
    }

    pd_ui_->profileTreeWidget->resizeColumnToContents(0);
    pd_ui_->newToolButton->setEnabled(enable_new);
    pd_ui_->deleteToolButton->setEnabled(enable_del);
    pd_ui_->copyToolButton->setEnabled(enable_copy);
    ok_button_->setEnabled(enable_ok);
}

void ProfileDialog::on_profileTreeWidget_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    Q_UNUSED(current);
    Q_UNUSED(previous);
    if (pd_ui_->profileTreeWidget->updatesEnabled()) updateWidgets();
}

void ProfileDialog::on_newToolButton_clicked()
{
    QTreeWidgetItem *item = new QTreeWidgetItem();
    profile_def *profile;
    const gchar *name = "New profile";
    GList *fl_entry = add_to_profile_list(name, "", PROF_STAT_NEW, FALSE, FALSE);

    profile = (profile_def *) fl_entry->data;
    item->setText(0, profile->name);
    item->setData(0, Qt::UserRole, qVariantFromValue(fl_entry));
    item->setFlags(item->flags() | Qt::ItemIsEditable);
    pd_ui_->profileTreeWidget->addTopLevelItem(item);
    pd_ui_->profileTreeWidget->setCurrentItem(item);
    pd_ui_->profileTreeWidget->editItem(item, 0);
}

void ProfileDialog::on_deleteToolButton_clicked()
{
    QTreeWidgetItem *item = pd_ui_->profileTreeWidget->currentItem();

    if (item) {
        GList *fl_entry = item->data(0, Qt::UserRole).value<GList *>();
        profile_def *profile = (profile_def *) fl_entry->data;
        if (profile->is_global || profile->status == PROF_STAT_DEFAULT) {
            return;
        }
        remove_from_profile_list(fl_entry);
        delete item;

        // Select the default
        pd_ui_->profileTreeWidget->setCurrentItem(pd_ui_->profileTreeWidget->topLevelItem(0));
    }
}

void ProfileDialog::on_copyToolButton_clicked()
{
    QTreeWidgetItem *cur_item = pd_ui_->profileTreeWidget->currentItem();
    profile_def *cur_profile = (profile_def *) cur_item->data(0, Qt::UserRole).value<GList *>()->data;

    if (!cur_item || !cur_profile) return;

    QTreeWidgetItem *new_item = new QTreeWidgetItem();
    GList *fl_entry;
    const gchar *parent;
    gchar *new_name;
    profile_def *new_profile;

    if (cur_profile->is_global) {
      parent = cur_profile->name;
    } else {
      parent = get_profile_parent (cur_profile->name);
    }

    if (cur_profile->is_global && !profile_exists (parent, FALSE)) {
      new_name = g_strdup (cur_profile->name);
    } else {
      new_name = g_strdup_printf ("%s (copy)", cur_profile->name);
    }

    /* Add a new entry to the profile list. */
    fl_entry = add_to_profile_list(new_name, parent, PROF_STAT_COPY, FALSE, cur_profile->from_global);
    new_profile = (profile_def *) fl_entry->data;
    new_item->setText(0, new_profile->name);
    new_item->setData(0, Qt::UserRole, qVariantFromValue(fl_entry));
    new_item->setFlags(new_item->flags() | Qt::ItemIsEditable);
    pd_ui_->profileTreeWidget->addTopLevelItem(new_item);
    pd_ui_->profileTreeWidget->setCurrentItem(new_item);
    pd_ui_->profileTreeWidget->editItem(new_item, 0);
}

void ProfileDialog::on_buttonBox_accepted()
{
    const gchar *err_msg;
    QTreeWidgetItem *item = pd_ui_->profileTreeWidget->currentItem();

    if ((err_msg = apply_profile_changes()) != NULL) {
        QMessageBox::critical(this, tr("Profile Error"),
                              err_msg,
                              QMessageBox::Ok);
        return;
    }

    if (item) {
        profile_def *profile = (profile_def *) item->data(0, Qt::UserRole).value<GList *>()->data;
        if (profile_exists (profile->name, FALSE) || profile_exists (profile->name, TRUE)) {
            /* The new profile exists, change */
            wsApp->setConfigurationProfile (profile->name);
        } else if (!profile_exists (get_profile_name(), FALSE)) {
            /* The new profile does not exist, and the previous profile has
               been deleted.  Change to the default profile */
            wsApp->setConfigurationProfile (NULL);
        }
    }
}

void ProfileDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_CONFIG_PROFILES_DIALOG);
}

void ProfileDialog::editingFinished()
{
    QTreeWidgetItem *item = pd_ui_->profileTreeWidget->currentItem();

    if (item) {
        profile_def *profile = (profile_def *) item->data(0, Qt::UserRole).value<GList *>()->data;
        if (item->text(0).compare(profile->name) != 0) {
            g_free(profile->name);
            profile->name = g_strdup(item->text(0).toUtf8().constData());
        }
    }
    updateWidgets();
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
