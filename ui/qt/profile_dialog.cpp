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

#include "qt_ui_utils.h"

#include "ui/profile.h"

#include <ui/qt/variant_pointer.h>

#include "profile_dialog.h"
#include <ui_profile_dialog.h>
#include "wireshark_application.h"
#include "color_utils.h"

#include <QBrush>
#include <QDir>
#include <QFont>
#include <QMessageBox>
#include <QPushButton>
#include <QTreeWidgetItem>
#include <QUrl>

ProfileDialog::ProfileDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    pd_ui_(new Ui::ProfileDialog),
    ok_button_(NULL)
{
    GList *fl_entry;
    profile_def *profile;
    const gchar *profile_name = get_profile_name();

    pd_ui_->setupUi(this);
    loadGeometry();
    setWindowTitle(wsApp->windowTitleString(tr("Configuration Profiles")));
    ok_button_ = pd_ui_->buttonBox->button(QDialogButtonBox::Ok);

    // XXX - Use NSImageNameAddTemplate and NSImageNameRemoveTemplate to set stock
    // icons on macOS.
    // Are there equivalent stock icons on Windows?
#ifdef Q_OS_MAC
    pd_ui_->newToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    pd_ui_->deleteToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    pd_ui_->copyToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    pd_ui_->infoLabel->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    init_profile_list();
    fl_entry = edited_profile_list();
    pd_ui_->profileTreeWidget->blockSignals(true);
    while (fl_entry && fl_entry->data) {
        profile = (profile_def *) fl_entry->data;
        QTreeWidgetItem *item = new QTreeWidgetItem(pd_ui_->profileTreeWidget);
        item->setText(0, profile->name);
        item->setData(0, Qt::UserRole, VariantPointer<GList>::asQVariant(fl_entry));

        if (profile->is_global || profile->status == PROF_STAT_DEFAULT) {
            QFont ti_font = item->font(0);
            ti_font.setItalic(true);
            item->setFont(0, ti_font);
        } else {
            item->setFlags(item->flags() | Qt::ItemIsEditable);
        }

        if (!profile->is_global && strcmp(profile_name, profile->name) == 0) {
            pd_ui_->profileTreeWidget->setCurrentItem(item);
        }

        fl_entry = g_list_next(fl_entry);
    }
    pd_ui_->profileTreeWidget->blockSignals(false);

    connect(pd_ui_->profileTreeWidget->itemDelegate(), SIGNAL(closeEditor(QWidget*, QAbstractItemDelegate::EndEditHint)),
            this, SLOT(editingFinished()));
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
        current_profile = (profile_def *) VariantPointer<GList>::asPtr(item->data(0, Qt::UserRole))->data;
        enable_new = true;
        enable_copy = true;
        if (!current_profile->is_global && !(item->font(0).strikeOut())) {
            enable_del = true;
        }
    }

    if (current_profile) {
        QString profile_path;
        QString profile_info;
        switch (current_profile->status) {
        case PROF_STAT_DEFAULT:
            if (item->font(0).strikeOut()) {
                profile_info = tr("Will be reset to default values");
            } else {
                profile_path = get_persconffile_path("", FALSE);
            }
            break;
        case PROF_STAT_EXISTS:
            {
            char* profile_dir = current_profile->is_global ? get_global_profiles_dir() : get_profiles_dir();
            profile_path = profile_dir;
            g_free(profile_dir);

            profile_path.append(QDir::separator()).append(current_profile->name);
            }
            break;
        case PROF_STAT_COPY:
            if (current_profile->reference) {
                profile_info = tr("Created from %1").arg(current_profile->reference);
                if (current_profile->from_global) {
                    profile_info.append(QString(" %1").arg(tr("(system provided)")));
                }
                break;
            }
            /* Fall Through */
        case PROF_STAT_NEW:
            profile_info = tr("Created from default settings");
            break;
        case PROF_STAT_CHANGED:
            profile_info = tr("Renamed from %1").arg(current_profile->reference);
            break;
        }
        if (!profile_path.isEmpty()) {
            pd_ui_->infoLabel->setUrl(QUrl::fromLocalFile(profile_path).toString());
            pd_ui_->infoLabel->setText(profile_path);
            pd_ui_->infoLabel->setToolTip(tr("Go to %1").arg(profile_path));
        } else {
            pd_ui_->infoLabel->clear();
            pd_ui_->infoLabel->setText(profile_info);
        }
    } else {
        pd_ui_->infoLabel->clear();
    }

    if (pd_ui_->profileTreeWidget->topLevelItemCount() > 0) {
        profile_def *profile;
        for (int i = 0; i < pd_ui_->profileTreeWidget->topLevelItemCount(); i++) {
            item = pd_ui_->profileTreeWidget->topLevelItem(i);
            profile = (profile_def *) VariantPointer<GList>::asPtr(item->data(0, Qt::UserRole))->data;
            if (gchar *err_msg = profile_name_is_valid(profile->name)) {
                item->setToolTip(0, err_msg);
                item->setBackground(0, ColorUtils::fromColorT(&prefs.gui_text_invalid));
                if (profile == current_profile) {
                    pd_ui_->infoLabel->setText(err_msg);
                }
                g_free(err_msg);
                enable_ok = false;
                continue;
            }
            if (profile->is_global) {
                item->setToolTip(0, tr("This is a system provided profile."));
                continue;
            }
            if (current_profile && !current_profile->is_global && profile != current_profile && strcmp(profile->name, current_profile->name) == 0) {
                item->setToolTip(0, tr("A profile already exists with this name."));
                item->setBackground(0, ColorUtils::fromColorT(&prefs.gui_text_invalid));
                if (current_profile->status != PROF_STAT_DEFAULT &&
                    current_profile->status != PROF_STAT_EXISTS)
                {
                    pd_ui_->infoLabel->setText(tr("A profile already exists with this name"));
                }
                enable_ok = false;
            } else if (item->font(0).strikeOut()) {
                item->setToolTip(0, tr("The profile will be reset to default values."));
                item->setBackground(0, ColorUtils::fromColorT(&prefs.gui_text_deprecated));
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

void ProfileDialog::on_profileTreeWidget_currentItemChanged(QTreeWidgetItem *, QTreeWidgetItem *)
{
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
    item->setData(0, Qt::UserRole, VariantPointer<GList>::asQVariant(fl_entry));
    item->setFlags(item->flags() | Qt::ItemIsEditable);
    pd_ui_->profileTreeWidget->addTopLevelItem(item);
    pd_ui_->profileTreeWidget->setCurrentItem(item);
    pd_ui_->profileTreeWidget->editItem(item, 0);
}

void ProfileDialog::on_deleteToolButton_clicked()
{
    QTreeWidgetItem *item = pd_ui_->profileTreeWidget->currentItem();

    if (item) {
        GList *fl_entry = VariantPointer<GList>::asPtr(item->data(0, Qt::UserRole));
        profile_def *profile = (profile_def *) fl_entry->data;
        if (profile->is_global || item->font(0).strikeOut()) {
            return;
        }
        if (profile->status == PROF_STAT_DEFAULT) {
            QFont ti_font = item->font(0);
            ti_font.setStrikeOut(true);
            item->setFont(0, ti_font);
            updateWidgets();
        } else {
            delete item;

            // Select the default
            pd_ui_->profileTreeWidget->setCurrentItem(pd_ui_->profileTreeWidget->topLevelItem(0));

            remove_from_profile_list(fl_entry);
        }
    }
}

void ProfileDialog::on_copyToolButton_clicked()
{
    QTreeWidgetItem *cur_item = pd_ui_->profileTreeWidget->currentItem();
    if (!cur_item) return;

    profile_def *cur_profile = (profile_def *) VariantPointer<GList>::asPtr(cur_item->data(0, Qt::UserRole))->data;
    if (!cur_profile) return;

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
    new_item->setData(0, Qt::UserRole, VariantPointer<GList>::asQVariant(fl_entry));
    new_item->setFlags(new_item->flags() | Qt::ItemIsEditable);
    pd_ui_->profileTreeWidget->addTopLevelItem(new_item);
    pd_ui_->profileTreeWidget->setCurrentItem(new_item);
    pd_ui_->profileTreeWidget->editItem(new_item, 0);
}

void ProfileDialog::on_buttonBox_accepted()
{
    const gchar *err_msg;
    QTreeWidgetItem *default_item = pd_ui_->profileTreeWidget->topLevelItem(0);
    QTreeWidgetItem *item = pd_ui_->profileTreeWidget->currentItem();
    gchar *profile_name = NULL;
    bool write_recent = true;
    bool item_data_removed = false;

    if (default_item && default_item->font(0).strikeOut()) {
        // Reset Default profile.
        GList *fl_entry = VariantPointer<GList>::asPtr(default_item->data(0, Qt::UserRole));
        remove_from_profile_list(fl_entry);

        // Don't write recent file if leaving the Default profile after this has been reset.
        write_recent = !is_default_profile();

        // Don't fetch profile data if removed.
        item_data_removed = (item == default_item);
    }

    if ((err_msg = apply_profile_changes()) != NULL) {
        QMessageBox::critical(this, tr("Profile Error"),
                              err_msg,
                              QMessageBox::Ok);
        g_free((gchar*)err_msg);
        return;
    }

    if (item && !item_data_removed) {
        profile_def *profile = (profile_def *) VariantPointer<GList>::asPtr(item->data(0, Qt::UserRole))->data;
        profile_name = profile->name;
    }

    if (profile_exists (profile_name, FALSE) || profile_exists (profile_name, TRUE)) {
        // The new profile exists, change.
        wsApp->setConfigurationProfile (profile_name, write_recent);
    } else if (!profile_exists (get_profile_name(), FALSE)) {
        // The new profile does not exist, and the previous profile has
        // been deleted.  Change to the default profile.
        wsApp->setConfigurationProfile (NULL, write_recent);
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
        profile_def *profile = (profile_def *) VariantPointer<GList>::asPtr(item->data(0, Qt::UserRole))->data;
        if (item->text(0).compare(profile->name) != 0) {
            g_free(profile->name);
            profile->name = qstring_strdup(item->text(0));
            if (profile->status == PROF_STAT_EXISTS) {
                profile->status = PROF_STAT_CHANGED;
            }
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
