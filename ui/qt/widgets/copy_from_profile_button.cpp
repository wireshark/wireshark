/* copy_from_profile_button.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/copy_from_profile_button.h>
#include <ui/profile.h>
#include <wsutil/filesystem.h>

#include <QPushButton>
#include <QDialogButtonBox>
#include <QMenu>

CopyFromProfileButton::CopyFromProfileButton(QString filename) :
    menu_(new QMenu(this)),
    filename_(filename)
{
    const gchar *profile_name = get_profile_name();
    bool profiles_added = false;
    bool globals_started = false;

    setText(tr("Copy from"));
    setToolTip(tr("Copy entries from another profile."));

    setMenu(menu_);

    init_profile_list();
    const GList *fl_entry = edited_profile_list();
    while (fl_entry && fl_entry->data) {
        profile_def *profile = (profile_def *) fl_entry->data;
        char *profile_dir = get_profile_dir(profile->name, profile->is_global);
        char *file_name = g_build_filename(profile_dir, filename_.toUtf8().constData(), NULL);
        if (file_exists(file_name) && strcmp(profile_name, profile->name) != 0) {
            if (profile->is_global && !globals_started) {
                if (profiles_added) {
                    menu_->addSeparator();
                }
                addSystemDefault();
                globals_started = true;
            }
            QAction *action = menu_->addAction(profile->name);
            action->setData(QString(file_name));
            if (profile->is_global) {
                QFont ti_font = action->font();
                ti_font.setItalic(true);
                action->setFont(ti_font);
            }
            profiles_added = true;
        }
        g_free(file_name);
        g_free(profile_dir);
        fl_entry = g_list_next(fl_entry);
    }

    if (!globals_started) {
        if (profiles_added) {
            menu_->addSeparator();
        }
        addSystemDefault();
    }

    setEnabled(profiles_added);
}

// "System default" is not a profile.
// Add a special entry for this if the filename exists.
void CopyFromProfileButton::addSystemDefault()
{
    char *file_name = g_build_filename(get_datafile_dir(), filename_.toUtf8().constData(), NULL);
    if (file_exists(file_name)) {
        QAction *action = menu_->addAction("System default");
        action->setData(QString(file_name));
        QFont ti_font = action->font();
        ti_font.setItalic(true);
        action->setFont(ti_font);
    }
    g_free(file_name);
}
