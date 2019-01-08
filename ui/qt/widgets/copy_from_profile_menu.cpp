/* copy_from_profile_menu.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/copy_from_profile_menu.h>
#include <ui/profile.h>
#include <wsutil/filesystem.h>

CopyFromProfileMenu::CopyFromProfileMenu(QString filename, QWidget *parent) :
    QMenu(parent),
    filename_(filename),
    have_profiles_(false)
{
    const gchar *profile_name = get_profile_name();
    bool globals_started = false;

    init_profile_list();

    const GList *fl_entry = edited_profile_list();
    while (fl_entry && fl_entry->data) {
        profile_def *profile = (profile_def *) fl_entry->data;
        char *profile_dir = get_profile_dir(profile->name, profile->is_global);
        char *file_name = g_build_filename(profile_dir, filename_.toUtf8().constData(), NULL);
        if ((strcmp(profile_name, profile->name) != 0) && config_file_exists_with_entries(file_name, '#')) {
            if (profile->is_global && !globals_started) {
                if (have_profiles_) {
                    addSeparator();
                }
                addSystemDefault();
                globals_started = true;
            }
            QAction *action = addAction(profile->name);
            action->setData(QString(file_name));
            if (profile->is_global) {
                QFont ti_font = action->font();
                ti_font.setItalic(true);
                action->setFont(ti_font);
            }
            have_profiles_ = true;
        }
        g_free(file_name);
        g_free(profile_dir);
        fl_entry = g_list_next(fl_entry);
    }

    if (!globals_started) {
        if (have_profiles_) {
            addSeparator();
        }
        addSystemDefault();
    }
}

// "System default" is not a profile.
// Add a special entry for this if the filename exists.
void CopyFromProfileMenu::addSystemDefault()
{
    char *file_name = g_build_filename(get_datafile_dir(), filename_.toUtf8().constData(), NULL);
    if (file_exists(file_name)) {
        QAction *action = addAction("System default");
        action->setData(QString(file_name));
        QFont ti_font = action->font();
        ti_font.setItalic(true);
        action->setFont(ti_font);
    }
    g_free(file_name);
}

bool CopyFromProfileMenu::haveProfiles()
{
    return have_profiles_;
}
