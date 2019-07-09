/* copy_from_profile_menu.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/copy_from_profile_menu.h>
#include <ui/qt/models/profile_model.h>
#include <wsutil/filesystem.h>

#include <QDir>
#include <QFileInfo>

CopyFromProfileMenu::CopyFromProfileMenu(QString filename, QWidget *parent) :
    QMenu(parent),
    have_profiles_(false)
{
    ProfileModel model(this);


    QActionGroup global(this);
    QActionGroup user(this);

    for(int cnt = 0; cnt < model.rowCount(); cnt++)
    {
        QModelIndex idx = model.index(cnt, ProfileModel::COL_NAME);
        QModelIndex idxPath = model.index(cnt, ProfileModel::COL_PATH);
        if ( ! idx.isValid() || ! idxPath.isValid() )
            continue;

        if ( ! idx.data(ProfileModel::DATA_PATH_IS_NOT_DESCRIPTION).toBool() || idx.data(ProfileModel::DATA_IS_SELECTED).toBool() )
            continue;

        QDir profileDir(idxPath.data().toString());
        if ( ! profileDir.exists() )
            continue;

        QFileInfo fi = profileDir.filePath(filename);
        if ( ! fi.exists() )
            continue;

        if ( ! config_file_exists_with_entries(fi.absoluteFilePath().toUtf8().constData(), '#') )
            continue;

        QAction * pa = Q_NULLPTR;
        if ( idx.data(ProfileModel::DATA_IS_DEFAULT).toBool() || idx.data(ProfileModel::DATA_IS_GLOBAL).toBool() )
            pa = global.addAction(idx.data().toString());
        else
            pa = user.addAction(idx.data().toString());

        pa->setCheckable(true);
        if ( idx.data(ProfileModel::DATA_IS_SELECTED).toBool() )
            pa->setChecked(true);

        pa->setFont(idx.data(Qt::FontRole).value<QFont>());
        pa->setProperty("profile_name", idx.data());
        pa->setProperty("profile_is_global", idx.data(ProfileModel::DATA_IS_GLOBAL));

        pa->setProperty("filename", fi.absoluteFilePath());
        pa->setData(fi.absoluteFilePath().toUtf8().constData());
    }

    addActions(global.actions());
    if (global.actions().count() > 0)
        addSeparator();
    addActions(user.actions());
}

bool CopyFromProfileMenu::haveProfiles()
{
    return have_profiles_;
}
