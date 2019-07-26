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

    QList<QAction *> global;
    QList<QAction *> user;

    QAction * pa = systemDefault(filename);
    if ( pa )
        global << pa;

    for(int cnt = 0; cnt < model.rowCount(); cnt++)
    {
        QModelIndex idx = model.index(cnt, ProfileModel::COL_NAME);
        QString profilePath = idx.data(ProfileModel::DATA_PATH).toString();
        if ( ! idx.isValid() || profilePath.isEmpty() )
            continue;

        if ( ! idx.data(ProfileModel::DATA_PATH_IS_NOT_DESCRIPTION).toBool() || idx.data(ProfileModel::DATA_IS_SELECTED).toBool() )
            continue;

        QDir profileDir(profilePath);
        if ( ! profileDir.exists() )
            continue;

        QFileInfo fi = profileDir.filePath(filename);
        if ( ! fi.exists() )
            continue;

        if ( ! config_file_exists_with_entries(fi.absoluteFilePath().toUtf8().constData(), '#') )
            continue;

        QString name = idx.data().toString();
        pa = new QAction(name, this);
        if ( idx.data(ProfileModel::DATA_IS_DEFAULT).toBool() )
            addAction(pa);
        else if ( idx.data(ProfileModel::DATA_IS_GLOBAL).toBool() )
            global << pa;
        else
            user << pa;

        pa->setFont(idx.data(Qt::FontRole).value<QFont>());
        pa->setProperty("profile_name", name);
        pa->setProperty("profile_is_global", idx.data(ProfileModel::DATA_IS_GLOBAL));

        pa->setProperty("filename", fi.absoluteFilePath());
        pa->setData(fi.absoluteFilePath().toUtf8().constData());
    }

    addActions(user);
    if (global.count() > 0)
    {
        if ( actions().count() > 0 )
            addSeparator();
        addActions(global);
    }

    have_profiles_ = actions().count() > 0;
}

bool CopyFromProfileMenu::haveProfiles()
{
    return have_profiles_;
}

// "System default" is not a profile.
// Add a special entry for this if the filename exists.
QAction * CopyFromProfileMenu::systemDefault(QString filename)
{
    QAction * data = Q_NULLPTR;

    QDir dataDir(get_datafile_dir());
    QString path = dataDir.filePath(filename);
    if ( QFile::exists(path) )
    {
        data = new QAction(tr("System default"), this);
        data->setData(path);
        QFont font = data->font();
        font.setItalic(true);
        data->setFont(font);
    }

    return data;
}
