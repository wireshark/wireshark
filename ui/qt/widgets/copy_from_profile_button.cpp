/* copy_from_profile_button.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/copy_from_profile_button.h>
#include <ui/qt/models/profile_model.h>
#include <wsutil/filesystem.h>
#include <app/application_flavor.h>

#include <QDir>
#include <QFileInfo>
#include <QMenu>
#include <QAction>

CopyFromProfileButton::CopyFromProfileButton(QWidget * parent, QString fileName, QString toolTip) :
    QPushButton(parent),
    buttonMenu_(Q_NULLPTR)
{
    setText(tr("Copy from"));
    if (toolTip.length() == 0)
        setToolTip(tr("Copy entries from another profile."));
    else {
        setToolTip(toolTip);
    }

    if (fileName.length() > 0)
        setFilename(fileName);
}

void CopyFromProfileButton::setFilename(QString filename)
{
    setEnabled(false);

    if (filename.length() <= 0)
        return;

    //Use the model object to pull the profile information
    ProfileModel model;
    ProfileSortModel sortModel;
    sortModel.setSourceModel(&model);
    sortModel.sort(0, Qt::DescendingOrder);

    QList<QAction *> global;
    QList<QAction *> user;

    QAction * pa = systemDefault(filename);
    if (pa)
        global << pa;

    if (! buttonMenu_)
        buttonMenu_ = new QMenu(this);

    if (buttonMenu_->actions().count() > 0)
        buttonMenu_->clear();

    const ProfileItem* currentProfile = model.getCurrentProfile();

    //Use the raw profile information from the model
    //(for performance and simpler looking code)
    for (int i = 0; i < sortModel.rowCount(); ++i)
    {
        //Go through the proxy model to get the profile information in the right order
        QModelIndex proxyIndex = sortModel.index(i, 0);
        QModelIndex sourceIndex = sortModel.mapToSource(proxyIndex);
        const ProfileItem* profile = model.getProfile(sourceIndex.row());
        if (profile == NULL)
            continue;   //Sanity check

        QString profilePath = profile->getProfilePath();
        if (profilePath.isEmpty())
            continue;

        //Ignore current profile
        if ((currentProfile != NULL) &&
            (profile->getName().compare(currentProfile->getName()) == 0) &&
            profile->isGlobal() == currentProfile->isGlobal())
            continue;

        QDir profileDir(profilePath);
        if (! profileDir.exists())
            continue;

        QFileInfo fi(profileDir.filePath(filename));
        if (! fi.exists())
            continue;

        if (! config_file_exists_with_entries(fi.absoluteFilePath().toUtf8().constData(), '#'))
            continue;

        QFont profileFont;
        QString name = profile->getName();
        pa = new QAction(name, this);
        if (profile->isDefault())
            buttonMenu_->addAction(pa);
        else if (profile->isGlobal())
        {
            global << pa;
            profileFont.setItalic(true);
        }
        else
            user << pa;

        pa->setFont(profileFont);
        pa->setProperty("profile_name", name);
        pa->setProperty("profile_is_global", profile->isGlobal());
        pa->setProperty("profile_filename", fi.absoluteFilePath());
    }

    buttonMenu_->addActions(user);
    if (global.count() > 0)
    {
        if (actions().count() > 0)
            buttonMenu_->addSeparator();
        buttonMenu_->addActions(global);
    }
    if (buttonMenu_->actions().count() <= 0)
        return;

    connect(buttonMenu_, &QMenu::triggered, this, &CopyFromProfileButton::menuActionTriggered);
    setMenu(buttonMenu_);
    setEnabled(true);
}

// "System default" is not a profile.
// Add a special entry for this if the filename exists.
QAction * CopyFromProfileButton::systemDefault(QString filename)
{
    QAction * data = Q_NULLPTR;

    QDir dataDir(get_datafile_dir(application_configuration_environment_prefix()));
    QString path = dataDir.filePath(filename);
    if (QFile::exists(path))
    {
        data = new QAction(tr("System default"), this);
        data->setData(path);
        QFont font = data->font();
        font.setItalic(true);
        data->setFont(font);
        data->setProperty("profile_filename", path);
    }

    return data;
}

void CopyFromProfileButton::menuActionTriggered(QAction * action)
{
    if (action->property("profile_filename").toString().length() > 0)
    {
        QString filename = action->property("profile_filename").toString();
        if (QFileInfo::exists(filename))
            emit copyProfile(filename);
    }
}
