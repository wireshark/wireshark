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

    ProfileModel model(this);

    QList<QAction *> global;
    QList<QAction *> user;

    QAction * pa = systemDefault(filename);
    if (pa)
        global << pa;

    if (! buttonMenu_)
        buttonMenu_ = new QMenu();

    if (buttonMenu_->actions().count() > 0)
        buttonMenu_->clear();

    for (int cnt = 0; cnt < model.rowCount(); cnt++)
    {
        QModelIndex idx = model.index(cnt, ProfileModel::COL_NAME);
        QString profilePath = idx.data(ProfileModel::DATA_PATH).toString();
        if (! idx.isValid() || profilePath.isEmpty())
            continue;

        if (! idx.data(ProfileModel::DATA_PATH_IS_NOT_DESCRIPTION).toBool() || idx.data(ProfileModel::DATA_IS_SELECTED).toBool())
            continue;

        QDir profileDir(profilePath);
        if (! profileDir.exists())
            continue;

        QFileInfo fi = profileDir.filePath(filename);
        if (! fi.exists())
            continue;

        if (! config_file_exists_with_entries(fi.absoluteFilePath().toUtf8().constData(), '#'))
            continue;

        QString name = idx.data().toString();
        pa = new QAction(name, this);
        if (idx.data(ProfileModel::DATA_IS_DEFAULT).toBool())
            buttonMenu_->addAction(pa);
        else if (idx.data(ProfileModel::DATA_IS_GLOBAL).toBool())
            global << pa;
        else
            user << pa;

        pa->setFont(idx.data(Qt::FontRole).value<QFont>());
        pa->setProperty("profile_name", name);
        pa->setProperty("profile_is_global", idx.data(ProfileModel::DATA_IS_GLOBAL));
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

    QDir dataDir(get_datafile_dir());
    QString path = dataDir.filePath(filename);
    if (QFile::exists(path))
    {
        data = new QAction(tr("System default"), this);
        data->setData(path);
        QFont font = data->font();
        font.setItalic(true);
        data->setFont(font);
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
