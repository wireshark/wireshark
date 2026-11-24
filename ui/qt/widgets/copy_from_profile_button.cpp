/* copy_from_profile_button.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/copy_from_profile_button.h>
#include <ui/qt/widgets/profile_inherit_combo_box.h>
#include <ui/qt/models/profile_model.h>
#include <wsutil/filesystem.h>
#include <app/application_flavor.h>

#include <QDir>
#include <QFileInfo>
#include <QMenu>
#include <QAction>

#include <functional>

CopyFromProfileButton::CopyFromProfileButton(QWidget * parent, QString fileName, QString toolTip, QString legacyFileName) :
    QPushButton(parent),
    legacy_filename_(legacyFileName),
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

    if (! buttonMenu_)
        buttonMenu_ = new QMenu(this);

    if (buttonMenu_->actions().count() > 0)
    {
        qDeleteAll(buttonMenu_->findChildren<QMenu *>(QString(), Qt::FindDirectChildrenOnly));
        buttonMenu_->clear();
    }

    const ProfileItem* currentProfile = model.getCurrentProfile();

    // Add the profiles of one scope having the file, using a submenu for profiles with children
    std::function<void(QMenu *, const QModelIndex &, bool)> addProfiles;
    // NOLINTNEXTLINE(misc-no-recursion)
    addProfiles = [&](QMenu * menu, const QModelIndex &parent, bool global) {
        for (int i = 0; i < sortModel.rowCount(parent); ++i)
        {
            //Go through the proxy model to get the profile information in the right order
            QModelIndex proxyIndex = sortModel.index(i, 0, parent);
            const ProfileItem* profile = model.getProfile(sortModel.mapToSource(proxyIndex));
            if (profile == NULL || profile->isGlobal() != global)
                continue;   //Sanity check

            QString name = profile->getLeafName();
            QMenu * subMenu = menu;
            if (sortModel.rowCount(proxyIndex) > 0)
            {
                subMenu = new QMenu(name, menu);
                QFont subMenuFont = subMenu->menuAction()->font();
                subMenuFont.setItalic(profile->isGlobal());
                subMenu->menuAction()->setFont(subMenuFont);
                addProfiles(subMenu, proxyIndex, global);
            }

            QDir profileDir(profile->getProfilePath());
            QFileInfo fi(profileDir.filePath(filename));
            if (!fi.exists() && !legacy_filename_.isEmpty())
            {
                // A profile not yet converted may only have the file under its former name
                fi.setFile(profileDir.filePath(legacy_filename_));
            }
            bool hasFile = true;

            //Ignore current profile
            if ((currentProfile != NULL) &&
                (profile->getName().compare(currentProfile->getName()) == 0) &&
                profile->isGlobal() == currentProfile->isGlobal())
                hasFile = false;
            else if (profile->getProfilePath().isEmpty() || ! fi.exists() ||
                     ! config_file_exists_with_entries(fi.absoluteFilePath().toUtf8().constData(), '#'))
                hasFile = false;

            if (hasFile)
            {
                QAction * pa = new QAction(name, this);
                QFont profileFont;
                if (profile->isGlobal())
                    profileFont.setItalic(true);

                pa->setFont(profileFont);
                pa->setProperty("profile_name", profile->getName());
                pa->setProperty("profile_is_global", profile->isGlobal());
                pa->setProperty("profile_filename", fi.absoluteFilePath());

                // A profile with children is the first entry in its submenu
                if (subMenu == menu || subMenu->isEmpty())
                    subMenu->addAction(pa);
                else
                {
                    subMenu->insertSeparator(subMenu->actions().first());
                    subMenu->insertAction(subMenu->actions().first(), pa);
                }
            }

            if (subMenu == menu)
                continue;

            if (subMenu->isEmpty())
                delete subMenu;
            else
                menu->addMenu(subMenu);
        }
    };

    addProfiles(buttonMenu_, QModelIndex(), false);

    QAction * separator = buttonMenu_->actions().count() > 0 ? buttonMenu_->addSeparator() : Q_NULLPTR;
    qsizetype count = buttonMenu_->actions().count();

    QAction * pa = systemDefault(filename);
    if (pa)
        buttonMenu_->addAction(pa);
    addProfiles(buttonMenu_, QModelIndex(), true);

    if (separator && buttonMenu_->actions().count() == count)
        delete separator;

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

void CopyFromProfileButton::setOwnEntriesUsed(bool own_used)
{
    setEnabled(own_used && menu() != nullptr);
    ProfileInheritComboBox::setOwnEntriesUsed(this, own_used);
}
