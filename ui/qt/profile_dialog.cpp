/* profile_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <wsutil/filesystem.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/themes/themed_icon.h>

#include "ui/profile.h"
#include "ui/recent.h"

#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/models/profile_model.h>

#include "profile_dialog.h"
#include <ui_profile_dialog.h>
#include "main_application.h"
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/simple_dialog.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>
#include <app/application_flavor.h>

#include <QBrush>
#include <QDir>
#include <QFont>
#include <QMessageBox>
#include <QPushButton>
#include <QToolButton>
#include <QTreeWidgetItem>
#include <QUrl>
#include <QComboBox>
#include <QLineEdit>
#include <QStandardPaths>
#include <QKeyEvent>
#include <QMenu>
#include <QTimer>
#include <QMessageBox>


ProfileDialog::ProfileDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    pd_ui_(new Ui::ProfileDialog),
    ok_button_(Q_NULLPTR),
    import_button_(Q_NULLPTR),
    model_(Q_NULLPTR),
    sort_model_(Q_NULLPTR)
{
    pd_ui_->setupUi(this);
    loadGeometry();
    setWindowTitle(mainApp->windowTitleString(tr("Configuration Profiles")));

    ok_button_ = pd_ui_->buttonBox->button(QDialogButtonBox::Ok);

    pd_ui_->newToolButton->setIcon(ThemedIcon("list-add"));
    pd_ui_->deleteToolButton->setIcon(ThemedIcon("list-remove"));
    pd_ui_->copyToolButton->setIcon(ThemedIcon("list-copy"));
#ifdef Q_OS_MACOS
    pd_ui_->newToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    pd_ui_->deleteToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    pd_ui_->copyToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    pd_ui_->hintLabel->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    QString as_tooltip = pd_ui_->autoSwitchLimitLabel->toolTip();
    pd_ui_->autoSwitchSpinBox->setToolTip(as_tooltip);
    pd_ui_->autoSwitchSpinBox->setValue(recent.gui_profile_switch_check_count);

    import_button_ = pd_ui_->buttonBox->addButton(tr("Import", "noun"), QDialogButtonBox::ActionRole);

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
    export_button_ = pd_ui_->buttonBox->addButton(tr("Export", "noun"), QDialogButtonBox::ActionRole);

    QMenu * importMenu = new QMenu(import_button_);
    QAction * entry = importMenu->addAction(tr("From Zip File…"));
    connect(entry, &QAction::triggered, this, [this]() { importFromZip(); }, Qt::QueuedConnection);
    entry = importMenu->addAction(tr("From Directory…"));
    connect(entry, &QAction::triggered, this, [this]() { importFromDirectory(); }, Qt::QueuedConnection);
    import_button_->setMenu(importMenu);

    QMenu * exportMenu = new QMenu(export_button_);
    export_selected_entry_ = exportMenu->addAction(tr("%Ln Personal Profile(s)…", "", 0));
    connect(export_selected_entry_, &QAction::triggered, this, [this]() { exportProfiles(); }, Qt::QueuedConnection);
    export_children_entry_ = exportMenu->addAction(tr("%Ln Personal Profile(s) (including sub-profiles)…", "", 0));
    connect(export_children_entry_, &QAction::triggered, this, [this]() { exportProfiles(false, true); }, Qt::QueuedConnection);
    entry = exportMenu->addAction(tr("All Personal Profiles…"));
    connect(entry, &QAction::triggered, this, [this]() { exportProfiles(true); }, Qt::QueuedConnection);
    export_button_->setMenu(exportMenu);
#else
    connect(import_button_, &QPushButton::clicked, this, [this]() { importFromDirectory(); });
#endif

    model_ = new ProfileModel(pd_ui_->profileTreeView);
    sort_model_ = new ProfileSortModel(pd_ui_->profileTreeView);
    sort_model_->setSourceModel(model_);
    pd_ui_->profileTreeView->setModel(sort_model_);
    pd_ui_->profileTreeView->expandAll();

    connect(model_, &ProfileModel::dataChanged, this, &ProfileDialog::dataChanged, Qt::QueuedConnection);
    // Show a moved profile, also when its new parent is collapsed
    connect(model_, &ProfileModel::rowsAboutToBeMoved, this, [this](const QModelIndex &parent, int start) {
        moved_ = model_->index(start, ProfileModel::COL_NAME, parent);
    });
    connect(model_, &ProfileModel::rowsMoved, this, [this]() {
        QTimer::singleShot(0, this, [this]() {
            QModelIndex idx = sort_model_->mapFromSource(moved_);
            if (idx.isValid()) {
                pd_ui_->profileTreeView->setCurrentIndex(idx);
                pd_ui_->profileTreeView->scrollTo(idx);
            }
        });
    });
    QItemSelectionModel* selModel = pd_ui_->profileTreeView->selectionModel();
    connect(selModel, &QItemSelectionModel::selectionChanged, this, &ProfileDialog::selectionChanged);

    pd_ui_->profileTreeView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(pd_ui_->profileTreeView, &QTreeView::customContextMenuRequested, this, &ProfileDialog::profileContextMenu);

    // Select the row for the currently selected profile or the first row if non is selected
    selectProfile();

    // Setup filtering
    pd_ui_->cmbProfileTypes->addItems(ProfileSortModel::filterTypes());
    connect(pd_ui_->cmbProfileTypes, &QComboBox::currentTextChanged, this, &ProfileDialog::filterChanged);
    connect(pd_ui_->lineProfileFilter, &QLineEdit::textChanged, this, &ProfileDialog::filterChanged);

    // Setup button handling
    connect(pd_ui_->newToolButton, &QToolButton::clicked, this, &ProfileDialog::newToolButtonClicked);
    connect(pd_ui_->deleteToolButton, &QToolButton::clicked, this, &ProfileDialog::deleteToolButtonClicked);
    connect(pd_ui_->copyToolButton, &QToolButton::clicked, this, &ProfileDialog::copyToolButtonClicked);
    connect(pd_ui_->buttonBox, &QDialogButtonBox::accepted, this, &ProfileDialog::buttonBoxAccepted);
    connect(pd_ui_->buttonBox, &QDialogButtonBox::helpRequested, this, &ProfileDialog::buttonBoxHelpRequested);

    pd_ui_->profileTreeView->resizeColumnToContents(ProfileModel::COL_NAME);
    pd_ui_->profileTreeView->resizeColumnToContents(ProfileModel::COL_TYPE);

    pd_ui_->profileTreeView->setFocus();
}

ProfileDialog::~ProfileDialog()
{
    delete pd_ui_;
}

QLabel* ProfileDialog::autoSwitchLimitLabel() const
{
    return pd_ui_->autoSwitchLimitLabel;
}

void ProfileDialog::keyPressEvent(QKeyEvent *evt)
{
    if (pd_ui_->lineProfileFilter->hasFocus() && (evt->key() == Qt::Key_Enter || evt->key() == Qt::Key_Return))
        return;
    QDialog::keyPressEvent(evt);
}

void ProfileDialog::selectProfile(QString profile)
{
    if (profile.isEmpty())
        profile = QString(get_profile_name());

    QModelIndex idx = sort_model_->mapFromSource(model_->findByName(profile));
    pd_ui_->profileTreeView->selectIndex(idx.isValid() ? idx : sort_model_->index(0, ProfileModel::COL_NAME));
}

int ProfileDialog::execAction(ProfileDialog::ProfileAction profile_action)
{
    int ret = QDialog::Accepted;
    QModelIndex item;

    switch (profile_action) {
    case ShowProfiles:
        ret = exec();
        break;
    case NewProfile:
        newToolButtonClicked();
        ret = exec();
        break;
    case ImportZipProfile:
#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
        importFromZip();
#endif
        break;
    case ImportDirProfile:
        importFromDirectory();
        break;
    case ExportSingleProfile:
#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
        exportProfiles();
#endif
        break;
    case ExportSingleProfileWithChildren:
#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
        exportProfiles(false, true);
#endif
        break;
    case ExportAllProfiles:
#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
        exportProfiles(true);
#endif
        break;
    case EditCurrentProfile:
        item = pd_ui_->profileTreeView->currentIndex();
        if (item.isValid()) {
            pd_ui_->profileTreeView->edit(item);
        }
        ret = exec();
        break;
    case DeleteCurrentProfile:
    {
        // A profile with sub-profiles is deleted in the dialog, to show what is deleted
        if (model_->rowCount(model_->findByName(get_profile_name())) > 0) {
            deleteToolButtonClicked();
            ret = exec();
            break;
        }

        char* err = NULL;
        if (profile_delete_current(application_configuration_environment_prefix(), &err)) {
            mainApp->setConfigurationProfile (Q_NULLPTR);
        } else if (err != NULL) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err);
            g_free(err);
        }
        break;
    }
    }
    return ret;
}

QModelIndexList ProfileDialog::selectedProfiles()
{
    QModelIndexList profiles;

    foreach (QModelIndex idx, pd_ui_->profileTreeView->selectionModel()->selectedIndexes())
    {
        QModelIndex temp = sort_model_->mapToSource(idx);
        if (! temp.isValid() || profiles.contains(temp) || temp.column() != ProfileModel::COL_NAME)
            continue;

        profiles << temp;
    }

    return profiles;
}

void ProfileDialog::selectionChanged()
{
    QModelIndexList profiles = selectedProfiles();
    qsizetype numSelected = profiles.count();

    QModelIndex index = sort_model_->mapToSource(pd_ui_->profileTreeView->currentIndex());
    // Ensure that the index is always the name column
    if (index.column() != ProfileModel::COL_NAME)
        index = index.sibling(index.row(), ProfileModel::COL_NAME);

    // multiple profiles are being selected, copy is no longer allowed
    // A copy inside a deleted profile would be deleted with it
    bool enable_copy = (numSelected == 1);
    const ProfileItem* selected = model_->getProfile(index);
    for (const ProfileItem* p = selected ? selected->parent() : Q_NULLPTR; p; p = p->parent())
    {
        if (p->isDeleted())
            enable_copy = false;
    }
    pd_ui_->copyToolButton->setEnabled(enable_copy);

    // Walk the selected profiles to collect information to use for buttons and labels
    bool enable_del = false;
    int user_profiles = 0;
    for (const QModelIndex& profile_index : profiles)
    {
        const ProfileItem* profile = model_->getProfile(profile_index);
        if (profile == Q_NULLPTR)
            continue;   //Pacify the static analyzer, but this should never happen.

        // Count the number of user profiles selected
        if (!profile->isGlobal() && !profile->isDefault())
            user_profiles++;

        // Delete the selected personal profiles, ignoring global and deleted profiles
        if (!profile->isGlobal() && !profile->isDeleted())
            enable_del = true;
    }
    pd_ui_->deleteToolButton->setEnabled(enable_del);

    // Handle hints
    QString hintUrl, msg;
    if (numSelected > 1)
    {
        msg = tr("%Ln Personal Profile(s)…", "", user_profiles);
        hintUrl = tr("%Ln personal profile(s) selected", "", user_profiles);
    }
    else
    {
        const ProfileItem* profile = model_->getProfile(index);
        if (profile != Q_NULLPTR)
        {
            // If only one profile is selected, display it's path in the hint label and activate link (if allowed)
            QString profilePath;
            QString temp = model_->dataPath(index, profilePath).toString();
            if (!profilePath.isEmpty())
                pd_ui_->hintLabel->setUrl(QUrl::fromLocalFile(profilePath).toString());
            else
                pd_ui_->hintLabel->setUrl("");

            hintUrl = temp;

            if (!profile->isGlobal() && !profile->isDefault())
                msg = tr("%Ln Personal Profile(s)…", "", 1);
        }
    }

    pd_ui_->hintLabel->setText(hintUrl);
    pd_ui_->hintLabel->setToolTip(index.data(Qt::ToolTipRole).toString());

    QString ignore;
    ok_button_->setEnabled(model_->isDataValid(ignore));


#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
    export_selected_entry_->setText(msg);
    export_selected_entry_->setVisible(user_profiles > 0);

    qsizetype with_children = exportItems(profiles, true).count();
    export_children_entry_->setText(tr("%Ln Personal Profile(s) (including sub-profiles)…", "", static_cast<int>(with_children)));
    export_children_entry_->setVisible(with_children > user_profiles);
#endif
}

void ProfileDialog::clearFilter()
{
    pd_ui_->lineProfileFilter->setText("");
    pd_ui_->cmbProfileTypes->setCurrentIndex(ProfileSortModel::AllProfiles);
    sort_model_->setFilterString();
}

void ProfileDialog::newToolButtonClicked()
{
    // A new profile is created in the same parent as the selected sub-profile
    QString name = tr("New profile");
    const ProfileItem* selected = model_->getProfile(sort_model_->mapToSource(pd_ui_->profileTreeView->currentIndex()));
    const ProfileItem* parent = selected ? selected->parent() : Q_NULLPTR;
    if (parent && !parent->isGlobal() && !parent->isDeleted())
        name = QStringLiteral("%1/%2").arg(parent->getName(), name);

    // If not restoring a deleted profile, add a new one
    if (!restoreSelected())
        addProfile(name);
}

bool ProfileDialog::restoreSelected()
{
    // Restore deleted profiles with their sub-profiles
    QModelIndexList deleted;
    foreach (QModelIndex idx, selectedProfiles())
    {
        const ProfileItem* profile = model_->getProfile(idx);
        if (profile && profile->isDeleted())
            deleted << idx;
    }

    bool restored = model_->restoreEntries(model_->withChildren(deleted));
    if (restored)
        selectionChanged();

    return restored;
}

void ProfileDialog::addProfile(const QString &name)
{
    clearFilter();

    QModelIndex ridx = sort_model_->mapFromSource(model_->addNewProfile(name));
    if (ridx.isValid())
    {
        pd_ui_->profileTreeView->setCurrentIndex(ridx);
        pd_ui_->profileTreeView->scrollTo(ridx);
        pd_ui_->profileTreeView->edit(ridx);
    }
}

void ProfileDialog::profileContextMenu(const QPoint &pos)
{
    QModelIndex idx = sort_model_->mapToSource(pd_ui_->profileTreeView->indexAt(pos));
    const ProfileItem* profile = model_->getProfile(idx);
    if (profile == Q_NULLPTR)
        return;

    QModelIndexList profiles = selectedProfiles();

    QMenu * menu = new QMenu(this);
    menu->setAttribute(Qt::WA_DeleteOnClose);

    // A sub-profile of a global or the default profile cannot be stored
    bool canAddBelow = profiles.count() == 1 && !profile->isGlobal() && !profile->isDeleted() &&
                       !profile->isDefault() && profile->getName().count('/') + 1 < PROFILE_MAX_DEPTH;
    QAction * action = menu->addAction(tr("New sub-profile"), this, [this, profile]() {
        addProfile(QStringLiteral("%1/%2").arg(profile->getName(), tr("New profile")));
    });
    action->setEnabled(canAddBelow);

    action = menu->addAction(tr("Duplicate"), this, &ProfileDialog::copyToolButtonClicked);
    action->setEnabled(pd_ui_->copyToolButton->isEnabled());

    menu->addSeparator();
    // Deleting the default profile resets it
    action = menu->addAction((profiles.count() == 1 && profile->isDefault()) ? tr("Reset") : tr("Delete"), this, &ProfileDialog::deleteToolButtonClicked);
    action->setEnabled(pd_ui_->deleteToolButton->isEnabled());

    foreach (QModelIndex selected, profiles)
    {
        const ProfileItem* item = model_->getProfile(selected);
        if (item && item->isDeleted())
        {
            menu->addAction(tr("Restore"), this, &ProfileDialog::restoreSelected);
            break;
        }
    }

    menu->addSeparator();
    // Import below the selected profile
    QMenu * importMenu = menu->addMenu(tr("Import"));
    importMenu->setEnabled(canAddBelow);
    QString targetName = profile->getName();
#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
    importMenu->addAction(tr("From Zip File…"), this, [this, targetName]() { importFromZip(targetName); });
#endif
    importMenu->addAction(tr("From Directory…"), this, [this, targetName]() { importFromDirectory(targetName); });

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
    QMenu * exportMenu = menu->addMenu(tr("Export"));
    qsizetype exportCount = exportItems(profiles, false).count();
    qsizetype exportChildrenCount = exportItems(profiles, true).count();
    exportMenu->setEnabled(exportCount > 0);
    exportMenu->addAction(tr("%Ln Personal Profile(s)…", "", static_cast<int>(exportCount)),
                          this, [this]() { exportProfiles(); });
    action = exportMenu->addAction(tr("%Ln Personal Profile(s) (including sub-profiles)…", "", static_cast<int>(exportChildrenCount)),
                                   this, [this]() { exportProfiles(false, true); });
    action->setEnabled(exportChildrenCount > exportCount);
#endif

    menu->addSeparator();
#ifdef Q_OS_MACOS
    QString show_in_str = tr("Show in Finder");
#else
    QString show_in_str = tr("Show in Folder");
#endif
    // A new profile has no directory until the changes are applied
    QString path;
    model_->dataPath(idx, path);
    action = menu->addAction(show_in_str, this, [path]() { desktop_show_in_folder(path); });
    action->setEnabled(!path.isEmpty() && QDir(path).exists());

    menu->popup(pd_ui_->profileTreeView->viewport()->mapToGlobal(pos));
}

void ProfileDialog::deleteToolButtonClicked()
{
    QModelIndexList profiles = selectedProfiles();
    if (profiles.count() <= 0)
        return;

    // Show the sub-profiles being deleted
    foreach (QModelIndex idx, profiles)
        pd_ui_->profileTreeView->expandRecursively(sort_model_->mapFromSource(idx));

    model_->deleteEntries(profiles);
    // Update the buttons, as the selected profiles are now either deleted or invalid
    selectionChanged();
}

void ProfileDialog::copyToolButtonClicked()
{
    QModelIndexList profiles = selectedProfiles();
    if (profiles.count() > 1)
        return;

    clearFilter();

    QModelIndex current = pd_ui_->profileTreeView->currentIndex();
    if (current.column() != ProfileModel::COL_NAME)
        current = current.sibling(current.row(), ProfileModel::COL_NAME);

    QModelIndex source = sort_model_->mapToSource(current);
    QModelIndex ridx = model_->duplicateEntry(source);
    if (ridx.isValid())
    {
        // Show the copied sub-profiles
        pd_ui_->profileTreeView->expandRecursively(sort_model_->mapFromSource(ridx));
        pd_ui_->profileTreeView->setCurrentIndex(sort_model_->mapFromSource(ridx));
        pd_ui_->profileTreeView->scrollTo(sort_model_->mapFromSource(ridx));
        pd_ui_->profileTreeView->edit(sort_model_->mapFromSource(ridx));
    }
}

void ProfileDialog::buttonBoxAccepted()
{
    recent.gui_profile_switch_check_count = pd_ui_->autoSwitchSpinBox->value();

    write_profile_recent();

    model_->applyChanges();

    QModelIndex index = sort_model_->mapToSource(pd_ui_->profileTreeView->currentIndex());

    QModelIndexList profiles = selectedProfiles();

    // The current profile may be deleted or moved together with a parent profile
    const ProfileItem* currentProfile = model_->getCurrentProfile();
    bool currentDeleted = (currentProfile != Q_NULLPTR) && currentProfile->isDeleted();
    bool currentMoved = (currentProfile != Q_NULLPTR) && !currentDeleted &&
                        (currentProfile->getName().compare(get_profile_name()) != 0);

    // If multiple profiles are selected, do not change the selected profile,
    // unless the current profile has been deleted or moved
    QString profileName;
    if (profiles.count() == 1 || currentDeleted || currentMoved)
    {
        const ProfileItem* newProfile = (profiles.count() == 1) ? model_->getProfile(index) : currentProfile;

        // Follow the moved current profile instead of switching to a deleted one
        if ((newProfile != Q_NULLPTR) && newProfile->isDeleted() && currentMoved)
            newProfile = currentProfile;

        // If the current profile has been deleted, reset to default
        if ((newProfile == Q_NULLPTR) || (newProfile->isDeleted() && currentDeleted))
            newProfile = model_->getProfile(model_->index(0, ProfileModel::COL_NAME));

        // Switching profile reapplies the fonts, which lays out every widget,
        // including this tree view, while the dialog is still open. The dialog
        // is closing, so detach the view from the model first.
        pd_ui_->profileTreeView->setModel(Q_NULLPTR);

        if ((currentProfile == Q_NULLPTR) ||
            (newProfile != currentProfile) ||
            (newProfile->getName().compare(get_profile_name()) != 0))
        {
            // The new profile exists, change. Another profile may have been
            // given the name of the deleted or moved one, so reload it.
            mainApp->setConfigurationProfile(newProfile->getName().toUtf8().constData(), false, currentDeleted || currentMoved);
        }
        else if (newProfile->isDefault() && currentProfile->isDefault())
        {
            // The default profile is resetting, ensure if reloads
            mainApp->setConfigurationProfile(Q_NULLPTR, false);
        }
    }
}

void ProfileDialog::buttonBoxHelpRequested()
{
    mainApp->helpTopicAction(HELP_CONFIG_PROFILES_DIALOG);
}

void ProfileDialog::dataChanged(const QModelIndex&)
{
    QString hintUrl;

    // Ensure, that the ok button is disabled, if an invalid name is used or if duplicate global profiles exist
    bool enable_ok = model_->isDataValid(hintUrl);

    // Update the currently selected profile's hint label, as the name or path may have changed
    QModelIndex index = sort_model_->mapToSource(pd_ui_->profileTreeView->currentIndex());

    QString profilePath;
    QString temp = model_->dataPath(index, profilePath).toString();
    if (!profilePath.isEmpty())
        pd_ui_->hintLabel->setUrl(QUrl::fromLocalFile(profilePath).toString());
    else
        pd_ui_->hintLabel->setUrl("");

    hintUrl = temp;

    pd_ui_->hintLabel->setText(hintUrl);
    pd_ui_->hintLabel->setToolTip(index.data(Qt::ToolTipRole).toString());

    ok_button_->setEnabled(enable_ok);

    pd_ui_->profileTreeView->viewport()->update();
}

void ProfileDialog::filterChanged(const QString &text)
{
    if (qobject_cast<QComboBox *>(sender()))
    {
        QComboBox * cmb = qobject_cast<QComboBox *>(sender());
        sort_model_->setFilterType(static_cast<ProfileSortModel::FilterType>(cmb->currentIndex()));
    }
    else if (qobject_cast<QLineEdit *>(sender()))
        sort_model_->setFilterString(text);

    // Rows shown again by the filter come back collapsed
    pd_ui_->profileTreeView->expandAll();

    QModelIndex active = sort_model_->mapFromSource(model_->activeProfile());
    if (active.isValid())
        pd_ui_->profileTreeView->setCurrentIndex(active);
}

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
QModelIndexList ProfileDialog::exportItems(const QModelIndexList &items, bool withChildren) const
{
    QModelIndexList result;
    foreach (QModelIndex idx, withChildren ? model_->withChildren(items) : items)
    {
        if (model_->isExportable(idx))
            result << idx;
    }
    return result;
}

void ProfileDialog::exportProfiles(bool exportAllPersonalProfiles, bool withChildren)
{
    QModelIndexList items;
    int skipped = 0;

    if (! exportAllPersonalProfiles)
    {
        // Skip global, default, deleted and imported profiles
        foreach (QModelIndex idx, selectedProfiles())
        {
            if (! exportItems({idx}, false).isEmpty())
                items << idx;
            else
                skipped++;
        }
    }
    else
    {
        // All profiles, also those hidden by the filter
        for (int cnt = 0; cnt < model_->rowCount(); cnt++)
            items << model_->index(cnt, ProfileModel::COL_NAME);
        withChildren = true;
    }
    items = exportItems(items, withChildren);
    if (items.count() == 0)
    {
        QString msg = tr("No profiles found for export");
        if (skipped > 0)
            msg = tr("The selected profiles cannot be exported. Global, default, deleted and not yet applied profiles are not exported.");
        QMessageBox::critical(this, tr("Exporting profiles"), msg);
        return;
    }

    QString zipFile = WiresharkFileDialog::getSaveFileName(this, tr("Select zip file for export"), openDialogInitialDir(), tr("Zip File (*.zip)"));

    if (zipFile.length() > 0)
    {
        QFileInfo fi(zipFile);
        if (fi.suffix().length() == 0 || fi.suffix().toLower().compare("zip") != 0)
            zipFile += ".zip";

        QString err;
        if (model_->exportProfiles(zipFile, items, err))
        {
            QString msg = tr("%Ln profile(s) exported", "", static_cast<int>(items.count()));
            if (skipped > 0)
                msg = tr("%Ln profile(s) exported (%1 skipped)", "", static_cast<int>(items.count())).arg(skipped);
            QMessageBox::information(this, tr("Exporting profiles"), msg);

            QFileInfo zip(zipFile);
            storeLastDir(zip.absolutePath());
        }
        else
        {
            QString msg = err.length() > 0 ? tr("Exporting profiles failed: %1").arg(err)
                                           : tr("Exporting profiles failed");
            QMessageBox::critical(this, tr("Exporting profiles"), msg);
        }
    }
}

void ProfileDialog::importFromZip(const QString &targetParent)
{
    QString zipFile = WiresharkFileDialog::getOpenFileName(this, tr("Select zip file for import"), openDialogInitialDir(), tr("Zip File (*.zip)"));

    QFileInfo fi(zipFile);
    if (! fi.exists())
        return;

    int skipped = 0;
    QStringList import;
    model_->importProfilesFromZip(zipFile, skipped, import, targetParent);

    finishImport(fi, skipped, import);
}
#endif

void ProfileDialog::importFromDirectory(const QString &targetParent)
{
    QString importDir = WiresharkFileDialog::getExistingDirectory(this, tr("Select directory for import"), openDialogInitialDir());

    QFileInfo fi(importDir);
    if (! fi.isDir())
        return;

    int skipped = 0;
    QStringList import;
    model_->importProfilesFromDir(importDir, skipped, import, false, targetParent);

    finishImport(fi, skipped, import);
}

void ProfileDialog::finishImport(QFileInfo fi, int skipped, const QStringList& importedProfiles)
{
    QString msg;
    QMessageBox::Icon icon;

    if (importedProfiles.count() == 0 && skipped == 0)
    {
        icon = QMessageBox::Warning;
        msg = tr("No profiles found for import in %1").arg(fi.fileName());
    }
    else
    {
        icon = QMessageBox::Information;
        msg = tr("%Ln profile(s) imported", "", static_cast<int>(importedProfiles.count()));
        if (skipped > 0)
            msg = tr("%Ln profile(s) imported (%1 skipped)", "", static_cast<int>(importedProfiles.count())).arg(skipped);
    }
    pd_ui_->profileTreeView->expandAll();
    // Deleted parents may have been restored
    selectionChanged();

    QMessageBox msgBox(icon, tr("Importing profiles"), msg, QMessageBox::Ok, this);
    msgBox.exec();

    storeLastDir(fi.absolutePath());
}
