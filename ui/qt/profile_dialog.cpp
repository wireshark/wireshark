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
#include <QTreeWidgetItem>
#include <QUrl>
#include <QComboBox>
#include <QLineEdit>
#include <QStandardPaths>
#include <QKeyEvent>
#include <QMenu>
#include <QMessageBox>

#define PROFILE_EXPORT_PROPERTY "export"
#define PROFILE_EXPORT_ALL "all"
#define PROFILE_EXPORT_SELECTED "selected"

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

    pd_ui_->newToolButton->setStockIcon("list-add");
    pd_ui_->deleteToolButton->setStockIcon("list-remove");
    pd_ui_->copyToolButton->setStockIcon("list-copy");
#ifdef Q_OS_MAC
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
    connect(entry, &QAction::triggered, this, &ProfileDialog::importFromZip, Qt::QueuedConnection);
    entry = importMenu->addAction(tr("From Directory…"));
    connect(entry, &QAction::triggered, this, &ProfileDialog::importFromDirectory, Qt::QueuedConnection);
    import_button_->setMenu(importMenu);

    QMenu * exportMenu = new QMenu(export_button_);
    export_selected_entry_ = exportMenu->addAction(tr("%Ln Selected Personal Profile(s)…", "", 0));
    export_selected_entry_->setProperty(PROFILE_EXPORT_PROPERTY, PROFILE_EXPORT_SELECTED);
    connect(export_selected_entry_, &QAction::triggered, this, &ProfileDialog::exportProfiles, Qt::QueuedConnection);
    entry = exportMenu->addAction(tr("All Personal Profiles…"));
    entry->setProperty(PROFILE_EXPORT_PROPERTY, PROFILE_EXPORT_ALL);
    connect(entry, &QAction::triggered, this, &ProfileDialog::exportProfiles, Qt::QueuedConnection);
    export_button_->setMenu(exportMenu);
#else
    connect(import_button_, &QPushButton::clicked, this, &ProfileDialog::importFromDirectory);
#endif

    model_ = new ProfileModel(pd_ui_->profileTreeView);
    sort_model_ = new ProfileSortModel(pd_ui_->profileTreeView);
    sort_model_->setSourceModel(model_);
    pd_ui_->profileTreeView->setModel(sort_model_);

    connect(model_, &ProfileModel::dataChanged, this, &ProfileDialog::dataChanged, Qt::QueuedConnection);
    QItemSelectionModel* selModel = pd_ui_->profileTreeView->selectionModel();
    connect(selModel, &QItemSelectionModel::selectionChanged, this, &ProfileDialog::selectionChanged);

    // Select the row for the currently selected profile or the first row if non is selected
    selectProfile();

    // Setup filtering
    pd_ui_->cmbProfileTypes->addItems(ProfileSortModel::filterTypes());
    connect(pd_ui_->cmbProfileTypes, &QComboBox::currentTextChanged, this, &ProfileDialog::filterChanged);
    connect(pd_ui_->lineProfileFilter, &QLineEdit::textChanged, this, &ProfileDialog::filterChanged);

    // Setup button handling
    connect(pd_ui_->newToolButton, &StockIconToolButton::clicked, this, &ProfileDialog::newToolButtonClicked);
    connect(pd_ui_->deleteToolButton, &StockIconToolButton::clicked, this, &ProfileDialog::deleteToolButtonClicked);
    connect(pd_ui_->copyToolButton, &StockIconToolButton::clicked, this, &ProfileDialog::copyToolButtonClicked);
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

    int row = model_->findByName(profile);
    QModelIndex idx = sort_model_->mapFromSource(model_->index(row, ProfileModel::COL_NAME));
    pd_ui_->profileTreeView->selectRow(idx.isValid() ? idx.row(): 0);
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
    pd_ui_->copyToolButton->setEnabled(numSelected == 1);

    // Walk the selected profiles to collect information to use for buttons and labels
    bool enable_del = true;
    int user_profiles = 0;
    for (const QModelIndex& profile_index : profiles)
    {
        const ProfileItem* profile = model_->getProfile(profile_index.row());
        if (profile == Q_NULLPTR)
            continue;   //Pacify the static analyzer, but this should never happen.

        // Count the number of user profiles selected
        if (!profile->isGlobal() && !profile->isDefault())
            user_profiles++;

        // Can't delete Global profiles or deleted profiles
        if (profile->isGlobal() || (profile->isDeleted()))
            enable_del = false;
    }
    pd_ui_->deleteToolButton->setEnabled(enable_del);

    // Handle hints
    QString hintUrl, msg;
    if (numSelected > 1)
    {
        msg = tr("%Ln Selected Personal Profile(s)…", "", user_profiles);
        hintUrl = msg;
    }
    else
    {
        const ProfileItem* profile = model_->getProfile(index.row());
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
                msg = tr("%Ln Selected Personal Profile(s)…", "", 1);
        }
    }

    pd_ui_->hintLabel->setText(hintUrl);
    pd_ui_->hintLabel->setToolTip(index.data(Qt::ToolTipRole).toString());

    QString ignore;
    ok_button_->setEnabled(model_->isDataValid(ignore));


#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
    export_selected_entry_->setText(msg);
    export_selected_entry_->setVisible(user_profiles > 0);
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
    clearFilter();

    bool restored = model_->restoreEntries(selectedProfiles());

    if (restored)
    {
        pd_ui_->deleteToolButton->setEnabled(true);
    }
    else
    {
        // If not restoring a deleted profile, add a new one
        QModelIndex ridx = sort_model_->mapFromSource(model_->addNewProfile(tr("New profile")));
        if (ridx.isValid())
        {
            pd_ui_->profileTreeView->setCurrentIndex(ridx);
            pd_ui_->profileTreeView->scrollTo(ridx);
            pd_ui_->profileTreeView->edit(ridx);
        }
    }
}

void ProfileDialog::deleteToolButtonClicked()
{
    QModelIndexList profiles = selectedProfiles();
    if (profiles.count() <= 0)
        return;

    model_->deleteEntries(profiles);
    // Delete button should be disabled after deleting the selected profiles, as they are now either deleted or invalid
    pd_ui_->deleteToolButton->setEnabled(false);
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

    // If multiple profiles are selected, do not change the selected profile
    QString profileName;
    if (profiles.count() == 1)
    {
        const ProfileItem* newProfile = model_->getProfile(index.row());

        // If the current profile has been deleted, reset to default
        if ((newProfile == Q_NULLPTR) || ((newProfile->isDeleted()) &&
            (model_->getCurrentProfile() != Q_NULLPTR) &&
            (newProfile->getName().compare(model_->getCurrentProfile()->getName()) == 0)))
            newProfile = model_->getProfile(0);

        const ProfileItem* currentProfile = model_->getCurrentProfile();
        if ((currentProfile == Q_NULLPTR) ||
            (newProfile->getName() != currentProfile->getName()) ||
            (newProfile->getName().compare(get_profile_name()) != 0) ||
            (newProfile->isGlobal() != currentProfile->isGlobal()))
        {
            // The new profile exists, change.
            mainApp->setConfigurationProfile(newProfile->getName().toUtf8().constData(), false);
        }
        else if (newProfile->isDefault() && currentProfile->isDefault())
        {
            // The default profile is reseting, ensure if reloads
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

    pd_ui_->profileTreeView->dataChanged(sort_model_->mapFromSource(model_->index(0, ProfileModel::COL_NAME)),
        sort_model_->mapFromSource(model_->index(model_->rowCount() - 1, model_->columnCount())));
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

    QModelIndex active = sort_model_->mapFromSource(model_->activeProfile());
    if (active.isValid())
        pd_ui_->profileTreeView->setCurrentIndex(active);
}

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
void ProfileDialog::exportProfiles(bool exportAllPersonalProfiles)
{
    QAction * action = qobject_cast<QAction *>(sender());
    if (action && action->property(PROFILE_EXPORT_PROPERTY).isValid())
        exportAllPersonalProfiles = action->property(PROFILE_EXPORT_PROPERTY).toString().compare(PROFILE_EXPORT_ALL) == 0;

    QModelIndexList items;
    int skipped = 0;

    if (! exportAllPersonalProfiles)
    {
        foreach (QModelIndex idx, selectedProfiles())
        {
            QModelIndex baseIdx = sort_model_->index(idx.row(), ProfileModel::COL_NAME);
            if (! baseIdx.data(ProfileModel::DATA_IS_GLOBAL).toBool() && ! baseIdx.data(ProfileModel::DATA_IS_DEFAULT).toBool())
                items << sort_model_->mapToSource(baseIdx);
            else
                skipped++;
        }
    }
    else if (exportAllPersonalProfiles)
    {
        for (int cnt = 0; cnt < sort_model_->rowCount(); cnt++)
        {
            QModelIndex idx = sort_model_->index(cnt, ProfileModel::COL_NAME);
            if (! idx.data(ProfileModel::DATA_IS_GLOBAL).toBool() && ! idx.data(ProfileModel::DATA_IS_DEFAULT).toBool())
                items << sort_model_->mapToSource(idx);
        }
    }
    if (items.count() == 0)
    {
        QString msg = tr("No profiles found for export");
        if (skipped > 0)
            msg.append(tr(", %Ln profile(s) skipped", "", skipped));
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
                msg.append(tr(", %Ln profile(s) skipped", "", skipped));
            QMessageBox::information(this, tr("Exporting profiles"), msg);

            QFileInfo zip(zipFile);
            storeLastDir(zip.absolutePath());
        }
        else
        {
            QString msg = tr("An error has occurred while exporting profiles");
             if (err.length() > 0)
                 msg.append(QStringLiteral("\n\n%1: %2").arg(tr("Error"), err));
            QMessageBox::critical(this, tr("Exporting profiles"), msg);
        }
    }
}

void ProfileDialog::importFromZip()
{
    QString zipFile = WiresharkFileDialog::getOpenFileName(this, tr("Select zip file for import"), openDialogInitialDir(), tr("Zip File (*.zip)"));

    QFileInfo fi(zipFile);
    if (! fi.exists())
        return;

    int skipped = 0;
    QStringList import;
    model_->importProfilesFromZip(zipFile, skipped, import);

    finishImport(fi, skipped, import);
}
#endif

void ProfileDialog::importFromDirectory()
{
    QString importDir = WiresharkFileDialog::getExistingDirectory(this, tr("Select directory for import"), openDialogInitialDir());

    QFileInfo fi(importDir);
    if (! fi.isDir())
        return;

    int skipped = 0;
    QStringList import;
    model_->importProfilesFromDir(importDir, skipped, import, false);

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
            msg.append(tr(", %Ln profile(s) skipped", "", skipped));
    }
    QMessageBox msgBox(icon, tr("Importing profiles"), msg, QMessageBox::Ok, this);
    msgBox.exec();

    storeLastDir(fi.absolutePath());
}
