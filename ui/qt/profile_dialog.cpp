/* profile_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "wsutil/filesystem.h"

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

    // XXX - Use NSImageNameAddTemplate and NSImageNameRemoveTemplate to set stock
    // icons on macOS.
    // Are there equivalent stock icons on Windows?
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
    if (!is_packet_configuration_namespace()) {
        pd_ui_->autoSwitchLimitLabel->setText(tr("Auto switch event limit"));
    }
    pd_ui_->autoSwitchSpinBox->setValue(recent.gui_profile_switch_check_count);

    import_button_ = pd_ui_->buttonBox->addButton(tr("Import", "noun"), QDialogButtonBox::ActionRole);

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
    export_button_ = pd_ui_->buttonBox->addButton(tr("Export", "noun"), QDialogButtonBox::ActionRole);

    QMenu * importMenu = new QMenu(import_button_);
    QAction * entry = importMenu->addAction(tr("From Zip File..."));
    connect(entry, &QAction::triggered, this, &ProfileDialog::importFromZip, Qt::QueuedConnection);
    entry = importMenu->addAction(tr("From Directory..."));
    connect(entry, &QAction::triggered, this, &ProfileDialog::importFromDirectory, Qt::QueuedConnection);
    import_button_->setMenu(importMenu);

    QMenu * exportMenu = new QMenu(export_button_);
    export_selected_entry_ = exportMenu->addAction(tr("%Ln Selected Personal Profile(s)...", "", 0));
    export_selected_entry_->setProperty(PROFILE_EXPORT_PROPERTY, PROFILE_EXPORT_SELECTED);
    connect(export_selected_entry_, &QAction::triggered, this, &ProfileDialog::exportProfiles, Qt::QueuedConnection);
    entry = exportMenu->addAction(tr("All Personal Profiles..."));
    entry->setProperty(PROFILE_EXPORT_PROPERTY, PROFILE_EXPORT_ALL);
    connect(entry, &QAction::triggered, this, &ProfileDialog::exportProfiles, Qt::QueuedConnection);
    export_button_->setMenu(exportMenu);
#else
    connect(import_button_, &QPushButton::clicked, this, &ProfileDialog::importFromDirectory);
#endif

    resetTreeView();

    /* Select the row for the currently selected profile or the first row if non is selected*/
    selectProfile();

    pd_ui_->cmbProfileTypes->addItems(ProfileSortModel::filterTypes());

    connect (pd_ui_->cmbProfileTypes, &QComboBox::currentTextChanged,
              this, &ProfileDialog::filterChanged);
    connect (pd_ui_->lineProfileFilter, &QLineEdit::textChanged,
              this, &ProfileDialog::filterChanged);

    currentItemChanged();

    connect(pd_ui_->newToolButton, &StockIconToolButton::clicked, this, &ProfileDialog::newToolButtonClicked);
    connect(pd_ui_->deleteToolButton, &StockIconToolButton::clicked, this, &ProfileDialog::deleteToolButtonClicked);
    connect(pd_ui_->copyToolButton, &StockIconToolButton::clicked, this, &ProfileDialog::copyToolButtonClicked);
    connect(pd_ui_->buttonBox, &QDialogButtonBox::accepted, this, &ProfileDialog::buttonBoxAccepted);
    connect(pd_ui_->buttonBox, &QDialogButtonBox::rejected, this, &ProfileDialog::buttonBoxRejected);
    connect(pd_ui_->buttonBox, &QDialogButtonBox::helpRequested, this, &ProfileDialog::buttonBoxHelpRequested);

    pd_ui_->profileTreeView->resizeColumnToContents(ProfileModel::COL_NAME);
    pd_ui_->profileTreeView->resizeColumnToContents(ProfileModel::COL_TYPE);

    pd_ui_->profileTreeView->setFocus();
}

ProfileDialog::~ProfileDialog()
{
    delete pd_ui_;
    empty_profile_list (true);
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
    if (idx.isValid())
        pd_ui_->profileTreeView->selectRow(idx.row());
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
        if (delete_current_profile()) {
            mainApp->setConfigurationProfile (Q_NULLPTR);
        }
        break;
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
    if (selectedProfiles().count() == 0)
        pd_ui_->profileTreeView->selectRow(0);

    updateWidgets();
}

void ProfileDialog::updateWidgets()
{
    bool enable_del = true;
    bool enable_ok = true;
    bool multiple = false;
    bool enable_import = true;
    int user_profiles = 0;

    QString msg;
    QModelIndex index = sort_model_->mapToSource(pd_ui_->profileTreeView->currentIndex());
    QModelIndexList profiles = selectedProfiles();

    /* Ensure that the index is always the name column */
    if (index.column() != ProfileModel::COL_NAME)
        index = index.sibling(index.row(), ProfileModel::COL_NAME);

    /* check if more than one viable profile is selected, and inform the sorting model */
    if (profiles.count() > 1)
        multiple = true;

    /* Check if user profiles have been selected and allow export if it is so */
    for (int cnt = 0; cnt < profiles.count(); cnt++)
    {
        if (! profiles[cnt].data(ProfileModel::DATA_IS_GLOBAL).toBool() && ! profiles[cnt].data(ProfileModel::DATA_IS_DEFAULT).toBool())
            user_profiles++;
    }
    if (model_->changesPending())
    {
        enable_import = false;
        msg = tr("An import of profiles is not allowed, while changes are pending");
    }
    else if (model_->importPending())
    {
        enable_import = false;
        msg = tr("An import is pending to be saved. Additional imports are not allowed");
    }
    import_button_->setToolTip(msg);
    import_button_->setEnabled(enable_import);

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
    bool contains_user = false;
    bool enable_export = false;

    if (user_profiles > 0)
        contains_user = true;

    /* enable export if no changes are pending */
    if (! model_->changesPending())
        enable_export = true;

    export_button_->setEnabled(enable_export);
    if (! enable_export)
    {
        if (! contains_user)
            export_button_->setToolTip(tr("An export of profiles is only allowed for personal profiles"));
        else
            export_button_->setToolTip(tr("An export of profiles is not allowed, while changes are pending"));
    }
    export_selected_entry_->setVisible(contains_user);
#endif

    /* if the current profile is default with reset pending or a global one, deactivate delete */
    if (! multiple)
    {
        if (index.isValid())
        {
            if (index.data(ProfileModel::DATA_IS_GLOBAL).toBool())
                enable_del = false;
            else if (index.data(ProfileModel::DATA_IS_DEFAULT).toBool() && model_->resetDefault())
                enable_del = false;
        }
        else if (! index.isValid())
            enable_del = false;
    }

    QString hintUrl;
    msg.clear();
    if (multiple)
    {
        /* multiple profiles are being selected, copy is no longer allowed */
        pd_ui_->copyToolButton->setEnabled(false);

        msg = tr("%Ln Selected Personal Profile(s)...", "", user_profiles);
        pd_ui_->hintLabel->setText(msg);
#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
        export_selected_entry_->setText(msg);
#endif
    }
    else
    {
        /* if only one profile is selected, display it's path in the hint label and activate link (if allowed) */
        if (index.isValid())
        {
            QString temp = index.data(ProfileModel::DATA_PATH).toString();
            if (index.data(ProfileModel::DATA_PATH_IS_NOT_DESCRIPTION).toBool() && QFileInfo(temp).isDir())
                hintUrl = QUrl::fromLocalFile(temp).toString();
            pd_ui_->hintLabel->setText(temp);
            pd_ui_->hintLabel->setToolTip(index.data(Qt::ToolTipRole).toString());

            if (! index.data(ProfileModel::DATA_IS_GLOBAL).toBool() && ! index.data(ProfileModel::DATA_IS_DEFAULT).toBool())
                msg = tr("%Ln Selected Personal Profile(s)...", "", 1);
        }

        pd_ui_->copyToolButton->setEnabled(true);
#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
        export_selected_entry_->setText(msg);
#endif
    }

    /* Ensure, that the ok button is disabled, if an invalid name is used or if duplicate global profiles exist */
    if (model_ && model_->rowCount() > 0)
    {
        msg.clear();
        for (int row = 0; row < model_->rowCount() && enable_ok; row++)
        {
            QModelIndex idx = model_->index(row, ProfileModel::COL_NAME);
            QString name = idx.data().toString();

            if (! ProfileModel::checkNameValidity(name, &msg))
            {
                if (idx == index || selectedProfiles().contains(idx))
                {
                    hintUrl.clear();
                    pd_ui_->hintLabel->setText(msg);
                }

                enable_ok = false;
                continue;
            }

            if (model_->checkInvalid(idx) || (! idx.data(ProfileModel::DATA_IS_GLOBAL).toBool() && model_->checkIfDeleted(idx)) )
            {
                if (idx == index)
                    hintUrl.clear();
                enable_ok = false;
                continue;
            }

            if (idx != index && idx.data().toString().compare(index.data().toString()) == 0)
            {
                if (idx.data(ProfileModel::DATA_IS_GLOBAL).toBool() == index.data(ProfileModel::DATA_IS_GLOBAL).toBool())
                    enable_ok = false;
            }

            QList<int> rows = model_->findAllByNameAndVisibility(name, idx.data(ProfileModel::DATA_IS_GLOBAL).toBool());
            if (rows.count() > 1)
                enable_ok = false;
        }

        if (enable_ok && ! model_->checkIfDeleted(index) && index.data(ProfileModel::DATA_STATUS).toInt() == PROF_STAT_CHANGED)
            hintUrl.clear();
    }

    pd_ui_->hintLabel->setUrl(hintUrl);

    pd_ui_->deleteToolButton->setEnabled(enable_del);
    ok_button_->setEnabled(enable_ok);
}

void ProfileDialog::currentItemChanged(const QModelIndex &, const QModelIndex &)
{
    updateWidgets();
}

void ProfileDialog::newToolButtonClicked()
{
    pd_ui_->lineProfileFilter->setText("");
    pd_ui_->cmbProfileTypes->setCurrentIndex(ProfileSortModel::AllProfiles);
    sort_model_->setFilterString();

    QModelIndex ridx = sort_model_->mapFromSource(model_->addNewProfile(tr("New profile")));
    if (ridx.isValid())
    {
        pd_ui_->profileTreeView->setCurrentIndex(ridx);
        pd_ui_->profileTreeView->scrollTo(ridx);
        pd_ui_->profileTreeView->edit(ridx);
        currentItemChanged();
    }
    else
        updateWidgets();
}

void ProfileDialog::deleteToolButtonClicked()
{
    QModelIndexList profiles = selectedProfiles();
    if (profiles.count() <= 0)
        return;

    model_->deleteEntries(profiles);

    bool isGlobal = model_->activeProfile().data(ProfileModel::DATA_IS_GLOBAL).toBool();
    int row = model_->findByName(model_->activeProfile().data().toString());
    /* If the active profile is deleted, the default is selected next */
    if (row < 0)
        row = 0;
    QModelIndex newIdx = sort_model_->mapFromSource(model_->index(row, 0));
    if (newIdx.data(ProfileModel::DATA_IS_GLOBAL).toBool() != isGlobal)
        newIdx =  sort_model_->mapFromSource(model_->index(0, 0));

    pd_ui_->profileTreeView->setCurrentIndex(newIdx);

    updateWidgets();
}

void ProfileDialog::copyToolButtonClicked()
{
    QModelIndexList profiles = selectedProfiles();
    if (profiles.count() > 1)
        return;

    pd_ui_->lineProfileFilter->setText("");
    pd_ui_->cmbProfileTypes->setCurrentIndex(ProfileSortModel::AllProfiles);
    sort_model_->setFilterString();

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
        currentItemChanged();
    }
    else
        updateWidgets();
}

void ProfileDialog::buttonBoxAccepted()
{
    bool write_recent = true;
    bool item_data_removed = false;

    recent.gui_profile_switch_check_count = pd_ui_->autoSwitchSpinBox->value();

    QModelIndex index = sort_model_->mapToSource(pd_ui_->profileTreeView->currentIndex());

    pd_ui_->buttonBox->setFocus();

    QModelIndexList profiles = selectedProfiles();
    if (profiles.count() <= 0)
        index = QModelIndex();

    QModelIndex default_item = sort_model_->mapFromSource(model_->index(0, ProfileModel::COL_NAME));
    if (index.isValid() && index.column() != ProfileModel::COL_NAME)
        index = index.sibling(index.row(), ProfileModel::COL_NAME);

    if (default_item.data(ProfileModel::DATA_STATUS).toInt() == PROF_STAT_DEFAULT && model_->resetDefault())
    {
        // Reset Default profile.
        GList *fl_entry = model_->at(0);
        remove_from_profile_list(fl_entry);

        // Don't write recent file if leaving the Default profile after this has been reset.
        write_recent = !is_default_profile();

        // Don't fetch profile data if removed.
        item_data_removed = (index.row() == 0);
    }

    if (write_recent) {
        /* Get the current geometry, before writing it to disk */
        mainApp->emitAppSignal(MainApplication::ProfileChanging);

        /* Write recent file for current profile now because
         * the profile may be renamed in apply_profile_changes() */
        write_profile_recent();
    }

    char * err_msg = Q_NULLPTR;
    if ((err_msg = apply_profile_changes()) != Q_NULLPTR) {
        QMessageBox::critical(this, tr("Profile Error"),
                              err_msg,
                              QMessageBox::Ok);
        g_free(err_msg);

        model_->doResetModel();
        return;
    }

    model_->doResetModel();

    QString profileName;

    if (! index.isValid() && model_->lastSetRow() >= 0)
    {
        QModelIndex original = model_->index(model_->lastSetRow(), ProfileModel::COL_NAME);
        index = sort_model_->mapFromSource(original);
    }

    /* If multiple profiles are selected, do not change the selected profile */
    if (index.isValid() && ! item_data_removed && profiles.count() <= 1)
    {
        profileName = model_->data(index).toString();
    }

    if (profileName.length() > 0 && model_->findByName(profileName) >= 0) {
        // The new profile exists, change.
        mainApp->setConfigurationProfile (profileName.toUtf8().constData(), false);
    } else if (!model_->activeProfile().isValid()) {
        // The new profile does not exist, and the previous profile has
        // been deleted.  Change to the default profile.
        mainApp->setConfigurationProfile (Q_NULLPTR, false);
    }
}

void ProfileDialog::buttonBoxRejected()
{
    QString msg;
    if (! model_->clearImported(&msg))
        QMessageBox::critical(this, tr("Error"), msg);
}

void ProfileDialog::buttonBoxHelpRequested()
{
    mainApp->helpTopicAction(HELP_CONFIG_PROFILES_DIALOG);
}

void ProfileDialog::dataChanged(const QModelIndex &)
{
    pd_ui_->lineProfileFilter->setText("");
    pd_ui_->cmbProfileTypes->setCurrentIndex(ProfileSortModel::AllProfiles);

    pd_ui_->profileTreeView->setFocus();
    if (model_->lastSetRow() >= 0)
    {
        QModelIndex original = model_->index(model_->lastSetRow(), ProfileModel::COL_NAME);
        pd_ui_->profileTreeView->setCurrentIndex(sort_model_->mapFromSource(original));
        pd_ui_->profileTreeView->selectRow(sort_model_->mapFromSource(original).row());
    }

    updateWidgets();
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
        if (model_->exportProfiles(zipFile, items, &err))
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
                 msg.append(QString("\n\n%1: %2").arg(tr("Error"), err));
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
    int count = model_->importProfilesFromZip(zipFile, &skipped, &import);

    finishImport(fi, count, skipped, import);
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
    int count = model_->importProfilesFromDir(importDir, &skipped, false, &import);

    finishImport(fi, count, skipped, import);
}

void ProfileDialog::finishImport(QFileInfo fi, int count, int skipped, QStringList import)
{
    QString msg;
    QMessageBox::Icon icon;

    if (count == 0 && skipped == 0)
    {
        icon = QMessageBox::Warning;
        msg = tr("No profiles found for import in %1").arg(fi.fileName());
    }
    else
    {
        icon = QMessageBox::Information;
        msg = tr("%Ln profile(s) imported", "", count);
        if (skipped > 0)
            msg.append(tr(", %Ln profile(s) skipped", "", skipped));
    }
    QMessageBox msgBox(icon, tr("Importing profiles"), msg, QMessageBox::Ok, this);
    msgBox.exec();

    storeLastDir(fi.absolutePath());

    if (count > 0)
    {
        import.sort();
        resetTreeView();
        model_->markAsImported(import);
        int rowFirstImported = model_->findByName(import.at(0));
        QModelIndex idx = sort_model_->mapFromSource(model_->index(rowFirstImported, ProfileModel::COL_NAME));
        pd_ui_->profileTreeView->selectRow(idx.isValid() ? idx.row() : 0);
    }

    updateWidgets();
}

void ProfileDialog::resetTreeView()
{
    if (model_)
    {
        pd_ui_->profileTreeView->setModel(Q_NULLPTR);
        sort_model_->setSourceModel(Q_NULLPTR);
        model_->disconnect();
        if (pd_ui_->profileTreeView->selectionModel())
            pd_ui_->profileTreeView->selectionModel()->disconnect();
        delete sort_model_;
        delete model_;
    }

    model_ = new ProfileModel(pd_ui_->profileTreeView);
    sort_model_ = new ProfileSortModel(pd_ui_->profileTreeView);
    sort_model_->setSourceModel(model_);
    pd_ui_->profileTreeView->setModel(sort_model_);

    connect(model_, &ProfileModel::itemChanged, this, &ProfileDialog::dataChanged, Qt::QueuedConnection);
    QItemSelectionModel *selModel = pd_ui_->profileTreeView->selectionModel();
    connect(selModel, &QItemSelectionModel::currentChanged,
            this, &ProfileDialog::currentItemChanged, Qt::QueuedConnection);
    connect(selModel, &QItemSelectionModel::selectionChanged,
            this, &ProfileDialog::selectionChanged);

    selectionChanged();

    if (sort_model_->columnCount() <= 1) {
        pd_ui_->profileTreeView->header()->hide();
    }
}

