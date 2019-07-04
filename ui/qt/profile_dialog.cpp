/* profile_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <glib.h>

#include "wsutil/filesystem.h"
#include "epan/prefs.h"

#include <ui/qt/utils/qt_ui_utils.h>

#include "ui/profile.h"
#include "ui/recent.h"

#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/models/profile_model.h>

#include "profile_dialog.h"
#include <ui_profile_dialog.h>
#include "wireshark_application.h"
#include <ui/qt/utils/color_utils.h>

#include <QBrush>
#include <QDir>
#include <QFont>
#include <QMessageBox>
#include <QPushButton>
#include <QTreeWidgetItem>
#include <QUrl>
#include <QComboBox>
#include <QLineEdit>

ProfileDialog::ProfileDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    pd_ui_(new Ui::ProfileDialog),
    ok_button_(Q_NULLPTR),
    model_(Q_NULLPTR),
    sort_model_(Q_NULLPTR)
{
    pd_ui_->setupUi(this);
    loadGeometry();
    setWindowTitle(wsApp->windowTitleString(tr("Configuration Profiles")));

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
    pd_ui_->infoLabel->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    model_ = new ProfileModel(this);
    sort_model_ = new ProfileSortModel(this);
    sort_model_->setSourceModel(model_);
    pd_ui_->profileTreeView->setModel(sort_model_);

    connect(pd_ui_->profileTreeView, &ProfileTreeView::currentItemChanged,
            this, &ProfileDialog::currentItemChanged);

    connect(pd_ui_->profileTreeView->itemDelegate(), SIGNAL(closeEditor(QWidget*, QAbstractItemDelegate::EndEditHint)),
            this, SLOT(editingFinished()));

    /* Select the row for the currently selected profile or the first row if non is selected*/
    selectProfile();

    QStringList items;
    items << tr("All Profiles") << tr("Global profiles") << tr("User-defined profiles");
    pd_ui_->cmbProfileTypes->addItems(items);

    connect (pd_ui_->cmbProfileTypes, SIGNAL(currentTextChanged(const QString &)),
              this, SLOT(filterChanged(const QString &)));
    connect (pd_ui_->lineProfileFilter, SIGNAL(textChanged(const QString &)),
              this, SLOT(filterChanged(const QString &)));

    updateWidgets();
}

ProfileDialog::~ProfileDialog()
{
    delete pd_ui_;
    empty_profile_list (TRUE);
}

void ProfileDialog::selectProfile(QString profile)
{
    if ( profile.isEmpty() )
        profile = QString(get_profile_name());

    int row = model_->findByName(profile);
    QModelIndex idx = sort_model_->mapFromSource(model_->index(row, ProfileModel::COL_NAME));
    if ( idx.isValid() )
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
        on_newToolButton_clicked();
        ret = exec();
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
            wsApp->setConfigurationProfile (Q_NULLPTR);
        }
        break;
    }
    return ret;
}

void ProfileDialog::updateWidgets()
{
    bool enable_del = false;
    bool enable_ok = true;

    QModelIndex index = sort_model_->mapToSource(pd_ui_->profileTreeView->currentIndex());
    if ( index.column() != ProfileModel::COL_NAME )
        index = index.sibling(index.row(), ProfileModel::COL_NAME);

    if (index.isValid()) {
        if ( !index.data(ProfileModel::DATA_IS_GLOBAL).toBool() && ! model_->resetDefault())
            enable_del = true;
    }

    if (model_ && model_->rowCount() > 0)
    {
        for ( int row = 0; row < model_->rowCount(); row++ )
        {
            QModelIndex idx = model_->index(row, ProfileModel::COL_NAME);
            QString name = idx.data().toString();

            if (gchar * err_msg = profile_name_is_valid(name.toLatin1().data()))
            {
                pd_ui_->infoLabel->setText(gchar_free_to_qstring(err_msg));
                enable_ok = false;
                continue;
            }

            if ( idx != index && idx.data().toString().compare(index.data().toString()) == 0 )
            {
                if (idx.data(ProfileModel::DATA_IS_GLOBAL).toBool() == index.data(ProfileModel::DATA_IS_GLOBAL).toBool())
                {
                    int status = index.data(ProfileModel::DATA_STATUS).toInt();
                    if (status != PROF_STAT_DEFAULT && status != PROF_STAT_EXISTS)
                        pd_ui_->infoLabel->setText(tr("A profile already exists with this name"));
                    enable_ok = false;
                }
            }
        }
    }

    pd_ui_->profileTreeView->resizeColumnToContents(0);
    pd_ui_->deleteToolButton->setEnabled(enable_del);
    ok_button_->setEnabled(enable_ok);
}

void ProfileDialog::currentItemChanged()
{
    updateWidgets();
}

void ProfileDialog::on_newToolButton_clicked()
{
    if ( model_->findByName(tr("New profile")) >= 0 )
        return;

    pd_ui_->cmbProfileTypes->setCurrentIndex(ProfileSortModel::UserProfiles);
    sort_model_->setFilterString();

    QModelIndex ridx = sort_model_->mapFromSource(model_->addNewProfile(tr("New profile")));
    if (ridx.isValid())
    {
        pd_ui_->profileTreeView->setCurrentIndex(ridx);
        pd_ui_->profileTreeView->edit(ridx);
    }
}

void ProfileDialog::on_deleteToolButton_clicked()
{
    QModelIndex index = sort_model_->mapToSource(pd_ui_->profileTreeView->currentIndex());

    model_->deleteEntry(index);
}

void ProfileDialog::on_copyToolButton_clicked()
{
    pd_ui_->cmbProfileTypes->setCurrentIndex(ProfileSortModel::AllProfiles);
    sort_model_->setFilterString();

    QModelIndex current = pd_ui_->profileTreeView->currentIndex();
    if ( current.column() != ProfileModel::COL_NAME )
        current = current.sibling(current.row(), ProfileModel::COL_NAME);

    QModelIndex source = sort_model_->mapToSource(current);
    QModelIndex ridx = model_->duplicateEntry(source);
    if (ridx.isValid())
    {
        pd_ui_->profileTreeView->setCurrentIndex(sort_model_->mapFromSource(ridx));
        pd_ui_->profileTreeView->edit(sort_model_->mapFromSource(ridx));
    }
}

void ProfileDialog::on_buttonBox_accepted()
{
    QModelIndex default_item = sort_model_->mapFromSource(model_->index(0, ProfileModel::COL_NAME));
    QModelIndex index = sort_model_->mapToSource(pd_ui_->profileTreeView->currentIndex());
    if (index.column() != ProfileModel::COL_NAME)
        index = index.sibling(index.row(), ProfileModel::COL_NAME);

    bool write_recent = true;
    bool item_data_removed = false;

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
        wsApp->emitAppSignal(WiresharkApplication::ProfileChanging);

        /* Write recent file for current profile now because
         * the profile may be renamed in apply_profile_changes() */
        write_profile_recent();
    }

    gchar * err_msg = Q_NULLPTR;
    if ((err_msg = apply_profile_changes()) != Q_NULLPTR) {
        QMessageBox::critical(this, tr("Profile Error"),
                              err_msg,
                              QMessageBox::Ok);
        g_free(err_msg);

        model_->doResetModel();
        return;
    }

    model_->doResetModel();

    const char * profile_name = Q_NULLPTR;
    if (index.isValid() && !item_data_removed) {
        QString profileName = model_->data(index).toString();
        profile_name = profileName.toLatin1().data();
    }

    if (profile_exists (profile_name, FALSE) || profile_exists (profile_name, TRUE)) {
        // The new profile exists, change.
        wsApp->setConfigurationProfile (profile_name, FALSE);
    } else if (!profile_exists (get_profile_name(), FALSE)) {
        // The new profile does not exist, and the previous profile has
        // been deleted.  Change to the default profile.
        wsApp->setConfigurationProfile (Q_NULLPTR, FALSE);
    }
}

void ProfileDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_CONFIG_PROFILES_DIALOG);
}

void ProfileDialog::editingFinished()
{
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

    pd_ui_->profileTreeView->resizeColumnToContents(ProfileModel::COL_NAME);

    QModelIndex active = sort_model_->mapFromSource(model_->activeProfile());
    if (active.isValid())
        pd_ui_->profileTreeView->setCurrentIndex(active);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
