/* uat_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "uat_dialog.h"
#include <ui_uat_dialog.h>
#include "main_application.h"

#include "epan/strutil.h"
#include "epan/uat-int.h"
#include "ui/help_url.h"
#include <wsutil/report_message.h>
#include <app/application_flavor.h>

#include <ui/qt/widgets/copy_from_profile_button.h>
#include <ui/qt/widgets/list_edit_buttons.h>
#include <ui/qt/utils/hide_overridden_rows.h>
#include <ui/qt/widgets/profile_inherit_combo_box.h>
#include <ui/qt/utils/inherit_selection.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/themed_icon.h>

#include <QDesktopServices>
#include <QPushButton>
#include <QUrl>

#include <QDebug>

// NOTE currently uat setter is always invoked in UatModel even if the uat checker fails.

UatDialog::UatDialog(QWidget *parent, epan_uat *uat) :
    GeometryStateDialog(parent),
    ui(new Ui::UatDialog),
    uat_model_(NULL),
    uat_delegate_(NULL),
    uat_(uat),
    copy_button_(NULL),
    inherit_combo_(NULL)
{
    ui->setupUi(this);

    ListEditButtons::ToolTips tool_tips;
    tool_tips.add = tr("Create a new entry.");
    tool_tips.remove = tr("Remove the selected entries.");
    tool_tips.copy = tr("Copy the selected entries.");
    tool_tips.moveUp = tr("Move the selected entries up.");
    tool_tips.moveDown = tr("Move the selected entries down.");
    tool_tips.clear = tr("Clear all entries.");
    ui->editButtons->setToolTips(tool_tips);
    connect(ui->editButtons, &ListEditButtons::newClicked, this, &UatDialog::newClicked);
    connect(ui->editButtons, &ListEditButtons::deleteClicked, this, &UatDialog::deleteClicked);
    connect(ui->editButtons, &ListEditButtons::copyClicked, this, &UatDialog::copyClicked);
    connect(ui->editButtons, &ListEditButtons::moveUpClicked, ui->uatTreeView, &RowMoveTreeView::moveSelectedRowsUp);
    connect(ui->editButtons, &ListEditButtons::moveDownClicked, ui->uatTreeView, &RowMoveTreeView::moveSelectedRowsDown);
    connect(ui->editButtons, &ListEditButtons::clearClicked, this, &UatDialog::clearClicked);
    if (uat) loadGeometry(0, 0, uat->name);

    ok_button_ = ui->buttonBox->button(QDialogButtonBox::Ok);
    help_button_ = ui->buttonBox->button(QDialogButtonBox::Help);

#ifdef Q_OS_MACOS
    ui->pathLabel->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    setUat(uat);

    // FIXME: this prevents the columns from being resized, even if the text
    // within a combobox needs more space (e.g. in the USER DLT settings).  For
    // very long filenames in the TLS RSA keys dialog, it also results in a
    // vertical scrollbar. Maybe remove this since the editor is not limited to
    // the column width (and overlays other fields if more width is needed)?
    ui->uatTreeView->header()->setSectionResizeMode(QHeaderView::Interactive);

    // start editing as soon as the field is selected or when typing starts
    ui->uatTreeView->setEditTriggers(ui->uatTreeView->editTriggers() |
            QAbstractItemView::CurrentChanged | QAbstractItemView::AnyKeyPressed);

    // Do NOT start editing the first column for the first item
    ui->uatTreeView->setCurrentIndex(QModelIndex());
}

UatDialog::~UatDialog()
{
    delete ui;
    delete uat_delegate_;
    delete uat_model_;
}

void UatDialog::setUat(epan_uat *uat)
{
    QString title(tr("Unknown User Accessible Table"));

    uat_ = uat;

    ui->pathLabel->clear();
    ui->pathLabel->setEnabled(false);
    help_button_->setEnabled(false);

    if (uat_) {
        if (uat_->name) {
            title = uat_->name;
        }

        if (uat->from_profile) {
            copy_button_ = new CopyFromProfileButton(this, uat->filename);
            ui->buttonBox->addButton(copy_button_, QDialogButtonBox::ActionRole);
            connect(copy_button_, &CopyFromProfileButton::copyProfile, this, &UatDialog::copyFromProfile);

            // Where the records come from, next to the button clearing them
            inherit_combo_ = ProfileInheritComboBox::addNextTo(this, ui->horizontalLayout, ui->editButtons, uat->filename);
            inherit_combo_->syncMode(uat_get_inherit_mode(uat_));
            connect(inherit_combo_, &ProfileInheritComboBox::modeChanged, this, &UatDialog::inheritModeChanged);
        }

        uat_model_ = new UatModel(NULL, uat);
        uat_delegate_ = new UatDelegate;
        ui->uatTreeView->setModel(uat_model_);
        ui->uatTreeView->setItemDelegate(uat_delegate_);

        if (inherit_combo_) {
            // Not used records can be hidden, which is not stored
            addHideNotUsedCheckBox(this, ui->horizontalLayout, inherit_combo_, ui->uatTreeView, uat_model_, uat->enabled_field);
        }
        resizeColumns();
        updatePathLabel();
        followInheritedProfiles(uat_model_, this, &UatDialog::updatePathLabel);
        updateWidgets();

        connect(uat_model_, SIGNAL(dataChanged(QModelIndex,QModelIndex)),
                this, SLOT(modelDataChanged(QModelIndex)));
        connect(uat_model_, SIGNAL(rowsRemoved(QModelIndex, int, int)),
                this, SLOT(modelRowsRemoved()));
        connect(uat_model_, SIGNAL(modelReset()), this, SLOT(modelRowsReset()));
        connect(uat_model_, &UatModel::rowsMoved, this, &UatDialog::updateWidgets);

        connect(ui->uatTreeView->selectionModel(), &QItemSelectionModel::selectionChanged,
                this, &UatDialog::uatTreeViewSelectionChanged);

        ok_button_->setEnabled(!uat_model_->hasErrors());

        if (uat_->help && strlen(uat_->help) > 0) {
            help_button_->setEnabled(true);
        }

        connect(this, SIGNAL(rejected()), this, SLOT(rejectChanges()));
        connect(this, SIGNAL(accepted()), this, SLOT(acceptChanges()));
    }

    setWindowTitle(title);
}

void UatDialog::updatePathLabel()
{
    bool own_used = !inherit_combo_ || inherit_combo_->mode() != PROFILE_INHERIT_PARENT_ONLY;
    QString abs_path = own_used ? gchar_free_to_qstring(uat_get_actual_filename(uat_, false, application_configuration_environment_prefix())) : QString();
    QString own_text = !own_used ? QString() : abs_path.length() > 0 ? abs_path : QString(uat_->filename);

    if (inherit_combo_) {
        inherit_combo_->setPathText(ui->pathLabel, own_text, inheritedProfiles(uat_model_));
    } else {
        ui->pathLabel->setText(own_text);
    }
    ui->pathLabel->setUrl(abs_path.length() > 0 ? QUrl::fromLocalFile(abs_path).toString() : QString());
    ui->pathLabel->setToolTip(abs_path.length() > 0 ? tr("Open ") + uat_->filename : QString());
    ui->pathLabel->setEnabled(own_used);
}

void UatDialog::updateWidgets()
{
    if (!uat_model_)
        return;

    QModelIndexList selectedRows = ui->uatTreeView->selectionModel() ?
                ui->uatTreeView->selectionModel()->selectedRows() : QModelIndexList();
    InheritSelection sel = inheritSelection(uat_model_, selectedRows, ui->uatTreeView);

    // Inherited entries can be copied into the own entries, but not changed
    ui->editButtons->setSelection(sel);
    if (copy_button_) {
        copy_button_->setOwnEntriesUsed(sel.own_used);
    }
}

void UatDialog::inheritModeChanged(profile_inherit_e mode)
{
    if (!uat_model_)
        return;

    QString error;
    if (!uat_model_->setInheritMode(mode, error)) {
        report_failure("%s", qPrintable(error));
    }
    resizeColumns();
    updatePathLabel();
    updateWidgets();
    ok_button_->setEnabled(!uat_model_->hasErrors());
}

void UatDialog::copyFromProfile(QString filename)
{
    char *err = NULL;
    if (uat_load(uat_, filename.toUtf8().constData(), application_configuration_environment_prefix(), &err)) {
        uat_->changed = true;
        uat_model_->reloadUat();
        uat_model_->markOwnChanged();
    } else {
        report_failure("Error while loading %s: %s", uat_->name, err);
        g_free(err);
        // Some errors are non-fatal (a record was added but failed
        // validation), so the model must follow the records.
        uat_model_->reloadUat();
    }
}

// Invoked when a field in the model changes (e.g. by closing the editor)
void UatDialog::modelDataChanged(const QModelIndex &topLeft)
{
    checkForErrorHint(topLeft, QModelIndex());
    ok_button_->setEnabled(!uat_model_->hasErrors());
    resizeColumns();
}

// Invoked after a row has been removed from the model.
void UatDialog::modelRowsRemoved()
{
    const QModelIndex &current = ui->uatTreeView->currentIndex();

    // Because currentItemChanged() is called before the row is removed from the model
    // we also need to check for button enabling here.
    updateWidgets();

    checkForErrorHint(current, QModelIndex());
    ok_button_->setEnabled(!uat_model_->hasErrors());
}

void UatDialog::modelRowsReset()
{
    updateWidgets();
}

void UatDialog::uatTreeViewSelectionChanged(const QItemSelection&, const QItemSelection&)
{
    updateWidgets();
}

// Invoked when a different field is selected. Note: when selecting a different
// field after editing, this event is triggered after modelDataChanged.
void UatDialog::on_uatTreeView_currentItemChanged(const QModelIndex &current, const QModelIndex &previous)
{
    updateWidgets();

    checkForErrorHint(current, previous);
}

// If the current field has errors, show them.
// Otherwise if the row has not changed, but the previous field has errors, show them.
// Otherwise pick the first error in the current row.
// Otherwise show the error from the previous field (if any).
// Otherwise clear the error hint.
void UatDialog::checkForErrorHint(const QModelIndex &current, const QModelIndex &previous)
{
    if (current.isValid()) {
        if (trySetErrorHintFromField(current)) {
            return;
        }

        const int row = current.row();
        if (row == previous.row() && trySetErrorHintFromField(previous)) {
            return;
        }

        for (int i = 0; i < uat_model_->columnCount(); i++) {
            if (trySetErrorHintFromField(uat_model_->index(row, i))) {
                return;
            }
        }
    }

    if (previous.isValid()) {
        if (trySetErrorHintFromField(previous)) {
            return;
        }
    }

    ui->hintLabel->clear();
    ThemeManager::setNoticeState(ui->hintLabel, QString());
}

bool UatDialog::trySetErrorHintFromField(const QModelIndex &index)
{
    const QVariant &data = uat_model_->data(index, Qt::UserRole + 1);
    if (!data.isNull()) {
        // use HTML instead of PlainText because that handles wordwrap properly
        ui->hintLabel->setText("<small><i>" + html_escape(data.toString()) + "</i></small>");
        ThemeManager::setNoticeState(ui->hintLabel, "error");
        return true;
    }
    return false;
}

void UatDialog::addRecord(bool copy_from_current)
{
    if (!uat_) return;

    QModelIndex current = ui->uatTreeView->currentIndex();
    if (copy_from_current && !current.isValid()) return;

    QModelIndex new_index;
    if (copy_from_current) {
        new_index = uat_model_->copyRow(current);
    }  else {
        // New records go after the own records, before the inherited records
        int row = uat_model_->ownRowCount();
        // should not fail, but you never know.
        if (!uat_model_->insertRows(row, 1)) {
            qDebug() << "Failed to add a new record";
            return;
        }

        new_index = uat_model_->index(row, 0);
    }

    // due to an EditTrigger, this will also start editing.
    ui->uatTreeView->setCurrentIndex(new_index);
    // trigger updating error messages and the OK button state.
    modelDataChanged(new_index);
}

void UatDialog::newClicked()
{
    addRecord();
}

void UatDialog::deleteClicked()
{
    if (uat_model_ == nullptr) {
        return;
    }

    for (int row : rowsLastFirst(ui->uatTreeView->selectionModel()->selectedRows())) {
        if (!uat_model_->removeRows(row, 1)) {
            qDebug() << "Failed to remove row" << row;
        }
    }
}

void UatDialog::copyClicked()
{
    if (uat_model_ == nullptr) {
        return;
    }

    QModelIndexList selectedRows = ui->uatTreeView->selectionModel()->selectedRows();
    if (selectedRows.size() > 0) {
        std::sort(selectedRows.begin(), selectedRows.end());

        QModelIndex copyIdx;

        for (const auto &idx : selectedRows) {
            copyIdx = uat_model_->copyRow(idx);
            if (!copyIdx.isValid())
            {
                qDebug() << "Failed to copy row" << idx.row();
            }
            // trigger updating error messages and the OK button state.
            modelDataChanged(copyIdx);
        }
        // due to an EditTrigger, this will also start editing.
        ui->uatTreeView->setCurrentIndex(copyIdx);
    }

}

void UatDialog::clearClicked()
{
    if (uat_model_) {
        removeVisibleOwnRows(ui->uatTreeView, uat_model_);
    }
}

void UatDialog::applyChanges()
{
    if (!uat_) return;

    if (uat_->flags & UAT_AFFECTS_FIELDS) {
        /* Recreate list with new fields */
        mainApp->queueAppSignal(MainApplication::FieldsChanged);
    }
    if (uat_->flags & UAT_AFFECTS_DISSECTION) {
        /* Redissect packets if we have any */
        mainApp->queueAppSignal(MainApplication::PacketDissectionChanged);
    }
}


void UatDialog::acceptChanges()
{
    if (!uat_model_) return;

    QString error;
    bool applied = uat_model_->applyChanges(error);
    if (!error.isEmpty()) {
        report_failure("%s", qPrintable(error));
    } else {
        // The mode is only kept with the records saved for it
        QString mode_error;
        if (inherit_combo_ && !inherit_combo_->saveMode(mode_error)) {
            report_failure("%s", qPrintable(mode_error));
        }
    }
    if (applied) {
        applyChanges();
    }
}

void UatDialog::rejectChanges()
{
    if (!uat_model_) return;

    QString error;
    if (uat_model_->revertChanges(error)) {
        if (!error.isEmpty()) {
            report_failure("%s", qPrintable(error));
        }
        // Why do we have to trigger a redissection? If the original UAT is
        // restored and dissectors only apply changes after the post_update_cb
        // method is invoked, then it should not be necessary to trigger
        // redissection. One potential exception is when something modifies the
        // UAT file after Wireshark has started, but this behavior is not
        // supported and causes potentially unnecessary redissection whenever
        // the preferences dialog is closed.
        // XXX audit all UAT providers and check whether it is safe to remove
        // the next call (that is, when their update_cb has no side-effects).
        applyChanges();
    }
}

void UatDialog::on_buttonBox_helpRequested()
{
    if (!uat_) return;

    QString help_page = uat_->help, url;

    help_page.append(".html");
    url = gchar_free_to_qstring(user_guide_url(help_page.toUtf8().constData()));
    if (!url.isNull()) {
        QDesktopServices::openUrl(QUrl(QDir::fromNativeSeparators(url)));
    }
}

void UatDialog::resizeColumns()
{
    for (int i = 0; i < uat_model_->columnCount(); i++) {
        ui->uatTreeView->resizeColumnToContents(i);
    }
}
