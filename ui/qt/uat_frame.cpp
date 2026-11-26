/* uat_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/filter_expressions.h>
#include <epan/uat-int.h>

#include "uat_frame.h"
#include <ui_uat_frame.h>
#include <ui/qt/widgets/display_filter_edit.h>
#include "main_application.h"

#include <ui/qt/widgets/copy_from_profile_button.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/themes/themed_icon.h>
#include <wsutil/report_message.h>
#include <app/application_flavor.h>

#include <QLineEdit>
#include <ui/qt/utils/inherit_selection.h>
#include <ui/qt/utils/hide_overridden_rows.h>
#include <ui/qt/widgets/list_edit_buttons.h>

#include <QKeyEvent>
#include <QTreeWidgetItemIterator>
#include <QUrl>

#include <QDebug>

UatFrame::UatFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::UatFrame),
    uat_model_(NULL),
    uat_delegate_(NULL),
    uat_(NULL)
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
    connect(ui->editButtons, &ListEditButtons::newClicked, this, &UatFrame::newClicked);
    connect(ui->editButtons, &ListEditButtons::deleteClicked, this, &UatFrame::deleteClicked);
    connect(ui->editButtons, &ListEditButtons::copyClicked, this, &UatFrame::copyClicked);
    connect(ui->editButtons, &ListEditButtons::moveUpClicked, ui->uatTreeView, &RowMoveTreeView::moveSelectedRowsUp);
    connect(ui->editButtons, &ListEditButtons::moveDownClicked, ui->uatTreeView, &RowMoveTreeView::moveSelectedRowsDown);
    connect(ui->editButtons, &ListEditButtons::clearClicked, this, &UatFrame::clearClicked);

#ifdef Q_OS_MACOS
    ui->pathLabel->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    // FIXME: this prevents the columns from being resized, even if the text
    // within a combobox needs more space (e.g. in the USER DLT settings).  For
    // very long filenames in the TLS RSA keys dialog, it also results in a
    // vertical scrollbar. Maybe remove this since the editor is not limited to
    // the column width (and overlays other fields if more width is needed)?
    ui->uatTreeView->header()->setSectionResizeMode(QHeaderView::Interactive);

    // start editing as soon as the field is selected or when typing starts
    ui->uatTreeView->setEditTriggers(ui->uatTreeView->editTriggers() |
            QAbstractItemView::CurrentChanged | QAbstractItemView::AnyKeyPressed);

    set_section_title_font(ui->uatGroupBox);
}

UatFrame::~UatFrame()
{
    delete ui;
    delete uat_delegate_;
    delete uat_model_;
}

void UatFrame::setUat(epan_uat *uat)
{
    QString title(tr("Unknown User Accessible Table"));

    uat_ = uat;

    ui->pathLabel->clear();
    ui->pathLabel->setEnabled(false);

    if (uat_) {
        if (uat_->name) {
            title = uat_->name;
        }

        if (uat->from_profile) {
            // The dialog shows the button while this page is current
            if (!copy_button_) {
                copy_button_ = new CopyFromProfileButton(this);
                addPageButton(copy_button_);
                connect(copy_button_, &CopyFromProfileButton::copyProfile, this, &UatFrame::copyFromProfile);
            }
            copy_button_->setFilename(uat->filename);

            // Where the records come from
            ui->inheritComboBox->setFilename(uat->filename);
            ui->inheritComboBox->syncMode(uat_get_inherit_mode(uat_));
            connect(ui->inheritComboBox, &ProfileInheritComboBox::modeChanged, this, &UatFrame::inheritModeChanged);
        } else {
            ui->inheritComboBox->setFilename(QString());
        }

        uat_model_ = new UatModel(NULL, uat);
        uat_delegate_ = new UatDelegate;
        ui->uatTreeView->setModel(uat_model_);
        ui->uatTreeView->setItemDelegate(uat_delegate_);

        if (uat->from_profile) {
            // Not used records can be hidden, which is not stored
            addHideNotUsedCheckBox(this, ui->horizontalLayout, ui->inheritComboBox, ui->uatTreeView, uat_model_, uat->enabled_field);
        }
        resizeColumns();
        updatePathLabel();
        followInheritedProfiles(uat_model_, this, &UatFrame::updatePathLabel);
        updateWidgets();

        connect(uat_model_, &UatModel::dataChanged, this, &UatFrame::modelDataChanged);
        connect(uat_model_, &UatModel::rowsRemoved,this, &UatFrame::modelRowsRemoved);
        connect(uat_model_, &UatModel::modelReset, this, &UatFrame::modelRowsReset);
        connect(uat_model_, &UatModel::rowsMoved, this, &UatFrame::updateWidgets);

        connect(ui->uatTreeView->selectionModel(), &QItemSelectionModel::selectionChanged,
                this, &UatFrame::uatTreeViewSelectionChanged);
    }

    setWindowTitle(title);
    ui->uatGroupBox->setTitle(title);
}

void UatFrame::updatePathLabel()
{
    bool own_used =  ui->inheritComboBox->mode() != PROFILE_INHERIT_PARENT_ONLY;
    QString abs_path = own_used ? gchar_free_to_qstring(uat_get_actual_filename(uat_, false, application_configuration_environment_prefix())) : QString();
    QString own_text = !own_used ? QString() : abs_path.length() > 0 ? abs_path : QString(uat_->filename);

    ui->inheritComboBox->setPathText(ui->pathLabel, own_text, inheritedProfiles(uat_model_));
    ui->pathLabel->setUrl(abs_path.length() > 0 ? QUrl::fromLocalFile(abs_path).toString() : QString());
    ui->pathLabel->setToolTip(abs_path.length() > 0 ? tr("Open ") + uat_->filename : QString());
    ui->pathLabel->setEnabled(own_used);
}

void UatFrame::updateWidgets()
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

void UatFrame::inheritModeChanged(profile_inherit_e mode)
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
}

void UatFrame::copyFromProfile(QString filename)
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

void UatFrame::applyChanges()
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

void UatFrame::acceptChanges()
{
    if (!uat_model_) return;

    QString error;
    bool applied = uat_model_->applyChanges(error);
    if (!error.isEmpty()) {
        report_failure("%s", qPrintable(error));
    } else {
        // The mode is only kept with the records saved for it
        QString mode_error;
        if (!ui->inheritComboBox->saveMode(mode_error)) {
            report_failure("%s", qPrintable(mode_error));
        }
    }
    if (applied) {
        applyChanges();
    }
}

void UatFrame::rejectChanges()
{
    if (!uat_model_) return;

    QString error;
    if (uat_model_->revertChanges(error)) {
        if (!error.isEmpty()) {
            report_failure("%s", qPrintable(error));
        }
    }
}

void UatFrame::addRecord(bool copy_from_current)
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

void UatFrame::uatTreeViewSelectionChanged(const QItemSelection&, const QItemSelection&)
{
    updateWidgets();
}

// Invoked when a different field is selected. Note: when selecting a different
// field after editing, this event is triggered after modelDataChanged.
void UatFrame::on_uatTreeView_currentItemChanged(const QModelIndex &current, const QModelIndex &previous)
{
    updateWidgets();

    checkForErrorHint(current, previous);
}

// Invoked when a field in the model changes (e.g. by closing the editor)
void UatFrame::modelDataChanged(const QModelIndex &topLeft)
{
    checkForErrorHint(topLeft, QModelIndex());
    resizeColumns();
}

// Invoked after a row has been removed from the model.
void UatFrame::modelRowsRemoved()
{
    const QModelIndex &current = ui->uatTreeView->currentIndex();

    // Because currentItemChanged() is called before the row is removed from the model
    // we also need to check for button enabling here.
    updateWidgets();

    checkForErrorHint(current, QModelIndex());
}

void UatFrame::modelRowsReset()
{
    updateWidgets();
}

// If the current field has errors, show them.
// Otherwise if the row has not changed, but the previous field has errors, show them.
// Otherwise pick the first error in the current row.
// Otherwise show the error from the previous field (if any).
// Otherwise clear the error hint.
void UatFrame::checkForErrorHint(const QModelIndex &current, const QModelIndex &previous)
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
}

bool UatFrame::trySetErrorHintFromField(const QModelIndex &index)
{
    const QVariant &data = uat_model_->data(index, Qt::UserRole + 1);
    if (!data.isNull()) {
        // use HTML instead of PlainText because that handles wordwrap properly
        ui->hintLabel->setText("<small><i>" + html_escape(data.toString()) + "</i></small>");
        return true;
    }
    return false;
}

void UatFrame::newClicked()
{
    addRecord();
}

void UatFrame::deleteClicked()
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

void UatFrame::copyClicked()
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

void UatFrame::clearClicked()
{
    if (uat_model_) {
        removeVisibleOwnRows(ui->uatTreeView, uat_model_);
    }
}

void UatFrame::resizeColumns()
{
    for (int i = 0; i < uat_model_->columnCount(); i++) {
        ui->uatTreeView->resizeColumnToContents(i);
    }
}
