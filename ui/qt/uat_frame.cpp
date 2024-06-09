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

#include "uat_frame.h"
#include <ui_uat_frame.h>
#include <ui/qt/widgets/display_filter_edit.h>
#include "main_application.h"

#include <ui/qt/widgets/copy_from_profile_button.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <wsutil/report_message.h>

#include <QLineEdit>
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

    ui->newToolButton->setStockIcon("list-add");
    ui->deleteToolButton->setStockIcon("list-remove");
    ui->copyToolButton->setStockIcon("list-copy");
    ui->moveUpToolButton->setStockIcon("list-move-up");
    ui->moveDownToolButton->setStockIcon("list-move-down");
    ui->clearToolButton->setStockIcon("list-clear");

#ifdef Q_OS_MAC
    ui->newToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->deleteToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->copyToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->moveUpToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->moveDownToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->clearToolButton->setAttribute(Qt::WA_MacSmallSize, true);
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
            ui->copyFromProfileButton->setFilename(uat->filename);
            connect(ui->copyFromProfileButton, &CopyFromProfileButton::copyProfile, this, &UatFrame::copyFromProfile);
        }

        QString abs_path = gchar_free_to_qstring(uat_get_actual_filename(uat_, false));
        if (abs_path.length() > 0) {
            ui->pathLabel->setText(abs_path);
            ui->pathLabel->setUrl(QUrl::fromLocalFile(abs_path).toString());
            ui->pathLabel->setToolTip(tr("Open ") + uat->filename);
        } else {
            ui->pathLabel->setText(uat_->filename);
        }
        ui->pathLabel->setEnabled(true);

        uat_model_ = new UatModel(NULL, uat);
        uat_delegate_ = new UatDelegate;
        ui->uatTreeView->setModel(uat_model_);
        ui->uatTreeView->setItemDelegate(uat_delegate_);
        ui->uatTreeView->setSelectionMode(QAbstractItemView::ContiguousSelection);
        resizeColumns();
        ui->clearToolButton->setEnabled(uat_model_->rowCount() != 0);

        connect(uat_model_, SIGNAL(dataChanged(QModelIndex,QModelIndex)),
                this, SLOT(modelDataChanged(QModelIndex)));
        connect(uat_model_, SIGNAL(rowsRemoved(QModelIndex, int, int)),
                this, SLOT(modelRowsRemoved()));
        connect(uat_model_, SIGNAL(modelReset()), this, SLOT(modelRowsReset()));

        connect(ui->uatTreeView->selectionModel(), &QItemSelectionModel::selectionChanged,
                this, &UatFrame::uatTreeViewSelectionChanged);
    }

    setWindowTitle(title);
}

void UatFrame::copyFromProfile(QString filename)
{
    char *err = NULL;
    if (uat_load(uat_, filename.toUtf8().constData(), &err)) {
        uat_->changed = true;
        uat_model_->reloadUat();
    } else {
        report_failure("Error while loading %s: %s", uat_->name, err);
        g_free(err);
    }
}

void UatFrame::showEvent(QShowEvent *)
{
#ifndef Q_OS_MAC
    ui->copyFromProfileButton->setFixedHeight(ui->copyToolButton->geometry().height());
#endif
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
    if (uat_model_->applyChanges(error)) {
        if (!error.isEmpty()) {
            report_failure("%s", qPrintable(error));
        }
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
        // should not fail, but you never know.
        if (!uat_model_->insertRows(uat_model_->rowCount(), 1)) {
            qDebug() << "Failed to add a new record";
            return;
        }
        new_index = uat_model_->index(uat_model_->rowCount() - 1, 0);
    }

    // due to an EditTrigger, this will also start editing.
    ui->uatTreeView->setCurrentIndex(new_index);
    // trigger updating error messages and the OK button state.
    modelDataChanged(new_index);
}

void UatFrame::uatTreeViewSelectionChanged(const QItemSelection&, const QItemSelection&)
{
    QModelIndexList selectedRows = ui->uatTreeView->selectionModel()->selectedRows();
    qsizetype num_selected = selectedRows.size();
    if (num_selected > 0) {
        std::sort(selectedRows.begin(), selectedRows.end());
        ui->deleteToolButton->setEnabled(true);
        ui->copyToolButton->setEnabled(true);
        ui->moveUpToolButton->setEnabled(selectedRows.first().row() > 0);
        ui->moveDownToolButton->setEnabled(selectedRows.last().row() < uat_model_->rowCount() - 1);
    } else {
        ui->deleteToolButton->setEnabled(false);
        ui->copyToolButton->setEnabled(false);
        ui->moveUpToolButton->setEnabled(false);
        ui->moveDownToolButton->setEnabled(false);
    }
}

// Invoked when a different field is selected. Note: when selecting a different
// field after editing, this event is triggered after modelDataChanged.
void UatFrame::on_uatTreeView_currentItemChanged(const QModelIndex &current, const QModelIndex &previous)
{
    if (current.isValid()) {
        ui->clearToolButton->setEnabled(true);
    } else {
        ui->clearToolButton->setEnabled(false);
    }

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
    if (current.isValid()) {
        ui->moveUpToolButton->setEnabled(current.row() != 0);
        ui->moveDownToolButton->setEnabled(current.row() != (uat_model_->rowCount() - 1));
    } else {
        ui->moveUpToolButton->setEnabled(false);
        ui->moveDownToolButton->setEnabled(false);
    }
    ui->clearToolButton->setEnabled(uat_model_->rowCount() != 0);

    checkForErrorHint(current, QModelIndex());
}

void UatFrame::modelRowsReset()
{
    ui->deleteToolButton->setEnabled(false);
    ui->clearToolButton->setEnabled(uat_model_->rowCount() != 0);
    ui->copyToolButton->setEnabled(false);
    ui->moveUpToolButton->setEnabled(false);
    ui->moveDownToolButton->setEnabled(false);
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

void UatFrame::on_newToolButton_clicked()
{
    addRecord();
}

void UatFrame::on_deleteToolButton_clicked()
{
    if (uat_model_ == nullptr) {
        return;
    }

    for (const auto &range : ui->uatTreeView->selectionModel()->selection()) {
        // Each QItemSelectionRange is contiguous
        if (!range.isEmpty()) {
            if (!uat_model_->removeRows(range.top(), range.bottom() - range.top() + 1)) {
                qDebug() << "Failed to remove rows" << range.top() << "to" << range.bottom();
            }
        }
    }
}

void UatFrame::on_copyToolButton_clicked()
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

void UatFrame::on_moveUpToolButton_clicked()
{
    if (uat_model_ == nullptr) {
        return;
    }

    for (const auto &range : ui->uatTreeView->selectionModel()->selection()) {
        // Each QItemSelectionRange is contiguous
        if (!range.isEmpty() && range.top() > 0) {
            // Swap range of rows with the row above the top
            if (! uat_model_->moveRows(QModelIndex(), range.top(), range.bottom() - range.top() + 1, QModelIndex(), range.top() - 1)) {
                qDebug() << "Failed to move up rows" << range.top() << "to" << range.bottom();
            }
            // Our moveRows implementation calls begin/endMoveRows(), so
            // range.top() already has the new row number.
            ui->moveUpToolButton->setEnabled(range.top() > 0);
            ui->moveDownToolButton->setEnabled(true);
        }
    }
}

void UatFrame::on_moveDownToolButton_clicked()
{
    if (uat_model_ == nullptr) {
        return;
    }

    for (const auto &range : ui->uatTreeView->selectionModel()->selection()) {
        // Each QItemSelectionRange is contiguous
        if (!range.isEmpty() && range.bottom() + 1 < uat_model_->rowCount()) {
            // Swap range of rows with the row below the top
            if (! uat_model_->moveRows(QModelIndex(), range.top(), range.bottom() - range.top() + 1, QModelIndex(), range.bottom() + 1)) {
                qDebug() << "Failed to move down rows" << range.top() << "to" << range.bottom();
            }
            // Our moveRows implementation calls begin/endMoveRows, so
            // range.bottom() already has the new row number.
            ui->moveUpToolButton->setEnabled(true);
            ui->moveDownToolButton->setEnabled(range.bottom() < uat_model_->rowCount() - 1);
        }
    }
}

void UatFrame::on_clearToolButton_clicked()
{
    if (uat_model_) {
        uat_model_->clearAll();
    }
}

void UatFrame::resizeColumns()
{
    for (int i = 0; i < uat_model_->columnCount(); i++) {
        ui->uatTreeView->resizeColumnToContents(i);
        if (i == 0) {
            ui->uatTreeView->setColumnWidth(i, ui->uatTreeView->columnWidth(i)+ui->uatTreeView->indentation());
        }
    }
}
