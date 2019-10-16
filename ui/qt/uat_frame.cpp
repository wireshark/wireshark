/* uat_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/filter_expressions.h>

#include "uat_frame.h"
#include <ui_uat_frame.h>
#include <ui/qt/widgets/display_filter_edit.h>
#include "wireshark_application.h"

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
    ui->uatTreeView->header()->setSectionResizeMode(QHeaderView::ResizeToContents);

    // start editing as soon as the field is selected or when typing starts
    ui->uatTreeView->setEditTriggers(ui->uatTreeView->editTriggers() |
            QAbstractItemView::CurrentChanged | QAbstractItemView::AnyKeyPressed);

    // XXX - Need to add uat_move or uat_insert to the UAT API for drag/drop
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

        QString abs_path = gchar_free_to_qstring(uat_get_actual_filename(uat_, FALSE));
        ui->pathLabel->setText(abs_path);
        ui->pathLabel->setUrl(QUrl::fromLocalFile(abs_path).toString());
        ui->pathLabel->setToolTip(tr("Open ") + uat->filename);
        ui->pathLabel->setEnabled(true);

        uat_model_ = new UatModel(NULL, uat);
        uat_delegate_ = new UatDelegate;
        ui->uatTreeView->setModel(uat_model_);
        ui->uatTreeView->setItemDelegate(uat_delegate_);
        ui->clearToolButton->setEnabled(uat_model_->rowCount() != 0);

        connect(uat_model_, SIGNAL(dataChanged(QModelIndex,QModelIndex)),
                this, SLOT(modelDataChanged(QModelIndex)));
        connect(uat_model_, SIGNAL(rowsRemoved(QModelIndex, int, int)),
                this, SLOT(modelRowsRemoved()));
        connect(uat_model_, SIGNAL(modelReset()), this, SLOT(modelRowsReset()));
    }

    setWindowTitle(title);
}

void UatFrame::copyFromProfile(QString filename)
{
    gchar *err = NULL;
    if (uat_load(uat_, filename.toUtf8().constData(), &err)) {
        uat_->changed = TRUE;
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
        /* Recreate list with new fields and redissect packets */
        wsApp->queueAppSignal(WiresharkApplication::FieldsChanged);
    }
    if (uat_->flags & UAT_AFFECTS_DISSECTION) {
        /* Just redissect packets if we have any */
        wsApp->queueAppSignal(WiresharkApplication::PacketDissectionChanged);
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

    const QModelIndex &current = ui->uatTreeView->currentIndex();
    if (copy_from_current && !current.isValid()) return;

    // should not fail, but you never know.
    if (!uat_model_->insertRows(uat_model_->rowCount(), 1)) {
        qDebug() << "Failed to add a new record";
        return;
    }
    const QModelIndex &new_index = uat_model_->index(uat_model_->rowCount() - 1, 0);
    if (copy_from_current) {
        uat_model_->copyRow(new_index.row(), current.row());
    }
    // due to an EditTrigger, this will also start editing.
    ui->uatTreeView->setCurrentIndex(new_index);
    // trigger updating error messages and the OK button state.
    modelDataChanged(new_index);
}

// Invoked when a different field is selected. Note: when selecting a different
// field after editing, this event is triggered after modelDataChanged.
void UatFrame::on_uatTreeView_currentItemChanged(const QModelIndex &current, const QModelIndex &previous)
{
    if (current.isValid()) {
        ui->deleteToolButton->setEnabled(true);
        ui->clearToolButton->setEnabled(true);
        ui->copyToolButton->setEnabled(true);
        ui->moveUpToolButton->setEnabled(current.row() != 0);
        ui->moveDownToolButton->setEnabled(current.row() != (uat_model_->rowCount() - 1));
    } else {
        ui->deleteToolButton->setEnabled(false);
        ui->clearToolButton->setEnabled(false);
        ui->copyToolButton->setEnabled(false);
        ui->moveUpToolButton->setEnabled(false);
        ui->moveDownToolButton->setEnabled(false);
    }

    checkForErrorHint(current, previous);
}

// Invoked when a field in the model changes (e.g. by closing the editor)
void UatFrame::modelDataChanged(const QModelIndex &topLeft)
{
    checkForErrorHint(topLeft, QModelIndex());
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
    const QModelIndex &current = ui->uatTreeView->currentIndex();
    if (uat_model_ && current.isValid()) {
        if (!uat_model_->removeRows(current.row(), 1)) {
            qDebug() << "Failed to remove row";
        }
    }
}

void UatFrame::on_copyToolButton_clicked()
{
    addRecord(true);
}

void UatFrame::on_moveUpToolButton_clicked()
{
    const QModelIndex &current = ui->uatTreeView->currentIndex();
    int current_row = current.row();
    if (uat_model_ && current.isValid() && current_row > 0) {
        if (!uat_model_->moveRow(current_row, current_row - 1)) {
            qDebug() << "Failed to move row up";
            return;
        }
        current_row--;
        ui->moveUpToolButton->setEnabled(current_row > 0);
        ui->moveDownToolButton->setEnabled(current_row < (uat_model_->rowCount() - 1));
    }
}

void UatFrame::on_moveDownToolButton_clicked()
{
    const QModelIndex &current = ui->uatTreeView->currentIndex();
    int current_row = current.row();
    if (uat_model_ && current.isValid() && current_row < (uat_model_->rowCount() - 1)) {
        if (!uat_model_->moveRow(current_row, current_row + 1)) {
            qDebug() << "Failed to move row down";
            return;
        }
        current_row++;
        ui->moveUpToolButton->setEnabled(current_row > 0);
        ui->moveDownToolButton->setEnabled(current_row < (uat_model_->rowCount() - 1));
    }
}

void UatFrame::on_clearToolButton_clicked()
{
    if (uat_model_) {
        uat_model_->clearAll();
    }
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
