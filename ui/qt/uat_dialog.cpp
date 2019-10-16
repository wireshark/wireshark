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
#include "wireshark_application.h"

#include "epan/strutil.h"
#include "epan/uat-int.h"
#include "ui/help_url.h"
#include <wsutil/report_message.h>

#include <ui/qt/widgets/copy_from_profile_button.h>
#include <ui/qt/utils/qt_ui_utils.h>

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
    uat_(uat)
{
    ui->setupUi(this);
    if (uat) loadGeometry(0, 0, uat->name);

    ok_button_ = ui->buttonBox->button(QDialogButtonBox::Ok);
    help_button_ = ui->buttonBox->button(QDialogButtonBox::Help);

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

    setUat(uat);

    // FIXME: this prevents the columns from being resized, even if the text
    // within a combobox needs more space (e.g. in the USER DLT settings).  For
    // very long filenames in the TLS RSA keys dialog, it also results in a
    // vertical scrollbar. Maybe remove this since the editor is not limited to
    // the column width (and overlays other fields if more width is needed)?
    ui->uatTreeView->header()->setSectionResizeMode(QHeaderView::ResizeToContents);

    // start editing as soon as the field is selected or when typing starts
    ui->uatTreeView->setEditTriggers(ui->uatTreeView->editTriggers() |
            QAbstractItemView::CurrentChanged | QAbstractItemView::AnyKeyPressed);

    // Need to add uat_move or uat_insert to the UAT API.
    ui->uatTreeView->setDragEnabled(false);
    qDebug() << "FIX Add drag reordering to UAT dialog";

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
            CopyFromProfileButton * copy_button = new CopyFromProfileButton(this, uat->filename);
            ui->buttonBox->addButton(copy_button, QDialogButtonBox::ActionRole);
            connect(copy_button, &CopyFromProfileButton::copyProfile, this, &UatDialog::copyFromProfile);
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

        ok_button_->setEnabled(!uat_model_->hasErrors());

        if (uat_->help && strlen(uat_->help) > 0) {
            help_button_->setEnabled(true);
        }

        connect(this, SIGNAL(rejected()), this, SLOT(rejectChanges()));
        connect(this, SIGNAL(accepted()), this, SLOT(acceptChanges()));
    }

    setWindowTitle(title);
}

void UatDialog::copyFromProfile(QString filename)
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

// Invoked when a field in the model changes (e.g. by closing the editor)
void UatDialog::modelDataChanged(const QModelIndex &topLeft)
{
    checkForErrorHint(topLeft, QModelIndex());
    ok_button_->setEnabled(!uat_model_->hasErrors());
}

// Invoked after a row has been removed from the model.
void UatDialog::modelRowsRemoved()
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
    ok_button_->setEnabled(!uat_model_->hasErrors());
}

void UatDialog::modelRowsReset()
{
    ui->deleteToolButton->setEnabled(false);
    ui->clearToolButton->setEnabled(uat_model_->rowCount() != 0);
    ui->copyToolButton->setEnabled(false);
    ui->moveUpToolButton->setEnabled(false);
    ui->moveDownToolButton->setEnabled(false);
}


// Invoked when a different field is selected. Note: when selecting a different
// field after editing, this event is triggered after modelDataChanged.
void UatDialog::on_uatTreeView_currentItemChanged(const QModelIndex &current, const QModelIndex &previous)
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
}

bool UatDialog::trySetErrorHintFromField(const QModelIndex &index)
{
    const QVariant &data = uat_model_->data(index, Qt::UserRole + 1);
    if (!data.isNull()) {
        // use HTML instead of PlainText because that handles wordwrap properly
        ui->hintLabel->setText("<small><i>" + html_escape(data.toString()) + "</i></small>");
        return true;
    }
    return false;
}

void UatDialog::addRecord(bool copy_from_current)
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

void UatDialog::on_newToolButton_clicked()
{
    addRecord();
}

void UatDialog::on_deleteToolButton_clicked()
{
    const QModelIndex &current = ui->uatTreeView->currentIndex();
    if (uat_model_ && current.isValid()) {
        if (!uat_model_->removeRows(current.row(), 1)) {
            qDebug() << "Failed to remove row";
        }
    }
}

void UatDialog::on_copyToolButton_clicked()
{
    addRecord(true);
}

void UatDialog::on_moveUpToolButton_clicked()
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

void UatDialog::on_moveDownToolButton_clicked()
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

void UatDialog::on_clearToolButton_clicked()
{
    if (uat_model_) {
        uat_model_->clearAll();
    }
}

void UatDialog::applyChanges()
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


void UatDialog::acceptChanges()
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
        QDesktopServices::openUrl(QUrl(url));
    }
}

/* * Editor modelines
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
