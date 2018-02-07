/* decode_as_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*/

#include "decode_as_dialog.h"
#include <ui_decode_as_dialog.h>

#include "epan/decode_as.h"
#include "epan/epan_dissect.h"

#include "ui/decode_as_utils.h"
#include "ui/simple_dialog.h"
#include <wsutil/utf8_entities.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include "wireshark_application.h"

#include <ui/qt/utils/variant_pointer.h>

#include <QComboBox>
#include <QFont>
#include <QFontMetrics>
#include <QLineEdit>
#include <QDebug>

// To do:
// - Ranges
// - Add DCERPC support (or make DCERPC use a regular dissector table?)

DecodeAsDialog::DecodeAsDialog(QWidget *parent, capture_file *cf, bool create_new) :
    GeometryStateDialog(parent),
    ui(new Ui::DecodeAsDialog),
    model_(new DecodeAsModel(this, cf)),
    delegate_(NULL)
{
    ui->setupUi(this);
    loadGeometry();

    delegate_ = new DecodeAsDelegate(ui->decodeAsTreeView, cf);

    ui->decodeAsTreeView->setModel(model_);
    ui->decodeAsTreeView->setItemDelegate(delegate_);

    setWindowTitle(wsApp->windowTitleString(tr("Decode As" UTF8_HORIZONTAL_ELLIPSIS)));

    fillTable();

    if (create_new)
        on_newToolButton_clicked();
}

DecodeAsDialog::~DecodeAsDialog()
{
    delete ui;
    delete model_;
    delete delegate_;
}

void DecodeAsDialog::fillTable()
{
    model_->fillTable();

    resizeColumns();

    //set selection as first row
    if (model_->rowCount() > 0) {
        const QModelIndex &new_index = model_->index(0, 0);
        ui->decodeAsTreeView->setCurrentIndex(new_index);
    }
}

void DecodeAsDialog::resizeColumns()
{
    if (model_->rowCount() > 0) {
        for (int i = 0; i < model_->columnCount(); i++) {
            ui->decodeAsTreeView->resizeColumnToContents(i);
        }
    }
}

void DecodeAsDialog::on_decodeAsTreeView_currentItemChanged(const QModelIndex &current, const QModelIndex&)
{
    if (current.isValid()) {
        ui->deleteToolButton->setEnabled(true);
        ui->copyToolButton->setEnabled(true);
    } else {
        ui->deleteToolButton->setEnabled(false);
        ui->copyToolButton->setEnabled(false);
    }
}

void DecodeAsDialog::addRecord(bool copy_from_current)
{
    const QModelIndex &current = ui->decodeAsTreeView->currentIndex();
    if (copy_from_current && !current.isValid()) return;

//    XXX - This doesn't appear to work as intended to give "edit triggers on demand"
    ui->decodeAsTreeView->setEditTriggers(ui->decodeAsTreeView->editTriggers() | QAbstractItemView::CurrentChanged | QAbstractItemView::AnyKeyPressed);

    // should not fail, but you never know.
    if (!model_->insertRows(model_->rowCount(), 1)) {
        qDebug() << "Failed to add a new record";
        return;
    }
    const QModelIndex &new_index = model_->index(model_->rowCount() - 1, 0);
    if (copy_from_current) {
        model_->copyRow(new_index.row(), current.row());
    }

    resizeColumns();

    // due to an EditTrigger, this will also start editing.
    ui->decodeAsTreeView->setCurrentIndex(new_index);
}

void DecodeAsDialog::on_newToolButton_clicked()
{
    addRecord();
}

void DecodeAsDialog::on_deleteToolButton_clicked()
{
    const QModelIndex &current = ui->decodeAsTreeView->currentIndex();
    if (model_ && current.isValid()) {
        if (!model_->removeRows(current.row(), 1)) {
            qDebug() << "Failed to remove row";
        }
    }
}

void DecodeAsDialog::on_copyToolButton_clicked()
{
    addRecord(true);
}

void DecodeAsDialog::applyChanges()
{
    model_->applyChanges();
    wsApp->queueAppSignal(WiresharkApplication::PacketDissectionChanged);
}

void DecodeAsDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    switch (ui->buttonBox->standardButton(button)) {
    case QDialogButtonBox::Ok:
        applyChanges();
        break;
    case QDialogButtonBox::Save:
        {
        gchar* err = NULL;

        applyChanges();
        if (save_decode_as_entries(&err) < 0) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err);
            g_free(err);
        }
        }
        break;
    case QDialogButtonBox::Help:
        wsApp->helpTopicAction(HELP_DECODE_AS_SHOW_DIALOG);
        break;
    default:
        break;
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
