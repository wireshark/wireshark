/* decode_as_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "decode_as_dialog.h"
#include <ui_decode_as_dialog.h>

#include "epan/decode_as.h"
#include "epan/epan_dissect.h"

#include "ui/decode_as_utils.h"
#include "ui/simple_dialog.h"
#include "wsutil/filesystem.h"
#include "app/application_flavor.h"
#include <wsutil/utf8_entities.h>

#include <ui/qt/widgets/copy_from_profile_button.h>
#include <ui/qt/widgets/list_edit_buttons.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include "main_application.h"

#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/utils/themes/themed_icon.h>

#include <QComboBox>
#include <QFont>
#include <QFontMetrics>
#include <QLineEdit>
#include <QUrl>

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

    ListEditButtons::ToolTips tool_tips;
    tool_tips.add = tr("Change the dissection behavior for a protocol.");
    tool_tips.remove = tr("Remove this dissection behavior.");
    tool_tips.copy = tr("Copy this dissection behavior.");
    tool_tips.clear = tr("Clear all dissection behaviors.");
    ui->editButtons->setToolTips(tool_tips);
    connect(ui->editButtons, &ListEditButtons::newClicked, this, &DecodeAsDialog::newClicked);
    connect(ui->editButtons, &ListEditButtons::deleteClicked, this, &DecodeAsDialog::deleteClicked);
    connect(ui->editButtons, &ListEditButtons::copyClicked, this, &DecodeAsDialog::copyClicked);
    connect(ui->editButtons, &ListEditButtons::clearClicked, this, &DecodeAsDialog::clearClicked);
    loadGeometry();

    delegate_ = new DecodeAsDelegate(ui->decodeAsTreeView, cf);

    ui->decodeAsTreeView->setModel(model_);
    connect(ui->decodeAsTreeView->selectionModel(), &QItemSelectionModel::selectionChanged, this, &DecodeAsDialog::updateWidgets);
    ui->decodeAsTreeView->setItemDelegate(delegate_);

#ifdef Q_OS_MACOS
    ui->pathLabel->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    setWindowTitle(mainApp->windowTitleString(tr("Decode As…")));

    QString abs_path = gchar_free_to_qstring(get_persconffile_path(DECODE_AS_ENTRIES_FILE_NAME, true, application_configuration_environment_prefix()));
    if (file_exists(abs_path.toUtf8().constData())) {
        ui->pathLabel->setText(abs_path);
        ui->pathLabel->setUrl(QUrl::fromLocalFile(abs_path).toString());
        ui->pathLabel->setToolTip(tr("Open ") + DECODE_AS_ENTRIES_FILE_NAME);
        ui->pathLabel->setEnabled(true);
    }

    CopyFromProfileButton *copy_button = new CopyFromProfileButton(this, DECODE_AS_ENTRIES_FILE_NAME);
    ui->buttonBox->addButton(copy_button, QDialogButtonBox::ActionRole);
    connect(copy_button, &CopyFromProfileButton::copyProfile, this, &DecodeAsDialog::copyFromProfile);

    fillTable();

    connect(model_, &DecodeAsModel::modelReset, this, &DecodeAsDialog::modelRowsReset);
    connect(model_, &DecodeAsModel::rowsInserted, this, &DecodeAsDialog::modelRowsReset);
    connect(model_, &DecodeAsModel::rowsRemoved, this, &DecodeAsDialog::modelRowsReset);
    updateWidgets();

    if (create_new)
        newClicked();
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

void DecodeAsDialog::modelRowsReset()
{
    updateWidgets();
}

void DecodeAsDialog::updateWidgets()
{
    ui->editButtons->setSelection(ui->decodeAsTreeView->selectionModel()->selectedRows(), model_->rowCount());
}

void DecodeAsDialog::copyFromProfile(QString filename)
{
    const char *err = NULL;

    if (!model_->copyFromProfile(filename, &err)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Error while loading %s: %s", filename.toUtf8().constData(), err);
    }

    resizeColumns();

    updateWidgets();
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

void DecodeAsDialog::newClicked()
{
    addRecord();
}

void DecodeAsDialog::deleteClicked()
{
    if (!model_)
        return;

    for (int row : rowsLastFirst(ui->decodeAsTreeView->selectionModel()->selectedRows())) {
        if (!model_->removeRows(row, 1)) {
            qDebug() << "Failed to remove row" << row;
        }
    }
}

void DecodeAsDialog::copyClicked()
{
    addRecord(true);
}

void DecodeAsDialog::clearClicked()
{
    model_->clearAll();
}

void DecodeAsDialog::applyChanges()
{
    model_->applyChanges();
    mainApp->queueAppSignal(MainApplication::PacketDissectionChanged);
}

void DecodeAsDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    ui->buttonBox->setFocus();

    switch (ui->buttonBox->standardButton(button)) {
    case QDialogButtonBox::Ok:
        applyChanges();
        break;
    case QDialogButtonBox::Save:
        {
        char* err = NULL;

        applyChanges();
        if (save_decode_as_entries(application_flavor_name_proper(), application_configuration_environment_prefix(), &err) < 0) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err);
            g_free(err);
        }
        }
        break;
    case QDialogButtonBox::Help:
        mainApp->helpTopicAction(HELP_DECODE_AS_SHOW_DIALOG);
        break;
    default:
        break;
    }
}
