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
#include <ui/qt/utils/hide_overridden_rows.h>
#include <ui/qt/widgets/profile_inherit_combo_box.h>
#include <ui/qt/utils/inherit_selection.h>
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
    delegate_(NULL),
    copy_button_(NULL),
    inherit_combo_(NULL)
{
    ui->setupUi(this);

    ListEditButtons::ToolTips tool_tips;
    tool_tips.add = tr("Change the dissection behavior for a protocol.");
    tool_tips.remove = tr("Remove the selected dissection behaviors.");
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

    copy_button_ = new CopyFromProfileButton(this, DECODE_AS_ENTRIES_FILE_NAME);
    ui->buttonBox->addButton(copy_button_, QDialogButtonBox::ActionRole);
    connect(copy_button_, &CopyFromProfileButton::copyProfile, this, &DecodeAsDialog::copyFromProfile);

    // Where the entries come from, next to the button clearing them
    inherit_combo_ = ProfileInheritComboBox::addNextTo(this, ui->horizontalLayout, ui->editButtons, DECODE_AS_ENTRIES_FILE_NAME);
    connect(inherit_combo_, &ProfileInheritComboBox::modeChanged, this, &DecodeAsDialog::inheritModeChanged);

    // Not used entries can be hidden, which is not stored
    addHideNotUsedCheckBox(this, ui->horizontalLayout, inherit_combo_, ui->decodeAsTreeView, model_, -1);

    fillTable();
    updatePathLabel();
    followInheritedProfiles(model_, this, &DecodeAsDialog::updatePathLabel);

    connect(model_, &DecodeAsModel::modelReset, this, &DecodeAsDialog::modelRowsReset);
    connect(model_, &DecodeAsModel::rowsInserted, this, &DecodeAsDialog::modelRowsReset);
    connect(model_, &DecodeAsModel::rowsRemoved, this, &DecodeAsDialog::modelRowsReset);
    updateWidgets();

    if (create_new) {
        // A new entry is an own entry, which needs the own entries in use
        inherit_combo_->useOwnEntries();
        newClicked();
    }
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

void DecodeAsDialog::updatePathLabel()
{
    inherit_combo_->updatePathLabel(ui->pathLabel, inheritedProfiles(model_));
}

void DecodeAsDialog::updateWidgets()
{
    if (!inherit_combo_)
        return;

    InheritSelection sel = inheritSelection(model_, ui->decodeAsTreeView->selectionModel()->selectedRows());

    // Inherited entries can be copied into the own entries, but not changed
    ui->editButtons->setSelection(sel);
    if (copy_button_) {
        copy_button_->setOwnEntriesUsed(sel.own_used);
    }
}

void DecodeAsDialog::inheritModeChanged(profile_inherit_e mode)
{
    // The own entries are kept while hidden, and saved from there
    model_->setInheritMode(mode);
    resizeColumns();
    updatePathLabel();
    updateWidgets();
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

    // New entries go after the own entries, before the inherited entries
    int row = model_->ownRowCount();
    int src_row = (copy_from_current && current.row() >= row) ? current.row() + 1 : current.row();
    // should not fail, but you never know.
    if (!model_->insertRows(row, 1)) {
        qDebug() << "Failed to add a new record";
        return;
    }
    const QModelIndex &new_index = model_->index(row, 0);
    if (copy_from_current) {
        model_->copyRow(new_index.row(), src_row);
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
        {
        // The entries applied follow the selected mode, so it is kept as well;
        // otherwise the next Decode As would take inherited entries as own
        QString inherit_err;
        applyChanges();
        if (!inherit_combo_->saveMode(inherit_err)) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", inherit_err.toUtf8().constData());
        }
        }
        break;
    case QDialogButtonBox::Save:
        {
        char* err = NULL;
        QString inherit_err;

        applyChanges();
        if (save_decode_as_entries_for_mode(application_flavor_name_proper(), application_configuration_environment_prefix(),
                                            inherit_combo_->mode(), &err) < 0) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err);
            g_free(err);
        }
        // The own entries hidden while only the parent's are used aren't in the tables
        if (inherit_combo_->mode() == PROFILE_INHERIT_PARENT_ONLY && !model_->saveHiddenOwn(inherit_err)) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", inherit_err.toUtf8().constData());
            inherit_err.clear();
        }
        if (!inherit_combo_->saveMode(inherit_err)) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", inherit_err.toUtf8().constData());
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
