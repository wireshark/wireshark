/* coloring_rules_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "coloring_rules_dialog.h"
#include <ui_coloring_rules_dialog.h>

#include "ui/simple_dialog.h"
#include "epan/prefs.h"

#include <wsutil/utf8_entities.h>

#include "wsutil/filesystem.h"
#include "app/application_flavor.h"
#include "epan/dfilter/dfilter.h"

#include "main_application.h"

#include "ui/qt/utils/qt_ui_utils.h"
#include "ui/qt/utils/themes/themed_icon.h"
#include "ui/qt/widgets/copy_from_profile_button.h"
#include "ui/qt/widgets/profile_inherit_combo_box.h"
#include "ui/qt/utils/inherit_selection.h"
#include <ui/qt/utils/hide_overridden_rows.h>
#include <ui/qt/widgets/list_edit_buttons.h>
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <functional>
#include <QColorDialog>
#include <QMessageBox>
#include <QPushButton>
#include <QSet>
#include <QUrl>

/*
 * @file Coloring Rules dialog
 *
 * Coloring rule editor for the current profile.
 */

// To do:
// - Make the filter column narrower? It's easy to run into Qt's annoying
//   habit of horizontally scrolling QTreeWidgets here.

ColoringRulesDialog::ColoringRulesDialog(QWidget *parent, QString add_filter, QString add_name) :
    GeometryStateDialog(parent),
    ui(new Ui::ColoringRulesDialog),
    import_button_(nullptr),
    export_button_(nullptr),
    copy_button_(nullptr),
    inherit_combo_(nullptr),
    colorRuleModel_(palette().color(QPalette::Text), palette().color(QPalette::Base), this),
    colorRuleDelegate_(this)
{
    ui->setupUi(this);

    ListEditButtons::ToolTips tool_tips;
    tool_tips.add = tr("Add a new coloring rule.");
    tool_tips.remove = tr("Delete the selected coloring rules.");
    tool_tips.copy = tr("Duplicate this coloring rule.");
    tool_tips.moveUp = tr("Move the selected coloring rules up.");
    tool_tips.moveDown = tr("Move the selected coloring rules down.");
    tool_tips.clear = tr("Clear all coloring rules.");
    ui->editButtons->setToolTips(tool_tips);
    connect(ui->editButtons, &ListEditButtons::newClicked, this, &ColoringRulesDialog::newClicked);
    connect(ui->editButtons, &ListEditButtons::deleteClicked, this, &ColoringRulesDialog::deleteClicked);
    connect(ui->editButtons, &ListEditButtons::copyClicked, this, &ColoringRulesDialog::copyClicked);
    connect(ui->editButtons, &ListEditButtons::clearClicked, this, &ColoringRulesDialog::clearClicked);
    connect(ui->editButtons, &ListEditButtons::moveUpClicked, ui->coloringRulesTreeView, &RowMoveTreeView::moveSelectedRowsUp);
    connect(ui->editButtons, &ListEditButtons::moveDownClicked, ui->coloringRulesTreeView, &RowMoveTreeView::moveSelectedRowsDown);
    if (parent) loadGeometry(parent->width() * 2 / 3, parent->height() * 4 / 5);

    setWindowTitle(mainApp->windowTitleString(tr("Coloring Rules %1").arg(get_profile_name())));

    ui->coloringRulesTreeView->setModel(&colorRuleModel_);
    ui->coloringRulesTreeView->setItemDelegate(&colorRuleDelegate_);

    for (int i = 0; i < colorRuleModel_.columnCount(); i++) {
        ui->coloringRulesTreeView->resizeColumnToContents(i);
    }

#ifdef Q_OS_MACOS
    ui->pathLabel->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    connect(ui->coloringRulesTreeView->selectionModel(), &QItemSelectionModel::selectionChanged, this, &ColoringRulesDialog::colorRuleSelectionChanged);
    connect(&colorRuleDelegate_, &ColoringRulesDelegate::invalidField, this, &ColoringRulesDialog::invalidField);
    connect(&colorRuleDelegate_, &ColoringRulesDelegate::validField, this, &ColoringRulesDialog::validField);
    connect(ui->coloringRulesTreeView, &QTreeView::clicked, this, &ColoringRulesDialog::treeItemClicked);
    connect(&colorRuleModel_, &ColoringRulesModel::rowsInserted, this, &ColoringRulesDialog::rowCountChanged);
    connect(&colorRuleModel_, &ColoringRulesModel::rowsRemoved, this, &ColoringRulesDialog::rowCountChanged);
    connect(&colorRuleModel_, &ColoringRulesModel::rowsMoved, this, &ColoringRulesDialog::updateWidgets);

    // Where the rules come from, next to the button clearing them
    inherit_combo_ = ProfileInheritComboBox::addNextTo(this, ui->horizontalLayout, ui->editButtons, COLORING_RULES_FILE_NAME);
    connect(inherit_combo_, &ProfileInheritComboBox::modeChanged, this, &ColoringRulesDialog::inheritModeChanged);

    // Not used entries can be hidden, which is not stored
    addHideNotUsedCheckBox(this, ui->horizontalLayout, inherit_combo_, ui->coloringRulesTreeView, &colorRuleModel_);

    import_button_ = ui->buttonBox->addButton(tr("Import…"), QDialogButtonBox::ApplyRole);
    import_button_->setToolTip(tr("Select a file and add its filters to the end of the list."));
    export_button_ = ui->buttonBox->addButton(tr("Export…"), QDialogButtonBox::ApplyRole);
    export_button_->setToolTip(tr("Save filters in a file."));

    copy_button_ = new CopyFromProfileButton(this, COLORING_RULES_FILE_NAME,
                                             tr("Copy coloring rules from another profile."),
                                             COLORFILTERS_FILE_NAME);
    ui->buttonBox->addButton(copy_button_, QDialogButtonBox::ActionRole);
    connect(copy_button_, &CopyFromProfileButton::copyProfile, this, &ColoringRulesDialog::copyFromProfile);

    updatePathLabel();
    followInheritedProfiles(&colorRuleModel_, this, &ColoringRulesDialog::updatePathLabel);
    rowCountChanged();

    if (!add_filter.isEmpty()) {
        // A new rule is an own rule, which is not used with the parent's rules only
        inherit_combo_->useOwnEntries();
        colorRuleModel_.addColor(true, add_filter, palette().color(QPalette::Text), palette().color(QPalette::Base));

        if (!add_name.isEmpty()) {
            colorRuleModel_.setData(colorRuleModel_.index(0, ColoringRulesModel::colName),
                                    add_name, Qt::EditRole);
        }

        //setup the buttons appropriately
        ui->coloringRulesTreeView->setCurrentIndex(colorRuleModel_.index(0, 0));

        //set edit on display filter
        ui->coloringRulesTreeView->edit(colorRuleModel_.index(0, 1));
    }else {
        ui->coloringRulesTreeView->setCurrentIndex(QModelIndex());
    }

    updateHint();
}

ColoringRulesDialog::~ColoringRulesDialog()
{
    delete ui;
}

void ColoringRulesDialog::copyFromProfile(QString filename)
{
    QString err;

    if (!colorRuleModel_.importColors(filename, err)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err.toUtf8().constData());
    }

    for (int i = 0; i < colorRuleModel_.columnCount(); i++) {
        ui->coloringRulesTreeView->resizeColumnToContents(i);
    }
}

void ColoringRulesDialog::showEvent(QShowEvent *)
{
    ui->fGPushButton->setFixedHeight(ui->editButtons->copyButton()->geometry().height());
    ui->bGPushButton->setFixedHeight(ui->editButtons->copyButton()->geometry().height());
#ifndef Q_OS_MACOS
    ui->displayFilterPushButton->setFixedHeight(ui->editButtons->copyButton()->geometry().height());
#endif
}

void ColoringRulesDialog::rowCountChanged()
{
    updateWidgets();
}

void ColoringRulesDialog::updatePathLabel()
{
    inherit_combo_->updatePathLabel(ui->pathLabel, inheritedProfiles(&colorRuleModel_));
}

void ColoringRulesDialog::updateWidgets()
{
    if (!inherit_combo_)
        return;

    InheritSelection sel = inheritSelection(&colorRuleModel_, ui->coloringRulesTreeView->selectionModel()->selectedIndexes(), ui->coloringRulesTreeView);

    // Inherited rules can be copied into the own rules, but not changed
    ui->editButtons->setSelection(sel);
    if (copy_button_) {
        copy_button_->setOwnEntriesUsed(sel.own_used);
    }

    ui->fGPushButton->setVisible(sel.selected_count == 1 && !sel.inherited_selected);
    ui->bGPushButton->setVisible(sel.selected_count == 1 && !sel.inherited_selected);
    ui->displayFilterPushButton->setVisible(sel.selected_count == 1);
    ProfileInheritComboBox::setOwnEntriesUsed(import_button_, sel.own_used);
    if (import_button_)
        import_button_->setEnabled(sel.own_used);
}

void ColoringRulesDialog::inheritModeChanged(profile_inherit_e mode)
{
    colorRuleModel_.setInheritMode(mode);
    for (int i = 0; i < colorRuleModel_.columnCount(); i++) {
        ui->coloringRulesTreeView->resizeColumnToContents(i);
    }
    updatePathLabel();
    updateWidgets();
}

bool ColoringRulesDialog::isValidFilter(QString filter, QString * error)
{
    dfilter_t *dfp = NULL;
    df_error_t *df_err = NULL;

    if (dfilter_compile(filter.toUtf8().constData(), &dfp, &df_err)) {
        dfilter_free(dfp);
        return true;
    }

    if (df_err)
    {
        error->append(df_err->msg);
        df_error_free(&df_err);
    }

    return false;
}

void ColoringRulesDialog::treeItemClicked(const QModelIndex &index)
{
    QModelIndex idx = ui->coloringRulesTreeView->model()->index(index.row(), ColoringRulesModel::colFilter);
    QString filter = idx.data(Qt::DisplayRole).toString();
    QString err;
    if (! isValidFilter(filter, &err) && index.data(Qt::CheckStateRole).toInt() == Qt::Checked)
    {
        errors_.insert(index, err);
        updateHint(index);
    }
    else
    {
        QList<QModelIndex> keys = errors_.keys();
        bool update = false;
        foreach (QModelIndex key, keys)
        {
            if (key.row() == index.row())
            {
                errors_.remove(key);
                update = true;
            }
        }

        if (update)
            updateHint(index);
    }
}

void ColoringRulesDialog::invalidField(const QModelIndex &index, const QString& errMessage)
{
    errors_.insert(index, errMessage);
    updateHint(index);
}

void ColoringRulesDialog::validField(const QModelIndex &index)
{
    QList<QModelIndex> keys = errors_.keys();
    bool update = false;
    foreach (QModelIndex key, keys)
    {
        if (key.row() == index.row())
        {
            errors_.remove(key);
            update = true;
        }
    }

    if (update)
        updateHint(index);
}

void ColoringRulesDialog::updateHint(QModelIndex idx)
{
    QString hint = "<small><i>";
    QString error_text;
    bool enable_save = true;

    if (errors_.count() > 0) {
        //take the list of QModelIndexes and sort them so first color rule error is displayed
        //This isn't the most efficient algorithm, but the list shouldn't be large to matter
        QList<QModelIndex> keys = errors_.keys();

        //list is not guaranteed to be sorted, so force it
        std::sort(keys.begin(), keys.end());
        const QModelIndex& error_key = keys[0];
        error_text = QStringLiteral("%1: %2")
                            .arg(colorRuleModel_.data(colorRuleModel_.index(error_key.row(), ColoringRulesModel::colName), Qt::DisplayRole).toString())
                            .arg(errors_[error_key]);
    }

    if (error_text.isEmpty()) {
        hint += tr("Double click to edit. Drag to move. Rules are processed in order until a match is found.");
    } else {
        hint += error_text;
        if (idx.isValid())
        {
            QModelIndex fiIdx = ui->coloringRulesTreeView->model()->index(idx.row(), ColoringRulesModel::colName);
            if (fiIdx.data(Qt::CheckStateRole).toInt() == Qt::Checked)
                enable_save = false;
        }
        else
            enable_save = false;
    }

    hint += "</i></small>";
    ui->hintLabel->setText(hint);

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(enable_save);
}

void ColoringRulesDialog::setColorButtons(QModelIndex &index)
{
    QString color_button_ss =
            "QPushButton {"
            "  border: 1px solid palette(Dark);"
            "  padding-left: %1px;"
            "  padding-right: %1px;"
            "  color: %2;"
            "  background-color: %3;"
            "}";

    int one_em = fontMetrics().height();
    QVariant fg = colorRuleModel_.data(index, Qt::ForegroundRole);
    QVariant bg = colorRuleModel_.data(index, Qt::BackgroundRole);
    if (fg.isNull() || bg.isNull()) {
        //should never happen
        ui->fGPushButton->setVisible(false);
        ui->bGPushButton->setVisible(false);
    } else {
        QString fg_color = fg.toString();
        QString bg_color = bg.toString();

        ui->fGPushButton->setStyleSheet(color_button_ss.arg(one_em).arg(bg_color).arg(fg_color));
        ui->bGPushButton->setStyleSheet(color_button_ss.arg(one_em).arg(fg_color).arg(bg_color));
    }
}

void ColoringRulesDialog::colorRuleSelectionChanged(const QItemSelection&, const QItemSelection&)
{
    QModelIndexList selectedList = ui->coloringRulesTreeView->selectionModel()->selectedIndexes();

    //determine the number of unique rows
    QHash<int, QModelIndex> selectedRows;
    foreach (const QModelIndex &index, selectedList) {
        selectedRows.insert(index.row(), index);
    }

    qsizetype num_selected = selectedRows.count();
    if (num_selected == 1) {
        setColorButtons(selectedList[0]);
    }

    updateWidgets();
}

void ColoringRulesDialog::changeColor(bool foreground)
{
    QModelIndex current = ui->coloringRulesTreeView->currentIndex();
    if (!current.isValid())
        return;

    QColorDialog *color_dlg = new QColorDialog(this);
    color_dlg->setCurrentColor(colorRuleModel_.data(current, foreground ? Qt::ForegroundRole : Qt::BackgroundRole).toString());

    connect(color_dlg, &QColorDialog::colorSelected, std::bind(&ColoringRulesDialog::colorChanged, this, foreground, std::placeholders::_1));
    color_dlg->setWindowModality(Qt::ApplicationModal);
    color_dlg->setAttribute(Qt::WA_DeleteOnClose);
    color_dlg->show();
}

void ColoringRulesDialog::colorChanged(bool foreground, const QColor &cc)
{
    QModelIndex current = ui->coloringRulesTreeView->currentIndex();
    if (!current.isValid())
        return;

    colorRuleModel_.setData(current, cc, foreground ? Qt::ForegroundRole : Qt::BackgroundRole);
    setColorButtons(current);
}

void ColoringRulesDialog::on_fGPushButton_clicked()
{
    changeColor();
}

void ColoringRulesDialog::on_bGPushButton_clicked()
{
    changeColor(false);
}

void ColoringRulesDialog::on_displayFilterPushButton_clicked()
{
    QModelIndex current = ui->coloringRulesTreeView->currentIndex();
    if (!current.isValid())
        return;

    QString filter = colorRuleModel_.data(colorRuleModel_.index(current.row(), ColoringRulesModel::colFilter), Qt::DisplayRole).toString();
    emit filterAction(filter, FilterAction::ActionApply, FilterAction::ActionTypePlain);
}

void ColoringRulesDialog::addRule(bool copy_from_current)
{
    const QModelIndex &current = ui->coloringRulesTreeView->currentIndex();
    if (copy_from_current && !current.isValid())
        return;

    //always add rules at the top of the list
    if (copy_from_current) {
        colorRuleModel_.copyRow(colorRuleModel_.index(0, 0).row(), current.row());
    } else {
        if (!colorRuleModel_.insertRows(0, 1)) {
            return;
        }
    }

    //set edit on display filter
    ui->coloringRulesTreeView->edit(colorRuleModel_.index(0, 1));
}

void ColoringRulesDialog::newClicked()
{
    addRule();
}

void ColoringRulesDialog::deleteClicked()
{
    for (int row : rowsLastFirst(ui->coloringRulesTreeView->selectionModel()->selectedRows()))
        colorRuleModel_.removeRows(row, 1);
}

void ColoringRulesDialog::copyClicked()
{
    addRule(true);
}

void ColoringRulesDialog::clearClicked()
{
    removeVisibleOwnRows(ui->coloringRulesTreeView, &colorRuleModel_);
}

void ColoringRulesDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    QString err;

    if (button == import_button_) {
        QString file_name = WiresharkFileDialog::getOpenFileName(this, mainApp->windowTitleString(tr("Import Coloring Rules")),
                                                         mainApp->openDialogInitialDir().path());
        if (!file_name.isEmpty()) {
            if (!colorRuleModel_.importColors(file_name, err)) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err.toUtf8().constData());
            }
        }
    } else if (button == export_button_) {
        int num_items = static_cast<int>(ui->coloringRulesTreeView->selectionModel()->selectedIndexes().count()) / colorRuleModel_.columnCount();

        if (num_items < 1) {
            num_items = colorRuleModel_.rowCount();
        }

        if (num_items < 1)
            return;

        QString caption = mainApp->windowTitleString(tr("Export %1 Coloring Rules").arg(num_items));
        QString file_name = WiresharkFileDialog::getSaveFileName(this, caption,
                                                         mainApp->openDialogInitialDir().path());
        if (!file_name.isEmpty()) {
            if (!colorRuleModel_.exportColors(file_name, err)) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err.toUtf8().constData());
            }
        }
    }
}

void ColoringRulesDialog::on_buttonBox_accepted()
{
    QString err;
    int ret = QDialog::Accepted;
    if (!colorRuleModel_.writeColors(err)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err.toUtf8().constData());
        ret = QDialog::Rejected;
    } else if (!inherit_combo_->saveMode(err)) {
        // The mode is only kept with the rules written for it
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err.toUtf8().constData());
    }
    done(ret);
}

void ColoringRulesDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_COLORING_RULES_DIALOG);
}
