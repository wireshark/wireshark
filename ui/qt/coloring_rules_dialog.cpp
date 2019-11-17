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
#include "epan/dfilter/dfilter.h"

#include "wireshark_application.h"
#include "ui/qt/utils/qt_ui_utils.h"
#include "ui/qt/widgets/copy_from_profile_button.h"
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <functional>
#include <QColorDialog>
#include <QMessageBox>
#include <QPushButton>
#include <QUrl>

/*
 * @file Coloring Rules dialog
 *
 * Coloring rule editor for the current profile.
 */

// To do:
// - Make the filter column narrower? It's easy to run into Qt's annoying
//   habit of horizontally scrolling QTreeWidgets here.

ColoringRulesDialog::ColoringRulesDialog(QWidget *parent, QString add_filter) :
    GeometryStateDialog(parent),
    ui(new Ui::ColoringRulesDialog),
    colorRuleModel_(palette().color(QPalette::Text), palette().color(QPalette::Base), this),
    colorRuleDelegate_(this)
{
    ui->setupUi(this);
    if (parent) loadGeometry(parent->width() * 2 / 3, parent->height() * 4 / 5);

    setWindowTitle(wsApp->windowTitleString(tr("Coloring Rules %1").arg(get_profile_name())));

    ui->coloringRulesTreeView->setModel(&colorRuleModel_);
    ui->coloringRulesTreeView->setItemDelegate(&colorRuleDelegate_);

    ui->coloringRulesTreeView->viewport()->setAcceptDrops(true);

    for (int i = 0; i < colorRuleModel_.columnCount(); i++) {
        ui->coloringRulesTreeView->resizeColumnToContents(i);
    }

    ui->newToolButton->setStockIcon("list-add");
    ui->deleteToolButton->setStockIcon("list-remove");
    ui->copyToolButton->setStockIcon("list-copy");
    ui->clearToolButton->setStockIcon("list-clear");

#ifdef Q_OS_MAC
    ui->newToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->deleteToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->copyToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->clearToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->pathLabel->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    connect(ui->coloringRulesTreeView->selectionModel(), SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)),
            this, SLOT(colorRuleSelectionChanged(const QItemSelection &, const QItemSelection &)));
    connect(&colorRuleDelegate_, SIGNAL(invalidField(const QModelIndex&, const QString&)),
            this, SLOT(invalidField(const QModelIndex&, const QString&)));
    connect(&colorRuleDelegate_, SIGNAL(validField(const QModelIndex&)),
            this, SLOT(validField(const QModelIndex&)));
    connect(ui->coloringRulesTreeView, &QTreeView::clicked, this, &ColoringRulesDialog::treeItemClicked);
    connect(&colorRuleModel_, SIGNAL(rowsInserted(const QModelIndex &, int, int)), this, SLOT(rowCountChanged()));
    connect(&colorRuleModel_, SIGNAL(rowsRemoved(const QModelIndex &, int, int)), this, SLOT(rowCountChanged()));

    rowCountChanged();

    import_button_ = ui->buttonBox->addButton(tr("Import" UTF8_HORIZONTAL_ELLIPSIS), QDialogButtonBox::ApplyRole);
    import_button_->setToolTip(tr("Select a file and add its filters to the end of the list."));
    export_button_ = ui->buttonBox->addButton(tr("Export" UTF8_HORIZONTAL_ELLIPSIS), QDialogButtonBox::ApplyRole);
    export_button_->setToolTip(tr("Save filters in a file."));

    CopyFromProfileButton * copy_button = new CopyFromProfileButton(this, COLORFILTERS_FILE_NAME, tr("Copy coloring rules from another profile."));
    ui->buttonBox->addButton(copy_button, QDialogButtonBox::ActionRole);
    connect(copy_button, &CopyFromProfileButton::copyProfile, this, &ColoringRulesDialog::copyFromProfile);

    QString abs_path = gchar_free_to_qstring(get_persconffile_path(COLORFILTERS_FILE_NAME, TRUE));
    if (file_exists(abs_path.toUtf8().constData())) {
        ui->pathLabel->setText(abs_path);
        ui->pathLabel->setUrl(QUrl::fromLocalFile(abs_path).toString());
        ui->pathLabel->setToolTip(tr("Open ") + COLORFILTERS_FILE_NAME);
        ui->pathLabel->setEnabled(true);
    }

    if (!add_filter.isEmpty()) {
        colorRuleModel_.addColor(false, add_filter, palette().color(QPalette::Text), palette().color(QPalette::Base));

        //setup the buttons appropriately
        ui->coloringRulesTreeView->setCurrentIndex(colorRuleModel_.index(0, 0));

        //set edit on display filter
        ui->coloringRulesTreeView->edit(colorRuleModel_.index(0, 1));
    }else {
        ui->coloringRulesTreeView->setCurrentIndex(QModelIndex());
    }

    checkUnknownColorfilters();

    updateHint();
}

ColoringRulesDialog::~ColoringRulesDialog()
{
    delete ui;
}

void ColoringRulesDialog::checkUnknownColorfilters()
{
    if (prefs.unknown_colorfilters) {
        QMessageBox *mb = new QMessageBox();
        mb->setText(tr("Your coloring rules file contains unknown rules"));
        mb->setInformativeText(tr("Wireshark doesn't recognize one or more of your coloring rules. "
                                 "They have been disabled."));
        mb->setStandardButtons(QMessageBox::Ok);

        mb->setWindowModality(Qt::ApplicationModal);
        mb->setAttribute(Qt::WA_DeleteOnClose);
        mb->show();
        prefs.unknown_colorfilters = FALSE;
    }
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

    checkUnknownColorfilters();
}

void ColoringRulesDialog::showEvent(QShowEvent *)
{
    ui->fGPushButton->setFixedHeight(ui->copyToolButton->geometry().height());
    ui->bGPushButton->setFixedHeight(ui->copyToolButton->geometry().height());
#ifndef Q_OS_MAC
    ui->displayFilterPushButton->setFixedHeight(ui->copyToolButton->geometry().height());
#endif
}

void ColoringRulesDialog::rowCountChanged()
{
    ui->clearToolButton->setEnabled(colorRuleModel_.rowCount() > 0);
}

bool ColoringRulesDialog::isValidFilter(QString filter, QString * error)
{
    dfilter_t *dfp = NULL;
    gchar *err_msg;
    if (dfilter_compile(filter.toUtf8().constData(), &dfp, &err_msg)) {
        GPtrArray *depr = NULL;
        if (dfp) {
            depr = dfilter_deprecated_tokens(dfp);
        }
        if (! depr) {
            return true;
        }
    }
    dfilter_free(dfp);

    if (err_msg)
    {
        error->append(err_msg);
        g_free(err_msg);
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
        //This isn't the most efficent algorithm, but the list shouldn't be large to matter
        QList<QModelIndex> keys = errors_.keys();

        //list is not guaranteed to be sorted, so force it
        std::sort(keys.begin(), keys.end());
        const QModelIndex& error_key = keys[0];
        error_text = QString("%1: %2")
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

    int num_selected = selectedRows.count();
    if (num_selected == 1) {
        setColorButtons(selectedList[0]);
    }

    ui->copyToolButton->setEnabled(num_selected == 1);
    ui->deleteToolButton->setEnabled(num_selected > 0);
    ui->fGPushButton->setVisible(num_selected == 1);
    ui->bGPushButton->setVisible(num_selected == 1);
    ui->displayFilterPushButton->setVisible(num_selected == 1);
}

void ColoringRulesDialog::changeColor(bool foreground)
{
    QModelIndex current = ui->coloringRulesTreeView->currentIndex();
    if (!current.isValid())
        return;

    QColorDialog *color_dlg = new QColorDialog();
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

void ColoringRulesDialog::on_newToolButton_clicked()
{
    addRule();
}

void ColoringRulesDialog::on_deleteToolButton_clicked()
{
    QModelIndexList selectedList = ui->coloringRulesTreeView->selectionModel()->selectedIndexes();
    int num_selected = selectedList.count()/colorRuleModel_.columnCount();
    if (num_selected > 0) {
        //list is not guaranteed to be sorted, so force it
        std::sort(selectedList.begin(), selectedList.end());

        //walk the list from the back because deleting a value in
        //the middle will leave the selectedList out of sync and
        //delete the wrong elements
        for (int i = selectedList.count()-1; i >= 0; i--) {
            QModelIndex deleteIndex = selectedList[i];
            //selectedList includes all cells, use first column as key to remove row
            if (deleteIndex.isValid() && (deleteIndex.column() == 0)) {
                colorRuleModel_.removeRows(deleteIndex.row(), 1);
            }
        }
    }
}

void ColoringRulesDialog::on_copyToolButton_clicked()
{
    addRule(true);
}

void ColoringRulesDialog::on_clearToolButton_clicked()
{
    colorRuleModel_.removeRows(0, colorRuleModel_.rowCount());
}

void ColoringRulesDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    QString err;

    if (button == import_button_) {
        QString file_name = WiresharkFileDialog::getOpenFileName(this, wsApp->windowTitleString(tr("Import Coloring Rules")),
                                                         wsApp->lastOpenDir().path());
        if (!file_name.isEmpty()) {
            if (!colorRuleModel_.importColors(file_name, err)) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err.toUtf8().constData());
            }

            checkUnknownColorfilters();
        }
    } else if (button == export_button_) {
        int num_items = ui->coloringRulesTreeView->selectionModel()->selectedIndexes().count()/colorRuleModel_.columnCount();

        if (num_items < 1) {
            num_items = colorRuleModel_.rowCount();
        }

        if (num_items < 1)
            return;

        QString caption = wsApp->windowTitleString(tr("Export %1 Coloring Rules").arg(num_items));
        QString file_name = WiresharkFileDialog::getSaveFileName(this, caption,
                                                         wsApp->lastOpenDir().path());
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
    if (!colorRuleModel_.writeColors(err)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err.toUtf8().constData());
    }
}

void ColoringRulesDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_COLORING_RULES_DIALOG);
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
