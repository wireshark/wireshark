/* filter_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <wsutil/filter_files.h>
#include <wsutil/filesystem.h>
#include <app/application_flavor.h>

#include "filter_dialog.h"
#include <ui_filter_dialog.h>

#include <QMessageBox>
#include <QThread>
#include <QUrl>
#include <QSortFilterProxyModel>

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/widgets/filter_edit.h>
#include <ui/qt/widgets/list_edit_buttons.h>
#include <ui/qt/models/capture_filter_validator.h>
#include <ui/qt/widgets/display_filter_edit.h>
#include "main_application.h"

FilterDialog::FilterDialog(QWidget *parent, FilterType filter_type, QString new_filter_) :
    GeometryStateDialog(parent),
    ui(new Ui::FilterDialog),
    filter_type_(filter_type),
    filter_tree_delegate_(new FilterTreeDelegate(this, filter_type))
{
    ui->setupUi(this);

    if (parent) loadGeometry(parent->width() * 2 / 3, parent->height() * 2 / 3);
    setWindowIcon(mainApp->normalIcon());

#ifdef Q_OS_MACOS
    ui->pathLabel->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    const char * filename = NULL;
    QString newFilterText;
    ListEditButtons::ToolTips tool_tips;
    switch (filter_type) {
        case CaptureFilter:
            setWindowTitle(mainApp->windowTitleString(tr("Capture Filters")));
            filename = CFILTER_FILE_NAME;
            newFilterText = tr("New capture filter");
            tool_tips.add = tr("Create a new filter.");
            tool_tips.remove = tr("Remove the selected filters.");
            tool_tips.copy = tr("Copy this filter.");
            tool_tips.moveUp = tr("Move the selected filters up.");
            tool_tips.moveDown = tr("Move the selected filters down.");
            tool_tips.clear = tr("Clear all filters.");
            model_ = new FilterListModel(FilterListModel::Capture, this);
            break;
        case DisplayFilter:
            setWindowTitle(mainApp->windowTitleString(tr("Display Filters")));
            filename = DFILTER_FILE_NAME;
            newFilterText = tr("New display filter");
            tool_tips.add = tr("Create a new filter.");
            tool_tips.remove = tr("Remove the selected filters.");
            tool_tips.copy = tr("Copy this filter.");
            tool_tips.moveUp = tr("Move the selected filters up.");
            tool_tips.moveDown = tr("Move the selected filters down.");
            tool_tips.clear = tr("Clear all filters.");
            model_ = new FilterListModel(FilterListModel::Display, this);
            break;
        case DisplayMacro:
            setWindowTitle(mainApp->windowTitleString(tr("Display Filter Macros")));
            filename = DMACROS_FILE_NAME;
            newFilterText = tr("New macro");
            tool_tips.add = tr("Create a new macro.");
            tool_tips.remove = tr("Remove the selected macros.");
            tool_tips.copy = tr("Copy this macro.");
            tool_tips.moveUp = tr("Move the selected macros up.");
            tool_tips.moveDown = tr("Move the selected macros down.");
            tool_tips.clear = tr("Clear all macros.");
            model_ = new FilterListModel(FilterListModel::DisplayMacro, this);
            break;
        default:
            ws_assert_not_reached();
    }

    ui->editButtons->setToolTips(tool_tips);
    connect(ui->editButtons, &ListEditButtons::newClicked, this, &FilterDialog::newClicked);
    connect(ui->editButtons, &ListEditButtons::deleteClicked, this, &FilterDialog::deleteClicked);
    connect(ui->editButtons, &ListEditButtons::copyClicked, this, &FilterDialog::copyClicked);
    connect(ui->editButtons, &ListEditButtons::clearClicked, this, &FilterDialog::clearClicked);
    connect(ui->editButtons, &ListEditButtons::moveUpClicked, ui->filterTreeView, &RowMoveTreeView::moveSelectedRowsUp);
    connect(ui->editButtons, &ListEditButtons::moveDownClicked, ui->filterTreeView, &RowMoveTreeView::moveSelectedRowsDown);

    ui->filterTreeView->setModel(model_);

    ui->filterTreeView->setItemDelegate(new FilterTreeDelegate(this, filter_type));

    if (new_filter_.length() > 0)
        addFilter(newFilterText, new_filter_, true);

    ui->filterTreeView->resizeColumnToContents(FilterListModel::ColumnName);

    connect(ui->filterTreeView->selectionModel(), &QItemSelectionModel::selectionChanged, this, &FilterDialog::selectionChanged);
    connect(model_, &FilterListModel::rowsInserted, this, &FilterDialog::updateWidgets);
    connect(model_, &FilterListModel::rowsRemoved, this, &FilterDialog::updateWidgets);
    connect(model_, &FilterListModel::rowsMoved, this, &FilterDialog::updateWidgets);
    connect(model_, &FilterListModel::modelReset, this, &FilterDialog::updateWidgets);
    updateWidgets();

    QString abs_path = gchar_free_to_qstring(get_persconffile_path(filename, true, application_configuration_environment_prefix()));
    if (file_exists(abs_path.toUtf8().constData())) {
        ui->pathLabel->setText(abs_path);
        ui->pathLabel->setUrl(QUrl::fromLocalFile(abs_path).toString());
        ui->pathLabel->setToolTip(tr("Open ") + filename);
        ui->pathLabel->setEnabled(true);
    }
}

FilterDialog::~FilterDialog()
{
    delete ui;
}

void FilterDialog::addFilter(QString name, QString filter, bool start_editing)
{
    if (model_)
    {
        QModelIndex idx = model_->addFilter(name, filter);
        ui->filterTreeView->scrollTo(idx);
        if (start_editing)
            ui->filterTreeView->edit(idx);
        else
            ui->filterTreeView->selectionModel()->select(idx,QItemSelectionModel::ClearAndSelect|QItemSelectionModel::Rows);
    }
}

void FilterDialog::updateWidgets()
{
    if (! ui->filterTreeView->selectionModel())
        return;

    ui->editButtons->setSelection(ui->filterTreeView->selectionModel()->selectedRows(), model_->rowCount());
}

void FilterDialog::selectionChanged(const QItemSelection &/*selected*/, const QItemSelection &/*deselected*/)
{
    updateWidgets();
}

void FilterDialog::newClicked()
{
    QString name;
    QString filter;

    switch (filter_type_) {
        case CaptureFilter:
            //: This text is automatically filled in when a new filter is created
            name = tr("New capture filter");
            filter = "ip host host.example.com";
            break;
        case DisplayFilter:
            //: This text is automatically filled in when a new filter is created
            name = tr("New display filter");
            filter = "ip.host == host.example.com";
            break;
        case DisplayMacro:
            //: This text is automatically filled in when a new filter is created
            name = "eq_example_com";
            filter = "$1 == host.example.com";
            break;
        default:
            ws_assert_not_reached();
    }

    addFilter(name, filter, true);
}

void FilterDialog::deleteClicked()
{
    for (int row : rowsLastFirst(ui->filterTreeView->selectionModel()->selectedRows()))
        model_->removeFilter(model_->index(row, 0));
}

void FilterDialog::copyClicked()
{
    QModelIndexList selected = ui->filterTreeView->selectionModel()->selectedRows();
    if (selected.count() <= 0)
        return;

    int rowNr = selected.at(0).row();
    QModelIndex row = selected.at(0).sibling(rowNr, FilterListModel::ColumnName);

    addFilter(row.data().toString(), row.sibling(rowNr, FilterListModel::ColumnExpression).data().toString(), true);
}

void FilterDialog::clearClicked()
{
    for (int row = model_->rowCount() - 1; row >= 0; row--)
        model_->removeFilter(model_->index(row, 0));
}

void FilterDialog::on_buttonBox_accepted()
{
    model_->saveList();

    switch (filter_type_) {
        case CaptureFilter:
            mainApp->emitAppSignal(MainApplication::CaptureFilterListChanged);
            break;
        case DisplayFilter:
            mainApp->emitAppSignal(MainApplication::DisplayFilterListChanged);
            break;
        case DisplayMacro:
            mainApp->reloadDisplayFilterMacros();
            // The function above emits MainApplication::FieldsChanged, which
            // takes care of invalidating the current display filter text if
            // it no longer compiles.
            // XXX - What if the current display filter means something
            // different now? Should we force a refilter (not redissection,
            // the dissection shouldn't have changed) with the current display
            // filter, or wait for the user to refilter?
            // The UAT based display macro system did not refilter.
            break;
        default:
            ws_assert_not_reached();
    }
}

void FilterDialog::on_buttonBox_helpRequested()
{
    switch (filter_type_) {
        case CaptureFilter:
            mainApp->helpTopicAction(HELP_CAPTURE_FILTERS_DIALOG);
            break;
        case DisplayFilter:
            mainApp->helpTopicAction(HELP_DISPLAY_FILTERS_DIALOG);
            break;
        case DisplayMacro:
            mainApp->helpTopicAction(HELP_DISPLAY_MACRO_DIALOG);
            break;
        default:
            ws_assert_not_reached();
    }
}

//
// FilterTreeDelegate
// Delegate for editing capture and display filters.
//

FilterTreeDelegate::FilterTreeDelegate(QObject *parent, FilterDialog::FilterType filter_type) :
    QStyledItemDelegate(parent),
    filter_type_(filter_type)
{}

QWidget *FilterTreeDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QWidget * w = Q_NULLPTR;
    if (index.column() != FilterListModel::ColumnExpression) {
        w = QStyledItemDelegate::createEditor(parent, option, index);
    }
    else if (filter_type_ == FilterDialog::CaptureFilter) {
        // Plain capture-filter edit for the inline cell: validity tinting only,
        // no bookmark/history chrome (this is the saved-filter manager itself).
        FilterEdit *fe = new FilterEdit(parent);
        fe->setValidator(new CaptureFilterValidator(fe));
        w = fe;
    }
    else if (filter_type_ == FilterDialog::DisplayFilter) {
        w = new DisplayFilterEdit(parent, DisplayFilterToEnter);
    }
    else {
        w = QStyledItemDelegate::createEditor(parent, option, index);
    }

    QLineEdit *le = qobject_cast<QLineEdit *>(w);
    if (le != nullptr) {
        if (index.column() == FilterListModel::ColumnName) {
            if (filter_type_ == FilterDialog::DisplayMacro) {
                le->setValidator(new MacroNameValidator(le));
            }
            else {
                le->setValidator(new DialogFilterValidator(le));
            }
        }
    }

    return w;
}

void FilterTreeDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    if (! editor || ! index.isValid())
        return;

    QStyledItemDelegate::setEditorData(editor, index);

    if (qobject_cast<QLineEdit *>(editor))
        qobject_cast<QLineEdit *>(editor)->setText(index.data().toString());
}

QValidator::State DialogFilterValidator::validate(QString & input, int & /*pos*/) const
{
    /* Making this a list to be able to easily add additional values in the future */
    QStringList invalidKeys = QStringList() << "\"";

    if (input.length() <= 0)
        return QValidator::Intermediate;

    foreach (QString key, invalidKeys)
        if (input.indexOf(key) >= 0)
            return QValidator::Invalid;

    return QValidator::Acceptable;
}

QValidator::State MacroNameValidator::validate(QString &input, int & /*pos*/) const
{
    if (input.length() <= 0)
        return QValidator::Intermediate;

    for (QChar ch: input) {
        if (!ch.isLetterOrNumber() && ch != '_') {
            return QValidator::Invalid;
        }
    }

    return QValidator::Acceptable;
}
