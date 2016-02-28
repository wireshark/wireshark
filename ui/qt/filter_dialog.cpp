/* filter_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <config.h>

#include <errno.h>

#include <glib.h>

#include <filter_files.h>

#include <wsutil/filesystem.h>

#include "filter_dialog.h"
#include <ui_filter_dialog.h>

#include <QMessageBox>
#include <QThread>

#include "capture_filter_edit.h"
//#include "capture_filter_syntax_worker.h"
#include "display_filter_edit.h"
#include "wireshark_application.h"

// To do:
// - Add filter expression button. The right thing to do might be to add an
//   action inside DisplayFilterEdit.
// - Show syntax state of each filter? A partial implementation is in place
//   for capture filters.

enum {
    name_col_,
    filter_col_
};

FilterDialog::FilterDialog(QWidget *parent, FilterType filter_type, const QString new_filter) :
    GeometryStateDialog(parent),
    ui(new Ui::FilterDialog),
    filter_type_(filter_type),
//    syntax_worker_(NULL),
    filter_tree_delegate_(new FilterTreeDelegate(this, filter_type)),
    new_filter_(new_filter)
{
    ui->setupUi(this);
    if (parent) loadGeometry(parent->width() * 2 / 3, parent->height() * 2 / 3);
    setWindowIcon(wsApp->normalIcon());

    ui->filterTreeWidget->setDragEnabled(true);
    ui->filterTreeWidget->viewport()->setAcceptDrops(true);
    ui->filterTreeWidget->setDropIndicatorShown(true);
    ui->filterTreeWidget->setDragDropMode(QAbstractItemView::InternalMove);

    if (filter_type == CaptureFilter) {
        setWindowTitle(wsApp->windowTitleString(tr("Capture Filters")));

//        QThread *syntax_thread = new QThread;
//        syntax_worker_ = new CaptureFilterSyntaxWorker;
//        syntax_worker_->moveToThread(syntax_thread);
//        connect(syntax_thread, SIGNAL(started()), syntax_worker_, SLOT(start()));
//        //    connect(syntax_thread, SIGNAL(started()), this, SLOT(checkFilter()));
//        connect(syntax_worker_, SIGNAL(syntaxResult(QString, bool, QString)),
//                this, SLOT(setFilterSyntaxState(QString, bool, QString)));
//        connect(syntax_thread, SIGNAL(finished()), syntax_worker_, SLOT(deleteLater()));
//        syntax_thread->start();
    } else {
        setWindowTitle(wsApp->windowTitleString(tr("Display Filters")));
    }

    ui->filterTreeWidget->setItemDelegateForColumn(filter_col_, filter_tree_delegate_);
}

FilterDialog::~FilterDialog()
{
    delete ui;
}

void FilterDialog::showEvent(QShowEvent *event)
{
    ui->filterTreeWidget->clear();

    GList *filter_list;
    if (filter_type_ == CaptureFilter) {
        filter_list = get_filter_list_first(CFILTER_LIST);
    } else {
        filter_list = get_filter_list_first(DFILTER_LIST);
    }
    for (GList *fl_item = filter_list; fl_item; fl_item = g_list_next(fl_item)) {
        if (!fl_item->data) continue;
        filter_def *fl_data = (filter_def *) fl_item->data;
        if (!fl_data->name || !fl_data->strval) continue;

        addFilter(fl_data->name, fl_data->strval);
    }

    if (!new_filter_.isEmpty()) {
        addFilter(tr("New filter"), new_filter_, true);
        new_filter_.clear();
    }

    ui->filterTreeWidget->resizeColumnToContents(name_col_);
    ui->filterTreeWidget->resizeColumnToContents(filter_col_);

    QDialog::showEvent(event);
}

void FilterDialog::addFilter(QString name, QString filter, bool start_editing)
{
    QTreeWidgetItem *ti = new QTreeWidgetItem(ui->filterTreeWidget);
    ti->setFlags(ti->flags() | Qt::ItemIsEditable);
    ti->setFlags(ti->flags() & ~(Qt::ItemIsDropEnabled));
    ti->setText(name_col_, name);
    ti->setText(filter_col_, filter);

    if (start_editing) {
        ui->filterTreeWidget->setCurrentItem(ti);
        updateWidgets();
        ui->filterTreeWidget->editItem(ti, filter_col_);
    }
}

void FilterDialog::updateWidgets()
{
    int num_selected = ui->filterTreeWidget->selectedItems().count();

    ui->copyToolButton->setEnabled(num_selected == 1);
    ui->deleteToolButton->setEnabled(num_selected > 0);
}

//void FilterDialog::setFilterSyntaxState(QString filter, bool valid, QString err_msg)
//{

//}

void FilterDialog::on_filterTreeWidget_itemSelectionChanged()
{
    updateWidgets();
}

void FilterDialog::on_newToolButton_clicked()
{
    QString name;
    QString filter;

    if (filter_type_ == CaptureFilter) {
        //: This text is automatically filled in when a new filter is created
        name = tr("New capture filter");
        filter = "ip host host.example.com";
    } else {
        //: This text is automatically filled in when a new filter is created
        name = tr("New display filter");
        filter = "ip.addr == host.example.com";
    }

    addFilter(name, filter, true);
}

void FilterDialog::on_deleteToolButton_clicked()
{
    QList<QTreeWidgetItem*> selected = ui->filterTreeWidget->selectedItems();
    foreach (QTreeWidgetItem *ti, selected) {
        delete ti;
    }
}

void FilterDialog::on_copyToolButton_clicked()
{
    if (!ui->filterTreeWidget->currentItem()) return;
    QTreeWidgetItem *ti = ui->filterTreeWidget->currentItem();

    addFilter(ti->text(name_col_), ti->text(filter_col_), true);
}

void FilterDialog::on_buttonBox_accepted()
{
    filter_list_type_t fl_type = filter_type_ == CaptureFilter ? CFILTER_LIST : DFILTER_LIST;

    while (GList *fl_item = get_filter_list_first(fl_type)) {
        remove_from_filter_list(fl_type, fl_item);
    }

    QTreeWidgetItemIterator it(ui->filterTreeWidget);
    while (*it) {
        add_to_filter_list(fl_type, (*it)->text(name_col_).toUtf8().constData(),
                           (*it)->text(filter_col_).toUtf8().constData());
        ++it;
    }

    char *pf_dir_path;
    char *f_path;
    int f_save_errno;

    /* Create the directory that holds personal configuration files,
       if necessary.  */
    if (create_persconffile_dir(&pf_dir_path) == -1) {
        QMessageBox::warning(this, tr("Unable to create profile directory."),
                tr("Unable to create directory\n\"%1\"\nfor filter files: %2.")
                             .arg(pf_dir_path)
                             .arg(g_strerror(errno)),
                QMessageBox::Ok);
        g_free(pf_dir_path);
        return;
    }

    save_filter_list(fl_type, &f_path, &f_save_errno);
    if (f_path != NULL) {
        /* We had an error saving the filter. */
        QString warning_title;
        QString warning_msg;
        if (fl_type == CFILTER_LIST) {
            warning_title = tr("Unable to save capture filter settings.");
            warning_msg = tr("Could not save to your capture filter file\n\"%1\": %2.")
              .arg(f_path).arg(g_strerror(f_save_errno));
        } else {
            warning_title = tr("Unable to save display filter settings.");
            warning_msg = tr("Could not save to your display filter file\n\"%1\": %2.")
              .arg(f_path).arg(g_strerror(f_save_errno));
        }
        QMessageBox::warning(this, warning_title, warning_msg, QMessageBox::Ok);
        g_free(f_path);
    }

    if (filter_type_ == CaptureFilter) {
        wsApp->emitAppSignal(WiresharkApplication::CaptureFilterListChanged);
    } else {
        wsApp->emitAppSignal(WiresharkApplication::DisplayFilterListChanged);
    }
}

void FilterDialog::on_buttonBox_helpRequested()
{
    if (filter_type_ == CaptureFilter) {
        wsApp->helpTopicAction(HELP_CAPTURE_FILTERS_DIALOG);
    } else {
        wsApp->helpTopicAction(HELP_DISPLAY_FILTERS_DIALOG);
    }
}

//
// FilterTreeDelegate
// Delegate for editing capture and display filters.
//

QWidget *FilterTreeDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    if (index.column() != filter_col_) {
        return QStyledItemDelegate::createEditor(parent, option, index);
    }

    QWidget *w;

    if (filter_type_ == FilterDialog::CaptureFilter) {
        w = new CaptureFilterEdit(parent, true);
    } else {
        w = new DisplayFilterEdit(parent, DisplayFilterToEnter);
    }

    return w;
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
