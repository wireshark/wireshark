/* column_preferences_frame.cpp
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

#include "config.h"

#include <glib.h>

#include <epan/column-info.h>
#include <epan/column.h>
#include <epan/prefs.h>
#include <epan/proto.h>

#include <ui/preference_utils.h>

#include "qt_ui_utils.h"
#include "column_preferences_frame.h"
#include <ui_column_preferences_frame.h>
#include "syntax_line_edit.h"
#include "field_filter_edit.h"
#include "wireshark_application.h"

#include <QComboBox>
#include <QTreeWidgetItemIterator>
#include <QLineEdit>
#include <QKeyEvent>

const int visible_col_           = 0;
const int title_col_             = 1;
const int type_col_              = 2;
const int custom_fields_col_     = 3;
const int custom_occurrence_col_ = 4;

ColumnPreferencesFrame::ColumnPreferencesFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::ColumnPreferencesFrame),
    cur_column_(0),
    cur_line_edit_(NULL),
    cur_combo_box_(NULL),
    saved_combo_idx_(0),
    saved_custom_combo_idx_(-1)
{
    ui->setupUi(this);

    int one_em = ui->columnTreeWidget->fontMetrics().height();
    ui->columnTreeWidget->setColumnWidth(custom_fields_col_, one_em * 10);
    ui->columnTreeWidget->setColumnWidth(custom_occurrence_col_, one_em * 5);

    ui->columnTreeWidget->setMinimumWidth(one_em * 20);
    ui->columnTreeWidget->setMinimumHeight(one_em * 12);

    ui->columnTreeWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->columnTreeWidget->setDragEnabled(true);
    ui->columnTreeWidget->viewport()->setAcceptDrops(true);
    ui->columnTreeWidget->setDropIndicatorShown(true);
    ui->columnTreeWidget->setDragDropMode(QAbstractItemView::InternalMove);

    for (GList *cur = g_list_first(prefs.col_list); cur != NULL && cur->data != NULL; cur = cur->next) {
        fmt_data *cfmt = (fmt_data *) cur->data;
        addColumn(cfmt->visible, cfmt->title, cfmt->fmt, cfmt->custom_fields, cfmt->custom_occurrence);
    }

    connect(ui->columnTreeWidget, SIGNAL(itemSelectionChanged()), this, SLOT(updateWidgets()));

    if (prefs.num_cols > 0) {
        ui->columnTreeWidget->topLevelItem(0)->setSelected(true);
    }

    updateWidgets();
}

ColumnPreferencesFrame::~ColumnPreferencesFrame()
{
    delete ui;
}

void ColumnPreferencesFrame::unstash()
{
    GList *new_col_list = NULL;
    bool changed = false;

    QTreeWidgetItemIterator it(ui->columnTreeWidget);
    while (*it) {
        fmt_data *cfmt = g_new0(fmt_data, 1);

        cfmt->title = qstring_strdup((*it)->text(title_col_));
        cfmt->fmt = (*it)->data(type_col_, Qt::UserRole).value<int>();
        cfmt->visible = (*it)->checkState(visible_col_) == Qt::Checked ? TRUE : FALSE;
        cfmt->resolved = TRUE;

        if (cfmt->fmt == COL_CUSTOM) {
            bool ok;
            int occurrence = (*it)->text(custom_occurrence_col_).toInt(&ok);
            cfmt->custom_fields = qstring_strdup((*it)->text(custom_fields_col_));
            cfmt->custom_occurrence = ok ? occurrence : 0;
        }

        if (prefs.col_list == NULL) {
            changed = true;
        } else {
            fmt_data *old_cfmt = (fmt_data *) prefs.col_list->data;
            if (!old_cfmt ||
                    g_strcmp0(old_cfmt->title, cfmt->title) != 0 ||
                    old_cfmt->fmt != cfmt->fmt ||
                    old_cfmt->visible != cfmt->visible ||
                    (old_cfmt->fmt == COL_CUSTOM && (
                         g_strcmp0(old_cfmt->custom_fields, cfmt->custom_fields) != 0 ||
                         old_cfmt->custom_occurrence != cfmt->custom_occurrence))) {
                changed = true;
            }
            column_prefs_remove_link(prefs.col_list);
        }

        new_col_list = g_list_append(new_col_list, cfmt);
        ++it;
    }

    while (prefs.col_list) {
        changed = true;
        column_prefs_remove_link(prefs.col_list);
    }
    prefs.col_list = new_col_list;

    if (changed) {
        wsApp->emitAppSignal(WiresharkApplication::ColumnsChanged);
    }
}

void ColumnPreferencesFrame::keyPressEvent(QKeyEvent *evt)
{
    if (cur_line_edit_ && cur_line_edit_->hasFocus()) {
        int new_idx = COL_CUSTOM;
        switch (evt->key()) {
        case Qt::Key_Escape:
            cur_line_edit_->setText(saved_col_string_);
            new_idx = saved_combo_idx_;
            /* Fall Through */
        case Qt::Key_Enter:
        case Qt::Key_Return:
            switch (cur_column_) {
            case title_col_:
                columnTitleEditingFinished();
                break;
            case custom_fields_col_:
                customFieldsEditingFinished();
                columnTypeCurrentIndexChanged(new_idx);
                break;
            case custom_occurrence_col_:
                customOccurrenceEditingFinished();
                columnTypeCurrentIndexChanged(new_idx);
                break;
            default:
                break;
            }

            delete cur_line_edit_;
            return;
        default:
            break;
        }
    } else if (cur_combo_box_ && cur_combo_box_->hasFocus()) {
        switch (evt->key()) {
        case Qt::Key_Escape:
            cur_combo_box_->setCurrentIndex(saved_combo_idx_);
            /* Fall Through */
        case Qt::Key_Enter:
        case Qt::Key_Return:
            // XXX The combo box eats enter and return
            columnTypeCurrentIndexChanged(cur_combo_box_->currentIndex());
            delete cur_combo_box_;
            return;
        default:
            break;
        }
    }
    QFrame::keyPressEvent(evt);
}

void ColumnPreferencesFrame::addColumn(bool visible, const char *title, int fmt, const char *custom_fields, int custom_occurrence)
{
    QTreeWidgetItem *item = new QTreeWidgetItem(ui->columnTreeWidget);

    item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
    item->setFlags(item->flags() & ~(Qt::ItemIsDropEnabled));
    item->setCheckState(visible_col_, visible ? Qt::Checked : Qt::Unchecked);
    item->setText(title_col_, title);
    item->setText(type_col_, col_format_desc(fmt));
    item->setData(type_col_, Qt::UserRole, QVariant(fmt));
    if (fmt == COL_CUSTOM) {
        item->setText(custom_fields_col_, custom_fields);
        item->setText(custom_occurrence_col_, QString::number(custom_occurrence));
    }

    updateWidgets();
}

void ColumnPreferencesFrame::updateWidgets()
{
    ui->columnTreeWidget->resizeColumnToContents(visible_col_);
    ui->columnTreeWidget->resizeColumnToContents(title_col_);
    ui->columnTreeWidget->resizeColumnToContents(type_col_);

    ui->deleteToolButton->setEnabled(ui->columnTreeWidget->selectedItems().count() > 0 && ui->columnTreeWidget->topLevelItemCount() > 1);
}


void ColumnPreferencesFrame::on_columnTreeWidget_currentItemChanged(QTreeWidgetItem *, QTreeWidgetItem *previous)
{
    if (previous) {
        if (ui->columnTreeWidget->itemWidget(previous, title_col_)) {
            ui->columnTreeWidget->removeItemWidget(previous, title_col_);
        }
        if (ui->columnTreeWidget->itemWidget(previous, type_col_)) {
            ui->columnTreeWidget->removeItemWidget(previous, type_col_);
            previous->setText(type_col_, col_format_desc(previous->data(type_col_, Qt::UserRole).toInt()));
        }
        if (ui->columnTreeWidget->itemWidget(previous, custom_fields_col_)) {
            ui->columnTreeWidget->removeItemWidget(previous, custom_fields_col_);
        }
        if (ui->columnTreeWidget->itemWidget(previous, custom_occurrence_col_)) {
            ui->columnTreeWidget->removeItemWidget(previous, custom_occurrence_col_);
        }

        // If the custom column auto-changed the Column type, change it back if
        // there isn't any text in the field columns
        if ((previous->text(custom_fields_col_) == "") &&
            (previous->text(custom_occurrence_col_) == "") &&
            (saved_custom_combo_idx_ >= 0))
        {
            previous->setText(type_col_, col_format_desc(saved_custom_combo_idx_));
            previous->setData(type_col_, Qt::UserRole, QVariant(saved_custom_combo_idx_));
            saved_custom_combo_idx_ = -1;
        }
    }
    updateWidgets();
}

void ColumnPreferencesFrame::on_columnTreeWidget_itemActivated(QTreeWidgetItem *item, int column)
{
    if (!item || cur_line_edit_ || cur_combo_box_) return;

    QWidget *editor = NULL;
    cur_column_ = column;
    saved_combo_idx_ = item->data(type_col_, Qt::UserRole).toInt();

    switch (column) {
    case title_col_:
    {
        cur_line_edit_ = new QLineEdit();
        cur_column_ = column;
        saved_col_string_ = item->text(title_col_);
        connect(cur_line_edit_, SIGNAL(editingFinished()), this, SLOT(columnTitleEditingFinished()));
        editor = cur_line_edit_;
        break;
    }
    case type_col_:
    {
        cur_combo_box_ = new QComboBox();
        for (int i = 0; i < NUM_COL_FMTS; i++) {
            cur_combo_box_->addItem(col_format_desc(i), QVariant(i));
            if (i == saved_combo_idx_) {
                cur_combo_box_->setCurrentIndex(i);
            }
        }
        connect(cur_combo_box_, SIGNAL(currentIndexChanged(int)), this, SLOT(columnTypeCurrentIndexChanged(int)));
        editor = cur_combo_box_;
        break;
    }
    case custom_fields_col_:
    {
        FieldFilterEdit *field_filter_edit = new FieldFilterEdit();
        saved_col_string_ = item->text(custom_fields_col_);
        connect(field_filter_edit, SIGNAL(textChanged(QString)),
                field_filter_edit, SLOT(checkCustomColumn(QString)));
        connect(field_filter_edit, SIGNAL(editingFinished()), this, SLOT(customFieldsEditingFinished()));
        editor = cur_line_edit_ = field_filter_edit;

        //Save off the current column type in case it needs to be restored
        if ((item->text(custom_fields_col_) == "") && (item->text(custom_occurrence_col_) == "")) {
            saved_custom_combo_idx_ = item->data(type_col_, Qt::UserRole).toInt();
        }
        item->setText(type_col_, col_format_desc(COL_CUSTOM));
        item->setData(type_col_, Qt::UserRole, QVariant(COL_CUSTOM));
        break;
    }
    case custom_occurrence_col_:
    {
        SyntaxLineEdit *syntax_edit = new SyntaxLineEdit();
        saved_col_string_ = item->text(custom_occurrence_col_);
        connect(syntax_edit, SIGNAL(textChanged(QString)),
                syntax_edit, SLOT(checkInteger(QString)));
        connect(syntax_edit, SIGNAL(editingFinished()), this, SLOT(customOccurrenceEditingFinished()));
        editor = cur_line_edit_ = syntax_edit;

        //Save off the current column type in case it needs to be restored
        if ((item->text(custom_fields_col_) == "") && (item->text(custom_occurrence_col_) == "")) {
            saved_custom_combo_idx_ = item->data(type_col_, Qt::UserRole).toInt();
        }
        item->setText(type_col_, col_format_desc(COL_CUSTOM));
        item->setData(type_col_, Qt::UserRole, QVariant(COL_CUSTOM));
        break;
    }
    default:
        return;
    }

    if (cur_line_edit_) {
        cur_line_edit_->setText(saved_col_string_);
        cur_line_edit_->selectAll();
        connect(cur_line_edit_, SIGNAL(destroyed()), this, SLOT(lineEditDestroyed()));
    }
    if (cur_combo_box_) {
        connect(cur_combo_box_, SIGNAL(destroyed()), this, SLOT(comboDestroyed()));
    }
    if (editor) {
        QFrame *edit_frame = new QFrame();
        QHBoxLayout *hb = new QHBoxLayout();
        QSpacerItem *spacer = new QSpacerItem(5, 10);

        hb->addWidget(editor, 0);
        hb->addSpacerItem(spacer);
        hb->setStretch(1, 1);
        hb->setContentsMargins(0, 0, 0, 0);

        edit_frame->setLineWidth(0);
        edit_frame->setFrameStyle(QFrame::NoFrame);
        // The documentation suggests setting autoFillbackground. That looks silly
        // so we clear the item text instead.
        item->setText(cur_column_, "");
        edit_frame->setLayout(hb);
        ui->columnTreeWidget->setItemWidget(item, cur_column_, edit_frame);
        editor->setFocus();
    }
}

void ColumnPreferencesFrame::lineEditDestroyed()
{
    cur_line_edit_ = NULL;
}

void ColumnPreferencesFrame::comboDestroyed()
{
    cur_combo_box_ = NULL;
}

void ColumnPreferencesFrame::columnTitleEditingFinished()
{
    QTreeWidgetItem *item = ui->columnTreeWidget->currentItem();
    if (!cur_line_edit_ || !item) return;

    item->setText(title_col_, cur_line_edit_->text());
    ui->columnTreeWidget->removeItemWidget(item, title_col_);
}

void ColumnPreferencesFrame::columnTypeCurrentIndexChanged(int index)
{
    QTreeWidgetItem *item = ui->columnTreeWidget->currentItem();
    if (!item || index < 0) return;

    item->setData(type_col_, Qt::UserRole, QVariant(index));
    item->setText(type_col_, col_format_desc(index));

    if (index != COL_CUSTOM) {
        item->setText(custom_fields_col_, "");
        item->setText(custom_occurrence_col_, "");
    }
}

void ColumnPreferencesFrame::customFieldsEditingFinished()
{
    QTreeWidgetItem *item = ui->columnTreeWidget->currentItem();
    if (!cur_line_edit_ || !item) return;

    item->setText(custom_fields_col_, cur_line_edit_->text());
    ui->columnTreeWidget->removeItemWidget(item, custom_fields_col_);
}

void ColumnPreferencesFrame::customOccurrenceEditingFinished()
{
    QTreeWidgetItem *item = ui->columnTreeWidget->currentItem();
    if (!cur_line_edit_ || !item) return;

    item->setText(custom_occurrence_col_, cur_line_edit_->text());
    ui->columnTreeWidget->removeItemWidget(item, custom_occurrence_col_);
}

void ColumnPreferencesFrame::on_newToolButton_clicked()
{
    addColumn(true, "New Column", COL_NUMBER, NULL, 0); //TODO : Fix Translate
}

void ColumnPreferencesFrame::on_deleteToolButton_clicked()
{
    if (ui->columnTreeWidget->topLevelItemCount() < 2) return;

    QTreeWidgetItem *item = ui->columnTreeWidget->currentItem();
    if (item) {
        ui->columnTreeWidget->invisibleRootItem()->removeChild(item);
    }

    updateWidgets();
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
