/* filter_expressions_preferences_frame.cpp
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

#include <epan/filter_expressions.h>

#include "filter_expressions_preferences_frame.h"
#include <ui_filter_expressions_preferences_frame.h>
#include "display_filter_edit.h"
#include "wireshark_application.h"

#include "qt_ui_utils.h"

#include <QLineEdit>
#include <QKeyEvent>
#include <QTreeWidgetItemIterator>

static const int enabled_col_    = 0;
static const int label_col_      = 1;
static const int expression_col_ = 2;

// This shouldn't exist in its current form. Instead it should be the "display filters"
// dialog, and the "dfilters" file should support a "show in toolbar" flag.

FilterExpressionsPreferencesFrame::FilterExpressionsPreferencesFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::FilterExpressionsPreferencesFrame),
    cur_column_(0),
    cur_line_edit_(NULL)
{
    ui->setupUi(this);

    int one_em = ui->expressionTreeWidget->fontMetrics().height();
    ui->expressionTreeWidget->resizeColumnToContents(enabled_col_);
    ui->expressionTreeWidget->setColumnWidth(label_col_, one_em * 10);
    ui->expressionTreeWidget->setColumnWidth(expression_col_, one_em * 5);

    ui->expressionTreeWidget->setMinimumWidth(one_em * 15);
    ui->expressionTreeWidget->setMinimumHeight(one_em * 10);

    ui->expressionTreeWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->expressionTreeWidget->setDragEnabled(true);
    ui->expressionTreeWidget->viewport()->setAcceptDrops(true);
    ui->expressionTreeWidget->setDropIndicatorShown(true);
    ui->expressionTreeWidget->setDragDropMode(QAbstractItemView::InternalMove);

    ui->expressionTreeWidget->clear();

    for (struct filter_expression *fe = *pfilter_expression_head; fe != NULL; fe = fe->next) {
        if (fe->deleted) continue;
        addExpression(fe->enabled, fe->label, fe->expression);
    }

    updateWidgets();
}

FilterExpressionsPreferencesFrame::~FilterExpressionsPreferencesFrame()
{
    delete ui;
}

void FilterExpressionsPreferencesFrame::unstash()
{
    struct filter_expression *cur_fe = *pfilter_expression_head, *new_fe_head = NULL, *new_fe = NULL;
    bool changed = false;

    QTreeWidgetItemIterator it(ui->expressionTreeWidget);
    while (*it) {
        struct filter_expression *fe = g_new0(struct filter_expression, 1);

        if (!new_fe_head) {
            new_fe_head = fe;
        } else {
            new_fe->next = fe;
        }
        new_fe = fe;

        new_fe->enabled = (*it)->checkState(enabled_col_) == Qt::Checked ? TRUE : FALSE;
        new_fe->label = qstring_strdup((*it)->text(label_col_));
        new_fe->expression = qstring_strdup((*it)->text(expression_col_));

        if (cur_fe == NULL) {
            changed = true;
        } else {
            if (cur_fe->enabled != new_fe->enabled ||
                    g_strcmp0(cur_fe->label, new_fe->label) != 0 ||
                    g_strcmp0(cur_fe->expression, new_fe->expression) != 0) {
                changed = true;
            }
            cur_fe = cur_fe->next;
        }
        ++it;
    }

    if (cur_fe) changed = true;

    cur_fe = new_fe_head;
    if (changed) {
        cur_fe = *pfilter_expression_head;
        *pfilter_expression_head = new_fe_head;
        wsApp->emitAppSignal(WiresharkApplication::FilterExpressionsChanged);
    }

    while (cur_fe) {
        struct filter_expression *fe = cur_fe;
        cur_fe = fe->next;
        g_free(fe->label);
        g_free(fe->expression);
        g_free(fe);
    }
}

void FilterExpressionsPreferencesFrame::keyPressEvent(QKeyEvent *evt)
{
    if (cur_line_edit_ && cur_line_edit_->hasFocus()) {
        switch (evt->key()) {
        case Qt::Key_Escape:
            cur_line_edit_->setText(saved_col_string_);
            /* Fall Through */
        case Qt::Key_Enter:
        case Qt::Key_Return:
            switch (cur_column_) {
            case label_col_:
                labelEditingFinished();
                break;
            case expression_col_:
                expressionEditingFinished();
                break;
            default:
                break;
            }

            delete cur_line_edit_;
            return;
        default:
            break;
        }
    }
    QFrame::keyPressEvent(evt);
}

void FilterExpressionsPreferencesFrame::addExpression(bool enabled, const QString label, const QString expression)
{
    QTreeWidgetItem *item = new QTreeWidgetItem(ui->expressionTreeWidget);

    item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
    item->setFlags(item->flags() & ~(Qt::ItemIsDropEnabled));
    item->setCheckState(enabled_col_, enabled ? Qt::Checked : Qt::Unchecked);
    item->setText(label_col_, label);
    item->setText(expression_col_, expression);
}

void FilterExpressionsPreferencesFrame::updateWidgets()
{
    int num_selected = ui->expressionTreeWidget->selectedItems().count();

    ui->copyToolButton->setEnabled(num_selected == 1);
    ui->deleteToolButton->setEnabled(num_selected > 0);
}

void FilterExpressionsPreferencesFrame::on_expressionTreeWidget_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    ui->deleteToolButton->setEnabled(current ? true : false);

    if (previous && ui->expressionTreeWidget->itemWidget(previous, label_col_)) {
        ui->expressionTreeWidget->removeItemWidget(previous, label_col_);
    }
    if (previous && ui->expressionTreeWidget->itemWidget(previous, expression_col_)) {
        ui->expressionTreeWidget->removeItemWidget(previous, expression_col_);
    }
}

void FilterExpressionsPreferencesFrame::on_expressionTreeWidget_itemActivated(QTreeWidgetItem *item, int column)
{
    if (!item || cur_line_edit_) return;

    QWidget *editor = NULL;
    cur_column_ = column;

    switch (column) {
    case label_col_:
    {
        cur_line_edit_ = new QLineEdit();
        saved_col_string_ = item->text(label_col_);
        connect(cur_line_edit_, SIGNAL(editingFinished()), this, SLOT(labelEditingFinished()));
        editor = cur_line_edit_;
        break;
    }
    case expression_col_:
    {
        DisplayFilterEdit *display_edit = new DisplayFilterEdit();
        saved_col_string_ = item->text(expression_col_);
        connect(display_edit, SIGNAL(textChanged(QString)),
                display_edit, SLOT(checkDisplayFilter(QString)));
        connect(display_edit, SIGNAL(editingFinished()), this, SLOT(expressionEditingFinished()));
        editor = cur_line_edit_ = display_edit;
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
        ui->expressionTreeWidget->setItemWidget(item, cur_column_, edit_frame);
        editor->setFocus();
    }
}

void FilterExpressionsPreferencesFrame::lineEditDestroyed()
{
    cur_line_edit_ = NULL;
}

void FilterExpressionsPreferencesFrame::labelEditingFinished()
{
    QTreeWidgetItem *item = ui->expressionTreeWidget->currentItem();
    if (!cur_line_edit_ || !item) return;

    item->setText(label_col_, cur_line_edit_->text());
    ui->expressionTreeWidget->removeItemWidget(item, label_col_);
}

void FilterExpressionsPreferencesFrame::expressionEditingFinished()
{
    QTreeWidgetItem *item = ui->expressionTreeWidget->currentItem();
    if (!cur_line_edit_ || !item) return;

    item->setText(expression_col_, cur_line_edit_->text());
    ui->expressionTreeWidget->removeItemWidget(item, expression_col_);
}

void FilterExpressionsPreferencesFrame::on_expressionTreeWidget_itemSelectionChanged()
{
    updateWidgets();
}

static const QString new_button_label_ = QObject::tr("My Filter");
void FilterExpressionsPreferencesFrame::on_newToolButton_clicked()
{
    addExpression(true, new_button_label_, QString());
}

void FilterExpressionsPreferencesFrame::on_deleteToolButton_clicked()
{
    QTreeWidgetItem *item = ui->expressionTreeWidget->currentItem();
    if (item) {
        ui->expressionTreeWidget->invisibleRootItem()->removeChild(item);
    }
}

void FilterExpressionsPreferencesFrame::on_copyToolButton_clicked()
{
    if (!ui->expressionTreeWidget->currentItem()) return;
    QTreeWidgetItem *ti = ui->expressionTreeWidget->currentItem();

    addExpression(ti->checkState(enabled_col_) == Qt::Checked,
                  ti->text(label_col_), ti->text(expression_col_));
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
