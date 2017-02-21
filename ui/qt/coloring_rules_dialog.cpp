/* coloring_rules_dialog.cpp
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

#include <errno.h>

#include <glib.h>

#include "coloring_rules_dialog.h"
#include <ui_coloring_rules_dialog.h>

#include "epan/color_filters.h"

#include "ui/simple_dialog.h"
#include "ui/simple_dialog.h"
#include "epan/dfilter/dfilter.h"
#include "epan/prefs.h"

#include <wsutil/utf8_entities.h>

#include "wsutil/filesystem.h"

#include "color_utils.h"
#include "ui/ui_util.h"
#include "display_filter_combo.h"
#include "syntax_line_edit.h"
#include "display_filter_edit.h"
#include "wireshark_application.h"

#include <QColorDialog>
#include <QDir>
#include <QFileDialog>
#include <QMessageBox>
#include <QPushButton>
#include <QTreeWidgetItemIterator>

/*
 * @file Coloring Rules dialog
 *
 * Coloring rule editor for the current profile.
 */

// To do:
// - Make the filter column narrower? It's easy to run into Qt's annoying
//   habit of horizontally scrolling QTreeWidgets here.


enum {
    name_col_ = 0,
    filter_col_
};

static const QString new_rule_name_ = QObject::tr("New coloring rule");

ColoringRulesDialog::ColoringRulesDialog(QWidget *parent, QString add_filter) :
    GeometryStateDialog(parent),
    ui(new Ui::ColoringRulesDialog),
    conversation_colors_(NULL)
{
    ui->setupUi(this);
    if (parent) loadGeometry(parent->width() * 2 / 3, parent->height() * 4 / 5);

    setWindowTitle(wsApp->windowTitleString(QStringList() << tr("Coloring Rules") << get_profile_name()));

    ui->coloringRulesTreeWidget->setDragEnabled(true);
    ui->coloringRulesTreeWidget->viewport()->setAcceptDrops(true);
    ui->coloringRulesTreeWidget->setDropIndicatorShown(true);
    ui->coloringRulesTreeWidget->setDragDropMode(QAbstractItemView::InternalMove);

    color_filters_clone(this, color_filter_add_cb);

    for (int i = 0; i < ui->coloringRulesTreeWidget->columnCount(); i++) {
        ui->coloringRulesTreeWidget->setItemDelegateForColumn(i, &coloring_rules_tree_delegate_);
        ui->coloringRulesTreeWidget->resizeColumnToContents(i);
    }
    coloring_rules_tree_delegate_.setTree(ui->coloringRulesTreeWidget);

    if (!add_filter.isEmpty()) {
        addColoringRule(false, new_rule_name_, add_filter,
                        palette().color(QPalette::Text),
                        palette().color(QPalette::Base),
                        true);
    }

    connect(ui->coloringRulesTreeWidget, SIGNAL(itemChanged(QTreeWidgetItem*,int)),
            this, SLOT(updateWidgets()));

    import_button_ = ui->buttonBox->addButton(tr("Import" UTF8_HORIZONTAL_ELLIPSIS), QDialogButtonBox::ApplyRole);
    import_button_->setToolTip(tr("Select a file and add its filters to the end of the list."));
    export_button_ = ui->buttonBox->addButton(tr("Export" UTF8_HORIZONTAL_ELLIPSIS), QDialogButtonBox::ApplyRole);
    export_button_->setToolTip(tr("Save filters in a file."));

    updateWidgets();
}

ColoringRulesDialog::~ColoringRulesDialog()
{
    delete ui;
    color_filter_list_delete(&conversation_colors_);
}

void ColoringRulesDialog::addColor(_color_filter *colorf)
{
    if (!colorf) return;

    if(strstr(colorf->filter_name, CONVERSATION_COLOR_PREFIX) != NULL) {
        conversation_colors_ = g_slist_append(conversation_colors_, colorf);
    } else {
        addColoringRule(colorf->disabled, colorf->filter_name, colorf->filter_text,
                        ColorUtils::fromColorT(colorf->fg_color),
                        ColorUtils::fromColorT(colorf->bg_color),
                        false, false);
    }
}

void ColoringRulesDialog::showEvent(QShowEvent *)
{
    ui->fGPushButton->setFixedHeight(ui->copyToolButton->geometry().height());
    ui->bGPushButton->setFixedHeight(ui->copyToolButton->geometry().height());
}

void ColoringRulesDialog::updateWidgets()
{
    QString hint = "<small><i>";
    int num_selected = ui->coloringRulesTreeWidget->selectedItems().count();

    if (num_selected == 1) {
        QTreeWidgetItem *ti = ui->coloringRulesTreeWidget->currentItem();
        QString color_button_ss =
                "QPushButton {"
                "  border: 1px solid palette(Dark);"
                "  padding-left: %1px;"
                "  padding-right: %1px;"
                "  color: %2;"
                "  background-color: %3;"
                "}";
        int one_em = fontMetrics().height();
        QString fg_color = ti->foreground(0).color().name();
        QString bg_color = ti->background(0).color().name();
        ui->fGPushButton->setStyleSheet(color_button_ss.arg(one_em).arg(bg_color).arg(fg_color));
        ui->bGPushButton->setStyleSheet(color_button_ss.arg(one_em).arg(fg_color).arg(bg_color));
    }

    ui->copyToolButton->setEnabled(num_selected == 1);
    ui->deleteToolButton->setEnabled(num_selected > 0);
    ui->fGPushButton->setVisible(num_selected == 1);
    ui->bGPushButton->setVisible(num_selected == 1);

    QString error_text;
    QTreeWidgetItemIterator iter(ui->coloringRulesTreeWidget);
    bool enable_save = true;

    while (*iter) {
        QTreeWidgetItem *item = (*iter);
        if (item->text(name_col_).contains("@")) {
            error_text = tr("the \"@\" symbol will be ignored.");
        }

        // Check the rule's display filter syntax only if it's checked.
        QString display_filter = item->text(filter_col_);
        if (!display_filter.isEmpty() && item->checkState(name_col_) == Qt::Checked) {
            dfilter_t *dfilter;
            bool status;
            gchar *err_msg;
            status = dfilter_compile(display_filter.toUtf8().constData(), &dfilter, &err_msg);
            dfilter_free(dfilter);
            if (!status) {
                if (!error_text.isEmpty()) error_text += " ";
                error_text += err_msg;
                g_free(err_msg);
                enable_save = false;
            }
        }

        if (!error_text.isEmpty()) {
            error_text.prepend(QString("%1: ").arg(item->text(name_col_)));
            break;
        }
        ++iter;
    }

    if (error_text.isEmpty()) {
        hint += tr("Double click to edit. Drag to move. Rules are processed in order until a match is found.");
    } else {
        hint += error_text;
    }
    hint += "</i></small>";
    ui->hintLabel->setText(hint);

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(enable_save);
}

GSList *ColoringRulesDialog::createColorFilterList()
{
    GSList *cfl = NULL;
    QTreeWidgetItemIterator iter(ui->coloringRulesTreeWidget);

    while (*iter) {
        QTreeWidgetItem *item = (*iter);
        color_t fg = ColorUtils::toColorT(item->foreground(0).color());
        color_t bg = ColorUtils::toColorT(item->background(0).color());
        color_filter_t *colorf = color_filter_new(item->text(name_col_).toUtf8().constData(),
                                                  item->text(filter_col_).toUtf8().constData(),
                                                  &bg, &fg, item->checkState(0) == Qt::Unchecked);
        cfl = g_slist_append(cfl, colorf);
        ++iter;
    }
    return cfl;
}

void ColoringRulesDialog::on_coloringRulesTreeWidget_itemSelectionChanged()
{
    updateWidgets();
}

void ColoringRulesDialog::changeColor(bool foreground)
{
    if (!ui->coloringRulesTreeWidget->currentItem()) return;

    QTreeWidgetItem *ti = ui->coloringRulesTreeWidget->currentItem();
    QColorDialog color_dlg;

    color_dlg.setCurrentColor(foreground ?
                                  ti->foreground(0).color() : ti->background(0).color());
    if (color_dlg.exec() == QDialog::Accepted) {
        QColor cc = color_dlg.currentColor();
        if (foreground) {
            for (int i = 0; i < ui->coloringRulesTreeWidget->columnCount(); i++) {
                ti->setForeground(i, cc);
            }
        } else {
            for (int i = 0; i < ui->coloringRulesTreeWidget->columnCount(); i++) {
                ti->setBackground(i, cc);
            }
        }
        updateWidgets();
    }

}

void ColoringRulesDialog::on_fGPushButton_clicked()
{
    changeColor();
}

void ColoringRulesDialog::on_bGPushButton_clicked()
{
    changeColor(false);
}

void ColoringRulesDialog::addColoringRule(bool disabled, QString name, QString filter, QColor foreground, QColor background, bool start_editing, bool at_top)
{
    QTreeWidgetItem *ti = new QTreeWidgetItem();

    ti->setFlags(ti->flags() | Qt::ItemIsUserCheckable | Qt::ItemIsEditable);
    ti->setFlags(ti->flags() & ~(Qt::ItemIsDropEnabled));
    ti->setCheckState(name_col_, disabled ? Qt::Unchecked : Qt::Checked);
    ti->setText(name_col_, name);
    ti->setText(filter_col_, filter);

    for (int i = 0; i < ui->coloringRulesTreeWidget->columnCount(); i++) {
        ti->setForeground(i, foreground);
        ti->setBackground(i, background);
    }

    if (at_top) {
        ui->coloringRulesTreeWidget->insertTopLevelItem(0, ti);
    } else {
        ui->coloringRulesTreeWidget->addTopLevelItem(ti);
    }

    if (start_editing) {
        ui->coloringRulesTreeWidget->setCurrentItem(ti);
        updateWidgets();
        ui->coloringRulesTreeWidget->editItem(ti, filter_col_);
    }
}

void ColoringRulesDialog::on_newToolButton_clicked()
{
    addColoringRule(false, new_rule_name_, QString(), palette().color(QPalette::Text),
                    palette().color(QPalette::Base), true);
}

void ColoringRulesDialog::on_deleteToolButton_clicked()
{
    QList<QTreeWidgetItem*> selected = ui->coloringRulesTreeWidget->selectedItems();
    foreach (QTreeWidgetItem *ti, selected) {
        delete ti;
    }
    updateWidgets();
}

void ColoringRulesDialog::on_copyToolButton_clicked()
{
    if (!ui->coloringRulesTreeWidget->currentItem()) return;
    QTreeWidgetItem *ti = ui->coloringRulesTreeWidget->currentItem();

    addColoringRule(ti->checkState(0) == Qt::Unchecked, ti->text(name_col_),
                    ti->text(filter_col_), ti->foreground(0).color(),
                    ti->background(0).color(), true);
}

void ColoringRulesDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    if (button == import_button_) {
        QString file_name = QFileDialog::getOpenFileName(this, wsApp->windowTitleString(tr("Import Coloring Rules")),
                                                         wsApp->lastOpenDir().path());
        if (!file_name.isEmpty()) {
            gchar* err_msg = NULL;
            if (!color_filters_import(file_name.toUtf8().constData(), this, &err_msg, color_filter_add_cb)) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_msg);
                g_free(err_msg);
            }
        }
    } else if (button == export_button_) {
        int num_items = ui->coloringRulesTreeWidget->selectedItems().count();

        if (num_items < 1) {
            num_items = ui->coloringRulesTreeWidget->topLevelItemCount();
        }

        if (num_items < 1) return;

        QString caption = wsApp->windowTitleString(tr("Export %1 Coloring Rules").arg(num_items));
        QString file_name = QFileDialog::getSaveFileName(this, caption,
                                                         wsApp->lastOpenDir().path());
        if (!file_name.isEmpty()) {
            GSList *cfl = createColorFilterList();
            gchar* err_msg = NULL;
            if (!color_filters_export(file_name.toUtf8().constData(), cfl, FALSE, &err_msg)) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_msg);
                g_free(err_msg);
            }
            color_filter_list_delete(&cfl);
        }
    }
}

void ColoringRulesDialog::on_buttonBox_accepted()
{
    GSList *cfl = createColorFilterList();
    gchar* err_msg = NULL;
    if (prefs.unknown_colorfilters) {
        QMessageBox mb;
        mb.setText(tr("Your coloring rules file contains unknown rules"));
        mb.setInformativeText(tr("Wireshark doesn't recognize one or more of your coloring rules. "
                                 "They have been disabled."));
        mb.setStandardButtons(QMessageBox::Ok);

        int result = mb.exec();
        if (result != QMessageBox::Save) return;
    }
    if (!color_filters_apply(conversation_colors_, cfl, &err_msg)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_msg);
        g_free(err_msg);
    }
    if (!color_filters_write(cfl, &err_msg)) {
        QMessageBox::warning(this, tr("Unable to save coloring rules: %s"), g_strerror(errno));
        g_free(err_msg);
    }
    color_filter_list_delete(&cfl);
}

void ColoringRulesDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_COLORING_RULES_DIALOG);
}

//
// ColoringRulesTreeDelegate
// Delegate for editing coloring rule names and filters.
//

QWidget *ColoringRulesTreeDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &, const QModelIndex &index) const
{
    QWidget *w = NULL;

    QTreeWidgetItem *ti = tree_->topLevelItem(index.row());
    if (!ti) return NULL;

    switch (index.column()) {
    case name_col_:
    {
        SyntaxLineEdit *sle = new SyntaxLineEdit(parent);
        connect(sle, SIGNAL(textChanged(QString)), this, SLOT(ruleNameChanged(QString)));
        sle->setText(ti->text(name_col_));
        w = (QWidget*) sle;
    }
        break;

    case filter_col_:
    {
        DisplayFilterEdit *dfe = new DisplayFilterEdit(parent);
        // It's possible to have an invalid filter and an enabled OK button at this point.
        // We might want to add a local slot for checking the filter status.
        connect(dfe, SIGNAL(textChanged(QString)), dfe, SLOT(checkDisplayFilter(QString)));
        dfe->setText(ti->text(filter_col_));
        w = (QWidget*) dfe;
    }
        break;
    default:
        break;
    }

    return w;
}

void ColoringRulesTreeDelegate::ruleNameChanged(const QString name)
{
    SyntaxLineEdit *name_edit = qobject_cast<SyntaxLineEdit*>(QObject::sender());
    if (!name_edit) return;

    if (name.isEmpty()) {
        name_edit->setSyntaxState(SyntaxLineEdit::Empty);
    } else if (name.contains("@")) {
        name_edit->setSyntaxState(SyntaxLineEdit::Invalid);
    } else {
        name_edit->setSyntaxState(SyntaxLineEdit::Valid);
    }

}

// Callback for color_filters_clone.
void
color_filter_add_cb(color_filter_t *colorf, gpointer user_data)
{
    ColoringRulesDialog *coloring_rules_dialog = static_cast<ColoringRulesDialog*>(user_data);

    if (!coloring_rules_dialog) return;
    coloring_rules_dialog->addColor(colorf);
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
