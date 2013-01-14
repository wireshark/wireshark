/* preferences_dialog.cpp
 *
 * $Id$
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

#include "preferences_dialog.h"
#include "ui_preferences_dialog.h"
#include "wireshark_application.h"

#include <epan/prefs-int.h>

#include "syntax_line_edit.h"
#include "qt_ui_utils.h"

#include <QTreeWidgetItemIterator>
#include <QFrame>
#include <QHBoxLayout>
#include <QSpacerItem>
#include <QLineEdit>
#include <QFileDialog>
#include <QColorDialog>
#include <QMessageBox>
#include <QPushButton>
#include <QKeyEvent>
#include <QDebug>

Q_DECLARE_METATYPE(pref_t *)

extern "C" {
// Callbacks prefs routines

static guint
fill_advanced_prefs(module_t *module, gpointer root_ptr)
{
    QTreeWidgetItem *root_item = static_cast<QTreeWidgetItem *>(root_ptr);

    if (!module || !root_item) return 1;

    if (module->numprefs < 1 && !prefs_module_has_submodules(module)) return 0;

    QString module_title = module->title;

    QTreeWidgetItem *tl_item = new QTreeWidgetItem(root_item);
    tl_item->setText(0, module_title);
    tl_item->setToolTip(0, QString("<span>%1</span>").arg(module->description));
    tl_item->setFirstColumnSpanned(true);

    QList<QTreeWidgetItem *>tl_children;
    for (GList *pref_l = module->prefs; pref_l && pref_l->data; pref_l = g_list_next(pref_l)) {
        pref_t *pref = (pref_t *) pref_l->data;

        if (pref->type == PREF_OBSOLETE || pref->type == PREF_STATIC_TEXT) continue;

        const char *type_name = prefs_pref_type_name(pref);
        if (!type_name) continue;

        QTreeWidgetItem *item = new QTreeWidgetItem();
        QString full_name = QString(module->name ? module->name : module->parent->name) + "." + pref->name;
        QString type_desc = gchar_free_to_qstring(prefs_pref_type_description(pref));
        QString default_value = gchar_free_to_qstring(prefs_pref_to_str(pref, true));

        item->setData(0, Qt::UserRole, qVariantFromValue(pref));
        item->setText(0, full_name);
        item->setToolTip(0, QString("<span>%1</span>").arg(pref->description));
        item->setText(2, type_name);
        item->setToolTip(2, QString("<span>%1</span>").arg(type_desc));
        item->setToolTip(3, QString("<span>%1</span>").arg(
                             default_value.isEmpty() ? default_value : "Default value is empty"));
        tl_children << item;
    }
    tl_item->addChildren(tl_children);

    if(prefs_module_has_submodules(module))
        return prefs_modules_foreach_submodules(module, fill_advanced_prefs, tl_item);

    return 0;
}

} // extern "C"

const int appearance_item_ = 0;
const int protocols_item_  = 4;
const int statistics_item_ = 5;
const int advanced_item_   = 6;

PreferencesDialog::PreferencesDialog(QWidget *parent) :
    QDialog(parent),
    pd_ui_(new Ui::PreferencesDialog),
    cur_line_edit_(NULL),
    cur_combo_box_(NULL)
{
    pd_ui_->setupUi(this);
    QTreeWidgetItem tmp_item; // Adding pre-populated top-level items is much faster

    prefs_modules_foreach_submodules(NULL, fill_advanced_prefs, (gpointer) &tmp_item);

    pd_ui_->advancedTree->invisibleRootItem()->addChildren(tmp_item.takeChildren());
    QTreeWidgetItemIterator pref_it(pd_ui_->advancedTree, QTreeWidgetItemIterator::NoChildren);
    while (*pref_it) {
//        pref_t *pref = (*pref_it)->data(0, Qt::UserRole).value<pref_t *>();
        updateItem(*(*pref_it));
//        if (pref) pref_item_hash_[pref] = (*pref_it);
        ++pref_it;
    }

    pd_ui_->splitter->setStretchFactor(0, 1);
    pd_ui_->splitter->setStretchFactor(1, 5);

    pd_ui_->prefsTree->invisibleRootItem()->child(appearance_item_)->setExpanded(true);
    pd_ui_->prefsTree->setCurrentItem(pd_ui_->prefsTree->invisibleRootItem()->child(advanced_item_));
}

PreferencesDialog::~PreferencesDialog()
{
    delete pd_ui_;
}

void PreferencesDialog::showEvent(QShowEvent *evt)
{
    Q_UNUSED(evt);
    QStyleOption style_opt;
    int new_prefs_tree_width =  pd_ui_->prefsTree->style()->subElementRect(QStyle::SE_TreeViewDisclosureItem, &style_opt).left();
    QList<int> sizes = pd_ui_->splitter->sizes();

    pd_ui_->prefsTree->resizeColumnToContents(0);
    new_prefs_tree_width += pd_ui_->prefsTree->columnWidth(0);
    sizes[1] += sizes[0] - new_prefs_tree_width;
    sizes[0] = new_prefs_tree_width;
    pd_ui_->splitter->setSizes(sizes);
    pd_ui_->splitter->setStretchFactor(0, 0);

    pd_ui_->advancedTree->expandAll();
    pd_ui_->advancedTree->setSortingEnabled(true);
    pd_ui_->advancedTree->sortByColumn(0, Qt::AscendingOrder);
    pd_ui_->advancedTree->setColumnWidth(0, pd_ui_->stackedWidget->width() / 2); // Don't let long items widen things too much
    pd_ui_->advancedTree->resizeColumnToContents(1);
    pd_ui_->advancedTree->resizeColumnToContents(2);
    pd_ui_->advancedTree->resizeColumnToContents(3);
}

void PreferencesDialog::keyPressEvent(QKeyEvent *evt)
{
    if (cur_line_edit_ && cur_line_edit_->hasFocus()) {
        switch (evt->key()) {
        case Qt::Key_Escape:
            cur_line_edit_->setText(saved_string_pref_);
        case Qt::Key_Enter:
        case Qt::Key_Return:
            switch (cur_pref_type_) {
            case PREF_UINT:
                uintPrefEditingFinished();
                break;
            case PREF_STRING:
                stringPrefEditingFinished();
                break;
            case PREF_RANGE:
                rangePrefEditingFinished();
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
        case Qt::Key_Enter:
        case Qt::Key_Return:
            // XXX The combo box eats enter and return
            enumPrefCurrentIndexChanged(cur_combo_box_->currentIndex());
            delete cur_combo_box_;
            return;
        default:
            break;
        }
    }
    QDialog::keyPressEvent(evt);
}

void PreferencesDialog::updateItem(QTreeWidgetItem &item)
{
    pref_t *pref = item.data(0, Qt::UserRole).value<pref_t *>();
    if (!pref) return;

    QString cur_value = gchar_free_to_qstring(prefs_pref_to_str(pref, false)).remove(QRegExp("\n\t"));
    bool is_changed = false;
    QFont font = item.font(0);

    if (pref->type == PREF_UAT) {
        item.setText(1, "Unknown");
    } else if (prefs_pref_is_default(pref)) {
        item.setText(1, "Default");
    } else {
        item.setText(1, "Changed");
        is_changed = true;
    }
    font.setBold(is_changed);
    item.setFont(0, font);
    item.setFont(0, font);
    item.setFont(1, font);
    item.setFont(2, font);
    item.setFont(3, font);

    item.setToolTip(1, "Has this value been changed?");
    item.setText(3, cur_value);
}

void PreferencesDialog::on_prefsTree_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    Q_UNUSED(previous)
    QString frame_name = current->text(0).remove(" ").toLower().append("Frame");
    QFrame *frame = pd_ui_->stackedWidget->findChild<QFrame *>(frame_name);
    if (frame) {
        pd_ui_->stackedWidget->setCurrentWidget(frame);
    }
}

void PreferencesDialog::on_advancedSearchLineEdit_textEdited(const QString &search_str)
{
    // Hide or show each branch
    QTreeWidgetItemIterator branch_it(pd_ui_->advancedTree);
    while (*branch_it) {
        if ((*branch_it)->data(0, Qt::UserRole).value<pref_t *>() == NULL) {
            (*branch_it)->setHidden(!search_str.isEmpty());
        }
        ++branch_it;
    }

    // Hide or show each item, showing its parents if needed
    QTreeWidgetItemIterator pref_it(pd_ui_->advancedTree);
    while (*pref_it) {
        bool hidden = true;

        if ((*pref_it)->data(0, Qt::UserRole).value<pref_t *>()) {
            QTreeWidgetItem *parent = (*pref_it)->parent();

            if (search_str.isEmpty() ||
                (*pref_it)->text(0).contains(search_str, Qt::CaseInsensitive) ||
                (*pref_it)->toolTip(0).contains(search_str, Qt::CaseInsensitive)) {
                hidden = false;
            }

            (*pref_it)->setHidden(hidden);
            if (!hidden) {
                while (parent) {
                    parent->setHidden(false);
                    parent = parent->parent();
                }
            }
        }
        ++pref_it;
    }
}

void PreferencesDialog::on_advancedTree_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    Q_UNUSED(current);

    if (previous && pd_ui_->advancedTree->itemWidget(previous, 3)) {
        pd_ui_->advancedTree->removeItemWidget(previous, 3);
    }
}

void PreferencesDialog::on_advancedTree_itemActivated(QTreeWidgetItem *item, int column)
{
    pref_t *pref = item->data(0, Qt::UserRole).value<pref_t *>();
    if (!pref || cur_line_edit_ || cur_combo_box_) return;

    if (column < 3) {
        reset_pref(pref);
        updateItem(*item);
    } else {
        QWidget *editor = NULL;

        switch (pref->type) {
        case PREF_UINT:
        {
            cur_line_edit_ = new QLineEdit();
//            cur_line_edit_->setInputMask("0000000009;");
            saved_string_pref_ = QString::number(*pref->varp.uint, pref->info.base);
            connect(cur_line_edit_, SIGNAL(editingFinished()), this, SLOT(uintPrefEditingFinished()));
            editor = cur_line_edit_;
            break;
        }
        case PREF_BOOL:
            *pref->varp.boolp = !*pref->varp.boolp;
            updateItem(*item);
            break;
        case PREF_ENUM:
        {
            cur_combo_box_ = new QComboBox();
            const enum_val_t *ev;
            for (ev = pref->info.enum_info.enumvals; ev && ev->description; ev++) {
                cur_combo_box_->addItem(ev->description, QVariant(ev->value));
                if (*pref->varp.enump == ev->value)
                    cur_combo_box_->setCurrentIndex(cur_combo_box_->count() - 1);
            }
            saved_combo_idx_ = cur_combo_box_->currentIndex();
            connect(cur_combo_box_, SIGNAL(currentIndexChanged(int)), this, SLOT(enumPrefCurrentIndexChanged(int)));
            editor = cur_combo_box_;
            break;
        }
        case PREF_STRING:
        {
            cur_line_edit_ = new QLineEdit();
            saved_string_pref_ = *pref->varp.string;
            connect(cur_line_edit_, SIGNAL(editingFinished()), this, SLOT(stringPrefEditingFinished()));
            editor = cur_line_edit_;
            break;
        }
        case PREF_FILENAME:
        {
            QString filename = QFileDialog::getSaveFileName(this,
                                                            QString("Wireshark: ") + pref->description,
                                                            *pref->varp.string);
            if (!filename.isEmpty()) {
                g_free((void *)*pref->varp.string);
                *pref->varp.string = g_strdup(filename.toUtf8().constData());
                updateItem(*item);
            }
            break;
        }
        case PREF_RANGE:
        {
            SyntaxLineEdit *syntax_edit = new SyntaxLineEdit();
            char *cur_val = prefs_pref_to_str(pref, FALSE);
            saved_string_pref_ = gchar_free_to_qstring(cur_val);
            connect(syntax_edit, SIGNAL(textChanged(QString)),
                    this, SLOT(rangePrefTextChanged(QString)));
            connect(syntax_edit, SIGNAL(editingFinished()), this, SLOT(rangePrefEditingFinished()));
            editor = cur_line_edit_ = syntax_edit;
            break;
        }
        case PREF_COLOR:
        {
            QColorDialog color_dlg;

            color_dlg.setCurrentColor(QColor(
                                          pref->varp.color->red >> 8,
                                          pref->varp.color->green >> 8,
                                          pref->varp.color->blue >> 8
                                          ));
            if (color_dlg.exec() == QDialog::Accepted) {
                QColor cc = color_dlg.currentColor();
                pref->varp.color->red = cc.red() << 8 | cc.red();
                pref->varp.color->green = cc.green() << 8 | cc.green();
                pref->varp.color->blue = cc.blue() << 8 | cc.blue();
                updateItem(*item);
            }
            break;
        }
        case PREF_UAT:
            qDebug() << "FIX open uat dialog" << item->text(column);
            break;
        default:
            break;
        }
        cur_pref_type_ = pref->type;
        if (cur_line_edit_) {
            cur_line_edit_->setText(saved_string_pref_);
            connect(cur_line_edit_, SIGNAL(destroyed()), this, SLOT(lineEditPrefDestroyed()));
        }
        if (cur_combo_box_) {
            connect(cur_combo_box_, SIGNAL(destroyed()), this, SLOT(enumPrefDestroyed()));
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
            item->setText(3, "");
            edit_frame->setLayout(hb);
            pd_ui_->advancedTree->setItemWidget(item, 3, edit_frame);
            editor->setFocus();
        }
    }
}

void PreferencesDialog::lineEditPrefDestroyed()
{
    cur_line_edit_ = NULL;
}

void PreferencesDialog::enumPrefDestroyed()
{
    cur_combo_box_ = NULL;
}

void PreferencesDialog::uintPrefEditingFinished()
{
    QTreeWidgetItem *item = pd_ui_->advancedTree->currentItem();
    if (!cur_line_edit_ || !item) return;

    pref_t *pref = item->data(0, Qt::UserRole).value<pref_t *>();
    if (!pref) return;

    *pref->varp.uint = cur_line_edit_->text().toUInt(NULL, pref->info.base);
    pd_ui_->advancedTree->removeItemWidget(item, 3);
    updateItem(*item);
}

void PreferencesDialog::enumPrefCurrentIndexChanged(int index)
{
    QTreeWidgetItem *item = pd_ui_->advancedTree->currentItem();
    if (!cur_combo_box_ || !item || index < 0) return;

    pref_t *pref = item->data(0, Qt::UserRole).value<pref_t *>();
    if (!pref) return;

    *pref->varp.enump = cur_combo_box_->itemData(index, Qt::UserRole).toInt();
//    pd_ui_->advancedTree->removeItemWidget(item, 3);
    updateItem(*item);
}

void PreferencesDialog::stringPrefEditingFinished()
{
    QTreeWidgetItem *item = pd_ui_->advancedTree->currentItem();
    if (!cur_line_edit_ || !item) return;

    pref_t *pref = item->data(0, Qt::UserRole).value<pref_t *>();
    if (!pref) return;

    g_free((void *)*pref->varp.string);
    *pref->varp.string = g_strdup(cur_line_edit_->text().toUtf8().constData());
    pd_ui_->advancedTree->removeItemWidget(item, 3);
    updateItem(*item);
}

void PreferencesDialog::rangePrefTextChanged(const QString &text)
{
    SyntaxLineEdit *syntax_edit = qobject_cast<SyntaxLineEdit *>(cur_line_edit_);
    QTreeWidgetItem *item = pd_ui_->advancedTree->currentItem();
    if (!syntax_edit || !item) return;

    pref_t *pref = item->data(0, Qt::UserRole).value<pref_t *>();
    if (!pref) return;

    if (text.isEmpty()) {
        syntax_edit->setSyntaxState(SyntaxLineEdit::Empty);
    } else {
        range_t *newrange;
        convert_ret_t ret = range_convert_str(&newrange, text.toUtf8().constData(), pref->info.max_value);

        if (ret == CVT_NO_ERROR) {
            syntax_edit->setSyntaxState(SyntaxLineEdit::Valid);
            g_free(newrange);
        } else {
            syntax_edit->setSyntaxState(SyntaxLineEdit::Invalid);
        }
    }
}

void PreferencesDialog::rangePrefEditingFinished()
{
    SyntaxLineEdit *syntax_edit = qobject_cast<SyntaxLineEdit *>(QObject::sender());
    QTreeWidgetItem *item = pd_ui_->advancedTree->currentItem();
    if (!syntax_edit || !item) return;

    pref_t *pref = item->data(0, Qt::UserRole).value<pref_t *>();
    if (!pref) return;

    range_t *newrange;
    convert_ret_t ret = range_convert_str(&newrange, syntax_edit->text().toUtf8().constData(), pref->info.max_value);

    if (ret == CVT_NO_ERROR) {
        g_free(*pref->varp.range);
        *pref->varp.range = newrange;
    }
    pd_ui_->advancedTree->removeItemWidget(item, 3);
    updateItem(*item);
}

void PreferencesDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_PREFERENCES_DIALOG);
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
