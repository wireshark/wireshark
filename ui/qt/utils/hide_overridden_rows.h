/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HIDE_OVERRIDDEN_ROWS_H
#define HIDE_OVERRIDDEN_ROWS_H

#include <QAbstractItemModel>
#include <QBoxLayout>
#include <QCheckBox>
#include <QCoreApplication>
#include <QItemSelectionModel>
#include <QTreeView>

/**
 * @brief Lets a check box hide the rules that are not used.
 *
 * A rule is not used when its own check box is unchecked, or, for a rule
 * inherited from a parent profile, when a rule of the profile overrides it.
 * The check box is shown only while such rules are there, and its state is
 * not stored.
 *
 * The rows are hidden in the view, not removed from the model, so the row
 * numbers of the model stay as they are.
 * @param view The view showing the rules.
 * @param model A model with isOverridden(row), the model of the view.
 * @param check_box The check box; the connections end with it.
 * @param check_column The column with the check box enabling a rule, or -1 for none.
 */
template <typename Model>
void hideOverriddenRows(QTreeView *view, Model *model, QCheckBox *check_box, int check_column = 0)
{
    auto not_used = [view, model, check_column](int row) {
        // An own row being edited or just changed stays where it is; an
        // inherited row, which is never edited, is hidden even if it is the
        // current row, e.g. after it was copied
        if (view->currentIndex().row() == row && !model->isInherited(row))
            return false;
        if (model->isOverridden(row))
            return true;
        if (check_column < 0)
            return false;
        // Rows without a check box have no check state
        QVariant check_state = model->index(row, check_column).data(Qt::CheckStateRole);
        return check_state.isValid() && check_state.toInt() == Qt::Unchecked;
    };

    auto update = [view, model, check_box, not_used]() {
        bool any = false;
        for (int row = 0; row < model->rowCount() && !any; row++)
            any = not_used(row);
        check_box->setVisible(any);
        bool hide = any && check_box->isChecked();

        for (int row = 0; row < model->rowCount(); row++) {
            bool hidden = hide && not_used(row);
            if (view->isRowHidden(row, QModelIndex()) != hidden)
                view->setRowHidden(row, QModelIndex(), hidden);
            // A hidden row must not be acted on
            if (hidden && view->selectionModel()) {
                view->selectionModel()->select(model->index(row, 0),
                                               QItemSelectionModel::Deselect | QItemSelectionModel::Rows);
            }
        }
    };

    QObject::connect(check_box, &QCheckBox::toggled, check_box, update);
    QObject::connect(model, &QAbstractItemModel::rowsInserted, check_box, update);
    QObject::connect(model, &QAbstractItemModel::rowsRemoved, check_box, update);
    QObject::connect(model, &QAbstractItemModel::rowsMoved, check_box, update);
    QObject::connect(model, &QAbstractItemModel::dataChanged, check_box, update);
    QObject::connect(model, &QAbstractItemModel::modelReset, check_box, update);
    if (view->selectionModel()) {
        // The row left becomes hidden if it is not used
        QObject::connect(view->selectionModel(), &QItemSelectionModel::currentChanged, check_box, update);
    }
    update();
}

/**
 * @brief Removes the own rules shown in the view, not those hidden in it.
 *
 * Inherited rules are not removed.
 * @param view The view showing the rules.
 * @param model A model with ownRowCount() and removeRows().
 */
template <typename Model>
void removeVisibleOwnRows(QTreeView *view, Model *model)
{
    for (int row = model->ownRowCount() - 1; row >= 0; row--) {
        if (!view->isRowHidden(row, QModelIndex()))
            model->removeRows(row, 1);
    }
}

/**
 * @brief Adds a "Hide unused" check box after a widget and lets it hide the rules not used.
 *
 * See hideOverriddenRows().
 * @param parent The parent of the check box.
 * @param layout The layout holding the widget the check box follows.
 * @param after The widget the check box follows, in the layout and the tab order.
 * @param view The view showing the rules.
 * @param model A model with isOverridden(row), the model of the view.
 * @param check_column The column with the check box enabling a rule, or -1 for none.
 * @return The check box.
 */
template <typename Model>
QCheckBox *addHideNotUsedCheckBox(QWidget *parent, QBoxLayout *layout, QWidget *after,
                                  QTreeView *view, Model *model, int check_column = 0)
{
    QCheckBox *check_box = new QCheckBox(QCoreApplication::translate("HideOverriddenRows", "Hide unused"), parent);
    // Only mention unchecked entries if an entry can be unchecked
    check_box->setToolTip(check_column >= 0 ?
        QCoreApplication::translate("HideOverriddenRows",
            "Hide the entries that are not used: the unchecked entries, and the inherited entries that an entry of this profile overrides.") :
        QCoreApplication::translate("HideOverriddenRows",
            "Hide the inherited entries that are not used because an entry of this profile overrides them."));
    layout->insertWidget(layout->indexOf(after) + 1, check_box);
    QWidget::setTabOrder(after, check_box);
    hideOverriddenRows(view, model, check_box, check_column);
    return check_box;
}

#endif // HIDE_OVERRIDDEN_ROWS_H
