/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LIST_EDIT_BUTTONS_H
#define LIST_EDIT_BUTTONS_H

#include <config.h>

#include <ui/qt/utils/inherit_selection.h>

#include <QList>
#include <QModelIndexList>
#include <QSet>
#include <QString>
#include <QToolButton>
#include <QWidget>

#include <algorithm>
#include <functional>

/**
 * @brief The row of buttons editing a list: new, delete, copy, move up, move down and clear.
 *
 * The buttons are enabled for the selection of the list, which may show
 * entries inherited from parent profiles. A disabled button tells why in
 * its tool tip, so that nobody is left wondering.
 */
class ListEditButtons : public QWidget
{
    Q_OBJECT

    /** Whether the buttons moving entries are shown. */
    Q_PROPERTY(bool moveButtonsVisible READ moveButtonsVisible WRITE setMoveButtonsVisible)
    /** Whether only a single entry can be copied. */
    Q_PROPERTY(bool copyNeedsSingleSelection READ copyNeedsSingleSelection WRITE setCopyNeedsSingleSelection)

public:
    /** @brief The tool tips of the buttons, describing what they do to the entries of the list. */
    struct ToolTips {
        QString add;        /**< E.g. "Add a new graph." */
        QString remove;     /**< E.g. "Remove the selected graphs." */
        QString copy;       /**< E.g. "Duplicate the selected graphs." */
        QString moveUp;     /**< E.g. "Move the selected graphs upwards." */
        QString moveDown;   /**< E.g. "Move the selected graphs downwards." */
        QString clear;      /**< E.g. "Clear all graphs." */
    };

    /**
     * @brief Constructs the buttons.
     * @param parent The parent widget.
     */
    explicit ListEditButtons(QWidget *parent = nullptr);

    /** @brief The button adding an entry. */
    QToolButton *newButton() const { return new_button_; }
    /** @brief The button deleting the selected entries. */
    QToolButton *deleteButton() const { return delete_button_; }
    /** @brief The button copying the selected entries. */
    QToolButton *copyButton() const { return copy_button_; }
    /** @brief The button moving the selected entries up. */
    QToolButton *moveUpButton() const { return move_up_button_; }
    /** @brief The button moving the selected entries down. */
    QToolButton *moveDownButton() const { return move_down_button_; }
    /** @brief The button clearing the entries. */
    QToolButton *clearButton() const { return clear_button_; }

    bool moveButtonsVisible() const { return move_visible_; }
    void setMoveButtonsVisible(bool visible);
    bool copyNeedsSingleSelection() const { return copy_single_; }
    void setCopyNeedsSingleSelection(bool single) { copy_single_ = single; }

    /**
     * @brief Sets what the buttons do, shown as their tool tips.
     * @param tool_tips The tool tips.
     */
    void setToolTips(const ToolTips &tool_tips);

    /**
     * @brief Enables the buttons for the selection.
     *
     * Inherited entries can be copied into the own entries, but not changed.
     * The own entries are not used with the parent's entries only.
     * @param sel What the selection allows.
     */
    void setSelection(const InheritSelection &sel);

signals:
    void newClicked();
    void deleteClicked();
    void copyClicked();
    void moveUpClicked();
    void moveDownClicked();
    void clearClicked();

private:
    QToolButton *makeButton(const char *icon);
    void updateToolTip(QToolButton *button, const QString &base, const QString &reason);

    QToolButton *new_button_;
    QToolButton *delete_button_;
    QToolButton *copy_button_;
    QToolButton *move_up_button_;
    QToolButton *move_down_button_;
    QToolButton *clear_button_;
    bool move_visible_;
    bool copy_single_;
    ToolTips tool_tips_;
};

/**
 * @brief The rows of indexes, the last row first.
 *
 * Removing the rows one by one in this order keeps the numbers of the rows
 * still to remove.
 * @param indexes The indexes, which may hold several columns of a row.
 * @return The distinct rows, in descending order.
 */
inline QList<int> rowsLastFirst(const QModelIndexList &indexes)
{
    QSet<int> unique;
    for (const QModelIndex &index : indexes)
        unique.insert(index.row());
    QList<int> rows(unique.begin(), unique.end());
    std::sort(rows.begin(), rows.end(), std::greater<int>());
    return rows;
}

#endif // LIST_EDIT_BUTTONS_H
