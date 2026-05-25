/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROFILE_TREEVIEW_H
#define PROFILE_TREEVIEW_H

#include <ui/qt/models/url_link_delegate.h>

#include <QTreeView>
#include <QItemDelegate>

/**
 * @brief Item delegate that provides inline editing for profile name cells
 *        in the profile tree view.
 */
class ProfileTreeEditDelegate : public QItemDelegate
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a ProfileTreeEditDelegate.
     * @param parent Optional parent widget.
     */
    ProfileTreeEditDelegate(QWidget *parent = Q_NULLPTR);

    /**
     * @brief Creates and returns an editor widget for the cell at @p index.
     * @param parent  Parent widget for the created editor.
     * @param option  Style options for the cell.
     * @param index   Model index of the cell being edited.
     * @return Pointer to the newly created editor widget.
     */
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const override;

    /**
     * @brief Populates the editor widget with the current value from the model.
     * @param editor Editor widget previously returned by createEditor().
     * @param index  Model index of the cell being edited.
     */
    virtual void setEditorData(QWidget *editor, const QModelIndex &index) const override;

private:
    QWidget     *editor_; /**< Pointer to the currently active editor widget, or @c nullptr if none. */
    QModelIndex  index_;  /**< Model index of the cell currently being edited. */
};


/**
 * @brief Tree view specialised for displaying and editing configuration profiles,
 *        with inline editing support and selection-change notifications.
 */
class ProfileTreeView : public QTreeView
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a ProfileTreeView.
     * @param parent Optional parent widget.
     */
    ProfileTreeView(QWidget *parent = nullptr);

    /**
     * @brief Destroys the view and releases the associated delegate.
     */
    ~ProfileTreeView();

    /**
     * @brief Selects the row at @p row in the view, scrolling it into view if necessary.
     * @param row Zero-based row index to select.
     */
    void selectRow(int row);

    /**
     * @brief Returns whether an inline edit is currently active in the view.
     * @return @c true if a cell editor is open.
     */
    bool activeEdit();

signals:
    /**
     * @brief Emitted when a profile item has been modified through the inline editor.
     */
    void itemUpdated();

protected:
    /**
     * @brief Restores the previously selected row when the view becomes visible.
     */
    virtual void showEvent(QShowEvent *) override;

    /**
     * @brief Opens an inline editor for the double-clicked cell when the profile
     *        is editable; otherwise propagates the event.
     * @param event The mouse double-click event.
     */
    virtual void mouseDoubleClickEvent(QMouseEvent *event) override;

protected slots:
    /**
     * @brief Responds to selection changes, updating UI state and emitting
     *        @c itemUpdated() when appropriate.
     * @param selected   Newly selected items.
     * @param deselected Previously selected items that are now deselected.
     */
    virtual void selectionChanged(const QItemSelection &selected, const QItemSelection &deselected) override;

private:
    ProfileTreeEditDelegate *delegate_; /**< Delegate providing inline editing for profile name cells. */
};

#endif
