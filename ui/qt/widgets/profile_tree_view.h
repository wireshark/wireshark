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
#include <QPersistentModelIndex>
#include <QPixmap>
#include <QPoint>

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
     * @brief Selects the row of @p idx in the view.
     * @param idx Index of the row to select.
     */
    void selectIndex(const QModelIndex &idx);

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

    /**
     * @brief Starts dragging the selected profile names, with the same drag
     *        image on all platforms.
     */
    virtual void startDrag(Qt::DropActions supportedActions) override;

    /**
     * @brief Highlights the profile where a dragged profile will be moved to,
     *        and all its parents.
     */
    virtual void dragMoveEvent(QDragMoveEvent *event) override;
    virtual void dragLeaveEvent(QDragLeaveEvent *event) override;
    virtual void dropEvent(QDropEvent *event) override;
    virtual void drawRow(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;
    virtual void paintEvent(QPaintEvent *event) override;

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
    QList<QPersistentModelIndex> drop_path_; /**< Drop target and its parents while dragging. */
    QPixmap drag_pixmap_; /**< Image of the dragged profile names, if the platform shows none. */
    QPoint drag_offset_; /**< Cursor position inside the drag image. */
    QPoint drag_pos_ = QPoint(-1, -1); /**< Cursor position in the viewport while dragging. */
    bool drop_top_level_ = false; /**< @c true while a drop would move the profile to the top level. */

    /**
     * @brief Sets the highlighted drop target and its parents.
     * @param target The drop target, or an invalid index for the top level.
     * @param topLevel @c true if the profile would be moved to the top level.
     */
    void setDropPath(const QModelIndex &target, bool topLevel = false);
};

#endif
