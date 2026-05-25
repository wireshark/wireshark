/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DRAG_DROP_TOOLBAR_H
#define DRAG_DROP_TOOLBAR_H

#include <QToolBar>
#include <QPoint>

class WiresharkMimeData;

/**
 * @brief A customized QToolBar that supports drag-and-drop reordering of its actions and handling external drops.
 */
class DragDropToolBar : public QToolBar
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new DragDropToolBar with a specific title.
     * @param title The title of the toolbar.
     * @param parent The parent widget, defaults to Q_NULLPTR.
     */
    explicit DragDropToolBar(const QString &title, QWidget *parent = Q_NULLPTR);

    /**
     * @brief Constructs a new DragDropToolBar.
     * @param parent The parent widget, defaults to Q_NULLPTR.
     */
    explicit DragDropToolBar(QWidget *parent = Q_NULLPTR);

    /**
     * @brief Destroys the DragDropToolBar.
     */
    ~DragDropToolBar();

    /**
     * @brief Clears all actions from the toolbar.
     */
    virtual void clear();

signals:
    /**
     * @brief Signal emitted when an action has been moved via drag and drop.
     * @param action Pointer to the moved QAction.
     * @param oldPos The original index position of the action.
     * @param newPos The new index position of the action.
     */
    void actionMoved(QAction * action, int oldPos, int newPos);

    /**
     * @brief Signal emitted when a new filter is dropped onto the toolbar.
     * @param description The description of the dropped filter.
     * @param filter The filter string itself.
     */
    void newFilterDropped(QString description, QString filter);

protected:

    /**
     * @brief Creates MIME data for a specific toolbar item to support drag operations.
     * @param name The name or description of the item.
     * @param position The current position index of the item.
     * @return A pointer to the created WiresharkMimeData.
     */
    virtual WiresharkMimeData * createMimeData(QString name, int position);

    /**
     * @brief Handles child events, such as when widgets are added or removed.
     * @param event The child event details.
     */
    virtual void childEvent(QChildEvent * event) override;

    /**
     * @brief Event filter used to intercept mouse events on toolbar child widgets for drag detection.
     * @param obj The object receiving the event.
     * @param ev The event being intercepted.
     * @return True if the event was filtered out, false otherwise.
     */
    virtual bool eventFilter(QObject * obj, QEvent * ev) override;

    /**
     * @brief Handles drag enter events to accept valid drop targets.
     * @param event The drag enter event details.
     */
    virtual void dragEnterEvent(QDragEnterEvent *event) override;

    /**
     * @brief Handles drag move events for visual feedback during drag operations.
     * @param event The drag move event details.
     */
    virtual void dragMoveEvent(QDragMoveEvent *event) override;

    /**
     * @brief Handles drop events to finalize reordering or add new items.
     * @param event The drop event details.
     */
    virtual void dropEvent(QDropEvent *event) override;

private:

    /** The point where a drag operation originated. */
    QPoint dragStartPosition;

    /** Internal counter tracking the number of child widgets for positioning logic. */
    int childCounter;

    /**
     * @brief Initializes the toolbar's configuration for drag and drop behavior.
     */
    void setupToolbar();

    /**
     * @brief Adjusts the internal order of toolbar items following a drag and drop operation.
     * @param fromPos The original index position.
     * @param toPos The target index position.
     */
    void moveToolbarItems(int fromPos, int toPos);

};

#endif // DRAG_DROP_TOOLBAR_H
