/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/drag_drop_toolbar.h>

#include <QMenu>

#ifndef FILTER_EXPRESSION_TOOLBAR_H
#define FILTER_EXPRESSION_TOOLBAR_H

/**
 * @brief A toolbar that displays filter expressions and supports drag-and-drop operations.
 */
class FilterExpressionToolBar : public DragDropToolBar
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new FilterExpressionToolBar.
     * @param parent The parent widget, defaults to Q_NULLPTR.
     */
    explicit FilterExpressionToolBar(QWidget * parent = Q_NULLPTR);

protected:
    /**
     * @brief Handles events directed to the toolbar.
     * @param event The event to process.
     * @return True if the event was handled, false otherwise.
     */
    virtual bool event(QEvent *event) override;

    /**
     * @brief Filters events for watched objects.
     * @param obj The object being filtered.
     * @param ev The event to filter.
     * @return True if the event is filtered out, false otherwise.
     */
    virtual bool eventFilter(QObject *obj, QEvent *ev) override;

    /**
     * @brief Creates MIME data representing a dragged filter expression.
     * @param name The name of the dragged item.
     * @param position The position index of the item.
     * @return A pointer to the created WiresharkMimeData.
     */
    virtual WiresharkMimeData * createMimeData(QString name, int position) override;

public slots:
    /**
     * @brief Slot triggered when the underlying list of filter expressions changes.
     */
    void filterExpressionsChanged();

signals:
    /**
     * @brief Signal emitted when a filter expression is selected.
     * @param filter The filter expression string.
     * @param apply True to apply the filter immediately, false to just prepare it.
     */
    void filterSelected(QString filter, bool apply);

    /**
     * @brief Signal emitted to open the filter preferences dialog.
     */
    void filterPreferences();

    /**
     * @brief Signal emitted to edit a filter expression at a specific index.
     * @param uatIndex The UAT row index of the filter expression.
     */
    void filterEdit(int uatIndex);

protected slots:
    /**
     * @brief Handles custom context menu requests on the toolbar.
     * @param pos The position where the context menu was requested.
     */
    void onCustomMenuHandler(const QPoint &pos);

    /**
     * @brief Slot triggered when an action is dragged and moved within the toolbar.
     * @param action The action that was moved.
     * @param oldPos The previous position index.
     * @param newPos The new position index.
     */
    void onActionMoved(QAction * action, int oldPos, int newPos);

    /**
     * @brief Slot triggered when a filter is dropped onto the toolbar.
     * @param description The label/description of the dropped filter.
     * @param filter The filter expression string.
     */
    void onFilterDropped(QString description, QString filter);

private slots:
    /**
     * @brief Slot triggered to remove a filter expression.
     */
    void removeFilter();

    /**
     * @brief Slot triggered to disable a filter expression.
     */
    void disableFilter();

    /**
     * @brief Slot triggered to edit a filter expression.
     */
    void editFilter();

    /**
     * @brief Slot triggered when a filter button is clicked.
     */
    void filterClicked();

    /**
     * @brief Slot triggered to show the toolbar preferences.
     */
    void toolBarShowPreferences();

    /**
     * @brief Slot triggered to close an open menu.
     */
    void closeMenu(QAction *);

private:
    /**
     * @brief Updates the stylesheet of the toolbar to match current preferences or themes.
     */
    void updateStyleSheet();

    /**
     * @brief Finds the UAT row index for a given filter label and expression.
     * @param label The label of the filter.
     * @param expression The expression string of the filter.
     * @return The UAT row index, or a negative value if not found.
     */
    int uatRowIndexForFilter(QString label, QString expression);

    /**
     * @brief Constructs and displays a custom context menu for a filter action.
     * @param target The target widget.
     * @param filterAction The action representing the filter expression.
     * @param pos The position to show the menu.
     */
    void customMenu(QWidget* target, QAction * filterAction, const QPoint& pos);

    /**
     * @brief Static callback used to iterate over and add filter expression actions.
     * @param key The key pointer from the hash table.
     * @param value The value pointer from the hash table.
     * @param user_data User-defined data pointer passed to the callback.
     * @return True to continue iteration, false to stop.
     */
    static bool filter_expression_add_action(const void *key, void *value, void *user_data);

    /**
     * @brief Finds or creates the appropriate parent menu based on a hierarchical tree path.
     * @param tree The list of string path components for the menu hierarchy.
     * @param fed_data Pointer to the filter expression data.
     * @param parent The root parent menu to search from, defaults to Q_NULLPTR.
     * @return A pointer to the found or newly created QMenu.
     */
    static QMenu * findParentMenu(const QStringList tree, void *fed_data, QMenu *parent = Q_NULLPTR);
};

#endif //FILTER_EXPRESSION_TOOLBAR_H
