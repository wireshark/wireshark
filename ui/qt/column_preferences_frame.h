/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COLUMN_PREFERENCES_FRAME_H
#define COLUMN_PREFERENCES_FRAME_H

#include <ui/qt/models/column_list_model.h>

#include <QFrame>
#include <QItemSelection>

namespace Ui {
class ColumnPreferencesFrame;
}

/**
 * @brief A frame for configuring packet list column preferences.
 */
class ColumnPreferencesFrame : public QFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ColumnPreferencesFrame.
     * @param parent The parent widget, defaults to Q_NULLPTR.
     */
    explicit ColumnPreferencesFrame(QWidget *parent = Q_NULLPTR);

    /**
     * @brief Destroys the ColumnPreferencesFrame.
     */
    ~ColumnPreferencesFrame();

    /**
     * @brief Restores any previously stashed column preference state.
     */
    void unstash();

private:
    /** Pointer to the generated UI elements. */
    Ui::ColumnPreferencesFrame *ui;

    /** Model containing the editable list of columns. */
    ColumnListModel * model_;

    /** Proxy model used to filter and present the column list. */
    ColumnProxyModel * proxyModel_;

    /** Delegate used to edit column type-related fields. */
    ColumnTypeDelegate * delegate_;

private slots:
    /**
     * @brief Updates the frame state when the selection changes.
     * @param selected The newly selected items.
     * @param deselected The newly deselected items.
     */
    void selectionChanged(const QItemSelection &selected, const QItemSelection &deselected);

    /**
     * @brief Adds a new column entry.
     */
    void on_newToolButton_clicked();

    /**
     * @brief Deletes the currently selected column entry.
     */
    void on_deleteToolButton_clicked();

    /**
     * @brief Updates the displayed-only filter state.
     */
    void on_chkShowDisplayedOnly_stateChanged(int);

    /**
     * @brief Shows the context menu for the column tree view.
     * @param pos The position within the tree view where the menu was requested.
     */
    void on_columnTreeView_customContextMenuRequested(const QPoint &pos);

    /**
     * @brief Resets the column preferences.
     * @param checked The checked state associated with the triggering action, defaults to false.
     */
    void resetAction(bool checked = false);
};

#endif // COLUMN_PREFERENCES_FRAME_H
