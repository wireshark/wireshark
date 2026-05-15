/** @file
 *
 * Delegate to select a file path for a treeview entry
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PATH_SELECTION_DELEGATE_H_
#define PATH_SELECTION_DELEGATE_H_

#include <QStyledItemDelegate>

/**
 * @brief A delegate for selecting and editing file or directory paths in a view.
 */
class PathSelectionDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new PathSelectionDelegate.
     * @param parent The parent object, defaults to 0.
     */
    PathSelectionDelegate(QObject *parent = 0);

protected:
    /**
     * @brief Creates the custom editor widget for path selection.
     * @param parent The parent widget for the editor.
     * @param option The style option for the item.
     * @param idx The model index of the item being edited.
     * @return A pointer to the created editor widget.
     */
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &idx) const override;

    /**
     * @brief Updates the geometry of the editor to fit the item.
     * @param editor The editor widget to update.
     * @param option The style option containing the geometry information.
     * @param idx The model index of the item being edited.
     */
    void updateEditorGeometry (QWidget * editor, const QStyleOptionViewItem & option, const QModelIndex & idx) const override;

    /**
     * @brief Sets the data to be displayed in the editor.
     * @param editor The editor widget.
     * @param idx The model index containing the data to set.
     */
    void setEditorData(QWidget *editor, const QModelIndex &idx) const override;

    /**
     * @brief Saves the data from the editor back into the model.
     * @param editor The editor widget containing the updated data.
     * @param model The model to update.
     * @param idx The model index of the item being edited.
     */
    void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &idx) const override;

protected slots:
    /**
     * @brief Slot triggered when the selected path changes in the editor.
     * @param newPath The newly selected path.
     */
    void pathHasChanged(QString newPath);
};

#endif /* PATH_SELECTION_DELEGATE_H_ */
