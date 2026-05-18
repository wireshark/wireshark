/** @file
 *
 * Delegates for editing various field types in a UAT record.
 *
 * Copyright 2016 Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UAT_DELEGATE_H
#define UAT_DELEGATE_H

#include <config.h>
#include <epan/uat.h>

#include <QStyledItemDelegate>
#include <QModelIndex>

/**
 * @brief A delegate for rendering and editing fields in User Accessible Tables (UAT).
 */
class UatDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new UatDelegate object.
     * @param parent The parent object.
     */
    UatDelegate(QObject *parent = 0);

    /**
     * @brief Creates the editor widget for the specified item.
     * @param parent The parent widget.
     * @param option The style option for the item.
     * @param index The model index of the item being edited.
     * @return A pointer to the created editor widget.
     */
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const override;

    /**
     * @brief Sets the data to be displayed in the editor widget.
     * @param editor The editor widget.
     * @param index The model index of the item being edited.
     */
    void setEditorData(QWidget *editor, const QModelIndex &index) const override;

    /**
     * @brief Saves the data from the editor widget back into the model.
     * @param editor The editor widget.
     * @param model The data model.
     * @param index The model index of the item being edited.
     */
    void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index) const override;

    /**
     * @brief Updates the geometry of the editor widget based on the style option.
     * @param editor The editor widget.
     * @param option The style option for the item.
     * @param index The model index of the item being edited.
     */
    void updateEditorGeometry(QWidget *editor, const QStyleOptionViewItem &option, const QModelIndex &index) const override;

protected slots:
    /**
     * @brief Handles the event when a file or directory path has changed.
     * @param newPath The newly selected path string.
     */
    void pathHasChanged(QString newPath);

private:
    /**
     * @brief Retrieves the UAT field structure associated with a specific model index.
     * @param index The model index.
     * @return A pointer to the underlying uat_field_t structure.
     */
    uat_field_t *indexToField(const QModelIndex &index) const;
};
#endif // UAT_DELEGATE_H
