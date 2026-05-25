/** @file
 *
 * Delegates for editing various coloring rule fields.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COLORING_RULE_DELEGATE_H
#define COLORING_RULE_DELEGATE_H

#include <config.h>

#include <QStyledItemDelegate>
#include <QModelIndex>

/**
 * @brief A delegate for rendering and editing coloring rules in a view.
 */
class ColoringRulesDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ColoringRulesDelegate.
     * @param parent The parent QObject, defaults to 0.
     */
    ColoringRulesDelegate(QObject *parent = 0);

    /**
     * @brief Creates an editor widget for editing a coloring rule.
     * @param parent The parent widget.
     * @param option The style options for the item.
     * @param index The model index of the item being edited.
     * @return A pointer to the created editor widget.
     */
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override;

    /**
     * @brief Paints the coloring rule item.
     * @param painter The painter used to render the item.
     * @param option The style options for the item.
     * @param index The model index of the item to paint.
     */
    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override;

    /**
     * @brief Sets the data for the editor from the model.
     * @param editor The editor widget.
     * @param index The model index containing the data.
     */
    void setEditorData(QWidget *editor, const QModelIndex &index) const override;

    /**
     * @brief Sets the data in the model from the editor.
     * @param editor The editor widget containing the modified data.
     * @param model The abstract item model to update.
     * @param index The model index to update.
     */
    void setModelData(QWidget *editor, QAbstractItemModel *model,
                      const QModelIndex &index) const override;

    /**
     * @brief Updates the geometry of the editor.
     * @param editor The editor widget.
     * @param option The style options indicating the available space.
     * @param index The model index being edited.
     */
    void updateEditorGeometry(QWidget *editor,
            const QStyleOptionViewItem &option, const QModelIndex &index) const override;

signals:
    /**
     * @brief Signal emitted when a field contains invalid data.
     * @param index The model index of the invalid field.
     * @param errMessage The error message describing the invalidity.
     */
    void invalidField(const QModelIndex &index, const QString& errMessage) const;

    /**
     * @brief Signal emitted when a field contains valid data.
     * @param index The model index of the valid field.
     */
    void validField(const QModelIndex &index) const;

private slots:
    /**
     * @brief Slot triggered when the rule name changes in the editor.
     * @param name The new rule name.
     */
    void ruleNameChanged(const QString name);
};
#endif // COLORING_RULE_DELEGATE_H
