/** @file
 *
 * Delegate to select a numeric value for a treeview entry
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef NUMERIC_VALUE_CHOOSER_DELEGATE_H_
#define NUMERIC_VALUE_CHOOSER_DELEGATE_H_


#include <QStyledItemDelegate>

/**
 * @brief A delegate for choosing numeric values within a specified range in item views.
 */
class NumericValueChooserDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new NumericValueChooserDelegate object.
     * @param min The minimum allowed value.
     * @param max The maximum allowed value.
     * @param parent The parent object.
     */
    NumericValueChooserDelegate(int min = 0, int max = 0, QObject *parent = 0);

    /**
     * @brief Destroys the NumericValueChooserDelegate object.
     */
    ~NumericValueChooserDelegate();

    /**
     * @brief Sets the minimum and maximum allowed range for the chooser.
     * @param min The minimum value.
     * @param max The maximum value.
     */
    void setMinMaxRange(int min, int max);

    /**
     * @brief Sets the default value and the default return variant.
     * @param defValue The default numeric value.
     * @param defaultReturn The default variant to return.
     */
    void setDefaultValue(int defValue, QVariant defaultReturn);

protected:
    /**
     * @brief Creates the editor widget for the item.
     * @param parent The parent widget.
     * @param option The style option for the item.
     * @param index The model index of the item being edited.
     * @return A pointer to the created editor widget.
     */
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const;

    /**
     * @brief Sets the data to be displayed in the editor widget.
     * @param editor The editor widget.
     * @param index The model index of the item being edited.
     */
    void setEditorData(QWidget *editor, const QModelIndex &index) const;

    /**
     * @brief Saves the data from the editor widget back into the model.
     * @param editor The editor widget.
     * @param model The data model.
     * @param index The model index of the item being edited.
     */
    void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index) const;

private:
    /** @brief The minimum allowed value. */
    int _min;

    /** @brief The maximum allowed value. */
    int _max;

    /** @brief The default numeric value. */
    int _default;

    /** @brief The default variant to return. */
    QVariant _defReturn;

private slots:
    /**
     * @brief Handles the event when the numeric value changes in the editor.
     * @param i The new numeric value.
     */
    void onValueChanged(int i);
};

#endif /* NUMERIC_VALUE_CHOOSER_DELEGATE_H_ */
