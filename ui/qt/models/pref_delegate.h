/** @file
 *
 * Delegates for editing preferences.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PREF_DELEGATE_H
#define PREF_DELEGATE_H

#include <config.h>

#include <ui/qt/models/pref_models.h>

#include <QStyledItemDelegate>
#include <QModelIndex>

/**
 * @brief Item delegate providing in-place editors for the Advanced Preferences table.
 */
class AdvancedPrefDelegate : public QStyledItemDelegate
{
public:
    /**
     * @brief Construct an AdvancedPrefDelegate.
     * @param parent The parent QObject.
     */
    AdvancedPrefDelegate(QObject *parent = 0);

    /**
     * @brief Create an editor widget appropriate for the preference at @p index.
     *
     * @param parent  The parent widget for the editor.
     * @param option  Style options for the editor's geometry.
     * @param index   The model index of the cell being edited.
     * @return The editor widget; ownership is transferred to the view.
     */
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const;

    /**
     * @brief Populate the editor with the current preference value.
     *
     * @param editor The editor widget returned by createEditor().
     * @param index  The model index whose data should be loaded into the editor.
     */
    void setEditorData(QWidget *editor, const QModelIndex &index) const;

    /**
     * @brief Write the editor's current value back to the model.
     *
     * @param editor The editor widget whose value should be committed.
     * @param model  The model to update.
     * @param index  The model index to write to.
     */
    void setModelData(QWidget *editor, QAbstractItemModel *model,
                      const QModelIndex &index) const;

private:
    /**
     * @brief Return the PrefsItem for the given model index.
     *
     * @param index The model index to look up.
     * @return The PrefsItem for @p index, or nullptr if unavailable.
     */
    PrefsItem *indexToPref(const QModelIndex &index) const;
};

#endif // PREF_DELEGATE_H
