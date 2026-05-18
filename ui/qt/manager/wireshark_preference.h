/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WIRESHARK_PREFERENCE_H
#define WIRESHARK_PREFERENCE_H

#include <ui/qt/models/pref_models.h>

#include <QStyleOptionViewItem>
#include <QModelIndex>
#include <QWidget>

/**
 * @brief Base class for preference editor delegates used in the preferences tree view.
 *
 * Subclasses implement editor(), setData(), and setModelData() to provide
 * type-specific inline editors (e.g. spin boxes, combo boxes, colour pickers)
 * for each preference type.
 */
class WiresharkPreference : public QObject
{
public:
    /**
     * @brief Constructs a WiresharkPreference with no associated PrefsItem.
     * @param parent Optional parent QObject.
     */
    explicit Q_INVOKABLE WiresharkPreference(QObject *parent = Q_NULLPTR);

    /**
     * @brief Creates and returns an editor widget for the preference at @p index.
     * @param parent  Parent widget for the created editor.
     * @param option  Style options for the cell being edited.
     * @param index   Model index of the preference cell.
     * @return Pointer to the newly created editor widget, or @c nullptr if no
     *         inline editor is provided by this preference type.
     */
    virtual QWidget *editor(QWidget *parent, const QStyleOptionViewItem &option,
                            const QModelIndex &index);

    /**
     * @brief Populates the editor widget with the current preference value from
     *        the model at @p index.
     * @param editor The editor widget previously returned by editor().
     * @param index  Model index of the preference being edited.
     */
    virtual void setData(QWidget *editor, const QModelIndex &index);

    /**
     * @brief Writes the editor's current value back to the model.
     * @param editor The editor widget containing the new value.
     * @param model  The model to update.
     * @param index  Model index of the preference cell to update.
     */
    virtual void setModelData(QWidget *editor, QAbstractItemModel *model,
                              const QModelIndex &index);

    /**
     * @brief Associates a PrefsItem with this preference editor.
     * @param item Pointer to the PrefsItem this editor operates on.
     */
    void setPrefsItem(PrefsItem *item);

protected:
    /**
     * @brief Returns the PrefsItem associated with this preference editor.
     * @return Pointer to the associated PrefsItem, or @c nullptr if none has been set.
     */
    PrefsItem *prefsItem() const;

private:
    PrefsItem *_prefsItem; /**< The preference item this editor is bound to. */
};

#endif // WIRESHARK_PREFERENCE_H
