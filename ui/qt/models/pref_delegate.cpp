/* pref_delegate.cpp
 * Delegates for editing prefereneces.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/pref_delegate.h>
#include <epan/prefs-int.h>

#include <ui/qt/manager/preference_manager.h>
#include <ui/qt/manager/wireshark_preference.h>

AdvancedPrefDelegate::AdvancedPrefDelegate(QObject *parent) : QStyledItemDelegate(parent)
{
}

PrefsItem* AdvancedPrefDelegate::indexToPref(const QModelIndex &index) const
{
    const QVariant v = index.model()->data(index, Qt::UserRole);
    return VariantPointer<PrefsItem>::asPtr(v);
}

QWidget *AdvancedPrefDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                                  const QModelIndex &index) const
{
    PrefsItem* pref;
    QString filename;

    switch(index.column())
    {
    case AdvancedPrefsModel::colName:
    case AdvancedPrefsModel::colStatus:
    case AdvancedPrefsModel::colType:
        //If user clicks on any of these columns, reset preference back to default
        //There is no need to launch an editor
        const_cast<QAbstractItemModel*>(index.model())->setData(index, QVariant(), Qt::EditRole);
        break;
    case AdvancedPrefsModel::colValue:
        pref = indexToPref(index);
        WiresharkPreference * wspref = PreferenceManager::instance()->getPreference(pref);
        if (wspref) {
            QWidget *editor = wspref->editor(parent, option, index);
            if (editor) {
                editor->setAutoFillBackground(true);
            }
            return editor;
        }
        break;
    }

    return Q_NULLPTR;
}

void AdvancedPrefDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    PrefsItem* pref = indexToPref(index);

    WiresharkPreference * wspref = PreferenceManager::instance()->getPreference(pref);
    if (wspref)
    {
        wspref->setData(editor, index);
        return;
    }

    Q_ASSERT(false);
}

void AdvancedPrefDelegate::setModelData(QWidget *editor, QAbstractItemModel *model,
                              const QModelIndex &index) const
{
    PrefsItem* pref = indexToPref(index);

    WiresharkPreference * wspref = PreferenceManager::instance()->getPreference(pref);
    if (wspref)
    {
        wspref->setModelData(editor, model, index);
        return;
    }

    Q_ASSERT(false);
}
