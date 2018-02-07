/* pref_delegate.h
 * Delegates for editing prefereneces.
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

class AdvancedPrefDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    AdvancedPrefDelegate(QObject *parent = 0);

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const;
    void setEditorData(QWidget *editor, const QModelIndex &index) const;
    void setModelData(QWidget *editor, QAbstractItemModel *model,
                      const QModelIndex &index) const;

private:
    PrefsItem* indexToPref(const QModelIndex &index) const;
};

#endif // PREF_DELEGATE_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
