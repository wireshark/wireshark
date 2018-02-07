/* wireshark_preference.h
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

class WiresharkPreference : public QObject
{
    Q_OBJECT
public:
    explicit Q_INVOKABLE WiresharkPreference(QObject * parent = Q_NULLPTR);

    virtual QWidget * editor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index);
    virtual void setData(QWidget *editor, const QModelIndex &index);
    virtual void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index);

    void setPrefsItem(PrefsItem *);

protected:
    PrefsItem * prefsItem() const;

private:
    PrefsItem * _prefsItem;

};

#endif // WIRESHARK_PREFERENCE_H
