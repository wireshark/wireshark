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
#include <epan/uat-int.h>

#include <QStyledItemDelegate>
#include <QModelIndex>

class UatDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    UatDelegate(QObject *parent = 0);

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const override;
    void setEditorData(QWidget *editor, const QModelIndex &index) const override;
    void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index) const override;
    void updateEditorGeometry(QWidget *editor, const QStyleOptionViewItem &option, const QModelIndex &index) const override;

protected slots:
    void pathHasChanged(QString newPath);

private:
    uat_field_t *indexToField(const QModelIndex &index) const;
};
#endif // UAT_DELEGATE_H
