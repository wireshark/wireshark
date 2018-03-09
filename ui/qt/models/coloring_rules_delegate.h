/* coloring_rules_delegate.h
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

class ColoringRulesDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    ColoringRulesDelegate(QObject *parent = 0);

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const;
    void setEditorData(QWidget *editor, const QModelIndex &index) const;
    void setModelData(QWidget *editor, QAbstractItemModel *model,
                      const QModelIndex &index) const;

    void updateEditorGeometry(QWidget *editor,
            const QStyleOptionViewItem &option, const QModelIndex &index) const;

signals:
    void invalidField(const QModelIndex &index, const QString& errMessage) const;
    void validField(const QModelIndex &index) const;

private slots:
    void ruleNameChanged(const QString name);
};
#endif // COLORING_RULE_DELEGATE_H
