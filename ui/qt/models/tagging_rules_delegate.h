/* tagging_rules_delegate.h
 *
 * Delegate for editing tagging rule fields
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TAGGING_RULES_DELEGATE_H
#define TAGGING_RULES_DELEGATE_H

#include <config.h>

#include <QStyledItemDelegate>
#include <QModelIndex>

class TaggingRulesDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    TaggingRulesDelegate(QObject *parent = nullptr);

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override;

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override;

    void setEditorData(QWidget *editor, const QModelIndex &index) const override;

    void setModelData(QWidget *editor, QAbstractItemModel *model,
                      const QModelIndex &index) const override;

    void updateEditorGeometry(QWidget *editor,
            const QStyleOptionViewItem &option, const QModelIndex &index) const override;

signals:
    void invalidField(const QModelIndex &index, const QString &errMessage) const;
    void validField(const QModelIndex &index) const;

private slots:
    void ruleNameChanged(const QString name);
};

#endif // TAGGING_RULES_DELEGATE_H
