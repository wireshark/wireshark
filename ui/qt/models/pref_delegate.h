/* pref_delegate.h
 * Delegates for editing prefereneces.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef PREF_DELEGATE_H
#define PREF_DELEGATE_H

#include <config.h>

#include <ui/qt/models/pref_models.h>
#include <ui/qt/widgets/syntax_line_edit.h>

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

//Utility class for range preferences
class RangeSyntaxLineEdit : public SyntaxLineEdit
{
    Q_OBJECT
public:
    explicit RangeSyntaxLineEdit(QWidget *parent = 0);
    void setMaxRange(unsigned int max) {maxRange_ = max;}

public slots:
    void checkRange(QString range);

private:
    unsigned int maxRange_;
};

#endif // PREF_DELEGATE_H
