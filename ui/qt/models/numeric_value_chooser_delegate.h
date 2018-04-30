/* numeric_value_chooser_delegate.h
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

class NumericValueChooserDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    NumericValueChooserDelegate(int min = 0, int max = 0, QObject *parent = 0);
    ~NumericValueChooserDelegate();

    void setMinMaxRange(int min, int max);
    void setDefaultValue(int defValue, QVariant defaultReturn);

protected:
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const;
    void setEditorData(QWidget *editor, const QModelIndex &index) const;
    void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index) const;

private:

    int _min;
    int _max;
    int _default;
    QVariant _defReturn;

private slots:
    void onValueChanged(int i);
};

#endif /* NUMERIC_VALUE_CHOOSER_DELEGATE_H_ */

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
