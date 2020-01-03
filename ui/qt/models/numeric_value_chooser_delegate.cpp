/* numeric_value_chooser_delegate.cpp
 * Delegate to select a numeric value for a treeview entry
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/models/numeric_value_chooser_delegate.h>

#include <QStyledItemDelegate>
#include <QSpinBox>

NumericValueChooserDelegate::NumericValueChooserDelegate(int min, int max, QObject *parent)
    : QStyledItemDelegate(parent)
{
    _min = min;
    _max = max;
    _default = min;
}

NumericValueChooserDelegate::~NumericValueChooserDelegate()
{
}

void NumericValueChooserDelegate::setMinMaxRange(int min, int max)
{
    _min = qMin(min, max);
    _max = qMax(min, max);
    /* ensure, that the default value is within the new min<->max */
    _default = qMin(_max, qMax(_min, _default));
    _defReturn = QVariant::fromValue(_default);
}

void NumericValueChooserDelegate::setDefaultValue(int defValue, QVariant defaultReturn)
{
    /* ensure, that the new default value is within min<->max */
    _default = qMin(_max, qMax(_min, defValue));
    _defReturn = defaultReturn;
}

QWidget* NumericValueChooserDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    if (!index.isValid()) {
        return QStyledItemDelegate::createEditor(parent, option, index);
    }

    QSpinBox * editor = new QSpinBox(parent);
    editor->setMinimum(_min);
    editor->setMaximum(_max);
    editor->setWrapping(true);

    connect(editor, static_cast<void (QSpinBox::*)(int)>(&QSpinBox::valueChanged), this,
            &NumericValueChooserDelegate::onValueChanged);

    return editor;
}

void NumericValueChooserDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    if (index.isValid())
    {
        bool canConvert = false;
        int val = index.data().toInt(&canConvert);
        if (! canConvert)
            val = _default;

        QSpinBox * spinBox = qobject_cast<QSpinBox *>(editor);
        spinBox->setValue(val);
    }
    else
        QStyledItemDelegate::setEditorData(editor, index);
}

void NumericValueChooserDelegate::setModelData(QWidget *editor, QAbstractItemModel * model, const QModelIndex &index) const
{
    if (index.isValid()) {
        QSpinBox * spinBox = qobject_cast<QSpinBox *>(editor);
        model->setData(index, _default == spinBox->value() ? _defReturn : QVariant::fromValue(spinBox->value()));
    } else {
        QStyledItemDelegate::setModelData(editor, model, index);
    }
}

void NumericValueChooserDelegate::onValueChanged(int)
{
    QSpinBox * spinBox = qobject_cast<QSpinBox *>(sender());
    emit commitData(spinBox);
}

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
