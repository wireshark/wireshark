/* coloring_rules_delegate.cpp
 * Delegates for editing various coloring rule fields.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <QApplication>

#include <ui/qt/models/coloring_rules_delegate.h>
#include <ui/qt/models/coloring_rules_model.h>
#include <ui/qt/widgets/display_filter_edit.h>

ColoringRulesDelegate::ColoringRulesDelegate(QObject *parent) : QStyledItemDelegate(parent)
{
}

void ColoringRulesDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyledItemDelegate::paint(painter, option, index);
    switch (index.column())
    {
    case ColoringRulesModel::colName:
    {
        // Qt Item Views use the text color/Foreground color to draw the check
        // mark in a checkbox, but always use the same theme/palette color for
        // the square behind the checkbox. (The background color is used behind
        // the checkbox.) That doesn't look good for certain foreground colors.
        // Let's draw the item check area a second time.
        QStyleOptionViewItem opt = option;
        const QWidget *widget = option.widget;
        initStyleOption(&opt, index);
        QStyle *style = widget->style();
        opt.rect = style->subElementRect(QStyle::SE_ItemViewItemCheckIndicator, &opt, widget);
        switch (opt.checkState) {
        case Qt::Unchecked:
            opt.state |= QStyle::State_Off;
            break;
        case Qt::PartiallyChecked:
            opt.state |= QStyle::State_NoChange;
            break;
        case Qt::Checked:
            opt.state |= QStyle::State_On;
            break;
        }
        opt.state = opt.state & ~QStyle::State_HasFocus;
        // Override the palette to our application default.
        opt.palette = QApplication::palette();

        style->drawPrimitive(QStyle::PE_IndicatorItemViewItemCheck, &opt, painter, widget);
        break;
    }

    case ColoringRulesModel::colFilter:
       break;

    default:
        Q_ASSERT(false);
    }
}

QWidget* ColoringRulesDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem&,
                                  const QModelIndex &index) const
{
    switch (index.column())
    {
    case ColoringRulesModel::colName:
    {
        SyntaxLineEdit *editor = new SyntaxLineEdit(parent);
        connect(editor, &SyntaxLineEdit::textChanged, this, &ColoringRulesDelegate::ruleNameChanged);
        return editor;
    }

    case ColoringRulesModel::colFilter:
        return new DisplayFilterEdit(parent);

    default:
        Q_ASSERT(false);
        return 0;
    }

    return 0;
}

void ColoringRulesDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    switch (index.column())
    {
    case ColoringRulesModel::colName:
    {
        SyntaxLineEdit *syntaxEdit = static_cast<SyntaxLineEdit*>(editor);
        syntaxEdit->setText(index.model()->data(index, Qt::EditRole).toString());
        break;
    }
    case ColoringRulesModel::colFilter:
    {
        DisplayFilterEdit *displayEdit = static_cast<DisplayFilterEdit*>(editor);
        displayEdit->setText(index.model()->data(index, Qt::EditRole).toString());
        break;
    }
    default:
        QStyledItemDelegate::setEditorData(editor, index);
        break;
    }
}

void ColoringRulesDelegate::setModelData(QWidget *editor, QAbstractItemModel *model,
                              const QModelIndex &index) const
{
    switch (index.column())
    {
    case ColoringRulesModel::colName:
    {
        SyntaxLineEdit *syntaxEdit = static_cast<SyntaxLineEdit*>(editor);
        model->setData(index, syntaxEdit->text(), Qt::EditRole);
        if (syntaxEdit->syntaxState() == SyntaxLineEdit::Invalid) {
            QString error_text = tr("the \"@\" symbol will be ignored.");
            emit invalidField(index, error_text);
        }
        else
        {
            emit validField(index);
        }
        break;
    }
    case ColoringRulesModel::colFilter:
    {
        DisplayFilterEdit *displayEdit = static_cast<DisplayFilterEdit*>(editor);
        model->setData(index, displayEdit->text(), Qt::EditRole);
        if ((displayEdit->syntaxState() == SyntaxLineEdit::Invalid) &&
            (model->data(model->index(index.row(), ColoringRulesModel::colName), Qt::CheckStateRole) == Qt::Checked))
        {
            model->setData(model->index(index.row(), ColoringRulesModel::colName), Qt::Unchecked, Qt::CheckStateRole);
            emit invalidField(index, displayEdit->syntaxErrorMessage());
        }
        else
        {
            emit validField(index);
        }
        break;
    }
    default:
        QStyledItemDelegate::setModelData(editor, model, index);
        break;
    }
}

void ColoringRulesDelegate::updateEditorGeometry(QWidget *editor,
        const QStyleOptionViewItem &option, const QModelIndex&) const
{
    editor->setGeometry(option.rect);
}

void ColoringRulesDelegate::ruleNameChanged(const QString name)
{
    SyntaxLineEdit *name_edit = qobject_cast<SyntaxLineEdit*>(QObject::sender());
    if (!name_edit) return;

    if (name.isEmpty()) {
        name_edit->setSyntaxState(SyntaxLineEdit::Empty);
    } else if (name.contains("@")) {
        name_edit->setSyntaxState(SyntaxLineEdit::Invalid);
    } else {
        name_edit->setSyntaxState(SyntaxLineEdit::Valid);
    }
}
