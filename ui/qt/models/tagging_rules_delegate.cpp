/* tagging_rules_delegate.cpp
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

#include <QApplication>
#include <QLineEdit>

#include <ui/qt/models/tagging_rules_delegate.h>
#include <ui/qt/models/tagging_rules_model.h>
#include <ui/qt/widgets/display_filter_edit.h>
#include <ui/qt/widgets/syntax_line_edit.h>

TaggingRulesDelegate::TaggingRulesDelegate(QObject *parent) : QStyledItemDelegate(parent)
{
}

void TaggingRulesDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyledItemDelegate::paint(painter, option, index);
    if (index.column() == TaggingRulesModel::colName) {
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
        opt.palette = QApplication::palette();
        style->drawPrimitive(QStyle::PE_IndicatorItemViewItemCheck, &opt, painter, widget);
    }
}

QWidget *TaggingRulesDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &,
                                            const QModelIndex &index) const
{
    switch (index.column()) {
    case TaggingRulesModel::colName: {
        SyntaxLineEdit *editor = new SyntaxLineEdit(parent);
        connect(editor, &SyntaxLineEdit::textChanged, this, &TaggingRulesDelegate::ruleNameChanged);
        return editor;
    }
    case TaggingRulesModel::colFilter:
        return new DisplayFilterEdit(parent);
    case TaggingRulesModel::colTag:
    case TaggingRulesModel::colLink:
        return new QLineEdit(parent);
    case TaggingRulesModel::colComment:
        return new SyntaxLineEdit(parent);
    default:
        return nullptr;
    }
}

void TaggingRulesDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    switch (index.column()) {
    case TaggingRulesModel::colName:
    case TaggingRulesModel::colComment: {
        SyntaxLineEdit *syntaxEdit = static_cast<SyntaxLineEdit *>(editor);
        syntaxEdit->setText(index.model()->data(index, Qt::EditRole).toString());
        break;
    }
    case TaggingRulesModel::colFilter: {
        DisplayFilterEdit *displayEdit = static_cast<DisplayFilterEdit *>(editor);
        displayEdit->setText(index.model()->data(index, Qt::EditRole).toString());
        break;
    }
    case TaggingRulesModel::colTag:
    case TaggingRulesModel::colLink: {
        QLineEdit *lineEdit = static_cast<QLineEdit *>(editor);
        lineEdit->setText(index.model()->data(index, Qt::EditRole).toString());
        break;
    }
    default:
        QStyledItemDelegate::setEditorData(editor, index);
        break;
    }
}

void TaggingRulesDelegate::setModelData(QWidget *editor, QAbstractItemModel *model,
                                        const QModelIndex &index) const
{
    switch (index.column()) {
    case TaggingRulesModel::colName: {
        SyntaxLineEdit *syntaxEdit = static_cast<SyntaxLineEdit *>(editor);
        model->setData(index, syntaxEdit->text(), Qt::EditRole);
        emit validField(index);
        break;
    }
    case TaggingRulesModel::colFilter: {
        DisplayFilterEdit *displayEdit = static_cast<DisplayFilterEdit *>(editor);
        model->setData(index, displayEdit->text(), Qt::EditRole);
        if (displayEdit->syntaxState() == SyntaxLineEdit::Invalid &&
            model->data(model->index(index.row(), TaggingRulesModel::colName), Qt::CheckStateRole) == Qt::Checked)
        {
            model->setData(model->index(index.row(), TaggingRulesModel::colName), Qt::Unchecked, Qt::CheckStateRole);
            emit invalidField(index, displayEdit->syntaxErrorMessage());
        } else {
            emit validField(index);
        }
        break;
    }
    case TaggingRulesModel::colTag:
    case TaggingRulesModel::colLink: {
        QLineEdit *lineEdit = static_cast<QLineEdit *>(editor);
        model->setData(index, lineEdit->text(), Qt::EditRole);
        emit validField(index);
        break;
    }
    case TaggingRulesModel::colComment: {
        SyntaxLineEdit *syntaxEdit = static_cast<SyntaxLineEdit *>(editor);
        model->setData(index, syntaxEdit->text(), Qt::EditRole);
        emit validField(index);
        break;
    }
    default:
        QStyledItemDelegate::setModelData(editor, model, index);
        break;
    }
}

void TaggingRulesDelegate::updateEditorGeometry(QWidget *editor,
        const QStyleOptionViewItem &option, const QModelIndex &) const
{
    editor->setGeometry(option.rect);
}

void TaggingRulesDelegate::ruleNameChanged(const QString name)
{
    SyntaxLineEdit *name_edit = qobject_cast<SyntaxLineEdit *>(QObject::sender());
    if (!name_edit) return;

    if (name.isEmpty()) {
        name_edit->setSyntaxState(SyntaxLineEdit::Empty);
    } else {
        name_edit->setSyntaxState(SyntaxLineEdit::Valid);
    }
}
