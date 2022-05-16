/* path_chooser_delegate.cpp
 * Delegate to select a file path for a treeview entry
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/path_selection_delegate.h>
#include <ui/qt/widgets/path_selection_edit.h>

PathSelectionDelegate::PathSelectionDelegate(QObject *parent)
    : QStyledItemDelegate(parent)
{
}

QWidget* PathSelectionDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &, const QModelIndex &) const
{
    PathSelectionEdit * editor = new PathSelectionEdit(tr("Open a pipe"), QString(), true, parent);

    connect(editor, &PathSelectionEdit::pathChanged, this, &PathSelectionDelegate::pathHasChanged);

    return editor;
}

void PathSelectionDelegate::pathHasChanged(QString)
{
    PathSelectionEdit * editor = qobject_cast<PathSelectionEdit *>(sender());
    if (editor)
        emit commitData(editor);
}

void PathSelectionDelegate::updateEditorGeometry(QWidget *editor, const QStyleOptionViewItem &option, const QModelIndex &) const
{
    editor->setGeometry(option.rect);
}

void PathSelectionDelegate::setEditorData(QWidget *editor, const QModelIndex &idx) const
{
    if (idx.isValid() && qobject_cast<PathSelectionEdit *>(editor) != nullptr)
    {
        PathSelectionEdit * edit = qobject_cast<PathSelectionEdit *>(editor);
        edit->setPath(idx.data().toString());
    }
    else
        QStyledItemDelegate::setEditorData(editor, idx);
}

void PathSelectionDelegate::setModelData(QWidget *editor, QAbstractItemModel * model, const QModelIndex &idx) const
{
    if (idx.isValid() && qobject_cast<PathSelectionEdit *>(editor) != nullptr)
    {
        PathSelectionEdit * edit = qobject_cast<PathSelectionEdit *>(editor);
        model->setData(idx, edit->path());
    }
    else
    {
        QStyledItemDelegate::setModelData(editor, model, idx);
    }
}

