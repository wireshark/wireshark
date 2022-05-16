/* uat_delegate.cpp
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

#include <ui/qt/models/uat_delegate.h>
#include "epan/value_string.h"
#include <wsutil/ws_assert.h>
#include <QRegularExpression>
#include <QComboBox>
#include <QEvent>
#include <QFileDialog>
#include <QLineEdit>
#include <QCheckBox>
#include <QColorDialog>

#include <ui/qt/widgets/display_filter_edit.h>
#include <ui/qt/widgets/field_filter_edit.h>
#include <ui/qt/widgets/editor_file_dialog.h>
#include <ui/qt/widgets/path_selection_edit.h>

// The Qt docs suggest overriding updateEditorGeometry, but the
// defaults seem sane.

UatDelegate::UatDelegate(QObject *parent) : QStyledItemDelegate(parent)
{
}

uat_field_t *UatDelegate::indexToField(const QModelIndex &index) const
{
    const QVariant v = index.model()->data(index, Qt::UserRole);
    return static_cast<uat_field_t *>(v.value<void *>());
}

QWidget *UatDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                                  const QModelIndex &index) const
{
    uat_field_t *field = indexToField(index);
    QWidget *editor = nullptr;

    switch (field->mode) {
    case PT_TXTMOD_DIRECTORYNAME:
    case PT_TXTMOD_FILENAME:
        if (index.isValid()) {
            QString filename_old = index.model()->data(index, Qt::EditRole).toString();
            PathSelectionEdit * pathEdit = new PathSelectionEdit(field->title, QString(), field->mode != PT_TXTMOD_DIRECTORYNAME, parent);
            connect(pathEdit, &PathSelectionEdit::pathChanged, this, &UatDelegate::pathHasChanged);
            return pathEdit;
        }
        break;
   case PT_TXTMOD_COLOR:
        if (index.isValid()) {
            QColor color(index.model()->data(index, Qt::DecorationRole).toString());
            QColorDialog * colorDialog = new QColorDialog(color, parent);
            // Don't fall through and set setAutoFillBackground(true)
            return colorDialog;
        }
        break;

    case PT_TXTMOD_ENUM:
    {
        // Note: the string repr. is written, not the integer value.
        QComboBox *cb_editor = new QComboBox(parent);
        const value_string *enum_vals = (const value_string *)field->fld_data;
        for (int i = 0; enum_vals[i].strptr != nullptr; i++) {
            cb_editor->addItem(enum_vals[i].strptr);
        }
        editor = cb_editor;
        cb_editor->setMinimumWidth(cb_editor->minimumSizeHint().width());
        break;
    }

    case PT_TXTMOD_STRING:
        // TODO add a live validator? Should SyntaxLineEdit be used?
        editor = QStyledItemDelegate::createEditor(parent, option, index);
        break;

    case PT_TXTMOD_DISPLAY_FILTER:
        editor = new DisplayFilterEdit(parent);
        break;

    case PT_TXTMOD_PROTO_FIELD:
        editor = new FieldFilterEdit(parent);
        break;

    case PT_TXTMOD_HEXBYTES:
    {
        // Requires input of the form "ab cd ef" (with possibly no or a colon
        // separator instead of a single whitespace) for the editor to accept.
        QRegularExpression hexbytes_regex("([0-9a-f]{2}[ :]?)*");
        hexbytes_regex.setPatternOptions(QRegularExpression::CaseInsensitiveOption);
        // QString types from QStyledItemDelegate are documented to return a
        // QLineEdit. Note that Qt returns a subclass from QLineEdit which
        // automatically adapts the width to the typed contents.
        QLineEdit *le_editor = static_cast<QLineEdit *>(
                QStyledItemDelegate::createEditor(parent, option, index));
        le_editor->setValidator(new QRegularExpressionValidator(hexbytes_regex, le_editor));
        editor = le_editor;
        break;
    }

    case PT_TXTMOD_BOOL:
        // model will handle creating checkbox
        break;

    case PT_TXTMOD_NONE:
        break;

    default:
        ws_assert_not_reached();
        break;
    }

    if (editor) {
        editor->setAutoFillBackground(true);
    }
    return editor;
}

void UatDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    uat_field_t *field = indexToField(index);

    switch (field->mode) {
    case PT_TXTMOD_DIRECTORYNAME:
    case PT_TXTMOD_FILENAME:
        if (index.isValid() && qobject_cast<PathSelectionEdit *>(editor))
            qobject_cast<PathSelectionEdit *>(editor)->setPath(index.model()->data(index, Qt::EditRole).toString());
        break;
    case PT_TXTMOD_ENUM:
    {
        QComboBox *combobox = static_cast<QComboBox *>(editor);
        const QString &data = index.model()->data(index, Qt::EditRole).toString();
        combobox->setCurrentText(data);

        break;
    }
    case PT_TXTMOD_COLOR:
    {
        if (qobject_cast<QColorDialog *>(editor))
        {
            QColor color(index.model()->data(index, Qt::DecorationRole).toString());
            qobject_cast<QColorDialog *>(editor)->setCurrentColor(color);
        }
        break;
    }

    default:
        QStyledItemDelegate::setEditorData(editor, index);
    }
}

void UatDelegate::setModelData(QWidget *editor, QAbstractItemModel *model,
                              const QModelIndex &index) const
{
    uat_field_t *field = indexToField(index);

    switch (field->mode) {
    case PT_TXTMOD_DIRECTORYNAME:
    case PT_TXTMOD_FILENAME:
        if (index.isValid() && qobject_cast<PathSelectionEdit *>(editor))
            const_cast<QAbstractItemModel *>(index.model())->setData(index, qobject_cast<PathSelectionEdit *>(editor)->path(), Qt::EditRole);
        break;
    case PT_TXTMOD_ENUM:
    {
        QComboBox *combobox = static_cast<QComboBox *>(editor);
        const QString &data = combobox->currentText();
        model->setData(index, data, Qt::EditRole);
        break;
    }
    case PT_TXTMOD_COLOR:
        //do nothing, dialog signals will update table
        if (qobject_cast<QColorDialog *>(editor))
        {
            QColor newColor = qobject_cast<QColorDialog *>(editor)->currentColor();
            const_cast<QAbstractItemModel *>(index.model())->setData(index, newColor.name(), Qt::EditRole);
        }
        break;

    default:
        QStyledItemDelegate::setModelData(editor, model, index);
    }
}

void UatDelegate::updateEditorGeometry(QWidget *editor,
                                           const QStyleOptionViewItem &option,
                                           const QModelIndex &index) const
{
    uat_field_t *field = indexToField(index);

    switch (field->mode) {
    case PT_TXTMOD_DIRECTORYNAME:
    case PT_TXTMOD_FILENAME:
        editor->setGeometry(option.rect);
        break;
    default:
        QStyledItemDelegate::updateEditorGeometry(editor, option, index);
    }
}

void UatDelegate::pathHasChanged(QString)
{
    PathSelectionEdit * editor = qobject_cast<PathSelectionEdit *>(sender());
    if (editor)
        emit commitData(editor);
}
