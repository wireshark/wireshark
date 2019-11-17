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
#include <QComboBox>
#include <QEvent>
#include <QFileDialog>
#include <QLineEdit>
#include <QCheckBox>
#include <QColorDialog>

#include <ui/qt/widgets/display_filter_edit.h>
#include <ui/qt/widgets/field_filter_edit.h>
#include <ui/qt/widgets/editor_file_dialog.h>

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

    switch (field->mode) {
    case PT_TXTMOD_DIRECTORYNAME:
        if (index.isValid()) {
            QString filename_old = index.model()->data(index, Qt::EditRole).toString();
            EditorFileDialog* fileDialog = new EditorFileDialog(index, EditorFileDialog::Directory, parent, QString(field->title), filename_old);

            //Use signals to accept data from cell
            connect(fileDialog, &EditorFileDialog::acceptEdit, this, &UatDelegate::applyFilename);
            return fileDialog;
        }

        //shouldn't happen
        return 0;

    case PT_TXTMOD_FILENAME:
        if (index.isValid()) {
            QString filename_old = index.model()->data(index, Qt::EditRole).toString();
            EditorFileDialog* fileDialog = new EditorFileDialog(index, EditorFileDialog::ExistingFile, parent, QString(field->title), filename_old);

            fileDialog->setOption(QFileDialog::DontConfirmOverwrite);

            //Use signals to accept data from cell
            connect(fileDialog, &EditorFileDialog::acceptEdit, this, &UatDelegate::applyFilename);
            return fileDialog;
        }

        //shouldn't happen
        return 0;

   case PT_TXTMOD_COLOR:
        if (index.isValid()) {
            QColor color(index.model()->data(index, Qt::DecorationRole).toString());
            QColorDialog * dialog = new QColorDialog(color, parent);
            return dialog;
        }

        //shouldn't happen
        return 0;

    case PT_TXTMOD_ENUM:
    {
        // Note: the string repr. is written, not the integer value.
        QComboBox *editor = new QComboBox(parent);
        const value_string *enum_vals = (const value_string *)field->fld_data;
        for (int i = 0; enum_vals[i].strptr != NULL; i++) {
            editor->addItem(enum_vals[i].strptr);
        }
        return editor;
    }

    case PT_TXTMOD_STRING:
        // TODO add a live validator? Should SyntaxLineEdit be used?
        return QStyledItemDelegate::createEditor(parent, option, index);

    case PT_TXTMOD_DISPLAY_FILTER:
    {
        DisplayFilterEdit *editor = new DisplayFilterEdit(parent);
        return editor;
    }
    case PT_TXTMOD_PROTO_FIELD:
    {
        FieldFilterEdit *editor = new FieldFilterEdit(parent);
        return editor;
    }
    case PT_TXTMOD_HEXBYTES:
    {
        // Requires input of the form "ab cd ef" (with possibly no or a colon
        // separator instead of a single whitespace) for the editor to accept.
        QRegExp hexbytes_regex("([0-9a-f]{2}[ :]?)*");
        hexbytes_regex.setCaseSensitivity(Qt::CaseInsensitive);
        // QString types from QStyledItemDelegate are documented to return a
        // QLineEdit. Note that Qt returns a subclass from QLineEdit which
        // automatically adapts the width to the typed contents.
        QLineEdit *editor = static_cast<QLineEdit *>(
                QStyledItemDelegate::createEditor(parent, option, index));
        editor->setValidator(new QRegExpValidator(hexbytes_regex, editor));
        return editor;
    }

    case PT_TXTMOD_BOOL:
    {
        // model will handle creating checkbox
        return 0;
    }

    case PT_TXTMOD_NONE:
        return 0;

    default:
        g_assert_not_reached();
        return 0;
    }
}

void UatDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    uat_field_t *field = indexToField(index);

    switch (field->mode) {
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
            ((QAbstractItemModel *)index.model())->setData(index, newColor.name(), Qt::EditRole);
        }
        break;

    default:
        QStyledItemDelegate::setModelData(editor, model, index);
    }
}

void UatDelegate::applyFilename(const QModelIndex& index)
{
    if (index.isValid()) {
        EditorFileDialog* fileDialog = static_cast<EditorFileDialog*>(sender());
        ((QAbstractItemModel *)index.model())->setData(index, fileDialog->text(), Qt::EditRole);
    }
}

/* * Editor modelines
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
