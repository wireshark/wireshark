/* uat_delegate.cpp
 * Delegates for editing various field types in a UAT record.
 *
 * Copyright 2016 Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
#include <ui/qt/widgets/editor_color_dialog.h>

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
            EditorFileDialog* fileDialog = new EditorFileDialog(index, parent, QString(field->title), filename_old);

            fileDialog->setFileMode(QFileDialog::DirectoryOnly);

            //Use signals to accept data from cell
            connect(fileDialog, SIGNAL(acceptEdit(const QModelIndex &)), this, SLOT(applyDirectory(const QModelIndex&)));
            return fileDialog;
        }

        //shouldn't happen
        return 0;

    case PT_TXTMOD_FILENAME:
        if (index.isValid()) {
            QString filename_old = index.model()->data(index, Qt::EditRole).toString();
            EditorFileDialog* fileDialog = new EditorFileDialog(index, parent, QString(field->title), filename_old);

            fileDialog->setFileMode(QFileDialog::ExistingFile);
            fileDialog->setOption(QFileDialog::DontConfirmOverwrite);

            //Use signals to accept data from cell
            connect(fileDialog, SIGNAL(acceptEdit(const QModelIndex &)), this, SLOT(applyFilename(const QModelIndex &)));
            return fileDialog;
        }

        //shouldn't happen
        return 0;

   case PT_TXTMOD_COLOR:
        if (index.isValid()) {
            QColor color(index.model()->data(index, Qt::DecorationRole).toString());
            EditorColorDialog *colorDialog = new EditorColorDialog(index, color, new QWidget(parent));

            colorDialog->setWindowFlags(Qt::Window);

            //Use signals to accept data from cell
            connect(colorDialog, SIGNAL(acceptEdit(const QModelIndex &)), this, SLOT(applyColor(const QModelIndex &)));
            return colorDialog;
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
#if QT_VERSION >= QT_VERSION_CHECK(5, 0, 0)
        combobox->setCurrentText(data);
#else
        int new_index = combobox->findText(data);
        if (new_index >= 0) {
            combobox->setCurrentIndex(new_index);
        }
#endif

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
    case PT_TXTMOD_DIRECTORYNAME:
    case PT_TXTMOD_FILENAME:
    case PT_TXTMOD_COLOR:
        //do nothing, dialog signals will update table
        break;

    default:
        QStyledItemDelegate::setModelData(editor, model, index);
    }
}

void UatDelegate::updateEditorGeometry(QWidget *editor,
        const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    uat_field_t *field = indexToField(index);

    switch (field->mode) {
    case PT_TXTMOD_DIRECTORYNAME:
    {
        QRect rect = option.rect;
        rect.setBottom(rect.width());
        editor->setGeometry(rect);
        break;
    }
    case PT_TXTMOD_FILENAME:
    {
        QRect rect = option.rect;
        rect.setWidth(600);
        rect.setHeight(600);
        editor->setGeometry(rect);
        break;
    }
    default:
        //the defaults for other editors seem sane.
        QStyledItemDelegate::updateEditorGeometry(editor, option, index);
    }
}

void UatDelegate::applyFilename(const QModelIndex& index)
{
    if (index.isValid()) {
        EditorFileDialog* fileDialog = static_cast<EditorFileDialog*>(sender());

        QStringList files = fileDialog->selectedFiles();
        if (files.size() > 0) {
            ((QAbstractItemModel *)index.model())->setData(index, files[0], Qt::EditRole);
        }
    }
}

void UatDelegate::applyDirectory(const QModelIndex& index)
{
    if (index.isValid()) {
        EditorFileDialog* fileDialog = static_cast<EditorFileDialog*>(sender());
        const QString &data = fileDialog->directory().absolutePath();
        ((QAbstractItemModel *)index.model())->setData(index, data, Qt::EditRole);
    }
}

void UatDelegate::applyColor(const QModelIndex& index)
{
    if (index.isValid()) {
        QColorDialog *colorDialog = static_cast<QColorDialog*>(sender());
        QColor newColor = colorDialog->currentColor();
        ((QAbstractItemModel *)index.model())->setData(index, newColor.name(), Qt::EditRole);
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
