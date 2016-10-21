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

#include "uat_delegate.h"
#include "epan/value_string.h"
#include <QComboBox>
#include <QEvent>
#include <QFileDialog>
#include <QLineEdit>

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
    case PT_TXTMOD_FILENAME:
        // TODO tab navigation from this field is broken.
        // Do not create editor, a dialog will be opened in editorEvent
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

    default:
        QStyledItemDelegate::setModelData(editor, model, index);
    }
}

#if 0
// Qt docs suggest overriding updateEditorGeometry, but the defaults seem sane.
void UatDelegate::updateEditorGeometry(QWidget *editor,
        const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    QStyledItemDelegate::updateEditorGeometry(editor, option, index);
}
#endif

bool UatDelegate::editorEvent(QEvent *event, QAbstractItemModel *model, const QStyleOptionViewItem &option, const QModelIndex &index)
{
    uat_field_t *field = indexToField(index);

    switch (field->mode) {
    case PT_TXTMOD_DIRECTORYNAME:
    case PT_TXTMOD_FILENAME:
        if (event && (event->type() == QEvent::MouseButtonRelease ||
                    event->type() == QEvent::MouseButtonDblClick)) {
            // Ignore these mouse events, only handle MouseButtonPress.
            return false;
        }
        if (index.isValid()) {
            QString filename_old = model->data(index, Qt::EditRole).toString();
            QString filename = openFileDialog(field, filename_old);
            // TODO should this overwrite only when !filename.isEmpty()?
            model->setData(index, filename, Qt::EditRole);
        }
        // returns false to ensure that QAbstractItemView::edit does not assume
        // the editing state. This causes the view's currentIndex to be changed
        // to the cell where this delegate was "created", as desired.
        return false;

    default:
        return QStyledItemDelegate::editorEvent(event, model, option, index);
    }
}

QString UatDelegate::openFileDialog(uat_field_t *field, const QString &cur_path) const
{
    // Note: file dialogs have their parent widget set to NULL because we do not
    // have an editor nor the view that would attach us.
    switch (field->mode) {
    case PT_TXTMOD_DIRECTORYNAME:
        return QFileDialog::getExistingDirectory(NULL, field->title, cur_path);

    case PT_TXTMOD_FILENAME:
        return QFileDialog::getOpenFileName(NULL, field->title, cur_path,
                QString(), NULL, QFileDialog::DontConfirmOverwrite);

    default:
        g_assert_not_reached();
        return 0;
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
