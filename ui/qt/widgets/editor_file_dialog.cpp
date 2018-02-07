/* editor_file_dialog.h
 *
 * File dialog that can be used as an "inline editor" in a table
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*/

#include <ui/qt/widgets/editor_file_dialog.h>

EditorFileDialog::EditorFileDialog(const QModelIndex& index, QWidget* parent, Qt::WindowFlags flags)
    : QFileDialog(parent, flags)
    , index_(index)
{
}

EditorFileDialog::EditorFileDialog(const QModelIndex& index, QWidget* parent, const QString& caption, const QString& directory, const QString& filter)
    : QFileDialog(parent, caption, directory, filter)
    , index_(index)
{
}

void EditorFileDialog::accept()
{
    emit acceptEdit(index_);
    QFileDialog::accept();
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
