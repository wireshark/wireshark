/* editor_color_dialog.cpp
 *
 * Color dialog that can be used as an "inline editor" in a table
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*/

#include <ui/qt/widgets/editor_color_dialog.h>

EditorColorDialog::EditorColorDialog(const QModelIndex& index, QWidget* parent)
    : QColorDialog(parent)
    , index_(index)
{

}

EditorColorDialog::EditorColorDialog(const QModelIndex& index, const QColor& initial, QWidget* parent)
    : QColorDialog(initial, parent)
    , index_(index)
{

}

void EditorColorDialog::accept()
{
    emit acceptEdit(index_);
    QColorDialog::accept();
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
