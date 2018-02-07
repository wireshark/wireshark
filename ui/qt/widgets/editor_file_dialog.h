/* editor_file_dialog.h
 *
 * File dialog that can be used as an "inline editor" in a table
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*/

#ifndef EDITOR_FILE_DIALOG_H_
#define EDITOR_FILE_DIALOG_H_

#include <QFileDialog>
#include <QModelIndex>

class EditorFileDialog : public QFileDialog
{
    Q_OBJECT
public:
    explicit EditorFileDialog(const QModelIndex& index, QWidget* parent, Qt::WindowFlags flags);
    explicit EditorFileDialog(const QModelIndex& index, QWidget* parent = 0, const QString & caption = QString(), const QString & directory = QString(), const QString & filter = QString());

    void accept();

signals:
    void acceptEdit(const QModelIndex& index);

protected:
    const QModelIndex index_; //saved index of table cell
};

#endif /* EDITOR_FILE_DIALOG_H_ */

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
