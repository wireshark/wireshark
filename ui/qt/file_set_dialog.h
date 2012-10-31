/* fileset_dialog.h
 *
 * $Id$
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

#ifndef FILE_SET_DIALOG_H
#define FILE_SET_DIALOG_H

#include "config.h"

#include <glib.h>

#include "file.h"
#include "fileset.h"

#include <QDialog>
#include <QTreeWidgetItem>

namespace Ui {
class FileSetDialog;
}

class FileSetDialog : public QDialog
{
    Q_OBJECT

public:
    explicit FileSetDialog(QWidget *parent = 0);
    ~FileSetDialog();

    void fileOpened(const capture_file *cf);
    void fileClosed();
    void addFile(fileset_entry *entry = NULL);

signals:
    void fileSetOpenCaptureFile(QString &);

private slots:
    void on_buttonBox_helpRequested();
    void on_fileSetTree_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);

private:
    QString nameToDate(const char *name);

    Ui::FileSetDialog *fs_ui_;
    QPushButton *close_button_;
};

#endif // FILE_SET_DIALOG_H

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
