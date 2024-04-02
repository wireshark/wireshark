/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILE_SET_DIALOG_H
#define FILE_SET_DIALOG_H

#include <config.h>

#include "file.h"
#include "fileset.h"

#include "geometry_state_dialog.h"

#include <QItemSelection>

namespace Ui {
class FileSetDialog;
}

class FilesetEntryModel;

class FileSetDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit FileSetDialog(QWidget *parent = 0);
    ~FileSetDialog();

    void fileOpened(const capture_file *cf);
    void fileClosed();
    void addFile(fileset_entry *entry = NULL);
    void beginAddFile();
    void endAddFile();

signals:
    void fileSetOpenCaptureFile(QString);

private slots:
    void selectionChanged(const QItemSelection &selected, const QItemSelection &);
    void on_buttonBox_helpRequested();

private:
    Ui::FileSetDialog *fs_ui_;
    FilesetEntryModel *fileset_entry_model_;
    QPushButton *close_button_;
    int cur_idx_;
};

#endif // FILE_SET_DIALOG_H
