/* fileset_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include "file.h"
#include "fileset.h"

#include "ui/help_url.h"

#include <wsutil/str_util.h>

#include "file_set_dialog.h"
#include <ui_file_set_dialog.h>
#include "models/fileset_entry_model.h"
#include "wireshark_application.h"

#include <QDialogButtonBox>
#include <QPushButton>
#include <QDateTime>
#include <QFontMetrics>
#include <QFont>
#include <QUrl>

// To do:
// - We might want to rename this to FilesetDialog / fileset_dialog.{cpp,h}.

void
fileset_dlg_begin_add_file(void *window) {
    FileSetDialog *fs_dlg = static_cast<FileSetDialog *>(window);

    if (fs_dlg) fs_dlg->beginAddFile();
}

/* This file is a part of the current file set. Add it to our model. */
void
fileset_dlg_add_file(fileset_entry *entry, void *window) {
    FileSetDialog *fs_dlg = static_cast<FileSetDialog *>(window);

    if (fs_dlg) fs_dlg->addFile(entry);
}

void
fileset_dlg_end_add_file(void *window) {
    FileSetDialog *fs_dlg = static_cast<FileSetDialog *>(window);

    if (fs_dlg) fs_dlg->endAddFile();
}

FileSetDialog::FileSetDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    fs_ui_(new Ui::FileSetDialog),
    fileset_entry_model_(new FilesetEntryModel(this)),
    close_button_(NULL)
{
    fs_ui_->setupUi(this);
    loadGeometry ();

    fs_ui_->fileSetTree->setModel(fileset_entry_model_);

    fs_ui_->fileSetTree->setFocus();

    close_button_ = fs_ui_->buttonBox->button(QDialogButtonBox::Close);

    connect(fs_ui_->fileSetTree->selectionModel(), SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
            this, SLOT(selectionChanged(QItemSelection,QItemSelection)));

    beginAddFile();
    addFile();
    endAddFile();
}

FileSetDialog::~FileSetDialog()
{
    fileset_entry_model_->clear();
    delete fs_ui_;
}

/* a new capture file was opened, browse the dir and look for files matching the given file set */
void FileSetDialog::fileOpened(const capture_file *cf) {
    if (!cf) return;
    fileset_entry_model_->clear();
    fileset_add_dir(cf->filename, this);
}

/* the capture file was closed */
void FileSetDialog::fileClosed() {
    fileset_entry_model_->clear();
}

void FileSetDialog::addFile(fileset_entry *entry) {
    if (!entry) return;

    if (entry->current) {
        cur_idx_ = fileset_entry_model_->entryCount();
    }
    fileset_entry_model_->appendEntry(entry);
}

void FileSetDialog::beginAddFile()
{
    cur_idx_ = -1;
    setWindowTitle(wsApp->windowTitleString(tr("No files in Set")));
    fs_ui_->directoryLabel->setText(tr("No capture loaded"));
    fs_ui_->directoryLabel->setEnabled(false);
}

void FileSetDialog::endAddFile()
{
    if (fileset_entry_model_->entryCount() > 0) {
        setWindowTitle(wsApp->windowTitleString(tr("%Ln File(s) in Set", "",
                                                   fileset_entry_model_->entryCount())));
    }

    QString dir_name = fileset_get_dirname();
    fs_ui_->directoryLabel->setText(dir_name);
    fs_ui_->directoryLabel->setUrl(QUrl::fromLocalFile(dir_name).toString());
    fs_ui_->directoryLabel->setEnabled(true);

    if (cur_idx_ >= 0) {
        fs_ui_->fileSetTree->setCurrentIndex(fileset_entry_model_->index(cur_idx_, 0));
    }

    for (int col = 0; col < 4; col++) {
        fs_ui_->fileSetTree->resizeColumnToContents(col);
    }

    if (close_button_)
        close_button_->setEnabled(true);
}

void FileSetDialog::selectionChanged(const QItemSelection &selected, const QItemSelection &)
{
    const fileset_entry *entry = fileset_entry_model_->getRowEntry(selected.first().top());

    if (!entry || entry->current)
        return;

    QString new_cf_path = entry->fullname;

    if (new_cf_path.length() > 0) {
        emit fileSetOpenCaptureFile(new_cf_path);
    }
}

void FileSetDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_FILESET_DIALOG);
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
