/* fileset_dialog.cpp
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

#include "config.h"

#include <glib.h>

#include "file.h"
#include "fileset.h"

#include "ui/help_url.h"

#include <wsutil/str_util.h>

#include "file_set_dialog.h"
#include <ui_file_set_dialog.h>
#include "wireshark_application.h"

#include <QDialogButtonBox>
#include <QPushButton>
#include <QDateTime>
#include <QFontMetrics>
#include <QFont>
#include <QTreeWidgetItem>
#include <QUrl>

Q_DECLARE_METATYPE(fileset_entry *)

/* this file is a part of the current file set, add it to the dialog */
void
fileset_dlg_add_file(fileset_entry *entry, void *window) {
    FileSetDialog *fs_dlg = static_cast<FileSetDialog *>(window);

    if (fs_dlg) fs_dlg->addFile(entry);
}

FileSetDialog::FileSetDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    fs_ui_(new Ui::FileSetDialog),
    close_button_(NULL)
{
    fs_ui_->setupUi(this);
    loadGeometry ();

    fs_ui_->fileSetTree->headerItem();

    close_button_ = fs_ui_->buttonBox->button(QDialogButtonBox::Close);
    addFile();
}

FileSetDialog::~FileSetDialog()
{
    delete fs_ui_;
}

/* a new capture file was opened, browse the dir and look for files matching the given file set */
void FileSetDialog::fileOpened(const capture_file *cf) {
    if (!cf) return;
    fs_ui_->fileSetTree->clear();
    fileset_add_dir(cf->filename, this);
}

/* the capture file was closed */
void FileSetDialog::fileClosed() {
    fileset_delete();
    fs_ui_->fileSetTree->clear();
}

#include <QDebug>
void FileSetDialog::addFile(fileset_entry *entry) {
    QString created;
    QString modified;
    QString dir_name;
    QString elided_dir_name;
    QTreeWidgetItem *entry_item;
    gchar *size_str;

    if (!entry) {
        setWindowTitle(wsApp->windowTitleString(tr("No files in Set")));
        fs_ui_->directoryLabel->setText(tr("No capture loaded"));
        fs_ui_->directoryLabel->setEnabled(false);
        return;
    }

    created = nameToDate(entry->name);
    if(created.length() < 1) {
        /* if this file doesn't follow the file set pattern, */
        /* use the creation time of that file if available */
        /* http://en.wikipedia.org/wiki/ISO_8601 */
        /*
         * macOS provides 0 if the file system doesn't support the
         * creation time; FreeBSD provides -1.
         *
         * If this OS doesn't provide the creation time with stat(),
         * it will be 0.
         */
        if (entry->ctime > 0)
            created = QDateTime::fromTime_t(entry->ctime).toLocalTime().toString("yyyy-MM-dd HH:mm:ss");
        else
            created = "Not available";
    }

    modified = QDateTime::fromTime_t(entry->mtime).toLocalTime().toString("yyyy-MM-dd HH:mm:ss");

    size_str = format_size(entry->size, format_size_unit_bytes|format_size_prefix_si);

    entry_item = new QTreeWidgetItem(fs_ui_->fileSetTree);
    entry_item->setToolTip(0, QString(tr("Open this capture file")));
    entry_item->setData(0, Qt::UserRole, qVariantFromValue(entry));

    entry_item->setText(0, entry->name);
    entry_item->setText(1, created);
    entry_item->setText(2, modified);
    entry_item->setText(3, size_str);
    g_free(size_str);
    // Not perfect but better than nothing.
    entry_item->setTextAlignment(3, Qt::AlignRight);

    setWindowTitle(wsApp->windowTitleString(tr("%Ln File(s) in Set", "",
                                            fs_ui_->fileSetTree->topLevelItemCount())));

    dir_name = fileset_get_dirname();
    fs_ui_->directoryLabel->setText(dir_name);
    fs_ui_->directoryLabel->setUrl(QUrl::fromLocalFile(dir_name).toString());
    fs_ui_->directoryLabel->setEnabled(true);

    if(entry->current) {
        fs_ui_->fileSetTree->setCurrentItem(entry_item);
    }

    if (close_button_)
        close_button_->setEnabled(true);

    fs_ui_->fileSetTree->addTopLevelItem(entry_item);
    for (int i = 0; i < fs_ui_->fileSetTree->columnCount(); i++)
        fs_ui_->fileSetTree->resizeColumnToContents(i);
    fs_ui_->fileSetTree->setFocus();
}

QString FileSetDialog::nameToDate(const char *name) {
    QString dn;

    if (!fileset_filename_match_pattern(name))
        return NULL;

    dn = name;
    dn.remove(QRegExp(".*_"));
    dn.truncate(14);
    dn.insert(4, '-');
    dn.insert(7, '-');
    dn.insert(10, ' ');
    dn.insert(13, ':');
    dn.insert(16, ':');
    return dn;
}

void FileSetDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_FILESET_DIALOG);
}

void FileSetDialog::on_fileSetTree_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *)
{
    fileset_entry *entry;

    if (!current)
        return;

    entry = current->data(0, Qt::UserRole).value<fileset_entry *>();

    if (!entry || entry->current)
        return;

    QString new_cf_path = entry->fullname;

    if (new_cf_path.length() > 0)
        emit fileSetOpenCaptureFile(new_cf_path);
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
