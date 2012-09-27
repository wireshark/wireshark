/* capture_file_dialog.cpp
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

#include "config.h"

#include <glib.h>

#include <wiretap/wtap.h>

#include "capture_file_dialog.h"

#ifdef Q_WS_WIN
#include <windows.h>
#include "ui/win32/file_dlg_win32.h"
#endif

#include <errno.h>
#include "file.h"
#include "../../epan/addr_resolv.h"
#include "../../epan/prefs.h"
#include "../../epan/filesystem.h"
#include "../../epan/nstime.h"
#include <QGridLayout>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QCheckBox>
#include <QFileInfo>
#include <QMessageBox>

#include <QDebug>

#ifdef Q_WS_WIN
// All of these routines are required by file_dlg_win32.c.
// We don't yet have a good place for them so we'll add them as stubs here.

extern "C" {

// From gtk/capture_dlg.[ch]
/* capture start confirmed by "Save unsaved capture", so do it now */
extern void capture_start_confirmed(void) {
}

// From gtk/drag_and_drop.[ch]
/** Open a new file coming from drag and drop.
 * @param cf_names_freeme the selection data reported from GTK
 */
extern void dnd_open_file_cmd(gchar *cf_names_freeme) {
    Q_UNUSED(cf_names_freeme);
}

// From gtk/menus.h & main_menubar.c
/** User pushed a recent file submenu item.
 *
 * @param widget parent widget
 */
extern void menu_open_recent_file_cmd(gpointer action){
    Q_UNUSED(action)
}

/** One of the name resolution menu items changed. */
extern void menu_name_resolution_changed(void) {

}

// From gtk/export_sslkeys.[ch]
/** Callback for "Export SSL Session Keys" operation.
 *
 * @param w unused
 * @param data unused
 */
extern void savesslkeys_cb(gpointer * w, gpointer data) {
    Q_UNUSED(w);
    Q_UNUSED(data);
}

/** Dump the SSL Session Keys to a StringInfo string
 *
 * @param session_hash contains all the SSL Session Keys
 */
extern gpointer ssl_export_sessions(GHashTable *session_hash) {
    Q_UNUSED(session_hash);
    return NULL;
}

// From gtk/help_dlg.[ch]
/** Open a specific topic (create a "Help" dialog box or open a webpage).
 *
 * @param widget parent widget (unused)
 * @param topic the topic to display
 */
extern void topic_cb(gpointer *widget, int topic) {
    Q_UNUSED(widget);
    Q_UNUSED(topic);
}

}
// End stub routines
#endif // Q_WS_WIN

CaptureFileDialog::CaptureFileDialog(QWidget *parent, QString &display_filter) :
    QFileDialog(parent), display_filter_(display_filter)
#if !defined(Q_WS_WIN)
    , default_ft_(-1)
#else
  , file_type_(-1)
#endif
{
#if !defined(Q_WS_WIN)
    // Add extra widgets
    // http://qt-project.org/faq/answer/how_can_i_add_widgets_to_my_qfiledialog_instance
    setOption(QFileDialog::DontUseNativeDialog, true);
    QGridLayout *fd_grid = qobject_cast<QGridLayout*>(layout());
    QHBoxLayout *h_box = new QHBoxLayout();

    df_row_ = fd_grid->rowCount();

    fd_grid->addLayout(h_box, fd_grid->rowCount(), 1, 1, -1);

    // Left and right boxes for controls and preview
    h_box->addLayout(&left_v_box_);
    h_box->addLayout(&right_v_box_);


#else // Q_WS_WIN
    merge_type_ = 0;
#endif // Q_WS_WIN
}

check_savability_t CaptureFileDialog::checkSaveAsWithComments(QWidget *
#if defined(Q_WS_WIN)
        parent
#endif
        , capture_file *cf, int file_type) {
#if defined(Q_WS_WIN)
    if (!parent || !cf)
        return CANCELLED;
    return win32_check_save_as_with_comments(parent->effectiveWinId(), cf, file_type);
#else // Q_WS_WIN
    QMessageBox msg_dialog;
    int response;

    /* Do we have any comments? */
    if (!cf_has_comments(cf)) {
        /* No.  Let the save happen; no comments to delete. */
        return SAVE;
    }

    /* XXX - for now, we "know" that pcap-ng is the only format for which
       we support comments.  We should really ask Wiretap what the
       format in question supports (and handle different types of
       comments, some but not all of which some file formats might
       not support). */
    if (file_type == WTAP_FILE_PCAPNG) {
        /* Yes - they selected pcap-ng.  Let the save happen; we can
         save the comments, so no need to delete them. */
        return SAVE;
    }
    /* No. Is pcap-ng one of the formats in which we can write this file? */
    if (wtap_dump_can_write_encaps(WTAP_FILE_PCAPNG, cf->linktypes)) {
        QPushButton *default_button;
        /* Yes.  Offer the user a choice of "Save in a format that
           supports comments", "Discard comments and save in the
           format you selected", or "Cancel", meaning "don't bother
           saving the file at all". */
        msg_dialog.setIcon(QMessageBox::Question);
        msg_dialog.setText("This capture file contains comments.");
        msg_dialog.setInformativeText("The file format you chose doesn't support comments. "
                                      "Do you want to save the capture in a format that supports comments "
                                      "or discard the comments and save in the format you chose?");
        msg_dialog.setStandardButtons(QMessageBox::Cancel);
        // The predefined roles don't really match the tasks at hand...
        msg_dialog.addButton("Discard comments and save", QMessageBox::DestructiveRole);
        default_button = msg_dialog.addButton("Save in another format", QMessageBox::AcceptRole);
        msg_dialog.setDefaultButton(default_button);
    } else {
        /* No.  Offer the user a choice of "Discard comments and
           save in the format you selected" or "Cancel". */
        msg_dialog.setIcon(QMessageBox::Question);
        msg_dialog.setText("This capture file contains comments.");
        msg_dialog.setInformativeText("No file format in which it can be saved supports comments. "
                                      "Do you want to discard the comments and save in the format you chose?");
        msg_dialog.setStandardButtons(QMessageBox::Cancel);
        msg_dialog.addButton("Discard comments and save", QMessageBox::DestructiveRole);
        msg_dialog.setDefaultButton(QMessageBox::Cancel);
    }

    response = msg_dialog.exec();

    switch (response) {

    case QMessageBox::Save:
      /* OK, the only other format we support is pcap-ng.  Make that
         the one and only format in the combo box, and return to
         let the user continue with the dialog.

         XXX - removing all the formats from the combo box will clear
         the compressed checkbox; get the current value and restore
         it.

         XXX - we know pcap-ng can be compressed; if we ever end up
         supporting saving comments in a format that *can't* be
         compressed, such as NetMon format, we must check this. */
      /* XXX - need a compressed checkbox here! */
      return SAVE_IN_ANOTHER_FORMAT;

    case QMessageBox::Discard:
      /* Save without the comments and, if that succeeds, delete the
         comments. */
      return SAVE_WITHOUT_COMMENTS;

    case QMessageBox::Cancel:
    default:
      /* Just give up. */
      break;
    }
    return CANCELLED;
#endif // Q_WS_WIN
}

void CaptureFileDialog::addPreview(QVBoxLayout &v_box) {
    QGridLayout *preview_grid = new QGridLayout();
    QLabel *lbl;

    preview_labels_.clear();
    v_box.addLayout(preview_grid);

    preview_grid->setColumnStretch(0, 0);
    preview_grid->setColumnStretch(1, 10);

    lbl = new QLabel("Format:");
    preview_grid->addWidget(lbl, 0, 0);
    preview_grid->addWidget(&preview_format_, 0, 1);
    preview_labels_ << lbl << &preview_format_;

    lbl = new QLabel("Size:");
    preview_grid->addWidget(lbl, 1, 0);
    preview_grid->addWidget(&preview_size_, 1, 1);
    preview_labels_ << lbl << &preview_size_;

    lbl = new QLabel("Packets:");
    preview_grid->addWidget(lbl, 2, 0);
    preview_grid->addWidget(&preview_packets_, 2, 1);
    preview_labels_ << lbl << &preview_packets_;

    lbl = new QLabel("First Packet:");
    preview_grid->addWidget(lbl, 3, 0);
    preview_grid->addWidget(&preview_first_, 3, 1);
    preview_labels_ << lbl << &preview_first_;

    lbl = new QLabel("Elapsed Time:");
    preview_grid->addWidget(lbl, 4, 0);
    preview_grid->addWidget(&preview_elapsed_, 4, 1);
    preview_labels_ << lbl << &preview_elapsed_;

    connect(this, SIGNAL(currentChanged(const QString &)), this, SLOT(preview(const QString &)));

    preview("");
}

void CaptureFileDialog::addMergeControls(QVBoxLayout &v_box) {

    merge_prepend_.setText("Prepend packets");
    merge_prepend_.setToolTip("Insert packets from the selected file before the current file. Packet timestamps will be ignored.");
    v_box.addWidget(&merge_prepend_);

    merge_chrono_.setText("Merge chronologically");
    merge_chrono_.setToolTip("Insert packets in chronological order.");
    merge_chrono_.setChecked(true);
    v_box.addWidget(&merge_chrono_);

    merge_append_.setText("Append packets");
    merge_append_.setToolTip("Insert packets from the selected file after the current file. Packet timestamps will be ignored.");
    v_box.addWidget(&merge_append_);
}

// You have to use open, merge, saveAs, or exportPackets. We should
// probably just make each type a subclass.
int CaptureFileDialog::exec() {
    return QDialog::Rejected;
}

QString CaptureFileDialog::fileType(int ft, bool extension_globs)
{
    QString filter;
    GSList *extensions_list, *extension;

    filter = wtap_file_type_string(ft);

    if (!extension_globs) {
        return filter;
    }

    filter += " (";

    extensions_list = wtap_get_file_extensions_list(ft, TRUE);
    if (extensions_list == NULL) {
        /* This file type doesn't have any particular extension
           conventionally used for it, so we'll just use "*.*"
           as the pattern; on Windows, that matches all file names
           - even those with no extension -  so we don't need to
           worry about compressed file extensions.  (It does not
           do so on UN*X; the right pattern on UN*X would just
           be "*".) */
           filter += "*.*";
    } else {
        /* Construct the list of patterns. */
        for (extension = extensions_list; extension != NULL;
             extension = g_slist_next(extension)) {
            if (!filter.endsWith('('))
                filter += ' ';
            filter += "*.";
            filter += (char *)extension->data;
        }
        wtap_free_file_extensions_list(extensions_list);
    }
    filter += ')';
    return filter;
    /* XXX - does QStringList's destructor destroy the strings in the list? */
}

QStringList CaptureFileDialog::buildFileOpenTypeList() {
    QStringList filters;
    int   ft;

    /* Add the "All Files" entry. */
    filters << QString(tr("All Files (*.*)"));

    /* Include all the file types Wireshark supports. */
    for (ft = 0; ft < WTAP_NUM_FILE_TYPES; ft++) {
        if (ft == WTAP_FILE_UNKNOWN)
            continue;  /* not a real file type */

        filters << fileType(ft);
    }

    return filters;
}


// Windows
#ifdef Q_WS_WIN
int CaptureFileDialog::selectedFileType() {
    return file_type_;
}

bool CaptureFileDialog::isCompressed() {
    return compressed_;
}

int CaptureFileDialog::open(QString &file_name) {
    GString *fname = g_string_new(file_name.toUtf8().constData());
    GString *dfilter = g_string_new(display_filter_.toUtf8().constData());
    gboolean wof_status;

    wof_status = win32_open_file(parentWidget()->effectiveWinId(), fname, dfilter);
    file_name = fname->str;
    display_filter_ = dfilter->str;

    g_string_free(fname, TRUE);
    g_string_free(dfilter, TRUE);

    return (int) wof_status;
}

check_savability_t CaptureFileDialog::saveAs(capture_file *cf, QString &file_name, bool must_support_comments) {
    GString *fname = g_string_new(file_name.toUtf8().constData());
    gboolean wsf_status;

    wsf_status = win32_save_as_file(parentWidget()->effectiveWinId(), cf, fname, &file_type_, &compressed_, must_support_comments);
    file_name = fname->str;

    g_string_free(fname, TRUE);

    if (wsf_status) {
        return win32_check_save_as_with_comments(parentWidget()->effectiveWinId(), cf, file_type_);
    }

    return CANCELLED;
}

int CaptureFileDialog::merge(QString &file_name) {
    GString *fname = g_string_new(file_name.toUtf8().constData());
    GString *dfilter = g_string_new(display_filter_.toUtf8().constData());
    gboolean wmf_status;

    wmf_status = win32_merge_file(parentWidget()->effectiveWinId(), fname, dfilter, &merge_type_);
    file_name = fname->str;
    display_filter_ = dfilter->str;

    g_string_free(fname, TRUE);
    g_string_free(dfilter, TRUE);

    return (int) wmf_status;
}

int CaptureFileDialog::mergeType() {
    return merge_type_;
}

#else // not Q_WS_WINDOWS
int CaptureFileDialog::selectedFileType() {
    return type_hash_.value(selectedNameFilter(), -1);
}

bool CaptureFileDialog::isCompressed() {
    return compress_.isChecked();
}

void CaptureFileDialog::addDisplayFilterEdit() {
    QGridLayout *fd_grid = qobject_cast<QGridLayout*>(layout());

    fd_grid->addWidget(new QLabel(tr("Display Filter:")), df_row_, 0, 1, 1);

    display_filter_edit_ = new DisplayFilterEdit(this, true);
    display_filter_edit_->setText(display_filter_);
    fd_grid->addWidget(display_filter_edit_, df_row_, 1, 1, 1);

}

void CaptureFileDialog::addResolutionControls(QVBoxLayout &v_box) {
    mac_res_.setText(tr("&MAC name resolution"));
    mac_res_.setChecked(gbl_resolv_flags.mac_name);
    v_box.addWidget(&mac_res_);

    transport_res_.setText(tr("&Transport name resolution"));
    transport_res_.setChecked(gbl_resolv_flags.transport_name);
    v_box.addWidget(&transport_res_);

    network_res_.setText(tr("&Network name resolution"));
    network_res_.setChecked(gbl_resolv_flags.network_name);
    v_box.addWidget(&network_res_);

    external_res_.setText(tr("&External name resolver"));
    external_res_.setChecked(gbl_resolv_flags.use_external_net_name_resolver);
    v_box.addWidget(&external_res_);
}

void CaptureFileDialog::addGzipControls(QVBoxLayout &v_box, capture_file *cf) {
    compress_.setText(tr("Compress with g&zip"));
    if (cf->iscompressed && wtap_dump_can_compress(default_ft_)) {
        compress_.setChecked(true);
    } else {
        compress_.setChecked(false);
    }
    v_box.addWidget(&compress_);

}

int CaptureFileDialog::open(QString &file_name) {
    setWindowTitle(tr("Wireshark: Open Capture File"));
    setNameFilters(buildFileOpenTypeList());
    setFileMode(QFileDialog::ExistingFile);

    addDisplayFilterEdit();
    addResolutionControls(left_v_box_);
    addPreview(right_v_box_);

    // Grow the dialog to account for the extra widgets.
    resize(width(), height() + left_v_box_.minimumSize().height() + display_filter_edit_->minimumSize().height());

    display_filter_.clear();

    if (!file_name.isEmpty()) {
        selectFile(file_name);
    }

    if (QFileDialog::exec() && selectedFiles().length() > 0) {
        file_name = selectedFiles()[0];
        display_filter_.append(display_filter_edit_->text());

        gbl_resolv_flags.mac_name = mac_res_.isChecked();
        gbl_resolv_flags.transport_name = transport_res_.isChecked();
        gbl_resolv_flags.network_name = network_res_.isChecked();
        gbl_resolv_flags.use_external_net_name_resolver = external_res_.isChecked();

        return QDialog::Accepted;
    } else {
        return QDialog::Rejected;
    }
}

check_savability_t CaptureFileDialog::saveAs(capture_file *cf, QString &file_name, bool must_support_comments) {
    setWindowTitle(tr("Wireshark: Save Capture File As"));
    // XXX There doesn't appear to be a way to use setNameFilters without restricting
    // what the user can select. We might want to use our own combobox instead and
    // let the user select anything.
    setNameFilters(buildFileSaveAsTypeList(cf, must_support_comments));
    setAcceptMode(QFileDialog::AcceptSave);
    setLabelText(FileType, "Save as:");

    addGzipControls(left_v_box_, cf);

    // Grow the dialog to account for the extra widgets.
    resize(width(), height() + left_v_box_.minimumSize().height());

    if (!file_name.isEmpty()) {
        selectFile(file_name);
    }

    if (QFileDialog::exec() && selectedFiles().length() > 0) {
        file_name = selectedFiles()[0];
        return checkSaveAsWithComments(this, cf, selectedFileType());
    }
    return CANCELLED;
}

int CaptureFileDialog::merge(QString &file_name) {
    setWindowTitle(tr("Wireshark: Merge Capture File"));
    setNameFilters(buildFileOpenTypeList());
    setFileMode(QFileDialog::ExistingFile);

    addDisplayFilterEdit();
    addMergeControls(left_v_box_);
    addPreview(right_v_box_);

    file_name.clear();
    display_filter_.clear();

    // Grow the dialog to account for the extra widgets.
    resize(width(), height() + right_v_box_.minimumSize().height() + display_filter_edit_->minimumSize().height());

    if (QFileDialog::exec() && selectedFiles().length() > 0) {
        file_name.append(selectedFiles()[0]);
        display_filter_.append(display_filter_edit_->text());

        return QDialog::Accepted;
    } else {
        return QDialog::Rejected;
    }
}

QStringList CaptureFileDialog::buildFileSaveAsTypeList(capture_file *cf, bool must_support_comments) {
    QStringList filters;
    GArray *savable_file_types;
    guint i;
    int ft;

    type_hash_.clear();
    savable_file_types = wtap_get_savable_file_types(cf->cd_t, cf->linktypes);

    if (savable_file_types != NULL) {
        QString file_type;
        /* OK, we have at least one file type we can save this file as.
           (If we didn't, we shouldn't have gotten here in the first
           place.)  Add them all to the combo box.  */
        for (i = 0; i < savable_file_types->len; i++) {
            ft = g_array_index(savable_file_types, int, i);
            if (must_support_comments) {
                if (ft != WTAP_FILE_PCAPNG)
                    continue;
            }
            if (default_ft_ < 1)
                default_ft_ = ft; /* first file type is the default */
            file_type = fileType(ft);
            filters << file_type;
            type_hash_[file_type] = ft;
        }
        g_array_free(savable_file_types, TRUE);
    }

    return filters;
}

int CaptureFileDialog::mergeType() {
    if (merge_prepend_.isChecked())
        return -1;
    else if (merge_append_.isChecked())
        return 1;

    return 0;
}
#endif // Q_WS_WINDOWS


/* do a preview run on the currently selected capture file */
void CaptureFileDialog::preview(const QString & path)
{
    wtap        *wth;
    int          err = 0;
    gchar       *err_info;
    gint64       data_offset;
    const struct wtap_pkthdr *phdr;
    double       start_time = 0; /* seconds, with nsec resolution */
    double       stop_time = 0;  /* seconds, with nsec resolution */
    double       cur_time;
    unsigned int packets = 0;
    bool         timed_out = FALSE;
    time_t       time_preview;
    time_t       time_current;
    time_t       ti_time;
    struct tm   *ti_tm;
    unsigned int elapsed_time;

    // Follow the same steps as ui/win32/file_dlg_win32.c

    foreach (QLabel *lbl, preview_labels_) {
        lbl->setEnabled(false);
    }

    preview_format_.setText(tr("-"));
    preview_size_.setText(tr("-"));
    preview_packets_.setText(tr("-"));
    preview_first_.setText(tr("-"));
    preview_elapsed_.setText(tr("-"));

    if (path.length() < 1) {
        return;
    }

    if (test_for_directory(path.toUtf8().data()) == EISDIR) {
        preview_format_.setText(tr("directory"));
        return;
    }

    wth = wtap_open_offline(path.toUtf8().data(), &err, &err_info, TRUE);
    if (wth == NULL) {
        if(err == WTAP_ERR_FILE_UNKNOWN_FORMAT) {
            preview_format_.setText(tr("unknown file format"));
        } else {
            preview_format_.setText(tr("error opening file"));
        }
        return;
    }

    // Success!
    foreach (QLabel *lbl, preview_labels_) {
        lbl->setEnabled(true);
    }

    // Format
    preview_format_.setText(QString::fromUtf8(wtap_file_type_string(wtap_file_type(wth))));

    // Size
    preview_size_.setText(QString("%1 bytes").arg(wtap_file_size(wth, &err)));

    time(&time_preview);
    while ( (wtap_read(wth, &err, &err_info, &data_offset)) ) {
        phdr = wtap_phdr(wth);
        cur_time = wtap_nstime_to_sec(&phdr->ts);
        if(packets == 0) {
            start_time = cur_time;
            stop_time = cur_time;
        }
        if (cur_time < start_time) {
            start_time = cur_time;
        }
        if (cur_time > stop_time){
            stop_time = cur_time;
        }

        packets++;
        if(packets%1000 == 0) {
            /* do we have a timeout? */
            time(&time_current);
            if(time_current-time_preview >= (time_t) prefs.gui_fileopen_preview) {
                timed_out = TRUE;
                break;
            }
        }
    }

    if(err != 0) {
        preview_packets_.setText(QString("error after reading %1 packets").arg(packets));
        return;
    }

    // Packet count
    if(timed_out) {
        preview_packets_.setText(QString("more than %1 (preview timeout)").arg(packets));
    } else {
        preview_packets_.setText(QString("%1").arg(packets));
    }

    // First packet
    ti_time = (long)start_time;
    ti_tm = localtime( &ti_time );
    if(ti_tm) {
        preview_first_.setText(QString().sprintf(
                 "%04d-%02d-%02d %02d:%02d:%02d",
                 ti_tm->tm_year + 1900,
                 ti_tm->tm_mon + 1,
                 ti_tm->tm_mday,
                 ti_tm->tm_hour,
                 ti_tm->tm_min,
                 ti_tm->tm_sec
                 ));
    } else {
        preview_first_.setText(tr("?"));
    }

    // Elapsed time
    elapsed_time = (unsigned int)(stop_time-start_time);
    if(timed_out) {
        preview_elapsed_.setText(tr("unknown"));
    } else if(elapsed_time/86400) {
        preview_elapsed_.setText(QString().sprintf("%02u days %02u:%02u:%02u",
                elapsed_time/86400, elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60));
    } else {
        preview_elapsed_.setText(QString().sprintf("%02u:%02u:%02u",
                elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60));
    }

    wtap_close(wth);
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
