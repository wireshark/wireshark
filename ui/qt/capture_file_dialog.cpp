/* capture_file_dialog.cpp
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

#include <wiretap/wtap.h>

#include "packet_range_group_box.h"
#include "capture_file_dialog.h"

#ifdef Q_OS_WIN
#include <windows.h>
#include "ui/packet_range.h"
#include "ui/win32/file_dlg_win32.h"
#else // Q_OS_WIN

#include <errno.h>
#include "file.h"
#include "wsutil/filesystem.h"
#include "wsutil/nstime.h"
#include "wsutil/str_util.h"
#include "wsutil/utf8_entities.h"

#include "ui/all_files_wildcard.h"

#include <QCheckBox>
#include <QFileInfo>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QSortFilterProxyModel>
#include <QSpacerItem>
#include <QVBoxLayout>
#endif // ! Q_OS_WIN

#include <QPushButton>
#include "epan/prefs.h"
#include "qt_ui_utils.h"
#include <wireshark_application.h>

CaptureFileDialog::CaptureFileDialog(QWidget *parent, capture_file *cf, QString &display_filter) :
    QFileDialog(parent),
    cap_file_(cf),
    display_filter_(display_filter),
#if !defined(Q_OS_WIN)
    display_filter_edit_(NULL),
    default_ft_(-1),
    save_bt_(NULL),
    help_topic_(TOPIC_ACTION_NONE)
#else
    file_type_(-1)
#endif
{
    switch (prefs.gui_fileopen_style) {
    case FO_STYLE_LAST_OPENED:
        /* The user has specified that we should start out in the last directory
         * we looked in.  If we've already opened a file, use its containing
         * directory, if we could determine it, as the directory, otherwise
         * use the "last opened" directory saved in the preferences file if
         * there was one.
         */
        setDirectory(wsApp->lastOpenDir());
        break;

    case FO_STYLE_SPECIFIED:
        /* The user has specified that we should always start out in a
         * specified directory; if they've specified that directory,
         * start out by showing the files in that dir.
         */
        if (prefs.gui_fileopen_dir[0] != '\0')
            setDirectory(prefs.gui_fileopen_dir);
        break;
    }

#if !defined(Q_OS_WIN)
    // Add extra widgets
    // https://wiki.qt.io/Qt_project_org_faq#How_can_I_add_widgets_to_my_QFileDialog_instance.3F
    setOption(QFileDialog::DontUseNativeDialog, true);
    setOption(QFileDialog::HideNameFilterDetails, true);
    QGridLayout *fd_grid = qobject_cast<QGridLayout*>(layout());
    QHBoxLayout *h_box = new QHBoxLayout();

    last_row_ = fd_grid->rowCount();

    fd_grid->addItem(new QSpacerItem(1, 1), last_row_, 0);
    fd_grid->addLayout(h_box, last_row_, 0, 1, 2);
    last_row_++;

    // Left and right boxes for controls and preview
    h_box->addLayout(&left_v_box_);
    h_box->addLayout(&right_v_box_);

#else // Q_OS_WIN
    merge_type_ = 0;
#endif // Q_OS_WIN
}

check_savability_t CaptureFileDialog::checkSaveAsWithComments(QWidget *
#if defined(Q_OS_WIN)
        parent
#endif
        , capture_file *cf, int file_type) {
#if defined(Q_OS_WIN)
    if (!parent || !cf)
        return CANCELLED;
    return win32_check_save_as_with_comments((HWND)parent->effectiveWinId(), cf, file_type);
#else // Q_OS_WIN
    guint32 comment_types;

    /* What types of comments do we have? */
    comment_types = cf_comment_types(cf);

    /* Does the file's format support all the comments we have? */
    if (wtap_dump_supports_comment_types(file_type, comment_types)) {
        /* Yes.  Let the save happen; we can save all the comments, so
           there's no need to delete them. */
        return SAVE;
    }

    QMessageBox msg_dialog;
    QPushButton *save_button;
    QPushButton *discard_button;

    msg_dialog.setIcon(QMessageBox::Question);
    msg_dialog.setText(tr("This capture file contains comments."));
    msg_dialog.setStandardButtons(QMessageBox::Cancel);

    /* No. Are there formats in which we can write this file that
       supports all the comments in this file? */
    if (wtap_dump_can_write(cf->linktypes, comment_types)) {
        /* Yes.  Offer the user a choice of "Save in a format that
           supports comments", "Discard comments and save in the
           format you selected", or "Cancel", meaning "don't bother
           saving the file at all". */
        msg_dialog.setInformativeText(tr("The file format you chose doesn't support comments. "
                                         "Do you want to save the capture in a format that supports comments "
                                         "or discard the comments and save in the format you chose?"));
        // The predefined roles don't really match the tasks at hand...
        discard_button = msg_dialog.addButton(tr("Discard comments and save"), QMessageBox::DestructiveRole);
        save_button = msg_dialog.addButton(tr("Save in another format"), QMessageBox::AcceptRole);
        msg_dialog.setDefaultButton(save_button);
    } else {
        /* No.  Offer the user a choice of "Discard comments and
           save in the format you selected" or "Cancel". */
        msg_dialog.setInformativeText(tr("No file format in which it can be saved supports comments. "
                                         "Do you want to discard the comments and save in the format you chose?"));
        save_button = NULL;
        discard_button = msg_dialog.addButton(tr("Discard comments and save"), QMessageBox::DestructiveRole);
        msg_dialog.setDefaultButton(QMessageBox::Cancel);
    }

    discard_button->setAutoDefault(false);
    discard_button->setFocus();

    msg_dialog.exec();
    /* According to the Qt doc:
     * when using QMessageBox with custom buttons, exec() function returns an opaque value.
     *
     * Therefore we should use clickedButton() to determine which button was clicked. */

    if (msg_dialog.clickedButton() == save_button) {
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

    } else if (msg_dialog.clickedButton() == discard_button) {
      /* Save without the comments and, if that succeeds, delete the
         comments. */
      return SAVE_WITHOUT_COMMENTS;
    }

    /* Just give up. */
    return CANCELLED;
#endif // Q_OS_WIN
}


// You have to use open, merge, saveAs, or exportPackets. We should
// probably just make each type a subclass.
int CaptureFileDialog::exec() {
    return QDialog::Rejected;
}



// Windows
// We use native file dialogs here, rather than the Qt dialog
#ifdef Q_OS_WIN
int CaptureFileDialog::selectedFileType() {
    return file_type_;
}

bool CaptureFileDialog::isCompressed() {
    return compressed_;
}

int CaptureFileDialog::open(QString &file_name, unsigned int &type) {
    GString *fname = g_string_new(file_name.toUtf8().constData());
    GString *dfilter = g_string_new(display_filter_.toUtf8().constData());
    gboolean wof_status;

    // XXX Add a widget->HWND routine to qt_ui_utils and use it instead.
    wof_status = win32_open_file((HWND)parentWidget()->effectiveWinId(), fname, &type, dfilter);
    file_name = fname->str;
    display_filter_ = dfilter->str;

    g_string_free(fname, TRUE);
    g_string_free(dfilter, TRUE);

    return (int) wof_status;
}

check_savability_t CaptureFileDialog::saveAs(QString &file_name, bool must_support_all_comments) {
    GString *fname = g_string_new(file_name.toUtf8().constData());
    gboolean wsf_status;

    wsf_status = win32_save_as_file((HWND)parentWidget()->effectiveWinId(), cap_file_, fname, &file_type_, &compressed_, must_support_all_comments);
    file_name = fname->str;

    g_string_free(fname, TRUE);

    if (wsf_status) {
        return win32_check_save_as_with_comments((HWND)parentWidget()->effectiveWinId(), cap_file_, file_type_);
    }

    return CANCELLED;
}

check_savability_t CaptureFileDialog::exportSelectedPackets(QString &file_name, packet_range_t *range) {
    GString *fname = g_string_new(file_name.toUtf8().constData());
    gboolean wespf_status;

    wespf_status = win32_export_specified_packets_file((HWND)parentWidget()->effectiveWinId(), cap_file_, fname, &file_type_, &compressed_, range);
    file_name = fname->str;

    g_string_free(fname, TRUE);

    if (wespf_status) {
        return win32_check_save_as_with_comments((HWND)parentWidget()->effectiveWinId(), cap_file_, file_type_);
    }

    return CANCELLED;
}

int CaptureFileDialog::merge(QString &file_name) {
    GString *fname = g_string_new(file_name.toUtf8().constData());
    GString *dfilter = g_string_new(display_filter_.toUtf8().constData());
    gboolean wmf_status;

    wmf_status = win32_merge_file((HWND)parentWidget()->effectiveWinId(), fname, dfilter, &merge_type_);
    file_name = fname->str;
    display_filter_ = dfilter->str;

    g_string_free(fname, TRUE);
    g_string_free(dfilter, TRUE);

    return (int) wmf_status;
}

int CaptureFileDialog::mergeType() {
    return merge_type_;
}

#else // not Q_OS_WINDOWS
// Not Windows
// We use the Qt dialogs here
QString CaptureFileDialog::fileExtensionType(int et, bool extension_globs)
{
    QString extension_type_name;
    QStringList all_wildcards;
    QStringList nogz_wildcards;
    GSList *extensions_list;
    GSList *extension;

    extension_type_name = wtap_get_file_extension_type_name(et);

    if (!extension_globs) {
        return extension_type_name;
    }

    extensions_list = wtap_get_file_extension_type_extensions(et);

    /* Construct the list of patterns. */
    for (extension = extensions_list; extension != NULL;
         extension = g_slist_next(extension)) {
        QString bare_wc = QString("*.%1").arg((char *)extension->data);
        all_wildcards << bare_wc;
        if (!bare_wc.endsWith(".gz")) {
            nogz_wildcards << bare_wc;
        }
    }
    wtap_free_extensions_list(extensions_list);

    // We set HideNameFilterDetails so that "All Files" and "All Capture
    // Files" don't show a wildcard list. We want to show the associated
    // wildcards for individual file types so we add them twice.
    return QString("%1 (%2) (%3)")
            .arg(extension_type_name)
            .arg(nogz_wildcards.join(" "))
            .arg(all_wildcards.join(" "));
}

QString CaptureFileDialog::fileType(int ft, bool extension_globs)
{
    QString filter;
    GSList *extensions_list;

    filter = wtap_file_type_subtype_string(ft);

    if (!extension_globs) {
        return filter;
    }

    filter += " (";

    extensions_list = wtap_get_file_extensions_list(ft, TRUE);
    if (extensions_list == NULL) {
        /* This file type doesn't have any particular extension
           conventionally used for it, so we'll just use a
           wildcard that matches all file names - even those
           with no extension, so we don't need to worry about
           compressed file extensions. */
           filter += ALL_FILES_WILDCARD;
    } else {
        GSList *extension;
        /* Construct the list of patterns. */
        for (extension = extensions_list; extension != NULL;
             extension = g_slist_next(extension)) {
            if (!filter.endsWith('('))
                filter += ' ';
            filter += "*.";
            filter += (char *)extension->data;
        }
        wtap_free_extensions_list(extensions_list);
    }
    filter += ')';
    return filter;
    /* XXX - does QStringList's destructor destroy the strings in the list? */
}

QStringList CaptureFileDialog::buildFileOpenTypeList() {
    QStringList filters;
    QString filter, sep;
    GSList *extensions_list;
    GSList *extension;
    int   et;

    /*
     * Microsoft's UI guidelines say, of the file filters in open and
     * save dialogs:
     *
     *    For meta-filters, remove the file extension list to eliminate
     *    clutter. Examples: "All files," "All pictures," "All music,"
     *    and "All videos."
     *
     * On both Windows XP and Windows 7, Wordpad doesn't do that, but
     * Paint does.
     *
     * XXX - on Windows, does Qt do that here?  For "All Capture Files",
     * the filter will be a bit long, so it *really* shouldn't be shown.
     * What about other platforms?
     */
    filters << QString(tr("All Files (" ALL_FILES_WILDCARD ")"));

    /*
     * Add an "All Capture Files" entry, with all the capture file
     * extensions we know about.
     */
    filter = tr("All Capture Files");

    /*
     * Construct its list of patterns.
     */
    extensions_list = wtap_get_all_capture_file_extensions_list();
    sep = " (";
    for (extension = extensions_list; extension != NULL;
         extension = g_slist_next(extension)) {
        filter += sep;
        filter += "*.";
        filter += (char *)extension->data;
        sep = " ";
    }
    wtap_free_extensions_list(extensions_list);
    filter += ")";
    filters << filter;

    /* Include all the file types Wireshark supports. */
    for (et = 0; et < wtap_get_num_file_type_extensions(); et++) {
        filters << fileExtensionType(et);
    }

    return filters;
}

void CaptureFileDialog::addPreview(QVBoxLayout &v_box) {
    QGridLayout *preview_grid = new QGridLayout();
    QLabel *lbl;

    preview_labels_.clear();
    v_box.addLayout(preview_grid);

    preview_grid->setColumnStretch(0, 0);
    preview_grid->setColumnStretch(1, 10);

    lbl = new QLabel(tr("Format:"));
    preview_grid->addWidget(lbl, 0, 0);
    preview_grid->addWidget(&preview_format_, 0, 1);
    preview_labels_ << lbl << &preview_format_;

    lbl = new QLabel(tr("Size:"));
    preview_grid->addWidget(lbl, 1, 0);
    preview_grid->addWidget(&preview_size_, 1, 1);
    preview_labels_ << lbl << &preview_size_;

    lbl = new QLabel(tr("Start / elapsed:"));
    preview_grid->addWidget(lbl, 3, 0);
    preview_grid->addWidget(&preview_first_elapsed_, 3, 1);
    preview_labels_ << lbl << &preview_first_elapsed_;

    connect(this, SIGNAL(currentChanged(const QString &)), this, SLOT(preview(const QString &)));

    preview("");
}

void CaptureFileDialog::addMergeControls(QVBoxLayout &v_box) {

    merge_prepend_.setText(tr("Prepend packets"));
    merge_prepend_.setToolTip(tr("Insert packets from the selected file before the current file. Packet timestamps will be ignored."));
    v_box.addWidget(&merge_prepend_, 0, Qt::AlignTop);

    merge_chrono_.setText(tr("Merge chronologically"));
    merge_chrono_.setToolTip(tr("Insert packets in chronological order."));
    merge_chrono_.setChecked(true);
    v_box.addWidget(&merge_chrono_, 0, Qt::AlignTop);

    merge_append_.setText(tr("Append packets"));
    merge_append_.setToolTip(tr("Insert packets from the selected file after the current file. Packet timestamps will be ignored."));
    v_box.addWidget(&merge_append_, 0, Qt::AlignTop);
}

int CaptureFileDialog::selectedFileType() {
    return type_hash_.value(selectedNameFilter(), -1);
}

bool CaptureFileDialog::isCompressed() {
    return compress_.isChecked();
}

void CaptureFileDialog::addDisplayFilterEdit() {
    QGridLayout *fd_grid = qobject_cast<QGridLayout*>(layout());

    fd_grid->addWidget(new QLabel(tr("Read filter:")), last_row_, 0);

    display_filter_edit_ = new DisplayFilterEdit(this, ReadFilterToApply);
    display_filter_edit_->setText(display_filter_);
    fd_grid->addWidget(display_filter_edit_, last_row_, 1);
    last_row_++;
}

void CaptureFileDialog::addFormatTypeSelector(QVBoxLayout &v_box) {
    format_type_.addItem(tr("Automatically detect file type"));
    for (int i = 0; open_routines[i].name != NULL; i += 1) {
        format_type_.addItem(open_routines[i].name);
    }

    v_box.addWidget(&format_type_, 0, Qt::AlignTop);
}

void CaptureFileDialog::addGzipControls(QVBoxLayout &v_box) {
    compress_.setText(tr("Compress with g&zip"));
    if (cap_file_->iscompressed && wtap_dump_can_compress(default_ft_)) {
        compress_.setChecked(true);
    } else {
        compress_.setChecked(false);
    }
    v_box.addWidget(&compress_, 0, Qt::AlignTop);

}

void CaptureFileDialog::addRangeControls(QVBoxLayout &v_box, packet_range_t *range) {
    packet_range_group_box_.initRange(range);
    v_box.addWidget(&packet_range_group_box_, 0, Qt::AlignTop);
}

QDialogButtonBox *CaptureFileDialog::addHelpButton(topic_action_e help_topic)
{
    // This doesn't appear to be documented anywhere but it seems pretty obvious
    // and it works.
    QDialogButtonBox *button_box = findChild<QDialogButtonBox *>();

    help_topic_ = help_topic;

    if (button_box) {
        button_box->addButton(QDialogButtonBox::Help);
        connect(button_box, SIGNAL(helpRequested()), this, SLOT(on_buttonBox_helpRequested()));
    }
    return button_box;
}

int CaptureFileDialog::open(QString &file_name, unsigned int &type) {
    setWindowTitle(wsApp->windowTitleString(tr("Open Capture File")));
    setNameFilters(buildFileOpenTypeList());
    setFileMode(QFileDialog::ExistingFile);

    addFormatTypeSelector(left_v_box_);
    addDisplayFilterEdit();
    addPreview(right_v_box_);
    addHelpButton(HELP_OPEN_DIALOG);

    // Grow the dialog to account for the extra widgets.
    resize(width(), height() + left_v_box_.minimumSize().height() + display_filter_edit_->minimumSize().height());

    display_filter_.clear();

    if (!file_name.isEmpty()) {
        selectFile(file_name);
    }

    if (QFileDialog::exec() && selectedFiles().length() > 0) {
        file_name = selectedFiles()[0];
        type = format_type_.currentIndex();
        display_filter_.append(display_filter_edit_->text());

        return QDialog::Accepted;
    } else {
        return QDialog::Rejected;
    }
}

check_savability_t CaptureFileDialog::saveAs(QString &file_name, bool must_support_all_comments) {
    setWindowTitle(wsApp->windowTitleString(tr("Save Capture File As")));
    // XXX There doesn't appear to be a way to use setNameFilters without restricting
    // what the user can select. We might want to use our own combobox instead and
    // let the user select anything.
    setNameFilters(buildFileSaveAsTypeList(must_support_all_comments));
    setAcceptMode(QFileDialog::AcceptSave);
    setLabelText(FileType, tr("Save as:"));

    addGzipControls(left_v_box_);
    addHelpButton(HELP_SAVE_DIALOG);

    // Grow the dialog to account for the extra widgets.
    resize(width(), height() + left_v_box_.minimumSize().height());

    if (!file_name.isEmpty()) {
        selectFile(file_name);
    }

    if (QFileDialog::exec() && selectedFiles().length() > 0) {
        file_name = selectedFiles()[0];
        return checkSaveAsWithComments(this, cap_file_, selectedFileType());
    }
    return CANCELLED;
}

check_savability_t CaptureFileDialog::exportSelectedPackets(QString &file_name, packet_range_t *range) {
    QDialogButtonBox *button_box;

    setWindowTitle(wsApp->windowTitleString(tr("Export Specified Packets")));
    // XXX See comment in ::saveAs regarding setNameFilters
    setNameFilters(buildFileSaveAsTypeList(false));
    setAcceptMode(QFileDialog::AcceptSave);
    setLabelText(FileType, tr("Export as:"));

    addRangeControls(left_v_box_, range);
    addGzipControls(right_v_box_);
    button_box = addHelpButton(HELP_EXPORT_FILE_DIALOG);

    if (button_box) {
        save_bt_ = button_box->button(QDialogButtonBox::Save);
        if (save_bt_) {
            connect(&packet_range_group_box_, SIGNAL(validityChanged(bool)),
                    save_bt_, SLOT(setEnabled(bool)));
        }
    }

    // Grow the dialog to account for the extra widgets.
    resize(width(), height() + (packet_range_group_box_.height() * 2 / 3));

    if (!file_name.isEmpty()) {
        selectFile(file_name);
    }

    if (QFileDialog::exec() && selectedFiles().length() > 0) {
        file_name = selectedFiles()[0];
        return checkSaveAsWithComments(this, cap_file_, selectedFileType());
    }
    return CANCELLED;
}

int CaptureFileDialog::merge(QString &file_name) {
    setWindowTitle(wsApp->windowTitleString(tr("Merge Capture File")));
    setNameFilters(buildFileOpenTypeList());
    setFileMode(QFileDialog::ExistingFile);

    addDisplayFilterEdit();
    addMergeControls(left_v_box_);
    addPreview(right_v_box_);
    addHelpButton(HELP_MERGE_DIALOG);

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

QStringList CaptureFileDialog::buildFileSaveAsTypeList(bool must_support_all_comments) {
    QStringList filters;
    guint32 required_comment_types;
    GArray *savable_file_types_subtypes;
    guint i;

    type_hash_.clear();

    /* What types of comments do we have to support? */
    if (must_support_all_comments)
        required_comment_types = cf_comment_types(cap_file_); /* all the ones the file has */
    else
        required_comment_types = 0; /* none of them */

  /* What types of file can we save this file as? */
    savable_file_types_subtypes = wtap_get_savable_file_types_subtypes(cap_file_->cd_t,
                                                                       cap_file_->linktypes,
                                                                       required_comment_types);

    if (savable_file_types_subtypes != NULL) {
        QString file_type;
        QString hash_file_type;
        int ft;
        /* OK, we have at least one file type we can save this file as.
           (If we didn't, we shouldn't have gotten here in the first
           place.)  Add them all to the combo box.  */
        for (i = 0; i < savable_file_types_subtypes->len; i++) {
            ft = g_array_index(savable_file_types_subtypes, int, i);
            if (default_ft_ < 1)
                default_ft_ = ft; /* first file type is the default */
            file_type = fileType(ft);
            hash_file_type = fileType(ft, false);
            filters << file_type;
            type_hash_[hash_file_type] = ft;
        }
        g_array_free(savable_file_types_subtypes, TRUE);
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

// Slots



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

    preview_format_.setText(tr(UTF8_EM_DASH));
    preview_size_.setText(tr(UTF8_EM_DASH));
    preview_first_elapsed_.setText(tr(UTF8_EM_DASH));

    if (path.length() < 1) {
        return;
    }

    if (test_for_directory(path.toUtf8().data()) == EISDIR) {
        preview_format_.setText(tr("directory"));
        return;
    }

    wth = wtap_open_offline(path.toUtf8().data(), WTAP_TYPE_AUTO, &err, &err_info, TRUE);
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
    preview_format_.setText(QString::fromUtf8(wtap_file_type_subtype_string(wtap_file_type_subtype(wth))));

    // Size
    gint64 filesize = wtap_file_size(wth, &err);
    // Finder and Windows Explorer use IEC. What do the various Linux file managers use?
    QString size_str(gchar_free_to_qstring(format_size(filesize, format_size_unit_bytes|format_size_prefix_iec)));

    time(&time_preview);
    while ((wtap_read(wth, &err, &err_info, &data_offset))) {
        phdr = wtap_phdr(wth);
        cur_time = nstime_to_sec(&phdr->ts);
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
        preview_size_.setText(tr("%1, error after %Ln packet(s)", "", packets)
                              .arg(size_str));
        return;
    }

    // Packet count
    if(timed_out) {
        preview_size_.setText(tr("%1, timed out at %Ln packet(s)", "", packets)
                              .arg(size_str));
    } else {
        preview_size_.setText(tr("%1, %Ln packet(s)", "", packets)
                              .arg(size_str));
    }

    // First packet + elapsed time
    ti_time = (long)start_time;
    ti_tm = localtime(&ti_time);
    QString first_elapsed = "?";
    if(ti_tm) {
        first_elapsed = QString().sprintf(
                 "%04d-%02d-%02d %02d:%02d:%02d",
                 ti_tm->tm_year + 1900,
                 ti_tm->tm_mon + 1,
                 ti_tm->tm_mday,
                 ti_tm->tm_hour,
                 ti_tm->tm_min,
                 ti_tm->tm_sec
                 );
    }

    // Elapsed time
    first_elapsed += " / ";
    elapsed_time = (unsigned int)(stop_time-start_time);
    if(timed_out) {
        first_elapsed += tr("unknown");
    } else if(elapsed_time/86400) {
        first_elapsed += QString().sprintf("%02u days %02u:%02u:%02u",
                elapsed_time/86400, elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60);
    } else {
        first_elapsed += QString().sprintf("%02u:%02u:%02u",
                elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60);
    }
    preview_first_elapsed_.setText(first_elapsed);

    wtap_close(wth);
}

void CaptureFileDialog::on_buttonBox_helpRequested()
{
    if (help_topic_ != TOPIC_ACTION_NONE) wsApp->helpTopicAction(help_topic_);
}

#endif // Q_OS_WINDOWS

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
