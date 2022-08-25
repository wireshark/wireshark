/* capture_file_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "file.h"

#include <wiretap/wtap.h>

#include "packet_range_group_box.h"
#include "capture_file_dialog.h"


#ifdef Q_OS_WIN
#include <windows.h>
#include "ui/packet_range.h"
#include "ui/win32/file_dlg_win32.h"
#else // Q_OS_WIN

#include <errno.h>
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
#include <QSortFilterProxyModel>
#include <QSpacerItem>
#include <QVBoxLayout>
#endif // ! Q_OS_WIN

#include <QPushButton>
#include <QMessageBox>

#include "epan/prefs.h"
#include <ui/qt/utils/qt_ui_utils.h>
#include <main_application.h>

static const double WIDTH_SCALE_FACTOR = 1.4;
static const double HEIGHT_SCALE_FACTOR = 1.4;

CaptureFileDialog::CaptureFileDialog(QWidget *parent, capture_file *cf) :
    WiresharkFileDialog(parent),
    cap_file_(cf),
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
        setDirectory(mainApp->lastOpenDir());
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

check_savability_t CaptureFileDialog::checkSaveAsWithComments(QWidget *parent, capture_file *cf, int file_type) {
    guint32 comment_types;
    bool all_comment_types_supported = true;

    /* What types of comments do we have? */
    comment_types = cf_comment_types(cf);

    /* Does the file's format support all the comments we have? */
    if (comment_types & WTAP_COMMENT_PER_SECTION) {
        if (wtap_file_type_subtype_supports_option(file_type,
                                                   WTAP_BLOCK_SECTION,
                                                   OPT_COMMENT) == OPTION_NOT_SUPPORTED)
            all_comment_types_supported = false;
    }
    if (comment_types & WTAP_COMMENT_PER_INTERFACE) {
        if (wtap_file_type_subtype_supports_option(file_type,
                                                   WTAP_BLOCK_IF_ID_AND_INFO,
                                                   OPT_COMMENT) == OPTION_NOT_SUPPORTED)
            all_comment_types_supported = false;
    }
    if (comment_types & WTAP_COMMENT_PER_PACKET) {
        if (wtap_file_type_subtype_supports_option(file_type,
                                                   WTAP_BLOCK_PACKET,
                                                   OPT_COMMENT) == OPTION_NOT_SUPPORTED)
            all_comment_types_supported = false;
    }
    if (all_comment_types_supported) {
        /* Yes.  Let the save happen; we can save all the comments, so
           there's no need to delete them. */
        return SAVE;
    }

    QMessageBox msg_dialog(parent);
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

#if defined(Q_OS_MAC)
    /*
     * In macOS, the "default button" is not necessarily the button that
     * has the input focus; Enter/Return activates the default button, and
     * the spacebar activates the button that has the input focus, and
     * they might be different buttons.
     *
     * In a "do you want to save" dialog, for example, the "save" button
     * is the default button, and the "don't save" button has the input
     * focus, so you can press Enter/Return to save or space not to save
     * (or Escape to dismiss the dialog).
     *
     * In Qt terms, this means "no auto-default", as auto-default makes the
     * button with the input focus the default button, so that Enter/Return
     * will activate it.
     */
    QList<QAbstractButton *> buttons = msg_dialog.buttons();
    for (int i = 0; i < buttons.size(); ++i) {
        QPushButton *button = static_cast<QPushButton *>(buttons.at(i));;
        button->setAutoDefault(false);
    }

    /*
     * It also means that the "don't save" button should be the one
     * initially given the focus.
     */
    discard_button->setFocus();
#endif

    msg_dialog.exec();
    /* According to the Qt doc:
     * when using QMessageBox with custom buttons, exec() function returns an opaque value.
     *
     * Therefore we should use clickedButton() to determine which button was clicked. */

    if (msg_dialog.clickedButton() == save_button) {
      /* OK, the only other format we support is pcapng.  Make that
         the one and only format in the combo box, and return to
         let the user continue with the dialog.

         XXX - removing all the formats from the combo box will clear
         the compressed checkbox; get the current value and restore
         it.

         XXX - we know pcapng can be compressed; if we ever end up
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
}


#ifndef Q_OS_WIN
void CaptureFileDialog::accept()
{
    //
    // If this is a dialog for writing files, we want to ensure that
    // the filename has a valid extension before performing file
    // existence checks and before closing the dialog.
    // This isn't necessary for dialogs for reading files; the name
    // has to exactly match the name of the file you want to open,
    // and doesn't need to be, and shouldn't be, modified.
    //
    // XXX also useful for Windows, but that uses a different dialog...
    //
    if (acceptMode() == QFileDialog::AcceptSave) {
        // HACK: ensure that the filename field does not have the focus,
        // otherwise selectFile will not change the filename.
        setFocus();
        fixFilenameExtension();
    }
    WiresharkFileDialog::accept();
}
#endif // ! Q_OS_WIN


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

wtap_compression_type CaptureFileDialog::compressionType() {
    return compression_type_;
}

int CaptureFileDialog::open(QString &file_name, unsigned int &type, QString &display_filter) {
    QString title_str = mainApp->windowTitleString(tr("Open Capture File"));
    GString *fname = g_string_new(file_name.toUtf8().constData());
    GString *dfilter = g_string_new(display_filter.toUtf8().constData());
    gboolean wof_status;

    // XXX Add a widget->HWND routine to qt_ui_utils and use it instead.
    wof_status = win32_open_file((HWND)parentWidget()->effectiveWinId(), title_str.toStdWString().c_str(), fname, &type, dfilter);
    file_name = fname->str;
    display_filter = dfilter->str;

    g_string_free(fname, TRUE);
    g_string_free(dfilter, TRUE);

    return (int) wof_status;
}

check_savability_t CaptureFileDialog::saveAs(QString &file_name, bool must_support_all_comments) {
    QString title_str = mainApp->windowTitleString(tr("Save Capture File As"));
    GString *fname = g_string_new(file_name.toUtf8().constData());
    gboolean wsf_status;

    wsf_status = win32_save_as_file((HWND)parentWidget()->effectiveWinId(), title_str.toStdWString().c_str(), cap_file_, fname, &file_type_, &compression_type_, must_support_all_comments);
    file_name = fname->str;

    g_string_free(fname, TRUE);

    if (wsf_status) {
        return checkSaveAsWithComments(parentWidget(), cap_file_, file_type_);
    }

    return CANCELLED;
}

check_savability_t CaptureFileDialog::exportSelectedPackets(QString &file_name, packet_range_t *range, QString selRange) {
    QString title_str = mainApp->windowTitleString(tr("Export Specified Packets"));
    GString *fname = g_string_new(file_name.toUtf8().constData());
    gboolean wespf_status;

    if (selRange.length() > 0)
    {
        packet_range_convert_selection_str(range, selRange.toUtf8().constData());
    }

    wespf_status = win32_export_specified_packets_file((HWND)parentWidget()->effectiveWinId(), title_str.toStdWString().c_str(), cap_file_, fname, &file_type_, &compression_type_, range);
    file_name = fname->str;

    g_string_free(fname, TRUE);

    if (wespf_status) {
        return checkSaveAsWithComments(parentWidget(), cap_file_, file_type_);
    }

    return CANCELLED;
}

int CaptureFileDialog::merge(QString &file_name, QString &display_filter) {
    QString title_str = mainApp->windowTitleString(tr("Merge Capture File"));
    GString *fname = g_string_new(file_name.toUtf8().constData());
    GString *dfilter = g_string_new(display_filter.toUtf8().constData());
    gboolean wmf_status;


    wmf_status = win32_merge_file((HWND)parentWidget()->effectiveWinId(), title_str.toStdWString().c_str(), fname, dfilter, &merge_type_);
    file_name = fname->str;
    display_filter = dfilter->str;

    g_string_free(fname, TRUE);
    g_string_free(dfilter, TRUE);

    return (int) wmf_status;
}

int CaptureFileDialog::mergeType() {
    return merge_type_;
}

#else // ! Q_OS_WIN
// Not Windows
// We use the Qt dialogs here
QString CaptureFileDialog::fileExtensionType(int et, bool extension_globs)
{
    QString extension_type_name;
    QStringList all_wildcards;
    QStringList no_compression_suffix_wildcards;
    GSList *extensions_list;
    GSList *extension;

    extension_type_name = wtap_get_file_extension_type_name(et);

    if (!extension_globs) {
        return extension_type_name;
    }

    extensions_list = wtap_get_file_extension_type_extensions(et);

    // Get the list of compression-type extensions.
    GSList *compression_type_extensions = wtap_get_all_compression_type_extensions_list();

    /* Construct the list of patterns. */
    for (extension = extensions_list; extension != NULL;
         extension = g_slist_next(extension)) {
        QString bare_wc = QString("*.%1").arg((char *)extension->data);
        all_wildcards << bare_wc;

        // Does this end with a compression suffix?
        bool ends_with_compression_suffix = false;
        for (GSList *compression_type_extension = compression_type_extensions;
            compression_type_extension != NULL;
            compression_type_extension = g_slist_next(compression_type_extension)) {
            QString suffix = QString(".") + (char *)compression_type_extension->data;
            if (bare_wc.endsWith(suffix)) {
                ends_with_compression_suffix = true;
                break;
            }
        }

        // If it doesn't, add it to the list of wildcards-without-
        // compression-suffixes.
        if (!ends_with_compression_suffix)
            no_compression_suffix_wildcards << bare_wc;
    }
    g_slist_free(compression_type_extensions);
    wtap_free_extensions_list(extensions_list);

    // We set HideNameFilterDetails so that "All Files" and "All Capture
    // Files" don't show a wildcard list. We want to show the associated
    // wildcards for individual file types so we add them twice.
    return QString("%1 (%2) (%3)")
            .arg(extension_type_name)
            .arg(no_compression_suffix_wildcards.join(" "))
            .arg(all_wildcards.join(" "));
}

// Returns " (...)", containing the suffix list suitable for setNameFilters.
// All extensions ("pcap", "pcap.gz", etc.) are also returned in "suffixes".
QString CaptureFileDialog::fileType(int ft, QStringList &suffixes)
{
    QString filter;
    GSList *extensions_list;

    filter = " (";

    extensions_list = wtap_get_file_extensions_list(ft, TRUE);
    if (extensions_list == NULL) {
        /* This file type doesn't have any particular extension
           conventionally used for it, so we'll just use a
           wildcard that matches all file names - even those
           with no extension, so we don't need to worry about
           compressed file extensions. */
           filter += ALL_FILES_WILDCARD;
    } else {
        // HACK: at least for Qt 5.10 and before, if the first extension is
        // empty ("."), it will prevent the default (broken) extension
        // replacement from being applied in the non-native Save file dialog.
        filter += '.';

        /* Construct the list of patterns. */
        for (GSList *extension = extensions_list; extension != NULL;
             extension = g_slist_next(extension)) {
            QString suffix((char *)extension->data);
            filter += " *." + suffix;;
            suffixes << suffix;
        }
        wtap_free_extensions_list(extensions_list);
    }
    filter += ')';
    return filter;
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

// Replaces or appends an extension based on the current file filter
// and compression setting.
// Used in dialogs that select a file to write.
void CaptureFileDialog::fixFilenameExtension()
{
    QFileInfo fi(selectedFiles()[0]);
    QString filename = fi.fileName();
    if (fi.isDir() || filename.isEmpty()) {
        // no file selected, or a directory was selected. Ignore.
        return;
    }

    QString old_suffix;
    QString new_suffix(wtap_default_file_extension(selectedFileType()));
    QStringList valid_extensions = type_suffixes_.value(selectedNameFilter());
    // Find suffixes such as "pcap" or "pcap.gz" if any
    if (!fi.suffix().isEmpty()) {
        QStringList current_suffixes(fi.suffix());
        int pos = static_cast<int>(filename.lastIndexOf('.', -2 - current_suffixes.at(0).size()));
        if (pos > 0) {
            current_suffixes.prepend(filename.right(filename.size() - (pos + 1)));
        }

        // If the current suffix is valid for the current file type, try to
        // preserve it. Otherwise use the default file extension (if available).
        foreach (const QString &current_suffix, current_suffixes) {
            if (valid_extensions.contains(current_suffix)) {
                old_suffix = current_suffix;
                new_suffix = current_suffix;
                break;
            }
        }
        if (old_suffix.isEmpty()) {
            foreach (const QString &current_suffix, current_suffixes) {
                foreach (const QStringList &suffixes, type_suffixes_.values()) {
                    if (suffixes.contains(current_suffix)) {
                        old_suffix = current_suffix;
                        break;
                    }
                }
                if (!old_suffix.isEmpty()) {
                    break;
                }
            }
        }
    }

    // Fixup the new suffix based on whether we're compressing or not.
    if (compressionType() == WTAP_UNCOMPRESSED) {
        // Not compressing; strip off any compression suffix
        GSList *compression_type_extensions = wtap_get_all_compression_type_extensions_list();
        for (GSList *compression_type_extension = compression_type_extensions;
            compression_type_extension != NULL;
            compression_type_extension = g_slist_next(compression_type_extension)) {
            QString suffix = QString(".") + (char *)compression_type_extension->data;
            if (new_suffix.endsWith(suffix)) {
                //
                // It ends with this compression suffix; chop it off.
                //
                new_suffix.chop(suffix.size());
                break;
            }
        }
        g_slist_free(compression_type_extensions);
    } else {
        // Compressing; append the appropriate compression suffix.
        QString compressed_file_extension = QString(".") + wtap_compression_type_extension(compressionType());
        if (valid_extensions.contains(new_suffix + compressed_file_extension)) {
            new_suffix += compressed_file_extension;
        }
    }

    if (!new_suffix.isEmpty() && old_suffix != new_suffix) {
        filename.chop(old_suffix.size());
        if (old_suffix.isEmpty()) {
            filename += '.';
        }
        filename += new_suffix;
        selectFile(filename);
    }
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

    connect(this, &CaptureFileDialog::currentChanged, this, &CaptureFileDialog::preview);

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
    return type_hash_.value(selectedNameFilter(), WTAP_FILE_TYPE_SUBTYPE_UNKNOWN);
}

wtap_compression_type CaptureFileDialog::compressionType() {
    return compress_.isChecked() ? WTAP_GZIP_COMPRESSED : WTAP_UNCOMPRESSED;
}

void CaptureFileDialog::addDisplayFilterEdit(QString &display_filter) {
    QGridLayout *fd_grid = qobject_cast<QGridLayout*>(layout());

    fd_grid->addWidget(new QLabel(tr("Read filter:")), last_row_, 0);

    display_filter_edit_ = new DisplayFilterEdit(this, ReadFilterToApply);
    display_filter_edit_->setText(display_filter);
    fd_grid->addWidget(display_filter_edit_, last_row_, 1);
    last_row_++;
}

void CaptureFileDialog::addFormatTypeSelector(QVBoxLayout &v_box) {
    int i;
    /* Put Auto, as well as pcap and pcapng (which are the first two entries in
       open_routines), at the top of the file type list. */
    format_type_.addItem(tr("Automatically detect file type"));
    for (i = 0; i < 2; i += 1) {
        format_type_.addItem(open_routines[i].name);
    }
    /* Generate a sorted list of the remaining file types. */
    QStringList routine_names;
    for ( /* keep using i */ ; open_routines[i].name != NULL; i += 1) {
        routine_names += QString(open_routines[i].name);
    }
    routine_names.sort(Qt::CaseInsensitive);
    for (i = 0; i < routine_names.size(); i += 1) {
        format_type_.addItem(routine_names.at(i));
    }

    v_box.addWidget(&format_type_, 0, Qt::AlignTop);
}

void CaptureFileDialog::addGzipControls(QVBoxLayout &v_box) {
    compress_.setText(tr("Compress with g&zip"));
    if (cap_file_->compression_type == WTAP_GZIP_COMPRESSED &&
        wtap_dump_can_compress(default_ft_)) {
        compress_.setChecked(true);
    } else {
        compress_.setChecked(false);
    }
    v_box.addWidget(&compress_, 0, Qt::AlignTop);
    connect(&compress_, &QCheckBox::stateChanged, this, &CaptureFileDialog::fixFilenameExtension);

}

void CaptureFileDialog::addRangeControls(QVBoxLayout &v_box, packet_range_t *range, QString selRange) {
    packet_range_group_box_.initRange(range, selRange);
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
        connect(button_box, &QDialogButtonBox::helpRequested, this, &CaptureFileDialog::on_buttonBox_helpRequested);
    }
    return button_box;
}

int CaptureFileDialog::open(QString &file_name, unsigned int &type, QString &display_filter) {
    setWindowTitle(mainApp->windowTitleString(tr("Open Capture File")));
    setNameFilters(buildFileOpenTypeList());
    setFileMode(QFileDialog::ExistingFile);

    addFormatTypeSelector(left_v_box_);
    addDisplayFilterEdit(display_filter);
    addPreview(right_v_box_);
    addHelpButton(HELP_OPEN_DIALOG);

    // Grow the dialog to account for the extra widgets.
    resize(width() * WIDTH_SCALE_FACTOR, height() * HEIGHT_SCALE_FACTOR + left_v_box_.minimumSize().height() + display_filter_edit_->minimumSize().height());

    display_filter.clear();

    if (!file_name.isEmpty()) {
        selectFile(file_name);
    }

    if (WiresharkFileDialog::exec() && selectedFiles().length() > 0) {
        file_name = selectedFiles()[0];
        type = open_info_name_to_type(qPrintable(format_type_.currentText()));
        display_filter.append(display_filter_edit_->text());

        return QDialog::Accepted;
    } else {
        return QDialog::Rejected;
    }
}

check_savability_t CaptureFileDialog::saveAs(QString &file_name, bool must_support_all_comments) {
    setWindowTitle(mainApp->windowTitleString(tr("Save Capture File As")));
    // XXX There doesn't appear to be a way to use setNameFilters without restricting
    // what the user can select. We might want to use our own combobox instead and
    // let the user select anything.
    setNameFilters(buildFileSaveAsTypeList(must_support_all_comments));
    setAcceptMode(QFileDialog::AcceptSave);
    setLabelText(FileType, tr("Save as:"));

    addGzipControls(left_v_box_);
    addHelpButton(HELP_SAVE_DIALOG);

    // Grow the dialog to account for the extra widgets.
    resize(width() * WIDTH_SCALE_FACTOR, height() * HEIGHT_SCALE_FACTOR + left_v_box_.minimumSize().height());

    if (!file_name.isEmpty()) {
        selectFile(file_name);
    }
    connect(this, &QFileDialog::filterSelected, this, &CaptureFileDialog::fixFilenameExtension);

    if (WiresharkFileDialog::exec() && selectedFiles().length() > 0) {
        int file_type;

        file_name = selectedFiles()[0];
        file_type = selectedFileType();
        /* Is the file type bogus? */
        if (file_type == WTAP_FILE_TYPE_SUBTYPE_UNKNOWN) {
            /* This "should not happen". */
            QMessageBox msg_dialog;

            msg_dialog.setIcon(QMessageBox::Critical);
            msg_dialog.setText(tr("Unknown file type returned by save as dialog."));
            msg_dialog.setInformativeText(tr("Please report this as a Wireshark issue at https://gitlab.com/wireshark/wireshark/-/issues."));
            msg_dialog.exec();
            return CANCELLED;
        }
        return checkSaveAsWithComments(this, cap_file_, file_type);
    }
    return CANCELLED;
}

check_savability_t CaptureFileDialog::exportSelectedPackets(QString &file_name, packet_range_t *range, QString selRange) {
    QDialogButtonBox *button_box;

    setWindowTitle(mainApp->windowTitleString(tr("Export Specified Packets")));
    // XXX See comment in ::saveAs regarding setNameFilters
    setNameFilters(buildFileSaveAsTypeList(false));
    setAcceptMode(QFileDialog::AcceptSave);
    setLabelText(FileType, tr("Export as:"));

    addRangeControls(left_v_box_, range, selRange);
    addGzipControls(right_v_box_);
    button_box = addHelpButton(HELP_EXPORT_FILE_DIALOG);

    if (button_box) {
        save_bt_ = button_box->button(QDialogButtonBox::Save);
        if (save_bt_) {
            connect(&packet_range_group_box_, &PacketRangeGroupBox::validityChanged,
                    save_bt_, &QPushButton::setEnabled);
        }
    }

    // Grow the dialog to account for the extra widgets.
    resize(width() * WIDTH_SCALE_FACTOR, height() * HEIGHT_SCALE_FACTOR + (packet_range_group_box_.height() * 2 / 3));

    if (!file_name.isEmpty()) {
        selectFile(file_name);
    }
    connect(this, &QFileDialog::filterSelected, this, &CaptureFileDialog::fixFilenameExtension);

    if (WiresharkFileDialog::exec() && selectedFiles().length() > 0) {
        int file_type;

        file_name = selectedFiles()[0];
        file_type = selectedFileType();
        /* Is the file type bogus? */
        if (file_type == WTAP_FILE_TYPE_SUBTYPE_UNKNOWN) {
            /* This "should not happen". */
            QMessageBox msg_dialog;

            msg_dialog.setIcon(QMessageBox::Critical);
            msg_dialog.setText(tr("Unknown file type returned by save as dialog."));
            msg_dialog.setInformativeText(tr("Please report this as a Wireshark issue at https://gitlab.com/wireshark/wireshark/-/issues."));
            msg_dialog.exec();
            return CANCELLED;
        }
        return checkSaveAsWithComments(this, cap_file_, file_type);
    }
    return CANCELLED;
}

int CaptureFileDialog::merge(QString &file_name, QString &display_filter) {
    setWindowTitle(mainApp->windowTitleString(tr("Merge Capture File")));
    setNameFilters(buildFileOpenTypeList());
    setFileMode(QFileDialog::ExistingFile);

    addDisplayFilterEdit(display_filter);
    addMergeControls(left_v_box_);
    addPreview(right_v_box_);
    addHelpButton(HELP_MERGE_DIALOG);

    file_name.clear();
    display_filter.clear();

    // Grow the dialog to account for the extra widgets.
    resize(width() * WIDTH_SCALE_FACTOR, height() * HEIGHT_SCALE_FACTOR + right_v_box_.minimumSize().height() + display_filter_edit_->minimumSize().height());

    if (WiresharkFileDialog::exec() && selectedFiles().length() > 0) {
        file_name.append(selectedFiles()[0]);
        display_filter.append(display_filter_edit_->text());

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
    type_suffixes_.clear();

    /* What types of comments do we have to support? */
    if (must_support_all_comments)
        required_comment_types = cf_comment_types(cap_file_); /* all the ones the file has */
    else
        required_comment_types = 0; /* none of them */

  /* What types of file can we save this file as? */
    savable_file_types_subtypes = wtap_get_savable_file_types_subtypes_for_file(cap_file_->cd_t,
                                                                       cap_file_->linktypes,
                                                                       required_comment_types,
                                                                       FT_SORT_BY_DESCRIPTION);

    if (savable_file_types_subtypes != NULL) {
        int ft;
        /* OK, we have at least one file type we can save this file as.
           (If we didn't, we shouldn't have gotten here in the first
           place.)  Add them all to the combo box.  */
        for (i = 0; i < savable_file_types_subtypes->len; i++) {
            ft = g_array_index(savable_file_types_subtypes, int, i);
            if (default_ft_ < 1)
                default_ft_ = ft; /* first file type is the default */
            QString type_name(wtap_file_type_subtype_description(ft));
            filters << type_name + fileType(ft, type_suffixes_[type_name]);
            type_hash_[type_name] = ft;
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
    int          err;
    gchar       *err_info;
    ws_file_preview_stats stats;
    ws_file_preview_stats_status status;
    time_t       ti_time;
    struct tm   *ti_tm;
    unsigned int elapsed_time;

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
        if (err == WTAP_ERR_FILE_UNKNOWN_FORMAT) {
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
    preview_format_.setText(QString::fromUtf8(wtap_file_type_subtype_description(wtap_file_type_subtype(wth))));

    // Size
    gint64 filesize = wtap_file_size(wth, &err);
    // Finder and Windows Explorer use IEC. What do the various Linux file managers use?
    QString size_str(gchar_free_to_qstring(format_size(filesize, FORMAT_SIZE_UNIT_BYTES, FORMAT_SIZE_PREFIX_IEC)));

    status = get_stats_for_preview(wth, &stats, &err, &err_info);

    if (status == PREVIEW_READ_ERROR) {
        // XXX - give error details?
        g_free(err_info);
        preview_size_.setText(tr("%1, error after %Ln data record(s)", "", stats.records)
                              .arg(size_str));
        return;
    }

    // Packet count
    if (status == PREVIEW_TIMED_OUT) {
        preview_size_.setText(tr("%1, timed out at %Ln data record(s)", "", stats.data_records)
                              .arg(size_str));
    } else {
        preview_size_.setText(tr("%1, %Ln data record(s)", "", stats.data_records)
                              .arg(size_str));
    }

    // First packet + elapsed time
    QString first_elapsed;
    if (stats.have_times) {
        //
        // We saw at least one record with a time stamp, so we can give
        // a start time (if we have a mix of records with and without
        // time stamps, and there were records without time stamps
        // before the first one with a time stamp, this may be inaccurate).
        //
        ti_time = (long)stats.start_time;
        ti_tm = localtime(&ti_time);
        first_elapsed = "?";
        if (ti_tm) {
            first_elapsed = QString("%1-%2-%3 %4:%5:%6")
                    .arg(ti_tm->tm_year + 1900, 4, 10, QChar('0'))
                    .arg(ti_tm->tm_mon + 1, 2, 10, QChar('0'))
                    .arg(ti_tm->tm_mday, 2, 10, QChar('0'))
                    .arg(ti_tm->tm_hour, 2, 10, QChar('0'))
                    .arg(ti_tm->tm_min, 2, 10, QChar('0'))
                    .arg(ti_tm->tm_sec, 2, 10, QChar('0'));
        }
    } else {
        first_elapsed = tr("unknown");
    }

    // Elapsed time
    first_elapsed += " / ";
    if (status == PREVIEW_SUCCEEDED && stats.have_times) {
        //
        // We didn't time out, so we looked at all packets, and we got
        // at least one packet with a time stamp, so we can calculate
        // an elapsed time from the time stamp of the last packet with
        // with a time stamp (if we have a mix of records with and without
        // time stamps, and there were records without time stamps after
        // the last one with a time stamp, this may be inaccurate).
        //
        elapsed_time = (unsigned int)(stats.stop_time-stats.start_time);
        if (elapsed_time/86400) {
            first_elapsed += QString("%1 days ").arg(elapsed_time/86400, 2, 10, QChar('0'));
            elapsed_time = elapsed_time % 86400;
        }
        first_elapsed += QString("%2:%3:%4")
                .arg(elapsed_time%86400/3600, 2, 10, QChar('0'))
                .arg(elapsed_time%3600/60, 2, 10, QChar('0'))
                .arg(elapsed_time%60, 2, 10, QChar('0'));
    } else {
        first_elapsed += tr("unknown");
    }
    preview_first_elapsed_.setText(first_elapsed);

    wtap_close(wth);
}

void CaptureFileDialog::on_buttonBox_helpRequested()
{
    if (help_topic_ != TOPIC_ACTION_NONE) mainApp->helpTopicAction(help_topic_);
}

#endif // ! Q_OS_WIN
