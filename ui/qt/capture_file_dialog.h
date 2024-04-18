/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_FILE_DIALOG_H
#define CAPTURE_FILE_DIALOG_H

#include <ui/qt/widgets/wireshark_file_dialog.h>

#include <ui/qt/widgets/display_filter_edit.h>
#include "packet_range_group_box.h"
#include "ui/help_url.h"

#include <ui/packet_range.h>

#include <ui/qt/models/packet_list_record.h>
#include "cfile.h"

#include "ui/file_dialog.h"

#include <QVBoxLayout>
#include <QLabel>
#include <QRadioButton>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QComboBox>

class CaptureFileDialog : public WiresharkFileDialog
{
    // The GTK+ Open Capture File dialog has the following elements and features:
    //   - The ability to select a capture file from a list of known extensions
    //   - A display filter entry
    //   - Name resolution checkboxes
    //   - Capture file preview information
    // Ideally we should provide similar functionality here.
    //
    // You can subclass QFileDialog (which we've done here) and add widgets as
    // described at
    //
    //   https://web.archive.org/web/20100528190736/http://developer.qt.nokia.com/faq/answer/how_can_i_add_widgets_to_my_qfiledialog_instance
    //
    // However, Qt's idea of what a file dialog looks like isn't what Microsoft
    // and Apple think a file dialog looks like.
    //
    // On Windows, we should probably use the Common Item Dialog:
    //
    //   https://learn.microsoft.com/en-us/windows/win32/shell/common-file-dialog
    //
    // We currently use GetOpenFileNam in ui/win32/file_dlg_win32.c.
    //
    // On macOS we should use NSOpenPanel and NSSavePanel:
    //
    //   https://developer.apple.com/documentation/appkit/nsopenpanel?language=objc
    //   https://developer.apple.com/documentation/appkit/nssavepanel?language=objc
    //
    // On other platforms we should fall back to QFileDialog (or maybe
    // KDE's or GTK+/GNOME's file dialog, as appropriate for the desktop
    // environment being used, if QFileDialog doesn't do so with various
    // platform plugins).
    //
    // Yes, that's four implementations of the same window.
    //
    // If a plain native open file dialog is good enough we can just the static
    // version of QFileDialog::getOpenFileName. (Commenting out Q_OBJECT and
    // "explicit" below has the same effect.)

    Q_OBJECT
public:
    explicit CaptureFileDialog(QWidget *parent = NULL, capture_file *cf = NULL);
    static check_savability_t checkSaveAsWithComments(QWidget *
            , capture_file *cf, int file_type);

    int mergeType();
    int selectedFileType();
    wtap_compression_type compressionType();

private:
    capture_file *cap_file_;

    void addMergeControls(QVBoxLayout &v_box);
    void addFormatTypeSelector(QVBoxLayout &v_box);
    void addDisplayFilterEdit(QString &display_filter);
    void addPreview(QVBoxLayout &v_box);
    QString fileExtensionType(int et, bool extension_globs = true);
    QString fileType(int ft, QStringList &suffixes);
    QStringList buildFileOpenTypeList(void);

    QVBoxLayout left_v_box_;
    QVBoxLayout right_v_box_;

    DisplayFilterEdit* display_filter_edit_;
    int last_row_;

    QLabel preview_format_;
    QLabel preview_size_;
    QLabel preview_first_elapsed_;
    QList<QLabel *> preview_labels_;

    QRadioButton merge_prepend_;
    QRadioButton merge_chrono_;
    QRadioButton merge_append_;

    QComboBox format_type_;
    QHash<QString, int> type_hash_;
    QHash<QString, QStringList> type_suffixes_;

    void addGzipControls(QVBoxLayout &v_box);
    void addRangeControls(QVBoxLayout &v_box, packet_range_t *range, QString selRange = QString());
    QDialogButtonBox *addHelpButton(topic_action_e help_topic);

    QStringList buildFileSaveAsTypeList(bool must_support_comments);

    int default_ft_;

    QCheckBox compress_;

    PacketRangeGroupBox packet_range_group_box_;
    QPushButton *save_bt_;
    topic_action_e help_topic_;

signals:

public slots:

    void accept() Q_DECL_OVERRIDE;
    int exec() Q_DECL_OVERRIDE;
    int open(QString &file_name, unsigned int &type, QString &display_filter);
    check_savability_t saveAs(QString &file_name, bool must_support_comments);
    check_savability_t exportSelectedPackets(QString &file_name, packet_range_t *range, QString selRange = QString());
    int merge(QString &file_name, QString &display_filter);

private slots:
    void fixFilenameExtension();
    void preview(const QString & path);
    void on_buttonBox_helpRequested();
};

#endif // CAPTURE_FILE_DIALOG_H
