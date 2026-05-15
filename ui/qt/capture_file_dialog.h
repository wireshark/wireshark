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
#include <ui/qt/widgets/compression_group_box.h>
#include "packet_range_group_box.h"
#include "ui/help_url.h"

#include <ui/packet_range.h>

#include <ui/qt/models/packet_list_record.h>
#include <epan/cfile.h>

#include "ui/file_dialog.h"

#include <QVBoxLayout>
#include <QLabel>
#include <QRadioButton>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QComboBox>

/**
 * @brief A file dialog for opening, saving, and merging capture files with additional options.
 */
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
    /**
     * @brief Constructs a new CaptureFileDialog.
     * @param parent The parent widget, defaults to NULL.
     * @param cf The capture file associated with the dialog, defaults to NULL.
     */
    explicit CaptureFileDialog(QWidget *parent = NULL, capture_file *cf = NULL);

    /**
     * @brief Checks whether the capture file can be saved with comments in the specified format.
     * @param parent The parent widget.
     * @param cf The capture file to check.
     * @param file_type The file format type.
     * @return The savability status.
     */
    static check_savability_t checkSaveAsWithComments(QWidget *parent, capture_file *cf, int file_type);

    /**
     * @brief Retrieves the selected merge type.
     * @return The merge type identifier.
     */
    int mergeType();

    /**
     * @brief Retrieves the selected file type.
     * @return The file type identifier.
     */
    int selectedFileType();

    /**
     * @brief Retrieves the selected compression type.
     * @return The compression type used.
     */
    ws_compression_type compressionType();

private:
    /** Pointer to the core capture_file structure. */
    capture_file *cap_file_;

    /**
     * @brief Adds merge control widgets to the given layout.
     * @param v_box The layout to add the controls to.
     */
    void addMergeControls(QVBoxLayout &v_box);

    /**
     * @brief Adds file format selection widgets to the given layout.
     * @param v_box The layout to add the controls to.
     */
    void addFormatTypeSelector(QVBoxLayout &v_box);

    /**
     * @brief Adds a display filter edit widget and binds it to a string.
     * @param display_filter The string to bind the filter to.
     */
    void addDisplayFilterEdit(QString &display_filter);

    /**
     * @brief Adds preview information widgets to the given layout.
     * @param v_box The layout to add the controls to.
     */
    void addPreview(QVBoxLayout &v_box);

    /**
     * @brief Formats the extension type string.
     * @param et The extension type.
     * @param extension_globs Whether to include globs.
     * @return The formatted extension string.
     */
    QString fileExtensionType(int et, bool extension_globs = true);

    /**
     * @brief Retrieves the file type and populates its suffixes.
     * @param ft The file type.
     * @param suffixes The list of suffixes to populate.
     * @return The file type description.
     */
    QString fileType(int ft, QStringList &suffixes);

    /**
     * @brief Builds a list of supported file types for opening.
     * @return The list of file type strings.
     */
    QStringList buildFileOpenTypeList(void);

    /** Left vertical box layout for the dialog. */
    QVBoxLayout left_v_box_;

    /** Right vertical box layout for the dialog. */
    QVBoxLayout right_v_box_;

    /** Pointer to the display filter edit widget. */
    DisplayFilterEdit* display_filter_edit_;

    /** Tracks the last row used in grid layouts. */
    int last_row_;

    /** Label displaying the format in the file preview. */
    QLabel preview_format_;

    /** Label displaying the size in the file preview. */
    QLabel preview_size_;

    /** Label displaying the elapsed time of the first packet in the file preview. */
    QLabel preview_first_elapsed_;

    /** List of generic preview labels. */
    QList<QLabel *> preview_labels_;

    /** Radio button for prepending during a merge. */
    QRadioButton merge_prepend_;

    /** Radio button for chronological merging. */
    QRadioButton merge_chrono_;

    /** Radio button for appending during a merge. */
    QRadioButton merge_append_;

    /** Combo box for selecting the format type. */
    QComboBox format_type_;

    /** Hash map mapping format names to format type IDs. */
    QHash<QString, int> type_hash_;

    /** Hash map mapping format names to lists of acceptable suffixes. */
    QHash<QString, QStringList> type_suffixes_;

    /**
     * @brief Adds gzip compression controls to the given layout.
     * @param v_box The layout to add the controls to.
     */
    void addGzipControls(QVBoxLayout &v_box);

    /**
     * @brief Adds packet range selection controls to the given layout.
     * @param v_box The layout to add the controls to.
     * @param range Pointer to the packet range structure.
     * @param selRange Optional default selection range string.
     */
    void addRangeControls(QVBoxLayout &v_box, packet_range_t *range, QString selRange = QString());

    /**
     * @brief Adds a help button to the dialog button box.
     * @param help_topic The help topic to associate with the button.
     * @return Pointer to the created dialog button box.
     */
    QDialogButtonBox *addHelpButton(topic_action_e help_topic);

    /**
     * @brief Builds a list of supported file types for saving.
     * @param must_support_comments True if the formats must support comments.
     * @return The list of file type strings.
     */
    QStringList buildFileSaveAsTypeList(bool must_support_comments);

    /** The default file type identifier. */
    int default_ft_;

    /** Group box widget containing compression options. */
    CompressionGroupBox compress_group_box_;

    /** Group box widget containing packet range selection options. */
    PacketRangeGroupBox packet_range_group_box_;

    /** Pointer to the save push button. */
    QPushButton *save_bt_;

    /** The active help topic for the dialog. */
    topic_action_e help_topic_;

signals:

public slots:
    /**
     * @brief Accepts the dialog and finalizes the operation.
     */
    void accept() Q_DECL_OVERRIDE;

    /**
     * @brief Executes the dialog in a modal state.
     * @return The result code of the dialog execution.
     */
    int exec() Q_DECL_OVERRIDE;

    /**
     * @brief Opens a file dialog to open a capture file.
     * @param file_name Output string to store the selected file name.
     * @param type Output integer to store the selected file type.
     * @param display_filter Output string to store the applied display filter.
     * @return The result code of the operation.
     */
    int open(QString &file_name, unsigned int &type, QString &display_filter);

    /**
     * @brief Opens a file dialog to save the capture file.
     * @param file_name Output string to store the chosen save file name.
     * @param must_support_comments True if the saved format must support comments.
     * @return The savability status.
     */
    check_savability_t saveAs(QString &file_name, bool must_support_comments);

    /**
     * @brief Opens a file dialog to export specific packets.
     * @param file_name Output string to store the chosen export file name.
     * @param range The packet range to export.
     * @param selRange Optional string representing the selected range.
     * @return The savability status.
     */
    check_savability_t exportSelectedPackets(QString &file_name, packet_range_t *range, QString selRange = QString());

    /**
     * @brief Opens a file dialog to merge capture files.
     * @param file_name Output string to store the chosen merge file name.
     * @param display_filter Output string to store the applied display filter.
     * @return The result code of the merge operation.
     */
    int merge(QString &file_name, QString &display_filter);

private slots:
    /**
     * @brief Automatically fixes the filename extension based on the selected type.
     */
    void fixFilenameExtension();

    /**
     * @brief Updates the file preview widgets for a specified file path.
     * @param path The path of the file to preview.
     */
    void preview(const QString & path);

    /**
     * @brief Slot triggered when help is requested from the button box.
     */
    void on_buttonBox_helpRequested();
};

#endif // CAPTURE_FILE_DIALOG_H
