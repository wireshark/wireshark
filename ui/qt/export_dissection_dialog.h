/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXPORT_DISSECTION_DIALOG_H
#define EXPORT_DISSECTION_DIALOG_H

#include <config.h>

#include "file.h"
#include "epan/print.h"

#include "ui/file_dialog.h"
#include <ui/qt/widgets/wireshark_file_dialog.h>

#include "packet_range_group_box.h"
#include "packet_format_stack.h"

#include <QMap>

/**
 * @brief A dialog for exporting packet dissections to various file formats.
 */
class ExportDissectionDialog : public WiresharkFileDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ExportDissectionDialog.
     * @param parent The parent widget.
     * @param cap_file The capture file containing the packets to export.
     * @param export_type The initial export format type.
     * @param selRange The initially selected range of packets (defaults to an empty string).
     */
    explicit ExportDissectionDialog(QWidget *parent, capture_file *cap_file, export_type_e export_type, QString selRange = QString());

    /**
     * @brief Destroys the ExportDissectionDialog.
     */
    ~ExportDissectionDialog();

public slots:
    /**
     * @brief Displays the export dissection dialog.
     */
    void show();

protected:
    /**
     * @brief Filters events for the dialog, allowing custom event handling.
     * @param obj The object that generated the event.
     * @param event The event to filter.
     * @return True if the event was filtered (handled), false otherwise.
     */
    bool eventFilter(QObject *obj, QEvent *event) override;

private slots:
    /**
     * @brief Slot triggered when the dialog is accepted and the user proceeds to export.
     * @param selected A list containing the selected file path(s).
     */
    void dialogAccepted(const QStringList &selected);

    /**
     * @brief Slot triggered when the selected export file type changes.
     * @param name_filter The name filter corresponding to the new export type.
     */
    void exportTypeChanged(QString name_filter);

    /**
     * @brief Checks the validity of the current dialog state and updates UI elements accordingly.
     */
    void checkValidity();

    /**
     * @brief Slot triggered when help is requested from the dialog's button box.
     */
    void on_buttonBox_helpRequested();

private:
    /** The active export format type. */
    export_type_e export_type_;

    /** Pointer to the underlying capture file. */
    capture_file *cap_file_;

    /** Arguments configuring the specific print/export output format. */
    print_args_t print_args_;

    /** Map connecting file dialog name filters to their respective export types. */
    QMap<QString, export_type_e> export_type_map_;

    /** Group box widget for selecting the range of packets to export. */
    PacketRangeGroupBox packet_range_group_box_;

    /** Stack widget holding format-specific option panels. */
    PacketFormatStack *packet_format_stack_;

    /** Pointer to the save button in the dialog. */
    QPushButton *save_bt_;

    /**
     * @brief Validates the current export settings.
     * @return True if the current configuration is valid and can be exported, false otherwise.
     */
    bool isValid();
};

#endif // EXPORT_DISSECTION_DIALOG_H
