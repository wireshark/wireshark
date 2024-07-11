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
#include "packet_format_group_box.h"

#include <QMap>

class ExportDissectionDialog : public WiresharkFileDialog
{
    Q_OBJECT

public:
    explicit ExportDissectionDialog(QWidget *parent, capture_file *cap_file, export_type_e export_type, QString selRange = QString());
    ~ExportDissectionDialog();

public slots:
    void show();

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;

private slots:
    void dialogAccepted(const QStringList &selected);
    void exportTypeChanged(QString name_filter);
    void checkValidity();
    void on_buttonBox_helpRequested();

private:
    export_type_e export_type_;
    capture_file *cap_file_;
    print_args_t print_args_;

    QMap<QString, export_type_e> export_type_map_;
    PacketRangeGroupBox packet_range_group_box_;

    PacketFormatGroupBox packet_format_group_box_;

    QPushButton *save_bt_;

    bool isValid();
};

#endif // EXPORT_DISSECTION_DIALOG_H
