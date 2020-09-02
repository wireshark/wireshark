/* export_dissection_dialog.h
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

#include <glib.h>

#include "file.h"
#include "epan/print.h"

#include "ui/file_dialog.h"
#include <ui/qt/widgets/wireshark_file_dialog.h>

#ifndef Q_OS_WIN
#include "packet_range_group_box.h"
#include "packet_format_group_box.h"
#endif // Q_OS_WIN

#include <QMap>

class ExportDissectionDialog : public WiresharkFileDialog
{
    Q_OBJECT

public:
    explicit ExportDissectionDialog(QWidget *parent, capture_file *cap_file, export_type_e export_type, QString selRange = QString());
    ~ExportDissectionDialog();

public slots:
    void show();

private slots:
#ifndef Q_OS_WIN
    void dialogAccepted();
    void exportTypeChanged(QString name_filter);
    void checkValidity();
    void on_buttonBox_helpRequested();
#endif // Q_OS_WIN

private:
    export_type_e export_type_;
    capture_file *cap_file_;
#ifndef Q_OS_WIN
    print_args_t print_args_;

    QMap<QString, export_type_e> export_type_map_;
    PacketRangeGroupBox packet_range_group_box_;

    PacketFormatGroupBox packet_format_group_box_;

    QPushButton *save_bt_;
#else
    QString sel_range_;
#endif // Q_OS_WIN
};

#endif // EXPORT_DISSECTION_DIALOG_H

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
