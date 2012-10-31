/* export_dissection_dialog.h
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

#ifndef EXPORT_DISSECTION_DIALOG_H
#define EXPORT_DISSECTION_DIALOG_H

#include "config.h"

#include <glib.h>

#include "file.h"
#include "print.h"

#include "ui/file_dialog.h"

#ifndef Q_WS_WIN
#include "packet_range_group_box.h"
#include "packet_format_group_box.h"
#endif // Q_WS_WIN

#include <QFileDialog>
#include <QMap>

class ExportDissectionDialog : public QFileDialog
{
    Q_OBJECT
    
public:
    explicit ExportDissectionDialog(QWidget *parent, capture_file *cap_file, export_type_e export_type);
    ~ExportDissectionDialog();
    
public slots:
    int exec();

private slots:
#ifndef Q_WS_WIN
    void exportTypeChanged(QString name_filter);
    void checkValidity();
    void on_buttonBox_helpRequested();
#endif // Q_WS_WIN

private:
    export_type_e export_type_;
    capture_file *cap_file_;
#ifndef Q_WS_WIN
    print_args_t print_args_;

    QMap<QString, export_type_e> export_type_map_;
    PacketRangeGroupBox packet_range_group_box_;

    PacketFormatGroupBox packet_format_group_box_;

    QPushButton *save_bt_;
#endif // Q_WS_WIN
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
