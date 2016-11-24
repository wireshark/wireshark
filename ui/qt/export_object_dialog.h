/* export_object_dialog.h
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

#ifndef EXPORT_OBJECT_DIALOG_H
#define EXPORT_OBJECT_DIALOG_H

#include <config.h>

#include <glib.h>

#include <file.h>

#include <epan/packet_info.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/export_object.h>

#include <ui/export_object_ui.h>

#include "wireshark_dialog.h"

class QTreeWidgetItem;
class QAbstractButton;

namespace Ui {
class ExportObjectDialog;
}

typedef struct _export_object_list_gui_t {
    class ExportObjectDialog *eod;
} export_object_list_gui_t;


class ExportObjectDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit ExportObjectDialog(QWidget &parent, CaptureFile &cf, register_eo_t* eo);
    ~ExportObjectDialog();


    void addObjectEntry(export_object_entry_t *entry);
    export_object_entry_t *objectEntry(int row);
    void resetObjects();

public slots:
    void show();

private slots:
    void accept();
    void captureFileClosing();
    void on_buttonBox_helpRequested();
    void on_objectTree_currentItemChanged(QTreeWidgetItem *item, QTreeWidgetItem *previous);
    void on_buttonBox_clicked(QAbstractButton *button);

private:
    void saveCurrentEntry();
    void saveAllEntries();

    Ui::ExportObjectDialog *eo_ui_;

    QPushButton *save_bt_;
    QPushButton *save_all_bt_;

    export_object_list_t export_object_list_;
    export_object_list_gui_t eo_gui_data_;
    register_eo_t* eo_;
};

#endif // EXPORT_OBJECT_DIALOG_H

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
