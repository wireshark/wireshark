/* packet_dialog.h
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

#ifndef PACKET_DIALOG_H
#define PACKET_DIALOG_H

#include "wireshark_dialog.h"

#include "epan/epan_dissect.h"
#include "wiretap/wtap.h"

class ByteViewTab;
class ProtoTree;

namespace Ui {
class PacketDialog;
}

class PacketDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit PacketDialog(QWidget &parent, CaptureFile &cf, frame_data *fdata);
    ~PacketDialog();

signals:
    void monospaceFontChanged(QFont);

private slots:
    void captureFileClosing();
    void setHintText() { QString empty; setHintText(empty); }
    void setHintText(const QString &hint);
    void on_buttonBox_helpRequested();

private:
    Ui::PacketDialog *ui;

    QString col_info_;
    ProtoTree *proto_tree_;
    ByteViewTab *byte_view_tab_;
    epan_dissect_t edt_;
    struct wtap_pkthdr phdr_;
    guint8 *packet_data_;
};

#endif // PACKET_DIALOG_H

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
