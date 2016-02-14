/* show_packet_bytes_dialog.h
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

#ifndef SHOW_PACKET_BYTES_DIALOG_H
#define SHOW_PACKET_BYTES_DIALOG_H

#include <config.h>
#include <glib.h>
#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "file.h"
#include "wireshark_dialog.h"

#include <QPushButton>

namespace Ui {
class ShowPacketBytesDialog;
}

class ShowPacketBytesDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit ShowPacketBytesDialog(QWidget &parent, CaptureFile &cf);
    ~ShowPacketBytesDialog();

public slots:
    void captureFileClosing();

protected:
    bool eventFilter(QObject *obj, QEvent *event);
    void keyPressEvent(QKeyEvent *event);

private slots:
    void on_cbShowAs_currentIndexChanged(int idx);
    void on_leFind_returnPressed();
    void on_bFind_clicked();
    void on_buttonBox_rejected();

    void useRegexFind(bool use_regex);
    void findText(bool go_back = true);
    void helpButton();
    void printBytes();
    void copyBytes();
    void saveAs();

private:
    enum ShowAsType {
        ShowAsASCII,
        ShowAsCArray,
        ShowAsEBCDIC,
        ShowAsHexDump,
        ShowAsHTML,
        ShowAsImage,
        ShowAsISO8859_1,
        ShowAsRAW,
        ShowAsUTF8,
        ShowAsYAML
    };

    void updateWidgets(); // Needed for WiresharkDialog?
    void updatePacketBytes(void);

    Ui::ShowPacketBytesDialog  *ui;

    QByteArray  field_bytes_;
    QPushButton *print_button_;
    QPushButton *copy_button_;
    QPushButton *save_as_button_;
    ShowAsType  show_as_;
    bool        use_regex_find_;
    QImage      image_;
};

#endif // SHOW_PACKET_BYTES_DIALOG_H

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
