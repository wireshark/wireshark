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

#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>

namespace Ui {
class ShowPacketBytesDialog;
class ShowPacketBytesTextEdit;
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
    void on_sbStart_valueChanged(int value);
    void on_sbEnd_valueChanged(int value);
    void on_cbDecodeAs_currentIndexChanged(int idx);
    void on_cbShowAs_currentIndexChanged(int idx);
    void on_leFind_returnPressed();
    void on_bFind_clicked();
    void on_buttonBox_rejected();

    void showSelected(int start, int end);
    void useRegexFind(bool use_regex);
    void findText(bool go_back = true);
    void helpButton();
    void printBytes();
    void copyBytes();
    void saveAs();

private:
    enum DecodeAsType {
        DecodeAsNone,
        DecodeAsBASE64,
        DecodeAsCompressed,
        DecodeAsQuotedPrintable,
        DecodeAsROT13
    };
    enum ShowAsType {
        ShowAsASCII,
        ShowAsASCIIandControl,
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

    void setStartAndEnd(int start, int end);
    bool enableShowSelected();
    void updateWidgets(); // Needed for WiresharkDialog?
    void updateHintLabel();
    void sanitizeBuffer(QByteArray &ba, bool handle_CR);
    void symbolizeBuffer(QByteArray &ba);
    QByteArray decodeQuotedPrintable(const guint8 *bytes, int length);
    void rot13(QByteArray &ba);
    void updateFieldBytes(bool initialization = false);
    void updatePacketBytes();

    Ui::ShowPacketBytesDialog  *ui;

    const field_info  *finfo_;
    QByteArray  field_bytes_;
    QString     hint_label_;
    QPushButton *print_button_;
    QPushButton *copy_button_;
    QPushButton *save_as_button_;
    DecodeAsType decode_as_;
    ShowAsType  show_as_;
    bool        use_regex_find_;
    int         start_;
    int         end_;
    QImage      image_;
};

class ShowPacketBytesTextEdit : public QTextEdit
{
    Q_OBJECT

public:
    explicit ShowPacketBytesTextEdit(QWidget *parent = 0) :
        QTextEdit(parent), show_selected_enabled_(true), menus_enabled_(true) { }
    ~ShowPacketBytesTextEdit() { }

    void setShowSelectedEnabled(bool enabled) { show_selected_enabled_ = enabled; }
    void setMenusEnabled(bool enabled) { menus_enabled_ = enabled; }

signals:
    void showSelected(int, int);

private slots:
    void contextMenuEvent(QContextMenuEvent *event);
    void showSelected();
    void showAll();

private:
    bool show_selected_enabled_;
    bool menus_enabled_;
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
