/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
#include <QTextCodec>

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

    void addCodecs(const QMap<QString, QTextCodec *> &codecMap);

protected:
    bool eventFilter(QObject *obj, QEvent *event);
    void keyPressEvent(QKeyEvent *event);
    void captureFileClosing();
    void captureFileClosed();

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
        DecodeAsHexDigits,
        DecodeAsPercentEncoding,
        DecodeAsQuotedPrintable,
        DecodeAsROT13
    };
    enum ShowAsType {
        ShowAsASCII,
        ShowAsASCIIandControl,
        ShowAsCArray,
        ShowAsRustArray,
        ShowAsEBCDIC,
        ShowAsHexDump,
        ShowAsHTML,
        ShowAsImage,
        ShowAsJson,
        ShowAsRAW,
        ShowAsCodec, // Ordered to match the UTF-8 combobox index
        ShowAsYAML,
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
