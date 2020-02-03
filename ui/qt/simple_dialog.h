/* simple_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SIMPLE_DIALOG_H
#define SIMPLE_DIALOG_H

#include <config.h>

#include <stdio.h>

#include <glib.h>

#include "ui/simple_dialog.h"

#include <QPair>
#include <QString>

typedef QPair<QString,QString> MessagePair;

class QCheckBox;
class QMessageBox;
class QWidget;

// This might be constructed before Qt is initialized and must be a plain, non-Qt object.
class SimpleDialog
{
public:
    explicit SimpleDialog(QWidget *parent, ESD_TYPE_E type, int btn_mask, const char *msg_format, va_list ap);
    ~SimpleDialog();

    static void displayQueuedMessages(QWidget *parent = 0);
    static QString dontShowThisAgain();
    void setDetailedText(QString text) { detailed_text_ = text; }
    void setCheckBox(QCheckBox *cb) { check_box_ = cb; }
    int exec();
    void show();

private:
    const MessagePair splitMessage(QString &message) const;
    QString detailed_text_;
    QCheckBox *check_box_;
    QMessageBox *message_box_;
};

#endif // SIMPLE_DIALOG_H

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
