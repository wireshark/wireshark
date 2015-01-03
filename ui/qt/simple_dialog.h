/* simple_dialog.h
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

#ifndef SIMPLE_DIALOG_H
#define SIMPLE_DIALOG_H

#include <config.h>

#include <stdio.h>

#include <glib.h>

#include "ui/simple_dialog.h"

#include <QMessageBox>

typedef QPair<QString,QString> MessagePair;

class SimpleDialog : public QMessageBox
{
    Q_OBJECT

public:
    explicit SimpleDialog(QWidget *parent, ESD_TYPE_E type, int btn_mask, const char *msg_format, va_list ap);
    ~SimpleDialog();
    static void displayQueuedMessages(QWidget *parent = 0);

public slots:
    int exec();

private:
    const MessagePair splitMessage(QString &message) const;
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
