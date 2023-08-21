/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IO_CONSOLE_DIALOG_H
#define IO_CONSOLE_DIALOG_H

#include <wireshark.h>

#include <QTextEdit>
#include <QSplitter>
#include <QKeySequence>
#include <QPushButton>
#include <QSizePolicy>

#include "geometry_state_dialog.h"
#include <epan/funnel.h>

namespace Ui {
class IOConsoleDialog;
}

class IOConsoleDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit IOConsoleDialog(QWidget &parent,
                                QString title,
                                funnel_console_eval_cb_t eval_cb,
                                funnel_console_open_cb_t open_cb,
                                funnel_console_close_cb_t close_cb,
                                void *callback_data);
    ~IOConsoleDialog();
    void appendOutputText(const QString &text);
    void setHintText(const QString &text);
    void clearHintText();

private slots:
    void acceptInput();
    void on_clearActivated(void);
    void clearSuccessHint(void);

private:
    Ui::IOConsoleDialog *ui;
    funnel_console_eval_cb_t eval_cb_;
    funnel_console_open_cb_t open_cb_;
    funnel_console_close_cb_t close_cb_;
    void *callback_data_;
};

#endif // IO_CONSOLE_DIALOG_H
