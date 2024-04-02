/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_COMMENT_DIALOG_H
#define CAPTURE_COMMENT_DIALOG_H

#include "wireshark_dialog.h"

namespace Ui {
class CaptureCommentDialog;
}

class CaptureCommentDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit CaptureCommentDialog(QWidget &parent, CaptureFile &capture_file);
    ~CaptureCommentDialog();

signals:
    void captureCommentChanged();

private slots:
    void addComment();
    void updateWidgets();
    void on_buttonBox_helpRequested();
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();

private:
    QPushButton *actionAddButton;
    Ui::CaptureCommentDialog *ui;
};

#endif // CAPTURE_COMMENT_DIALOG_H
