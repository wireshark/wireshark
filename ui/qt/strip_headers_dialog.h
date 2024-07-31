/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STRIP_HEADERS_DIALOG_H
#define STRIP_HEADERS_DIALOG_H

#include <QDialog>
#include <QDebug>

namespace Ui {
class StripHeadersDialog;
}

class StripHeadersDialog : public QDialog
{
    Q_OBJECT

public:
    explicit StripHeadersDialog(QWidget *parent = 0);
    ~StripHeadersDialog();

private:
    Ui::StripHeadersDialog *ui;

private slots:
    void on_buttonBox_accepted();
    void on_buttonBox_helpRequested();
};

#endif // STRIP_HEADERS_DIALOG_H
