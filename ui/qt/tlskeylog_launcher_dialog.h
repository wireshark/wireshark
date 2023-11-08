/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TLSKEYLOG_DIALOG_H
#define TLSKEYLOG_DIALOG_H

#include <wireshark.h>
#include <QProcess>
#include <QDialog>

#include <epan/prefs.h>

namespace Ui {
class TLSKeylogDialog;
}

class TLSKeylogDialog : public QDialog
{
    Q_OBJECT

public:
    explicit TLSKeylogDialog(QWidget &parent);
    ~TLSKeylogDialog();

private slots:
    void on_launchActivated();
    void on_saveActivated();
    void on_resetActivated();
    void on_browseKeylogPath();
    void on_browseProgramPath();

private:
    Ui::TLSKeylogDialog *ui;

    module_t *tls_module_;
    pref_t *pref_tls_keylog_;

    module_t *gui_module_;
    pref_t *pref_tlskeylog_command_;
};

#endif // TLSKEYLOG_DIALOG_H
