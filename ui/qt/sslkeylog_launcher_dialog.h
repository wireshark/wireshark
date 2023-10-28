/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SSLKEYLOG_DIALOG_H
#define SSLKEYLOG_DIALOG_H

#include <wireshark.h>
#include <QProcess>
#include <QDialog>

#include <epan/prefs.h>

namespace Ui {
class SSLKeylogDialog;
}

class SSLKeylogDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SSLKeylogDialog(QWidget &parent);
    ~SSLKeylogDialog();

private slots:
    void on_launchActivated();
    void on_saveActivated();
    void on_resetActivated();
    void on_browseKeylogPath();
    void on_browseBrowserPath();

private:
    Ui::SSLKeylogDialog *ui;

    module_t *tls_module_;
    pref_t *pref_tls_keylog_;

    module_t *gui_module_;
    pref_t *pref_browser_path_;
};

#endif // SSLKEYLOG_DIALOG_H
