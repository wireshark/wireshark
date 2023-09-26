/*
 * browser_sslkeylog_dialog.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include "browser_sslkeylog_dialog.h"
#include <ui_browser_sslkeylog_dialog.h>

#include "main_application.h"
#include "ui/qt/widgets/wireshark_file_dialog.h"
#include "wsutil/report_message.h"
#include <models/pref_models.h>
#include <epan/prefs-int.h>
#include <ui/preference_utils.h>

SSLKeylogDialog::SSLKeylogDialog(QWidget &parent) :
    QDialog(&parent),
    ui(new Ui::SSLKeylogDialog),
    pref_tls_keylog_(nullptr),
    pref_browser_path_(nullptr)
{
    ui->setupUi(this);

    QString title("Browser with SSLKEYLOG");
    setWindowTitle(mainApp->windowTitleString(title));

    QPushButton *launch_button = ui->buttonBox->addButton(tr("Launch"), QDialogButtonBox::ApplyRole);
    launch_button->setDefault(true);
    connect(launch_button, &QPushButton::clicked, this, &SSLKeylogDialog::on_launchActivated);

    QPushButton *save_button = ui->buttonBox->addButton(tr("Save"), QDialogButtonBox::ApplyRole);
    connect(save_button, &QPushButton::clicked, this, &SSLKeylogDialog::on_saveActivated);

    QPushButton *reset_button = ui->buttonBox->button(QDialogButtonBox::Reset);
    connect(reset_button, &QPushButton::clicked, this, &SSLKeylogDialog::on_resetActivated);

    connect(ui->keylogPushButton, &QPushButton::clicked, this, &SSLKeylogDialog::on_browseKeylogPath);
    connect(ui->browserPushbutton, &QPushButton::clicked, this, &SSLKeylogDialog::on_browseBrowserPath);

    tls_module_ = prefs_find_module("tls");
    if (tls_module_) {
        pref_tls_keylog_ = prefs_find_preference(tls_module_, "keylog_file");
        if (pref_tls_keylog_) {
            const char *path = prefs_get_string_value(pref_tls_keylog_, pref_current);
            if (path && *path) {
                ui->keylogLineEdit->setText(QString(path));
            }
        }
    }

    gui_module_ = prefs_find_module("gui");
    ws_assert(gui_module_);
    pref_browser_path_ = prefs_find_preference(gui_module_, "browser_sslkeylog.path");
    ws_assert(pref_browser_path_);
    const char *path = prefs_get_string_value(pref_browser_path_, pref_current);
    if (path && *path) {
        ui->browserLineEdit->setText(QString(path));
    }
}

SSLKeylogDialog::~SSLKeylogDialog()
{
    delete ui;
}

void SSLKeylogDialog::on_saveActivated()
{
    int changed;

    if (pref_tls_keylog_) {
        QString keylog = ui->keylogLineEdit->text();
        changed = prefs_set_string_value(pref_tls_keylog_, qUtf8Printable(keylog), pref_current);
        tls_module_->prefs_changed_flags |= changed;
    }

    QString browser = ui->browserLineEdit->text();
    changed = prefs_set_string_value(pref_browser_path_, qUtf8Printable(browser), pref_current);
    gui_module_->prefs_changed_flags |= changed;

    prefs_main_write();
}

void SSLKeylogDialog::on_launchActivated()
{
    QProcess browserProcess;
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();

    QString keylog = ui->keylogLineEdit->text();
    if (keylog.isEmpty())
        return;
    QString browser = ui->browserLineEdit->text();
    if (browser.isEmpty())
        return;

    env.insert("SSLKEYLOGFILE", keylog);
    browserProcess.setProgram(browser);
    browserProcess.setProcessEnvironment(env);
    bool ok = browserProcess.startDetached();
    if (ok) {
        return;
    }

    QString error = browserProcess.errorString();
    if (!error.isEmpty())
        report_failure("Error launching browser: %s", qUtf8Printable(error));
    else
        report_failure("Error launching browser");
}

// Restore user preferences
void SSLKeylogDialog::on_resetActivated()
{
    QString keylog_path;
    QString browser_path;

    if (pref_tls_keylog_) {
        keylog_path = prefs_get_string_value(pref_tls_keylog_, pref_current);
        ui->keylogLineEdit->setText(keylog_path);
    }
    browser_path = prefs_get_string_value(pref_browser_path_, pref_current);
    ui->browserLineEdit->setText(browser_path);
}

void SSLKeylogDialog::on_browseKeylogPath()
{
    QString caption = mainApp->windowTitleString(tr("TLS Keylog"));
    QString file_name = WiresharkFileDialog::getSaveFileName(this, caption,
                            mainApp->lastOpenDir().path());
    if (!file_name.isEmpty()) {
        ui->keylogLineEdit->setText(file_name);
    }
}

void SSLKeylogDialog::on_browseBrowserPath()
{
    QString caption = mainApp->windowTitleString(tr("Web Browser"));
    QString file_name = WiresharkFileDialog::getOpenFileName(this, caption);
    if (!file_name.isEmpty()) {
        ui->browserLineEdit->setText(file_name);
    }
}
