/*
 * tlskeylog_launcher_dialog.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include "tlskeylog_launcher_dialog.h"
#include <ui_tlskeylog_launcher_dialog.h>

#include "main_application.h"
#include "ui/qt/widgets/wireshark_file_dialog.h"
#include "wsutil/report_message.h"
#include <models/pref_models.h>
#include <epan/prefs-int.h>
#include <ui/preference_utils.h>

TLSKeylogDialog::TLSKeylogDialog(QWidget &parent) :
    QDialog(&parent),
    ui(new Ui::TLSKeylogDialog),
    pref_tls_keylog_(nullptr),
    pref_tlskeylog_command_(nullptr)
{
    ui->setupUi(this);

    QString title(tr("Launch application with SSLKEYLOGFILE"));
    setWindowTitle(mainApp->windowTitleString(title));

    QPushButton *launch_button = ui->buttonBox->addButton(tr("Launch"), QDialogButtonBox::ActionRole);
    launch_button->setDefault(true);
    connect(launch_button, &QPushButton::clicked, this, &TLSKeylogDialog::on_launchActivated);

    QPushButton *save_button = ui->buttonBox->addButton(tr("Save"), QDialogButtonBox::ApplyRole);
    connect(save_button, &QPushButton::clicked, this, &TLSKeylogDialog::on_saveActivated);

    QPushButton *reset_button = ui->buttonBox->button(QDialogButtonBox::Reset);
    connect(reset_button, &QPushButton::clicked, this, &TLSKeylogDialog::on_resetActivated);

    connect(ui->keylogPushButton, &QPushButton::clicked, this, &TLSKeylogDialog::on_browseKeylogPath);
    connect(ui->programPushbutton, &QPushButton::clicked, this, &TLSKeylogDialog::on_browseProgramPath);

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
    pref_tlskeylog_command_ = prefs_find_preference(gui_module_, "tlskeylog_command");
    ws_assert(pref_tlskeylog_command_);
    const char *path = prefs_get_string_value(pref_tlskeylog_command_, pref_current);
    if (path && *path) {
        ui->commandLineEdit->setText(QString(path));
    }
}

TLSKeylogDialog::~TLSKeylogDialog()
{
    delete ui;
}

void TLSKeylogDialog::on_saveActivated()
{
    int changed;

    if (pref_tls_keylog_) {
        QString keylog = ui->keylogLineEdit->text();
        changed = prefs_set_string_value(pref_tls_keylog_, qUtf8Printable(keylog), pref_current);
        tls_module_->prefs_changed_flags |= changed;
    }

    QString command = ui->commandLineEdit->text();
    changed = prefs_set_string_value(pref_tlskeylog_command_, qUtf8Printable(command), pref_current);
    gui_module_->prefs_changed_flags |= changed;

    prefs_main_write();
}

#if (QT_VERSION < QT_VERSION_CHECK(5, 15, 0))
// Splits the string \a command into a list of tokens, and returns the list.
//
// Tokens with spaces can be surrounded by double quotes; three
// consecutive double quotes represent the quote character itself.
//
// Copied from Qt 5.15.2
static QStringList splitCommand(QStringView command)
{
    QStringList args;
    QString tmp;
    int quoteCount = 0;
    bool inQuote = false;

    // handle quoting. tokens can be surrounded by double quotes
    // "hello world". three consecutive double quotes represent
    // the quote character itself.
    for (int i = 0; i < command.size(); ++i) {
        if (command.at(i) == QLatin1Char('"')) {
            ++quoteCount;
            if (quoteCount == 3) {
                // third consecutive quote
                quoteCount = 0;
                tmp += command.at(i);
            }
            continue;
        }
        if (quoteCount) {
            if (quoteCount == 1)
                inQuote = !inQuote;
            quoteCount = 0;
        }
        if (!inQuote && command.at(i).isSpace()) {
            if (!tmp.isEmpty()) {
                args += tmp;
                tmp.clear();
            }
        } else {
            tmp += command.at(i);
        }
    }
    if (!tmp.isEmpty())
        args += tmp;

    return args;
}
#endif

void TLSKeylogDialog::on_launchActivated()
{
    QProcess externalProcess;
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();

    QString keylog = ui->keylogLineEdit->text();
    if (keylog.isEmpty())
        return;
    QString command = ui->commandLineEdit->text();
    if (command.isEmpty())
        return;
#if (QT_VERSION >= QT_VERSION_CHECK(5, 15, 0))
    QStringList commandArgs = QProcess::splitCommand(command);
#else
    QStringList commandArgs = splitCommand(command);
#endif
    if (commandArgs.isEmpty())
        return;

    // This should work with command lines such as:
    // - firefox
    // - firefox -profile /tmp/ff
    // - /usr/bin/firefox -profile /tmp/ff
    // - "C:\Program Files\Mozilla Firefox\firefox.exe"
    // - "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --user-data-dir=/tmp/cr
    externalProcess.setProgram(commandArgs.takeFirst());
    externalProcess.setArguments(commandArgs);

    env.insert("SSLKEYLOGFILE", keylog);
    externalProcess.setProcessEnvironment(env);
    bool ok = externalProcess.startDetached();
    if (ok) {
        return;
    }

    QString error = externalProcess.errorString();
    if (!error.isEmpty())
        report_failure("Error launching command: %s", qUtf8Printable(error));
    else
        report_failure("Error launching command");
}

// Restore user preferences
void TLSKeylogDialog::on_resetActivated()
{
    QString keylog_path;
    QString tlskeylog_command;

    if (pref_tls_keylog_) {
        keylog_path = prefs_get_string_value(pref_tls_keylog_, pref_current);
        ui->keylogLineEdit->setText(keylog_path);
    }
    tlskeylog_command = prefs_get_string_value(pref_tlskeylog_command_, pref_current);
    ui->commandLineEdit->setText(tlskeylog_command);
}

void TLSKeylogDialog::on_browseKeylogPath()
{
    QString caption = mainApp->windowTitleString(tr("TLS Keylog file"));
    QString file_name = WiresharkFileDialog::getSaveFileName(this, caption,
                            mainApp->openDialogInitialDir().path());
    if (!file_name.isEmpty()) {
        ui->keylogLineEdit->setText(file_name);
    }
}

void TLSKeylogDialog::on_browseProgramPath()
{
    QString caption = mainApp->windowTitleString(tr("Program to start with SSLKEYLOGFILE"));
    QString file_name = WiresharkFileDialog::getOpenFileName(this, caption);
    if (file_name.isEmpty()) {
        return;
    }
#ifdef Q_OS_MAC
    if (file_name.endsWith(".app")) {
        QString base_name = QFileInfo(file_name).baseName();
        QString bundle_exe_name = QString("%1/Contents/MacOS/%2").arg(file_name, base_name);
        if (QFile::exists(bundle_exe_name)) {
            file_name = bundle_exe_name;
        }
    }
#endif
    // If the program contains spaces, quote it to ensure it is not broken up
    // into multiple arguments.
    if (file_name.contains(" ")) {
        file_name = QString("\"%1\"").arg(file_name);
    }
    ui->commandLineEdit->setText(file_name);
}
