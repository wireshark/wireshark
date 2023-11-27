/*
 * io_console_dialog.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#define WS_LOG_DOMAIN LOG_DOMAIN_QTUI
#include "io_console_dialog.h"
#include <ui_io_console_dialog.h>

#include "main_application.h"

extern "C" {
static void print_function(const char *str, void *ptr);
}

static void print_function(const char *str, void *print_data)
{
    IOConsoleDialog *dialog = static_cast<IOConsoleDialog *>(print_data);
    dialog->appendOutputText(QString(str));
}

IOConsoleDialog::IOConsoleDialog(QWidget &parent,
                                QString title,
                                funnel_console_eval_cb_t eval_cb,
                                funnel_console_open_cb_t open_cb,
                                funnel_console_close_cb_t close_cb,
                                void *callback_data = nullptr) :
    GeometryStateDialog(&parent),
    ui(new Ui::IOConsoleDialog),
    eval_cb_(eval_cb),
    open_cb_(open_cb),
    close_cb_(close_cb),
    callback_data_(callback_data)
{
    ui->setupUi(this);

    if (title.isEmpty())
        title = QString("Console");

    loadGeometry(0, 0, title);
    loadSplitterState(ui->splitter);
    setWindowTitle(mainApp->windowTitleString(title));

    QPushButton *eval_button = ui->buttonBox->addButton(tr("Evaluate"), QDialogButtonBox::ActionRole);
    eval_button->setDefault(true);
    eval_button->setShortcut(QKeySequence("Ctrl+Return"));
    connect(eval_button, &QPushButton::clicked, this, &IOConsoleDialog::acceptInput);

    QPushButton *clear_button = ui->buttonBox->addButton(tr("Clear"), QDialogButtonBox::ActionRole);
    connect(clear_button, &QPushButton::clicked, this, &IOConsoleDialog::on_clearActivated);

    ui->inputTextEdit->setFont(mainApp->monospaceFont());
    ui->inputTextEdit->setPlaceholderText(QString(tr("Use %1 to evaluate."))
            .arg(eval_button->shortcut().toString(QKeySequence::NativeText)));

    ui->outputTextEdit->setFont(mainApp->monospaceFont());
    ui->outputTextEdit->setReadOnly(true);

    ui->hintLabel->clear();

    // Install print
    open_cb_(print_function, this, callback_data_);
}

IOConsoleDialog::~IOConsoleDialog()
{
    delete ui;
    // Remove print
    close_cb_(callback_data_);
}

void IOConsoleDialog::setHintText(const QString &text)
{
    ui->hintLabel->setText(QString("<small><i>%1.</i></small>").arg(text));
}

void IOConsoleDialog::clearHintText()
{
    ui->hintLabel->clear();
}

void IOConsoleDialog::clearSuccessHint()
{
    // Text changed so we no longer have a success.
    ui->hintLabel->clear();
    // Disconnect this slot until the next success.
    disconnect(ui->inputTextEdit, &QTextEdit::textChanged, this, &IOConsoleDialog::clearSuccessHint);
}

void IOConsoleDialog::acceptInput()
{
    clearHintText();

    QString text = ui->inputTextEdit->toPlainText();
    if (text.isEmpty())
        return;

    char *error_str = nullptr;
    char *error_hint = nullptr;
    int result = eval_cb_(qUtf8Printable(text), &error_str, &error_hint, callback_data_);
    if (result != 0) {
        if (error_hint) {
            QString hint(error_hint);
            setHintText(hint.at(0).toUpper() + hint.mid(1));
            g_free(error_hint);
        }
        else if (result < 0) {
            setHintText("Error loading string");
        }
        else {
            setHintText("Error running chunk");
        }
        if (error_str) {
            appendOutputText(QString(error_str));
            g_free(error_str);
        }
    }
    else {
        setHintText("Code evaluated successfully");
        connect(ui->inputTextEdit, &QTextEdit::textChanged, this, &IOConsoleDialog::clearSuccessHint);
    }
}

void IOConsoleDialog::appendOutputText(const QString &text)
{
    ui->outputTextEdit->append(text);
}

void IOConsoleDialog::on_clearActivated()
{
    ui->inputTextEdit->clear();
    ui->outputTextEdit->clear();
    ui->hintLabel->clear();
}
