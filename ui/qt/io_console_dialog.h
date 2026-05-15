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

/**
 * @brief A generic interactive console dialog used primarily by funnel plugins (e.g., Lua).
 */
class IOConsoleDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new IOConsoleDialog.
     * @param parent The parent widget.
     * @param title The title of the console window.
     * @param eval_cb The callback function used to evaluate text input from the user.
     * @param open_cb The callback function executed when the console is successfully opened.
     * @param close_cb The callback function executed when the console is closed.
     * @param callback_data User data passed to the callback functions.
     */
    explicit IOConsoleDialog(QWidget &parent,
                                QString title,
                                funnel_console_eval_cb_t eval_cb,
                                funnel_console_open_cb_t open_cb,
                                funnel_console_close_cb_t close_cb,
                                void *callback_data);

    /**
     * @brief Destroys the IOConsoleDialog.
     */
    ~IOConsoleDialog();

    /**
     * @brief Appends text to the console's output area.
     * @param text The text string to append.
     */
    void appendOutputText(const QString &text);

    /**
     * @brief Sets the hint text displayed near the input area.
     * @param text The hint text string.
     */
    void setHintText(const QString &text);

    /**
     * @brief Clears the currently displayed hint text.
     */
    void clearHintText();

private slots:
    /**
     * @brief Slot triggered to process and evaluate the user's input.
     */
    void acceptInput();

    /**
     * @brief Slot triggered to clear the console's output and input areas.
     */
    void on_clearActivated(void);

    /**
     * @brief Slot triggered to clear specifically the success hint message.
     */
    void clearSuccessHint(void);

private:
    /** Pointer to the generated UI elements. */
    Ui::IOConsoleDialog *ui;

    /** Callback function to evaluate user input. */
    funnel_console_eval_cb_t eval_cb_;

    /** Callback function triggered when the dialog opens. */
    funnel_console_open_cb_t open_cb_;

    /** Callback function triggered when the dialog closes. */
    funnel_console_close_cb_t close_cb_;

    /** Pointer to custom user data passed into the callbacks. */
    void *callback_data_;
};

#endif // IO_CONSOLE_DIALOG_H
