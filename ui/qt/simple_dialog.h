/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SIMPLE_DIALOG_H
#define SIMPLE_DIALOG_H

#include <config.h>

#include <stdio.h>

#include "ui/simple_dialog.h"

#include <QPair>
#include <QString>

class QCheckBox;
class QMessageBox;
class QWidget;

/**
 * @brief Thin wrapper around QMessageBox that can be constructed before Qt is
 *        fully initialised, queuing messages for deferred display if necessary.
 *
 * Because instances may be created before the Qt event loop is running,
 * this is a plain non-Qt object (no Q_OBJECT macro, no QObject base).
 */
class SimpleDialog
{
public:
    /**
     * @brief Constructs a SimpleDialog, building the underlying QMessageBox if
     *        Qt is ready, or queuing the message for later display via
     *        displayQueuedMessages() if it is not.
     * @param parent        Parent widget for the QMessageBox; may be @c nullptr.
     * @param type          Severity/type of the dialog (ESD_TYPE_INFO, ESD_TYPE_WARN, etc.).
     * @param btn_mask      Bitmask of buttons to show (ESD_BTN_* constants).
     * @param msg_format    printf-style format string for the primary message text.
     * @param ap            Variadic argument list for @p msg_format.
     * @param secondary_msg Optional secondary (informative) message shown below the primary text.
     */
    explicit SimpleDialog(QWidget *parent, ESD_TYPE_E type, int btn_mask,
                          const char *msg_format, va_list ap,
                          QString secondary_msg = QString());

    /**
     * @brief Destroys the SimpleDialog and the underlying QMessageBox if one was created.
     */
    ~SimpleDialog();

    /**
     * @brief Displays any messages that were queued before Qt was initialised.
     *
     * Should be called once the Qt event loop is running and a main window is
     * available.
     *
     * @param parent Optional parent widget for the queued message boxes.
     */
    static void displayQueuedMessages(QWidget *parent = 0);

    /**
     * @brief Returns the standard label text for a "Don't show this again" check box.
     * @return Localised "Don't show this again" string.
     */
    static QString dontShowThisAgain();

    /**
     * @brief Sets the informative (secondary) text shown below the main message.
     * @param text Informative text string.
     */
    void setInformativeText(QString text) { informative_text_ = text; }

    /**
     * @brief Sets the detailed text shown in the expandable details area.
     * @param text Detailed text string.
     */
    void setDetailedText(QString text) { detailed_text_ = text; }

    /**
     * @brief Attaches a check box (e.g. "Don't show this again") to the dialog.
     * @param cb Pointer to the QCheckBox to embed; ownership is not transferred.
     */
    void setCheckBox(QCheckBox *cb) { check_box_ = cb; }

    /**
     * @brief Shows the dialog modally and returns the result code of the button
     *        that was clicked.
     * @return QDialog::Accepted, QDialog::Rejected, or a QMessageBox::StandardButton value.
     */
    int exec();

    /**
     * @brief Shows the dialog modelessly (non-blocking).
     */
    void show();

private:
    QString     informative_text_; /**< Secondary informative text displayed below the main message. */
    QString     detailed_text_;    /**< Expandable detailed text shown in the details area. */
    QCheckBox  *check_box_;        /**< Optional check box embedded in the dialog (e.g. "Don't show again"). */
    QMessageBox *message_box_;     /**< Underlying QMessageBox; @c nullptr if Qt was not yet initialised. */
};

#endif // SIMPLE_DIALOG_H
