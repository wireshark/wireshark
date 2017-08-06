/* simple_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "simple_dialog.h"

#include "file.h"

#include "epan/strutil.h"
#include "epan/prefs.h"

#include "ui/commandline.h"

#include <wsutil/utf8_entities.h>

#include "qt_ui_utils.h"
#include "wireshark_application.h"

#if (QT_VERSION > QT_VERSION_CHECK(5, 2, 0))
#include <QCheckBox>
#endif
#include <QMessageBox>
#include <QRegExp>
#include <QTextCodec>

/* Simple dialog function - Displays a dialog box with the supplied message
 * text.
 *
 * This is meant to be used as a backend for the functions defined in
 * ui/simple_dialog.h. Qt code should use QMessageBox directly.
 *
 * Args:
 * type       : One of ESD_TYPE_*.
 * btn_mask   : The value passed in determines which buttons are displayed.
 * msg_format : Sprintf-style format of the text displayed in the dialog.
 * ...        : Argument list for msg_format
 */

QList<MessagePair> message_queue_;
ESD_TYPE_E max_severity_ = ESD_TYPE_INFO;

const char *primary_delimiter_ = "__CB754A38-94A2-4E59-922D-DD87EDC80E22__";

const char *
simple_dialog_primary_start(void) {
    return primary_delimiter_;
}

const char *
simple_dialog_primary_end(void) {
    return primary_delimiter_;
}

char *
simple_dialog_format_message(const char *msg)
{
    return g_strdup(msg);
}

gpointer
simple_dialog(ESD_TYPE_E type, gint btn_mask, const gchar *msg_format, ...)
{
    va_list ap;

    va_start(ap, msg_format);
    SimpleDialog sd(wsApp->mainWindow(), type, btn_mask, msg_format, ap);
    va_end(ap);

    sd.exec();
    return NULL;
}

/*
 * Alert box, with optional "don't show this message again" variable
 * and checkbox, and optional secondary text.
 */
void
simple_message_box(ESD_TYPE_E type, gboolean *notagain,
                   const char *secondary_msg, const char *msg_format, ...)
{
    if (notagain && *notagain) {
        return;
    }

    va_list ap;

    va_start(ap, msg_format);
    SimpleDialog sd(wsApp->mainWindow(), type, ESD_BTN_OK, msg_format, ap);
    va_end(ap);

    sd.setDetailedText(secondary_msg);

#if (QT_VERSION > QT_VERSION_CHECK(5, 2, 0))
    QCheckBox *cb = NULL;
    if (notagain) {
        cb = new QCheckBox();
        cb->setChecked(true);
        cb->setText(QObject::tr("Don't show this message again."));
        sd.setCheckBox(cb);
    }
#endif

    sd.exec();

#if (QT_VERSION > QT_VERSION_CHECK(5, 2, 0))
    if (notagain && cb) {
        *notagain = cb->isChecked();
    }
#endif
}

/*
 * Error alert box, taking a format and a va_list argument.
 */
void
vsimple_error_message_box(const char *msg_format, va_list ap)
{
#ifdef HAVE_LIBPCAP
    // We want to quit after reading the capture file, hence
    // we don't actually open the error dialog.
    if (global_commandline_info.quit_after_cap)
        exit(0);
#endif

    SimpleDialog sd(wsApp->mainWindow(), ESD_TYPE_ERROR, ESD_BTN_OK, msg_format, ap);
    sd.exec();
}

/*
 * Warning alert box, taking a format and a va_list argument.
 */
void
vsimple_warning_message_box(const char *msg_format, va_list ap)
{
#ifdef HAVE_LIBPCAP
    // We want to quit after reading the capture file, hence
    // we don't actually open the error dialog.
    if (global_commandline_info.quit_after_cap)
        exit(0);
#endif

    SimpleDialog sd(wsApp->mainWindow(), ESD_TYPE_WARN, ESD_BTN_OK, msg_format, ap);
    sd.exec();
}

/*
 * Error alert box, taking a format and a list of arguments.
 */
void
simple_error_message_box(const char *msg_format, ...)
{
    va_list ap;

    va_start(ap, msg_format);
    vsimple_error_message_box(msg_format, ap);
    va_end(ap);
}

SimpleDialog::SimpleDialog(QWidget *parent, ESD_TYPE_E type, int btn_mask, const char *msg_format, va_list ap) :
#if (QT_VERSION > QT_VERSION_CHECK(5, 2, 0))
    check_box_(0),
#endif
    message_box_(0)
{
    gchar *vmessage;
    QString message;

    vmessage = g_strdup_vprintf(msg_format, ap);
    message = QTextCodec::codecForLocale()->toUnicode(vmessage);
    g_free(vmessage);

    MessagePair msg_pair = splitMessage(message);
    // Remove leading and trailing whitespace along with excessive newline runs.
    QString primary = msg_pair.first.trimmed();
    QString secondary = msg_pair.second.trimmed();
    secondary.replace(QRegExp("\n\n+"), "\n\n");

    if (primary.isEmpty()) {
        return;
    }

    if (!parent || !wsApp->isInitialized() || wsApp->isReloadingLua()) {
        message_queue_ << msg_pair;
        if (type > max_severity_) {
            max_severity_ = type;
        }
        return;
    }

    message_box_ = new QMessageBox(parent);
    message_box_->setTextFormat(Qt::PlainText);
#if QT_VERSION >= QT_VERSION_CHECK(5, 1, 0)
    message_box_->setTextInteractionFlags(Qt::TextSelectableByMouse);
#endif


    switch(type) {
    case ESD_TYPE_ERROR:
        message_box_->setIcon(QMessageBox::Critical);
        break;
    case ESD_TYPE_WARN:
        message_box_->setIcon(QMessageBox::Warning);
        break;
    case ESD_TYPE_CONFIRMATION:
        message_box_->setIcon(QMessageBox::Question);
        break;
    case ESD_TYPE_INFO:
    default:
        message_box_->setIcon(QMessageBox::Information);
        break;
    }

    if (btn_mask & ESD_BTN_OK) {
        message_box_->addButton(QMessageBox::Ok);
    }
    if (btn_mask & ESD_BTN_CANCEL) {
        message_box_->addButton(QMessageBox::Cancel);
    }
    if (btn_mask & ESD_BTN_YES) {
        message_box_->addButton(QMessageBox::Yes);
    }
    if (btn_mask & ESD_BTN_NO) {
        message_box_->addButton(QMessageBox::No);
    }
//    if (btn_mask & ESD_BTN_CLEAR) {
//        addButton(QMessageBox::);
//    }
    if (btn_mask & ESD_BTN_SAVE) {
        message_box_->addButton(QMessageBox::Save);
    }
    if (btn_mask & ESD_BTN_DONT_SAVE) {
        message_box_->addButton(QMessageBox::Discard);
    }
//    if (btn_mask & ESD_BTN_QUIT_DONT_SAVE) {
//        addButton(QMessageBox::);
//    }


    message_box_->setText(primary);
    message_box_->setInformativeText(secondary);
}

SimpleDialog::~SimpleDialog()
{
}

void SimpleDialog::displayQueuedMessages(QWidget *parent)
{
    if (message_queue_.isEmpty()) {
        return;
    }

    QMessageBox mb(parent ? parent : wsApp->mainWindow());

    switch(max_severity_) {
    case ESD_TYPE_ERROR:
        mb.setIcon(QMessageBox::Critical);
        break;
    case ESD_TYPE_WARN:
        mb.setIcon(QMessageBox::Warning);
        break;
    case ESD_TYPE_CONFIRMATION:
        mb.setIcon(QMessageBox::Question);
        break;
    case ESD_TYPE_INFO:
    default:
        mb.setIcon(QMessageBox::Information);
        break;
    }

    mb.addButton(QMessageBox::Ok);

    if (message_queue_.length() > 1) {
        QStringList msg_details;
        QString first_primary = message_queue_[0].first;
        first_primary.append(UTF8_HORIZONTAL_ELLIPSIS);

        mb.setText(QObject::tr("Multiple problems found"));
        mb.setInformativeText(first_primary);

        foreach (MessagePair msg_pair, message_queue_) {
            msg_details << msg_pair.first;
            if (!msg_pair.second.isEmpty()) {
                msg_details.append(msg_pair.second);
            }
        }
        mb.setDetailedText(msg_details.join("\n\n"));
    } else {
        mb.setText(message_queue_[0].first);
        mb.setInformativeText(message_queue_[0].second);
    }

    message_queue_.clear();
    max_severity_ = ESD_TYPE_INFO;

    mb.exec();
}

int SimpleDialog::exec()
{
    if (!message_box_) {
        return 0;
    }

    message_box_->setDetailedText(detailed_text_);
#if (QT_VERSION > QT_VERSION_CHECK(5, 2, 0))
    message_box_->setCheckBox(check_box_);
#endif

    int status = message_box_->exec();
    delete message_box_;
    message_box_ = 0;
    detailed_text_ = QString();

    switch (status) {
    case QMessageBox::Ok:
        return ESD_BTN_OK;
    case QMessageBox::Yes:
        return ESD_BTN_YES;
    case QMessageBox::No:
        return ESD_BTN_NO;
    case QMessageBox::Save:
        return ESD_BTN_SAVE;
    case QMessageBox::Discard:
        return ESD_BTN_DONT_SAVE;
    case QMessageBox::Cancel: // XXX Should OK be the default?
    default:
        return ESD_BTN_CANCEL;
    }
}

const MessagePair SimpleDialog::splitMessage(QString &message) const
{
    if (message.startsWith(primary_delimiter_)) {
        QStringList parts = message.split(primary_delimiter_, QString::SkipEmptyParts);
        switch (parts.length()) {
        case 0:
            return MessagePair(QString(), QString());
        case 1:
            return MessagePair(parts[0], QString());
        default:
            QString first = parts.takeFirst();
            return MessagePair(first, parts.join(" "));
        }
    }
    return MessagePair(message, QString());
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
