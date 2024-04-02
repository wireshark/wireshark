/* simple_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "simple_dialog.h"

#include "file.h"

#include "epan/strutil.h"
#include "epan/prefs.h"

#include "ui/commandline.h"

#include <wsutil/utf8_entities.h>
#include <wsutil/wslog.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include "main_application.h"

#include <functional>
#include <QCheckBox>
#include <QMessageBox>
#include <QMutex>
#include <QRegularExpression>
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

struct VisibleAsyncMessage
{
    QMessageBox *box;
    int counter;

    VisibleAsyncMessage(QMessageBox *box) : box(box), counter(0) {}
};

static QList<VisibleAsyncMessage> visible_messages;
static QMutex visible_messages_mutex;

static void visible_message_finished(QMessageBox *box, int result _U_)
{
    visible_messages_mutex.lock();
    for (int i = 0; i < visible_messages.size(); i++) {
        if (visible_messages[i].box == box) {
            if (visible_messages[i].counter) {
                ws_log(LOG_DOMAIN_MAIN, LOG_LEVEL_WARNING, "%d duplicates of \"%s\" were suppressed",
                    visible_messages[i].counter, box->text().toStdString().c_str());
            }
            visible_messages.removeAt(i);
            break;
        }
    }
    visible_messages_mutex.unlock();
}

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

void *
simple_dialog(ESD_TYPE_E type, int btn_mask, const char *msg_format, ...)
{
    va_list ap;

    va_start(ap, msg_format);
    SimpleDialog sd(mainApp->mainWindow(), type, btn_mask, msg_format, ap);
    va_end(ap);

    sd.exec();
    return NULL;
}

void *
simple_dialog_async(ESD_TYPE_E type, int btn_mask, const char *msg_format, ...)
{
    va_list ap;

    va_start(ap, msg_format);
    SimpleDialog sd(mainApp->mainWindow(), type, btn_mask, msg_format, ap);
    va_end(ap);

    sd.show();
    return NULL;
}

/*
 * Alert box, with optional "don't show this message again" variable
 * and checkbox, and optional secondary text.
 */
void
simple_message_box(ESD_TYPE_E type, bool *notagain,
                   const char *secondary_msg, const char *msg_format, ...)
{
    if (notagain && *notagain) {
        return;
    }

    va_list ap;

    va_start(ap, msg_format);
    SimpleDialog sd(mainApp->mainWindow(), type, ESD_BTN_OK, msg_format, ap);
    va_end(ap);

    sd.setDetailedText(secondary_msg);

    QCheckBox *cb = NULL;
    if (notagain) {
        cb = new QCheckBox();
        cb->setChecked(true);
        cb->setText(SimpleDialog::dontShowThisAgain());
        sd.setCheckBox(cb);
    }

    sd.exec();

    if (notagain && cb) {
        *notagain = cb->isChecked();
    }
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

    SimpleDialog sd(mainApp->mainWindow(), ESD_TYPE_ERROR, ESD_BTN_OK, msg_format, ap);
    sd.show();
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

    SimpleDialog sd(mainApp->mainWindow(), ESD_TYPE_WARN, ESD_BTN_OK, msg_format, ap);
    sd.show();
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
    check_box_(0),
    message_box_(0)
{
    char *vmessage;
    QString message;

    vmessage = ws_strdup_vprintf(msg_format, ap);
#ifdef _WIN32
    //
    // On Windows, filename strings inside Wireshark are UTF-8 strings,
    // so error messages containing file names are UTF-8 strings.  Convert
    // from UTF-8, not from the local code page.
    //
    message = QString().fromUtf8(vmessage, -1);
#else
    //
    // On UN*X, who knows?  Assume the locale's encoding.
    //
    message = QTextCodec::codecForLocale()->toUnicode(vmessage);
#endif
    g_free(vmessage);

    MessagePair msg_pair = splitMessage(message);
    // Remove leading and trailing whitespace along with excessive newline runs.
    QString primary = msg_pair.first.trimmed();
    QString secondary = msg_pair.second.trimmed();
    secondary.replace(QRegularExpression("\n\n+"), "\n\n");

    if (primary.isEmpty()) {
        return;
    }

    if (!parent || !mainApp->isInitialized() || mainApp->isReloadingLua()) {
        message_queue_ << msg_pair;
        if (type > max_severity_) {
            max_severity_ = type;
        }
        return;
    }

    message_box_ = new QMessageBox(parent);
    message_box_->setTextFormat(Qt::PlainText);
    message_box_->setTextInteractionFlags(Qt::TextSelectableByMouse);

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

    QMessageBox mb(parent ? parent : mainApp->mainWindow());

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

QString SimpleDialog::dontShowThisAgain()
{
    return QObject::tr("Don't show this message again.");
}

int SimpleDialog::exec()
{
    if (!message_box_) {
        return 0;
    }

    message_box_->setDetailedText(detailed_text_);
    message_box_->setCheckBox(check_box_);

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

void SimpleDialog::show()
{
    if (!message_box_) {
        return;
    }

    message_box_->setDetailedText(detailed_text_);
    message_box_->setCheckBox(check_box_);

    visible_messages_mutex.lock();
    bool found = false;
    for (int i = 0; i < visible_messages.size(); i++) {
        VisibleAsyncMessage &msg = visible_messages[i];
        if ((msg.box->icon() == message_box_->icon()) &&
            (msg.box->checkBox() == message_box_->checkBox()) &&
            (msg.box->text() == message_box_->text()) &&
            (msg.box->informativeText() == message_box_->informativeText()) &&
            (msg.box->detailedText() == message_box_->detailedText()))
        {
            /* Message box of same type with same text is already visible. */
            msg.counter++;
            found = true;
            break;
        }
    }
    if (!found) {
        visible_messages.append(VisibleAsyncMessage(message_box_));
    }
    visible_messages_mutex.unlock();

    if (found)
    {
        delete message_box_;
    }
    else
    {
        QObject::connect(message_box_, &QMessageBox::finished,
            std::bind(visible_message_finished,message_box_,std::placeholders::_1));
        message_box_->setModal(Qt::WindowModal);
        message_box_->setAttribute(Qt::WA_DeleteOnClose);
        message_box_->show();
    }

    /* Message box was shown and will be deleted once user closes it */
    message_box_ = 0;
}

const MessagePair SimpleDialog::splitMessage(QString &message) const
{
    if (message.startsWith(primary_delimiter_)) {
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
        QStringList parts = message.split(primary_delimiter_, Qt::SkipEmptyParts);
#else
        QStringList parts = message.split(primary_delimiter_, QString::SkipEmptyParts);
#endif
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
