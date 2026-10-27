/* field_filter_edit.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/proto.h>

#include <wsutil/utf8_entities.h>

#include <ui/qt/widgets/field_filter_edit.h>
#include "filter_dialog.h"
#include <ui/qt/widgets/syntax_line_edit.h>

#include <QAction>
#include <QCompleter>
#include <QEvent>
#include <QStringListModel>

#include <wsutil/utf8_entities.h>

#ifdef __APPLE__
#define DEFAULT_MODIFIER UTF8_PLACE_OF_INTEREST_SIGN
#else
#define DEFAULT_MODIFIER "Ctrl-"
#endif

// proto.c:fld_abbrev_chars
static const QString fld_abbrev_chars_ = "-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

FieldFilterEdit::FieldFilterEdit(QWidget *parent) :
    SyntaxLineEdit(parent)
{
    setAccessibleName(tr("Field entry"));

    completion_model_ = new QStringListModel(this);
    setCompleter(new QCompleter(completion_model_, this));
    setCompletionTokenChars(fld_abbrev_chars_);

    setDefaultPlaceholderText();

    connect(this, &FieldFilterEdit::textChanged, this,
            static_cast<void (FieldFilterEdit::*)(const QString &)>(&FieldFilterEdit::checkFilter));
}

void FieldFilterEdit::setFieldListMode(bool enabled)
{
    list_mode_ = enabled;
    setDefaultPlaceholderText();
    checkFilter(text());
}

void FieldFilterEdit::setMaxFields(int max_fields)
{
    max_fields_ = max_fields;
    setDefaultPlaceholderText();
    checkFilter(text());
}

QStringList FieldFilterEdit::splitFieldList(const QString &text)
{
    QStringList tokens;
    if (text.trimmed().isEmpty()) {
        return tokens;
    }
    for (const QString &token : text.split(',')) {
        tokens << token.trimmed();
    }
    return tokens;
}

QStringList FieldFilterEdit::fieldList() const
{
    if (!list_mode_) {
        const QString field_word = text().trimmed();
        return field_word.isEmpty() ? QStringList() : QStringList(field_word);
    }

    QStringList fields;
    for (const QString &token : splitFieldList(text())) {
        if (!token.isEmpty()) {
            fields << token;
        }
    }
    return fields;
}

void FieldFilterEdit::setDefaultPlaceholderText()
{
    if (list_mode_) {
        if (max_fields_ > 0) {
            placeholder_text_ = tr("Enter up to %1 fields, separated by commas%2")
                    .arg(max_fields_).arg(UTF8_HORIZONTAL_ELLIPSIS);
        } else {
            placeholder_text_ = tr("Enter fields, separated by commas%1")
                    .arg(UTF8_HORIZONTAL_ELLIPSIS);
        }
    } else {
        placeholder_text_ = tr("Enter a field %1").arg(UTF8_HORIZONTAL_ELLIPSIS);
    }

    setPlaceholderText(placeholder_text_);
}

void FieldFilterEdit::focusOutEvent(QFocusEvent *event)
{
    if (syntaxState() == Valid)
        emit popFilterSyntaxStatus();
    SyntaxLineEdit::focusOutEvent(event);
}

bool FieldFilterEdit::checkFilter()
{
    checkFilter(text());

    return syntaxState() != Invalid;
}

void FieldFilterEdit::checkFieldList(const QString &filter_text)
{
    const QStringList tokens = splitFieldList(filter_text);
    QString invalid_msg;
    QString deprecated_msg;

    if (max_fields_ > 0) {
        int entered = 0;
        for (const QString &token : tokens) {
            if (!token.isEmpty()) {
                entered++;
            }
        }
        if (entered > max_fields_) {
            invalid_msg = tr("Up to %1 fields can be combined (%2 entered).")
                    .arg(max_fields_).arg(entered);
        }
    }

    for (int i = 0; invalid_msg.isEmpty() && i < tokens.size(); i++) {
        const QString &token = tokens.at(i);
        if (token.isEmpty()) {
            invalid_msg = tr("Field %1 is empty.").arg(i + 1);
            break;
        }
        const QByteArray token_ba = token.toUtf8();
        if (proto_registrar_get_byname(token_ba.constData())) {
            continue;
        }
        const header_field_info *hfinfo = proto_registrar_get_byalias(token_ba.constData());
        if (!hfinfo) {
            invalid_msg = tr("\"%1\" is neither a field nor a protocol name.").arg(token);
        } else if (deprecated_msg.isEmpty()) {
            deprecated_msg = tr("\"%1\" is deprecated. Use \"%2\" instead.")
                    .arg(token, hfinfo->abbrev);
        }
    }

    if (tokens.isEmpty()) {
        list_message_.clear();
        setSyntaxState(SyntaxLineEdit::Empty);
    } else if (!invalid_msg.isEmpty()) {
        list_message_ = invalid_msg;
        setSyntaxState(SyntaxLineEdit::Invalid);
        emit pushFilterSyntaxStatus(list_message_);
    } else if (!deprecated_msg.isEmpty()) {
        list_message_ = deprecated_msg;
        setSyntaxState(SyntaxLineEdit::Deprecated);
        emit pushFilterSyntaxWarning(list_message_);
    } else {
        list_message_.clear();
        setSyntaxState(SyntaxLineEdit::Valid);
    }
}

void FieldFilterEdit::checkFilter(const QString& filter_text)
{
    popFilterSyntaxStatus();

    if (list_mode_) {
        checkFieldList(filter_text);
        return;
    }

    QString field_word = filter_text.trimmed();

    if (field_word.isEmpty()) {
        setSyntaxState(SyntaxLineEdit::Empty);
    } else {
        const header_field_info *hfinfo = proto_registrar_get_byname(field_word.toUtf8().constData());
        if (hfinfo) {
            setSyntaxState(SyntaxLineEdit::Valid);
        } else {
            hfinfo = proto_registrar_get_byalias(field_word.toUtf8().constData());
            if (hfinfo) {
                setSyntaxState(SyntaxLineEdit::Deprecated);
            } else {
                setSyntaxState(SyntaxLineEdit::Invalid);
            }
        }
    }

    switch (syntaxState()) {
    case Deprecated:
    {
        emit pushFilterSyntaxWarning(syntaxErrorMessage());
        break;
    }
    case Invalid:
    {
        QString invalidMsg(tr("Invalid field: "));
        invalidMsg.append(syntaxErrorMessage());
        emit pushFilterSyntaxStatus(invalidMsg);
        break;
    }
    default:
        break;
    }
}

void FieldFilterEdit::buildCompletionList(const QString &field_word, const QString &preamble)
{
    // Push a hint about the current field.
    if (syntaxState() == Valid) {
        emit popFilterSyntaxStatus();

        header_field_info *hfinfo = proto_registrar_get_byname(field_word.toUtf8().constData());
        if (hfinfo) {
            QString cursor_field_msg = QStringLiteral("%1: %2")
                    .arg(hfinfo->name)
                    .arg(ftype_pretty_name(hfinfo->type));
            emit pushFilterSyntaxStatus(cursor_field_msg);
        }
    }

    // Single fields only; don't offer completion if there's a preamble. In
    // list mode the preamble is the already entered fields, which end in a comma.
    if (!preamble.isEmpty() && !(list_mode_ && preamble.endsWith(','))) {
        completion_model_->setStringList(QStringList());
        return;
    }

    if (field_word.length() < 1) {
        completion_model_->setStringList(QStringList());
        return;
    }

    void *proto_cookie;
    QStringList field_list;
    int field_dots = static_cast<int>(field_word.count('.')); // Some protocol names (_ws.expert) contain periods.
    for (int proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1; proto_id = proto_get_next_protocol(&proto_cookie)) {
        protocol_t *protocol = find_protocol_by_id(proto_id);
        if (!proto_is_protocol_enabled(protocol)) continue;

        const QString pfname = proto_get_protocol_filter_name(proto_id);
        field_list << pfname;

        // Add fields only if we're past the protocol name and only for the
        // current protocol.
        if (field_dots > pfname.count('.')) {
            void *field_cookie;
            const QByteArray fw_ba = field_word.toUtf8(); // or toLatin1 or toStdString?
            const char *fw_utf8 = fw_ba.constData();
            size_t fw_len = (size_t) strlen(fw_utf8);
            for (header_field_info *hfinfo = proto_get_first_protocol_field(proto_id, &field_cookie); hfinfo; hfinfo = proto_get_next_protocol_field(proto_id, &field_cookie)) {
                if (hfinfo->same_name_prev_id != -1) continue; // Ignore duplicate names.

                if (!g_ascii_strncasecmp(fw_utf8, hfinfo->abbrev, fw_len)) {
                    if ((size_t) strlen(hfinfo->abbrev) != fw_len) field_list << hfinfo->abbrev;
                }
            }
        }
    }
    field_list.sort();

    completion_model_->setStringList(field_list);
    completer()->setCompletionPrefix(field_word);
}

void FieldFilterEdit::changeEvent(QEvent* event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            setDefaultPlaceholderText();
            break;
        default:
            break;
        }
    }
    SyntaxLineEdit::changeEvent(event);
}
