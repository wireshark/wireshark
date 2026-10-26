/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "jsonc_document.h"

#include <wsutil/wsjson.h>

#include <QJsonParseError>
#include <QRegularExpression>

bool JsoncDocument::parse(const QByteArray &jsonc)
{
    document_ = QJsonDocument();
    text_.clear();
    error_string_.clear();
    error_line_ = 0;
    error_column_ = 0;

    // json_strip_jsonc_comments() works in place on a NUL-terminated
    // buffer; QByteArray::data() of the copy is one.
    QByteArray json = jsonc;
    if (!json_strip_jsonc_comments(json.data())) {
        error_string_ = tr("A block comment is not closed.");
        return false;
    }
    text_ = QString::fromUtf8(json);

    QJsonParseError parse_error;
    document_ = QJsonDocument::fromJson(json, &parse_error);
    if (document_.isNull()) {
        const QByteArray head = json.left(parse_error.offset);
        error_line_ = int(head.count('\n')) + 1;
        error_column_ = int(head.size() - (head.lastIndexOf('\n') + 1)) + 1;
        error_string_ = parse_error.errorString();
        return false;
    }
    return true;
}

int JsoncDocument::lineOf(const QString &name, const QString &child) const
{
    auto find = [this](const QString &key, qsizetype from) -> qsizetype {
        const QRegularExpression re(QStringLiteral("\"%1\"\\s*:")
                                        .arg(QRegularExpression::escape(key)));
        const QRegularExpressionMatch m = re.match(text_, from);
        return m.hasMatch() ? m.capturedStart() : -1;
    };

    qsizetype pos = find(name, 0);
    if (pos < 0)
        return 0;
    if (!child.isEmpty()) {
        pos = find(child, pos + name.size());
        if (pos < 0)
            return 0;
    }
    return int(text_.left(pos).count(QLatin1Char('\n'))) + 1;
}
