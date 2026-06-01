/* filter_validator.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/models/filter_validator.h>

FilterValidator::FilterValidator(QObject *parent) :
    QValidator(parent)
{
}

QString FilterValidator::lastErrorFull(const QString &filter) const
{
    Detail d = lastDetail();
    if (d.errMsg.isEmpty())
        return QString();
    return createSyntaxErrorMessageFull(filter, d.errMsg, d.errPos, static_cast<size_t>(d.errLen));
}

// Carried over verbatim from the retired SyntaxLineEdit so the location
// annotation matches what users have seen historically.
QString FilterValidator::createSyntaxErrorMessageFull(
                                const QString &filter, const QString &err_msg,
                                qsizetype loc_start, size_t loc_length)
{
    QString msg = tr("Invalid filter: %1").arg(err_msg);

    if (loc_start >= 0 && loc_length >= 1) {
        // Add underlined location
        msg = QStringLiteral("<p>%1<pre>  %2\n  %3^%4</pre></p>")
            .arg(msg)
            .arg(filter)
            .arg(QString(' ').repeated(static_cast<int>(loc_start)))
            .arg(QString('~').repeated(static_cast<int>(loc_length) - 1));
    }
    return msg;
}
