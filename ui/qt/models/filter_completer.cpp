/* filter_completer.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/models/filter_completer.h>

#include <QAbstractItemModel>

FilterCompleter::FilterCompleter(QObject *parent) :
    QCompleter(parent)
{
    setCaseSensitivity(Qt::CaseInsensitive);
    setCompletionMode(QCompleter::PopupCompletion);
    // History + field completions arrive in their own (recency / registration)
    // order, so do not assume the model is sorted.
    setModelSorting(QCompleter::UnsortedModel);
}

QStringList FilterCompleter::splitPath(const QString &path) const
{
    // Match against the final token. With an explicit token-character set we
    // walk back from the end while characters remain valid; otherwise we fall
    // back to the last whitespace-delimited word.
    qsizetype start = path.length();
    while (start > 0) {
        const QChar c = path.at(start - 1);
        const bool in_token = token_chars_.isEmpty() ? !c.isSpace()
                                                      : token_chars_.contains(c);
        if (!in_token)
            break;
        --start;
    }
    return QStringList(path.mid(start));
}

QString FilterCompleter::pathFromIndex(const QModelIndex &index) const
{
    if (!index.isValid())
        return QString();
    return index.data(Qt::DisplayRole).toString();
}
