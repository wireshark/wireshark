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
#include <QAbstractItemView>
#include <QEvent>
#include <QScrollBar>

FilterCompleter::FilterCompleter(QObject *parent) :
    QCompleter(parent)
{
    setCaseSensitivity(Qt::CaseInsensitive);
    setCompletionMode(QCompleter::PopupCompletion);
    // History + field completions arrive in their own (recency / registration)
    // order, so do not assume the model is sorted.
    setModelSorting(QCompleter::UnsortedModel);

    // popup() lazily builds the default view; watch it so we can size it to its
    // content rather than the (full-width) host field.
    popup()->installEventFilter(this);
}

bool FilterCompleter::eventFilter(QObject *watched, QEvent *event)
{
    QAbstractItemView *view = popup();
    if (watched == view &&
        (event->type() == QEvent::Show || event->type() == QEvent::Resize)) {
        int content = view->sizeHintForColumn(0) + 2 * view->frameWidth();
        if (view->verticalScrollBar() && view->verticalScrollBar()->isVisible())
            content += view->verticalScrollBar()->sizeHint().width();
        // setFixedWidth pins min == max, so QCompleter's geometry call is clamped
        // to the content width. Guard re-entrancy from the resize we trigger.
        if (content > 0 && view->maximumWidth() != content)
            view->setFixedWidth(content);
    }
    return QCompleter::eventFilter(watched, event);
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
