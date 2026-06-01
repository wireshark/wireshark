/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILTER_COMPLETER_H
#define FILTER_COMPLETER_H

#include <QCompleter>
#include <QString>
#include <QStringList>

/**
 * @brief QCompleter base for filter expressions, attachable to any QLineEdit.
 *
 * Token semantics live here rather than in the line edit. By overriding
 * QCompleter::splitPath() and QCompleter::pathFromIndex(), the standard
 * QCompleter machinery performs the "replace the token under the cursor with the
 * chosen completion" step natively; the host widget does not hand-roll
 * insertion.
 *
 * The base provides a whitespace-token default: splitPath() returns the final
 * whitespace-delimited word as the completion prefix, and pathFromIndex()
 * returns the selected row's text. Subclasses (DisplayFilterCompleter,
 * CaptureFilterCompleter) refine the token character set and the
 * "too complex to complete" guard.
 */
class FilterCompleter : public QCompleter
{
    Q_OBJECT

public:
    explicit FilterCompleter(QObject *parent = nullptr);

    /**
     * @brief Sets the characters considered part of a single completion token.
     * @param token_chars Characters valid within a token (e.g. letters, digits,
     *                    underscore, dot). Empty means "split on whitespace".
     */
    void setTokenChars(const QString &token_chars) { token_chars_ = token_chars; }

    /** @brief Returns the configured token characters. */
    const QString &tokenChars() const { return token_chars_; }

    /**
     * @brief Splits @p path into the prefix QCompleter should match against.
     * @return A single-element list holding the token under/before the cursor.
     */
    QStringList splitPath(const QString &path) const override;

    /**
     * @brief Maps a chosen completion row back to the text to insert.
     */
    QString pathFromIndex(const QModelIndex &index) const override;

protected:
    QString token_chars_; /**< Characters valid within a completion token. */
};

#endif // FILTER_COMPLETER_H
