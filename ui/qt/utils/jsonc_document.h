/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef JSONC_DOCUMENT_H
#define JSONC_DOCUMENT_H

#include <QByteArray>
#include <QCoreApplication>
#include <QJsonDocument>
#include <QString>

/**
 * A JSON document read from JSONC text (JSON with line and block comments).
 *
 * Comments are blanked by json_strip_jsonc_comments(), which keeps the offset
 * of every other byte, so error positions and lines refer to the original
 * text.  QJsonDocument carries no positions; lineOf() finds a member by
 * searching the text.
 */
class JsoncDocument
{
    Q_DECLARE_TR_FUNCTIONS(JsoncDocument)
public:
    /**
     * Parses @p jsonc.
     * @return true when the text is valid JSON once comments are removed.
     */
    bool parse(const QByteArray &jsonc);

    /** The parsed document; null after a failed parse(). */
    const QJsonDocument &document() const { return document_; }

    /** Why the last parse() failed, translated; empty after success. */
    const QString &errorString() const { return error_string_; }

    /** 1-based line of the syntax error, or 0 when unknown. */
    int errorLine() const { return error_line_; }

    /** 1-based column (in bytes) of the syntax error, or 0 when unknown. */
    int errorColumn() const { return error_column_; }

    /**
     * 1-based line of the member `"name":`, or 0 when it is absent.  With
     * @p child, the line of the first `"child":` after it, which finds a key
     * inside an object in the usual one-member-per-line layout.
     */
    int lineOf(const QString &name, const QString &child = QString()) const;

private:
    QJsonDocument document_;
    QString       text_;          ///< comment-blanked text, for lineOf()
    QString       error_string_;
    int           error_line_ = 0;
    int           error_column_ = 0;
};

#endif // JSONC_DOCUMENT_H
