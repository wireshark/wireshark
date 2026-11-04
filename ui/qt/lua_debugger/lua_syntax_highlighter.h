/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LUA_SYNTAX_HIGHLIGHTER_H
#define LUA_SYNTAX_HIGHLIGHTER_H

#include <ui/qt/utils/theme_manager.h>

#include <QColor>
#include <QHash>
#include <QRegularExpression>
#include <QString>
#include <QSyntaxHighlighter>
#include <QTextCharFormat>
#include <QVector>
#include <QtGlobal>

class QTextDocument;

/**
 * @brief Syntax highlighter tuned for Lua keywords, strings, numbers,
 *        comments and Lua's long-bracket strings/comments.
 *
 * Colours come from the theme's @c code section (ThemeManager::Code*
 * tokens).  By default they are read from the live theme for the active
 * light/dark mode; call @ref updateColors after a theme or mode change.
 * The Theme Designer passes a draft's colours with @ref setColors instead.
 */
class LuaSyntaxHighlighter : public QSyntaxHighlighter
{
  public:
    /** @brief Build the rule set from the current theme and bind to @p parent's document. */
    explicit LuaSyntaxHighlighter(QTextDocument *parent);

    /** @brief Rebuild the rule set from the current theme colours and rehighlight. */
    void updateColors();

    /**
     * @brief Use @p colors instead of the live theme, then rehighlight.
     * @param colors Code* token to colour; a missing token falls back to the
     *               live theme. An empty map means the live theme.
     */
    void setColors(const QHash<ThemeManager::ThemeToken, QColor> &colors);

  protected:
    /** @brief Apply highlighting to a single text block. */
    void highlightBlock(const QString &text) override;

  private:
    /**
     * @brief A single syntax highlighting rule pairing a regex pattern with a text format.
     */
    struct Rule
    {
        QRegularExpression pattern;  /**< Regular expression used to match tokens in source text. */
        QTextCharFormat format;      /**< Text character format applied to matched tokens. */
    };


    QVector<Rule> rules_;                    /**< Ordered list of syntax highlighting rules applied in sequence. */
    QTextCharFormat stringFormat_;           /**< Text format applied to string literals. */
    QTextCharFormat commentFormat_;          /**< Text format applied to comment text. */
    QRegularExpression singleLineComment_;   /**< Regular expression used to detect single-line comments. */
    QHash<ThemeManager::ThemeToken, QColor> colors_;  /**< Colours set with setColors(); empty for the live theme. */

    /** @brief The colour of @p token: from @c colors_, else the live theme. */
    QColor color(ThemeManager::ThemeToken token) const;

    /** @brief Highlight multi-line strings or comments, preserving parser state. */
    bool highlightLongBlock(const QString &text, bool isComment, bool continuingPrevious, qint32 eqCountFromState,
                            qint32 &nextStateEqCount);
    /** @brief Locate the beginning of a Lua long bracket token. */
    qint32 findLongBlockStart(const QString &text, qint32 from, bool isComment, qint32 &eqCount,
                              qint32 &tokenLength) const;
    /** @brief Locate the closing delimiter for a Lua long bracket token. */
    qint32 findLongBlockEnd(const QString &text, qint32 from, qint32 eqCount) const;

    /** @brief Build the syntax-highlighting rules from the current theme colours and store them in @c rules_. */
    void buildRules();
};

#endif // LUA_SYNTAX_HIGHLIGHTER_H
