/* lua_syntax_highlighter.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/lua_debugger/lua_syntax_highlighter.h>

#include <QFont>
#include <QRegularExpressionMatch>
#include <QRegularExpressionMatchIterator>
#include <QStringList>
#include <QTextDocument>

namespace
{

constexpr qint32 kStringStateBase = 0x1000;  // Unique positive range for long strings
constexpr qint32 kCommentStateBase = 0x2000; // Distinct positive range for block comments

} // namespace

LuaSyntaxHighlighter::LuaSyntaxHighlighter(QTextDocument *parent) : QSyntaxHighlighter(parent)
{
    singleLineComment_ = QRegularExpression(QStringLiteral(R"(--(?!\[).*)"));
    buildRules();
}

void LuaSyntaxHighlighter::updateColors()
{
    buildRules();
    rehighlight();
}

void LuaSyntaxHighlighter::setColors(const QHash<ThemeManager::ThemeToken, QColor> &colors)
{
    colors_ = colors;
    updateColors();
}

QColor LuaSyntaxHighlighter::color(ThemeManager::ThemeToken token) const
{
    const QColor color = colors_.value(token);
    return color.isValid() ? color : ThemeManager::instance()->color(token);
}

void LuaSyntaxHighlighter::buildRules()
{
    rules_.clear();

    stringFormat_.setForeground(color(ThemeManager::CodeString));
    rules_.append({QRegularExpression(QStringLiteral("\"(?:\\\\.|[^\"\\\\])*\"")), stringFormat_});
    rules_.append({QRegularExpression(QStringLiteral("'(?:\\\\.|[^'\\\\])*'")), stringFormat_});

    QTextCharFormat keywordFormat;
    keywordFormat.setForeground(color(ThemeManager::CodeKeyword));
    keywordFormat.setFontWeight(QFont::Bold);
    const QStringList keywords = {
        QStringLiteral("and"),      QStringLiteral("break"),  QStringLiteral("do"),    QStringLiteral("else"),
        QStringLiteral("elseif"),   QStringLiteral("end"),    QStringLiteral("false"), QStringLiteral("for"),
        QStringLiteral("function"), QStringLiteral("goto"),   QStringLiteral("if"),    QStringLiteral("in"),
        QStringLiteral("local"),    QStringLiteral("nil"),    QStringLiteral("not"),   QStringLiteral("or"),
        QStringLiteral("repeat"),   QStringLiteral("return"), QStringLiteral("then"),  QStringLiteral("true"),
        QStringLiteral("until"),    QStringLiteral("while")};
    for (const QString &keyword : keywords)
    {
        Rule rule;
        rule.pattern = QRegularExpression(QStringLiteral("\\b%1\\b").arg(keyword));
        rule.format = keywordFormat;
        rules_.append(rule);
    }

    QTextCharFormat numberFormat;
    numberFormat.setForeground(color(ThemeManager::CodeNumber));
    rules_.append({QRegularExpression(QStringLiteral("\\b0[xX][0-9a-fA-F]+\\b")), numberFormat});
    rules_.append({QRegularExpression(QStringLiteral("\\b\\d+(?:\\.\\d+)?\\b")), numberFormat});

    QTextCharFormat builtInFormat;
    builtInFormat.setForeground(color(ThemeManager::CodeBuiltIn));
    rules_.append({QRegularExpression(QStringLiteral("\\bself\\b")), builtInFormat});

    QTextCharFormat functionCallFormat;
    functionCallFormat.setForeground(color(ThemeManager::CodeFunctionCall));
    Rule functionCallRule;
    functionCallRule.pattern = QRegularExpression(QStringLiteral("\\b(?!function\\b)([A-Za-z_]\\w*)\\s*(?=\\()"));
    functionCallRule.format = functionCallFormat;
    rules_.append(functionCallRule);

    commentFormat_.setForeground(color(ThemeManager::CodeComment));
}

void LuaSyntaxHighlighter::highlightBlock(const QString &text)
{
    for (const Rule &rule : rules_)
    {
        QRegularExpressionMatchIterator iterator = rule.pattern.globalMatch(text);
        while (iterator.hasNext())
        {
            const QRegularExpressionMatch match = iterator.next();
            setFormat(static_cast<int>(match.capturedStart()), static_cast<int>(match.capturedLength()), rule.format);
        }
    }

    QRegularExpressionMatchIterator commentMatches = singleLineComment_.globalMatch(text);
    while (commentMatches.hasNext())
    {
        const QRegularExpressionMatch match = commentMatches.next();
        setFormat(static_cast<int>(match.capturedStart()), static_cast<int>(match.capturedLength()), commentFormat_);
    }

    const qint32 previousState = previousBlockState();
    const bool continuingString = (previousState >= kStringStateBase) && (previousState < kCommentStateBase);
    const bool continuingComment = previousState >= kCommentStateBase;
    const qint32 stringEqCount = continuingString ? (previousState - kStringStateBase) : 0;
    const qint32 commentEqCount = continuingComment ? (previousState - kCommentStateBase) : 0;

    qint32 nextStringEqCount = 0;
    const bool stringStillOpen = highlightLongBlock(text, false, continuingString, stringEqCount, nextStringEqCount);

    qint32 nextCommentEqCount = 0;
    const bool commentStillOpen = highlightLongBlock(text, true, continuingComment, commentEqCount, nextCommentEqCount);

    if (commentStillOpen)
    {
        setCurrentBlockState(kCommentStateBase + nextCommentEqCount);
    }
    else if (stringStillOpen)
    {
        setCurrentBlockState(kStringStateBase + nextStringEqCount);
    }
    else
    {
        setCurrentBlockState(0);
    }
}

bool LuaSyntaxHighlighter::highlightLongBlock(const QString &text, bool isComment, bool continuingPrevious,
                                              qint32 eqCountFromState, qint32 &nextStateEqCount)
{
    QTextCharFormat format = isComment ? commentFormat_ : stringFormat_;
    qint32 eqCount = eqCountFromState;
    qint32 tokenLength = 0;
    bool continuing = continuingPrevious;
    qint32 startIndex = continuing ? 0 : findLongBlockStart(text, 0, isComment, eqCount, tokenLength);

    while (startIndex >= 0)
    {
        const qint32 searchFrom = continuing ? 0 : startIndex + tokenLength;
        const qint32 endIndex = findLongBlockEnd(text, searchFrom, eqCount);
        if (endIndex == -1)
        {
            setFormat(startIndex, static_cast<int>(text.length()) - startIndex, format);
            nextStateEqCount = eqCount;
            return true;
        }

        setFormat(startIndex, endIndex - startIndex + 1, format);
        continuing = false;
        startIndex = findLongBlockStart(text, endIndex + 1, isComment, eqCount, tokenLength);
    }

    nextStateEqCount = 0;
    return false;
}

qint32 LuaSyntaxHighlighter::findLongBlockStart(const QString &text, qint32 from, bool isComment, qint32 &eqCount,
                                                qint32 &tokenLength) const
{
    const qint32 len = static_cast<qint32>(text.length());
    for (qint32 i = from; i < len; ++i)
    {
        if (isComment)
        {
            if (i + 3 >= len)
            {
                break;
            }
            if (text[i] == '-' && text[i + 1] == '-' && text[i + 2] == '[')
            {
                qint32 j = i + 3;
                qint32 equals = 0;
                while (j < len && text[j] == '=')
                {
                    ++equals;
                    ++j;
                }
                if (j < len && text[j] == '[')
                {
                    eqCount = equals;
                    tokenLength = (j - i) + 1;
                    return i;
                }
            }
        }
        else
        {
            if (text[i] == '[')
            {
                if (i >= 2 && text[i - 2] == '-' && text[i - 1] == '-')
                {
                    continue; // Part of comment start, skip
                }
                qint32 j = i + 1;
                qint32 equals = 0;
                while (j < len && text[j] == '=')
                {
                    ++equals;
                    ++j;
                }
                if (j < len && text[j] == '[')
                {
                    eqCount = equals;
                    tokenLength = (j - i) + 1;
                    return i;
                }
            }
        }
    }
    return -1;
}

qint32 LuaSyntaxHighlighter::findLongBlockEnd(const QString &text, qint32 from, qint32 eqCount) const
{
    const qint32 len = static_cast<qint32>(text.length());
    for (qint32 i = from; i < len; ++i)
    {
        if (text[i] == ']')
        {
            qint32 j = i + 1;
            qint32 equals = 0;
            while (j < len && text[j] == '=')
            {
                ++equals;
                ++j;
            }
            if (equals == eqCount && j < len && text[j] == ']')
            {
                return j;
            }
        }
    }
    return -1;
}
