/* lua_debugger_code_editor.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Code editor stack: editor view, gutter, syntax highlighter, theme
 * palette, font policy and the script-tabs controller.
 */

#include <lua_debugger_code_editor.h>
#include <ui_lua_debugger_dialog.h>

#include <QAction>
#include <QApplication>
#include <QColor>
#include <QContextMenuEvent>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QFontDatabase>
#include <QGuiApplication>
#include <QHeaderView>
#include <QKeyEvent>
#include <QList>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QMouseEvent>
#include <QPainter>
#include <QPalette>
#include <QPlainTextEdit>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QStandardPaths>
#include <QStringList>
#include <QTabWidget>
#include <QTextBlock>
#include <QTextDocument>
#include <QTextStream>
#include <QTreeView>
#include <QWidget>
#include <QtGlobal>

#include <algorithm>
#include <climits>

#include "epan/wslua/wslua_debugger.h"
#include "lua_debugger_breakpoints.h"
#include "lua_debugger_dialog.h"
#include "lua_debugger_files.h"
#include "main_application.h"
#include "utils/color_utils.h"
#include <ui/qt/utils/theme_manager.h>

/* ===== code_palette ===== */

LuaDebuggerEditorPalette luaDebuggerEditorPaletteFor(bool isDark)
{
    LuaDebuggerEditorPalette p;
    if (isDark)
    {
        p.editorBackground = QColor(QStringLiteral("#1E1E1E"));
        p.editorText = QColor(QStringLiteral("#D4D4D4"));
        p.selection = QColor(QStringLiteral("#264F78"));
        p.selectionText = QColor(QStringLiteral("#FFFFFF"));
        p.gutterBackground = QColor(QStringLiteral("#252526"));
        p.gutterText = QColor(QStringLiteral("#858585"));
        /* Translucent deep gold (reads well on #1E1E1E). */
        p.pausedLine = QColor(QStringLiteral("#806F00"));
        p.pausedLine.setAlpha(120);
    }
    else
    {
        p.editorBackground = QColor(QStringLiteral("#FFFFFF"));
        p.editorText = QColor(QStringLiteral("#000000"));
        p.selection = QColor(QStringLiteral("#ADD6FF"));
        p.selectionText = QColor(QStringLiteral("#000000"));
        p.gutterBackground = QColor(QStringLiteral("#F3F3F3"));
        p.gutterText = QColor(QStringLiteral("#237893"));
        /* Pale warm amber; distinct from the selection #ADD6FF. */
        p.pausedLine = QColor(QStringLiteral("#FEF3C7"));
    }
    return p;
}

/* ===== lua_highlighter ===== */


namespace
{

constexpr qint32 kStringStateBase = 0x1000;  // Unique positive range for long strings
constexpr qint32 kCommentStateBase = 0x2000; // Distinct positive range for block comments

/**
 * @brief Theme-keyed colour table for syntax highlighting.
 *
 * Lives next to the highlighter (its only consumer) so the rule
 * builder is the single owner of "what colour does X get". The
 * editor / gutter palette is a separate story handled by
 * @c LuaDebuggerEditorPalette.
 */
struct ThemeColors
{
    QColor stringColor;
    QColor keywordColor;
    QColor numberColor;
    QColor builtInColor;
    QColor functionCallColor;
    QColor commentColor;
};

ThemeColors themeColorsFor(bool isDark)
{
    ThemeColors c;
    if (isDark)
    {
        c.stringColor = QColor(QStringLiteral("#CE9178"));
        c.keywordColor = QColor(QStringLiteral("#569CD6"));
        c.numberColor = QColor(QStringLiteral("#B5CEA8"));
        c.builtInColor = QColor(QStringLiteral("#4FC1FF"));
        c.functionCallColor = QColor(QStringLiteral("#DCDCAA"));
        c.commentColor = QColor(QStringLiteral("#6A9955"));
    }
    else
    {
        c.stringColor = QColor(QStringLiteral("#A31515"));
        c.keywordColor = QColor(QStringLiteral("#0000FF"));
        c.numberColor = QColor(QStringLiteral("#098658"));
        c.builtInColor = QColor(QStringLiteral("#267F99"));
        c.functionCallColor = QColor(QStringLiteral("#795E26"));
        c.commentColor = QColor(QStringLiteral("#008000"));
    }
    return c;
}

} // namespace

LuaSyntaxHighlighter::LuaSyntaxHighlighter(QTextDocument *parent, bool isDark) : QSyntaxHighlighter(parent)
{
    singleLineComment_ = QRegularExpression(QStringLiteral(R"(--(?!\[).*)"));
    buildRules(isDark);
}

void LuaSyntaxHighlighter::setTheme(bool isDark)
{
    buildRules(isDark);
    rehighlight();
}

void LuaSyntaxHighlighter::buildRules(bool isDark)
{
    const ThemeColors colors = themeColorsFor(isDark);
    rules_.clear();

    stringFormat_.setForeground(colors.stringColor);
    rules_.append({QRegularExpression(QStringLiteral("\"(?:\\\\.|[^\"\\\\])*\"")), stringFormat_});
    rules_.append({QRegularExpression(QStringLiteral("'(?:\\\\.|[^'\\\\])*'")), stringFormat_});

    QTextCharFormat keywordFormat;
    keywordFormat.setForeground(colors.keywordColor);
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
    numberFormat.setForeground(colors.numberColor);
    rules_.append({QRegularExpression(QStringLiteral("\\b0[xX][0-9a-fA-F]+\\b")), numberFormat});
    rules_.append({QRegularExpression(QStringLiteral("\\b\\d+(?:\\.\\d+)?\\b")), numberFormat});

    QTextCharFormat builtInFormat;
    builtInFormat.setForeground(colors.builtInColor);
    rules_.append({QRegularExpression(QStringLiteral("\\bself\\b")), builtInFormat});

    QTextCharFormat functionCallFormat;
    functionCallFormat.setForeground(colors.functionCallColor);
    Rule functionCallRule;
    functionCallRule.pattern = QRegularExpression(QStringLiteral("\\b(?!function\\b)([A-Za-z_]\\w*)\\s*(?=\\()"));
    functionCallRule.format = functionCallFormat;
    rules_.append(functionCallRule);

    commentFormat_.setForeground(colors.commentColor);
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

/* ===== code_view ===== */

LuaDebuggerCodeView::LuaDebuggerCodeView(QWidget *parent)
    : QPlainTextEdit(parent), lineNumberArea(new LineNumberArea(this)), syntaxHighlighter(nullptr)
{
    /* Gutter tooltip surfaces both click affordances; the Shift+click
     * behavior is otherwise non-discoverable. */
    lineNumberArea->setToolTip(tr("Click: add or remove breakpoint\n"
                                  "Drag existing breakpoint: move to nearest free visible line\n"
                                  "Shift+click: on an empty line, add a disabled breakpoint;\n"
                                  "on an existing breakpoint, toggle its active state"));
    syntaxHighlighter = new LuaSyntaxHighlighter(document(), ThemeManager::isDark());

    connect(this, &LuaDebuggerCodeView::blockCountChanged, this, &LuaDebuggerCodeView::updateLineNumberAreaWidth);
    connect(this, &LuaDebuggerCodeView::updateRequest, this, &LuaDebuggerCodeView::updateLineNumberArea);
    connect(this, &LuaDebuggerCodeView::cursorPositionChanged, this, &LuaDebuggerCodeView::rebuildLineHighlights);

    /* QAbstractScrollArea delivers key events to the viewport; Esc never
     * reaches QDialog::keyPressEvent. Forward to LuaDebuggerDialog::handleEscapeKey(). */
    viewport()->installEventFilter(this);

    setReadOnly(false);
    setLineWrapMode(QPlainTextEdit::NoWrap);

    QFont initialFont;
    if (mainApp && mainApp->isInitialized())
    {
        initialFont = mainApp->monospaceFont();
    }
    setEditorFont(initialFont);
    applyEditorPalette();
    rebuildLineHighlights();
}

QString LuaDebuggerCodeView::luaIdentifierUnderCursor(const QTextCursor &cursor) const
{
    const QString block = cursor.block().text();
    const int posInBlock = cursor.positionInBlock();
    if (block.isEmpty() || posInBlock < 0 || posInBlock > block.size())
    {
        return {};
    }

    auto isIdentChar = [](QChar c) { return c.isLetterOrNumber() || c == QLatin1Char('_'); };
    auto isIdentStart = [](QChar c) { return c.isLetter() || c == QLatin1Char('_'); };

    /* Caret may sit one past the end of the identifier; expand left
     * until we are inside, then sweep both directions. */
    int start = posInBlock;
    int end = posInBlock;
    if (start > 0 && !isIdentChar(block.at(start - 1)) && (start >= block.size() || !isIdentChar(block.at(start))))
    {
        return {};
    }
    while (start > 0 && isIdentChar(block.at(start - 1)))
    {
        --start;
    }
    while (end < block.size() && isIdentChar(block.at(end)))
    {
        ++end;
    }
    if (start >= end)
    {
        return {};
    }
    if (!isIdentStart(block.at(start)))
    {
        return {};
    }
    return block.mid(start, end - start);
}

QString LuaDebuggerCodeView::watchExpressionForContextMenu(const QPoint &viewportPos) const
{
    QString s = textCursor().selectedText().trimmed();
    if (!s.isEmpty())
    {
        return s;
    }
    return luaIdentifierUnderCursor(cursorForPosition(viewportPos));
}

qint32 LuaDebuggerCodeView::lineNumberAreaWidth()
{
    qint32 digits = 1;
    qint32 maxBlockCount = qMax(1, blockCount());
    while (maxBlockCount >= 10)
    {
        maxBlockCount /= 10;
        ++digits;
    }

    const qint32 space = 3 + fontMetrics().horizontalAdvance(QLatin1Char('9')) * digits;
    return space + 20; // Extra space for breakpoint icon
}

void LuaDebuggerCodeView::updateLineNumberAreaWidth(int /* newBlockCount */)
{
    setViewportMargins(static_cast<int>(lineNumberAreaWidth()), 0, 0, 0);
}

void LuaDebuggerCodeView::updateLineNumberArea(const QRect &rect, int dy)
{
    if (dy)
        lineNumberArea->scroll(0, dy);
    else
        lineNumberArea->update(0, rect.y(), lineNumberArea->width(), rect.height());

    if (rect.contains(viewport()->rect()))
        updateLineNumberAreaWidth(0);
}

void LuaDebuggerCodeView::resizeEvent(QResizeEvent *e)
{
    QPlainTextEdit::resizeEvent(e);

    QRect cr = contentsRect();
    lineNumberArea->setGeometry(QRect(cr.left(), cr.top(), static_cast<int>(lineNumberAreaWidth()), cr.height()));
}

bool LuaDebuggerCodeView::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == viewport() && event->type() == QEvent::KeyPress)
    {
        auto *ke = static_cast<QKeyEvent *>(event);
        if (ke->key() == Qt::Key_Escape && ke->modifiers() == Qt::NoModifier)
        {
            if (LuaDebuggerDialog *dlg = LuaDebuggerDialog::instance())
            {
                QMetaObject::invokeMethod(dlg, "handleEscapeKey", Qt::QueuedConnection);
                return true;
            }
        }
    }
    return QPlainTextEdit::eventFilter(watched, event);
}

void LuaDebuggerCodeView::rebuildLineHighlights()
{
    QList<QTextEdit::ExtraSelection> extraSelections;

    /* Debugger paused line — amber bar; theme-specific (independent of caret). */
    if (pausedExecutionLine_ > 0)
    {
        QTextBlock pauseBlock = document()->findBlockByNumber(static_cast<int>(pausedExecutionLine_ - 1));
        if (pauseBlock.isValid())
        {
            QTextCursor pauseCursor(pauseBlock);
            pauseCursor.movePosition(QTextCursor::StartOfBlock);
            QTextEdit::ExtraSelection pauseSel;
            const LuaDebuggerEditorPalette palette = luaDebuggerEditorPaletteFor(ThemeManager::isDark());
            pauseSel.format.setBackground(palette.pausedLine);
            pauseSel.format.setProperty(QTextFormat::FullWidthSelection, true);
            pauseSel.cursor = pauseCursor;
            pauseSel.cursor.clearSelection();
            extraSelections.append(pauseSel);
        }
    }

    /* Caret line — subtle; skip if same line as debugger (do not replace pause look). */
    QTextBlock caretBlock = textCursor().block();
    if (caretBlock.isValid())
    {
        const int caretLine = caretBlock.blockNumber() + 1;
        const bool sameAsPause = (pausedExecutionLine_ > 0) && (caretLine == pausedExecutionLine_);

        if (!sameAsPause)
        {
            /* Match the line-number gutter background (see applyEditorPalette). */
            const QColor lineColor = lineNumberArea->palette().color(QPalette::Base);

            QTextCursor caretLineCursor(caretBlock);
            caretLineCursor.movePosition(QTextCursor::StartOfBlock);
            QTextEdit::ExtraSelection caretSel;
            caretSel.format.setBackground(lineColor);
            caretSel.format.setProperty(QTextFormat::FullWidthSelection, true);
            caretSel.cursor = caretLineCursor;
            caretSel.cursor.clearSelection();
            extraSelections.append(caretSel);
        }
    }

    setExtraSelections(extraSelections);
}

void LuaDebuggerCodeView::setCurrentLine(qint32 line)
{
    /* The gutter repaints on cursor movement via the updateRequest
     * signal, but the early-return branches below do not move the
     * cursor, and we need the paused-line yellow arrow (and the
     * accompanying dimmed breakpoint circle, if any) to appear /
     * disappear whenever pausedExecutionLine_ changes. Request a
     * line-number-area repaint explicitly in every branch. */
    if (line <= 0)
    {
        pausedExecutionLine_ = -1;
        rebuildLineHighlights();
        lineNumberArea->update();
        return;
    }

    QTextBlock block = document()->findBlockByNumber(static_cast<int>(line - 1));
    if (!block.isValid())
    {
        pausedExecutionLine_ = -1;
        rebuildLineHighlights();
        lineNumberArea->update();
        return;
    }

    pausedExecutionLine_ = line;
    QTextCursor cursor(block);
    cursor.movePosition(QTextCursor::StartOfBlock);
    setTextCursor(cursor);
    rebuildLineHighlights();
    lineNumberArea->update();
}

void LuaDebuggerCodeView::moveCaretToLineStart(qint32 line)
{
    if (line <= 0)
    {
        return;
    }

    QTextBlock block = document()->findBlockByNumber(static_cast<int>(line - 1));
    if (!block.isValid())
    {
        return;
    }

    QTextCursor cursor(block);
    cursor.movePosition(QTextCursor::StartOfBlock);
    setTextCursor(cursor);
}

void LuaDebuggerCodeView::clearCurrentLineHighlight()
{
    pausedExecutionLine_ = -1;
    rebuildLineHighlights();
    /* Force the gutter to repaint so the paused-line yellow arrow
     * is cleared and any dimmed breakpoint circle returns to full
     * brightness on resume, even when no cursor movement triggers
     * updateRequest. */
    lineNumberArea->update();
}

void LuaDebuggerCodeView::setEditorFont(const QFont &font)
{
    QFont resolvedFont = font;
    if (resolvedFont.family().isEmpty())
    {
        resolvedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    }
    resolvedFont.setStyleHint(QFont::TypeWriter, QFont::PreferDefault);
    QPlainTextEdit::setFont(resolvedFont);
    lineNumberArea->setFont(resolvedFont);
    updateLineNumberAreaWidth(0);
    lineNumberArea->update();
    viewport()->update();
}

void LuaDebuggerCodeView::updateBreakpointMarkers()
{
    lineNumberArea->update();
}

void LuaDebuggerCodeView::applyTheme()
{
    const bool isDark = ThemeManager::isDark();
    applyEditorPalette();
    if (syntaxHighlighter)
    {
        static_cast<LuaSyntaxHighlighter *>(syntaxHighlighter)->setTheme(isDark);
    }
    lineNumberArea->update();
    viewport()->update();
    rebuildLineHighlights();
}

void LuaDebuggerCodeView::applyEditorPalette()
{
    const LuaDebuggerEditorPalette colors = luaDebuggerEditorPaletteFor(ThemeManager::isDark());
    QPalette pal = palette();
    QPalette gutterPal = lineNumberArea->palette();

    pal.setColor(QPalette::Base, colors.editorBackground);
    pal.setColor(QPalette::Text, colors.editorText);
    pal.setColor(QPalette::Highlight, colors.selection);
    pal.setColor(QPalette::HighlightedText, colors.selectionText);
    /* Match the editor base on Window so the gap between gutter and
     * viewport doesn't reveal the host palette. */
    pal.setColor(QPalette::Window, colors.editorBackground);

    gutterPal.setColor(QPalette::Window, colors.gutterBackground);
    gutterPal.setColor(QPalette::Base, colors.gutterBackground);
    gutterPal.setColor(QPalette::WindowText, colors.gutterText);

    setPalette(pal);
    setAutoFillBackground(true);

    viewport()->setPalette(pal);
    viewport()->setAutoFillBackground(true);

    lineNumberArea->setPalette(gutterPal);
    lineNumberArea->setAutoFillBackground(true);
    lineNumberArea->update();
}

void LuaDebuggerCodeView::lineNumberAreaPaintEvent(QPaintEvent *event)
{
    const LuaDebuggerEditorPalette colors = luaDebuggerEditorPaletteFor(ThemeManager::isDark());
    QPainter painter(lineNumberArea);
    painter.setRenderHint(QPainter::Antialiasing, true);

    painter.fillRect(event->rect(), colors.gutterBackground);

    /* Highlight the drag target line if a breakpoint move is in progress. */
    LineNumberArea *gutter = static_cast<LineNumberArea *>(lineNumberArea);
    if (gutter && gutter->isDraggingBreakpoint() && gutter->dragTargetLine() > 0)
    {
        const qint32 targetLine = gutter->dragTargetLine();
        QTextBlock targetBlock = document()->findBlockByNumber(static_cast<int>(targetLine - 1));
        if (targetBlock.isValid())
        {
            qint32 targetTop = static_cast<qint32>(blockBoundingGeometry(targetBlock).translated(contentOffset()).top());
            qint32 targetHeight = static_cast<qint32>(blockBoundingRect(targetBlock).height());
            QColor dragHighlight = colors.selection;
            dragHighlight.setAlpha(80);
            painter.fillRect(0, targetTop, lineNumberArea->width(), targetHeight, dragHighlight);
        }
    }

    /* Canonicalize the filename once for all visible lines. */
    char *canonical = nullptr;
    if (!filename.isEmpty())
    {
        canonical = wslua_debugger_canonical_path(filename.toUtf8().constData());
    }

    QTextBlock block = firstVisibleBlock();
    qint32 blockNumber = block.blockNumber();
    qint32 top = static_cast<qint32>(blockBoundingGeometry(block).translated(contentOffset()).top());
    qint32 bottom = top + static_cast<qint32>(blockBoundingRect(block).height());

    while (block.isValid() && top <= event->rect().bottom())
    {
        if (block.isVisible() && bottom >= event->rect().top())
        {
            QString number = QString::number(blockNumber + 1);
            painter.setPen(colors.gutterText);
            painter.drawText(0, top, lineNumberArea->width() - 20, fontMetrics().height(), Qt::AlignRight, number);

            const qint32 lineNo = static_cast<qint32>(blockNumber + 1);
            const bool pausedHere = (pausedExecutionLine_ == lineNo);

            /* Breakpoint circle. On the paused line the red (enabled)
             * circle is drawn dimmed (reduced alpha) so the overlaid
             * yellow right-pointing triangle is visually dominant while
             * the breakpoint itself stays recognizable underneath.
             * Gray (disabled) circles are not dimmed — the yellow
             * arrow is the only indicator that is never dimmed.
             * During a breakpoint drag, skip drawing the source line's
             * breakpoint so the preview at the target is visually distinct. */
            const bool isDragSource = (gutter && gutter->isDraggingBreakpoint() && lineNo == gutter->dragSourceLine());
            if (canonical && !isDragSource)
            {
                bool hasExtras = false;
                const int32_t state = wslua_debugger_get_breakpoint_state_canonical(canonical, lineNo, &hasExtras);
                if (state != -1)
                {
                    const qint32 radius = fontMetrics().height() / 2 - 2;
                    const qint32 cx = lineNumberArea->width() - 15;
                    const qint32 cy = top + 3;
                    luaDbgDrawBreakpointDot(painter, cx, cy, radius, (state == 1), hasExtras);
                }
            }

            /* Yellow right-pointing triangle marks the line the
             * debugger is paused at. Drawn after (and therefore on
             * top of) the breakpoint circle, which is dimmed on this
             * line so the triangle dominates while the breakpoint is
             * still visible. */
            if (pausedHere)
            {
                const qint32 radius = fontMetrics().height() / 2 - 2;
                const qint32 diameter = radius * 2;
                const qreal x = lineNumberArea->width() - 15;
                const qreal y = top + 2;
                QPolygonF triangle;
                triangle << QPointF(x, y) << QPointF(x, y + diameter) << QPointF(x + diameter, y + diameter / 2.0);
                const QColor triangleColor("#FFC107");
                painter.setBrush(triangleColor);
                /* Same 1px darker rim as the toolbar state indicator
                 * (see updateEnabledCheckboxIcon()). */
                painter.setPen(QPen(triangleColor.darker(140), 1));
                painter.drawPolygon(triangle);
            }
        }

        block = block.next();
        top = bottom;
        bottom = top + static_cast<qint32>(blockBoundingRect(block).height());
        ++blockNumber;
    }

    /* Draw semi-transparent preview breakpoint at the drag target line.
     * Uses the same color and indicators (white core for extras) as the
     * source breakpoint, with reduced alpha for visual distinction. */
    if (gutter && gutter->isDraggingBreakpoint() && gutter->dragTargetLine() > 0)
    {
        const qint32 targetLine = gutter->dragTargetLine();
        const qint32 sourceLine = gutter->dragSourceLine();
        QTextBlock targetBlock = document()->findBlockByNumber(static_cast<int>(targetLine - 1));
        if (targetBlock.isValid() && canonical && sourceLine > 0)
        {
            /* Query the source breakpoint to get its state and extras info. */
            bool hasExtras = false;
            const int32_t state = wslua_debugger_get_breakpoint_state_canonical(canonical, sourceLine, &hasExtras);
            if (state != -1)
            {
                qint32 targetTop = static_cast<qint32>(blockBoundingGeometry(targetBlock).translated(contentOffset()).top());
                qint32 targetBottom = targetTop + static_cast<qint32>(blockBoundingRect(targetBlock).height());

                if (targetTop <= event->rect().bottom() && targetBottom >= event->rect().top())
                {
                    const qint32 radius = fontMetrics().height() / 2 - 2;
                    const qint32 cx = lineNumberArea->width() - 15;
                    const qint32 cy = targetTop + 3;
                    luaDbgDrawBreakpointDot(painter, cx, cy, radius, (state == 1), hasExtras, 120);
                }
            }
        }
    }

    g_free(canonical);
}

qint32 LineNumberArea::lineAtY(qint32 yPx) const
{
    QTextBlock block = codeEditor->firstVisibleBlock();
    qint32 top =
        static_cast<qint32>(codeEditor->blockBoundingGeometry(block).translated(codeEditor->contentOffset()).top());
    qint32 bottom = top + static_cast<qint32>(codeEditor->blockBoundingRect(block).height());
    qint32 blockNumber = block.blockNumber();
    while (block.isValid())
    {
        if (yPx >= top && yPx <= bottom)
        {
            return blockNumber + 1;
        }
        block = block.next();
        top = bottom;
        bottom = top + static_cast<qint32>(codeEditor->blockBoundingRect(block).height());
        ++blockNumber;
    }
    return -1;
}

bool LineNumberArea::hasBreakpointAtLine(qint32 line) const
{
    if (!codeEditor || codeEditor->filename.isEmpty() || line < 1)
    {
        return false;
    }

    char *canonical = wslua_debugger_canonical_path(codeEditor->filename.toUtf8().constData());
    if (!canonical)
    {
        return false;
    }
    const int32_t state = wslua_debugger_get_breakpoint_state_canonical(canonical, line, /*has_extras=*/nullptr);
    g_free(canonical);
    return state != -1;
}

qint32 LineNumberArea::nearestVisibleDropLine(qint32 yPx, qint32 sourceLine) const
{
    struct Candidate
    {
        qint32 line;
        qint32 centerY;
    };

    QVector<Candidate> candidates;
    QTextBlock block = codeEditor->firstVisibleBlock();
    qint32 top =
        static_cast<qint32>(codeEditor->blockBoundingGeometry(block).translated(codeEditor->contentOffset()).top());
    qint32 bottom = top + static_cast<qint32>(codeEditor->blockBoundingRect(block).height());
    qint32 blockNumber = block.blockNumber();
    const qint32 viewportBottom = codeEditor->viewport()->height();

    while (block.isValid() && top <= viewportBottom)
    {
        if (block.isVisible() && bottom >= 0)
        {
            const qint32 line = blockNumber + 1;
            const bool occupied = hasBreakpointAtLine(line);
            if (!occupied || line == sourceLine)
            {
                candidates.append({line, top + (bottom - top) / 2});
            }
        }

        block = block.next();
        top = bottom;
        bottom = top + static_cast<qint32>(codeEditor->blockBoundingRect(block).height());
        ++blockNumber;
    }

    if (candidates.isEmpty())
    {
        return -1;
    }

    qint32 bestLine = -1;
    qint32 bestDist = INT_MAX;
    qint32 bestLineDelta = INT_MAX;
    for (const Candidate &candidate : candidates)
    {
        const qint32 yDist = qAbs(candidate.centerY - yPx);
        const qint32 lineDelta = qAbs(candidate.line - sourceLine);
        if (bestLine == -1 || yDist < bestDist || (yDist == bestDist && lineDelta < bestLineDelta))
        {
            bestLine = candidate.line;
            bestDist = yDist;
            bestLineDelta = lineDelta;
        }
    }
    return bestLine;
}

void LineNumberArea::mousePressEvent(QMouseEvent *event)
{
    leftPressArmed_ = false;
    draggingBreakpoint_ = false;
    pressedLine_ = -1;
    dragTargetLine_ = -1;
    pressShiftToggle_ = false;
    pressHadBreakpoint_ = false;

    /* Only the primary button drives add / remove / toggle here. The
     * secondary button (right-click on Win/Linux, Ctrl-click or
     * two-finger trackpad tap on macOS) is handled by
     * @ref contextMenuEvent, which always pops the
     * Edit / Disable / Remove menu so that gesture is never confused
     * with the toggle path. */
    if (event->button() != Qt::LeftButton)
    {
        QWidget::mousePressEvent(event);
        return;
    }

    const QPoint click_pos = event->pos();
    if (click_pos.x() <= width() - 20)
    {
        QWidget::mousePressEvent(event);
        return;
    }

    const qint32 lineNo = lineAtY(click_pos.y());
    if (lineNo < 1)
    {
        QWidget::mousePressEvent(event);
        return;
    }

    leftPressArmed_ = true;
    pressPos_ = click_pos;
    pressedLine_ = lineNo;
    dragTargetLine_ = lineNo;
    pressShiftToggle_ = (event->modifiers() & Qt::ShiftModifier) != 0;
    pressHadBreakpoint_ = hasBreakpointAtLine(lineNo);
    event->accept();
}

void LineNumberArea::mouseMoveEvent(QMouseEvent *event)
{
    if (!leftPressArmed_ || !pressHadBreakpoint_)
    {
        QWidget::mouseMoveEvent(event);
        return;
    }

    if (!draggingBreakpoint_)
    {
        const qint32 dragDistance = (event->pos() - pressPos_).manhattanLength();
        if (dragDistance < QApplication::startDragDistance())
        {
            return;
        }
        draggingBreakpoint_ = true;
        setCursor(Qt::ClosedHandCursor);
    }

    const qint32 prevTarget = dragTargetLine_;
    dragTargetLine_ = nearestVisibleDropLine(event->pos().y(), pressedLine_);

    /* Repaint gutter to show updated drag target highlight. */
    if (dragTargetLine_ != prevTarget)
    {
        update();
    }
    event->accept();
}

void LineNumberArea::mouseReleaseEvent(QMouseEvent *event)
{
    if (event->button() != Qt::LeftButton)
    {
        QWidget::mouseReleaseEvent(event);
        return;
    }

    const bool armed = leftPressArmed_;
    const bool wasDragging = draggingBreakpoint_;
    const bool sourceHasBreakpoint = pressHadBreakpoint_;
    const bool toggleActive = pressShiftToggle_;
    const qint32 lineNo = pressedLine_;
    const qint32 dropLine = (dragTargetLine_ > 0) ? dragTargetLine_ : nearestVisibleDropLine(event->pos().y(), lineNo);

    leftPressArmed_ = false;
    draggingBreakpoint_ = false;
    pressedLine_ = -1;
    dragTargetLine_ = -1;
    pressShiftToggle_ = false;
    pressHadBreakpoint_ = false;
    unsetCursor();

    if (!armed || lineNo < 1)
    {
        QWidget::mouseReleaseEvent(event);
        return;
    }

    if (wasDragging && sourceHasBreakpoint)
    {
        if (dropLine > 0 && dropLine != lineNo)
        {
            emit codeEditor->breakpointMoveRequested(codeEditor->filename, lineNo, dropLine);
            codeEditor->viewport()->update();
            update();
        }
        event->accept();
        return;
    }

    /* Plain left-click on a "rich" breakpoint (one carrying a
     * condition, a hit-count target, or a log message) opens the
     * Edit / Disable / Remove popup instead of removing it: those
     * extras are easy to lose to a misclick, so the destructive
     * action requires an explicit Remove choice from the menu. Plain
     * breakpoints and clicks on bare lines keep the original
     * add-or-remove-on-click flow. Shift+click keeps the existing
     * modifier semantics (toggle active / pre-arm disabled). */
    bool richBp = false;
    if (!toggleActive && !codeEditor->filename.isEmpty())
    {
        char *canonical = wslua_debugger_canonical_path(codeEditor->filename.toUtf8().constData());
        if (canonical)
        {
            bool hasExtras = false;
            const int32_t state = wslua_debugger_get_breakpoint_state_canonical(canonical, lineNo, &hasExtras);
            g_free(canonical);
            if (state != -1 && hasExtras)
            {
                richBp = true;
            }
        }
    }

    if (richBp)
    {
        QPoint globalPos =
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
            event->globalPosition().toPoint();
#else
            event->globalPos();
#endif
        emit codeEditor->breakpointGutterMenuRequested(codeEditor->filename, lineNo, globalPos);
    }
    else
    {
        emit codeEditor->breakpointToggled(codeEditor->filename, lineNo, toggleActive);
        codeEditor->viewport()->update();
        update();
    }

    event->accept();
}

void LineNumberArea::contextMenuEvent(QContextMenuEvent *event)
{
    /* Secondary-click contract on the gutter: always pop the
     * Edit / Disable / Remove menu when the gesture lands on an
     * existing breakpoint, regardless of whether it carries extras.
     * This is the canonical "second click" affordance — works on
     * Windows / Linux right-click, macOS Ctrl-click and the macOS
     * two-finger trackpad tap, all of which Qt funnels through
     * QContextMenuEvent. Bare lines have nothing to act on; we let
     * the event through so the parent editor (or its viewport) can
     * decide what to do (currently nothing in that area). */
    const QPoint pos = event->pos();
    if (pos.x() <= width() - 20 || codeEditor->filename.isEmpty())
    {
        QWidget::contextMenuEvent(event);
        return;
    }

    const qint32 lineNo = lineAtY(pos.y());
    if (lineNo < 1)
    {
        QWidget::contextMenuEvent(event);
        return;
    }

    char *canonical = wslua_debugger_canonical_path(codeEditor->filename.toUtf8().constData());
    if (!canonical)
    {
        QWidget::contextMenuEvent(event);
        return;
    }
    const int32_t state = wslua_debugger_get_breakpoint_state_canonical(canonical, lineNo, /*has_extras=*/nullptr);
    g_free(canonical);
    if (state == -1)
    {
        QWidget::contextMenuEvent(event);
        return;
    }

    emit codeEditor->breakpointGutterMenuRequested(codeEditor->filename, lineNo, event->globalPos());
    event->accept();
}

/* ===== font_policy ===== */

void LuaDebuggerFontPolicy::attach(QTabWidget *codeTabs, QTreeView *variablesTree, QTreeView *watchTree,
                                   QStandardItemModel *watchModel, QTreeView *stackTree, QTreeView *fileTree,
                                   QTreeView *breakpointsTree, QPlainTextEdit *evalInputEdit,
                                   QPlainTextEdit *evalOutputEdit)
{
    codeTabs_ = codeTabs;
    variablesTree_ = variablesTree;
    watchTree_ = watchTree;
    watchModel_ = watchModel;
    stackTree_ = stackTree;
    fileTree_ = fileTree;
    breakpointsTree_ = breakpointsTree;
    evalInputEdit_ = evalInputEdit;
    evalOutputEdit_ = evalOutputEdit;
}

void LuaDebuggerFontPolicy::applyAll()
{
    applyToCodeEditors(monospaceFont(true));
    applyToPanels();
}

void LuaDebuggerFontPolicy::applyToCodeEditors(const QFont &font)
{
    QFont effective = font;
    if (effective.family().isEmpty())
    {
        effective = monospaceFont(true);
    }

    if (!codeTabs_)
    {
        return;
    }
    const qint32 tabCount = static_cast<qint32>(codeTabs_->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(codeTabs_->widget(static_cast<int>(tabIndex)));
        if (view)
        {
            view->setEditorFont(effective);
        }
    }
}

void LuaDebuggerFontPolicy::applyToPanels()
{
    const QFont panelMono = monospaceFont(false);
    const QFont headerFont = regularFont();

    const QList<QWidget *> widgets = {variablesTree_,   watchTree_,     stackTree_,
                                      breakpointsTree_, evalInputEdit_, evalOutputEdit_};
    for (QWidget *widget : widgets)
    {
        if (widget)
        {
            widget->setFont(panelMono);
        }
    }

    const QList<QTreeView *> treesWithStandardHeaders = {variablesTree_, watchTree_, stackTree_, fileTree_,
                                                         breakpointsTree_};
    for (QTreeView *tree : treesWithStandardHeaders)
    {
        if (tree && tree->header())
        {
            tree->header()->setFont(headerFont);
        }
    }
    reapplyToWatchItemModel();
}

namespace
{

/* Walk the watch QStandardItemModel tree: set each item's QFont to the
 * panel monospace while preserving the existing bold bit (change-
 * highlight) so it wins over the tree widget font after row moves. */
// NOLINTNEXTLINE(misc-no-recursion)
void reapplyMonospaceToWatchItemModelRecursive(const QFont &base, QStandardItemModel *m, const QModelIndex &parent)
{
    if (!m)
    {
        return;
    }
    const int rows = m->rowCount(parent);
    const int cols = m->columnCount(parent);
    for (int r = 0; r < rows; ++r)
    {
        for (int c = 0; c < cols; ++c)
        {
            const QModelIndex idx = m->index(r, c, parent);
            if (QStandardItem *it = m->itemFromIndex(idx))
            {
                QFont f = base;
                f.setBold(it->font().bold());
                it->setFont(f);
            }
        }
        const QModelIndex specIndex = m->index(r, WatchColumn::Spec, parent);
        if (specIndex.isValid() && m->rowCount(specIndex) > 0)
        {
            reapplyMonospaceToWatchItemModelRecursive(base, m, specIndex);
        }
    }
}

} // namespace

void LuaDebuggerFontPolicy::reapplyToWatchItemModel()
{
    if (!watchModel_)
    {
        return;
    }
    reapplyMonospaceToWatchItemModelRecursive(monospaceFont(false), watchModel_, QModelIndex());
    if (watchTree_)
    {
        watchTree_->update();
    }
}

QFont LuaDebuggerFontPolicy::monospaceFont(bool zoomed) const
{
    /* Monospace font for panels and the script editor. */
    if (mainApp && mainApp->isInitialized())
    {
        return mainApp->monospaceFont(zoomed);
    }

    /* Fall back to system fixed font */
    return QFontDatabase::systemFont(QFontDatabase::FixedFont);
}

QFont LuaDebuggerFontPolicy::regularFont() const
{
    if (mainApp && mainApp->isInitialized())
    {
        return mainApp->font();
    }
    return QGuiApplication::font();
}

/* ===== code_tabs_controller ===== */

LuaDebuggerCodeTabsController::LuaDebuggerCodeTabsController(LuaDebuggerDialog *host) : QObject(host), host_(host) {}

void LuaDebuggerCodeTabsController::attach(QTabWidget *tabs)
{
    tabs_ = tabs;
}

void LuaDebuggerDialog::wireCodeTabs()
{
    codeTabsController_.attach(ui->codeTabWidget);

    connect(ui->actionSaveFile, &QAction::triggered, &codeTabsController_, &LuaDebuggerCodeTabsController::onSaveFile);

    connect(ui->codeTabWidget, &QTabWidget::tabCloseRequested, &codeTabsController_,
            &LuaDebuggerCodeTabsController::onTabCloseRequested);
    connect(ui->codeTabWidget, &QTabWidget::currentChanged, &codeTabsController_,
            &LuaDebuggerCodeTabsController::onCurrentTabChanged);
}

QString LuaDebuggerCodeTabsController::lastOpenDirectory()
{
    if (lastOpenDirectory_.isEmpty())
    {
        lastOpenDirectory_ = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
        if (lastOpenDirectory_.isEmpty())
        {
            lastOpenDirectory_ = QDir::homePath();
        }
    }
    return lastOpenDirectory_;
}

void LuaDebuggerCodeTabsController::setLastOpenDirectory(const QString &dir)
{
    lastOpenDirectory_ = dir;
}

LuaDebuggerCodeView *LuaDebuggerCodeTabsController::loadFile(const QString &file_path)
{
    if (!host_ || !tabs_)
    {
        return nullptr;
    }

    QString normalizedPath = host_->normalizedFilePath(file_path);
    if (normalizedPath.isEmpty())
    {
        normalizedPath = file_path;
    }

    /* Check if file exists before creating a tab. */
    QFileInfo fileInfo(normalizedPath);
    if (!fileInfo.exists() || !fileInfo.isFile())
    {
        return nullptr;
    }

    const qint32 existingTabCount = static_cast<qint32>(tabs_->count());
    for (qint32 tabIndex = 0; tabIndex < existingTabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(tabs_->widget(static_cast<int>(tabIndex)));
        if (view && view->getFilename() == normalizedPath)
        {
            tabs_->setCurrentIndex(static_cast<int>(tabIndex));
            return view;
        }
    }

    LuaDebuggerCodeView *codeView = new LuaDebuggerCodeView(tabs_);
    codeView->setEditorFont(host_->fontPolicy().monospaceFont(true));
    codeView->setFilename(normalizedPath);

    QFile file(normalizedPath);
    if (file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        codeView->setPlainText(file.readAll());
    }
    else
    {
        /* This should not happen since we checked exists() above,
         * but handle it gracefully just in case. */
        delete codeView;
        return nullptr;
    }

    host_->filesController().ensureEntry(normalizedPath);

    codeView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(codeView, &QWidget::customContextMenuRequested, host_, &LuaDebuggerDialog::onCodeViewContextMenu);

    /* Queued connection: the gutter emits this from inside its
     * mousePressEvent, so dispatching the popup via a queued slot
     * lets the press event fully unwind before QMenu::exec() spins
     * its own nested loop. Avoids the "press grab still attached"
     * artefacts that bite when a modal popup is opened directly out
     * of a press handler. */
    connect(codeView, &LuaDebuggerCodeView::breakpointGutterMenuRequested, &host_->breakpointsController(),
            &LuaDebuggerBreakpointsController::showGutterMenu, Qt::QueuedConnection);

    connect(codeView, &LuaDebuggerCodeView::breakpointToggled, this,
            &LuaDebuggerCodeTabsController::onCodeViewBreakpointToggled);

        connect(codeView, &LuaDebuggerCodeView::breakpointMoveRequested, &host_->breakpointsController(),
            &LuaDebuggerBreakpointsController::moveAtLine, Qt::QueuedConnection);

    connect(codeView->document(), &QTextDocument::modificationChanged, this,
            [this, codeView]()
            {
                updateTabTextForCodeView(codeView);
                updateWindowModifiedState();
                if (tabs_ && tabs_->currentWidget() == codeView)
                {
                    updateSaveActionState();
                }
            });
    connect(codeView, &QPlainTextEdit::cursorPositionChanged, &host_->breakpointsController(),
            &LuaDebuggerBreakpointsController::updateHeaderButtonState);

    tabs_->addTab(codeView, QFileInfo(normalizedPath).fileName());
    updateTabTextForCodeView(codeView);
    tabs_->setCurrentWidget(codeView);
    tabs_->show();
    updateSaveActionState();
    updateWindowModifiedState();
    host_->updateLuaEditorAuxFrames();
    return codeView;
}

LuaDebuggerCodeView *LuaDebuggerCodeTabsController::currentCodeView() const
{
    if (!tabs_)
    {
        return nullptr;
    }
    return qobject_cast<LuaDebuggerCodeView *>(tabs_->currentWidget());
}

qint32 LuaDebuggerCodeTabsController::unsavedOpenScriptTabCount() const
{
    if (!tabs_)
    {
        return 0;
    }
    qint32 count = 0;
    const qint32 tabCount = static_cast<qint32>(tabs_->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(tabs_->widget(static_cast<int>(tabIndex)));
        if (view && view->document()->isModified())
        {
            ++count;
        }
    }
    return count;
}

bool LuaDebuggerCodeTabsController::hasUnsavedChanges() const
{
    return unsavedOpenScriptTabCount() > 0;
}

bool LuaDebuggerCodeTabsController::ensureUnsavedChangesHandled(const QString &title)
{
    if (!hasUnsavedChanges())
    {
        return true;
    }

    const qint32 unsavedCount = unsavedOpenScriptTabCount();
    const QMessageBox::StandardButton reply =
        QMessageBox::question(host_, title, tr("There are unsaved changes in %Ln open file(s).", "", unsavedCount),
                              QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel, QMessageBox::Save);

    if (reply == QMessageBox::Cancel)
    {
        return false;
    }
    if (reply == QMessageBox::Save)
    {
        return saveAllModified();
    }
    clearAllDocumentModified();
    return true;
}

void LuaDebuggerCodeTabsController::clearAllDocumentModified()
{
    if (!tabs_)
    {
        return;
    }
    const qint32 tabCount = static_cast<qint32>(tabs_->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(tabs_->widget(static_cast<int>(tabIndex)));
        if (view)
        {
            view->document()->setModified(false);
        }
    }
}

bool LuaDebuggerCodeTabsController::saveCodeView(LuaDebuggerCodeView *view)
{
    if (!view)
    {
        return false;
    }
    const QString path = view->getFilename();
    if (path.isEmpty())
    {
        return false;
    }

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::warning(host_, tr("Save Lua Script"),
                             tr("Could not write to %1:\n%2").arg(path, file.errorString()));
        return false;
    }
    QTextStream out(&file);
    out << view->toPlainText();
    file.close();
    view->document()->setModified(false);
    return true;
}

bool LuaDebuggerCodeTabsController::saveAllModified()
{
    if (!tabs_)
    {
        return true;
    }
    const qint32 tabCount = static_cast<qint32>(tabs_->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(tabs_->widget(static_cast<int>(tabIndex)));
        if (view && view->document()->isModified())
        {
            if (!saveCodeView(view))
            {
                return false;
            }
        }
    }
    return true;
}

void LuaDebuggerCodeTabsController::updateTabTextForCodeView(LuaDebuggerCodeView *view)
{
    if (!view || !tabs_)
    {
        return;
    }
    const int tabIndex = tabs_->indexOf(view);
    if (tabIndex < 0)
    {
        return;
    }
    QString label = QFileInfo(view->getFilename()).fileName();
    if (view->document()->isModified())
    {
        label += QStringLiteral(" *");
    }
    tabs_->setTabText(tabIndex, label);
}

void LuaDebuggerCodeTabsController::updateSaveActionState()
{
    if (!host_)
    {
        return;
    }
    LuaDebuggerCodeView *view = currentCodeView();
    host_->setSaveActionEnabled(view && view->document()->isModified());
}

void LuaDebuggerCodeTabsController::updateWindowModifiedState()
{
    if (!host_)
    {
        return;
    }
    host_->setWindowModified(hasUnsavedChanges());
}

void LuaDebuggerCodeTabsController::openInitialBreakpointFiles(const QVector<QString> &files)
{
    for (const QString &path : files)
    {
        loadFile(path);
    }
}

void LuaDebuggerCodeTabsController::clearAllCodeHighlights()
{
    if (!tabs_)
    {
        return;
    }
    const qint32 tabCount = static_cast<qint32>(tabs_->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(tabs_->widget(static_cast<int>(tabIndex)));
        if (view)
        {
            view->clearCurrentLineHighlight();
        }
    }
}

void LuaDebuggerCodeTabsController::applyThemeToAllTabs()
{
    if (!tabs_)
    {
        return;
    }
    const qint32 tabCount = static_cast<qint32>(tabs_->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(tabs_->widget(static_cast<int>(tabIndex)));
        if (view)
        {
            view->applyTheme();
        }
    }
}

void LuaDebuggerCodeTabsController::onSaveFile()
{
    LuaDebuggerCodeView *view = currentCodeView();
    if (!view || !view->document()->isModified())
    {
        return;
    }
    saveCodeView(view);
    updateSaveActionState();
}

void LuaDebuggerCodeTabsController::onCurrentTabChanged(int index)
{
    Q_UNUSED(index);
    if (!host_)
    {
        return;
    }
    updateSaveActionState();
    host_->updateLuaEditorAuxFrames();
    host_->breakpointsController().updateHeaderButtonState();
    host_->updateContinueActionState();
}

void LuaDebuggerCodeTabsController::onTabCloseRequested(int index)
{
    if (!host_ || !tabs_)
    {
        return;
    }
    QWidget *widget = tabs_->widget(index);
    auto *view = qobject_cast<LuaDebuggerCodeView *>(widget);
    if (view && view->document()->isModified())
    {
        const QMessageBox::StandardButton reply = QMessageBox::question(
            host_, tr("Lua Debugger"),
            tr("Save changes to %1 before closing?").arg(QFileInfo(view->getFilename()).fileName()),
            QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel, QMessageBox::Save);
        if (reply == QMessageBox::Cancel)
        {
            return;
        }
        if (reply == QMessageBox::Save)
        {
            if (!saveCodeView(view))
            {
                return;
            }
        }
        else
        {
            view->document()->setModified(false);
        }
    }

    tabs_->removeTab(index);
    delete widget;
    updateSaveActionState();
    updateWindowModifiedState();
}

void LuaDebuggerCodeTabsController::onCodeViewBreakpointToggled(const QString &file_path, qint32 line, bool toggleActive)
{
    if (!host_)
    {
        return;
    }
    /* Two distinct gestures share this code-view signal:
     *
     *   - Plain click (toggleActive=false) — F9 / gutter add+remove. The
     *     breakpoint is created active and the debugger is auto-enabled
     *     so the new row is immediately effective.
     *   - Shift+click (toggleActive=true) — pre-arm / disarm without
     *     destroying the row, so the user can park breakpoints on lines
     *     they intend to revisit later. Never auto-enables the debugger;
     *     that would defeat the "no surprise" intent.
     *
     * Both gestures dispatch through @ref LuaDebuggerBreakpointsController
     * so the chrome refresh (table rebuild, gutter markers, header dot)
     * is identical regardless of the entry point. */
    if (toggleActive)
    {
        host_->breakpointsController().shiftToggleAtLine(file_path, line);
    }
    else
    {
        host_->breakpointsController().toggleAtLine(file_path, line);
    }
}
