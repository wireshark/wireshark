/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_CODE_VIEW_H
#define THEME_CODE_VIEW_H

#include <QFont>
#include <QString>
#include <QVector>
#include <QWidget>

class QSyntaxHighlighter;
class ThemeCodeEdit;

/** Kind of a line in the code view's diff. */
enum class ThemeDiffKind { Equal, Changed, Added, Removed };

/** One displayed line of the code view. */
struct ThemeDiffLine
{
    ThemeDiffKind kind = ThemeDiffKind::Equal;
    QString text;
    int number = 0; // line number in the current text; 0 for removed lines
};

/**
 * Read-only viewer for theme file text with a line diff against a comparison
 * text: gutter with line numbers and change markers, tinted changed lines,
 * removed lines shown struck through, and simple JSONC syntax coloring.
 */
class ThemeCodeView : public QWidget
{
    Q_OBJECT
public:
    explicit ThemeCodeView(QWidget *parent = nullptr);

    void setTexts(const QString &compareText, const QString &currentText);
    void setViewFont(const QFont &monospace);

    int changedLines() const { return changed_lines_; }
    int addedLines() const { return added_lines_; }
    int removedLines() const { return removed_lines_; }

    /** Moves to the next/previous run of changed lines, wrapping around. */
    void nextChange();
    void previousChange();

    /** The current text without the removed (ghost) lines. */
    QString currentText() const { return current_text_; }

signals:
    void countsChanged();

private:
    void applyColors();
    void rebuildSelections();
    void goToBlock(int block);

    ThemeCodeEdit *edit_;
    QSyntaxHighlighter *highlighter_ = nullptr;
    QVector<ThemeDiffLine> lines_;
    QVector<int> run_starts_;
    QString current_text_;
    int changed_lines_ = 0;
    int added_lines_ = 0;
    int removed_lines_ = 0;
};

#endif // THEME_CODE_VIEW_H
