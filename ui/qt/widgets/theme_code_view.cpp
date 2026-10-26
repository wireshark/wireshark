/* theme_code_view.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <config.h>

#include "theme_code_view.h"

#include <ui/qt/utils/theme_manager.h>

#include <QPainter>
#include <QPlainTextEdit>
#include <QRegularExpression>
#include <QScrollBar>
#include <QSyntaxHighlighter>
#include <QTextEdit>
#include <QTextBlock>
#include <QTextCursor>
#include <QTextDocument>
#include <QVBoxLayout>

namespace {

QColor themeColor(ThemeManager::ThemeToken token)
{
    return ThemeManager::instance()->color(token);
}

} // namespace

// QPlainTextEdit with a line number / change marker gutter in its viewport
// margin, following the pattern of the Lua debugger's code view.
class ThemeCodeEdit : public QPlainTextEdit
{
public:
    explicit ThemeCodeEdit(const QVector<ThemeDiffLine> *lines, QWidget *parent);

    const QVector<ThemeDiffLine> *lines() const { return lines_; }

    int gutterWidth() const
    {
        int digits = 1;
        for (int n = qMax(1, blockCount()); n >= 10; n /= 10)
            ++digits;
        const int advance = fontMetrics().horizontalAdvance(QLatin1Char('9'));
        // number column, marker column, small padding
        return advance * (digits + 2) + 12;
    }
    void updateGutterWidth();
    void paintGutter(QPaintEvent *event);

protected:
    void resizeEvent(QResizeEvent *e) override;

private:
    QWidget *gutter_;
    const QVector<ThemeDiffLine> *lines_;
};

namespace {

class CodeGutter : public QWidget
{
public:
    explicit CodeGutter(ThemeCodeEdit *edit) : QWidget(edit), edit_(edit) {}
    QSize sizeHint() const override { return QSize(edit_->gutterWidth(), 0); }

protected:
    void paintEvent(QPaintEvent *event) override { edit_->paintGutter(event); }

private:
    ThemeCodeEdit *edit_;
};

} // namespace

ThemeCodeEdit::ThemeCodeEdit(const QVector<ThemeDiffLine> *lines, QWidget *parent)
    : QPlainTextEdit(parent), gutter_(new CodeGutter(this)), lines_(lines)
{
    setReadOnly(true);
    setLineWrapMode(QPlainTextEdit::NoWrap);
    connect(this, &QPlainTextEdit::blockCountChanged, this, [this]() { updateGutterWidth(); });
    connect(this, &QPlainTextEdit::updateRequest, this, [this](const QRect &rect, int dy) {
        if (dy)
            gutter_->scroll(0, dy);
        else
            gutter_->update(0, rect.y(), gutter_->width(), rect.height());
    });
    updateGutterWidth();
}

void ThemeCodeEdit::updateGutterWidth()
{
    setViewportMargins(gutterWidth(), 0, 0, 0);
    gutter_->setGeometry(QRect(contentsRect().left(), contentsRect().top(),
                               gutterWidth(), contentsRect().height()));
}

void ThemeCodeEdit::resizeEvent(QResizeEvent *e)
{
    QPlainTextEdit::resizeEvent(e);
    updateGutterWidth();
}

void ThemeCodeEdit::paintGutter(QPaintEvent *event)
{
    QPainter painter(gutter_);
    painter.fillRect(event->rect(), themeColor(ThemeManager::PaletteWindow));
    painter.setPen(themeColor(ThemeManager::MutedText));

    const int advance = fontMetrics().horizontalAdvance(QLatin1Char('9'));
    const int marker_w = advance * 2;
    const int number_w = gutter_->width() - marker_w;

    QFont bold = font();
    bold.setBold(true);

    QTextBlock block = firstVisibleBlock();
    int top = qRound(blockBoundingGeometry(block).translated(contentOffset()).top());
    int bottom = top + qRound(blockBoundingRect(block).height());
    while (block.isValid() && top <= event->rect().bottom()) {
        const int n = block.blockNumber();
        if (block.isVisible() && bottom >= event->rect().top() && n < lines_->size()) {
            const ThemeDiffLine &line = lines_->at(n);
            const int h = fontMetrics().height();
            if (line.number > 0) {
                painter.setFont(font());
                painter.drawText(0, top, number_w - 6, h, Qt::AlignRight | Qt::AlignVCenter,
                                 QString::number(line.number));
            }
            QChar mark;
            switch (line.kind) {
            case ThemeDiffKind::Changed: mark = QLatin1Char('~'); break;
            case ThemeDiffKind::Added: mark = QLatin1Char('+'); break;
            case ThemeDiffKind::Removed: mark = QLatin1Char('-'); break;
            default: break;
            }
            if (!mark.isNull()) {
                painter.setFont(bold);
                painter.drawText(number_w, top, marker_w, h, Qt::AlignHCenter | Qt::AlignVCenter,
                                 QString(mark));
            }
        }
        block = block.next();
        top = bottom;
        bottom = top + qRound(blockBoundingRect(block).height());
    }
}

namespace {

// Colors comments, "#hex" strings and numbers after a colon.  Only the
// foreground is set so the strike-out of removed lines survives.
class JsoncHighlighter : public QSyntaxHighlighter
{
public:
    JsoncHighlighter(QTextDocument *doc, const ThemeCodeEdit *edit)
        : QSyntaxHighlighter(doc), edit_(edit) {}

protected:
    void highlightBlock(const QString &text) override
    {
        static const QRegularExpression comment(QStringLiteral("^\\s*//.*$"));
        static const QRegularExpression string(QStringLiteral("\"#[0-9A-Fa-f]{6,8}\""));
        static const QRegularExpression number(QStringLiteral(":\\s*(\\d+)"));

        QTextCharFormat base;
        const int n = currentBlock().blockNumber();
        if (n < edit_->lines()->size() && edit_->lines()->at(n).kind == ThemeDiffKind::Removed) {
            base.setFontStrikeOut(true);
            base.setForeground(themeColor(ThemeManager::MutedText));
            setFormat(0, static_cast<int>(text.length()), base);
        }

        auto apply = [&](const QRegularExpression &re, const QColor &color, int group) {
            auto it = re.globalMatch(text);
            while (it.hasNext()) {
                const QRegularExpressionMatch m = it.next();
                QTextCharFormat f = base;
                f.setForeground(color);
                setFormat(static_cast<int>(m.capturedStart(group)),
                          static_cast<int>(m.capturedLength(group)), f);
            }
        };
        apply(comment, themeColor(ThemeManager::SyntaxKey), 0);
        apply(string, themeColor(ThemeManager::SyntaxString), 0);
        apply(number, themeColor(ThemeManager::SyntaxNumber), 1);
    }

private:
    const ThemeCodeEdit *edit_;
};

// Line diff of compare vs current via LCS.  Adjacent remove+add runs pair up
// as changed lines; leftovers are plain added or removed lines.
QVector<ThemeDiffLine> diffLines(const QStringList &a, const QStringList &b)
{
    const int n = static_cast<int>(a.size());
    const int m = static_cast<int>(b.size());
    QVector<int> lcs(static_cast<qsizetype>(n + 1) * (m + 1), 0);
    auto at = [&](int i, int j) -> int & { return lcs[static_cast<qsizetype>(i) * (m + 1) + j]; };
    for (int i = n - 1; i >= 0; --i) {
        for (int j = m - 1; j >= 0; --j) {
            at(i, j) = (a[i] == b[j]) ? at(i + 1, j + 1) + 1 : qMax(at(i + 1, j), at(i, j + 1));
        }
    }

    QVector<ThemeDiffLine> out;
    QStringList removed;
    QStringList added;
    int added_first = 0; // current line number of the first line in `added`
    auto flush = [&]() {
        const int pairs = static_cast<int>(qMin(removed.size(), added.size()));
        for (int k = 0; k < pairs; ++k)
            out.append({ ThemeDiffKind::Changed, added[k], added_first + k });
        for (int k = pairs; k < added.size(); ++k)
            out.append({ ThemeDiffKind::Added, added[k], added_first + k });
        for (int k = pairs; k < removed.size(); ++k)
            out.append({ ThemeDiffKind::Removed, removed[k], 0 });
        removed.clear();
        added.clear();
    };

    int i = 0, j = 0;
    while (i < n || j < m) {
        if (i < n && j < m && a[i] == b[j]) {
            flush();
            out.append({ ThemeDiffKind::Equal, b[j], j + 1 });
            ++i;
            ++j;
        } else if (j < m && (i == n || at(i, j + 1) >= at(i + 1, j))) {
            if (added.isEmpty())
                added_first = j + 1;
            added.append(b[j]);
            ++j;
        } else {
            removed.append(a[i]);
            ++i;
        }
    }
    flush();
    return out;
}

} // namespace

ThemeCodeView::ThemeCodeView(QWidget *parent)
    : QWidget(parent), edit_(new ThemeCodeEdit(&lines_, this))
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(edit_);
    edit_->setObjectName(QStringLiteral("themeCodeEdit"));
    highlighter_ = new JsoncHighlighter(edit_->document(), edit_);
    applyColors();
    connect(ThemeManager::instance(), &ThemeManager::themeChanged, this, &ThemeCodeView::applyColors);
}

void ThemeCodeView::applyColors()
{
    rebuildSelections();
    highlighter_->rehighlight();
    edit_->viewport()->update();
}

void ThemeCodeView::setViewFont(const QFont &monospace)
{
    edit_->setFont(monospace);
    edit_->updateGutterWidth();
    edit_->viewport()->update();
}

void ThemeCodeView::setTexts(const QString &compareText, const QString &currentText)
{
    current_text_ = currentText;
    lines_ = diffLines(compareText.split(QLatin1Char('\n')), currentText.split(QLatin1Char('\n')));
    // A trailing newline yields one empty last element in both texts; it is
    // equal and would only show an empty numbered line.
    if (!lines_.isEmpty() && lines_.last().kind == ThemeDiffKind::Equal && lines_.last().text.isEmpty()
        && currentText.endsWith(QLatin1Char('\n')))
        lines_.removeLast();

    changed_lines_ = added_lines_ = removed_lines_ = 0;
    run_starts_.clear();
    QStringList texts;
    bool in_run = false;
    for (int k = 0; k < lines_.size(); ++k) {
        const ThemeDiffLine &l = lines_[k];
        texts << l.text;
        switch (l.kind) {
        case ThemeDiffKind::Changed: ++changed_lines_; break;
        case ThemeDiffKind::Added: ++added_lines_; break;
        case ThemeDiffKind::Removed: ++removed_lines_; break;
        default: break;
        }
        const bool diff = l.kind != ThemeDiffKind::Equal;
        if (diff && !in_run)
            run_starts_.append(k);
        in_run = diff;
    }

    // lines_ is complete before the document changes: the highlighter and the
    // gutter read it while the text is set.
    edit_->setPlainText(texts.join(QLatin1Char('\n')));
    rebuildSelections();
    emit countsChanged();
}

void ThemeCodeView::rebuildSelections()
{
    QList<QTextEdit::ExtraSelection> selections;
    for (int k = 0; k < lines_.size(); ++k) {
        QColor bg;
        switch (lines_[k].kind) {
        case ThemeDiffKind::Added: bg = themeColor(ThemeManager::DiffAdded); break;
        case ThemeDiffKind::Changed: bg = themeColor(ThemeManager::DiffChanged); break;
        case ThemeDiffKind::Removed: bg = themeColor(ThemeManager::DiffRemoved); break;
        default: continue;
        }
        QTextEdit::ExtraSelection sel;
        sel.cursor = QTextCursor(edit_->document()->findBlockByNumber(k));
        sel.format.setBackground(bg);
        sel.format.setProperty(QTextFormat::FullWidthSelection, true);
        selections.append(sel);
    }
    edit_->setExtraSelections(selections);
}

void ThemeCodeView::goToBlock(int block)
{
    QTextCursor cursor(edit_->document()->findBlockByNumber(block));
    edit_->setTextCursor(cursor);
    edit_->centerCursor();
}

void ThemeCodeView::nextChange()
{
    if (run_starts_.isEmpty())
        return;
    const int current = edit_->textCursor().blockNumber();
    for (int start : std::as_const(run_starts_)) {
        if (start > current) {
            goToBlock(start);
            return;
        }
    }
    goToBlock(run_starts_.first());
}

void ThemeCodeView::previousChange()
{
    if (run_starts_.isEmpty())
        return;
    const int current = edit_->textCursor().blockNumber();
    for (int k = static_cast<int>(run_starts_.size()) - 1; k >= 0; --k) {
        if (run_starts_[k] < current) {
            goToBlock(run_starts_[k]);
            return;
        }
    }
    goToBlock(run_starts_.last());
}
