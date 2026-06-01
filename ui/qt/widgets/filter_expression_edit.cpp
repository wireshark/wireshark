/* filter_expression_edit.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/widgets/filter_expression_edit.h>

#include <ui/qt/models/filter_history_model.h>
#include <ui/qt/models/bookmark_model.h>
#include <ui/qt/utils/stock_icon.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/themed_icon.h>

#include <QAction>
#include <QApplication>
#include <QConcatenateTablesProxyModel>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPen>
#include <QToolButton>
#include <QWidgetAction>

#include <functional>

namespace {

// An opaque "muted" foreground: the text color blended `toward_bg` of the way
// to the window background. Using a solid blend (not an alpha) keeps it legible
// in both light and dark mode and under macOS menu vibrancy, where alpha text
// washes out.
QColor mutedColor(const QPalette &pal, qreal toward_bg)
{
    const QColor fg = pal.color(QPalette::WindowText);
    const QColor bg = pal.color(QPalette::Window);
    return QColor::fromRgbF(
        fg.redF()   + (bg.redF()   - fg.redF())   * toward_bg,
        fg.greenF() + (bg.greenF() - fg.greenF()) * toward_bg,
        fg.blueF()  + (bg.blueF()  - fg.blueF())  * toward_bg);
}

// A bookmark-menu row: monospace expression on the left, muted name on the
// right (per the design mockup). No Q_OBJECT — it only overrides event
// handlers and invokes a callback, so it needs no moc.
class BookmarkEntryWidget : public QWidget
{
public:
    BookmarkEntryWidget(const QString &expr, const QString &name, const QFont &base,
                        QWidget *parent = nullptr) :
        QWidget(parent)
    {
        QHBoxLayout *layout = new QHBoxLayout(this);
        layout->setContentsMargins(12, 3, 12, 3);
        layout->setSpacing(18);

        // Monospace expression, sized to match the surrounding menu text.
        QLabel *expr_label = new QLabel(expr, this);
        QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        mono.setPointSizeF(base.pointSizeF());
        expr_label->setFont(mono);
        expr_label->setAttribute(Qt::WA_TransparentForMouseEvents);
        layout->addWidget(expr_label);
        layout->addStretch(1);

        if (!name.isEmpty()) {
            // Muted-but-legible name, right-aligned, slightly smaller.
            QLabel *name_label = new QLabel(name, this);
            QFont nf = base;
            nf.setPointSizeF(base.pointSizeF() - 1.0);
            name_label->setFont(nf);
            name_label->setAttribute(Qt::WA_TransparentForMouseEvents);
            QPalette pal = name_label->palette();
            pal.setColor(QPalette::WindowText, mutedColor(pal, 0.40));
            name_label->setPalette(pal);
            layout->addWidget(name_label);
        }
    }

    std::function<void()> onActivate; /**< Called on click. */

protected:
    bool event(QEvent *e) override
    {
        if (e->type() == QEvent::Enter) { hovered_ = true; update(); }
        else if (e->type() == QEvent::Leave) { hovered_ = false; update(); }
        return QWidget::event(e);
    }

    void mouseReleaseEvent(QMouseEvent *) override
    {
        if (onActivate)
            onActivate();
    }

    void paintEvent(QPaintEvent *) override
    {
        if (!hovered_)
            return;
        // Subtle selection tint that keeps the label text readable (no color
        // switch needed) — mirrors the mockup's light hover row.
        QColor tint = palette().color(QPalette::Highlight);
        tint.setAlpha(48);
        QPainter painter(this);
        painter.fillRect(rect(), tint);
    }

private:
    bool hovered_ = false;
};

// QLineEdit creates one internal QToolButton per side action but exposes no
// action-to-button accessor. Each addAction() builds its button synchronously,
// so right afterwards the one child not yet in `known` is the button just added.
// `known` accumulates across calls so each capture returns a distinct button.
QToolButton *takeNewButton(const QLineEdit *edit, QList<QToolButton *> &known)
{
    const QList<QToolButton *> all = edit->findChildren<QToolButton *>();
    for (QToolButton *button : all) {
        if (!known.contains(button)) {
            known.append(button);
            return button;
        }
    }
    return nullptr;
}

} // namespace

FilterExpressionEdit::FilterExpressionEdit(QWidget *parent) :
    FilterEdit(parent),
    bookmark_action_(nullptr),
    clear_action_(nullptr),
    history_action_(nullptr),
    apply_action_(nullptr),
    bookmark_button_(nullptr),
    clear_button_(nullptr),
    history_button_(nullptr),
    apply_button_(nullptr),
    bookmark_menu_(nullptr),
    history_menu_(nullptr),
    save_action_(nullptr),
    remove_action_(nullptr),
    manage_action_(nullptr),
    preferences_action_(nullptr),
    static_separator_(nullptr),
    historyModel_(nullptr),
    bookmarkModel_(nullptr),
    completion_source_(new QConcatenateTablesProxyModel(this)),
    apply_visible_(false)
{
    // --- Bookmark menu, built once and kept in sync with the model. -------
    // The actions sit at the top, then a separator, then the saved-filter
    // section header and its per-bookmark entries (appended at the bottom and
    // rebuilt from the model).
    bookmark_menu_ = new QMenu(this);
    saved_section_label_ = tr("Saved Filters");
    save_action_ = bookmark_menu_->addAction(tr("Save this filter"));
    remove_action_ = bookmark_menu_->addAction(tr("Remove this filter"));
    manage_action_ = bookmark_menu_->addAction(tr("Manage Saved Filters"));
    preferences_action_ = bookmark_menu_->addAction(tr("Filter Button Preferences..."));
    static_separator_ = bookmark_menu_->addSeparator();

    connect(save_action_, &QAction::triggered, this, [this]() {
        emit saveBookmarkRequested(text());
    });
    connect(remove_action_, &QAction::triggered, this, [this]() {
        emit removeBookmarkRequested(text());
    });
    connect(manage_action_, &QAction::triggered, this, [this]() {
        emit manageBookmarksRequested();
    });
    connect(preferences_action_, &QAction::triggered, this, [this]() {
        emit preferencesRequested();
    });

    // --- Recent-list popup, filled on demand. ----------------------------
    history_menu_ = new QMenu(this);

    // --- In-line actions (native addAction layout, no hand geometry). ----
    // Capture the internal icon buttons as their actions create them, so
    // paintEvent() can fence the icon zones off from the tint and anchor the
    // dividers to the right button edges.
    QList<QToolButton *> known_buttons;

    // Leading: bookmark.
    bookmark_action_ = new QAction(StockIcon("x-capture-filter-bookmark"), QString(), this);
    bookmark_action_->setToolTip(tr("Manage saved filters"));
    addAction(bookmark_action_, QLineEdit::LeadingPosition);
    bookmark_button_ = takeNewButton(this, known_buttons);
    bookmark_action_->setVisible(false);
    connect(bookmark_action_, &QAction::triggered, this, [this]() {
        bookmark_menu_->popup(mapToGlobal(QPoint(0, height())));
    });

    // Trailing actions are right-anchored: the first added sits nearest the
    // edge, each subsequent one to its left.  Adding history, then apply, then
    // clear yields a left-to-right order of clear, apply, history -- matching
    // the long-standing toolbar layout.
    history_action_ = new QAction(
        ThemedIcon(":/svg_icons/x-filter-history.svg", ThemeManager::PaletteText),
        QString(), this);
    history_action_->setToolTip(tr("Recent filters"));
    addAction(history_action_, QLineEdit::TrailingPosition);
    history_button_ = takeNewButton(this, known_buttons);
    history_action_->setVisible(false);
    connect(history_action_, &QAction::triggered, this, [this]() {
        populateHistoryMenu();
        // Span at least the field width, like the old combo dropdown; the menu
        // still grows wider for longer entries.
        history_menu_->setMinimumWidth(width());
        history_menu_->popup(mapToGlobal(QPoint(0, height())));
    });

    // Monochrome like clear/history: the validity feedback lives in the central
    // background tint, so a coloured apply glyph would clash with it (a green
    // apply beside a green valid field).
    apply_action_ = new QAction(
        ThemedIcon(":/svg_icons/x-filter-apply.svg", ThemeManager::PaletteText),
        QString(), this);
    apply_action_->setToolTip(tr("Apply this filter"));
    addAction(apply_action_, QLineEdit::TrailingPosition);
    apply_button_ = takeNewButton(this, known_buttons);
    apply_action_->setVisible(false);
    connect(apply_action_, &QAction::triggered, this, &FilterExpressionEdit::applyExpression);

    clear_action_ = new QAction(
        ThemedIcon(":/svg_icons/x-filter-clear.svg", ThemeManager::PaletteText),
        QString(), this);
    clear_action_->setToolTip(tr("Clear the filter"));
    addAction(clear_action_, QLineEdit::TrailingPosition);
    clear_button_ = takeNewButton(this, known_buttons);
    clear_action_->setVisible(false);
    connect(clear_action_, &QAction::triggered, this, [this]() {
        clear();
        emit cleared();
    });

    // --- Generic signal/state plumbing. ----------------------------------
    connect(this, &QLineEdit::textChanged, this, [this](const QString &t) {
        updateClearVisible();
        updateApplyEnabled();
        updateRemoveEnabled();
        emit textChangedExpr(t);
    });
    connect(this, &FilterEdit::syntaxStateChanged, this, [this](FilterEdit::SyntaxState s) {
        updateApplyEnabled();
        emit validityChanged(s == FilterEdit::SyntaxState::Valid ||
                             s == FilterEdit::SyntaxState::Deprecated);
    });
    connect(this, &QLineEdit::returnPressed, this, &FilterExpressionEdit::applyExpression);

    updateClearVisible();
    updateApplyEnabled();
    updateRemoveEnabled();
}

void FilterExpressionEdit::setHistoryModel(FilterHistoryModel *model)
{
    if (historyModel_ == model)
        return;

    // Caller-owned: drop our merged-completion reference to the old one, but
    // never delete it.
    if (historyModel_)
        completion_source_->removeSourceModel(historyModel_);

    historyModel_ = model;

    if (historyModel_)
        completion_source_->addSourceModel(historyModel_);

    history_action_->setVisible(historyModel_ != nullptr);
}

void FilterExpressionEdit::setBookmarkModel(BookmarkModel *model)
{
    if (bookmarkModel_ == model)
        return;

    if (bookmarkModel_) {
        completion_source_->removeSourceModel(bookmarkModel_);
        delete bookmarkModel_; // widget-owned
    }

    bookmarkModel_ = model;

    if (bookmarkModel_) {
        bookmarkModel_->setParent(this);
        completion_source_->addSourceModel(bookmarkModel_);
        // Keep the menu's dynamic section in sync without rebuilding the whole
        // menu or re-wiring the static actions.
        connect(bookmarkModel_, &QAbstractItemModel::modelReset,
                this, &FilterExpressionEdit::rebuildBookmarkEntries);
        connect(bookmarkModel_, &QAbstractItemModel::rowsInserted,
                this, &FilterExpressionEdit::rebuildBookmarkEntries);
        connect(bookmarkModel_, &QAbstractItemModel::rowsRemoved,
                this, &FilterExpressionEdit::rebuildBookmarkEntries);
        connect(bookmarkModel_, &QAbstractItemModel::dataChanged,
                this, &FilterExpressionEdit::rebuildBookmarkEntries);
    }

    bookmark_action_->setVisible(bookmarkModel_ != nullptr);
    rebuildBookmarkEntries();
    updateRemoveEnabled();
}

void FilterExpressionEdit::setApplyActionVisible(bool visible)
{
    apply_visible_ = visible;
    apply_action_->setVisible(visible);
    updateApplyEnabled();
}

void FilterExpressionEdit::setBookmarkIcon(const QIcon &icon)
{
    bookmark_action_->setIcon(icon);
}

void FilterExpressionEdit::setPreferencesActionVisible(bool visible)
{
    preferences_action_->setVisible(visible);
}

void FilterExpressionEdit::setBookmarkMenuLabels(const QString &saved_section,
                                                 const QString &save_current,
                                                 const QString &remove_current,
                                                 const QString &manage,
                                                 const QString &preferences)
{
    saved_section_label_ = saved_section;
    save_action_->setText(save_current);
    remove_action_->setText(remove_current);
    manage_action_->setText(manage);
    preferences_action_->setText(preferences);
    rebuildBookmarkEntries(); // header text changed
}

void FilterExpressionEdit::applyExpression()
{
    validateNow();

    const QString expr = text();
    if (expr.isEmpty() || state() == FilterEdit::SyntaxState::Invalid)
        return;

    emit applied(expr);

    // Commit to history (dedup + move-to-front, bounded) on the injected model.
    if (historyModel_)
        historyModel_->addRecent(expr);
}

void FilterExpressionEdit::rebuildBookmarkEntries()
{
    // Remove only the dynamic per-bookmark actions; the static block and its
    // connections are left untouched.
    for (QAction *entry : entry_actions_) {
        bookmark_menu_->removeAction(entry);
        delete entry;
    }
    entry_actions_.clear();

    const int rows = bookmarkModel_ ? bookmarkModel_->rowCount() : 0;
    if (rows == 0) {
        // Nothing saved: drop the separator too, so the menu is just the actions.
        static_separator_->setVisible(false);
        return;
    }
    static_separator_->setVisible(true);

    const QFont base = bookmark_menu_->font();

    // Section header: small, uppercase, muted — a real widget because macOS
    // QMenu::addSection() drops the title text.
    QLabel *header = new QLabel(saved_section_label_.toUpper());
    QFont header_font = base;
    header_font.setPointSizeF(qMax(1.0, base.pointSizeF() - 2.0));
    header->setFont(header_font);
    header->setContentsMargins(12, 5, 12, 2);
    {
        QPalette pal = header->palette();
        pal.setColor(QPalette::WindowText, mutedColor(pal, 0.45));
        header->setPalette(pal);
    }
    QWidgetAction *header_action = new QWidgetAction(this);
    header_action->setDefaultWidget(header);
    header_action->setEnabled(false); // non-interactive label
    // Appended after the separator, so the saved section sits below the actions.
    bookmark_menu_->addAction(header_action);
    entry_actions_.append(header_action);

    for (int row = 0; row < rows; ++row) {
        const QModelIndex idx = bookmarkModel_->index(row, 0);
        const QString expr = idx.data(BookmarkModel::ExpressionRole).toString();
        const QString name = idx.data(BookmarkModel::NameRole).toString();

        // Two-column row: monospace expression on the left, muted name on the
        // right. Selecting a bookmark sets the field text; it does not apply.
        BookmarkEntryWidget *widget = new BookmarkEntryWidget(expr, name, base);
        QWidgetAction *entry = new QWidgetAction(this);
        entry->setDefaultWidget(widget);
        widget->onActivate = [this, expr]() {
            setText(expr);
            bookmark_menu_->close();
        };
        // Keep entries grouped under the section header at the bottom of the menu.
        bookmark_menu_->addAction(entry);
        entry_actions_.append(entry);
    }
}

void FilterExpressionEdit::populateHistoryMenu()
{
    history_menu_->clear();
    if (!historyModel_)
        return;

    // Most-recent first is the model's own row order (row 0 == newest).
    const int rows = historyModel_->rowCount();
    for (int row = 0; row < rows; ++row) {
        const QString expr = historyModel_->index(row, 0).data(Qt::DisplayRole).toString();
        QAction *entry = history_menu_->addAction(expr);
        connect(entry, &QAction::triggered, this, [this, expr]() {
            setText(expr); // sets and re-validates; does not auto-apply
        });
    }
}

void FilterExpressionEdit::updateClearVisible()
{
    clear_action_->setVisible(!text().isEmpty());
}

void FilterExpressionEdit::updateApplyEnabled()
{
    apply_action_->setEnabled(apply_visible_ && !text().isEmpty() &&
                              state() != FilterEdit::SyntaxState::Invalid);
}

void FilterExpressionEdit::updateRemoveEnabled()
{
    // Always present; enabled only when the current text exactly matches a
    // saved entry. Centralises logic the old edits duplicated in checkFilter().
    const bool match = bookmarkModel_ && bookmarkModel_->contains(text());
    remove_action_->setEnabled(match);
}

void FilterExpressionEdit::paintEvent(QPaintEvent *event)
{
    FilterEdit::paintEvent(event);

    QPainter painter(this);

    // Stay inside the 1px rounded frame the QSS draws (border-radius 3px → ~2px
    // inner radius) so nothing here paints over the border.
    const QRect inner = rect().adjusted(1, 1, -1, -1);
    QPainterPath clip;
    clip.addRoundedRect(inner, 2, 2);
    painter.setClipPath(clip);

    // The QSS background-color tints the whole field, including behind the
    // in-line icons; repaint the leading (bookmark) and trailing
    // (clear/history/apply) icon strips with the neutral field background so the
    // tint stays in the text area. The glyphs are child widgets painted after
    // us, so they stay visible over this fill.
    //
    // Source the neutral from the application palette, not this widget's: under
    // the QSS state tint the widget's own QPalette::Base reads off-colour (a
    // dark box even in light mode), while qApp's base is the true field colour
    // — the same source the in-line glyphs use, so the strips match.
    const QColor field = qApp->palette().color(QPalette::Base);

    if (bookmark_button_ && bookmark_button_->isVisible()) {
        const int edge = bookmark_button_->geometry().right() + 1;
        painter.fillRect(QRect(QPoint(inner.left(), inner.top()),
                               QPoint(edge - 1, inner.bottom())), field);
    }

    int trailing_edge = inner.right() + 1;
    for (const QToolButton *button : {clear_button_, history_button_, apply_button_}) {
        if (button && button->isVisible())
            trailing_edge = qMin(trailing_edge, button->geometry().left());
    }
    if (trailing_edge <= inner.right())
        painter.fillRect(QRect(QPoint(trailing_edge, inner.top()),
                               QPoint(inner.right(), inner.bottom())), field);

    // Thin vertical hairlines mark the icon-zone boundaries — the separation the
    // mockup draws with its `vsep` dividers. At a low alpha so each reads as a
    // hairline rather than a second border. The two sit on different
    // backgrounds, so they take their colour from different places: the bookmark
    // hairline borders the tinted text area, so use the widget foreground that
    // setState() keeps contrast-correct against the active tint; the history
    // hairline sits on the neutral trailing strip, so use the application text
    // colour (a tinted state overrides the widget's QPalette::Text).
    QColor tint_divider = palette().color(QPalette::Text);
    tint_divider.setAlpha(150);
    QColor base_divider = qApp->palette().color(QPalette::Text);
    base_divider.setAlpha(150);

    // QLineEdit's icon button sits its glyph near the button's own right edge, so
    // the only gap before the text is the line edit's small text margin. The line
    // sits a single pixel past the edge to land midway between glyph and text.
    // Tune kGapInset if it drifts toward either side.
    const int kGapInset = 1;

    auto drawDivider = [&](const QToolButton *button, int x, const QColor &color) {
        painter.setPen(QPen(color, 1));
        const QRect g = button->geometry();
        painter.drawLine(x, g.top() + 2, x, g.bottom() - 2);
    };

    if (bookmark_button_ && bookmark_button_->isVisible())
        drawDivider(bookmark_button_, bookmark_button_->geometry().right() + kGapInset,
                    tint_divider);
    // Isolate the history dropdown on the far right, the way the old combo box's
    // drop arrow read as its own affordance.
    if (history_button_ && history_button_->isVisible())
        drawDivider(history_button_, history_button_->geometry().left() - kGapInset,
                    base_divider);
}
