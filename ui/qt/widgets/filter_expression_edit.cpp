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

#include <ui/qt/widgets/adaptive_tool_button.h>
#include <ui/qt/models/filter_history_model.h>
#include <ui/qt/models/bookmark_model.h>
#include <ui/qt/utils/font_manager.h>
#include <ui/qt/utils/stock_icon.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/themed_icon.h>
#include <ui/qt/utils/theme_manager.h>

#include <ui/recent.h>

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
#include <QStyle>
#include <QToolButton>
#include <QWidgetAction>
#include <QMargins>

#include <functional>

namespace {

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
        QFont mono = FontManager::monospaceFont();
        mono.setPointSizeF(base.pointSizeF() - 1.0); // match the header's relative sizing
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

} // namespace

// Spacing (px) between adjacent inline buttons and between a button and the text
// area; small so the affordances read as a tight cluster.
static const int inline_button_spacing_ = 2;

FilterExpressionEdit::FilterExpressionEdit(QWidget *parent) :
    FilterEdit(parent),
    bookmark_button_(nullptr),
    clear_button_(nullptr),
    history_button_(nullptr),
    apply_button_(nullptr),
    inline_layout_(nullptr),
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
    apply_visible_(false),
    buttons_left_aligned_(recent.gui_geometry_leftalign_actions)
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

    // --- In-line buttons, placed by a layout and sized by AdaptiveToolButton. -
    // Each button hugs its glyph and tracks zoom; the layout below reflows them
    // on resize, and updateInlineMargins() reserves matching text margins.
    // Buttons start hidden and are shown by their model/text/apply conditions.

    // Leading: bookmark.
    bookmark_button_ = new AdaptiveToolButton(this);
    bookmark_button_->setIconPadding(1);
    bookmark_button_->setBaseIconSize(QSize(14, 14));
    bookmark_button_->setIcon(StockIcon("x-capture-filter-bookmark"));
    bookmark_button_->setToolTip(tr("Manage saved filters"));
    bookmark_button_->setVisible(false);
    connect(bookmark_button_, &QAbstractButton::clicked, this, [this]() {
        bookmark_menu_->popup(mapToGlobal(QPoint(0, height())));
    });

    // Trailing trio, in left-to-right order clear, apply, history.
    clear_button_ = new AdaptiveToolButton(this);
    clear_button_->setIconPadding(1);
    clear_button_->setBaseIconSize(QSize(14, 14));
    // Neutral at rest, red on hover (QIcon::Active) — the old "x-filter-clear"
    // gray→scarlet behaviour, now theme-token driven.
    clear_button_->setIcon(ThemedIcon(":/svg_icons/x-filter-clear.svg",
                                      ThemeManager::PaletteText, ThemeManager::FilterClear));
    clear_button_->setToolTip(tr("Clear the filter"));
    clear_button_->setVisible(false);
    connect(clear_button_, &QAbstractButton::clicked, this, [this]() {
        clear();
        emit cleared();
    });

    // Blue when there is something to apply (item 6). The state tint stays in
    // the text area (paintEvent fences the icon strips with the neutral field
    // bg), so the blue glyph reads as its own affordance rather than clashing
    // with a green "valid" field. Disabled (nothing to apply) dims via the
    // engine's Disabled mode.
    apply_button_ = new AdaptiveToolButton(this);
    apply_button_->setIconPadding(1);
    apply_button_->setIcon(ThemedIcon(":/svg_icons/x-filter-apply.svg", ThemeManager::FilterApply));
    apply_button_->setToolTip(tr("Apply this filter"));
    // The apply glyph is a wide 24x14 chevron (its native SVG size); set that
    // fixed so a square box doesn't squeeze it short. AdaptiveToolButton scales
    // width and height independently, so the 24:14 aspect holds under zoom.
    apply_button_->setBaseIconSize(QSize(24, 14));
    apply_button_->setVisible(false);
    connect(apply_button_, &QAbstractButton::clicked, this, &FilterExpressionEdit::applyExpression);

    history_button_ = new AdaptiveToolButton(this);
    history_button_->setIconPadding(1);
    // Dimmed disclosure caret at rest (FilterHistory ≈ the classic combo-arrow
    // gray), brightening to the brand colour on hover and press so the arrow
    // reads as a button. The stateful ThemedIcon supplies the per-mode glyph
    // colours QToolButton requests on hover/press; QSS cannot recolour an SVG
    // fill, so the feedback has to live on the icon, as it does for clear.
    history_button_->setIcon(ThemedIcon(":/svg_icons/x-filter-history.svg",
                                        ThemeManager::FilterHistory,
                                        ThemeManager::BrandPrimary));
    history_button_->setToolTip(tr("Recent filters"));
    // Size the recent-filters dropdown like a disclosure arrow rather than a full
    // action glyph. QStyle exposes no tree-arrow metric; PM_MenuButtonIndicator
    // is the dropdown-indicator size and the closest equivalent.
    const int arrow = style()->pixelMetric(QStyle::PM_MenuButtonIndicator, nullptr, this);
    history_button_->setBaseIconSize(QSize(arrow, arrow) * 2);
    history_button_->setVisible(false);
    connect(history_button_, &QAbstractButton::clicked, this, [this]() {
        populateHistoryMenu();
        // Span at least the field width, like the old combo dropdown; the menu
        // still grows wider for longer entries.
        history_menu_->setMinimumWidth(width());
        history_menu_->popup(mapToGlobal(QPoint(0, height())));
    });

    // Lay the buttons out inside the field. rebuildInlineLayout() places them for
    // the current alignment; hidden buttons take no layout space, so the row
    // tightens as conditions change.
    const int frame = style()->pixelMetric(QStyle::PM_DefaultFrameWidth, nullptr, this);
    inline_layout_ = new QHBoxLayout(this);
    inline_layout_->setContentsMargins(frame + 1, 0, frame + 1, 0);
    inline_layout_->setSpacing(inline_button_spacing_);
    rebuildInlineLayout();

    // --- Generic signal/state plumbing. ----------------------------------
    connect(this, &QLineEdit::textChanged, this, [this](const QString &t) {
        updateClearVisible();
        updateApplyEnabled();
        updateRemoveEnabled();
        updateBookmarkState();
        emit textChangedExpr(t);
    });
    connect(this, &FilterEdit::syntaxStateChanged, this, [this](FilterEdit::SyntaxState s) {
        updateApplyEnabled();
        emit validityChanged(s == FilterEdit::SyntaxState::Valid ||
                             s == FilterEdit::SyntaxState::Deprecated);
    });
    connect(this, &QLineEdit::returnPressed, this, &FilterExpressionEdit::applyExpression);

    // Button widths change with zoom; keep the reserved text margins in step so
    // the text/affordance boundary stays correct.
    connect(FontManager::instance(), &FontManager::zoomChanged,
            this, &FilterExpressionEdit::updateInlineMargins);

    updateClearVisible();
    updateApplyEnabled();
    updateRemoveEnabled();
    updateBookmarkState();
    updateInlineMargins();
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

    history_button_->setVisible(historyModel_ != nullptr);
    updateInlineMargins();
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

    bookmark_button_->setVisible(bookmarkModel_ != nullptr);
    rebuildBookmarkEntries();
    updateRemoveEnabled();
    updateInlineMargins();
}

void FilterExpressionEdit::setApplyActionVisible(bool visible)
{
    apply_visible_ = visible;
    apply_button_->setVisible(visible);
    updateApplyEnabled();
    updateInlineMargins();
}

void FilterExpressionEdit::setBookmarkIcon(const QIcon &normal, const QIcon &matching)
{
    normal_bookmark_icon_ = normal;
    matching_bookmark_icon_ = matching;
    updateBookmarkState();
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
    if (expr.isEmpty()) {
        emit cleared();
        return;
    }
    if (state() == FilterEdit::SyntaxState::Invalid)
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
        updateBookmarkState(); // e.g. the last bookmark was just removed
        return;
    }
    static_separator_->setVisible(true);

    const QFont base = bookmark_menu_->font();

    // Section header: small, uppercase, muted — a real widget because macOS
    // QMenu::addSection() drops the title text.
    QLabel *header = new QLabel(saved_section_label_.toUpper());
    QFont header_font = base;
    header_font.setPointSizeF(qMax(1.0, base.pointSizeF() - 1.0));
    header->setFont(header_font);
    header->setContentsMargins(12, 5, 12, 2);

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

    updateBookmarkState(); // the current text may now (not) match a saved entry
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
    // Reflow only when the clear button's presence actually flips, so typing
    // doesn't re-reserve text margins on every keystroke.
    const bool show = !text().isEmpty();
    if (show == !clear_button_->isHidden())
        return;
    clear_button_->setVisible(show);
    updateInlineMargins();
}

void FilterExpressionEdit::updateApplyEnabled()
{
    apply_button_->setEnabled(apply_visible_ && !text().isEmpty() &&
                              state() != FilterEdit::SyntaxState::Invalid);
}

void FilterExpressionEdit::rebuildInlineLayout()
{
    // Drop existing items; the buttons stay parented to the field, spacers freed.
    while (QLayoutItem *item = inline_layout_->takeAt(0))
        delete item;

    // Right-aligned (default):  bookmark | <text> | clear apply history
    // Left-aligned:             bookmark clear apply history | <text>
    inline_layout_->addWidget(bookmark_button_, 0, Qt::AlignVCenter);
    if (!buttons_left_aligned_)
        inline_layout_->addStretch(1);
    inline_layout_->addWidget(clear_button_, 0, Qt::AlignVCenter);
    inline_layout_->addWidget(apply_button_, 0, Qt::AlignVCenter);
    if (buttons_left_aligned_)
        inline_layout_->addStretch(1);
    inline_layout_->addWidget(history_button_, 0, Qt::AlignVCenter);

    updateInlineMargins();
}

void FilterExpressionEdit::setButtonsLeftAligned(bool left)
{
    if (buttons_left_aligned_ == left)
        return;
    buttons_left_aligned_ = left;
    recent.gui_geometry_leftalign_actions = left;
    write_recent();
    rebuildInlineLayout();
}

QMargins FilterExpressionEdit::inlineMargins() {
    // Reserve text margins matching the shown buttons so the text never runs
    // under one, and so QLineEdit's sizeHint accounts for them (keeping the
    // toolbar from compressing the field under its neighbours). The dividers in
    // paintEvent() use the buttons' real geometry, so a slight over-reservation
    // here is harmless. Use isHidden(), not isVisible(): this runs before the
    // field is first shown, when isVisible() is still false for every child.
    const int edge = style()->pixelMetric(QStyle::PM_DefaultFrameWidth, nullptr, this) + 1;

    auto zone = [](const AdaptiveToolButton *b) {
        return b->isHidden() ? 0 : b->sizeHint().width() + inline_button_spacing_;
    };

    auto leftTrail = edge + zone(bookmark_button_);
    auto rightTrail = edge + zone(history_button_);
    if (buttons_left_aligned_ )
        leftTrail += zone(clear_button_) + zone(apply_button_);
    else
        rightTrail += zone(clear_button_) + zone(apply_button_);

    return QMargins(leftTrail, 0, rightTrail, 0);
}

void FilterExpressionEdit::updateInlineMargins()
{
    setTextMargins(inlineMargins());
}

void FilterExpressionEdit::updateRemoveEnabled()
{
    // Always present; enabled only when the current text exactly matches a
    // saved entry. Centralises logic the old edits duplicated in checkFilter().
    const bool match = bookmarkModel_ && bookmarkModel_->contains(text());
    remove_action_->setEnabled(match);
}

void FilterExpressionEdit::updateBookmarkState()
{
    // "Matching" is data state, not an interaction mode, so the widget owns the
    // swap: show the matching (saved) glyph when the current text is a saved
    // bookmark, else the per-filter glyph. No-op until a leaf supplies both.
    if (normal_bookmark_icon_.isNull())
        return;
    const bool saved = bookmarkModel_ && bookmarkModel_->contains(text());
    bookmark_button_->setIcon(saved ? matching_bookmark_icon_ : normal_bookmark_icon_);
}

void FilterExpressionEdit::paintEvent(QPaintEvent *event)
{
    FilterEdit::paintEvent(event);

    // QLineEdit's icon button sits its glyph near the button's own right edge, so
    // the only gap before the text is the line edit's small text margin. The line
    // sits a single pixel past the edge to land midway between glyph and text.
    // Tune kGapInset if it drifts toward either side.
    const int kGapInset = 2;

    ThemeManager * tm = ThemeManager::instance();

    QMargins margins = inlineMargins();
    const QColor field = tm->color(ThemeManager::PaletteBase);
    const QColor tint_divider = tm->color(ThemeManager::FieldBorder);

    QPainter painter(this);

    // Stay inside the 1px rounded frame the QSS draws (border-radius 3px → ~2px
    // inner radius) so nothing here paints over the border.
    const QRect inner = rect().adjusted(1, 1, -1, -1);
    QPainterPath clip;
    clip.addRoundedRect(inner, 2, 2);
    painter.setClipPath(clip);
    painter.setPen(QPen(tint_divider, 1));

    // clear the background for the buttons on the left and right
    if (margins.left() > 0) {
        painter.fillRect(QRect(QPoint(inner.left(), inner.top()),
                QPoint(inner.left() + margins.left(), inner.bottom())), field);
        auto x = inner.left() + margins.left() - kGapInset;
        painter.drawLine(x, inner.top() + 2, x, inner.bottom() - 2);
    }
    if (margins.right() > 0) {
        painter.fillRect(QRect(QPoint(inner.right() - margins.right(), inner.top()),
                QPoint(inner.right(), inner.bottom())), field);
        auto x = inner.right() - margins.right() + kGapInset;
        painter.drawLine(x, inner.top() + 2, x, inner.bottom() - 2);
    }
}
