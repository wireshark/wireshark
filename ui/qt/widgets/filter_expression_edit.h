/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILTER_EXPRESSION_EDIT_H
#define FILTER_EXPRESSION_EDIT_H

#include <ui/qt/widgets/filter_edit.h>

#include <QIcon>
#include <QList>

class FilterHistoryModel;
class BookmarkModel;
class AdaptiveToolButton;

class QAction;
class QConcatenateTablesProxyModel;
class QHBoxLayout;
class QMenu;
class QMargins;

/**
 * @brief FilterEdit plus the in-line action set, menus and history/bookmark
 *        wiring shared by the display- and capture-filter entries.
 *
 * Sub-controls are AdaptiveToolButton children placed by a QHBoxLayout inside
 * the field (bookmark | text | clear apply history). Each button hugs its glyph
 * and tracks the application zoom; the layout reflows them on resize, and
 * updateInlineMargins() reserves matching text margins so the text never runs
 * under a button. Reserving via text margins also feeds QLineEdit's sizeHint, so
 * the toolbar cannot compress the field under its neighbours. The only painting
 * we add is a pair of thin vertical dividers (paintEvent) that fence the leading
 * bookmark and trailing apply zones off from the text, matching the design
 * mockup.
 *
 * Buttons, in layout order:
 *  - Bookmark (leading): opens the bookmark menu. Present only with a bookmark
 *    model set.
 *  - Clear (trailing): visible only when the text is non-empty.
 *  - History (trailing): opens the recent-list popup. Present only with a
 *    history model set.
 *  - Apply (trailing): applies the expression. Present only in explicit-apply
 *    mode (setApplyActionVisible(true)).
 *
 * The base emits generic, domain-neutral signals; the CaptureFilterEntry (and
 * the planned display-filter leaf) translate them to their existing vocabularies.
 */
class FilterExpressionEdit : public FilterEdit
{
    Q_OBJECT

public:
    explicit FilterExpressionEdit(QWidget *parent = nullptr);

    /**
     * @brief Sets the recent-history model. Caller-owned: the widget keeps a
     *        non-owning reference and never deletes it. The history action and
     *        merged completion source pick it up.
     */
    void setHistoryModel(FilterHistoryModel *model);

    /** @brief The injected history model, or nullptr. */
    FilterHistoryModel *historyModel() const { return historyModel_; }

    /**
     * @brief Sets the bookmark model. Widget-owned: deleted with the widget and
     *        replacing any previous model. Enables the bookmark action and menu.
     */
    void setBookmarkModel(BookmarkModel *model);

    /** @brief The bookmark model, or nullptr. */
    BookmarkModel *bookmarkModel() const { return bookmarkModel_; }

    /**
     * @brief Shows or hides the apply (→) action, selecting explicit- vs
     *        implicit-apply mode. Hidden by default.
     */
    void setApplyActionVisible(bool visible);

    /** @brief True when the apply action is present (explicit-apply mode). */
    bool isApplyActionVisible() const { return apply_visible_; }

    /**
     * @brief Shows or hides the bookmark menu's "preferences" item. Filter types
     *        without a relevant preferences pane (e.g. capture) hide it.
     */
    void setPreferencesActionVisible(bool visible);

    /**
     * @brief Sets the leading bookmark glyphs: @p normal in the per-filter
     *        colour and @p matching shown when the current text is already a
     *        saved bookmark. Leaves supply both (same SVG, different theme
     *        token); the base swaps between them as the text matches a bookmark.
     */
    void setBookmarkIcon(const QIcon &normal, const QIcon &matching);

    /**
     * @brief Supplies the bookmark-menu label strings. Menu structure, behaviour
     *        and enablement are identical across filter types; only the wording
     *        differs, so leaves provide it here.
     */
    void setBookmarkMenuLabels(const QString &saved_section,
                               const QString &save_current,
                               const QString &remove_current,
                               const QString &manage,
                               const QString &preferences);

    /**
     * @brief The merged history+bookmark model that backs typeahead completion.
     *        Owned by the widget; references (does not own) its sources. Leaves
     *        point their FilterCompleter at this.
     */
    QConcatenateTablesProxyModel *completionModel() const { return completion_source_; }

    /**
     * @brief Left-aligns the inline buttons (all clustered after the bookmark,
     *        with the text to their right) instead of right-anchoring the
     *        trailing trio. Persisted in recent.gui_geometry_leftalign_actions,
     *        so display and capture both honour the saved preference.
     */
    void setButtonsLeftAligned(bool left);

    /** @brief True when the inline buttons are left-aligned. */
    bool buttonsLeftAligned() const { return buttons_left_aligned_; }

signals:
    /** @brief The current expression was applied (action, or Enter). */
    void applied(const QString &expression);
    /** @brief The expression text changed (distinct from QLineEdit::textChanged). */
    void textChangedExpr(const QString &expression);
    /** @brief Convenience: emitted with (state == Valid || state == Deprecated). */
    void validityChanged(bool valid);
    /** @brief The clear action was triggered (distinct from typing to empty). */
    void cleared();

    /** @brief "Save current" chosen in the bookmark menu. */
    void saveBookmarkRequested(const QString &expression);
    /** @brief "Remove current" chosen in the bookmark menu. */
    void removeBookmarkRequested(const QString &expression);
    /** @brief "Manage" chosen in the bookmark menu. */
    void manageBookmarksRequested();
    /** @brief "Preferences" chosen in the bookmark menu. */
    void preferencesRequested();

protected:
    /**
     * @brief Validates the final text and, if applyable, emits applied() and
     *        records the expression to history. No-op when empty or Invalid.
     */
    void applyExpression();

    /** @brief Paints the field, then the bookmark/apply zone dividers on top. */
    void paintEvent(QPaintEvent *event) override;

private:
    void rebuildBookmarkEntries(); /**< Refresh the dynamic bookmark section. */
    void populateHistoryMenu();    /**< (Re)fill the recent-list popup on show. */
    void updateClearVisible();     /**< Clear button visible iff text non-empty. */
    void updateApplyEnabled();     /**< Apply enabled iff non-empty and not Invalid. */
    void updateRemoveEnabled();    /**< "Remove current" enabled on exact match. */
    void updateBookmarkState();    /**< Swap to the matching glyph when text is saved. */
    void updateInlineMargins();    /**< Reserve text margins for the shown inline buttons. */
    void rebuildInlineLayout();    /**< (Re)place the buttons for the current alignment. */

    QMargins inlineMargins(); /**< Returns the left and right text margins needed to clear the buttons. */

    // Inline affordance buttons, placed by a QHBoxLayout inside the field and
    // sized by AdaptiveToolButton (tight box, zoom-aware glyph). paintEvent()
    // uses their geometry to fence the icon zones off from the tint and to
    // anchor the dividers. Parented to this line edit via the layout.
    AdaptiveToolButton *bookmark_button_; /**< Leading; right edge ends the tinted area. */
    AdaptiveToolButton *clear_button_;    /**< Trailing; left edge starts the icon zone. */
    AdaptiveToolButton *history_button_;  /**< Trailing; left edge starts the icon zone. */
    AdaptiveToolButton *apply_button_;    /**< Trailing; left edge anchors its divider. */
    QHBoxLayout        *inline_layout_;   /**< Places the buttons + text-area stretch. */

    QIcon normal_bookmark_icon_;   /**< Leading glyph in the per-filter colour. */
    QIcon matching_bookmark_icon_; /**< Leading glyph when the text is already saved. */

    QMenu *bookmark_menu_;     /**< Built once; dynamic section synced to model. */
    QMenu *history_menu_;      /**< Recent-list popup, filled on show. */

    // Static bookmark-menu actions, kept so labels/enablement can be updated.
    QAction *save_action_;
    QAction *remove_action_;
    QAction *manage_action_;
    QAction *preferences_action_;
    QAction *static_separator_;     /**< Divides the dynamic entries from the static block. */
    QString saved_section_label_;   /**< "Saved Filters" header text (rendered as a widget). */
    QList<QAction *> entry_actions_; /**< Dynamic items (header + per-bookmark rows), in order. */

    FilterHistoryModel *historyModel_; /**< Non-owning. */
    BookmarkModel      *bookmarkModel_; /**< Widget-owned. */
    QConcatenateTablesProxyModel *completion_source_; /**< Widget-owned merge. */

    bool apply_visible_;         /**< Explicit-apply mode flag. */
    bool buttons_left_aligned_;  /**< Inline buttons clustered left vs right-anchored. */
};

#endif // FILTER_EXPRESSION_EDIT_H
