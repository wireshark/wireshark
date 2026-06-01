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

#include <QList>

class FilterHistoryModel;
class BookmarkModel;

class QAction;
class QConcatenateTablesProxyModel;
class QMenu;
class QToolButton;

/**
 * @brief FilterEdit plus the in-line action set, menus and history/bookmark
 *        wiring shared by the display- and capture-filter entries.
 *
 * Sub-controls are added with QLineEdit::addAction(), which positions icons
 * inside the field with native spacing, height, RTL and focus handling. There is
 * no hand-managed button geometry: showing or hiding an action reflows the
 * layout natively. The only painting we add is a pair of thin vertical dividers
 * (paintEvent) that fence the leading bookmark and trailing apply zones off from
 * the text, matching the design mockup.
 *
 * Actions, in layout order:
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
     * @brief Sets the bookmark glyph used for the leading action.
     *        The base is filter-type-neutral; leaves supply their own icon.
     */
    void setBookmarkIcon(const QIcon &icon);

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
    void updateClearVisible();     /**< Clear action visible iff text non-empty. */
    void updateApplyEnabled();     /**< Apply enabled iff non-empty and not Invalid. */
    void updateRemoveEnabled();    /**< "Remove current" enabled on exact match. */

    QAction *bookmark_action_; /**< Leading; opens bookmark menu. */
    QAction *clear_action_;    /**< Trailing; clears the field. */
    QAction *history_action_;  /**< Trailing; opens recent-list popup. */
    QAction *apply_action_;    /**< Trailing; applies (explicit mode only). */

    // The internal icon buttons QLineEdit builds for the leading/trailing
    // actions. QLineEdit exposes no action-to-button accessor, so we capture
    // them as their addAction() calls create them. paintEvent() uses their
    // geometry to fence the icon zones off from the tint and to anchor the
    // dividers. Non-owning (parented to this line edit).
    QToolButton *bookmark_button_; /**< Leading; right edge ends the tinted area. */
    QToolButton *clear_button_;    /**< Trailing; left edge starts the icon zone. */
    QToolButton *history_button_;  /**< Trailing; left edge starts the icon zone. */
    QToolButton *apply_button_;    /**< Trailing; left edge anchors its divider. */

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

    bool apply_visible_; /**< Explicit-apply mode flag. */
};

#endif // FILTER_EXPRESSION_EDIT_H
