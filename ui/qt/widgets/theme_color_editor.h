/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_COLOR_EDITOR_H
#define THEME_COLOR_EDITOR_H

#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/theme_token_handler.h>

#include <QColor>
#include <QHash>
#include <QIcon>
#include <QList>
#include <QMap>
#include <QPair>
#include <QString>
#include <QStringList>
#include <QVector>
#include <QWidget>

class QLabel;
class QPoint;
class QPushButton;
class QTreeWidgetItem;
class SyntaxLineEdit;

namespace Ui {
class ThemeColorEditor;
}

/**
 * Color list and detail panel of the Theme Designer.
 *
 * Lists every color a theme file can set, the separator, the graph color
 * cycle and, read-only, every derived color.  Each row is marked "edited"
 * when the draft input differs from the base theme, "changed" when only its
 * resolved value differs (a consequence of another edit), "required" for the
 * brand and accent inputs, or shows the derived value in italics when the
 * key is not set.  The detail panel below the list edits both sides of the
 * selected color.
 *
 * Text that is not a color is kept per field and reported through
 * invalidCount() and firstInvalidPath(); the draft keeps the last valid
 * value.
 */
class ThemeColorEditor : public QWidget
{
    Q_OBJECT
public:
    explicit ThemeColorEditor(QWidget *parent = nullptr);
    ~ThemeColorEditor();

    /**
     * Replaces the base theme the marks compare against and the draft being
     * edited.  The selected row is kept when it still exists.  Text that is
     * not a color is dropped when another theme or other colors come in.
     *
     * @param base   the saved theme the draft was loaded from.
     * @param draft  the draft to edit.
     */
    void setDrafts(const ThemeDraft &base, const ThemeDraft &draft);

    /** The draft with every valid edit applied. */
    const ThemeDraft &draft() const { return draft_; }

    /** Selects the side the list values and swatches show. */
    void setDarkSide(bool dark);

    /** Rows marked "edited", including graph slots removed from the base. */
    int editedCount() const;

    /** Rows marked "changed" (resolved value differs, input unchanged). */
    int changedCount() const;

    /** Fields that hold text that is not a color. */
    int invalidCount() const { return static_cast<int>(pending_.size()); }

    /**
     * JSON path of the first field in list order that holds text that is
     * not a color, e.g. "packets.marked.dark"; empty when there is none.
     */
    QString firstInvalidPath() const;

    /**
     * The bold " edited" mark appended to a title, in the theme's edit color.
     * Shared so every title in the designer marks edits the same way.
     */
    static QString editedMarkHtml();

    /**
     * Selects and centers the row of @p token.  Color and derived rows share
     * the token-valued row id, so either kind is found.  A row hidden by the
     * filter text or the "changed only" check box gets both cleared first.
     *
     * @param token           the color to show.
     * @param filter_cleared  set to true when a filter had to be cleared.
     * @return false when @p token has no row.
     */
    bool selectToken(ThemeManager::ThemeToken token, bool *filter_cleared = nullptr);

    /** The label the list shows for @p token, or its name when it has no row. */
    QString tokenLabel(ThemeManager::ThemeToken token) const;

    /** A swatch of the resolved value of @p token on the shown side. */
    QIcon tokenSwatch(ThemeManager::ThemeToken token) const;

signals:
    /** Any input change, including a change of invalidCount(). */
    void draftChanged();

    /** The color dialog was closed, with or without a choice. */
    void childDialogClosed();

private:
    enum class RowKind { Color, Graph, NoGraphs, Derived };
    enum class RowState { None, Edited, Changed, Required };

    struct Row {
        RowKind kind = RowKind::Color;
        ThemeManager::ThemeToken token = ThemeManager::NoRole;
        int graph = -1;
        QString label;
        QString section;
        QString path;
        QString description;
        bool required = false;
        RowState state = RowState::None;
        QTreeWidgetItem *item = nullptr;

        /** The id this row has in row_index_ and pending_. */
        int id() const { return rowIdFor(kind, token, graph); }

        /** True for rows whose colors the user can edit. */
        bool editable() const { return kind == RowKind::Color || kind == RowKind::Graph; }
    };

    using ResolvedMap = QHash<ThemeManager::ThemeToken, QColor>;

    static int rowIdFor(RowKind kind, ThemeManager::ThemeToken token, int graph);
    static QString graphDescription();
    static QString tokenName(ThemeManager::ThemeToken token);
    /** The text on the color dialog and the Choose button of @p row. */
    static QString chooseTitle(const Row &row, int side);
    static void resolveBoth(const ThemeDraft &draft, ResolvedMap out[2],
                            ThemeTokenHandler::SourceMap *sources = nullptr);

    void rebuildTree();
    void recompute();
    void refreshRows();
    void applyFilter();
    void updateDetail(bool force_fields);
    void updateField(int side);

    const Row *currentRow() const;
    QColor inputColor(const Row &row, int side, bool *is_set = nullptr) const;
    QColor shownColor(const Row &row, int side) const;
    QString rowDescription(const Row &row) const;
    /** How the derived @p token is computed; empty when unknown. */
    QString derivedText(ThemeManager::ThemeToken token) const;
    /** The list column text and placeholder of an unset color. */
    QString autoValueText(const QColor &shown) const;
    QStringList affectedTokens(ThemeManager::ThemeToken token) const;
    /**
     * The colors @p row is computed from, in rule text order.  Only derived
     * rows and colors not set on the shown side have sources.
     */
    QList<ThemeManager::ThemeToken> sourceTokens(const Row &row) const;
    /** True when @p row is derived or not set on the shown side. */
    bool offersSources(const Row &row) const;
    void setColor(const Row &row, int side, const QColor &color);
    void dropPending(int row_id);
    void shiftGraphPending(int from, int delta);
    void removeGraphSlot(int slot);
    /**
     * Recomputes the marks, refreshes the list and the detail panel and
     * emits draftChanged().
     *
     * @param force_fields  rewrite the hex fields even when one has focus.
     */
    void finishChange(bool force_fields = false);
    /**
     * True when the value on @p side differs from the base: the entry exists
     * in only one of draft and base, or that side's color differs.  Pending
     * text is not considered.
     */
    bool sideValueEdited(const Row &row, int side) const;
    /** True when @p side holds pending text or sideValueEdited(). */
    bool sideEdited(const Row &row, int side) const;

    void currentItemChanged(QTreeWidgetItem *current);
    void hexEdited(int side, const QString &text);
    void hexEditingFinished(int side);
    void chooseColor(int side);
    void useAuto();
    void revertColor();
    void revertSide(int side);
    void showContextMenu(const QPoint &pos);
    void addGraphColor();
    void removeGraphColor();
    void themeChanged();

    ThemeDraft base_;
    ThemeDraft draft_;
    ResolvedMap base_resolved_[2];
    ResolvedMap draft_resolved_[2];
    ThemeTokenHandler::SourceMap sources_;
    bool dark_ = false;
    int current_row_id_ = -1;

    QVector<Row> rows_;
    QHash<int, int> row_index_;
    QList<QTreeWidgetItem *> group_items_;
    // Text that is not a color, per (row id, side 0 = light / 1 = dark).
    QMap<QPair<int, int>, QString> pending_;

    Ui::ThemeColorEditor *ui_;
    // The light (0) and dark (1) field rows of the form, indexed by side.
    QWidget *side_widget_[2];
    QLabel *swatch_label_[2];
    SyntaxLineEdit *hex_edit_[2];
    QPushButton *choose_button_[2];
    QPushButton *revert_button_[2];
};

#endif // THEME_COLOR_EDITOR_H
