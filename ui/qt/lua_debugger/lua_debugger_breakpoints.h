/* lua_debugger_breakpoints.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Breakpoints panel: list/model, inline editor + mode picker,
 * gutter integration, and persistence.
 */

#ifndef LUA_DEBUGGER_BREAKPOINTS_H
#define LUA_DEBUGGER_BREAKPOINTS_H

#include <QIcon>
#include <QLineEdit>
#include <QList>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStyledItemDelegate>
#include <QVariantMap>
#include <QVector>

#include "lua_debugger_utils.h"

class LuaDebuggerCodeView;
class LuaDebuggerDialog;
class QAbstractItemModel;
class QAction;
class QComboBox;
class QEvent;
class QModelIndex;
class QObject;
class QPalette;
class QPaintEvent;
class QPoint;
class QResizeEvent;
class QShowEvent;
class QStandardItem;
class QStandardItemModel;
class QStyleOptionViewItem;
class QToolButton;
class QTreeView;
class QWidget;

/** @brief Column indices for the Breakpoints tree model.
 *
 * @c Line is hidden by @ref LuaDebuggerBreakpointsController::configureColumns;
 * the visible-to-the-user order is therefore @c Active, @c Hits, @c Location.
 * @c Hits sits next to @c Active so the at-a-glance "is this breakpoint
 * armed and how close to firing" cue lives right next to the on/off
 * checkbox; @c Location stays the elastic last column. */
namespace BreakpointColumn
{
constexpr int Active = 0;
constexpr int Hits = 1;
constexpr int Line = 2;
constexpr int Location = 3;
constexpr int Count = 4;
} // namespace BreakpointColumn

/* ===== breakpoint_modes ===== */

/**
 * @brief Inline editor mode metadata for the Breakpoints "Location" column.
 *
 * The inline editor in @ref BreakpointInlineLineEdit is a single
 * @c QLineEdit reused across three editing modes (Expression / Hit Count /
 * Log Message). This translation unit owns the table that drives the
 * per-mode validator / placeholder / tooltip / auxiliary-control
 * visibility — the delegate stays focused on Qt @c QStyledItemDelegate
 * plumbing, the inline editor stays focused on geometry, and adding a
 * fourth mode is a single-row append to @c kBreakpointEditModes plus an
 * extension of @ref applyEditorMode and the delegate's commit/load
 * logic in @c setEditorData / @c setModelData.
 */
namespace LuaDbgBreakpointModes
{

enum class Mode : int
{
    Expression = 0,
    HitCount = 1,
    LogMessage = 2,
};

/** Mode-table row. The @c label / @c placeholder / @c valueTooltip strings
 *  are stored as raw UTF-8 and are translated on use via the
 *  @c BreakpointConditionDelegate context (see @ref translatedLabel and
 *  @ref applyEditorMode). */
struct ModeSpec
{
    Mode mode;
    const char *label;
    const char *placeholder;
    const char *valueTooltip;
};

/** Number of entries in @ref kBreakpointEditModes (compile-time constant). */
constexpr int kModeCount = 3;

/** Per-mode metadata table; index matches @ref Mode. */
extern const ModeSpec kBreakpointEditModes[kModeCount];

/** @c BreakpointConditionDelegate-context translation of @ref ModeSpec::label. */
QString translatedLabel(const ModeSpec &spec);

/** Property name of the per-mode draft text cache for @p m. The
 *  shared editor line edit is one widget across all three modes,
 *  so the user's typing under each mode is stashed on the editor
 *  via this property and restored when the mode is reactivated. */
const char *draftPropertyName(Mode m);

/** Hit-count comparison combo stashed on the editor by
 *  @ref LuaDbgBreakpointConditionDelegate::createEditor; @c nullptr if
 *  @p editor is null or the property has not been set. */
QComboBox *editorHitModeCombo(QWidget *editor);

/** "Also pause" toggle stashed on the editor by
 *  @ref LuaDbgBreakpointConditionDelegate::createEditor; @c nullptr if
 *  @p editor is null or the property has not been set. */
QToolButton *editorPauseToggle(QWidget *editor);

/** Switch the editor's line edit to display @p modeIndex's mode.
 *
 *  Called by the mode-combo @c currentIndexChanged signal and
 *  directly from @c setEditorData on the initial open. Saves the
 *  current line-edit text into the previous mode's draft slot,
 *  loads the new mode's draft into the line edit, applies the
 *  mode-specific validator / placeholder / tooltip, and toggles
 *  the visibility of the auxiliary controls. The line edit then
 *  re-runs its layout pass so the new auxiliary visibility is
 *  reflected in the text margins. */
void applyEditorMode(QWidget *editor, int modeIndex);

/** Build a palette-aware "also pause" icon with separate Off / On
 *  variants. The toggled state is signalled by:
 *
 *   - @c QIcon::Off : two solid pause bars in the palette's
 *     @c ButtonText color, on a transparent background. The
 *     @c QToolButton's background stylesheet is also transparent
 *     in this state, so the cell shows the bars on the cell's
 *     own background.
 *   - @c QIcon::On  : two solid bars in @c HighlightedText (white).
 *     The bars sit on top of the @c QToolButton's checked-state
 *     stylesheet background — a rounded @c Highlight-color chip
 *     that fills the whole button, not just the 16×16 icon. */
QIcon makePauseIcon(const QPalette &palette);

/** Stylesheet for the breakpoint-editor pause toggle: transparent
 *  when unchecked, filled rounded @c Highlight chip when checked. */
QString pauseToggleStyleSheet();

} // namespace LuaDbgBreakpointModes

/* ===== breakpoint_inline_editor ===== */

/**
 * @brief Inline editor for the Breakpoints "Location" column.
 *
 * The editor IS a @c QLineEdit, exactly like the Watch tree's editor — same
 * widget class, same parent chain (direct child of the view's viewport),
 * same native rendering on every platform. This is what makes the
 * Breakpoint edit field render at @c QLineEdit::sizeHint() height with the
 * platform's native frame, focus ring, padding and selection colours,
 * pixel-identical to the Watch edit field.
 *
 * The earlier implementation wrapped the line edit inside
 * @c QStackedWidget inside @c QHBoxLayout inside a wrapper @c QWidget;
 * with that nesting the layout sized the @c QLineEdit to whatever the
 * row was (never to its own natural sizeHint), so on macOS the
 * @c QMacStyle frame painter drew a much shorter line edit than the
 * Watch tree's bare @c QLineEdit, even when the row itself was the same
 * height. Embedding the auxiliary controls as children of the
 * @c QLineEdit and reserving space with @c setTextMargins() lets the line
 * edit be the editor while keeping sizing consistent with the Watch tree.
 *
 * The mode combo lives on the left edge; the hit-count comparison combo
 * and the "also pause" toggle live on the right edge, hidden by
 * default and shown only for the modes that own them. Caller
 * (@ref LuaDbgBreakpointConditionDelegate::createEditor) wires up the
 * mode-change behaviour, the focus / commit logic and the model
 * read/write; this class is intentionally only responsible for the
 * geometry of the embedded widgets and the corresponding text margins.
 */
class BreakpointInlineLineEdit : public QLineEdit
{
  public:
    explicit BreakpointInlineLineEdit(QWidget *parent = nullptr);

    /** Hand the editor its three embedded widgets (already parented to
     *  @c this by the caller) so it can reserve text-margin space for
     *  them and reposition them on every resize. */
    void setEmbeddedWidgets(QComboBox *modeCombo, QComboBox *hitModeCombo, QToolButton *pauseButton);

    /** Re-run the geometry pass — call after toggling the visibility of
     *  any embedded widget so the text margins (and therefore the
     *  caret-claim area) follow.
     *
     *  Bails out when the editor has no real width yet (called e.g. from
     *  @c setEmbeddedWidgets or the mode-applier before @c QAbstractItemView
     *  has placed us in the cell): with width()==0 every right-anchored
     *  widget would land at a negative x. The first real layout pass
     *  happens via @c resizeEvent once the view sets our geometry, and a
     *  final pass via @c showEvent picks up any visibility changes that
     *  landed after that. */
    void relayout();

  protected:
    void resizeEvent(QResizeEvent *e) override;
    void showEvent(QShowEvent *e) override;
    void paintEvent(QPaintEvent *e) override;

  private:
    QComboBox *modeCombo_ = nullptr;
    QComboBox *hitModeCombo_ = nullptr;
    QToolButton *pauseButton_ = nullptr;
};

/* ===== breakpoint_delegate ===== */

/**
 * @brief Item delegate for the Breakpoints list Location column (condition /
 *        hit count / log message inline editor).
 *
 * The editor is a single @c QLineEdit configured per-mode by a small
 * mode-picker combo on the left. A hit-count comparison combo and an
 * "also pause" toggle are embedded as children of the line edit and are
 * shown only for the modes that own them. See the implementation file
 * for the full design rationale.
 */
class LuaDbgBreakpointConditionDelegate : public QStyledItemDelegate
{
  public:
    explicit LuaDbgBreakpointConditionDelegate(LuaDebuggerDialog *dialog);

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override;
    void setEditorData(QWidget *editor, const QModelIndex &index) const override;
    void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index) const override;
    void updateEditorGeometry(QWidget *editor, const QStyleOptionViewItem &option,
                              const QModelIndex &index) const override;
    QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override;

  protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

  private:
    /** Lazily-cached preferred row height matching @c QLineEdit::sizeHint. */
    int preferredEditorHeight() const;
    mutable int cachedPreferredHeight_ = 0;
};

/* ===== breakpoints_controller ===== */

/**
 * @brief Owns the breakpoints panel: tree wiring, model rebuild from the
 *        engine, inline edit dispatch, header strip controls, gutter menu,
 *        and persistence.
 *
 * The dialog only constructs the underlying widgets (model, tree, header
 * buttons, action) and hands them to this controller via @ref attach and
 * @ref attachHeaderButtons; from there every breakpoint-related slot,
 * mutation, and chrome update lives here.
 */
class LuaDebuggerBreakpointsController : public QObject
{
    Q_OBJECT

  public:
    explicit LuaDebuggerBreakpointsController(LuaDebuggerDialog *host);

    /** @brief Bind the tree + model and wire their signals. */
    void attach(QTreeView *tree, QStandardItemModel *model);

    /** @brief Bind the section-header strip and its shortcut action.
     *  Wires button clicks; safe to call before or after @ref attach. */
    void attachHeaderButtons(QToolButton *breakOnError, QToolButton *toggleAll, QToolButton *remove,
                             QToolButton *removeAll, QToolButton *edit, QAction *removeAllAction);

    void configureColumns() const;

    /** @brief Focus column 2 and open the delegate editor when editable. */
    void startInlineEdit(int row);

    /** @brief Snapshot the engine breakpoint list (file/line/active +
     *  condition / hit-count / log-message) into @p settingsMap under the
     *  @c Breakpoints key. Every per-breakpoint field is written so the JSON
     *  is fully self-describing. */
    void serializeTo(QVariantMap &settingsMap) const;

    /** @brief Apply the @c Breakpoints array from @p settingsMap to the engine.
     *  Missing keys fall back to the engine's defaults; an unknown hit-count
     *  mode collapses to the default @c FROM. */
    void restoreFrom(const QVariantMap &settingsMap);

    /** @brief Rebuild tree rows from the engine; refreshes header chrome. */
    void refreshFromEngine();

    /** @brief Confirm-and-clear all breakpoints (header / shortcut). */
    void clearAll();

    /**
     * @brief Add the breakpoint at @p file:@p line if absent, otherwise
     *        remove it. Drives F9 in the editor, the editor right-click
     *        @c "Add Breakpoint" / @c "Remove Breakpoint" actions, and the
     *        gutter plain-click. Adding auto-enables the debugger via
     *        @ref LuaDebuggerDialog::ensureDebuggerEnabledForActiveBreakpoints
     *        (so a fresh row is immediately effective); removing refreshes
     *        the chrome to reflect the (possibly empty) breakpoint set.
     *        Always rebuilds the breakpoint table and gutter markers.
     */
    void toggleAtLine(const QString &file, qint32 line);

    /**
     * @brief Convenience overload that resolves the file path from a
     *        @ref LuaDebuggerCodeView. Silently ignores null views or
     *        sub-1 line numbers; otherwise behaves exactly like
     *        @ref toggleAtLine.
     */
    void toggleOnCodeViewLine(LuaDebuggerCodeView *codeView, qint32 line);

    /**
     * @brief Pre-arm a breakpoint at @p file:@p line — the @c Shift+click
     *        gutter gesture. If absent, creates the breakpoint inactive so
     *        the user can arm a line without paying the line-hook cost
     *        until they activate it; if present, flips the active flag.
     *        Does NOT auto-enable the debugger (that pairs with the F9
     *        active-add path; pre-arm should never silently turn debugging
     *        back on). Always rebuilds the breakpoint table and gutter
     *        markers.
     */
    void shiftToggleAtLine(const QString &file, qint32 line);

    /**
     * @brief Set the active flag of an existing breakpoint at @p file:@p line.
     *        Used by the gutter context menu's @c Enable/Disable action;
     *        auto-enables the debugger when transitioning to active so the
     *        re-armed breakpoint is immediately effective. The breakpoint
     *        table's checkbox uses a different code path
     *        (@ref onItemChanged) on purpose — it must NOT touch the core
     *        enable state because that path is reachable during a live
     *        capture. Always rebuilds the breakpoint table and gutter
     *        markers.
     */
    void setActiveFromUser(const QString &file, qint32 line, bool active);

    /**
     * @brief Remove the breakpoint at @p file:@p line and refresh chrome.
     *        Drives the gutter context menu's @c Remove action. Always
     *        rebuilds the breakpoint table and gutter markers.
     */
    void removeAtLine(const QString &file, qint32 line);

    /**
     * @brief Move a breakpoint in @p file from @p fromLine to @p toLine,
     *        preserving metadata. No-op if either line is invalid, unchanged,
     *        source is absent, or destination is occupied.
     */
    void moveAtLine(const QString &file, qint32 fromLine, qint32 toLine);

    /** @brief Activate-all / deactivate-all toggle (header). */
    void toggleAllActive();

    /** @brief Refresh header dot icon + button enable states. */
    void updateHeaderButtonState();

    /** @brief Remove the breakpoints in the given (deduped) model rows. */
    bool removeRows(const QList<int> &rows);

    /** @brief Remove every selected breakpoint row.  */
    bool removeSelected();

  public slots:
    void onItemDoubleClicked(const QModelIndex &index);
    void showContextMenu(const QPoint &pos);
    /** @brief Active-checkbox toggle from the model. */
    void onItemChanged(QStandardItem *item);
    /** @brief Role-based dispatch for delegate-driven inline edits. */
    void onModelDataChanged(const QModelIndex &topLeft, const QModelIndex &bottomRight, const QVector<int> &roles);
    /** @brief Show Edit/Disable/Remove popup for a click in an editor gutter. */
    void showGutterMenu(const QString &filename, qint32 line, const QPoint &globalPos);

  private:
    /** @brief Repaint the breakpoint gutter on every open code tab. */
    void refreshAllOpenTabMarkers() const;
    /** @brief Repaint gutters only on tabs whose file is in @p files. */
    void refreshOpenTabMarkers(const QSet<QString> &files) const;

    LuaDebuggerDialog *host_ = nullptr;
    QTreeView *tree_ = nullptr;
    QStandardItemModel *model_ = nullptr;

    QToolButton *breakOnErrorButton_ = nullptr;
    QToolButton *toggleAllButton_ = nullptr;
    QToolButton *removeButton_ = nullptr;
    QToolButton *removeAllButton_ = nullptr;
    QToolButton *editButton_ = nullptr;
    QAction *removeAllAction_ = nullptr;

    /**
     * @brief Cached breakpoint header dot icons, indexed by
     *        @c LuaDbgBpHeaderIconMode (0..2). Recomputed lazily when the
     *        cache key (editor font + side + DPR) changes; without this the
     *        icon would be regenerated on every cursor move.
     */
    QIcon headerIconCache_[3];
    QString headerIconCacheKey_;

    /**
     * @brief True after the first @ref refreshFromEngine pass that ran with
     *        a non-empty engine breakpoint list. Subsequent rebuilds do not
     *        re-trigger the "open initial breakpoint files" auto-population.
     */
    bool tabsPrimed_ = false;

    /**
     * @brief Re-entrancy guard for the breakpoints model -> core mutation
     *        path. Set while @ref refreshFromEngine rebuilds rows from the
     *        engine; the role-based dispatch slots honour the guard so a
     *        programmatic @c setData during the rebuild does not loop back
     *        through @c set_breakpoint_*.
     */
    bool suppressItemChanged_ = false;
};

#endif
