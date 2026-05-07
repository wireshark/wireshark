/* lua_debugger_utils.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Shared helpers used across the debugger panels.
 */

#ifndef LUA_DEBUGGER_UTILS_H
#define LUA_DEBUGGER_UTILS_H

#include <QBrush>
#include <QChar>
#include <QColor>
#include <QFont>
#include <QHash>
#include <QIcon>
#include <QKeySequence>
#include <QModelIndex>
#include <QSet>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QString>
#include <QStringList>
#include <QTreeView>
#include <QVariant>
#include <QtGlobal>

#include "epan/wslua/wslua_debugger.h"

class LuaDebuggerDialog;
class QFont;
class QKeyEvent;
class QObject;
class QPalette;
class QToolButton;
class QTreeView;
class QWidget;

namespace Ui
{
class LuaDebuggerDialog;
}

/* ===== from internal ===== */


/** Walk watch-tree items to the top-level row (same row family as WatchSpecRole root). */
inline QStandardItem *luaDbgWatchRootItem(QStandardItem *item)
{
    while (item && item->parent())
    {
        item = item->parent();
    }
    return item;
}

/** Runtime expansion state for Watch roots or Variables sections (not persisted). */
struct LuaDbgTreeSectionExpansionState
{
    bool rootExpanded = false;
    QStringList subpaths;
};

/** @brief Record / clear root-level expansion for @p rootKey in @p map.
 *  Mutates @p map in place; collapsing a root with no remembered subpaths
 *  drops the entry entirely so the map stays minimal. */
void luaDbgRecordTreeSectionRootExpansion(QHash<QString, LuaDbgTreeSectionExpansionState> &map, const QString &rootKey,
                                          bool expanded);

/** @brief Add / remove one descendant subpath @p key under @p rootKey in @p map.
 *  Mirrors @ref luaDbgRecordTreeSectionRootExpansion: removing the last
 *  subpath of a collapsed root erases the root entry too. */
void luaDbgRecordTreeSectionSubpathExpansion(QHash<QString, LuaDbgTreeSectionExpansionState> &map,
                                             const QString &rootKey, const QString &key, bool expanded);

/** @brief Expanded-descendant subpaths recorded for @p rootKey, or empty. */
QStringList luaDbgTreeSectionExpandedSubpaths(const QHash<QString, LuaDbgTreeSectionExpansionState> &map,
                                              const QString &rootKey);

/** Global personal config path — debugger settings are not profile-specific. */
QString luaDebuggerSettingsFilePath();

namespace LuaDebuggerSettingsKeys
{
constexpr const char *Theme = "theme";
/** Last toolbar "Enable debugger" checkbox state (persisted across dialog instances). */
constexpr const char *DebuggerEnabled = "debuggerEnabled";
constexpr const char *MainSplitter = "mainSplitterState";
constexpr const char *LeftSplitter = "leftSplitterState";
constexpr const char *EvalSplitter = "evalSplitterState";
constexpr const char *SectionVariables = "sectionVariables";
constexpr const char *SectionStack = "sectionStack";
constexpr const char *SectionFiles = "sectionFiles";
constexpr const char *SectionBreakpoints = "sectionBreakpoints";
constexpr const char *SectionEval = "sectionEval";
constexpr const char *SectionSettings = "sectionSettings";
constexpr const char *SectionWatch = "sectionWatch";
constexpr const char *Breakpoints = "breakpoints";
constexpr const char *Watches = "watches";
constexpr const char *BreakOnError = "breakOnError";
} // namespace LuaDebuggerSettingsKeys

// Tree widget UserRoles (must stay stable for persisted settings / model code).
constexpr qint32 FileTreePathRole = static_cast<qint32>(Qt::UserRole);
constexpr qint32 FileTreeIsDirectoryRole = static_cast<qint32>(Qt::UserRole + 1);
constexpr qint32 BreakpointFileRole = static_cast<qint32>(Qt::UserRole + 2);
constexpr qint32 BreakpointLineRole = static_cast<qint32>(Qt::UserRole + 3);
constexpr qint32 BreakpointConditionRole = static_cast<qint32>(Qt::UserRole + 30);
constexpr qint32 BreakpointHitCountRole = static_cast<qint32>(Qt::UserRole + 31);
constexpr qint32 BreakpointHitTargetRole = static_cast<qint32>(Qt::UserRole + 32);
constexpr qint32 BreakpointConditionErrRole = static_cast<qint32>(Qt::UserRole + 33);
constexpr qint32 BreakpointLogMessageRole = static_cast<qint32>(Qt::UserRole + 34);
constexpr qint32 BreakpointHitModeRole = static_cast<qint32>(Qt::UserRole + 35);
constexpr qint32 BreakpointLogAlsoPauseRole = static_cast<qint32>(Qt::UserRole + 36);
constexpr qint32 StackItemFileRole = static_cast<qint32>(Qt::UserRole + 4);
constexpr qint32 StackItemLineRole = static_cast<qint32>(Qt::UserRole + 5);
constexpr qint32 StackItemNavigableRole = static_cast<qint32>(Qt::UserRole + 6);
constexpr qint32 StackItemLevelRole = static_cast<qint32>(Qt::UserRole + 7);
constexpr qint32 VariablePathRole = static_cast<qint32>(Qt::UserRole + 8);
constexpr qint32 VariableTypeRole = static_cast<qint32>(Qt::UserRole + 9);
constexpr qint32 VariableCanExpandRole = static_cast<qint32>(Qt::UserRole + 10);
constexpr qint32 WatchSpecRole = static_cast<qint32>(Qt::UserRole + 11);
constexpr qint32 WatchSubpathRole = static_cast<qint32>(Qt::UserRole + 13);
constexpr qint32 WatchPendingNewRole = static_cast<qint32>(Qt::UserRole + 15);
constexpr qint32 ChangedFlashSerialRole = static_cast<qint32>(Qt::UserRole + 20);

constexpr qsizetype WATCH_TOOLTIP_MAX_CHARS = 4096;
constexpr int WATCH_EXPR_MAX_CHARS = 65536;
constexpr int CHANGED_FLASH_MS = 500;
constexpr int WATCH_PLACEHOLDER_DEFER_MS = 250;
constexpr QChar CHANGE_KEY_SEP = QChar(0x1F);

/** Maximum number of lines the Evaluate / logpoint output retains. */
constexpr int kLuaDbgEvalOutputMaxLines = 5000;

extern const QKeySequence kLuaDbgCtxGoToLine;
extern const QKeySequence kLuaDbgCtxRunToLine;
extern const QKeySequence kLuaDbgCtxWatchEdit;
extern const QKeySequence kLuaDbgCtxWatchCopyValue;
extern const QKeySequence kLuaDbgCtxWatchDuplicate;
extern const QKeySequence kLuaDbgCtxWatchRemoveAll;
extern const QKeySequence kLuaDbgCtxAddWatch;
extern const QKeySequence kLuaDbgCtxToggleBreakpoint;
extern const QKeySequence kLuaDbgCtxReloadLuaPlugins;
extern const QKeySequence kLuaDbgCtxRemoveAllBreakpoints;

/** @brief Build a key sequence from a key event for matching against
 *  @c QAction shortcuts. Wraps the Qt5/Qt6 modifier-encoding split so callers
 *  do not have to repeat the version check. */
QKeySequence luaDbgSeqFromKeyEvent(const QKeyEvent *ke);

/* ===== from item_utils ===== */

namespace LuaDebuggerItems
{

/** Qt::DisplayRole text for column @p col in the same row as @p indexInRow. */
inline QString rowColumnDisplayText(const QModelIndex &indexInRow, int col)
{
    if (!indexInRow.isValid())
    {
        return QString();
    }
    return indexInRow.sibling(indexInRow.row(), col).data(Qt::DisplayRole).toString();
}

/** Column-0 item for the same row as @p cell. */
inline QStandardItem *rowCol0(QStandardItemModel *model, QStandardItem *cell)
{
    if (!model || !cell)
    {
        return nullptr;
    }
    const QModelIndex ix = model->indexFromItem(cell);
    if (!ix.isValid())
    {
        return nullptr;
    }
    return model->itemFromIndex(ix.sibling(ix.row(), 0));
}

/** Cell in column @p col for a row whose column-0 anchor is @p col0. */
inline QStandardItem *cellAt(QStandardItemModel *model, QStandardItem *col0, int col)
{
    if (!model || !col0 || col0->column() != 0)
    {
        return nullptr;
    }
    QStandardItem *par = col0->parent();
    if (!par)
    {
        return model->item(col0->row(), col);
    }
    return par->child(col0->row(), col);
}

inline QString text(QStandardItemModel *model, QStandardItem *col0, int col)
{
    QStandardItem *c = cellAt(model, col0, col);
    return c ? c->text() : QString();
}

inline void setText(QStandardItemModel *model, QStandardItem *col0, int col, const QString &t)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setText(t);
    }
}

inline void setToolTip(QStandardItemModel *model, QStandardItem *col0, int col, const QString &tip)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setToolTip(tip);
    }
}

inline void setFont(QStandardItemModel *model, QStandardItem *col0, int col, const QFont &font)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setFont(font);
    }
}

inline void setForeground(QStandardItemModel *model, QStandardItem *col0, int col, const QBrush &brush)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setForeground(brush);
    }
}

inline void setBackground(QStandardItemModel *model, QStandardItem *col0, int col, const QBrush &brush)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setBackground(brush);
    }
}

inline void setIcon(QStandardItemModel *model, QStandardItem *col0, int col, const QIcon &icon)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setIcon(icon);
    }
}

inline void setTextAlignment(QStandardItemModel *model, QStandardItem *col0, int col, Qt::Alignment align)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setTextAlignment(align);
    }
}

inline QModelIndex indexCol0(QStandardItemModel *model, QStandardItem *col0)
{
    if (!model || !col0 || col0->column() != 0)
    {
        return QModelIndex();
    }
    return model->indexFromItem(col0);
}

inline bool isExpanded(QTreeView *tree, QStandardItemModel *model, QStandardItem *col0)
{
    const QModelIndex ix = indexCol0(model, col0);
    return ix.isValid() && tree->isExpanded(ix);
}

inline void setExpanded(QTreeView *tree, QStandardItemModel *model, QStandardItem *col0, bool expanded)
{
    const QModelIndex ix = indexCol0(model, col0);
    if (ix.isValid())
    {
        tree->setExpanded(ix, expanded);
    }
}

} // namespace LuaDebuggerItems

/* ===== from path_utils ===== */

namespace LuaDebuggerPath
{

struct LuaDbgInvalidFilterColors
{
    QColor fg;
    QColor bg;
};

LuaDbgInvalidFilterColors invalidFilterColors();

bool watchSpecIsGlobalScoped(const QString &spec);

bool variablesPathIsGlobalScoped(const QString &path);

QString changeKey(int stackLevel, const QString &path);

QString watchSpecFromChangeKey(const QString &key);

QString stripWatchExpressionErrorPrefix(const QString &errStr);

template <class Key, class Map>
bool shouldMarkChanged(const Map &baseline, const Key &key, const QString &newVal, bool flashNew = false)
{
    const auto it = baseline.constFind(key);
    if (it != baseline.constEnd())
    {
        return *it != newVal;
    }
    return flashNew && !baseline.isEmpty();
}

QString variableSectionRootKeyFromItem(const QStandardItem *item);

bool watchSpecUsesPathResolution(const QString &spec);

QString variableTreeChildPath(const QString &parentPath, const QString &nameText);

QString expressionWatchChildSubpath(const QString &parentSubpath, const QString &nameText);

bool variableChildrenShouldSortByName(const QString &parentPath);

struct VariableRowFields
{
    QString name;
    QString value;
    QString type;
    bool canExpand = false;
    QString childPath;
};

VariableRowFields readVariableRowFields(const wslua_variable_t &v, const QString &parentPath);

void applyVariableExpansionIndicator(QStandardItem *anchor, bool canExpand, bool enabledOnlyPlaceholder,
                                     int columnCount = 3);

QString watchVariablePathForSpec(const QString &spec);

QString watchResolvedVariablePathForTooltip(const QString &spec);

void watchRootSetVariablePathRoleFromSpec(QStandardItem *row, const QString &spec);

QString watchPathOriginSuffix(const QStandardItem *item, const QString &spec);

QString capWatchTooltipText(const QString &s);

QString watchPathParentKey(const QString &path);

void applyWatchChildRowTextAndTooltip(QStandardItem *specItem, const QString &rawVal, const QString &typeText);

int watchSubpathBoundaryCount(const QString &subpath);

QStandardItem *findWatchItemBySubpathOrPathKey(QStandardItem *subtree, const QString &key);

QStandardItem *findVariableTreeItemByPathKey(QStandardItem *subtree, const QString &key);

using TreePathKeyFinder = QStandardItem *(*)(QStandardItem *, const QString &);

void reexpandTreeDescendantsByPathKeys(QTreeView *tree, QStandardItemModel *model, QStandardItem *subtree,
                                       QStringList pathKeys, TreePathKeyFinder findByKey);

void reexpandWatchDescendantsByPathKeys(QTreeView *tree, QStandardItemModel *model, QStandardItem *subtree,
                                        QStringList pathKeys);

void clearWatchFilterErrorChrome(QStandardItem *specItem, QTreeView *tree);

void applyWatchFilterErrorChrome(QStandardItem *specItem, QTreeView *tree);

void setupWatchRootItemFromSpec(QStandardItem *specItem, QStandardItem *valueItem, const QString &spec);

QStandardItem *findVariableItemByPathRecursive(QStandardItem *node, const QString &path);

QString watchItemExpansionKey(const QStandardItem *item);

} // namespace LuaDebuggerPath

/* ===== from header_styles ===== */

/** Selected-row tint for tree icons (breakpoints / variables / watch). */
QIcon luaDbgMakeSelectionAwareIcon(const QIcon &base, const QPalette &palette);

/** Paints @p glyph centred into a square @p side x @p side pixmap (scaled by
 *  @p dpr for HiDPI), sized so the glyph's inked extent fills the cell, and
 *  returns it as a @c QIcon. */
QIcon luaDbgPaintedGlyphIcon(const QString &glyph, int side, qreal dpr,
                             const QFont &baseFont, const QColor &color,
                             int margin = 1);

/** Returns a header-button-flavoured QIcon with two pixmaps painted from
 *  @p glyph: a Normal pixmap in @c palette.color(Active, ButtonText) and
 *  a Disabled pixmap in @c palette.color(Disabled, ButtonText). The
 *  Disabled pixmap is added so QToolButton renders it directly when the
 *  button is disabled instead of falling back to QStyle::generatedIcon-
 *  Pixmap()'s synthesised filter (which on Linux produces a darker tone
 *  than the palette's disabled-text gray used by neighbouring text-only
 *  buttons). */
QIcon luaDbgPaintedGlyphButtonIcon(const QString &glyph, int side, qreal dpr,
                                   const QFont &baseFont, const QPalette &palette,
                                   int margin = 2);

/** Fullwidth ＋/－ and flat tool button style for section headers. */
extern const QString kLuaDbgHeaderPlus;
extern const QString kLuaDbgHeaderMinus;
/** Gear (U+2699 + U+FE0E text presentation) for the Edit Breakpoint
 *  header button. */
extern const QString kLuaDbgHeaderEdit;
/** Three stacked horizontal lines (U+2630 trigram for heaven) for the
 *  Active-column logpoint row indicator. */
extern const QString kLuaDbgRowLog;
/** Reference mark (U+203B) for the Active-column condition / hit-count
 *  row indicator. */
extern const QString kLuaDbgRowExtras;
/** Circled Latin capital letter X (U+24CD) for the Remove All header
 *  buttons (Watch and Breakpoints). */
extern const QString kLuaDbgHeaderRemoveAll;
extern const QString kLuaDbgHeaderToolButtonStyle;

enum class LuaDbgBpHeaderIconMode
{
    NoBreakpoints,
    ActivateAll,
    DeactivateAll,
};

QIcon luaDbgBreakpointHeaderIconForMode(const QFont *editorFont, LuaDbgBpHeaderIconMode mode, int headerSide,
                                        qreal dpr);

void styleLuaDebuggerHeaderBreakpointToggleButton(QToolButton *btn, int side);

void styleLuaDebuggerHeaderFittedTextButton(QToolButton *btn, int side, const QFont &titleFont,
                                            const QStringList &glyphs);

void styleLuaDebuggerHeaderPlusMinusButton(QToolButton *btn, int side, const QFont &titleFont);

void styleLuaDebuggerHeaderIconOnlyButton(QToolButton *btn, int side);

/**
 * @brief Build a colored Break-on-Error toggle icon for the breakpoints
 *        section header.
 *
 * Paints a warning-sign glyph, red (#DC3545) when checked (active),
 * gray (disabled text color) when unchecked.
 *
 * @param checked   true to paint yellow, false to paint gray
 * @param side      icon size in pixels
 * @param dpr       device pixel ratio
 * @param titleFont font to use for glyph rendering
 * @param palette   palette for disabled text color
 * @return colored warning-sign icon
 */
QIcon luaDbgErrorBreakHeaderIcon(bool checked, int side, qreal dpr,
                                 const QFont &titleFont, const QPalette &palette);

/* ===== from key_router ===== */

/**
 * @brief Centralised keyboard-shortcut dispatcher for the Lua debugger
 *        dialog's @c eventFilter().
 *
 * The debugger dialog observes key events delivered to any descendant
 * widget so it can:
 *   - Reserve shortcuts that overlap main-window actions before Qt
 *     dispatches them to the global QShortcutMap (see
 *     @ref reserveShortcutOverride).
 *   - Route subsequent KeyPress events to the right consumer:
 *     breakpoint deletion in the breakpoints tree, "toggle breakpoint"
 *     and "run to line" inside a focused code view, Esc / Ctrl+Q
 *     handling, and finally fall through to the dialog's own QActions
 *     for shortcuts that share a sequence with main-window actions
 *     (Ctrl+F / Ctrl+S / Ctrl+G / Ctrl+R / Ctrl+W).
 *
 * Lifetime: owned by the dialog; non-owning pointers to the dialog and
 * its Ui struct (and the breakpoints tree view) are passed via
 * @ref attach() once the @c setupUi() pass has finished.
 */
class LuaDebuggerKeyRouter
{
public:
    explicit LuaDebuggerKeyRouter(LuaDebuggerDialog *host);

    /** @brief Wire the router to the dialog's Ui struct and breakpoints
     *  tree. Must be called once, after @c setupUi() and the
     *  programmatic-widget construction in
     *  @ref LuaDebuggerDialog::buildAccordionUi. */
    void attach(Ui::LuaDebuggerDialog *ui, QTreeView *breakpointsTree);

    /** @brief Pre-empt a debugger-owned shortcut on
     *  @c QEvent::ShortcutOverride.
     *  @return @c true if @p ke matches a shortcut the dialog wants to
     *  claim from the main window; the caller should @c accept() the
     *  event and return @c false from its @c eventFilter so Qt
     *  re-delivers the same key as a KeyPress to this dialog. */
    bool reserveShortcutOverride(const QKeyEvent *ke) const;

    /** @brief Handle a @c QEvent::KeyPress delivered to the debugger UI.
     *  @return @c true if the event has been consumed (caller's
     *  @c eventFilter should return @c true); @c false to fall through
     *  to @c QDialog::eventFilter. */
    bool handleKeyPress(QObject *obj, const QKeyEvent *ke);

private:
    LuaDebuggerDialog *host_;
    Ui::LuaDebuggerDialog *ui_ = nullptr;
    QTreeView *breakpointsTree_ = nullptr;
};

/* ===== from change_tracker ===== */

/**
 * @brief "Value changed since last pause" highlighter for the Watch and
 *        Variables trees.
 *
 * Owns five related concerns:
 *
 *   - Baseline / current value maps for watch roots, watch children, and
 *     variables rows; rotated on pause entry via
 *     @ref snapshotBaselinesOnPauseEntry.
 *   - Visited-parent companion sets so a "first child appears under an
 *     already-visited parent" event reads as a real change instead of the
 *     more common "first-time expansion" case.
 *   - The "is this paint inside a pause-entry refresh?" gate that decides
 *     whether changes get the one-shot row-flash on top of the persistent
 *     bold-accent.
 *   - The frame-identity check (@ref pauseEntryFrame0MatchesPrev_) that
 *     suppresses the cue across calls / returns when the same numeric stack
 *     level points at a different Lua function than at the previous pause.
 *   - The accent + flash brushes themselves, derived from the active
 *     palette in @ref refreshChangedValueBrushes.
 *
 * Callers do not poke at the baseline / current hashes directly; the
 * @c observe* helpers update the current map and return whether the new
 * value differs from baseline (also taking the parent-visited gate into
 * account where appropriate). Then @ref applyChangedVisuals stamps the
 * row with the matching visuals using the current pause-entry flag.
 *
 * That contract intentionally hides @c isPauseEntryRefresh_ and the value
 * maps from the rest of the dialog so the controllers stay focused on
 * "which row, which value" instead of "which map, which gate".
 */
class LuaDebuggerChangeHighlightTracker
{
  public:
    LuaDebuggerChangeHighlightTracker() = default;

    void refreshChangedValueBrushes(QTreeView *watchTree, QWidget *paletteFallback);

    void snapshotBaselinesOnPauseEntry();

    void updatePauseEntryFrameIdentity();

    void setPauseEntryStackLevel(int level) { pauseEntryStackLevel_ = level; }

    /** @brief Toggle the pause-entry refresh flag. The dialog turns it on
     *  for the duration of the pause-entry refresh sequence (so changed
     *  rows get the one-shot row flash on top of the persistent bold
     *  accent) and off again afterwards.  */
    void setPauseEntryRefresh(bool active) { isPauseEntryRefresh_ = active; }

    /** @brief Stamp the @p anchor row with the change visuals; @ref
     *  isPauseEntryRefresh_ is consulted internally so callers no longer
     *  have to thread it through.
     *  @param timerOwner Receives flash-clear timers.
     *  @param anchor     Any cell in the row to stamp; the helper walks
     *                    sibling cells in the same row.
     *  @param changed    True if the value differs from baseline (typically
     *                    obtained from one of the @c observe* helpers). */
    void applyChangedVisuals(QObject *timerOwner, QStandardItem *anchor, bool changed);

    void clearAllChangeBaselines();

    /** @brief Wipe watch-side baselines (root + child value maps and
     *  visited-parent sets). Variables-tree maps are kept; they are not
     *  tied to watch specs and remain valid across watch list rebuilds. */
    void clearWatchBaselines();

    void clearChangeBaselinesForWatchSpec(const QString &spec);

    void pruneChangeBaselinesToLiveWatchSpecs(QStandardItemModel *watchModel);

    bool changeHighlightAllowed(int stackSelectionLevel) const;

    /** @brief Record the latest @p value for a watch root keyed by the
     *  composite @p rootKey. Returns @c true if the new value differs from
     *  the previous baseline (a brand-new row never reads as changed). */
    bool observeWatchRootValue(const QString &rootKey, const QString &value);

    /** @brief Record @p parentPath as a visited parent in the watch-child
     *  visited-parents set keyed by @p rootKey. Returns @c true if the same
     *  parent was visited at the previous pause; @c false on first-time
     *  expansion. Used as the @c flashNew gate for child rows. */
    bool observeWatchChildParent(const QString &rootKey, const QString &parentPath);

    /** @brief Record the latest @p value for a watch-child row at
     *  @p rootKey/@p childPath. @p parentVisited is the result of
     *  @ref observeWatchChildParent for the matching parent and gates the
     *  "child appeared since last pause" branch. */
    bool observeWatchChildValue(const QString &rootKey, const QString &childPath, const QString &value,
                                bool parentVisited);

    /** @brief Variables-tree counterpart to @ref observeWatchChildParent. */
    bool observeVariablesParent(const QString &parentKey);

    /** @brief Variables-tree counterpart to @ref observeWatchChildValue. */
    bool observeVariablesValue(const QString &variablesKey, const QString &value, bool parentVisited);

  private:
    QHash<QString /* rootKey */, QString> watchRootBaseline_;
    QHash<QString /* rootKey */, QString> watchRootCurrent_;
    QHash<QString /* rootKey */, QHash<QString /* childPath */, QString>> watchChildBaseline_;
    QHash<QString /* rootKey */, QHash<QString /* childPath */, QString>> watchChildCurrent_;
    QHash<QString /* variablesKey */, QString> variablesBaseline_;
    QHash<QString /* variablesKey */, QString> variablesCurrent_;

    QSet<QString /* variablesKey of parent */> variablesBaselineParents_;
    QSet<QString /* variablesKey of parent */> variablesCurrentParents_;
    QHash<QString /* rootKey */, QSet<QString /* parentPath */>> watchChildBaselineParents_;
    QHash<QString /* rootKey */, QSet<QString /* parentPath */>> watchChildCurrentParents_;

    QBrush changedValueBrush_;
    QBrush changedFlashBrush_;
    bool isPauseEntryRefresh_ = false;
    qint32 flashSerial_ = 0;
    int pauseEntryStackLevel_ = 0;
    QString pauseEntryFrame0Identity_;
    bool pauseEntryFrame0MatchesPrev_ = false;
};

#endif
