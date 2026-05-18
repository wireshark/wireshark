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
class QPainter;
class QToolButton;
class QTreeView;
class QWidget;

namespace Ui
{
class LuaDebuggerDialog;
}

/* ===== from internal ===== */


/** Walk watch-tree items to the top-level row (same row family as WatchSpecRole root). */

/**
 * @brief Finds the root item of a QStandardItem hierarchy.
 *
 * @param item The starting item in the hierarchy.
 * @return The root item of the hierarchy.
 */
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

/**
 * @brief Record / clear root-level expansion for @p rootKey in @p map.
 *  Mutates @p map in place; collapsing a root with no remembered subpaths
 *  drops the entry entirely so the map stays minimal.
 *
 * @param map Reference to the hash map that stores the expansion state of tree sections.
 * @param rootKey The key representing the root section whose expansion state is to be recorded or cleared.
 * @param expanded Boolean indicating whether the root section should be expanded (true) or collapsed (false).
 */
void luaDbgRecordTreeSectionRootExpansion(QHash<QString, LuaDbgTreeSectionExpansionState> &map, const QString &rootKey,
                                          bool expanded);

/** @brief Add / remove one descendant subpath @p key under @p rootKey in @p map.
 *  Mirrors @ref luaDbgRecordTreeSectionRootExpansion: removing the last
 *  subpath of a collapsed root erases the root entry too.
 *
 * @param map Reference to the hash map that stores the expansion state of tree sections.
 * @param rootKey The root key under which the subpath is being expanded or collapsed.
 * @param key The subpath key to be added or removed.
 * @param expanded Boolean indicating whether the subpath is being expanded (true) or collapsed (false).
 */
void luaDbgRecordTreeSectionSubpathExpansion(QHash<QString, LuaDbgTreeSectionExpansionState> &map,
                                             const QString &rootKey, const QString &key, bool expanded);

/**
 * @brief Expanded-descendant subpaths recorded for @p rootKey, or empty.
 *
 * @param map Hash containing expansion states for LuaDbgTreeSection objects.
 * @param rootKey Key of the root section to retrieve expanded subpaths for.
 * @return QStringList List of expanded subpaths under the specified rootKey.
 */
QStringList luaDbgTreeSectionExpandedSubpaths(const QHash<QString, LuaDbgTreeSectionExpansionState> &map,
                                              const QString &rootKey);

/** Global personal config path — debugger settings are not profile-specific. */

/**
 * @brief Returns the file path for Lua debugger settings.
 *
 * @return QString The file path for Lua debugger settings.
 */
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

/**
 * @brief Build a key sequence from a key event for matching against
 *  @c QAction shortcuts. Wraps the Qt5/Qt6 modifier-encoding split so callers
 *  do not have to repeat the version check.
 *
 * @param ke Pointer to the QKeyEvent object containing the key event information.
 * @return QKeySequence The constructed key sequence based on the key event.
 */
QKeySequence luaDbgSeqFromKeyEvent(const QKeyEvent *ke);

/* ===== from item_utils ===== */

namespace LuaDebuggerItems
{

/**
 * @brief Qt::DisplayRole text for column @p col in the same row as @p indexInRow.
 * @param indexInRow The index of the row to query.
 * @param col The column to query.
 * @return The display text for the specified cell.
 */
inline QString rowColumnDisplayText(const QModelIndex &indexInRow, int col)
{
    if (!indexInRow.isValid())
    {
        return QString();
    }
    return indexInRow.sibling(indexInRow.row(), col).data(Qt::DisplayRole).toString();
}

/**
 * @brief Column-0 item for the same row as @p cell.
 * @param model The standard item model.
 * @param cell The cell for which to find the column-0 item.
 * @return The column-0 item for the same row as @p cell.
 */
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

/**
 * @brief Cell in column @p col for a row whose column-0 anchor is @p col0.
 * @param model The standard item model.
 * @param col0 The column-0 item for the row.
 * @param col The column to query.
 * @return The cell for the specified column.
 */
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

/**
 * @brief Return the text for a cell in column @p col for a row whose column-0 anchor is @p col0.
 * @param model The standard item model.
 * @param col0 The column-0 item for the row.
 * @param col The column to query.
 * @return The text for the specified cell.
 */
inline QString text(QStandardItemModel *model, QStandardItem *col0, int col)
{
    QStandardItem *c = cellAt(model, col0, col);
    return c ? c->text() : QString();
}

/**
 * @brief Set the text for a cell in column @p col for a row whose column-0 anchor is @p col0.
 * @param model The standard item model.
 * @param col0 The column-0 item for the row.
 * @param col The column to set.
 * @param t The text to set for the specified cell.
 */
inline void setText(QStandardItemModel *model, QStandardItem *col0, int col, const QString &t)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setText(t);
    }
}

/**
 * @brief Set the tool tip for a cell in column @p col for a row whose column-0 anchor is @p col0.
 * @param model The standard item model.
 * @param col0 The column-0 item for the row.
 * @param col The column to set.
 * @param tip The tool tip to set for the specified cell.
 */
inline void setToolTip(QStandardItemModel *model, QStandardItem *col0, int col, const QString &tip)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setToolTip(tip);
    }
}

/**
 * @brief Set the font for a cell in column @p col for a row whose column-0 anchor is @p col0.
 * @param model The standard item model.
 * @param col0 The column-0 item for the row.
 * @param col The column to set.
 * @param font The font to set for the specified cell.
 */
inline void setFont(QStandardItemModel *model, QStandardItem *col0, int col, const QFont &font)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setFont(font);
    }
}

/**
 * @brief Set the foreground brush for a cell in column @p col for a row whose column-0 anchor is @p col0.
 * @param model The standard item model.
 * @param col0 The column-0 item for the row.
 * @param col The column to set.
 * @param brush The foreground brush to set for the specified cell.
 */
inline void setForeground(QStandardItemModel *model, QStandardItem *col0, int col, const QBrush &brush)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setForeground(brush);
    }
}

/**
 * @brief Set the background brush for a cell in column @p col for a row whose column-0 anchor is @p col0.
 * @param model The standard item model.
 * @param col0 The column-0 item for the row.
 * @param col The column to set.
 * @param brush The background brush to set for the specified cell.
 */
inline void setBackground(QStandardItemModel *model, QStandardItem *col0, int col, const QBrush &brush)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setBackground(brush);
    }
}

/**
 * @brief Set the icon for a cell in column @p col for a row whose column-0 anchor is @p col0.
 * @param model The standard item model.
 * @param col0 The column-0 item for the row.
 * @param col The column to set.
 * @param icon The icon to set for the specified cell.
 */
inline void setIcon(QStandardItemModel *model, QStandardItem *col0, int col, const QIcon &icon)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setIcon(icon);
    }
}

/**
 * @brief Set the text alignment for a cell in column @p col for a row whose column-0 anchor is @p col0.
 * @param model The standard item model.
 * @param col0 The column-0 item for the row.
 * @param col The column to set.
 * @param align The text alignment to set for the specified cell.
 */
inline void setTextAlignment(QStandardItemModel *model, QStandardItem *col0, int col, Qt::Alignment align)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setTextAlignment(align);
    }
}

/**
 * @brief Check whether a cell in column @p col for a row whose column-0 anchor is @p col0 is expanded in the tree view.
 * @param model The standard item model.
 * @param col0 The column-0 item for the row.
 * @return The @c QModelIndex for @p col0, or an invalid index on failure.
 */
inline QModelIndex indexCol0(QStandardItemModel *model, QStandardItem *col0)
{
    if (!model || !col0 || col0->column() != 0)
    {
        return QModelIndex();
    }
    return model->indexFromItem(col0);
}

/**
 * @brief Check whether a cell in column @p col for a row whose column-0 anchor is @p col0 is expanded in the tree view.
 * @param model The standard item model.
 * @param col0 The column-0 item for the row.
 * @return true if the specified cell is expanded, false otherwise.
 */
inline bool isExpanded(QTreeView *tree, QStandardItemModel *model, QStandardItem *col0)
{
    const QModelIndex ix = indexCol0(model, col0);
    return ix.isValid() && tree->isExpanded(ix);
}

/**
 * @brief Set the expansion state for a cell in column @p col for a row whose column-0 anchor is @p col0.
 * @param tree The tree view to set expansion state.
 * @param model The standard item model.
 * @param col0 The column-0 item for the row.
 * @param expanded The expansion state to set for the specified cell.
 */
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

/**
 * @brief Return the foreground and background colors used to indicate an
 * invalid filter expression in the Lua debugger.
 *
 * @return A struct containing the foreground and background colors.
 */
LuaDbgInvalidFilterColors invalidFilterColors();

/**
 * @brief Check whether a watch specification is globally scoped.
 *
 * @param spec The watch specification string.
 * @return true if the specification is globally scoped, false otherwise.
 */
bool watchSpecIsGlobalScoped(const QString &spec);

/**
 * @brief Check whether a variables path is globally scoped.
 *
 * @param path The variables path string.
 * @return true if the path is globally scoped, false otherwise.
 */
bool variablesPathIsGlobalScoped(const QString &path);

/**
 * @brief Return the change key for a variable at a given stack level and path.
 *
 * @param stackLevel The stack level of the variable.
 * @param path       The path of the variable.
 * @return The change key string.
 */
QString changeKey(int stackLevel, const QString &path);

/**
 * @brief Return the watch specification corresponding to a change key.
 *
 * @param key The change key string.
 * @return The watch specification string.
 */
QString watchSpecFromChangeKey(const QString &key);

/**
 * @brief Strip the error prefix from a watch expression error string.
 *
 * @param errStr The error string to strip.
 * @return The error string with the watch expression error prefix removed.
 */
QString stripWatchExpressionErrorPrefix(const QString &errStr);

/**
 * @brief Determine whether a variable has changed based on its current and baseline values.
 * @param baseline The baseline map of variable values.
 * @param key The key for the variable to check.
 * @param newVal The new value for the variable.
 * @param flashNew Whether to flash the new value.
 * @return true if the variable has changed, false otherwise.
 */
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

/**
 * @brief Return the root key of the variable section containing an item.
 *
 * @param item The item in the variable tree.
 * @return The root key string of the variable section.
 */
QString variableSectionRootKeyFromItem(const QStandardItem *item);

/**
 * @brief Check whether a watch specification uses path resolution.
 *
 * @param spec The watch specification string.
 * @return true if the specification uses path resolution, false otherwise.
 */
bool watchSpecUsesPathResolution(const QString &spec);

/**
 * @brief Return the path of a child node in the variable tree.
 *
 * @param parentPath The path of the parent node.
 * @param nameText   The name of the child node.
 * @return The path of the child node.
 */
QString variableTreeChildPath(const QString &parentPath, const QString &nameText);

/**
 * @brief Return the subpath of a child node in an expression watch tree.
 *
 * @param parentSubpath The subpath of the parent node.
 * @param nameText      The name of the child node.
 * @return The subpath of the child node.
 */
QString expressionWatchChildSubpath(const QString &parentSubpath, const QString &nameText);

/**
 * @brief Check whether children of a variable node should be sorted by name.
 *
 * @param parentPath The path of the parent variable node.
 * @return true if children should be sorted by name, false otherwise.
 */
bool variableChildrenShouldSortByName(const QString &parentPath);

struct VariableRowFields
{
    QString name;
    QString value;
    QString type;
    bool canExpand = false;
    QString childPath;
};

/**
 * @brief Read the display fields of a variable row from a Lua variable.
 *
 * @param v          The Lua variable to read from.
 * @param parentPath The path of the parent variable node.
 * @return A @c VariableRowFields struct containing the display fields.
 */
VariableRowFields readVariableRowFields(const wslua_variable_t &v, const QString &parentPath);

/**
 * @brief Apply an expansion indicator to a variable row anchor item.
 *
 * @param anchor                 The anchor item in the variable tree.
 * @param canExpand              Whether the item can be expanded.
 * @param enabledOnlyPlaceholder Whether to use an enabled-only placeholder.
 * @param columnCount            The number of columns in the tree (default 3).
 */
void applyVariableExpansionIndicator(QStandardItem *anchor, bool canExpand, bool enabledOnlyPlaceholder,
                                     int columnCount = 3);

/**
 * @brief Return the variable path for a watch specification.
 *
 * @param spec The watch specification string.
 * @return The variable path string.
 */
QString watchVariablePathForSpec(const QString &spec);

/**
 * @brief Return the resolved variable path for a watch tooltip.
 *
 * @param spec The watch specification string.
 * @return The resolved variable path string for display in a tooltip.
 */
QString watchResolvedVariablePathForTooltip(const QString &spec);

/**
 * @brief Set the variable path role on a watch root row item from a
 * watch specification.
 *
 * @param row  The root row item.
 * @param spec The watch specification string.
 */
void watchRootSetVariablePathRoleFromSpec(QStandardItem *row, const QString &spec);

/**
 * @brief Return the origin suffix for a watch path tooltip.
 *
 * @param item The item in the watch tree.
 * @param spec The watch specification string.
 * @return The origin suffix string.
 */
QString watchPathOriginSuffix(const QStandardItem *item, const QString &spec);

/**
 * @brief Truncate a watch tooltip text string to a reasonable length.
 *
 * @param s The tooltip text string.
 * @return The capped tooltip text string.
 */
QString capWatchTooltipText(const QString &s);

/**
 * @brief Return the parent key of a watch path.
 *
 * @param path The watch path string.
 * @return The parent key string.
 */
QString watchPathParentKey(const QString &path);

/**
 * @brief Apply the raw value and type text to a watch child row item.
 *
 * @param specItem The watch specification item.
 * @param rawVal   The raw value string.
 * @param typeText The type text string.
 */
void applyWatchChildRowTextAndTooltip(QStandardItem *specItem, const QString &rawVal, const QString &typeText);

/**
 * @brief Return the number of subpath boundaries in a watch subpath.
 *
 * @param subpath The watch subpath string.
 * @return The number of subpath boundaries.
 */
int watchSubpathBoundaryCount(const QString &subpath);

/**
 * @brief Find a watch item in a subtree by its subpath or path key.
 *
 * @param subtree The root item of the subtree to search.
 * @param key     The subpath or path key to search for.
 * @return The matching item, or nullptr if not found.
 */
QStandardItem *findWatchItemBySubpathOrPathKey(QStandardItem *subtree, const QString &key);

/**
 * @brief Find a variable tree item in a subtree by its path key.
 *
 * @param subtree The root item of the subtree to search.
 * @param key     The path key to search for.
 * @return The matching item, or nullptr if not found.
 */
QStandardItem *findVariableTreeItemByPathKey(QStandardItem *subtree, const QString &key);

using TreePathKeyFinder = QStandardItem *(*)(QStandardItem *, const QString &);

/**
 * @brief Re-expand previously expanded descendants of a subtree by their
 * path keys.
 *
 * @param tree      The tree view.
 * @param model     The tree model.
 * @param subtree   The root item of the subtree to re-expand.
 * @param pathKeys  The list of path keys to re-expand.
 * @param findByKey The function to find an item by path key.
 */
void reexpandTreeDescendantsByPathKeys(QTreeView *tree, QStandardItemModel *model, QStandardItem *subtree,
                                       QStringList pathKeys, TreePathKeyFinder findByKey);

/**
 * @brief Re-expand previously expanded watch descendants of a subtree by
 * their path keys.
 *
 * @param tree     The tree view.
 * @param model    The tree model.
 * @param subtree  The root item of the subtree to re-expand.
 * @param pathKeys The list of path keys to re-expand.
 */
void reexpandWatchDescendantsByPathKeys(QTreeView *tree, QStandardItemModel *model, QStandardItem *subtree,
                                        QStringList pathKeys);

/**
 * @brief Clear the filter error chrome from a watch specification item.
 *
 * @param specItem The watch specification item.
 * @param tree     The tree view.
 */
void clearWatchFilterErrorChrome(QStandardItem *specItem, QTreeView *tree);

/**
 * @brief Apply filter error chrome to a watch specification item.
 *
 * @param specItem The watch specification item.
 * @param tree     The tree view.
 */
void applyWatchFilterErrorChrome(QStandardItem *specItem, QTreeView *tree);

/**
 * @brief Set up a watch root item from a watch specification.
 *
 * @param specItem  The watch specification item.
 * @param valueItem The watch value item.
 * @param spec      The watch specification string.
 */
void setupWatchRootItemFromSpec(QStandardItem *specItem, QStandardItem *valueItem, const QString &spec);

/**
 * @brief Find a variable item by path in a subtree, searching recursively.
 *
 * @param node The root item of the subtree to search.
 * @param path The path to search for.
 * @return The matching item, or nullptr if not found.
 */
QStandardItem *findVariableItemByPathRecursive(QStandardItem *node, const QString &path);

/**
 * @brief Return the expansion key for a watch item.
 *
 * @param item The watch item.
 * @return The expansion key string used to restore expansion state.
 */
QString watchItemExpansionKey(const QStandardItem *item);

} // namespace LuaDebuggerPath

/* ===== from header_styles ===== */

/**
 * @brief Create a selection-aware icon for tree icons (breakpoints, variables,
 * and watch) that applies a selected-row tint.
 *
 * @param base    The base icon to tint.
 * @param palette The palette to derive the selection tint from.
 * @return A @c QIcon that applies a tint when the row is selected.
 */
QIcon luaDbgMakeSelectionAwareIcon(const QIcon &base, const QPalette &palette);


/**
 * @brief Paint a glyph centred into a square pixmap and return it as an icon.
 *
 * Paints @p glyph centred into a square @p side x @p side pixmap (scaled by
 * @p dpr for HiDPI), sized so the glyph's inked extent fills the cell.
 *
 * @param glyph    The glyph string to paint.
 * @param side     The side length of the square pixmap in pixels.
 * @param dpr      The device pixel ratio for HiDPI scaling.
 * @param baseFont The font to use for painting the glyph.
 * @param color    The color to paint the glyph with.
 * @param margin   The margin around the glyph in pixels (default 1).
 * @return A @c QIcon containing the painted glyph.
 */
QIcon luaDbgPaintedGlyphIcon(const QString &glyph, int side, qreal dpr,
                             const QFont &baseFont, const QColor &color,
                             int margin = 1);

/**
 * @brief Creates an icon for a painted glyph button.
 *
 * Returns a header-button-flavoured QIcon with two pixmaps painted from
 *  @p glyph: a Normal pixmap in @c palette.color(Active, ButtonText) and
 *  a Disabled pixmap in @c palette.color(Disabled, ButtonText). The
 *  Disabled pixmap is added so QToolButton renders it directly when the
 *  button is disabled instead of falling back to QStyle::generatedIcon-
 *  Pixmap()'s synthesised filter (which on Linux produces a darker tone
 *  than the palette's disabled-text gray used by neighbouring text-only
 *  buttons).
 *
 * @param glyph The glyph to be displayed on the button.
 * @param side The size of the icon in pixels.
 * @param dpr The device pixel ratio.
 * @param baseFont The base font for rendering the glyph.
 * @param palette The color palette to use for rendering the glyph.
 * @param margin The margin around the glyph.
 * @return QIcon The created icon with both active and disabled states.
 */
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

/**
 * @brief Draws a breakpoint dot on the given painter.
 *
 * @param painter The QPainter object to draw on.
 * @param dotLeft The left coordinate of the dot.
 * @param dotTop The top coordinate of the dot.
 * @param radius The radius of the dot.
 * @param enabled Whether the breakpoint is enabled.
 * @param hasExtras Whether the dot has additional extras.
 * @param alpha The transparency level of the dot.
 */
void luaDbgDrawBreakpointDot(QPainter &painter, qreal dotLeft, qreal dotTop, qreal radius, bool enabled,
                             bool hasExtras = false, int alpha = 255);

enum class LuaDbgBpHeaderIconMode
{
    NoBreakpoints,
    ActivateAll,
    DeactivateAll,
};

/**
 * @brief Return the appropriate breakpoint header icon for the given mode.
 *
 * @param editorFont The font used in the editor.
 * @param mode       The breakpoint header icon mode.
 * @param headerSide The side length of the header icon in pixels.
 * @param dpr        The device pixel ratio for HiDPI scaling.
 * @return A @c QIcon for the breakpoint header in the given mode.
 */
QIcon luaDbgBreakpointHeaderIconForMode(const QFont *editorFont, LuaDbgBpHeaderIconMode mode, int headerSide,
                                        qreal dpr);

/**
 * @brief Style a Lua debugger header breakpoint toggle button.
 *
 * @param btn  The tool button to style.
 * @param side The side length of the button in pixels.
 */
void styleLuaDebuggerHeaderBreakpointToggleButton(QToolButton *btn, int side);

/**
 * @brief Style a Lua debugger header button with fitted text glyphs.
 *
 * @param btn       The tool button to style.
 * @param side      The side length of the button in pixels.
 * @param titleFont The font used for sizing the glyphs.
 * @param glyphs    The list of glyph strings to fit within the button.
 */
void styleLuaDebuggerHeaderFittedTextButton(QToolButton *btn, int side, const QFont &titleFont,
                                            const QStringList &glyphs);

/**
 * @brief Style a Lua debugger header plus/minus button.
 *
 * @param btn       The tool button to style.
 * @param side      The side length of the button in pixels.
 * @param titleFont The font used for sizing the plus/minus glyph.
 */
void styleLuaDebuggerHeaderPlusMinusButton(QToolButton *btn, int side, const QFont &titleFont);

/**
 * @brief Style a Lua debugger header icon-only button.
 *
 * @param btn  The tool button to style.
 * @param side The side length of the button in pixels.
 */
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
    /**
     * @brief Constructs a LuaDebuggerKeyRouter with a pointer to the host dialog.
     * @param host Pointer to the LuaDebuggerDialog that owns this key router.
     */
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
    /**
     * @brief Constructs a default LuaDebuggerChangeHighlightTracker.
     */
    LuaDebuggerChangeHighlightTracker() = default;

    /**
     * @brief Refreshes the brushes used for changed values based on the application palette.
     * @param watchTree Pointer to the watch tree view to derive palette properties from.
     * @param paletteFallback Pointer to a fallback widget to use if watchTree is unavailable.
     */
    void refreshChangedValueBrushes(QTreeView *watchTree, QWidget *paletteFallback);

    /**
     * @brief Snapshots the current values to baseline on a new pause entry.
     */
    void snapshotBaselinesOnPauseEntry();

    /**
     * @brief Updates the identity of the current frame on pause entry.
     */
    void updatePauseEntryFrameIdentity();

    /**
     * @brief Sets the stack level for the pause entry.
     * @param level The stack level to set.
     */
    void setPauseEntryStackLevel(int level) { pauseEntryStackLevel_ = level; }

    /**
     * @brief Toggle the pause-entry refresh flag. The dialog turns it on
     *  for the duration of the pause-entry refresh sequence (so changed
     *  rows get the one-shot row flash on top of the persistent bold
     *  accent) and off again afterwards.
     * @param active True to enable the pause-entry refresh state, false to disable.
     */
    void setPauseEntryRefresh(bool active) { isPauseEntryRefresh_ = active; }

    /**
     * @brief Stamp the @p anchor row with the change visuals; @ref
     *  isPauseEntryRefresh_ is consulted internally so callers no longer
     *  have to thread it through.
     *  @param timerOwner Receives flash-clear timers.
     *  @param anchor     Any cell in the row to stamp; the helper walks
     *                    sibling cells in the same row.
     *  @param changed    True if the value differs from baseline (typically
     *                    obtained from one of the @c observe* helpers).
     */
    void applyChangedVisuals(QObject *timerOwner, QStandardItem *anchor, bool changed);

    /**
     * @brief Clears all change baselines for watches and variables.
     */
    void clearAllChangeBaselines();

    /**
     * @brief Wipe watch-side baselines (root + child value maps and
     *  visited-parent sets). Variables-tree maps are kept; they are not
     *  tied to watch specs and remain valid across watch list rebuilds.
     */
    void clearWatchBaselines();

    /**
     * @brief Clears change baselines for a specific watch specification.
     * @param spec The watch specification to clear baselines for.
     */
    void clearChangeBaselinesForWatchSpec(const QString &spec);

    /**
     * @brief Prunes baselines to keep only those present in the live watch specs.
     * @param watchModel Pointer to the current watch model containing live specs.
     */
    void pruneChangeBaselinesToLiveWatchSpecs(QStandardItemModel *watchModel);

    /**
     * @brief Checks if change highlighting is allowed for a given stack level.
     * @param stackSelectionLevel The stack level currently selected.
     * @return True if highlights are allowed, false otherwise.
     */
    bool changeHighlightAllowed(int stackSelectionLevel) const;

    /**
     * @brief Record the latest @p value for a watch root keyed by the
     *  composite @p rootKey. Returns @c true if the new value differs from
     *  the previous baseline (a brand-new row never reads as changed).
     * @param rootKey The composite key identifying the watch root.
     * @param value The current string value.
     * @return True if the value differs from baseline, false otherwise.
     */
    bool observeWatchRootValue(const QString &rootKey, const QString &value);

    /**
     * @brief Record @p parentPath as a visited parent in the watch-child
     *  visited-parents set keyed by @p rootKey. Returns @c true if the same
     *  parent was visited at the previous pause; @c false on first-time
     *  expansion. Used as the @c flashNew gate for child rows.
     * @param rootKey The composite key identifying the watch root.
     * @param parentPath The path of the parent to observe.
     * @return True if the parent was visited in the previous baseline, false otherwise.
     */
    bool observeWatchChildParent(const QString &rootKey, const QString &parentPath);

    /**
     * @brief Record the latest @p value for a watch-child row at
     *  @p rootKey/@p childPath. @p parentVisited is the result of
     *  @ref observeWatchChildParent for the matching parent and gates the
     *  "child appeared since last pause" branch.
     * @param rootKey The composite key identifying the watch root.
     * @param childPath The path of the child value.
     * @param value The current string value.
     * @param parentVisited True if the parent was previously visited.
     * @return True if the child value changed or newly appeared, false otherwise.
     */
    bool observeWatchChildValue(const QString &rootKey, const QString &childPath, const QString &value,
                                bool parentVisited);

    /**
     * @brief Variables-tree counterpart to @ref observeWatchChildParent.
     * @param parentKey The key of the variables tree parent.
     * @return True if the parent was visited in the previous baseline, false otherwise.
     */
    bool observeVariablesParent(const QString &parentKey);

    /**
     * @brief Variables-tree counterpart to @ref observeWatchChildValue.
     * @param variablesKey The key identifying the variable.
     * @param value The current string value.
     * @param parentVisited True if the parent was previously visited.
     * @return True if the variable value changed or newly appeared, false otherwise.
     */
    bool observeVariablesValue(const QString &variablesKey, const QString &value, bool parentVisited);

  private:
    /** Baseline values for watch roots, keyed by rootKey. */
    QHash<QString /* rootKey */, QString> watchRootBaseline_;

    /** Current values for watch roots, keyed by rootKey. */
    QHash<QString /* rootKey */, QString> watchRootCurrent_;

    /** Baseline values for watch children, keyed by rootKey and childPath. */
    QHash<QString /* rootKey */, QHash<QString /* childPath */, QString>> watchChildBaseline_;

    /** Current values for watch children, keyed by rootKey and childPath. */
    QHash<QString /* rootKey */, QHash<QString /* childPath */, QString>> watchChildCurrent_;

    /** Baseline values for variables, keyed by variablesKey. */
    QHash<QString /* variablesKey */, QString> variablesBaseline_;

    /** Current values for variables, keyed by variablesKey. */
    QHash<QString /* variablesKey */, QString> variablesCurrent_;

    /** Visited parents in the variables tree baseline. */
    QSet<QString /* variablesKey of parent */> variablesBaselineParents_;

    /** Visited parents in the variables tree currently. */
    QSet<QString /* variablesKey of parent */> variablesCurrentParents_;

    /** Visited parents in the watch child tree baseline, keyed by rootKey. */
    QHash<QString /* rootKey */, QSet<QString /* parentPath */>> watchChildBaselineParents_;

    /** Visited parents in the watch child tree currently, keyed by rootKey. */
    QHash<QString /* rootKey */, QSet<QString /* parentPath */>> watchChildCurrentParents_;

    /** Brush used to accent changed values persistently. */
    QBrush changedValueBrush_;

    /** Brush used for the momentary flash effect on changed values. */
    QBrush changedFlashBrush_;

    /** Flag indicating if a pause-entry refresh sequence is active. */
    bool isPauseEntryRefresh_ = false;

    /** Serial number for flash timers to prevent stale clear events. */
    qint32 flashSerial_ = 0;

    /** The stack level recorded at the moment of pause entry. */
    int pauseEntryStackLevel_ = 0;

    /** The identity of frame 0 at pause entry, used to detect frame changes. */
    QString pauseEntryFrame0Identity_;

    /** True if the current frame 0 identity matches the previous pause. */
    bool pauseEntryFrame0MatchesPrev_ = false;
};

#endif
