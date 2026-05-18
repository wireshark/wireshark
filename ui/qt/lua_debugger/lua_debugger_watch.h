/* lua_debugger_watch.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Watch panel: row model, drag-reorder tree, inline editor, presenter,
 * and the controller that orchestrates evaluation and persistence.
 */

#ifndef LUA_DEBUGGER_WATCH_H
#define LUA_DEBUGGER_WATCH_H

#include <QHash>
#include <QList>
#include <QModelIndex>
#include <QObject>
#include <QStandardItemModel>
#include <QString>
#include <QStringList>
#include <QStyledItemDelegate>
#include <QTreeView>
#include <QVariantMap>

#include <functional>

#include "lua_debugger_utils.h"

class LuaDebuggerChangeHighlightTracker;
class LuaDebuggerDialog;
class LuaDebuggerFontPolicy;
class QKeyEvent;
class QListView;
class QMouseEvent;
class QPoint;
class QStandardItem;
class QStandardItemModel;
class QToolButton;
class QTreeView;

/** @brief Column indices for the Watch tree model. */
namespace WatchColumn
{
constexpr int Spec = 0;
constexpr int Value = 1;
constexpr int Count = 2;
} // namespace WatchColumn

/* ===== watch_widgets ===== */

/**
 * @brief Model that routes drops to column 0 for watch reordering.
 */
class LuaDbgWatchItemModel : public QStandardItemModel
{
    Q_OBJECT

public:
    using QStandardItemModel::QStandardItemModel;

protected:
    /**
     * @brief Handles a drop event, forcing the target column to 0 to preserve watch item order.
     * @param data   The MIME data payload from the drag operation.
     * @param action The drop action being performed (e.g. move or copy).
     * @param row    The row at which the data is being dropped, or -1 to append.
     * @param column The requested target column; overridden to 0 internally.
     * @param parent The parent index under which the drop occurs.
     * @return True if the data was successfully handled, false otherwise.
     */
    bool dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column,
                      const QModelIndex &parent) override;
};

/**
 * @brief Watch tree: top-level reorder only; nested rows are not drop targets.
 */
class LuaDbgWatchTreeWidget : public QTreeView
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the watch tree widget.
     * @param fontPolicy Required so the tree can re-seat panel fonts after a
     *                   layout-changing drag-drop reorder.
     * @param parent     The QWidget parent.
     */
    LuaDbgWatchTreeWidget(LuaDebuggerFontPolicy *fontPolicy, QWidget *parent);

signals:
    /**
     * @brief Emitted on double-click on an empty tree area to insert a new pending row.
     */
    void requestNewRow();

    /**
     * @brief Emitted on Ctrl+Shift+K with at least one row present to confirm and clear all rows.
     */
    void requestRemoveAll();

    /**
     * @brief Emitted on Ctrl+Shift+C to request a value copy for the given item.
     * @param item  The item on which the shortcut was invoked (any row, top-level or child).
     * @param index The model index corresponding to @p item.
     */
    void requestCopyValue(QStandardItem *item, const QModelIndex &index);

    /**
     * @brief Emitted on Ctrl+Shift+D to request duplication of a top-level item.
     * @param item The top-level item to duplicate.
     */
    void requestDuplicateRoot(QStandardItem *item);

    /**
     * @brief Emitted on Delete or Backspace to remove the specified top-level rows.
     * @param items The list of top-level items to remove.
     */
    void requestDeleteRows(const QList<QStandardItem *> &items);

protected:
    /**
     * @brief Initiates a drag operation for top-level row reordering.
     * @param supportedActions The set of drop actions the drag source supports.
     */
    void startDrag(Qt::DropActions supportedActions) override;

    /**
     * @brief Validates and constrains drag-move events to top-level drop targets only.
     * @param event The drag move event to handle.
     */
    void dragMoveEvent(QDragMoveEvent *event) override;

    /**
     * @brief Handles drop events, restricting reordering to top-level rows.
     * @param event The drop event to handle.
     */
    void dropEvent(QDropEvent *event) override;

    /**
     * @brief Inserts a new pending row when the user double-clicks on empty space.
     * @param event The mouse double-click event to handle.
     */
    void mouseDoubleClickEvent(QMouseEvent *event) override;

    /**
     * @brief Handles watch-local keyboard shortcuts (remove-all, copy, duplicate, delete,
     *        inline edit). The dialog's ShortcutOverride filter still claims shortcuts that
     *        overlap main-window actions; this handler runs on KeyPress once Qt has
     *        dispatched the key to the focused widget.
     * @param event The key press event to handle.
     */
    void keyPressEvent(QKeyEvent *event) override;

private:
    /** @brief Font policy used to re-seat panel fonts after drag-drop reorders. */
    LuaDebuggerFontPolicy *fontPolicy_;
};

/**
 * @brief Variables tree: block inline editors on all columns.
 */
class LuaDbgVariablesReadOnlyDelegate : public QStyledItemDelegate
{
    Q_OBJECT

  public:
    /** @brief Inherit constructors from QStyledItemDelegate. */
    using QStyledItemDelegate::QStyledItemDelegate;

    /**
     * @brief Blocks editor creation by returning a null pointer.
     * @param parent The parent widget.
     * @param option The style option used for the item.
     * @param index The model index of the item.
     * @return nullptr to prevent editing.
     */
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const override;
};

/**
 * @brief Value column: elide middle; no editor.
 */
class LuaDbgWatchValueColumnDelegate : public QStyledItemDelegate
{
    Q_OBJECT

  public:
    /** @brief Inherit constructors from QStyledItemDelegate. */
    using QStyledItemDelegate::QStyledItemDelegate;

    /**
     * @brief Custom paint method to elide text in the middle.
     * @param painter The painter to use.
     * @param option The style option used for the item.
     * @param index The model index of the item.
     */
    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;

    /**
     * @brief Blocks editor creation by returning a null pointer.
     * @param parent The parent widget.
     * @param option The style option used for the item.
     * @param index The model index of the item.
     * @return nullptr to prevent editing.
     */
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const override;
};

/**
 * @brief Root watch cell: inline line edit for the expression column.
 */
class LuaDbgWatchRootDelegate : public QStyledItemDelegate
{
    Q_OBJECT

  public:
    /**
     * @brief Callback invoked from setModelData when the user finishes editing
     *  a top-level watch row's expression. The owner (the watch controller)
     *  decides how to persist or reject the new spec.
     */
    using CommitFn = std::function<void(QStandardItem *item, const QString &text)>;

    /**
     * @brief Constructs the root watch delegate.
     * @param tree The tree view the delegate operates on.
     * @param commit The commit callback function.
     * @param parent The parent object.
     */
    LuaDbgWatchRootDelegate(QTreeView *tree, CommitFn commit, QObject *parent = nullptr);

    /**
     * @brief Creates the inline line editor for the cell.
     * @param parent The parent widget.
     * @param option The style option used for the item.
     * @param index The model index of the item.
     * @return The created editor widget.
     */
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const override;

    /**
     * @brief Sets the data to be displayed and edited in the editor.
     * @param editor The editor widget.
     * @param index The model index of the item.
     */
    void setEditorData(QWidget *editor, const QModelIndex &index) const override;

    /**
     * @brief Saves the editor's data back to the model.
     * @param editor The editor widget.
     * @param model The data model.
     * @param index The model index of the item.
     */
    void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index) const override;

  private:
    QTreeView *tree_; /**< The tree view the delegate operates on. */
    CommitFn commit_; /**< The commit callback function. */
};

/* ===== watch_row_presenter ===== */

/**
 * @brief Per-row presentation for top-level Watch rows.
 *
 * Owns the icons / foreground / tooltip / change-highlight stamping
 * for each row state. Has no opinion about lazy-fill or expansion
 * tracking — those stay on @c LuaDebuggerWatchController, which calls
 * the matching @c apply* method after dispatching on liveness /
 * error / path-vs-expression.
 *
 * Construction takes only the immediate Qt collaborators plus the
 * change-highlight tracker, so the presenter can be exercised against
 * a stand-in model without spinning up an entire dialog.
 */
class LuaDebuggerWatchRowPresenter : public QObject
{
    Q_OBJECT

  public:
    /**
     * @param parent     Parent QObject; also receives one-shot flash timers
     *                   posted via @c LuaDebuggerChangeHighlightTracker.
     * @param tree       Watch tree (palette source).
     * @param model      Watch model (cell-data writes).
     * @param tracker    Owns baseline / current maps and the change-visuals
     *                   stamp. Borrowed reference, must outlive the presenter.
     */
    LuaDebuggerWatchRowPresenter(QObject *parent, QTreeView *tree, QStandardItemModel *model,
                                 LuaDebuggerChangeHighlightTracker &tracker);

    /** @brief Empty top-level row (no spec yet). */
    void applyEmpty(QStandardItem *item, const QString &muted, const QString &watchTipExtra);

    /** @brief Live context unavailable (debugger not paused). */
    void applyNoLiveContext(QStandardItem *item, const QString &muted, const QString &watchTipExtra);

    /** @brief Watch evaluation failed (path not found, expr error, etc.). */
    void applyError(QStandardItem *item, const QString &errStr, const QString &watchTipExtra);

    /** @brief Path-style watch root with a successful read. */
    void applySuccess(QStandardItem *item, const QString &spec, const char *val, const char *typ, bool can_expand,
                      const QString &watchTipExtra, int stackLevel, bool changeHighlightAllowed);

    /** @brief Expression-style watch root with a successful read. */
    void applyExpression(QStandardItem *item, const QString &spec, const char *val, const char *typ, bool can_expand,
                         const QString &watchTipExtra, int stackLevel, bool changeHighlightAllowed);

  private:
    QTreeView *tree_ = nullptr;
    QStandardItemModel *model_ = nullptr;
    LuaDebuggerChangeHighlightTracker *tracker_ = nullptr;
};

/* ===== watch_controller ===== */

/**
 * @brief Watch panel: column layout, expand/collapse tracking + lazy fill,
 *        runtime expansion-state map, and context menu. Inline edits to
 *        top-level rows enter via @ref commitWatchRootSpec, which the
 *        delegate calls through the commit callback set in @ref attach.
 */
class LuaDebuggerWatchController : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the watch controller bound to the given dialog host.
     * @param host The parent debugger dialog that owns this controller.
     */
    explicit LuaDebuggerWatchController(LuaDebuggerDialog *host);

    /**
     * @brief Bind the tree + model and wire all watch-internal signals
     *        (typed @ref LuaDbgWatchTreeWidget gestures, expand/collapse, context
     *        menu, inline-edit delegate, and the model/selection signals that
     *        drive the header buttons attached via @ref attachHeaderButtons).
     *        Cross-panel concerns (variables ↔ watch sync) stay with the dialog.
     * @param tree  The tree view to bind.
     * @param model The standard item model backing the tree.
     */
    void attach(QTreeView *tree, QStandardItemModel *model);

    /**
     * @brief Bind the section-header strip. Click signals are wired here;
     *        enable/disable state tracks the model and selection. Safe to call
     *        before or after @ref attach.
     * @param remove    The Remove Selected button.
     * @param removeAll The Remove All button.
     */
    void attachHeaderButtons(QToolButton *remove, QToolButton *removeAll);

    /**
     * @brief Configures column widths, resize modes, and visibility for the watch tree.
     */
    void configureColumns() const;

    /**
     * @brief Drop expansion-map entries for watch specs no longer in the tree.
     */
    void pruneExpansionMap();

    /**
     * @brief Re-expand persisted subpaths after refilling roots from settings.
     */
    void restoreExpansionState();

    /**
     * @brief Look up expanded descendant keys for @p rootSpec (may be empty).
     * @param rootSpec The canonical spec string of the root watch row to query.
     * @return List of expanded subpath strings under the given root spec.
     */
    QStringList expandedSubpathsForSpec(const QString &rootSpec) const;

    /**
     * @brief Re-query and replace all children of @p item.
     *        Used by the lazy-expand path and by @ref refreshBranch after pause / step.
     * @param item The parent item whose children are to be refilled.
     */
    void refillChildren(QStandardItem *item);

    /**
     * @brief Refresh value/type (and expansion affordances) for all watch roots,
     *        recursing into already-expanded branches. Safe to call when no watches
     *        exist or when the debugger is not paused (rows fall back to a muted placeholder).
     */
    void refreshDisplay();

    /**
     * @brief Re-evaluate one expanded branch depth-first; preserves the
     *        controller-tracked expansion state of nested rows. No-op when @p item
     *        is null or its branch is collapsed.
     * @param item The root item of the branch to refresh.
     */
    void refreshBranch(QStandardItem *item);

    /**
     * @brief Apply the per-row presentation for @p item given the current
     *        liveness context. Reads the row state, then dispatches to the matching
     *        @ref LuaDebuggerWatchRowPresenter @c apply* method (the presenter owns
     *        cell text / icons / tooltips / change-highlight stamping).
     * @param item        The item to update.
     * @param liveContext True if the debugger is currently paused and values are available.
     * @param muted       Placeholder string to display when values are unavailable.
     */
    void applyItemState(QStandardItem *item, bool liveContext, const QString &muted);

    /**
     * @brief Insert a top-level watch row; optionally open the inline editor.
     *        An empty @p initialSpec creates a "pending new" row. Otherwise the
     *        spec must be a Variables-style path
     *        (see wslua_debugger_watch_spec_uses_path_resolution). Duplicates of an
     *        existing spec just scroll to the existing row.
     * @param initialSpec The expression or path to watch, or empty to create a pending row.
     * @param openEditor  If true, immediately opens the inline editor on the new row.
     */
    void insertNewRow(const QString &initialSpec = QString(), bool openEditor = true);

    /**
     * @brief Apply the user's edit of a top-level watch row's expression.
     *
     *        Empty text removes the row (or discards a pending-new row); too-long
     *        text shows a warning and is rejected; otherwise the spec is committed,
     *        change-highlight baselines for the old and new specs are dropped, and
     *        the row is refreshed. Bound to the inline-editor delegate via the
     *        commit callback set in @ref attach.
     * @param item The top-level item being edited.
     * @param text The new expression text entered by the user.
     */
    void commitWatchRootSpec(QStandardItem *item, const QString &text);

    /**
     * @brief Delete the given top-level watch rows from the tree.
     *        Children, non-top-level rows and stale pointers are silently ignored.
     *        Drops change-highlight baselines for the now-orphaned specs.
     * @param items The list of top-level items to delete.
     */
    void deleteRows(const QList<QStandardItem *> &items);

    /**
     * @brief Confirm with the user, then remove every top-level row.
     */
    void removeAllTopLevelItems();

    /**
     * @brief Copy the (untruncated when paused) value of @p item to the clipboard;
     *        shared between the row context menu and the keyboard shortcut.
     * @param item The item whose value is to be copied.
     * @param ix   The model index of the item.
     */
    void copyValueForItem(QStandardItem *item, const QModelIndex &ix);

    /**
     * @brief Duplicate top-level watch row @p item below itself.
     * @param item The top-level item to duplicate.
     */
    void duplicateRootItem(QStandardItem *item);

    /**
     * @brief Top-level watch rows in the current selection (column 0) only;
     *        used by the section header Remove control. No currentIndex fallback,
     *        so the button does not act on a non-selected row.
     * @return List of selected top-level items eligible for removal.
     */
    QList<QStandardItem *> selectedRootItemsForRemove() const;

    /**
     * @brief Snapshot the live watch tree as a flat array of canonical spec
     *        strings into @p settingsMap (at the @c Watches key). Per-row expansion,
     *        editor origin, and other runtime state are tracked in QStandardItem
     *        data roles only and are not persisted. Also prunes the runtime
     *        expansion map to specs that survive in the tree.
     * @param settingsMap The map to write the serialized watch specs into.
     */
    void serializeTo(QVariantMap &settingsMap);

    /**
     * @brief Replace the watch tree with the contents of @c Watches in
     *        @p settingsMap. Empty / container-typed entries are dropped; scalar
     *        values are kept as expression watches even if they are not valid Lua
     *        (the next refresh will surface the error). Wipes all watch baselines
     *        (variables baselines are kept) so the first refresh starts clean.
     * @param settingsMap The map containing previously serialized watch specs.
     */
    void restoreFrom(const QVariantMap &settingsMap);

    /**
     * @brief Schedule a deferred "Watch column shows —" placeholder paint
     *        after a step resume.
     *
     *        Bumps an internal epoch and posts a single-shot timer; if a new pause
     *        arrives within @ref WATCH_PLACEHOLDER_DEFER_MS, the next call to
     *        @ref invalidatePlaceholder bumps the epoch again and the still-pending
     *        timer becomes a no-op. Without this defer step a typical fast
     *        single-step produces a visible value→—→value blink in every Watch row
     *        even when the value did not change.
     */
    void scheduleDeferredPlaceholder();

    /**
     * @brief Cancel the deferred placeholder by bumping the epoch. Call from
     *        @c handlePause() so the imminent refresh wins over a pending
     *        post-resume placeholder.
     */
    void invalidatePlaceholder();

public slots:
    /**
     * @brief Records the expansion of the item at @p index in the runtime expansion map.
     * @param index The model index of the item that was expanded.
     */
    void onExpanded(const QModelIndex &index);

    /**
     * @brief Records the collapse of the item at @p index in the runtime expansion map.
     * @param index The model index of the item that was collapsed.
     */
    void onCollapsed(const QModelIndex &index);

    /**
     * @brief Displays the watch row context menu at the given viewport position.
     * @param pos The position (in tree viewport coordinates) at which to show the menu.
     */
    void showContextMenu(const QPoint &pos);

private:
    /**
     * @brief Refill @p parent with the children of the path-style watch
     *        resolved to @p path (Locals.x, Globals.t.k, etc.). Reaches back to the
     *        dialog for change-highlight baselines and the active stack frame.
     * @param parent The item whose children are to be replaced.
     * @param path   The resolved Variables-style path string.
     */
    void fillPathChildren(QStandardItem *parent, const QString &path);

    /**
     * @brief Refill @p parent with the children of the expression-style
     *        watch @p rootSpec at descendant @p subpath. Reaches back to the
     *        dialog for change-highlight baselines.
     * @param parent   The item whose children are to be replaced.
     * @param rootSpec The canonical spec string of the root watch expression.
     * @param subpath  The dot-separated subpath within the root expression's value.
     */
    void fillExprChildren(QStandardItem *parent, const QString &rootSpec, const QString &subpath);

    /**
     * @brief Sync the header buttons' enabled state with the current selection and model contents.
     */
    void updateHeaderButtonState();

    /** @brief The parent debugger dialog; provides baselines, stack frame, and cross-panel sync. */
    LuaDebuggerDialog *host_ = nullptr;

    /** @brief The watch tree view. */
    QTreeView *tree_ = nullptr;

    /** @brief The standard item model backing the watch tree. */
    QStandardItemModel *model_ = nullptr;

    /** @brief The Remove Selected header button. */
    QToolButton *removeButton_ = nullptr;

    /** @brief The Remove All header button. */
    QToolButton *removeAllButton_ = nullptr;

    /**
     * @brief Per-row presenter; owns icons / foreground / tooltip / change
     *        highlighting for top-level Watch rows. Constructed lazily in
     *        @ref attach() once @c tree_ and @c model_ are known. Parented to
     *        @c this so destruction is automatic.
     */
    LuaDebuggerWatchRowPresenter *rowPresenter_ = nullptr;

    /** @brief Runtime-only expansion state for Watch roots (not persisted). */
    QHash<QString, LuaDbgTreeSectionExpansionState> expansion_;

    /**
     * @brief Monotonic epoch backing @ref scheduleDeferredPlaceholder /
     *        @ref invalidatePlaceholder. The deferred lambda only runs the
     *        placeholder refresh if the epoch it captured at schedule time
     *        still matches — any intervening pause / re-schedule wins.
     */
    qint32 placeholderEpoch_ = 0;
};

#endif
