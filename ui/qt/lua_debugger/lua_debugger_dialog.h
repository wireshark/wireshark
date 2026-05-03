/* lua_debugger_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Top-level Lua debugger dialog: hosts every panel, owns the pause
 * lifecycle, the reload coordinator, and the main-window close policy.
 */

#ifndef LUA_DEBUGGER_DIALOG_H
#define LUA_DEBUGGER_DIALOG_H

#include <QBrush>
#include <QCheckBox>
#include <QComboBox>
#include <QFont>
#include <QHash>
#include <QIcon>
#include <QKeySequence>
#include <QList>
#include <QModelIndex>
#include <QObject>
#include <QPair>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QTreeView>
#include <QVariantMap>
#include <QVector>

#include "epan/wslua/wslua_debugger.h"
#include "geometry_state_dialog.h"
#include "lua_debugger_breakpoints.h"
#include "lua_debugger_code_editor.h"
#include "lua_debugger_evaluate.h"
#include "lua_debugger_files.h"
#include "lua_debugger_pause.h"
#include "lua_debugger_settings.h"
#include "lua_debugger_stack.h"
#include "lua_debugger_utils.h"
#include "lua_debugger_variables.h"
#include "lua_debugger_watch.h"

class QToolButton;

struct _capture_session;

class AccordionFrame;
class CollapsibleSection;
class QAction;
class QEvent;
class QChildEvent;
class QCloseEvent;
class QShowEvent;
class QSplitter;

namespace Ui
{
class LuaDebuggerDialog;
}

class LuaDebuggerCodeView;
class LuaDebuggerDialog;

/**
 * @brief Coordinates Lua plugin reload: pre/post core callbacks, deferred
 *        reload after pause, toolbar checkbox chrome, and refreshing open
 *        script tabs from disk.
 */
class LuaDebuggerLuaReloadCoordinator : public QObject
{
    Q_OBJECT

  public:
    explicit LuaDebuggerLuaReloadCoordinator(LuaDebuggerDialog *host);

    void handlePreReload();
    void handlePostReload();

    /** @brief If @ref reloadDeferred_ was set, clear it and return true. */
    bool takeDeferredReload();

  public slots:
    void onReloadLuaPluginsRequested();

  private:
    void enterReloadUiStateIfEnabled();
    void exitReloadUiState();
    void reloadAllScriptFilesFromDisk();

    LuaDebuggerDialog *host_ = nullptr;
    bool reloadDeferred_ = false;
    bool reloadUiActive_ = false;
    bool reloadUiRequestWasEnabled_ = false;
};

/**
 * @brief Pause-aware arbitration for main-window close while the Lua
 *        debugger is involved.
 *
 * The Lua dissector can land Wireshark inside a nested QEventLoop driven
 * by @ref LuaDebuggerPauseController while the C call stack still has
 * @c cf_read / dissection frames above us. Allowing the main window to
 * tear down at that point would run @c tryClosingCaptureFile() and
 * @c mainApp->quit() with the Lua dissector still on the stack and abort
 * in @c wmem_cleanup_scopes() at exit. The main window therefore routes
 * its closeEvent through @ref handleMainCloseIfPaused first; if the
 * debugger needs to arbitrate (paused, or owns unsaved scripts), the
 * close is recorded as pending and the event is rejected. Once the Lua
 * stack has unwound (@ref deliverDeferredMainCloseIfPending called from
 * @c handlePause()'s post-loop cleanup, or from the dialog's own
 * closeEvent when not paused) the close is queued back to the main
 * window via @c QMetaObject::invokeMethod(Qt::QueuedConnection).
 */
namespace LuaDebuggerMainClosePolicy
{

/**
 * @brief Decide whether to defer a main-window close while the Lua
 *        debugger needs to arbitrate.
 *
 * @return @c true if the close has been deferred (the caller MUST treat
 *         the event as ignored and return without closing); @c false to
 *         let the main window close normally.
 */
bool handleMainCloseIfPaused(QCloseEvent *event);

/**
 * @brief Re-deliver a previously deferred main-window close, if any.
 *        Idempotent.
 */
void deliverDeferredMainCloseIfPending();

/**
 * @brief Record a debugger-initiated quit (Ctrl+Q from the debugger
 *        window) so that the main window will be closed after the
 *        debugger dialog has finished its own close gate.
 */
void markQuitRequested();

/** @brief Cancel any pending deferred main close. */
void cancelPendingClose();

} // namespace LuaDebuggerMainClosePolicy

/**
 * @brief Top-level dialog hosting the Lua debugger UI components.
 */
class LuaDebuggerDialog : public GeometryStateDialog
{
    Q_OBJECT

  public:
    /**
     * @brief Construct the dialog and initialize all child widgets.
     * @param parent Optional parent widget used for ownership and stacking.
     */
    explicit LuaDebuggerDialog(QWidget *parent = nullptr);
    /**
     * @brief Destroy the dialog and disconnect debugger callbacks.
     */
    ~LuaDebuggerDialog();

    /**
     * @brief Get the current theme setting.
     * @return Theme enum value (WSLUA_DEBUGGER_THEME_AUTO, DARK, or LIGHT).
     */
    static int32_t currentTheme();

    /**
     * @brief Retrieve the singleton instance, creating it if needed.
     * @param parent Optional parent widget supplied when instantiating.
     * @return Pointer to the global dialog instance.
     */
    static LuaDebuggerDialog *instance(QWidget *parent = nullptr);

    /**
     * @brief Like @ref instance but never creates the dialog; returns
     *        @c nullptr when no instance exists yet. Used by helpers
     *        that may run before the dialog has ever been opened.
     */
    static LuaDebuggerDialog *instanceIfExists();

    /**
     * @brief If the debugger is paused or owns unsaved scripts, defer
     *        the supplied main-window close event so the Lua C stack
     *        can unwind first; otherwise return @c false and let the
     *        main window close normally.
     *
     * Called from @c WiresharkMainWindow::closeEvent /
     * @c StratosharkMainWindow::closeEvent through @ref LuaDebugger::tryDeferMainWindowClose.
     *
     * @return @c true if the close has been deferred (the caller MUST
     *         treat the event as ignored and return without closing);
     *         @c false to let the main window close normally.
     */
    static bool handleMainCloseIfPaused(QCloseEvent *event);

    /**
     * @brief React to the debugger pausing execution at a breakpoint.
     * @param file_path Path of the Lua file that triggered the pause.
     * @param line Line number where execution stopped.
     */
    void handlePause(const char *file_path, int64_t line);

    /**
     * @brief Close from Esc or programmatic reject(); queues close() so
     *        closeEvent() runs (unsaved-scripts prompt matches the window
     *        close button). The base QDialog::reject() hides via done() and
     *        skips closeEvent(); synchronous close() from Esc can fail to close.
     */
    void reject() override;

    /** @brief Add a watch from an expression/path spec without opening the
     *  inline editor. Convenience used by the editor right-click menu and by
     *  the Variables panel context menu. */
    void addWatchFromSpec(const QString &watchSpec);

    /** @brief Borrowed reference to the change-highlight tracker. Used by
     *  controllers that compute "changed since last pause" cues without
     *  having to friend the dialog. */
    LuaDebuggerChangeHighlightTracker &changeHighlight() { return changeHighlight_; }

    /** @brief Borrowed reference to the stack controller. Used by Watch /
     *  Variables / Eval to read the currently inspected stack frame
     *  without friending the dialog. */
    LuaDebuggerStackController &stackController() { return stackController_; }

    /** @brief True while the dialog is in a pause-entry / nested event-loop
     *  UI. Mirrors the C side's @c wslua_debugger_is_paused on most paths
     *  but is updated from a different code path; controllers that need
     *  the Qt-side flag read it via this accessor. */
    bool isDebuggerPaused() const { return debuggerPaused; }

    /** @brief Combined "is the change-highlight cue allowed for paint this
     *  pass?" gate. Reads the tracker policy with the active stack
     *  selection level; centralised here so callers do not have to thread
     *  the level themselves. */
    bool changeHighlightAllowed() const
    {
        return changeHighlight_.changeHighlightAllowed(stackController_.selectionLevel());
    }

    /** @brief Stamp @p valueCell with the change-highlight visuals; the
     *  dialog supplies itself as the timer owner so the one-shot row
     *  flash gets cleaned up if the dialog is destroyed. */
    void applyChangedVisuals(QStandardItem *valueCell, bool changed)
    {
        changeHighlight_.applyChangedVisuals(this, valueCell, changed);
    }

    /** @brief Shortcut bound to the Add Watch toolbar action. Watch /
     *  Variables context menus mirror it on their "Add Watch" entries. */
    QKeySequence addWatchShortcut() const;

    /** @name Controller accessors
     *  Borrowed references to the dialog's per-panel controllers. Returned
     *  by reference because the controllers are direct (non-pointer)
     *  members of the dialog and have the same lifetime as the dialog
     *  itself. Callers must not store these references past the dialog's
     *  destruction. */
    /// @{
    LuaDebuggerVariablesController &variablesController() { return variablesController_; }
    LuaDebuggerCodeTabsController &codeTabsController() { return codeTabsController_; }
    LuaDebuggerFilesController &filesController() { return filesController_; }
    LuaDebuggerWatchController &watchController() { return watchController_; }
    LuaDebuggerBreakpointsController &breakpointsController() { return breakpointsController_; }
    LuaDebuggerPauseController &pauseController() { return pauseController_; }
    LuaDebuggerLuaReloadCoordinator &reloadCoordinator() { return reloadCoordinator_; }
    LuaDebuggerEvalController &evalController() { return evalController_; }
    LuaDebuggerFontPolicy &fontPolicy() { return fontPolicy_; }
    /// @}

    /** @brief Source file path (normalized) of the line the debugger is
     *  paused on; empty when not paused. Paired with @ref pausedLine. */
    QString pausedFile() const { return pausedFile_; }
    /** @brief Line number of the pause; zero when the debugger is not
     *  paused. Paired with @ref pausedFile. */
    qlonglong pausedLine() const { return pausedLine_; }

    /** @brief Borrowed reference to the toggle that mirrors the core's
     *  enable/disable state; the reload coordinator round-trips it across
     *  a forced-on reload. */
    QCheckBox *enabledToggle() { return enabledCheckBox; }

    /** @brief Normalize a path by trimming prefixes and resolving symbolic
     *  components. Public so controllers and the capture-suppression
     *  helper can canonicalise paths without friending the dialog. */
    QString normalizedFilePath(const QString &file_path) const;

    /** @brief Refresh checkbox sync + all debugger state chrome/widgets. */
    void refreshDebuggerStateUi();

    /** @brief Update all widgets based on the current debugger state. */
    void updateWidgets();

    /** @brief Enable the debugger if any active breakpoint requires it. */
    void ensureDebuggerEnabledForActiveBreakpoints();

    /** @brief Rebuild the variables tree after the stack frame for
     *  inspection changed. */
    void refreshVariablesForCurrentStackFrame();

    /** @brief Select the Variables row matching the current Watch row,
     *  or clear the Variables selection when no match exists. */
    void syncVariablesTreeToCurrentWatch();

    /** @brief Point find / goto bars at the active code tab. */
    void updateLuaEditorAuxFrames();

    /** @brief Populate/hide the inline error frame for paused break-on-error states. */
    void updatePausedErrorFrame();

    /** @brief Schedule a delayed hide to avoid hide/show flicker on rapid re-pauses. */
    void scheduleErrorFrameHide(int delayMs);

    /** @brief Cancel any pending delayed hide token. */
    void cancelErrorFrameHide();

    /** @brief Enable or disable the Continue action based on debugger state. */
    void updateContinueActionState();

    /** @brief Remove paused-state UI artifacts like stacks and highlights. */
    void clearPausedStateUi();

    /** @brief Toggle the toolbar Save Script action's enabled state.
     *  Surfaced as a typed setter so the code-tabs controller does not
     *  need to reach into the dialog's @c QAction members. */
    void setSaveActionEnabled(bool enabled);

    /** @brief Tear down an active pause loop because the Lua engine is
     *  about to be reloaded under us. Returns @c true if a pause loop
     *  was active (the caller may need to defer follow-up work to the
     *  post-reload phase). Unlike @ref resumeDebuggerAndExitLoop, the
     *  engine is NOT signalled to continue; the reload owns restarting
     *  the VM. */
    bool tearDownPauseLoopForReload();

  public slots:
    /** @brief Build and show the editor context menu (right-click in a
     *  code tab). Routed through Qt's signal/slot mechanism, so it must
     *  be visible from connect() sites in the code-tabs controller. */
    void onCodeViewContextMenu(const QPoint &pos);


    /**
     * @brief Escape: hide inline find/go accordions if shown, else close dialog.
     *        Invoked from the script editor because keys often go to the viewport,
     *        not the top-level dialog event filter.
     */
    void handleEscapeKey();

    /** @brief Run-to-line dispatch from the focused paused editor. Public
     *  so @ref LuaDebuggerKeyRouter can fire it from the dialog's event
     *  filter without reaching into private members. Same entry point
     *  used by the gutter context menu's "Run to Line". */
    void runToCurrentLineInPausedEditor(LuaDebuggerCodeView *codeView, qint32 line);

  protected:
    /**
     * @brief Flush state and resume execution when the dialog closes.
     * @param event Close request metadata from Qt.
     */
    void closeEvent(QCloseEvent *event) override;
    void showEvent(QShowEvent *event) override;
    bool event(QEvent *event) override;
    bool eventFilter(QObject *obj, QEvent *event) override;
    void childEvent(QChildEvent *event) override;

  private slots:
    /** @brief Resume Lua execution when the Continue action is triggered. */
    void onContinue();
    /** @brief Step over the current line. */
    void onStepOver();
    /** @brief Step into the next line (including callees). */
    void onStepIn();
    /** @brief Step out to the caller frame. */
    void onStepOut();
    /** @brief Run to the line under the cursor in the active code editor. */
    void onRunToLine();
    /** @brief Add a watch row, prefilled from the editor selection when present. */
    void onAddWatch();
    /** @brief Enable or disable the debugger when the toggle button is clicked.
     */
    void onDebuggerToggled(bool checked);
    /** @brief Prompt the user to open a Lua file into a new tab. */
    void onOpenFile();
    /** @brief Apply Wireshark text zoom to the script editor only. */
    void onMonospaceFontUpdated(const QFont &font);
    /** @brief Refresh fonts once the main application finishes initializing. */
    void onMainAppInitialized();
    /** @brief Update code view themes when preferences change. */
    void onPreferencesChanged();
    /** @brief Update code view themes when Wireshark's color scheme changes. */
    void onColorsChanged();
    /**
     * @brief Drain the cross-thread logpoint queue into the Evaluate
     *        output panel.
     *
     * Posted as a single queued invocation by the C-side log-emit
     * trampoline the first time a fire enqueues a message after the
     * previous drain finished. Many fires therefore funnel through
     * one event-loop tick instead of one queued lambda per fire,
     * which is what made per-packet logpoints freeze the GUI.
     */
    void drainPendingLogs();
    /**
     * @brief Drain the silent-bump notification: refresh the
     *        Breakpoints @em Hits column from engine state.
     *
     * Posted as a single queued invocation by the C-side
     * @ref onBreakpointStateDirty trampoline the first time the line
     * hook bumps any @c bp->hit_count after the previous drain
     * cleared the dirty flag. Hot lines therefore funnel through one
     * event-loop tick instead of one queued lambda per bump.
     *
     * No-ops while the dialog is hidden so a hot line doesn't pay for
     * model rebuilds the user can't see; @ref showEvent re-invokes
     * this on the next show to catch up the visible counter.
     */
    void drainBreakpointStateUpdates();
    /** @brief Handle theme selection changes from the Settings section. */
    void onThemeChanged(int idx);
    /** @brief Show inline find/replace bar. */
    void onEditorFind();
    /** @brief Show inline go-to-line bar. */
    void onEditorGoToLine();
    /** @brief Sync Watch selection when Variables row selection changes. */
    void onVariablesCurrentItemChanged(const QModelIndex &current, const QModelIndex &previous);
    /** @brief Sync Variables selection when a path-style watch root is selected. */
    void onWatchCurrentItemChanged(const QModelIndex &current, const QModelIndex &previous);
    /**
     * @brief Adjust the left panel layout based on section expansion state.
     *
     * When at least one collapsible section is expanded, the splitter takes
     * all extra vertical space. When every section is collapsed, the
     * splitter is clamped to its content height (sum of section header
     * heights plus inter-section handles) and a trailing stretch in
     * leftPanelLayout absorbs the leftover, keeping the toolbar and section
     * headers pinned to the top of the panel.
     */
    void updateLeftPanelStretch();

  private:
    Ui::LuaDebuggerDialog *ui;
    LuaDebuggerVariablesController variablesController_;
    LuaDebuggerStackController stackController_;
    LuaDebuggerEvalController evalController_;
    LuaDebuggerBreakpointsController breakpointsController_;
    LuaDebuggerFilesController filesController_;
    LuaDebuggerWatchController watchController_;
    LuaDebuggerCodeTabsController codeTabsController_;
    LuaDebuggerPauseController pauseController_;
    LuaDebuggerLuaReloadCoordinator reloadCoordinator_;
    /** @brief Owns the dialog's font story (zoomed editor + panels + watch model). */
    LuaDebuggerFontPolicy fontPolicy_;
    /** @brief Centralised eventFilter shortcut dispatcher. */
    LuaDebuggerKeyRouter keyRouter_;
    static LuaDebuggerDialog *_instance;
    static int32_t currentTheme_;

    void wireFilesPanel();
    void wireStackPanel();
    void wireVariablesPanel();
    void wireWatchPanel();
    void wireBreakpointsPanel();
    void wireEvaluatePanel();
    void wireCodeTabs();

    /** @brief Build the Variables collapsible section and its tree/model. */
    CollapsibleSection *createVariablesSection(QWidget *parent);
    /** @brief Build the Watch collapsible section, header buttons, and tree/model. */
    CollapsibleSection *createWatchSection(QWidget *parent);
    /** @brief Build the Stack Trace collapsible section and its tree/model. */
    CollapsibleSection *createStackSection(QWidget *parent);
    /** @brief Build the Breakpoints collapsible section, header buttons, and tree/model. */
    CollapsibleSection *createBreakpointsSection(QWidget *parent);
    /** @brief Build the Files collapsible section and its tree/model. */
    CollapsibleSection *createFilesSection(QWidget *parent);
    /** @brief Build the Evaluate collapsible section (input/output split + buttons). */
    CollapsibleSection *createEvaluateSection(QWidget *parent);

    void resetStackForPauseEntry();
    void clearStackPanel();

    QCheckBox *enabledCheckBox;
    /* True when this dialog is in a pause entry / nested event-loop UI
     * (Continue/step, freeze, chrome). The C side reports an actual
     * breakpoint with wslua_debugger_is_paused(); the two are usually
     * aligned but are updated on different call paths. */
    bool debuggerPaused;

    // Collapsible sections (created programmatically)
    CollapsibleSection *variablesSection;
    CollapsibleSection *watchSection;
    CollapsibleSection *stackSection;
    CollapsibleSection *breakpointsSection;
    CollapsibleSection *filesSection;
    CollapsibleSection *evalSection;
    CollapsibleSection *settingsSection;

    // Tree views and item models (created programmatically)
    QTreeView *variablesTree;
    QStandardItemModel *variablesModel;
    QTreeView *watchTree;
    QStandardItemModel *watchModel;
    QTreeView *stackTree;
    QStandardItemModel *stackModel;
    QTreeView *fileTree;
    QStandardItemModel *fileModel;
    QTreeView *breakpointsTree;
    QStandardItemModel *breakpointsModel;

    // Eval panel widgets (created programmatically)
    QPlainTextEdit *evalInputEdit;
    QPlainTextEdit *evalOutputEdit;
    QPushButton *evalButton;
    QPushButton *evalClearButton;
    /**
     * @brief Vertical splitter between the Evaluate input and output panes.
     *
     * Held as a member so that its collapse state and pane sizes can be
     * persisted across sessions via storeDialogSettings()/applyDialogSettings()
     * (see LuaDebuggerSettingsKeys::EvalSplitter).
     */
    QSplitter *evalSplitter_ = nullptr;

    // Settings panel widgets (created programmatically)
    QComboBox *themeComboBox;
    /** @brief Breakpoints section header: toggle at caret, clear all. */
    QToolButton *breakpointHeaderToggleButton_ = nullptr;
    /** @brief Breakpoints section header: remove selected breakpoint row(s). */
    QToolButton *breakpointHeaderRemoveButton_ = nullptr;
    QToolButton *breakpointHeaderRemoveAllButton_ = nullptr;
    /** @brief Breakpoints section header: toggle break-on-error mode. */
    QToolButton *breakpointHeaderBreakOnErrorButton_ = nullptr;
    /**
     * @brief Breakpoints section header: open the inline condition /
     *        hit count / log message editor on the focused row. Enabled
     *        only when exactly one editable row is selected (mirrors
     *        the inline editor's "edit one row at a time" model).
     */
    QToolButton *breakpointHeaderEditButton_ = nullptr;
    /** @brief Dialog-wide QAction backing the Ctrl+Shift+F9 shortcut. */
    QAction *actionRemoveAllBreakpoints_ = nullptr;

    /** @brief Hide other accordion bars then show one (matches main window). */
    void showAccordionFrame(AccordionFrame *frame, bool toggle = false);
    /** @brief Install this dialog as an event filter on all descendant widgets
     *  so conflicting shortcuts are handled here before the main window.
     */
    void installDescendantShortcutFilters();
    /** @brief Sync only the checkbox checked/enabled state from core flags. */
    void syncDebuggerToggleWithCore();
    /** @brief One combined status for window title and toolbar dot (single source
     *        of truth for chrome, derived from the core and Qt members). */
    enum class DebuggerUiStatus
    {
        Paused,
        DisabledLiveCapture,
        Disabled,
        Running
    };
    DebuggerUiStatus currentDebuggerUiStatus() const;
    /** @brief Update the checkbox icon based on the enabled state. */
    void updateEnabledCheckboxIcon();
    /** @brief Update the status label to show current debugger state. */
    void updateStatusLabel();
    /** @brief Apply the current theme preference to all code views. */
    void applyCodeViewThemes();
    /** @brief Re-apply stylesheet-driven chrome (toolbar, find/go accordions). */
    void updateStyleSheets();
    /** @brief Resume the debugger (if paused) and exit any nested event loop.
     */
    void resumeDebuggerAndExitLoop();
    /**
     * @brief Undo the pause-entry UI freeze synchronously.
     *
     * Idempotent: safe to call from both handlePause()'s post-loop
     * (normal Continue/Step resume) and from closeEvent() (so the
     * rest of WiresharkMainWindow::closeEvent runs with a fully
     * interactive UI when the user closes the app while the
     * debugger is paused). Gated by @ref LuaDebuggerPauseController::endFreeze.
     */
    void endPauseFreeze();
    /**
     * @brief Resume execution with a stepping mode; shared by step over/in/out.
     * @param step_fn Core step function (e.g. wslua_debugger_step_over).
     */
    void runDebuggerStep(void (*step_fn)(void));
    /** @brief Create the collapsible sections and their content widgets. */
    void createCollapsibleSections();

    // ---- Qt-based JSON settings persistence (like import_hexdump) ----
    /** @brief In-memory settings, persisted to lua_debugger.json. */
    LuaDebuggerSettingsStore settingsStore_;
    /** @brief True after lua_debugger.json was written from closeEvent (destructor fallback if false). */
    bool luaDebuggerJsonSaved_{false};
    /** @brief Save settings to lua_debugger.json (global personal config, not per-profile).
     */
    void saveSettingsFile();
    /** @brief Apply loaded settings to UI widgets. */
    void applyDialogSettings();
    /** @brief Store current UI widget state into settings map. */
    void storeDialogSettings();

    QStandardItem *findVariablesItemByPath(const QString &path) const;
    QStandardItem *findWatchRootForVariablePath(const QString &path) const;
    static void expandAncestorsOf(QTreeView *tree, QStandardItemModel *model, QStandardItem *item);

    bool syncWatchVariablesSelection_ = false;

    /** Changed-value (bold / accent / flash) baseline maps and brushes. */
    LuaDebuggerChangeHighlightTracker changeHighlight_;

    /**
     * @brief Source file (normalized) of the line the debugger is paused on.
     *
     * Set by @ref handlePause and cleared by @ref clearPausedStateUi.
     * @ref updateBreakpoints uses the pair (@ref pausedFile_,
     * @ref pausedLine_) to find the breakpoints-tree row matching the
     * current pause location and apply the same change-highlight visuals
     * the Watch / Variables trees use, so the row that "fired" stands
     * out at a glance.
     *
     * Empty when the debugger is not paused; matching is skipped in that
     * state so a resumed dialog never carries forward a stale cue. The
     * line number is paired in @ref pausedLine_; both must match for a
     * row to be considered the firing breakpoint.
     */
    QString pausedFile_;
    /** @brief Line number of the pause; see @ref pausedFile_. Zero when
     *  the debugger is not paused. */
    qlonglong pausedLine_ = 0;

    /** @brief Monotonic token used to debounce delayed error-frame hides. */
    int errorFrameHideEpoch_ = 0;

    void refreshChangedValueBrushes() { changeHighlight_.refreshChangedValueBrushes(watchTree, this); }

    void snapshotBaselinesOnPauseEntry() { changeHighlight_.snapshotBaselinesOnPauseEntry(); }

    void clearAllChangeBaselines() { changeHighlight_.clearAllChangeBaselines(); }

    void pruneChangeBaselinesToLiveWatchSpecs() { changeHighlight_.pruneChangeBaselinesToLiveWatchSpecs(watchModel); }

    void updatePauseEntryFrameIdentity() { changeHighlight_.updatePauseEntryFrameIdentity(); }
};

#endif // LUA_DEBUGGER_DIALOG_H
