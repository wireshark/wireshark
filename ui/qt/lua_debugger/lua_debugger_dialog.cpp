/* lua_debugger_dialog.cpp
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

#include <config.h>

#include "lua_debugger_dialog.h"
#include <ui_lua_debugger_dialog.h>

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QChildEvent>
#include <QClipboard>
#include <QCloseEvent>
#include <QColor>
#include <QDir>
#include <QDirIterator>
#include <QDragMoveEvent>
#include <QDropEvent>
#include <QEvent>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QFontMetricsF>
#include <QFormLayout>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QItemSelectionModel>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
#include <QKeyCombination>
#endif
#include <QKeyEvent>
#include <QKeySequence>
#include <QList>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QMutex>
#include <QMutexLocker>
#include <QPainter>
#include <QPalette>
#include <QPersistentModelIndex>
#include <QPlainTextEdit>
#include <QPointer>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QSet>
#include <QShowEvent>
#include <QSizePolicy>
#include <QSplitter>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QStringList>
#include <QStyle>
#include <QTabWidget>
#include <QTextBlock>
#include <QTextStream>
#include <QTimer>
#include <QToolButton>
#include <QToolTip>
#include <QTreeView>
#include <QUrl>
#include <QVBoxLayout>

#include <algorithm>
#include <climits>
#include <glib.h>

#include "accordion_frame.h"
#include "app/application_flavor.h"
#include "lua_debugger.h"
#include "lua_debugger_code_editor.h"
#include "lua_debugger_error_frame.h"
#include "lua_debugger_find_frame.h"
#include "lua_debugger_goto_line_frame.h"
#include "lua_debugger_utils.h"
#include "main_application.h"
#include "main_window.h"
#include "utils/stock_icon.h"
#include "widgets/collapsible_section.h"
#include "wsutil/filesystem.h"
#include <epan/prefs.h>
#include <epan/wslua/wslua_debugger.h>
#ifdef HAVE_LIBPCAP
#include <ui/capture.h>
#endif
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>

using namespace LuaDebuggerItems;

namespace
{

/**
 * @brief Process-global "live capture is forcing the debugger off" state.
 *
 * The capture-session callback is registered at process start (before the
 * dialog exists), so this state is intentionally static and does not depend
 * on a live @ref LuaDebuggerDialog instance. The dialog observes the state
 * (via @ref isActive) when refreshing chrome, and updates the "restore on
 * stop" intent (via @ref setPrevEnabled) when the user toggles the
 * debugger toolbar during a capture.
 */
class LuaDebuggerCaptureSuppression
{
  public:
    /** @brief True when a live capture currently has the debugger force-disabled. */
    static bool isActive();

    /** @brief Enter suppression. Snapshots the user's pre-capture enabled
     *  intent so we can restore it on @ref exit. Idempotent: returns true
     *  iff this call actually transitioned the state. */
    static bool enter();

    /** @brief Exit suppression. Restores the snapshotted enabled intent
     *  unless the user has since explicitly disabled the debugger.
     *  Idempotent: returns true iff this call actually transitioned the state. */
    static bool exit();

    /** @brief Re-apply suppression at dialog startup so any constructor-time
     *  paths that re-enabled the core get reverted. */
    static void reconcileOnStartup(LuaDebuggerDialog *dialog);

    /** @brief Capture-session observer registered at process start. */
    static void onCaptureSessionEvent(int event, struct _capture_session *cap_session, void *user_data);

    /** @brief Update the "restore on capture stop" intent. */
    static void setPrevEnabled(bool enabled);
};

bool g_captureSuppressionActive = false;
/* User's enabled-state at the moment the live capture started; restored
 * when capture finishes. Meaningful only while @c g_captureSuppressionActive is true. */
bool g_captureSuppressionPrevEnabled = false;

bool LuaDebuggerCaptureSuppression::isActive()
{
    return g_captureSuppressionActive;
}

bool LuaDebuggerCaptureSuppression::enter()
{
    /* Suppress on the very first start-ish event of a session.
     * "prepared" already commits us to a live capture, and the
     * dumpcap child may begin writing packets before the
     * "update_started" / "fixed_started" event arrives. */
    if (g_captureSuppressionActive)
    {
        return false;
    }
    g_captureSuppressionPrevEnabled = wslua_debugger_is_enabled();
    g_captureSuppressionActive = true;
    if (g_captureSuppressionPrevEnabled)
    {
        wslua_debugger_set_enabled(false);
    }
    return true;
}

bool LuaDebuggerCaptureSuppression::exit()
{
    if (!g_captureSuppressionActive)
    {
        return false;
    }
    const bool restore_enabled = g_captureSuppressionPrevEnabled;
    g_captureSuppressionActive = false;
    g_captureSuppressionPrevEnabled = false;
    /* Respect user_explicitly_disabled (unchecked toolbar or closed dialog):
     * do not turn the core back on when capture ends. */
    if (restore_enabled && wslua_debugger_may_auto_enable_for_breakpoints())
    {
        wslua_debugger_set_enabled(true);
    }
    return true;
}

void LuaDebuggerCaptureSuppression::reconcileOnStartup(LuaDebuggerDialog *dialog)
{
    /* The capture-session callback is registered at process start, so by the
     * time the dialog opens, g_captureSuppressionActive already reflects whether
     * a live capture is in progress.
     *
     * What this method exists to fix: ctor init paths can re-enable the core
     * debugger after the callback already established suppression — specifically
     * applyDialogSettings() → wslua_debugger_add_breakpoint, then
     * breakpointsController_.refreshFromEngine()
     * → ensureDebuggerEnabledForActiveBreakpoints can re-enable. */
    if (!g_captureSuppressionActive)
    {
        return;
    }
    if (wslua_debugger_is_enabled())
    {
        /* Force the core back off without touching g_captureSuppressionPrevEnabled
         * — it was correctly snapshotted to the user's pre-capture intent. */
        wslua_debugger_set_enabled(false);
    }
    if (dialog)
    {
        dialog->refreshDebuggerStateUi();
    }
}

void LuaDebuggerCaptureSuppression::onCaptureSessionEvent(int event, struct _capture_session *cap_session,
                                                          void *user_data)
{
    Q_UNUSED(cap_session);
    Q_UNUSED(user_data);

#ifdef HAVE_LIBPCAP
    bool state_changed = false;

    switch (event)
    {
    case capture_cb_capture_prepared:
    case capture_cb_capture_update_started:
    case capture_cb_capture_fixed_started:
        state_changed = enter();
        break;
    case capture_cb_capture_update_finished:
    case capture_cb_capture_fixed_finished:
    case capture_cb_capture_failed:
        state_changed = exit();
        break;
    default:
        break;
    }

    if (state_changed)
    {
        if (LuaDebuggerDialog *dialog = LuaDebuggerDialog::instanceIfExists())
        {
            dialog->refreshDebuggerStateUi();
        }
    }
#else
    Q_UNUSED(event);
#endif
}

void LuaDebuggerCaptureSuppression::setPrevEnabled(bool enabled)
{
    g_captureSuppressionPrevEnabled = enabled;
}

/* Cross-thread coalescing queue for logpoint emissions.
 *
 * The line hook fires on the Lua thread; the GUI mutation must run on the GUI
 * thread. Per-fire queued invocations through QMetaObject::invokeMethod
 * allocate a heap functor and post an event each time, which saturates the
 * main event queue when a logpoint matches every packet. Funnelling fires
 * through this queue and posting a single drain task per non-empty transition
 * keeps the queue depth bounded regardless of the firing rate. */
QMutex g_logEmitMutex;
QStringList g_pendingLogMessages;
bool g_logDrainScheduled = false;

extern "C" void onUiBreakpointHit(const char *file_path, int64_t line)
{
    LuaDebuggerDialog *dialog = LuaDebuggerDialog::instance();
    if (dialog)
    {
        dialog->handlePause(file_path, line);
    }
}

extern "C" void onLuaPreReload()
{
    if (LuaDebuggerDialog *dialog = LuaDebuggerDialog::instanceIfExists())
    {
        dialog->reloadCoordinator().handlePreReload();
    }
}

extern "C" void onLuaPostReload()
{
    if (LuaDebuggerDialog *dialog = LuaDebuggerDialog::instanceIfExists())
    {
        dialog->reloadCoordinator().handlePostReload();
    }
}

extern "C" void onScriptLoaded(const char *file_path)
{
    LuaDebuggerDialog *dialog = LuaDebuggerDialog::instanceIfExists();
    if (dialog && file_path)
    {
        dialog->filesController().ensureEntry(QString::fromUtf8(file_path));
        dialog->filesController().sortModel();
    }
}

extern "C" void onBreakpointStateDirty()
{
    /* Silent-bump trampoline: the Lua-side line hook fires this on
     * the first @c bp->hit_count++ of an "epoch" (subsequent bumps
     * stop at a CAS until the GUI thread clears the flag). We just
     * post a queued drain — all engine reads and model rebuilds
     * happen on the GUI thread inside @ref drainBreakpointStateUpdates. */
    LuaDebuggerDialog *dialog = LuaDebuggerDialog::instanceIfExists();
    if (!dialog)
    {
        return;
    }
    QMetaObject::invokeMethod(dialog, "drainBreakpointStateUpdates",
                              Qt::QueuedConnection);
}

extern "C" void onLogEmit(const char *file_path, int64_t line, const char *message)
{
    Q_UNUSED(file_path);
    Q_UNUSED(line);
    LuaDebuggerDialog *dialog = LuaDebuggerDialog::instanceIfExists();
    if (!dialog)
    {
        return;
    }
    QString messageQ = message ? QString::fromUtf8(message) : QString();

    bool schedule = false;
    {
        QMutexLocker lock(&g_logEmitMutex);
        g_pendingLogMessages.append(messageQ);
        if (!g_logDrainScheduled)
        {
            g_logDrainScheduled = true;
            schedule = true;
        }
    }
    if (schedule)
    {
        QMetaObject::invokeMethod(dialog, "drainPendingLogs", Qt::QueuedConnection);
    }
}

/** @brief Process-global registrar: wires the UI breakpoint-hit
 *  callback (and, when libpcap is available, the capture-session
 *  observer used by @ref LuaDebuggerCaptureSuppression) at process
 *  start, and tears them down at process exit. */
class UiCallbackProcessRegistrar
{
  public:
    UiCallbackProcessRegistrar()
    {
        wslua_debugger_register_ui_callback(onUiBreakpointHit);
#ifdef HAVE_LIBPCAP
        capture_callback_add(&LuaDebuggerCaptureSuppression::onCaptureSessionEvent, nullptr);
#endif
    }

    ~UiCallbackProcessRegistrar()
    {
        wslua_debugger_register_ui_callback(NULL);
#ifdef HAVE_LIBPCAP
        capture_callback_remove(&LuaDebuggerCaptureSuppression::onCaptureSessionEvent, nullptr);
#endif
    }
};

UiCallbackProcessRegistrar g_uiCallbackProcessRegistrar;

void installDialogCallbacks()
{
    wslua_debugger_register_reload_callback(onLuaPreReload);
    wslua_debugger_register_post_reload_callback(onLuaPostReload);
    wslua_debugger_register_script_loaded_callback(onScriptLoaded);
    wslua_debugger_register_log_emit_callback(onLogEmit);
    wslua_debugger_register_breakpoint_state_dirty_callback(onBreakpointStateDirty);
}

void uninstallDialogCallbacks()
{
    wslua_debugger_register_reload_callback(NULL);
    wslua_debugger_register_post_reload_callback(NULL);
    wslua_debugger_register_script_loaded_callback(NULL);
    wslua_debugger_register_log_emit_callback(NULL);
    wslua_debugger_register_breakpoint_state_dirty_callback(NULL);

    /* Discard any logpoint messages that arrived after the unregister
     * but before this destructor ran, and reset the drain-scheduled
     * flag so the next debugger session starts fresh. */
    QMutexLocker lock(&g_logEmitMutex);
    g_pendingLogMessages.clear();
    g_logDrainScheduled = false;
}

} // namespace

LuaDebuggerDialog *LuaDebuggerDialog::_instance = nullptr;
int32_t LuaDebuggerDialog::currentTheme_ = WSLUA_DEBUGGER_THEME_AUTO;

LuaDebuggerDialog *LuaDebuggerDialog::instanceIfExists()
{
    return _instance;
}

bool LuaDebuggerDialog::handleMainCloseIfPaused(QCloseEvent *event)
{
    return LuaDebuggerMainClosePolicy::handleMainCloseIfPaused(event);
}

int32_t LuaDebuggerDialog::currentTheme()
{
    return currentTheme_;
}

LuaDebuggerDialog::LuaDebuggerDialog(QWidget *parent)
    : GeometryStateDialog(parent), ui(new Ui::LuaDebuggerDialog), variablesController_(this), stackController_(this),
      evalController_(this), breakpointsController_(this), filesController_(this), watchController_(this),
      codeTabsController_(this), pauseController_(this), reloadCoordinator_(this), keyRouter_(this),
      enabledCheckBox(nullptr), debuggerPaused(false), variablesSection(nullptr),
      watchSection(nullptr), stackSection(nullptr), breakpointsSection(nullptr), filesSection(nullptr),
      evalSection(nullptr), settingsSection(nullptr), variablesTree(nullptr), variablesModel(nullptr),
      watchTree(nullptr), watchModel(nullptr), stackTree(nullptr), stackModel(nullptr), fileTree(nullptr),
      fileModel(nullptr), breakpointsTree(nullptr), breakpointsModel(nullptr), evalInputEdit(nullptr),
      evalOutputEdit(nullptr), evalButton(nullptr), evalClearButton(nullptr), themeComboBox(nullptr),
      breakpointHeaderToggleButton_(nullptr), breakpointHeaderRemoveButton_(nullptr),
      breakpointHeaderRemoveAllButton_(nullptr), breakpointHeaderEditButton_(nullptr)
{
    _instance = this;
    setAttribute(Qt::WA_DeleteOnClose);
    ui->setupUi(this);
    loadGeometry();

    // Create collapsible sections with their content widgets
    createCollapsibleSections();

    wireVariablesPanel();
    wireWatchPanel();
    wireStackPanel();
    wireBreakpointsPanel();
    wireFilesPanel();
    wireEvaluatePanel();
    wireCodeTabs();

    keyRouter_.attach(ui, breakpointsTree);

    // Toolbar controls - Checkbox for enable/disable
    // Order: Checkbox | Separator | Continue | Step Over/In/Out | Separator | Open | Reload
    QAction *firstAction = ui->toolBar->actions().isEmpty() ? nullptr : ui->toolBar->actions().first();

    // Compact toolbar styling with consistent icons
    ui->toolBar->setIconSize(QSize(18, 18));
    ui->toolBar->setToolButtonStyle(Qt::ToolButtonIconOnly);

    // Enable/Disable checkbox with colored icon
    enabledCheckBox = new QCheckBox(ui->toolBar);
    enabledCheckBox->setChecked(wslua_debugger_is_enabled());
    ui->toolBar->insertWidget(firstAction, enabledCheckBox);

    ui->actionContinue->setToolTip(tr("Continue execution (F5)"));
    ui->actionContinue->setShortcutContext(Qt::WidgetWithChildrenShortcut);

    ui->actionStepOver->setToolTip(tr("Step over (F10)"));
    ui->actionStepOver->setShortcutContext(Qt::WidgetWithChildrenShortcut);

    ui->actionStepIn->setToolTip(tr("Step into (F11)"));
    ui->actionStepIn->setShortcutContext(Qt::WidgetWithChildrenShortcut);

    ui->actionStepOut->setToolTip(tr("Step out (Shift+F11)"));
    ui->actionStepOut->setShortcutContext(Qt::WidgetWithChildrenShortcut);

    ui->actionRunToLine->setToolTip(tr("Run to line (%1)").arg(kLuaDbgCtxRunToLine.toString(QKeySequence::NativeText)));

    ui->actionOpenFile->setIcon(StockIcon("document-open"));
    ui->actionOpenFile->setToolTip(tr("Open Lua Script"));

    ui->actionSaveFile->setIcon(style()->standardIcon(QStyle::SP_DialogSaveButton));
    ui->actionSaveFile->setToolTip(tr("Save (%1)").arg(QKeySequence(QKeySequence::Save).toString(QKeySequence::NativeText)));
    ui->actionSaveFile->setShortcut(QKeySequence::Save);
    ui->actionSaveFile->setShortcutContext(Qt::WidgetWithChildrenShortcut);

    ui->actionReloadLuaPlugins->setIcon(StockIcon("view-refresh"));
    ui->actionReloadLuaPlugins->setToolTip(tr("Reload Lua Plugins (Ctrl+Shift+L)"));
    ui->actionReloadLuaPlugins->setShortcut(kLuaDbgCtxReloadLuaPlugins);
    ui->actionReloadLuaPlugins->setShortcutContext(Qt::WidgetWithChildrenShortcut);

    ui->actionAddWatch->setToolTip(tr("Add Watch (%1)").arg(kLuaDbgCtxAddWatch.toString(QKeySequence::NativeText)));
    ui->actionAddWatch->setShortcut(kLuaDbgCtxAddWatch);
    ui->actionAddWatch->setShortcutContext(Qt::WidgetWithChildrenShortcut);

    ui->actionFind->setToolTip(tr("Find in script (%1)").arg(QKeySequence(QKeySequence::Find).toString(QKeySequence::NativeText)));
    ui->actionFind->setShortcut(QKeySequence::Find);
    ui->actionFind->setShortcutContext(Qt::WidgetWithChildrenShortcut);

    ui->actionGoToLine->setToolTip(tr("Go to line (%1)").arg(kLuaDbgCtxGoToLine.toString(QKeySequence::NativeText)));
    ui->actionGoToLine->setShortcut(kLuaDbgCtxGoToLine);
    ui->actionGoToLine->setShortcutContext(Qt::WidgetWithChildrenShortcut);

    updateStyleSheets();

    connect(enabledCheckBox, &QCheckBox::toggled, this, &LuaDebuggerDialog::onDebuggerToggled);
    connect(ui->actionContinue, &QAction::triggered, this, &LuaDebuggerDialog::onContinue);
    connect(ui->actionStepOver, &QAction::triggered, this, &LuaDebuggerDialog::onStepOver);
    connect(ui->actionStepIn, &QAction::triggered, this, &LuaDebuggerDialog::onStepIn);
    connect(ui->actionStepOut, &QAction::triggered, this, &LuaDebuggerDialog::onStepOut);
    connect(ui->actionRunToLine, &QAction::triggered, this, &LuaDebuggerDialog::onRunToLine);
    connect(ui->actionAddWatch, &QAction::triggered, this, &LuaDebuggerDialog::onAddWatch);
    connect(ui->actionOpenFile, &QAction::triggered, this, &LuaDebuggerDialog::onOpenFile);
    connect(ui->actionFind, &QAction::triggered, this, &LuaDebuggerDialog::onEditorFind);
    connect(ui->actionGoToLine, &QAction::triggered, this, &LuaDebuggerDialog::onEditorGoToLine);
    connect(ui->actionReloadLuaPlugins, &QAction::triggered, &reloadCoordinator_,
            &LuaDebuggerLuaReloadCoordinator::onReloadLuaPluginsRequested);

    addAction(ui->actionContinue);
    addAction(ui->actionStepOver);
    addAction(ui->actionStepIn);
    addAction(ui->actionStepOut);
    addAction(ui->actionReloadLuaPlugins);
    addAction(ui->actionAddWatch);
    addAction(ui->actionSaveFile);
    addAction(ui->actionFind);
    addAction(ui->actionGoToLine);

    ui->luaDebuggerFindFrame->hide();
    ui->luaDebuggerGoToLineFrame->hide();
    ui->luaDebuggerErrorFrame->hide();

    variablesController_.configureColumns();
    watchController_.configureColumns();
    stackController_.configureColumns();
    breakpointsController_.configureColumns();

    fontPolicy_.attach(ui->codeTabWidget, variablesTree, watchTree, watchModel, stackTree, fileTree, breakpointsTree,
                       evalInputEdit, evalOutputEdit);
    fontPolicy_.applyAll();

    /* Seed the accent + flash brushes from the initial palette so the very
     * first pause shows correctly themed cues without having to wait for a
     * preference / color-scheme change. */
    refreshChangedValueBrushes();

    /*
     * Install the C-side callbacks (reload / post-reload / script-loaded /
     * log-emit) so the wslua debugger core can reach this dialog. Paired
     * with uninstallDialogCallbacks() in the destructor.
     */
    installDialogCallbacks();

    if (mainApp)
    {
        connect(mainApp, &MainApplication::zoomMonospaceFont, this, &LuaDebuggerDialog::onMonospaceFontUpdated,
                Qt::UniqueConnection);
        connect(mainApp, &MainApplication::appInitialized, this, &LuaDebuggerDialog::onMainAppInitialized,
                Qt::UniqueConnection);
        connect(mainApp, &MainApplication::preferencesChanged, this, &LuaDebuggerDialog::onPreferencesChanged,
                Qt::UniqueConnection);
        /*
         * Connect to themeChanged signal to update code view themes when
         * Wireshark's color scheme changes. This is important when the debugger
         * theme preference is set to "Auto (follow color scheme)".
         */
        connect(ThemeManager::instance(), &ThemeManager::themeChanged, this, &LuaDebuggerDialog::onColorsChanged,
                Qt::UniqueConnection);
        if (mainApp->isInitialized())
        {
            onMainAppInitialized();
        }
    }

    filesController_.refreshAvailableScripts();
    refreshDebuggerStateUi();

    /*
     * Apply all settings from JSON file (theme, font, sections, splitters,
     * breakpoints). This is done after all widgets are created.
     */
    applyDialogSettings();
    breakpointsController_.refreshFromEngine();
    codeTabsController_.updateSaveActionState();
    updateLuaEditorAuxFrames();

    installDescendantShortcutFilters();

    /* Reconcile with any live capture in progress AFTER all init paths
     * that may have re-enabled the core debugger (applyDialogSettings
     * / updateBreakpoints, including ensureDebuggerEnabledForActiveBreakpoints). */
    LuaDebuggerCaptureSuppression::reconcileOnStartup(this);
}

LuaDebuggerDialog::~LuaDebuggerDialog()
{
    /*
     * Persist JSON only from closeEvent(); if the dialog is destroyed without
     * a normal close (rare), flush once here.
     */
    if (!luaDebuggerJsonSaved_)
    {
        storeDialogSettings();
        saveSettingsFile();
    }

    /*
     * Unregister the C-side callbacks installed in the constructor and
     * discard any pending logpoint messages. See
     * uninstallDialogCallbacks() for details.
     */
    uninstallDialogCallbacks();

    delete ui;
    _instance = nullptr;
}

LuaDebuggerDialog *LuaDebuggerDialog::instance(QWidget *parent)
{
    if (!_instance)
    {
        QWidget *resolved_parent = parent;
        if (!resolved_parent && mainApp && mainApp->isInitialized())
        {
            resolved_parent = mainApp->mainWindow();
        }
        new LuaDebuggerDialog(resolved_parent);
    }
    return _instance;
}

void LuaDebuggerDialog::handlePause(const char *file_path, int64_t line)
{
    // Prevent deletion while in event loop
    setAttribute(Qt::WA_DeleteOnClose, false);

    // Bring to front
    show();
    raise();
    activateWindow();

    QString normalizedPath = normalizedFilePath(QString::fromUtf8(file_path));
    filesController_.ensureEntry(normalizedPath);
    LuaDebuggerCodeView *view = codeTabsController_.loadFile(normalizedPath);
    if (view)
    {
        view->setCurrentLine(static_cast<qint32>(line));
    }

    debuggerPaused = true;
    /* Record the pause location so the breakpoints-tree refresh below can
     * apply the same change-highlight visuals (bold + accent + one-shot
     * background flash) the Watch / Variables trees use. The pair is
     * cleared in clearPausedStateUi() on resume so a non-matching row
     * never carries forward a stale cue across pauses. */
    pausedFile_ = normalizedPath;
    pausedLine_ = static_cast<qlonglong>(line);

    updatePausedErrorFrame();

    /* Cancel any deferred "Watch column shows —" placeholder still pending
     * from the previous resume (typical for runDebuggerStep): we are
     * about to repaint the Watch tree with real values, so the user must
     * never see it briefly flip to "—" and back to the same value. */
    watchController_.invalidatePlaceholder();

    /* One snapshot per pause entry: rotate last pause's "current" values
     * into the baseline so every refresh below compares against them.
     * This MUST happen before any refresh that walks the Watch / Variables
     * trees, otherwise the very first refresh would overwrite
     * *Current_ with this pause's values and the snapshot would then
     * rotate those values into *Baseline_, losing the "changed since last
     * pause" signal. updateWidgets() calls watchController_.refreshDisplay(), so it
     * counts as such a refresh and must be preceded by the rotation.
     *
     * The pause-entry refresh flag is also set here so that every refresh
     * inside the pause-entry sequence — including the one triggered by
     * updateWidgets() — gets the transient row-flash in addition to the
     * persistent bold accent. Subsequent intra-pause refreshes
     * (stack-frame switch, theme change, watch edit, eval) read from the
     * same baseline and stay stable. */
    snapshotBaselinesOnPauseEntry();
    /* Decide whether the just-rotated baseline still describes the same
     * Lua function at frame 0. It does not after a call or return, and the
     * cue must be suppressed for this one pause; see
     * changeHighlightAllowed() and updatePauseEntryFrameIdentity(). Must
     * run before the first refresh below so the gate is in effect for
     * every paint in the pause-entry sequence. */
    updatePauseEntryFrameIdentity();
    changeHighlight_.setPauseEntryRefresh(true);
    updateWidgets();

    resetStackForPauseEntry();
    variablesController_.rebuildFromEngine();
    watchController_.refreshDisplay();
    /* Pull in the latest hit_count / condition_error from core so the
     * Breakpoints row tooltips reflect what just happened on the way in
     * to this pause (logpoints and "below threshold" hits accumulate
     * silently without taking us through the pause path). */
    breakpointsController_.refreshFromEngine();
    changeHighlight_.setPauseEntryRefresh(false);

    /*
     * If an event loop is already running (e.g. we were called from a step
     * action which triggered an immediate re-pause), reuse it instead of nesting.
     * The outer loop.exec() is still on the stack and will return when we
     * eventually quit it via Continue or close.
     *
     * The outer frame already ran @ref LuaDebuggerPauseController::beginOuterFreeze;
     * the re-entrant call leaves that freeze in place.
     */
    if (pauseController_.hasActiveLoop())
    {
        return;
    }

    pauseController_.beginOuterFreeze();

    /* Note: live capture cannot be running here. The live-capture
     * observer (LuaDebuggerCaptureSuppression::onCaptureSessionEvent) force-disables the debugger
     * for the duration of any capture, so wslua_debug_hook never
     * dispatches into us while dumpcap is feeding the pipe. That is
     * the only sane policy: suspending the pipe GSource for the
     * duration of the pause is fragile (g_source_destroy frees the
     * underlying GIOChannel, breaking any later resume) and racing
     * the dumpcap child while a Lua dissector is on the C stack
     * invites re-entrant dissection of partially-read packets. */

    QEventLoop loop;
    pauseController_.setActiveLoop(&loop);

    /*
     * If the parent window is destroyed while we're paused (e.g. the
     * application is shutting down), quit the event loop so the Lua
     * call stack can unwind cleanly.
     */
    QPointer<QWidget> parentGuard(parentWidget());
    QMetaObject::Connection parentConn;
    if (parentGuard)
    {
        parentConn = connect(parentGuard, &QObject::destroyed, &loop, &QEventLoop::quit);
    }

    // Enter event loop - blocks until Continue or dialog close
    loop.exec();

    if (parentConn)
    {
        disconnect(parentConn);
    }

    /* Undo the pause-entry UI freeze. Idempotent — may already have
     * run from closeEvent() if the user closed the main window while
     * we were paused (see endPauseFreeze() for details). */
    pauseController_.endFreeze();

    // Restore delete-on-close behavior and clear event loop pointer
    pauseController_.clearActiveLoop();
    setAttribute(Qt::WA_DeleteOnClose, true);

    /*
     * If a Lua plugin reload was requested while we were paused,
     * schedule it now that the Lua/C call stack has fully unwound.
     * We must NOT schedule it from inside the event loop (via
     * QTimer::singleShot) because the timer can fire before the
     * loop exits, running cf_close/wslua_reload_plugins while
     * cf_read is still on the C call stack.
     */
    if (reloadCoordinator_.takeDeferredReload() && mainApp)
    {
        mainApp->reloadLuaPluginsDelayed();
    }

    /* If the user (or the OS, e.g. macOS Dock-Quit) tried to close
     * the main window while we were paused, MainWindow::closeEvent
     * recorded the request via LuaDebuggerMainClosePolicy::
     * handleMainCloseIfPaused() and ignored the QCloseEvent. The pause
     * has now ended, so re-issue the close on the main window. Queued
     * so it runs after the Lua C stack above us has unwound. */
    LuaDebuggerMainClosePolicy::deliverDeferredMainCloseIfPending();

    /* If the debugger window was closed while paused, closeEvent ran with
     * WA_DeleteOnClose temporarily disabled, so Qt hid the dialog but kept
     * this instance alive until the pause loop unwound. Tear that hidden
     * instance down now so the next open always starts from a fresh, fully
     * initialized dialog state instead of reusing a half-torn-down one. */
    if (!isVisible())
    {
        deleteLater();
    }
}

void LuaDebuggerDialog::onContinue()
{
    resumeDebuggerAndExitLoop();
    updateWidgets();
}

void LuaDebuggerDialog::runDebuggerStep(void (*step_fn)(void))
{
    if (!debuggerPaused)
    {
        return;
    }

    debuggerPaused = false;
    clearPausedStateUi();

    /*
     * The step function resumes the VM and may synchronously hit handlePause()
     * again. handlePause() detects that the pause loop is already active and
     * reuses it instead of nesting a new one — so the stack does NOT grow with each
     * step.
     */
    step_fn();

    /* Synchronous re-pause: handlePause() already ran the full refresh
     * (including the Watch tree) with debuggerPaused=true. Anything we do
     * here would either be redundant or, worse, blank the freshly painted
     * values back to the "—" placeholder. */
    if (debuggerPaused)
    {
        return;
    }

    /*
     * If handlePause() was NOT called (e.g. step landed in C code
     * and the hook didn't fire), we need to quit the event loop so
     * the original handlePause() caller can return.
     */
    pauseController_.quitLoop();

    /* Update the non-Watch chrome (window title, action enabled-state, eval
     * panel placeholder) immediately so the user sees the debugger is no
     * longer paused. The Watch tree is a special case: a typical step
     * re-pauses within a few ms and immediately blanking every Watch value
     * to "—" only to repaint the same value right back looks like every
     * row is "blinking". The watch controller defers the placeholder
     * application via @ref LuaDebuggerWatchController::scheduleDeferredPlaceholder;
     * an arriving handlePause() bumps the epoch and the deferred refresh
     * becomes a no-op. If no pause arrives in the deferral window
     * (long-running step, script ended), the placeholder is applied
     * normally so stale values are not left displayed. */
    updateEnabledCheckboxIcon();
    updateStatusLabel();
    updateContinueActionState();
    evalController_.updatePanelState();

    watchController_.scheduleDeferredPlaceholder();
}

void LuaDebuggerDialog::onStepOver()
{
    runDebuggerStep(wslua_debugger_step_over);
}

void LuaDebuggerDialog::onStepIn()
{
    runDebuggerStep(wslua_debugger_step_in);
}

void LuaDebuggerDialog::onStepOut()
{
    runDebuggerStep(wslua_debugger_step_out);
}

void LuaDebuggerDialog::onDebuggerToggled(bool checked)
{
    if (LuaDebuggerCaptureSuppression::isActive())
    {
        /* The checkbox is normally setEnabled(false) while a live
         * capture is running, but a programmatic toggle (e.g. via
         * QAbstractButton::click in tests, or any path that bypasses
         * the disabled state) must not be allowed to flip the core
         * enable on or off. Remember the user's intent so it is
         * applied automatically when the capture stops, and re-sync
         * the checkbox to the (still suppressed) core state. */
        LuaDebuggerCaptureSuppression::setPrevEnabled(checked);
        refreshDebuggerStateUi();
        return;
    }
    wslua_debugger_set_user_explicitly_disabled(!checked);
    if (!checked && debuggerPaused)
    {
        onContinue();
    }
    wslua_debugger_set_enabled(checked);
    if (!checked)
    {
        debuggerPaused = false;
        clearPausedStateUi();
        /* Disabling the debugger breaks the "changed since last pause"
         * chain; drop every baseline so the next enable → pause cycle
         * starts clean instead of comparing against a stale snapshot. */
        clearAllChangeBaselines();
    }
    refreshDebuggerStateUi();
}

void LuaDebuggerDialog::reject()
{
    /* Base QDialog::reject() calls done(Rejected), which hides() without
     * delivering QCloseEvent, so our closeEvent() unsaved-scripts check does
     * not run (e.g. Esc). Synchronous close() from keyPressEvent → reject()
     * can fail to finish closing; queue close() so closeEvent() runs on the
     * next event-loop turn (same path as the window close control). */
    QMetaObject::invokeMethod(this, "close", Qt::QueuedConnection);
}

void LuaDebuggerDialog::closeEvent(QCloseEvent *event)
{
    const bool pausedOnEntry = debuggerPaused || wslua_debugger_is_paused();
    if (!codeTabsController_.ensureUnsavedChangesHandled(tr("Lua Debugger")))
    {
        /* User cancelled the debugger unsaved-file prompt; cancel any
         * deferred app-quit request attached to this close attempt. */
        LuaDebuggerMainClosePolicy::cancelPendingClose();
        event->ignore();
        return;
    }

    storeDialogSettings();
    /* Keep the toolbar checkbox preference as stored by storeDialogSettings()
     * (typically still checked if the user had debugging on). The C core is
     * forced off below and user_explicitly_disabled stays true until the next
     * dialog ctor runs applyDialogSettings(), which seeds both from JSON again.
     * Forcing DebuggerEnabled false here broke reopen: the next session always
     * loaded "off" even when the user had left the checkbox on. */
    saveSettingsFile();
    luaDebuggerJsonSaved_ = true;

    /* Disable the debugger so breakpoints won't fire and reopen the
     * dialog after it has been closed. */
    /* Must stay true: if we clear user_explicitly_disabled, dissect will call
     * wslua_debugger_init() and re-enable whenever active breakpoints exist,
     * which pops this dialog again on the next hit. */
    wslua_debugger_set_user_explicitly_disabled(true);
    wslua_debugger_set_enabled(false);
    resumeDebuggerAndExitLoop();
    debuggerPaused = false;
    clearPausedStateUi();
    refreshDebuggerStateUi();

    /* Tear the pause freeze down synchronously. If this closeEvent is
     * running because WiresharkMainWindow::closeEvent called
     * dbg->close() while the debugger was paused, control returns to
     * main_window's closeEvent as soon as we return — and its
     * tryClosingCaptureFile() may pop up a "Save unsaved capture?"
     * modal that must be interactive. The nested QEventLoop inside
     * handlePause has been asked to quit by resumeDebuggerAndExitLoop
     * above but hasn't unwound yet; by the time it does,
     * endPauseFreeze() there is a no-op if the freeze was already torn down. */
    endPauseFreeze();

    /* For non-paused closes we can re-deliver a deferred main close now.
     * Paused closes must wait for handlePause() post-loop cleanup so the
     * Lua C stack is unwound first. */
    if (!pausedOnEntry)
    {
        LuaDebuggerMainClosePolicy::deliverDeferredMainCloseIfPending();
    }

    /*
     * Do not call QDialog::closeEvent (GeometryStateDialog inherits it):
     * QDialog::closeEvent invokes reject(); our reject() queues close()
     * asynchronously, so the dialog stays visible and Qt then ignores the
     * close event (see qdialog.cpp: if (that && isVisible()) e->ignore()).
     * QWidget::closeEvent only accepts the event so the window can close.
     */
    QWidget::closeEvent(event);
}

bool LuaDebuggerDialog::event(QEvent *event)
{
    switch (event->type())
    {
    case QEvent::ApplicationPaletteChange:
        /*
         * Stylesheet-using widgets may not receive propagated palette updates
         * (see WiresharkMainWindow::updateStyleSheet). Refresh like WelcomePage.
         */
        onColorsChanged();
        break;
    default:
        break;
    }
    return GeometryStateDialog::event(event);
}

void LuaDebuggerDialog::showEvent(QShowEvent *event)
{
    GeometryStateDialog::showEvent(event);
    /* If the user has not left debugging explicitly off (persisted checkbox /
     * user_explicitly_disabled), turn the core on when breakpoints need it. */
    ensureDebuggerEnabledForActiveBreakpoints();
    updateWidgets();
    /* Catch up on any silent @c bp->hit_count++ bumps that landed
     * while the dialog was hidden — @ref drainBreakpointStateUpdates
     * gates on @c isVisible() so it would have skipped them. Now
     * that we're visible again, do one refresh and clear the
     * dirty bit so future bumps re-arm the trampoline normally. */
    drainBreakpointStateUpdates();
}

void LuaDebuggerDialog::handleEscapeKey()
{
    QWidget *const modal = QApplication::activeModalWidget();
    if (modal && modal != this)
    {
        return;
    }
    if (ui->luaDebuggerFindFrame->isVisible())
    {
        ui->luaDebuggerFindFrame->animatedHide();
        return;
    }
    if (ui->luaDebuggerGoToLineFrame->isVisible())
    {
        ui->luaDebuggerGoToLineFrame->animatedHide();
        return;
    }
    QMetaObject::invokeMethod(this, "close", Qt::QueuedConnection);
}

void LuaDebuggerDialog::installDescendantShortcutFilters()
{
    installEventFilter(this);
    for (QWidget *w : findChildren<QWidget *>())
    {
        w->installEventFilter(this);
    }
}

void LuaDebuggerDialog::childEvent(QChildEvent *event)
{
    if (event->added())
    {
        if (auto *w = qobject_cast<QWidget *>(event->child()))
        {
            w->installEventFilter(this);
            for (QWidget *d : w->findChildren<QWidget *>())
            {
                d->installEventFilter(this);
            }
        }
    }
    QDialog::childEvent(event);
}

bool LuaDebuggerDialog::eventFilter(QObject *obj, QEvent *event)
{
    QWidget *const receiver = qobject_cast<QWidget *>(obj);
    const bool inDebuggerUi = receiver && isVisible() && isAncestorOf(receiver);

    if (inDebuggerUi && event->type() == QEvent::ShortcutOverride)
    {
        auto *ke = static_cast<QKeyEvent *>(event);
        if (keyRouter_.reserveShortcutOverride(ke))
        {
            ke->accept();
            return false;
        }
    }

    if (inDebuggerUi && event->type() == QEvent::KeyPress)
    {
        auto *ke = static_cast<QKeyEvent *>(event);
        if (keyRouter_.handleKeyPress(obj, ke))
        {
            return true;
        }
    }
    return QDialog::eventFilter(obj, event);
}

void LuaDebuggerDialog::showAccordionFrame(AccordionFrame *show_frame, bool toggle)
{
    QList<AccordionFrame *> frame_list = QList<AccordionFrame *>()
                                         << ui->luaDebuggerFindFrame << ui->luaDebuggerGoToLineFrame;
    frame_list.removeAll(show_frame);
    for (AccordionFrame *af : frame_list)
    {
        if (af)
        {
            af->animatedHide();
        }
    }
    if (!show_frame)
    {
        return;
    }
    if (toggle && show_frame->isVisible())
    {
        show_frame->animatedHide();
        return;
    }
    LuaDebuggerGoToLineFrame *const goto_frame = qobject_cast<LuaDebuggerGoToLineFrame *>(show_frame);
    if (goto_frame)
    {
        goto_frame->syncLineFieldFromEditor();
    }
    show_frame->animatedShow();
    if (LuaDebuggerFindFrame *const find_frame = qobject_cast<LuaDebuggerFindFrame *>(show_frame))
    {
        find_frame->scheduleFindFieldFocus();
    }
    else if (goto_frame)
    {
        goto_frame->scheduleLineFieldFocus();
    }
}

void LuaDebuggerDialog::updateLuaEditorAuxFrames()
{
    QPlainTextEdit *ed = codeTabsController_.currentCodeView();
    ui->luaDebuggerFindFrame->setTargetEditor(ed);
    ui->luaDebuggerGoToLineFrame->setTargetEditor(ed);
}

void LuaDebuggerDialog::updatePausedErrorFrame()
{
    if (!ui->luaDebuggerErrorFrame)
    {
        return;
    }

    const char *lastError = wslua_debugger_consume_error_text();
    if (!lastError)
    {
        scheduleErrorFrameHide(120);
        return;
    }

    /* New break-on-error pause supersedes any pending delayed hide from the
     * immediately preceding resume/non-break-on-error pause. */
    cancelErrorFrameHide();

    QString errorMessage = QString::fromUtf8(lastError);

    /* Strip leading file:line prefixes so the frame displays message-only text. */
    static const QRegularExpression kLuaErrPrefixRegex(
        QStringLiteral(R"(^\s*(?:@?[^:\n]+(?:\:[^:\n]+)*)\:\d+\:\s*)"));
    errorMessage.remove(kLuaErrPrefixRegex);
    if (errorMessage.trimmed().isEmpty())
    {
        errorMessage = tr("(runtime error)");
    }

    if (QPlainTextEdit *ed = codeTabsController_.currentCodeView())
    {
        ui->luaDebuggerErrorFrame->setEditorStyleFont(ed->font());
    }

    ui->luaDebuggerErrorFrame->setErrorMessage(errorMessage);
    ui->luaDebuggerErrorFrame->show();
}

void LuaDebuggerDialog::cancelErrorFrameHide()
{
    ++errorFrameHideEpoch_;
}

void LuaDebuggerDialog::scheduleErrorFrameHide(int delayMs)
{
    if (!ui || !ui->luaDebuggerErrorFrame)
    {
        return;
    }

    const int hideEpoch = ++errorFrameHideEpoch_;
    QTimer::singleShot(
        delayMs, this,
        [this, hideEpoch]()
        {
            if (!ui || !ui->luaDebuggerErrorFrame)
            {
                return;
            }
            if (errorFrameHideEpoch_ != hideEpoch)
            {
                return;
            }
            ui->luaDebuggerErrorFrame->clearErrorContent();
            ui->luaDebuggerErrorFrame->hide();
        });
}

void LuaDebuggerDialog::onEditorFind()
{
    updateLuaEditorAuxFrames();
    showAccordionFrame(ui->luaDebuggerFindFrame, true);
}

void LuaDebuggerDialog::onEditorGoToLine()
{
    updateLuaEditorAuxFrames();
    showAccordionFrame(ui->luaDebuggerGoToLineFrame, true);
}

void LuaDebuggerDialog::onCodeViewContextMenu(const QPoint &pos)
{
    LuaDebuggerCodeView *codeView = qobject_cast<LuaDebuggerCodeView *>(sender());
    if (!codeView)
        return;

    QMenu menu(this);

    QAction *undoAct = menu.addAction(tr("Undo"));
    undoAct->setShortcut(QKeySequence::Undo);
    undoAct->setEnabled(codeView->document()->isUndoAvailable());
    connect(undoAct, &QAction::triggered, codeView, &QPlainTextEdit::undo);

    QAction *redoAct = menu.addAction(tr("Redo"));
    redoAct->setShortcut(QKeySequence::Redo);
    redoAct->setEnabled(codeView->document()->isRedoAvailable());
    connect(redoAct, &QAction::triggered, codeView, &QPlainTextEdit::redo);

    menu.addSeparator();

    QAction *cutAct = menu.addAction(tr("Cut"));
    cutAct->setShortcut(QKeySequence::Cut);
    cutAct->setEnabled(codeView->textCursor().hasSelection());
    connect(cutAct, &QAction::triggered, codeView, &QPlainTextEdit::cut);

    QAction *copyAct = menu.addAction(tr("Copy"));
    copyAct->setShortcut(QKeySequence::Copy);
    copyAct->setEnabled(codeView->textCursor().hasSelection());
    connect(copyAct, &QAction::triggered, codeView, &QPlainTextEdit::copy);

    QAction *pasteAct = menu.addAction(tr("Paste"));
    pasteAct->setShortcut(QKeySequence::Paste);
    pasteAct->setEnabled(codeView->canPaste());
    connect(pasteAct, &QAction::triggered, codeView, &QPlainTextEdit::paste);

    QAction *selAllAct = menu.addAction(tr("Select All"));
    selAllAct->setShortcut(QKeySequence::SelectAll);
    connect(selAllAct, &QAction::triggered, codeView, &QPlainTextEdit::selectAll);

    menu.addSeparator();
    menu.addAction(ui->actionFind);
    menu.addAction(ui->actionGoToLine);

    menu.addSeparator();

    QTextCursor cursor = codeView->cursorForPosition(pos);
    const qint32 lineNumber = static_cast<qint32>(cursor.blockNumber() + 1);

    // Check if breakpoint exists
    const int32_t state = wslua_debugger_get_breakpoint_state(codeView->getFilename().toUtf8().constData(), lineNumber);

    if (state == -1)
    {
        QAction *addBp = menu.addAction(tr("Add Breakpoint"));
        addBp->setShortcut(kLuaDbgCtxToggleBreakpoint);
        connect(addBp, &QAction::triggered,
                [this, codeView, lineNumber]() { breakpointsController_.toggleOnCodeViewLine(codeView, lineNumber); });
    }
    else
    {
        QAction *removeBp = menu.addAction(tr("Remove Breakpoint"));
        removeBp->setShortcut(kLuaDbgCtxToggleBreakpoint);
        connect(removeBp, &QAction::triggered,
                [this, codeView, lineNumber]() { breakpointsController_.toggleOnCodeViewLine(codeView, lineNumber); });
    }

    if (pauseController_.hasActiveLoop())
    { // Only if paused
        QAction *runToLine = menu.addAction(tr("Run to this line"));
        runToLine->setShortcut(kLuaDbgCtxRunToLine);
        connect(runToLine, &QAction::triggered,
                [this, codeView, lineNumber]() { runToCurrentLineInPausedEditor(codeView, lineNumber); });
    }

    /* Add Watch is available regardless of paused state, mirroring the
     * toolbar action and the Watch-panel header `+` button. Prefer the
     * current selection; otherwise fall back to the Lua identifier at the
     * right-click position so a single right-click on a variable name is
     * enough — no manual selection required. While the debugger is not
     * paused the watch row simply renders a muted em dash for its
     * value and resolves on the next pause. */
    {
        const QString watchSpec = codeView->watchExpressionForContextMenu(pos);
        if (!watchSpec.isEmpty())
        {
            menu.addSeparator();
            const QString shortLabel = watchSpec.length() > 48 ? watchSpec.left(48) + QStringLiteral("…") : watchSpec;
            QAction *addWatch = menu.addAction(tr("Add Watch: \"%1\"").arg(shortLabel));
            addWatch->setShortcut(ui->actionAddWatch->shortcut());
            connect(addWatch, &QAction::triggered,
                    [this, watchSpec]()
                    {
                        /* Both path watches (Locals.x, Globals.t.k) and
                         * expression watches (e.g. pinfo.src:tostring(),
                         * #packets) are accepted; the watch panel decides
                         * how to evaluate based on whether the text
                         * validates as a Variables-tree path. */
                        addWatchFromSpec(watchSpec.trimmed());
                    });
        }
    }

    menu.exec(codeView->mapToGlobal(pos));
}

void LuaDebuggerDialog::onMonospaceFontUpdated(const QFont &font)
{
    fontPolicy_.applyToCodeEditors(font);
}

void LuaDebuggerDialog::onMainAppInitialized()
{
    fontPolicy_.applyAll();
}

void LuaDebuggerDialog::onPreferencesChanged()
{
    applyCodeViewThemes();
    fontPolicy_.applyAll();
    watchController_.refreshDisplay();
}

void LuaDebuggerDialog::onThemeChanged(int idx)
{
    if (themeComboBox)
    {
        int32_t theme = themeComboBox->itemData(idx).toInt();

        /* Update static theme for CodeView syntax highlighting */
        currentTheme_ = theme;

        /* Store theme in our JSON settings */
        if (theme == WSLUA_DEBUGGER_THEME_DARK)
            settingsStore_.map()[LuaDebuggerSettingsKeys::Theme] = "dark";
        else if (theme == WSLUA_DEBUGGER_THEME_LIGHT)
            settingsStore_.map()[LuaDebuggerSettingsKeys::Theme] = "light";
        else
            settingsStore_.map()[LuaDebuggerSettingsKeys::Theme] = "auto";

        applyCodeViewThemes();
    }
}

void LuaDebuggerDialog::onColorsChanged()
{
    /*
     * When Wireshark's color scheme changes and the debugger theme is set to
     * "Auto (follow color scheme)", we need to re-apply themes to all code
     * views. The applyCodeViewThemes() function will query
     * ThemeManager::instance()->isDark() to determine the effective theme.
     */
    applyCodeViewThemes();
    watchController_.refreshDisplay();
}

void LuaDebuggerDialog::updateStyleSheets()
{
    ui->toolBar->setStyleSheet(QStringLiteral("QToolBar {"
                                              "  background-color: palette(window);"
                                              "  border: none;"
                                              "  spacing: 4px;"
                                              "  padding: 2px 4px;"
                                              "}"));

    ui->luaDebuggerFindFrame->updateStyleSheet();
    ui->luaDebuggerGoToLineFrame->updateStyleSheet();

    /* StockIcon template glyphs use qApp->palette(); re-resolve when the
     * scheme changes (same idea as StockIconToolButton). */
    ui->actionContinue->setIcon(StockIcon(QStringLiteral("x-lua-debug-continue")));
    ui->actionStepOver->setIcon(StockIcon(QStringLiteral("x-lua-debug-step-over")));
    ui->actionStepIn->setIcon(StockIcon(QStringLiteral("x-lua-debug-step-in")));
    ui->actionStepOut->setIcon(StockIcon(QStringLiteral("x-lua-debug-step-out")));
    ui->actionRunToLine->setIcon(StockIcon(QStringLiteral("x-lua-debug-run-to-line")));
}

void LuaDebuggerDialog::applyCodeViewThemes()
{
    updateStyleSheets();

    /* Theme / palette changed — recompute the accent + flash brushes used
     * by applyChangedVisuals so the Watch and Variables cues track the
     * active light/dark theme. */
    refreshChangedValueBrushes();
    codeTabsController_.applyThemeToAllTabs();
}

QString LuaDebuggerDialog::normalizedFilePath(const QString &file_path) const
{
    QString trimmed = file_path.trimmed();
    if (trimmed.startsWith("@"))
    {
        trimmed = trimmed.mid(1);
    }

    QFileInfo info(trimmed);
    QString absolutePath = info.absoluteFilePath();

    if (info.exists())
    {
        QString canonical = info.canonicalFilePath();
        if (!canonical.isEmpty())
        {
            return canonical;
        }
        return QDir::cleanPath(absolutePath);
    }

    if (!absolutePath.isEmpty())
    {
        return QDir::cleanPath(absolutePath);
    }

    return trimmed;
}

void LuaDebuggerDialog::clearPausedStateUi()
{
    if (variablesTree)
    {
        if (variablesModel)
        {
            variablesModel->removeRows(0, variablesModel->rowCount());
        }
    }
    clearStackPanel();
    codeTabsController_.clearAllCodeHighlights();
    /* Drop the pause location and refresh the breakpoints tree so the
     * row that was highlighted while paused returns to its normal
     * appearance. Doing it here (rather than at every individual resume
     * site) keeps the cue tied to the same teardown that already wipes
     * the editor's pause-line stripe and the Variables / Stack trees. */
    const bool hadPauseLocation = !pausedFile_.isEmpty();
    pausedFile_.clear();
    pausedLine_ = 0;
    if (hadPauseLocation && breakpointsModel)
    {
        breakpointsController_.refreshFromEngine();
    }

    if (ui->luaDebuggerErrorFrame)
    {
        scheduleErrorFrameHide(120);
    }
}

void LuaDebuggerDialog::resumeDebuggerAndExitLoop()
{
    if (debuggerPaused)
    {
        wslua_debugger_continue();
        debuggerPaused = false;
        clearPausedStateUi();
    }

    pauseController_.quitLoop();
}

void LuaDebuggerDialog::endPauseFreeze()
{
    pauseController_.endFreeze();
}

void LuaDebuggerDialog::syncDebuggerToggleWithCore()
{
    if (!enabledCheckBox)
    {
        return;
    }
    const bool debuggerEnabled = wslua_debugger_is_enabled();
    bool previousState = enabledCheckBox->blockSignals(true);
    enabledCheckBox->setChecked(debuggerEnabled);
    enabledCheckBox->blockSignals(previousState);
    /* Lock the toggle while a live capture is forcing the debugger
     * off so the checkbox cannot drift out of sync with the core
     * state, and the user gets an obvious "this is intentional, not
     * me" affordance. The disabled icon's tooltip explains why. */
    enabledCheckBox->setEnabled(!LuaDebuggerCaptureSuppression::isActive());
}

void LuaDebuggerDialog::refreshDebuggerStateUi()
{
    /* Full reconciliation is centralized in updateWidgets() (which syncs
     * the checkbox to the C core, then repaints status chrome). */
    updateWidgets();
}

LuaDebuggerDialog::DebuggerUiStatus LuaDebuggerDialog::currentDebuggerUiStatus() const
{
    const bool debuggerEnabled = wslua_debugger_is_enabled();
    const bool showPausedChrome = wslua_debugger_is_paused() || (debuggerEnabled && debuggerPaused);
    if (showPausedChrome)
    {
        return DebuggerUiStatus::Paused;
    }
    if (!debuggerEnabled)
    {
        if (LuaDebuggerCaptureSuppression::isActive())
        {
            return DebuggerUiStatus::DisabledLiveCapture;
        }
        return DebuggerUiStatus::Disabled;
    }
    return DebuggerUiStatus::Running;
}

void LuaDebuggerDialog::updateEnabledCheckboxIcon()
{
    if (!enabledCheckBox)
    {
        return;
    }

    // Create a colored circle icon to indicate enabled/disabled state.
    // Render at the screen's native pixel density so the circle stays
    // crisp on Retina / HiDPI displays instead of being upscaled from
    // a 16x16 bitmap.
    const qreal dpr = enabledCheckBox->devicePixelRatioF();
    QPixmap pixmap(QSize(16, 16) * dpr);
    pixmap.setDevicePixelRatio(dpr);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);

    const DebuggerUiStatus uiStatus = currentDebuggerUiStatus();
    QColor fill;
    switch (uiStatus)
    {
    case DebuggerUiStatus::Paused:
        // Yellow circle for paused
        fill = QColor("#FFC107");
        enabledCheckBox->setToolTip(tr("Debugger is paused. Uncheck to disable."));
        break;
    case DebuggerUiStatus::Running:
        // Green circle for enabled
        fill = QColor("#28A745");
        enabledCheckBox->setToolTip(tr("Debugger is enabled. Uncheck to disable."));
        break;
    case DebuggerUiStatus::DisabledLiveCapture:
        // Red circle with a "locked by live capture" tooltip so
        // the user understands the toggle is inert by design.
        fill = QColor("#DC3545");
        enabledCheckBox->setToolTip(tr("Debugger is disabled while a live capture is running. "
                                       "Stop the capture to re-enable."));
        break;
    case DebuggerUiStatus::Disabled:
        // Gray circle for disabled
        fill = QColor("#808080");
        enabledCheckBox->setToolTip(tr("Debugger is disabled. Check to enable."));
        break;
    }

    // Thin darker rim gives the circle definition on both light and dark backgrounds.
    painter.setBrush(fill);
    painter.setPen(QPen(fill.darker(140), 1));
    painter.drawEllipse(QRectF(2.5, 2.5, 12.0, 12.0));
    painter.end();

    /* Register the colored pixmap for BOTH QIcon::Normal and
     * QIcon::Disabled. The checkbox widget is disabled in the
     * "suppressed by live capture" state (see
     * syncDebuggerToggleWithCore), and with only a Normal pixmap
     * supplied, Qt synthesizes a Disabled pixmap by desaturating it.
     * macOS's Cocoa style does this subtly enough that the red stays
     * visible, but Linux styles (Fusion / Breeze / Adwaita / gtk3)
     * desaturate aggressively, making the red circle look gray. */
    QIcon icon;
    icon.addPixmap(pixmap, QIcon::Normal);
    icon.addPixmap(pixmap, QIcon::Disabled);
    enabledCheckBox->setIcon(icon);
}

void LuaDebuggerDialog::updateStatusLabel()
{
    const DebuggerUiStatus uiStatus = currentDebuggerUiStatus();
    /* [*] is required for setWindowModified() to show an unsaved
     * indicator in the title. */
    QString title = QStringLiteral("[*]%1").arg(tr("Lua Debugger"));

#ifdef Q_OS_MAC
    // On macOS we separate with a unicode em dash
    title += QString(" " UTF8_EM_DASH " ");
#else
    title += QString(" - ");
#endif

    switch (uiStatus)
    {
    case DebuggerUiStatus::Paused:
        title += tr("Paused");
        break;
    case DebuggerUiStatus::DisabledLiveCapture:
        title += tr("Disabled (live capture)");
        break;
    case DebuggerUiStatus::Disabled:
        title += tr("Disabled");
        break;
    case DebuggerUiStatus::Running:
        title += tr("Running");
        break;
    }

    setWindowTitle(title);
    codeTabsController_.updateWindowModifiedState();
}

void LuaDebuggerDialog::updateContinueActionState()
{
    const bool allowContinue = wslua_debugger_is_enabled() && debuggerPaused;
    ui->actionContinue->setEnabled(allowContinue);
    ui->actionStepOver->setEnabled(allowContinue);
    ui->actionStepIn->setEnabled(allowContinue);
    ui->actionStepOut->setEnabled(allowContinue);
    /* Run to this line additionally requires a focusable line in the editor,
     * i.e. an active code view tab. */
    ui->actionRunToLine->setEnabled(allowContinue && codeTabsController_.currentCodeView() != nullptr);
}

void LuaDebuggerDialog::setSaveActionEnabled(bool enabled)
{
    ui->actionSaveFile->setEnabled(enabled);
}

bool LuaDebuggerDialog::tearDownPauseLoopForReload()
{
    if (!debuggerPaused || !pauseController_.hasActiveLoop())
    {
        return false;
    }
    debuggerPaused = false;
    clearPausedStateUi();
    refreshDebuggerStateUi();
    pauseController_.quitLoop();
    return true;
}

void LuaDebuggerDialog::updateWidgets()
{
#ifndef QT_NO_DEBUG
    if (wslua_debugger_is_paused())
    {
        Q_ASSERT(wslua_debugger_is_enabled());
    }
#endif
    syncDebuggerToggleWithCore();
    updateEnabledCheckboxIcon();
    updateStatusLabel();
    updateContinueActionState();
    evalController_.updatePanelState();
    watchController_.refreshDisplay();
}

void LuaDebuggerDialog::ensureDebuggerEnabledForActiveBreakpoints()
{
    /* wslua_debugger owns enable *policy*; live capture gating is owned by
     * LuaDebuggerCaptureSuppression: epan has no knowledge of the capture path. */
    const bool shouldBeEnabled = wslua_debugger_may_auto_enable_for_breakpoints();
    if (LuaDebuggerCaptureSuppression::isActive())
    {
        /* During live capture, snapshot desired post-capture state but do not
         * flip the core debugger immediately. */
        LuaDebuggerCaptureSuppression::setPrevEnabled(shouldBeEnabled);
        refreshDebuggerStateUi();
        return;
    }

    const bool currentlyEnabled = wslua_debugger_is_enabled();
    if (shouldBeEnabled && !currentlyEnabled)
    {
        wslua_debugger_set_enabled(true);
    }
    else if (!shouldBeEnabled && currentlyEnabled)
    {
        if (debuggerPaused)
        {
            resumeDebuggerAndExitLoop();
        }
        wslua_debugger_set_enabled(false);
    }
    refreshDebuggerStateUi();
}

void LuaDebuggerDialog::onOpenFile()
{
    const QString filePath =
        WiresharkFileDialog::getOpenFileName(this, tr("Open Lua Script"), codeTabsController_.lastOpenDirectory(),
                                             tr("Lua Scripts (*.lua);;All Files (*)"));

    if (filePath.isEmpty())
    {
        return;
    }

    codeTabsController_.setLastOpenDirectory(QFileInfo(filePath).absolutePath());
    codeTabsController_.loadFile(filePath);
}

void LuaDebuggerDialog::onRunToLine()
{
    LuaDebuggerCodeView *codeView = codeTabsController_.currentCodeView();
    if (!codeView || !pauseController_.hasActiveLoop())
    {
        return;
    }
    const qint32 line = static_cast<qint32>(codeView->textCursor().blockNumber() + 1);
    runToCurrentLineInPausedEditor(codeView, line);
}

void LuaDebuggerDialog::onAddWatch()
{
    QString fromEditor;
    if (LuaDebuggerCodeView *cv = codeTabsController_.currentCodeView())
    {
        if (cv->textCursor().hasSelection())
        {
            fromEditor = cv->textCursor().selectedText().trimmed();
        }
    }
    if (fromEditor.isEmpty())
    {
        watchController_.insertNewRow(QString(), true);
    }
    else
    {
        watchController_.insertNewRow(fromEditor, false);
    }
}

void LuaDebuggerDialog::runToCurrentLineInPausedEditor(LuaDebuggerCodeView *codeView, qint32 line)
{
    if (!codeView || !pauseController_.hasActiveLoop() || line < 1)
    {
        return;
    }
    ensureDebuggerEnabledForActiveBreakpoints();
    wslua_debugger_run_to_line(codeView->getFilename().toUtf8().constData(), line);
    pauseController_.quitLoop();
    debuggerPaused = false;
    updateWidgets();
    clearPausedStateUi();
}

void LuaDebugger::open(QWidget *parent)
{
    LuaDebuggerDialog *dialog = LuaDebuggerDialog::instance(parent);
    if (dialog->isMinimized())
    {
        dialog->showNormal();
    }
    dialog->show();
    dialog->raise();
    dialog->activateWindow();
}

bool LuaDebugger::tryDeferMainWindowClose(QCloseEvent *event)
{
    return LuaDebuggerDialog::handleMainCloseIfPaused(event);
}

/* Drain entry point: defined as a slot on LuaDebuggerDialog so
 * QMetaObject::invokeMethod by name can reach it from the log-emit
 * trampoline above. */
void LuaDebuggerDialog::drainPendingLogs()
{
    /* Swap-and-release the queue under the mutex so further trampoline
     * calls reschedule us without contending with the GUI-side append
     * loop below. */
    QStringList batch;
    {
        QMutexLocker lock(&g_logEmitMutex);
        batch.swap(g_pendingLogMessages);
        g_logDrainScheduled = false;
    }
    if (batch.isEmpty())
    {
        return;
    }
    evalController().appendOutputLines(batch);
    /* Breakpoints @em Hits column refresh is handled by the silent-
     * bump trampoline (@ref drainBreakpointStateUpdates) — both the
     * non-pausing logpoint path and the below-threshold no-log path
     * funnel through it, so we don't repeat the refresh here. */
}

void LuaDebuggerDialog::drainBreakpointStateUpdates()
{
    /* Visibility gate: the model rebuild is wasted work when the
     * dialog isn't on screen. Intentionally leave the C-side dirty
     * bit set so subsequent bumps don't pay for queueing either —
     * @ref showEvent re-invokes this drain to catch up the moment
     * the dialog reopens. */
    if (!isVisible())
    {
        return;
    }
    /* Clear BEFORE the refresh: any concurrent @c bp->hit_count++
     * that lands while we're rebuilding the model will re-arm the
     * trampoline and be picked up by a follow-up drain on the next
     * event-loop tick. Clearing after would race the bump and could
     * lose it. */
    wslua_debugger_clear_breakpoint_state_dirty();
    breakpointsController_.refreshFromEngine();
}

namespace LuaDebuggerMainClosePolicy
{

namespace
{

/** @brief Process-global pending-close flag. There is at most one main
 *  window per process, so a single bool covers every entry path
 *  (main-window close, debugger Ctrl+Q, macOS Dock-Quit fan-out, etc.). */
bool s_mainCloseDeferredByPause = false;

} // namespace

bool handleMainCloseIfPaused(QCloseEvent *event)
{
    LuaDebuggerDialog *const dbg = LuaDebuggerDialog::instanceIfExists();
    if (!wslua_debugger_is_paused())
    {
        /* Keep main-window quit and debugger Ctrl+Q consistent: if the
         * debugger owns unsaved script edits, run the debugger close gate
         * first so Save/Discard/Cancel semantics stay identical. */
        if (!dbg || !dbg->isVisible() || !dbg->codeTabsController().hasUnsavedChanges())
        {
            return false;
        }
        event->ignore();
        s_mainCloseDeferredByPause = true;
        QMetaObject::invokeMethod(dbg, "close", Qt::QueuedConnection);
        dbg->raise();
        dbg->activateWindow();
        return true;
    }
    event->ignore();
    s_mainCloseDeferredByPause = true;
    if (dbg)
    {
        dbg->raise();
        dbg->activateWindow();
    }
    return true;
}

void deliverDeferredMainCloseIfPending()
{
    if (!s_mainCloseDeferredByPause)
    {
        return;
    }
    s_mainCloseDeferredByPause = false;

    /* Queue the close on the next event loop tick rather than calling
     * close() inline. We are still inside handlePause()'s post-loop
     * cleanup; the Lua C stack above us has not unwound yet, and
     * MainWindow::closeEvent ultimately invokes mainApp->quit() which
     * tears down epan. */
    if (mainApp)
    {
        QWidget *const mw = mainApp->mainWindow();
        if (mw)
        {
            QMetaObject::invokeMethod(mw, "close", Qt::QueuedConnection);
        }
    }
}

void markQuitRequested()
{
    s_mainCloseDeferredByPause = true;
}

void cancelPendingClose()
{
    s_mainCloseDeferredByPause = false;
}

} // namespace LuaDebuggerMainClosePolicy

LuaDebuggerLuaReloadCoordinator::LuaDebuggerLuaReloadCoordinator(LuaDebuggerDialog *host) : QObject(host), host_(host)
{
}

bool LuaDebuggerLuaReloadCoordinator::takeDeferredReload()
{
    if (!reloadDeferred_)
    {
        return false;
    }
    reloadDeferred_ = false;
    return true;
}

void LuaDebuggerLuaReloadCoordinator::handlePreReload()
{
    if (!host_)
    {
        return;
    }

    host_->changeHighlight().clearAllChangeBaselines();
    enterReloadUiStateIfEnabled();

    if (host_->tearDownPauseLoopForReload())
    {
        reloadDeferred_ = true;
        return;
    }

    reloadAllScriptFilesFromDisk();

    if (QTabWidget *const tabs = host_->codeTabsController().tabs())
    {
        const qint32 tabCount = static_cast<qint32>(tabs->count());
        for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
        {
            LuaDebuggerCodeView *view =
                qobject_cast<LuaDebuggerCodeView *>(tabs->widget(static_cast<int>(tabIndex)));
            if (view)
            {
                view->updateBreakpointMarkers();
            }
        }
    }
    host_->refreshDebuggerStateUi();
}

void LuaDebuggerLuaReloadCoordinator::handlePostReload()
{
    if (!host_)
    {
        return;
    }
    exitReloadUiState();
    host_->filesController().refreshAvailableScripts();
    host_->breakpointsController().refreshFromEngine();
}

void LuaDebuggerLuaReloadCoordinator::reloadAllScriptFilesFromDisk()
{
    if (!host_)
    {
        return;
    }
    QTabWidget *const tabs = host_->codeTabsController().tabs();
    if (!tabs)
    {
        return;
    }

    const qint32 tabCount = static_cast<qint32>(tabs->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(tabs->widget(static_cast<int>(tabIndex)));
        if (view)
        {
            if (view->document()->isModified())
            {
                continue;
            }
            QString filePath = view->getFilename();
            if (!filePath.isEmpty())
            {
                QFile file(filePath);
                if (file.open(QIODevice::ReadOnly | QIODevice::Text))
                {
                    QTextStream in(&file);
                    QString content = in.readAll();
                    file.close();
                    view->setPlainText(content);
                }
            }
        }
    }
}

void LuaDebuggerLuaReloadCoordinator::enterReloadUiStateIfEnabled()
{
    if (!host_ || !host_->enabledToggle() || reloadUiActive_)
    {
        return;
    }

    bool shouldActivate = reloadUiRequestWasEnabled_;
    if (!shouldActivate)
    {
        shouldActivate = host_->enabledToggle()->isChecked();
    }
    if (!shouldActivate)
    {
        return;
    }

    reloadUiActive_ = true;

    host_->updateWidgets();
}

void LuaDebuggerLuaReloadCoordinator::exitReloadUiState()
{
    reloadUiRequestWasEnabled_ = false;
    if (!host_ || !host_->enabledToggle() || !reloadUiActive_)
    {
        return;
    }

    reloadUiActive_ = false;
    host_->refreshDebuggerStateUi();
}

void LuaDebuggerLuaReloadCoordinator::onReloadLuaPluginsRequested()
{
    if (!host_)
    {
        return;
    }

    reloadUiRequestWasEnabled_ = false;
    if (!host_->codeTabsController().ensureUnsavedChangesHandled(host_->tr("Reload Lua Plugins")))
    {
        return;
    }

    const QMessageBox::StandardButton reply =
        QMessageBox::question(host_, host_->tr("Reload Lua Plugins"),
                              host_->tr("Are you sure you want to reload all Lua plugins?\n\nThis will "
                                        "restart all Lua "
                                        "scripts and may affect capture analysis."),
                              QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (reply != QMessageBox::Yes)
    {
        return;
    }
    reloadUiRequestWasEnabled_ = wslua_debugger_is_enabled();

    if (host_->isDebuggerPaused())
    {
        wslua_debugger_notify_reload();
        host_->updateWidgets();
        return;
    }

    if (mainApp)
    {
        mainApp->reloadLuaPluginsDelayed();
    }
}
void LuaDebuggerDialog::createCollapsibleSections()
{
    QSplitter *splitter = ui->leftSplitter;

    splitter->addWidget(createVariablesSection(this));
    splitter->addWidget(createWatchSection(this));
    splitter->addWidget(createStackSection(this));
    splitter->addWidget(createBreakpointsSection(this));
    splitter->addWidget(createFilesSection(this));
    splitter->addWidget(createEvaluateSection(this));

    /* Settings panel is intentionally inline: a single QComboBox with no
     * dedicated controller does not warrant its own translation unit. */
    settingsSection = new CollapsibleSection(tr("Settings"), this);
    QWidget *settingsWidget = new QWidget();
    QFormLayout *settingsLayout = new QFormLayout(settingsWidget);
    settingsLayout->setContentsMargins(4, 4, 4, 4);
    settingsLayout->setSpacing(6);

    themeComboBox = new QComboBox();
    themeComboBox->addItem(tr("Auto (follow color scheme)"), WSLUA_DEBUGGER_THEME_AUTO);
    themeComboBox->addItem(tr("Dark"), WSLUA_DEBUGGER_THEME_DARK);
    themeComboBox->addItem(tr("Light"), WSLUA_DEBUGGER_THEME_LIGHT);
    themeComboBox->setToolTip(tr("Color theme for the code editor"));
    // Theme will be set by applyDialogSettings() later
    settingsLayout->addRow(tr("Code View Theme:"), themeComboBox);

    connect(themeComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            &LuaDebuggerDialog::onThemeChanged);

    settingsSection->setContentWidget(settingsWidget);
    settingsSection->setExpanded(false);
    splitter->addWidget(settingsSection);

    QList<int> sizes;
    int headerH = variablesSection->headerHeight();
    sizes << 120 << 70 << 100 << headerH << 80 << headerH << headerH;
    splitter->setSizes(sizes);

    /* Tell QSplitter that every section is allowed to absorb surplus
     * vertical space. Collapsed sections cap themselves at headerHeight via
     * setMaximumHeight, so this stretch only takes effect for sections that
     * are actually expanded; without it, expanding one section while the
     * others stay collapsed leaves the leftover height unallocated and the
     * expanded section never grows past its savedHeight. */
    for (int i = 0; i < splitter->count(); ++i)
        splitter->setStretchFactor(i, 1);

    /* Trailing stretch in leftPanelLayout: absorbs leftover vertical space
     * when every section is collapsed (in tandem with leftSplitter being
     * clamped to its content height by updateLeftPanelStretch()), so the
     * toolbar and section headers stay pinned to the top of the panel.
     * When at least one section is expanded the stretch is set to 0 and
     * the splitter takes all extra height. */
    ui->leftPanelLayout->addStretch(0);

    const QList<CollapsibleSection *> allSections = {variablesSection, watchSection, stackSection,   breakpointsSection,
                                                     filesSection,     evalSection,  settingsSection};
    for (CollapsibleSection *s : allSections)
        connect(s, &CollapsibleSection::toggled, this, &LuaDebuggerDialog::updateLeftPanelStretch);
    updateLeftPanelStretch();
}

void LuaDebuggerDialog::updateLeftPanelStretch()
{
    if (!ui || !ui->leftSplitter || !ui->leftPanelLayout)
        return;

    const QList<CollapsibleSection *> sections = {variablesSection, watchSection, stackSection,   breakpointsSection,
                                                  filesSection,     evalSection,  settingsSection};

    bool anyExpanded = false;
    int contentH = 0;
    int counted = 0;
    for (CollapsibleSection *s : sections)
    {
        if (!s)
            continue;
        if (s->isExpanded())
            anyExpanded = true;
        contentH += s->headerHeight();
        ++counted;
    }
    if (counted > 1)
        contentH += (counted - 1) * ui->leftSplitter->handleWidth();

    const int splitterIdx = ui->leftPanelLayout->indexOf(ui->leftSplitter);
    /* The trailing stretch is the last layout item appended in
     * createCollapsibleSections(). */
    const int stretchIdx = ui->leftPanelLayout->count() - 1;
    if (splitterIdx < 0 || stretchIdx < 0 || splitterIdx == stretchIdx)
        return;

    if (anyExpanded)
    {
        ui->leftSplitter->setMaximumHeight(QWIDGETSIZE_MAX);
        ui->leftPanelLayout->setStretch(splitterIdx, 1);
        ui->leftPanelLayout->setStretch(stretchIdx, 0);
    }
    else
    {
        ui->leftSplitter->setMaximumHeight(contentH);
        ui->leftPanelLayout->setStretch(splitterIdx, 0);
        ui->leftPanelLayout->setStretch(stretchIdx, 1);
    }
}
