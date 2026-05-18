/* lua_debugger_pause.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Pause UX: visual overlay and key capture that engage while the
 * debugger holds execution.
 */

#ifndef LUA_DEBUGGER_PAUSE_H
#define LUA_DEBUGGER_PAUSE_H

#include <QList>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QWidget>

class LuaDebuggerDialog;
class LuaDebuggerPauseOverlay;
class QAction;
class QEvent;
class QEventLoop;
class QPaintEvent;

/* ===== pause_controller ===== */

/**
 * @brief Owns the nested pause @c QEventLoop pointer and the application-wide
 *        freeze (disabled top-levels, actions, central widget, overlay, input
 *        filter) for the outermost @ref LuaDebuggerDialog::handlePause frame.
 */
class LuaDebuggerPauseController : public QObject
{
  public:
    /**
     * @brief Constructs a new LuaDebuggerPauseController object.
     * @param host Pointer to the hosting Lua debugger dialog.
     */
    explicit LuaDebuggerPauseController(LuaDebuggerDialog *host);

    /**
     * @brief Checks if there is an active nested event loop.
     * @return True if an active loop exists, false otherwise.
     */
    bool hasActiveLoop() const { return activeLoop_ != nullptr; }

    /**
     * @brief Retrieves the currently active nested event loop.
     * @return Pointer to the active QEventLoop.
     */
    QEventLoop *activeLoop() const { return activeLoop_; }

    /**
     * @brief Sets the active nested event loop.
     * @param loop Pointer to the QEventLoop to set as active.
     */
    void setActiveLoop(QEventLoop *loop) { activeLoop_ = loop; }

    /**
     * @brief Clears the reference to the active nested event loop.
     */
    void clearActiveLoop() { activeLoop_ = nullptr; }

    /**
     * @brief Quits the currently active nested event loop if one exists.
     */
    void quitLoop();

    /**
     * @brief Begins the application-wide outer freeze during a pause.
     */
    void beginOuterFreeze();

    /**
     * @brief Ends the application-wide outer freeze, restoring interactivity.
     */
    void endFreeze();

  private:
    /** @brief Pointer to the hosting Lua debugger dialog. */
    LuaDebuggerDialog *host_ = nullptr;

    /** @brief Pointer to the currently active nested event loop. */
    QEventLoop *activeLoop_ = nullptr;

    /** @brief List of top-level widgets that were frozen during the pause. */
    QList<QPointer<QWidget>> frozenTopLevels_;

    /** @brief List of actions that were frozen during the pause. */
    QList<QPointer<QAction>> frozenActions_;

    /** @brief Pointer to the central widget frozen during the pause. */
    QPointer<QWidget> frozenCentralWidget_;

    /** @brief Pointer to the translucent pause overlay widget. */
    QPointer<LuaDebuggerPauseOverlay> pauseOverlay_;

    /** @brief Pointer to the input filter applied during the pause. */
    QObject *pauseInputFilter_ = nullptr;

    /** @brief State flag indicating if the pause state has been unfrozen. */
    bool pauseUnfrozen_ = true;
};

/* ===== pause_overlay ===== */

/**
 * @brief Translucent overlay shown over the main window while the Lua
 * debugger is paused.
 *
 * Renders a darkening vignette plus a centered card with a pause glyph,
 * bold title and subtext — similar visual vocabulary to the
 * startup SplashOverlay so the "wait" state feels native, with a
 * somewhat more opaque treatment so the pause state reads clearly.
 *
 * The overlay is a plain child QWidget of the main window, intentionally
 * *not* a top-level Qt::Window: a child widget has no platform-window
 * identity of its own (no NSWindow on macOS, no X11 window on Linux),
 * so it can never surface as an independent entry in Mission Control /
 * Alt-Tab, never carry its own drop shadow or zoom animation, and
 * trivially stays glued to the main window for free — exactly like
 * SplashOverlay does on the welcome page.
 *
 * The paint is static (no animation): like the splash screen, the card
 * is drawn once and stays put. While the debugger is paused the dialog
 * also installs a QEvent::UpdateRequest filter on the main window
 * (see PauseInputFilter in lua_debugger_dialog.cpp) to prevent
 * re-entrant paints of the main window's backing store.
 *
 * The overlay tracks its parent's size itself: the constructor
 * installs an event filter on the parent and sets the initial
 * geometry to the parent's rect. On QEvent::Resize the overlay
 * resizes to the new parent rect and calls repaint() synchronously
 * — required because an update() would post a QEvent::UpdateRequest
 * to the top-level main window, which PauseInputFilter swallows.
 * QEvent::Resize itself is not filtered, so the WM's resize is
 * delivered to the main window and we see it here as well.
 */
class LuaDebuggerPauseOverlay : public QWidget
{
    Q_OBJECT

  public:
    /**
     * @brief Constructs a new LuaDebuggerPauseOverlay object.
     * @param parent The parent widget to overlay.
     */
    explicit LuaDebuggerPauseOverlay(QWidget *parent);

    /**
     * @brief Destroys the LuaDebuggerPauseOverlay object.
     */
    ~LuaDebuggerPauseOverlay() override;

  protected:
    /**
     * @brief Handles paint events to draw the overlay.
     * @param event The paint event.
     */
    void paintEvent(QPaintEvent *event) override;

    /**
     * @brief Filters events on the parent widget to handle resizing.
     * @param obj The watched object.
     * @param event The event being filtered.
     * @return True if the event is handled, false otherwise.
     */
    bool eventFilter(QObject *obj, QEvent *event) override;

  private:
    /** @brief The bold title text displayed on the overlay. */
    QString title_text_;

    /** @brief The secondary subtext displayed on the overlay. */
    QString subtext_text_;
};

/* ===== pause_key_filter ===== */

/**
 * @brief Swallows input and selected events for non-debugger windows during pause,
 *        and suppresses UpdateRequest/LayoutRequest on the main window.
 */
class LuaDebuggerPauseInputFilter : public QObject
{
  public:
    /**
     * @brief Constructs a new LuaDebuggerPauseInputFilter object.
     * @param debugger_dialog Pointer to the active debugger dialog.
     * @param main_window Pointer to the application's main window.
     * @param parent The parent object.
     */
    explicit LuaDebuggerPauseInputFilter(QWidget *debugger_dialog, QWidget *main_window, QObject *parent = nullptr);

    /**
     * @brief Filters input events globally during a debugger pause.
     * @param watched The object receiving the event.
     * @param event The event being dispatched.
     * @return True to swallow the event, false to pass it through.
     */
    bool eventFilter(QObject *watched, QEvent *event) override;

  private:
    /**
     * @brief Checks if a specific widget is allowed to receive events during a pause.
     * @param w Pointer to the widget to check.
     * @return True if the widget is allowed, false otherwise.
     */
    bool isAllowedDuringPause(const QWidget *w) const;

    /** @brief Pointer to the active debugger dialog. */
    QWidget *debugger_dialog_;

    /** @brief Pointer to the application's main window. */
    QWidget *main_window_;
};

#endif
