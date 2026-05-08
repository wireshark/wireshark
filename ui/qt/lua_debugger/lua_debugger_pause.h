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
    explicit LuaDebuggerPauseController(LuaDebuggerDialog *host);

    bool hasActiveLoop() const { return activeLoop_ != nullptr; }
    QEventLoop *activeLoop() const { return activeLoop_; }
    void setActiveLoop(QEventLoop *loop) { activeLoop_ = loop; }
    void clearActiveLoop() { activeLoop_ = nullptr; }
    void quitLoop();

    void beginOuterFreeze();
    void endFreeze();

  private:
    LuaDebuggerDialog *host_ = nullptr;
    QEventLoop *activeLoop_ = nullptr;

    QList<QPointer<QWidget>> frozenTopLevels_;
    QList<QPointer<QAction>> frozenActions_;
    QPointer<QWidget> frozenCentralWidget_;
    QPointer<LuaDebuggerPauseOverlay> pauseOverlay_;
    QObject *pauseInputFilter_ = nullptr;
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
    explicit LuaDebuggerPauseOverlay(QWidget *parent);
    ~LuaDebuggerPauseOverlay() override;

  protected:
    void paintEvent(QPaintEvent *event) override;
    bool eventFilter(QObject *obj, QEvent *event) override;

  private:
    QString title_text_;
    QString subtext_text_;
};

/* ===== pause_key_filter ===== */

/**
 * Swallows input and selected events for non-debugger windows during pause,
 * and suppresses UpdateRequest/LayoutRequest on the main window.
 */
class LuaDebuggerPauseInputFilter : public QObject
{
  public:
    explicit LuaDebuggerPauseInputFilter(QWidget *debugger_dialog, QWidget *main_window, QObject *parent = nullptr);

    bool eventFilter(QObject *watched, QEvent *event) override;

  private:
    bool isAllowedDuringPause(const QWidget *w) const;

    QWidget *debugger_dialog_;
    QWidget *main_window_;
};

#endif
