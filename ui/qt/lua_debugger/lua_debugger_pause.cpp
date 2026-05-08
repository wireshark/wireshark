/* lua_debugger_pause.cpp
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

#include "lua_debugger_pause.h"

#include <QAction>
#include <QApplication>
#include <QDialog>
#include <QEvent>
#include <QEventLoop>
#include <QPainter>
#include <QRadialGradient>
#include <QResizeEvent>
#include <QSet>
#include <QTimer>
#include <QWidget>

#include <utility>

#include "lua_debugger_dialog.h"
#include "main_application.h"
#include "main_window.h"
#include <ui/qt/utils/color_utils.h>

namespace
{
bool isPauseAllowedWindow(const QWidget *w,
                          const QWidget *debugger_dialog,
                          const QWidget *main_window)
{
    if (!w)
    {
        return false;
    }

    if (main_window && w == main_window)
    {
        return true;
    }

    for (const QObject *o = w; o; o = o->parent())
    {
        if (o == debugger_dialog)
        {
            return true;
        }

        const QWidget *as_widget = qobject_cast<const QWidget *>(o);
        if (!as_widget || !as_widget->isWindow())
        {
            continue;
        }

        if (as_widget->windowModality() != Qt::NonModal)
        {
            return true;
        }

        const QDialog *as_dialog = qobject_cast<const QDialog *>(as_widget);
        if (as_dialog && as_dialog->isModal())
        {
            return true;
        }
    }

    return false;
}
} // namespace

/* ===== pause_controller ===== */

LuaDebuggerPauseController::LuaDebuggerPauseController(LuaDebuggerDialog *host) : QObject(host), host_(host) {}

void LuaDebuggerPauseController::quitLoop()
{
    if (activeLoop_)
    {
        activeLoop_->quit();
    }
}

void LuaDebuggerPauseController::beginOuterFreeze()
{
    if (!host_)
    {
        return;
    }

    /* Mark the freeze as active; endFreeze() will flip this back
     * on the first call (either from handlePause's post-loop or from
     * closeEvent during a main-window close while paused). */
    pauseUnfrozen_ = false;

    frozenTopLevels_.clear();
    QSet<QWidget *> ancestors;
    ancestors.insert(host_);
    for (QWidget *p = host_->parentWidget(); p; p = p->parentWidget())
    {
        ancestors.insert(p);
    }

    MainWindow *mw = mainApp ? mainApp->mainWindow() : nullptr;

    const QList<QWidget *> top_level_widgets = QApplication::topLevelWidgets();
    for (QWidget *w : top_level_widgets)
    {
        if (!w || ancestors.contains(w) ||
            isPauseAllowedWindow(w, host_, mw))
        {
            continue;
        }
        if (!w->isVisible() || !w->isEnabled())
        {
            continue;
        }
        w->setEnabled(false);
        frozenTopLevels_.append(QPointer<QWidget>(w));
    }

    frozenActions_.clear();
    const QList<QAction *> debugger_actions = host_->findChildren<QAction *>();
    QSet<QAction *> debugger_action_set;
    debugger_action_set.reserve(debugger_actions.size());
    for (QAction *a : debugger_actions)
    {
        if (a)
        {
            debugger_action_set.insert(a);
        }
    }
    for (QWidget *tlw : top_level_widgets)
    {
        if (!tlw || tlw == host_ ||
            isPauseAllowedWindow(tlw, host_, mw))
        {
            continue;
        }
        const QList<QAction *> actions = tlw->findChildren<QAction *>();
        for (QAction *a : actions)
        {
            if (a && a->isEnabled() && !debugger_action_set.contains(a))
            {
                a->setEnabled(false);
                frozenActions_.append(QPointer<QAction>(a));
            }
        }
    }

    frozenCentralWidget_.clear();
    if (mw)
    {
        if (QWidget *cw = mw->centralWidget())
        {
            if (cw->isEnabled())
            {
                cw->setEnabled(false);
                frozenCentralWidget_ = QPointer<QWidget>(cw);
            }
        }
    }

    if (mw && !pauseOverlay_)
    {
        pauseOverlay_ = new LuaDebuggerPauseOverlay(mw);
        pauseOverlay_->raise();
        pauseOverlay_->show();
        pauseOverlay_->repaint();
    }

    host_->raise();
    host_->activateWindow();

    pauseInputFilter_ = new LuaDebuggerPauseInputFilter(host_, mw);
    qApp->installEventFilter(pauseInputFilter_);
}

void LuaDebuggerPauseController::endFreeze()
{
    if (pauseUnfrozen_)
    {
        return;
    }
    pauseUnfrozen_ = true;

    MainWindow *mw = mainApp ? mainApp->mainWindow() : nullptr;

    if (pauseInputFilter_)
    {
        qApp->removeEventFilter(pauseInputFilter_);
        delete pauseInputFilter_;
        pauseInputFilter_ = nullptr;
    }

    if (pauseOverlay_)
    {
        delete pauseOverlay_;
        pauseOverlay_ = nullptr;
    }

    if (frozenCentralWidget_)
    {
        frozenCentralWidget_->setEnabled(true);
    }
    frozenCentralWidget_.clear();

    const QList<QPointer<QWidget>> frozen_snapshot = frozenTopLevels_;
    frozenTopLevels_.clear();
    for (const QPointer<QWidget> &w : frozen_snapshot)
    {
        if (w)
        {
            w->setEnabled(true);
        }
    }

    const QList<QPointer<QAction>> action_snapshot = frozenActions_;
    frozenActions_.clear();
    for (const QPointer<QAction> &a : action_snapshot)
    {
        if (a)
        {
            a->setEnabled(true);
        }
    }

    if (mw)
    {
        QPointer<QWidget> mw_p(mw);
        QTimer::singleShot(0, mw,
                           [mw_p = std::move(mw_p)]()
                           {
                               if (mw_p)
                               {
                                   mw_p->repaint();
                               }
                           });
    }
}

/* ===== pause_overlay ===== */

namespace
{
/* Shared geometry constants — tuned to match SplashOverlay's card
 * proportions so the pause banner reads as part of the same visual
 * family. */
constexpr int kCardPadding = 16;
constexpr int kCardCornerRadius = kCardPadding / 2;
constexpr int kCardHeight = 100;
constexpr qreal kCardVerticalPosition = 0.38;
constexpr int kTitleHeight = 22;
constexpr qreal kTitleFontScale = 1.05;
constexpr qreal kSubtextFontScale = 1.0;
/* Subtext is bold; use near-full foreground alpha so it stays readable. */
constexpr int kSubtextAlpha = 235;

/* Pause glyph (two rounded vertical bars). */
constexpr int kGlyphBarWidth = 5;
constexpr int kGlyphBarHeight = 22;
constexpr int kGlyphBarGap = 5;
constexpr int kGlyphBarRadius = 2;
constexpr int kGlyphTotalWidth = 2 * kGlyphBarWidth + kGlyphBarGap;
constexpr int kGlyphTitleSpacing = 12;
} // namespace

LuaDebuggerPauseOverlay::LuaDebuggerPauseOverlay(QWidget *parent)
    : QWidget(parent), title_text_(tr("Lua debugger paused")),
      subtext_text_(tr("Use the Lua Debugger window to step, continue, or "
                       "evaluate. The main window resumes when execution is "
                       "released."))
{
    /* Translucent background + mouse-event pass-through: the overlay
     * only provides a visual cue. Input is policed separately by the
     * dialog (setEnabled(false) on every widget that is not part of
     * the debugger, plus an application event filter). */
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_TransparentForMouseEvents);
    setAttribute(Qt::WA_NoSystemBackground);

    /* Track the parent's size ourselves. Qt does not auto-resize a
     * child widget with no layout, and the debugger's PauseInputFilter
     * swallows UpdateRequest / LayoutRequest on the main window while
     * paused, so we cannot rely on either the parent's layout or on
     * a deferred update() to refresh our geometry. QEvent::Resize is
     * not filtered, so we see it here and react with a synchronous
     * repaint() that bypasses the queued-event path entirely. */
    if (parent)
    {
        setGeometry(parent->rect());
        parent->installEventFilter(this);
    }
}

LuaDebuggerPauseOverlay::~LuaDebuggerPauseOverlay() = default;

bool LuaDebuggerPauseOverlay::eventFilter(QObject *obj, QEvent *event)
{
    if (obj == parent() && event->type() == QEvent::Resize)
    {
        if (QWidget *p = parentWidget())
        {
            setGeometry(p->rect());
            repaint();
        }
    }
    return QWidget::eventFilter(obj, event);
}

void LuaDebuggerPauseOverlay::paintEvent(QPaintEvent *)
{
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    const bool dark = ColorUtils::themeIsDark();

    /* Radial vignette — more opaque than SplashOverlay so the main
     * window clearly reads as "stopped". */
    const QColor edge_color = dark ? QColor(0, 0, 0, 220) : QColor(0, 0, 0, 175);
    const QColor center_color = dark ? QColor(0, 0, 0, 130) : QColor(0, 0, 0, 105);

    const QPointF center(width() / 2.0, height() / 2.0);
    const qreal radius = qMax(width(), height()) * 0.75;

    QRadialGradient vignette(center, radius);
    vignette.setColorAt(0.0, center_color);
    vignette.setColorAt(1.0, edge_color);
    painter.fillRect(rect(), vignette);

    /* Centered card — same dimensions and colors as SplashOverlay. */
    const int card_w = qMax(360, static_cast<int>(width() * 0.6));
    const int card_x = (width() - card_w) / 2;
    const int card_y = static_cast<int>(height() * kCardVerticalPosition);
    const QRectF card_rect(card_x, card_y, card_w, kCardHeight);

    const QColor card_bg = dark ? QColor(40, 40, 46, 230) : QColor(255, 255, 255, 222);
    const QColor card_border = dark ? QColor(255, 255, 255, 40) : QColor(0, 0, 0, 35);

    painter.setPen(QPen(card_border, 1.0));
    painter.setBrush(card_bg);
    painter.drawRoundedRect(card_rect, kCardCornerRadius, kCardCornerRadius);

    const QColor text_color = dark ? QColor(220, 220, 225) : QColor(50, 50, 55);

    /* Pause glyph (static two-bar symbol). */
    painter.setPen(Qt::NoPen);
    painter.setBrush(text_color);

    const int glyph_y = card_y + kCardPadding + (kTitleHeight - kGlyphBarHeight) / 2;
    const int bar1_x = card_x + kCardPadding;
    const int bar2_x = bar1_x + kGlyphBarWidth + kGlyphBarGap;
    painter.drawRoundedRect(QRectF(bar1_x, glyph_y, kGlyphBarWidth, kGlyphBarHeight), kGlyphBarRadius, kGlyphBarRadius);
    painter.drawRoundedRect(QRectF(bar2_x, glyph_y, kGlyphBarWidth, kGlyphBarHeight), kGlyphBarRadius, kGlyphBarRadius);

    /* Title (bold, slightly larger) — same style as SplashOverlay. */
    const int text_left = card_x + kCardPadding + kGlyphTotalWidth + kGlyphTitleSpacing;
    const int text_width = card_w - (text_left - card_x) - kCardPadding;
    QRectF title_rect(text_left, card_y + kCardPadding, text_width, kTitleHeight);

    QFont title_font = font();
    title_font.setPointSizeF(font().pointSizeF() * kTitleFontScale);
    title_font.setBold(true);
    painter.setFont(title_font);
    painter.setPen(text_color);

    const QString elided_title =
        painter.fontMetrics().elidedText(title_text_, Qt::ElideMiddle, static_cast<int>(title_rect.width()));
    painter.drawText(title_rect, Qt::AlignLeft | Qt::AlignVCenter, elided_title);

    /* Subtext (smaller). */
    if (!subtext_text_.isEmpty())
    {
        const int sub_top = card_y + kCardPadding + kTitleHeight + 4;
        const int sub_height = kCardHeight - (sub_top - card_y) - kCardPadding;
        QRectF sub_rect(text_left, sub_top, text_width, sub_height);

        QFont sub_font = font();
        sub_font.setPointSizeF(font().pointSizeF() * kSubtextFontScale);
        painter.setFont(sub_font);

        QColor sub_color = text_color;
        sub_color.setAlpha(kSubtextAlpha);
        painter.setPen(sub_color);

        painter.drawText(sub_rect, Qt::AlignLeft | Qt::AlignTop | Qt::TextWordWrap, subtext_text_);
    }
}

/* ===== pause_key_filter ===== */

LuaDebuggerPauseInputFilter::LuaDebuggerPauseInputFilter(QWidget *debugger_dialog, QWidget *main_window,
                                                         QObject *parent)
    : QObject(parent), debugger_dialog_(debugger_dialog), main_window_(main_window)
{
}

bool LuaDebuggerPauseInputFilter::eventFilter(QObject *watched, QEvent *event)
{
    const QEvent::Type type = event->type();

    if (type == QEvent::UpdateRequest || type == QEvent::LayoutRequest)
    {
        if (main_window_ && watched == main_window_)
        {
            event->accept();
            return true;
        }
        return QObject::eventFilter(watched, event);
    }

    if (type == QEvent::Close)
    {
        QWidget *w = qobject_cast<QWidget *>(watched);
        if (!w)
        {
            return QObject::eventFilter(watched, event);
        }
        if (isAllowedDuringPause(w))
        {
            return QObject::eventFilter(watched, event);
        }
        if (w->isWindow())
        {
            event->ignore();
            return true;
        }
        return QObject::eventFilter(watched, event);
    }

    switch (type)
    {
    case QEvent::MouseButtonPress:
    case QEvent::MouseButtonRelease:
    case QEvent::MouseButtonDblClick:
    case QEvent::KeyPress:
    case QEvent::KeyRelease:
    case QEvent::Wheel:
    case QEvent::Shortcut:
    case QEvent::ShortcutOverride:
    case QEvent::ContextMenu:
        break;
    default:
        return QObject::eventFilter(watched, event);
    }

    QWidget *w = qobject_cast<QWidget *>(watched);
    if (!w)
    {
        return QObject::eventFilter(watched, event);
    }

    if (isAllowedDuringPause(w))
    {
        return QObject::eventFilter(watched, event);
    }

    event->accept();
    return true;
}

bool LuaDebuggerPauseInputFilter::isAllowedDuringPause(const QWidget *w) const
{
    return isPauseAllowedWindow(w, debugger_dialog_, main_window_);
}
