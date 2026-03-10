/* splash_overlay.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "splash_overlay.h"
#include "main_application.h"

#include <QGraphicsOpacityEffect>
#include <QPainter>
#include <QPixmap>
#include <QPropertyAnimation>
#include <QRadialGradient>

#include <wsutil/utf8_entities.h>
#include <ui/qt/utils/color_utils.h>
#include <app/application_flavor.h>

#ifdef HAVE_LUA
#include "epan/wslua/init_wslua.h"
#endif

#include "extcap.h"

// Uncomment to slow the update progress
//#define THROTTLE_STARTUP 1

/*
 * Update frequency for the splash screen, given in milliseconds.
 */
const int info_update_freq_ = 65; // ~15 fps

void splash_update(register_action_e action, const char *message, void *) {
    emit mainApp->registerUpdate(action, message);
}

SplashOverlay::SplashOverlay(QWidget *parent) :
    QWidget(parent),
    last_action_(RA_NONE),
    register_cur_(0),
    register_max_(RA_BASE_COUNT)
{
    setAttribute(Qt::WA_TranslucentBackground);

#ifdef HAVE_LUA
    register_max_++;
#endif
    register_max_++;

    elapsed_timer_.start();

    opacity_effect_ = new QGraphicsOpacityEffect(this);
    opacity_effect_->setOpacity(1.0);
    setGraphicsEffect(opacity_effect_);

    fade_animation_ = new QPropertyAnimation(opacity_effect_, "opacity", this);
    fade_animation_->setDuration(300);
    fade_animation_->setStartValue(1.0);
    fade_animation_->setEndValue(0.0);
    fade_animation_->setEasingCurve(QEasingCurve::OutCubic);
    connect(fade_animation_, &QPropertyAnimation::finished, this, &QObject::deleteLater);

    connect(mainApp, &MainApplication::splashUpdate, this, &SplashOverlay::splashUpdate);
}

void SplashOverlay::fadeOut()
{
    fade_animation_->start();
}

void SplashOverlay::paintEvent(QPaintEvent *)
{
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    bool dark = ColorUtils::themeIsDark();

    // --- Radial vignette background ---
    QColor edge_color = dark ? QColor(0, 0, 0, 178) : QColor(0, 0, 0, 140);
    QColor center_color = dark ? QColor(0, 0, 0, 30) : QColor(0, 0, 0, 10);

    QPointF center(width() / 2.0, height() / 2.0);
    qreal radius = qMax(width(), height()) * 0.75;

    QRadialGradient vignette(center, radius);
    vignette.setColorAt(0.0, center_color);
    vignette.setColorAt(1.0, edge_color);

    painter.fillRect(rect(), vignette);

    // --- App logo ---
    const int logo_size = 64;
    const int logo_card_gap = 16;
    QString icon_path = application_flavor_is_wireshark()
        ? QStringLiteral(":/wsicon/wsicon256.png")
        : QStringLiteral(":/ssicon/ssicon256.png");
    QPixmap logo(icon_path);
    if (!logo.isNull()) {
        QPixmap scaled = logo.scaled(logo_size, logo_size,
            Qt::KeepAspectRatio, Qt::SmoothTransformation);
        int logo_x = (width() - scaled.width()) / 2;
        int logo_y = static_cast<int>(height() * 0.38) - scaled.height() - logo_card_gap;
        painter.drawPixmap(logo_x, logo_y, scaled);
    }

    // --- Progress card (60% of width, minimum 320px) ---
    const int card_w = qMax(320, static_cast<int>(width() * 0.6));
    const int card_h = 80;
    int card_x = (width() - card_w) / 2;
    int card_y = static_cast<int>(height() * 0.38);
    QRectF card_rect(card_x, card_y, card_w, card_h);

    QColor card_bg = dark ? QColor(40, 40, 46, 200) : QColor(255, 255, 255, 190);
    QColor card_border = dark ? QColor(255, 255, 255, 30) : QColor(0, 0, 0, 25);

    painter.setPen(QPen(card_border, 1.0));
    painter.setBrush(card_bg);
    painter.drawRoundedRect(card_rect, 8, 8);

    // --- Action label ---
    const int padding = 16;
    const int text_h = 20;
    QRectF text_rect(card_x + padding, card_y + padding, card_w - 2 * padding, text_h);

    QColor text_color = dark ? QColor(220, 220, 225) : QColor(50, 50, 55);
    painter.setPen(text_color);

    QFont label_font = font();
    label_font.setPointSizeF(font().pointSizeF() * 0.9);
    painter.setFont(label_font);

    QString elided = painter.fontMetrics().elidedText(
        action_text_, Qt::ElideMiddle, static_cast<int>(text_rect.width()));
    painter.drawText(text_rect, Qt::AlignLeft | Qt::AlignVCenter, elided);

    // --- Progress bar ---
    const int bar_h = 6;
    const int bar_y = card_y + card_h - padding - bar_h;
    QRectF bar_bg_rect(card_x + padding, bar_y, card_w - 2 * padding, bar_h);

    QColor bar_bg = dark ? QColor(255, 255, 255, 25) : QColor(0, 0, 0, 20);
    painter.setPen(Qt::NoPen);
    painter.setBrush(bar_bg);
    painter.drawRoundedRect(bar_bg_rect, bar_h / 2.0, bar_h / 2.0);

    if (register_max_ > 0 && register_cur_ > 0) {
        qreal fraction = qMin(1.0, static_cast<qreal>(register_cur_) / register_max_);
        qreal fill_w = (card_w - 2 * padding) * fraction;

        QRectF bar_fill_rect(card_x + padding, bar_y, fill_w, bar_h);
        QColor bar_fill = dark ? QColor(130, 170, 255, 200) : QColor(52, 101, 164, 200);

        painter.setBrush(bar_fill);
        painter.drawRoundedRect(bar_fill_rect, bar_h / 2.0, bar_h / 2.0);
    }
}

// Useful for debugging on fast machines.
#ifdef THROTTLE_STARTUP
#include <QThread>
class ThrottleThread : public QThread
{
public:
    static void msleep(unsigned long msecs)
    {
        QThread::msleep(msecs);
    }
};
#endif

void SplashOverlay::splashUpdate(register_action_e action, const char *message)
{
    QString action_msg = UTF8_HORIZONTAL_ELLIPSIS;

#ifdef THROTTLE_STARTUP
    ThrottleThread::msleep(10);
#endif

    if (last_action_ == action && (elapsed_timer_.elapsed() < info_update_freq_)) {
        return;
    }

    if (last_action_ != action) {
        register_cur_++;
    }
    last_action_ = action;

    switch(action) {
    case RA_DISSECTORS:
        action_msg = tr("Initializing dissectors");
        break;
    case RA_LISTENERS:
        action_msg = tr("Initializing tap listeners");
        break;
    case RA_EXTCAP:
        action_msg = tr("Initializing external capture plugins");
        break;
    case RA_REGISTER:
        action_msg = tr("Registering dissectors");
        break;
    case RA_PLUGIN_REGISTER:
        action_msg = tr("Registering plugins");
        break;
    case RA_HANDOFF:
        action_msg = tr("Handing off dissectors");
        break;
    case RA_PLUGIN_HANDOFF:
        action_msg = tr("Handing off plugins");
        break;
    case RA_LUA_PLUGINS:
        action_msg = tr("Loading Lua plugins");
        break;
    case RA_LUA_DEREGISTER:
        action_msg = tr("Removing Lua plugins");
        break;
    case RA_PREFERENCES:
        action_msg = tr("Loading module preferences");
        break;
    case RA_INTERFACES:
        action_msg = tr("Finding local interfaces");
        break;
    case RA_PREFERENCES_APPLY:
        action_msg = tr("Applying changed preferences");
        break;
    default:
        action_msg = tr("(Unknown action)");
        break;
    }

    if (message) {
        if (!strncmp(message, "proto_register_", 15))
            message += 15;
        else if (!strncmp(message, "proto_reg_handoff_", 18))
            message += 18;
        action_msg.append(" ").append(message);
    }

    action_text_ = action_msg;
    update();

    mainApp->processEvents(QEventLoop::ExcludeUserInputEvents | QEventLoop::ExcludeSocketNotifiers, 1);
    elapsed_timer_.restart();
}
