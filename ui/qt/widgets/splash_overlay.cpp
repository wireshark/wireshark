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
static const int info_update_freq_ = 65; // ~15 fps

// Layout constants for the splash overlay
static const int kLogoSize = 64;
static const int kCardPadding = 16;
static const int kCardCornerRadius = kCardPadding / 2;
static const int kCardHeight = 100;
static const qreal kCardVerticalPosition = 0.38;
static const int kTitleHeight = 22;
static const qreal kTitleFontScale = 1.05;
static const int kSubtextHeight = kTitleHeight - 4;
static const qreal kSubtextFontScale = 1.0;
static const int kSubtextAlpha = 160;
static const int kBarHeight = 6;

SplashOverlay *SplashOverlay::instance_ = nullptr;

void splash_update(register_action_e action, const char *message, void *) {
    if (SplashOverlay::instance_)
        SplashOverlay::instance_->splashUpdate(action, message);
}

SplashOverlay::SplashOverlay(QWidget *parent) :
    QWidget(parent),
    last_action_(RA_NONE),
    register_cur_(0),
    register_max_(RA_BASE_COUNT)
{
    instance_ = this;
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
}

SplashOverlay::~SplashOverlay()
{
    if (instance_ == this)
        instance_ = nullptr;
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
    QString icon_path = application_flavor_is_wireshark()
        ? QStringLiteral(":/wsicon/wsicon256.png")
        : QStringLiteral(":/ssicon/ssicon256.png");
    QPixmap logo(icon_path);
    if (!logo.isNull()) {
        QPixmap scaled = logo.scaled(kLogoSize, kLogoSize,
            Qt::KeepAspectRatio, Qt::SmoothTransformation);
        int logo_x = (width() - scaled.width()) / 2;
        int logo_y = static_cast<int>(height() * kCardVerticalPosition) - scaled.height() - kCardPadding;
        painter.drawPixmap(logo_x, logo_y, scaled);
    }

    // --- Progress card ---
    const int card_w = qMax(320, static_cast<int>(width() * 0.6));
    int card_x = (width() - card_w) / 2;
    int card_y = static_cast<int>(height() * kCardVerticalPosition);
    QRectF card_rect(card_x, card_y, card_w, kCardHeight);

    QColor card_bg = dark ? QColor(40, 40, 46, 200) : QColor(255, 255, 255, 190);
    QColor card_border = dark ? QColor(255, 255, 255, 30) : QColor(0, 0, 0, 25);

    painter.setPen(QPen(card_border, 1.0));
    painter.setBrush(card_bg);
    painter.drawRoundedRect(card_rect, kCardCornerRadius, kCardCornerRadius);

    QColor text_color = dark ? QColor(220, 220, 225) : QColor(50, 50, 55);

    // --- Action title (bold, slightly larger) ---
    QRectF title_rect(card_x + kCardPadding, card_y + kCardPadding,
                      card_w - 2 * kCardPadding, kTitleHeight);

    QFont title_font = font();
    title_font.setPointSizeF(font().pointSizeF() * kTitleFontScale);
    title_font.setBold(true);
    painter.setFont(title_font);
    painter.setPen(text_color);

    QString elided_title = painter.fontMetrics().elidedText(
        action_text_, Qt::ElideMiddle, static_cast<int>(title_rect.width()));
    painter.drawText(title_rect, Qt::AlignLeft | Qt::AlignVCenter, elided_title);

    // --- Action subtext (smaller, dimmer) ---
    if (!action_subtext_.isEmpty()) {
        QRectF sub_rect(card_x + kCardPadding,
                        card_y + kCardPadding + kTitleHeight + 2,
                        card_w - 2 * kCardPadding, kSubtextHeight);

        QFont sub_font = font();
        sub_font.setPointSizeF(font().pointSizeF() * kSubtextFontScale);
        painter.setFont(sub_font);

        QColor sub_color = text_color;
        sub_color.setAlpha(kSubtextAlpha);
        painter.setPen(sub_color);

        QString elided_sub = painter.fontMetrics().elidedText(
            action_subtext_, Qt::ElideMiddle, static_cast<int>(sub_rect.width()));
        painter.drawText(sub_rect, Qt::AlignLeft | Qt::AlignVCenter, elided_sub);
    }

    // --- Progress bar ---
    const int bar_y = card_y + kCardHeight - kCardPadding - kBarHeight;
    QRectF bar_bg_rect(card_x + kCardPadding, bar_y, card_w - 2 * kCardPadding, kBarHeight);

    QColor bar_bg = dark ? QColor(255, 255, 255, 25) : QColor(0, 0, 0, 20);
    painter.setPen(Qt::NoPen);
    painter.setBrush(bar_bg);
    painter.drawRoundedRect(bar_bg_rect, kBarHeight / 2.0, kBarHeight / 2.0);

    if (register_max_ > 0 && register_cur_ > 0) {
        qreal fraction = qMin(1.0, static_cast<qreal>(register_cur_) / register_max_);
        qreal fill_w = (card_w - 2 * kCardPadding) * fraction;

        QRectF bar_fill_rect(card_x + kCardPadding, bar_y, fill_w, kBarHeight);
        QColor bar_fill = dark ? QColor(130, 170, 255, 200) : QColor(52, 101, 164, 200);

        painter.setBrush(bar_fill);
        painter.drawRoundedRect(bar_fill_rect, kBarHeight / 2.0, kBarHeight / 2.0);
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

    QString sub_msg;
    if (message) {
        if (!strncmp(message, "proto_register_", 15))
            message += 15;
        else if (!strncmp(message, "proto_reg_handoff_", 18))
            message += 18;
        sub_msg = QString(message);
    }

    action_text_ = action_msg;
    action_subtext_ = sub_msg;
    repaint();

    mainApp->processEvents(QEventLoop::ExcludeUserInputEvents | QEventLoop::ExcludeSocketNotifiers, info_update_freq_);
    elapsed_timer_.restart();
}
