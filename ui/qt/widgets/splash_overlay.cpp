/* splash_overlay.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "splash_overlay.h"
#include <ui_splash_overlay.h>
#include "wireshark_application.h"

#include <QPainter>

#include "ui/util.h"
#include <wsutil/utf8_entities.h>
#include <ui/qt/utils/tango_colors.h>

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
    emit wsApp->registerUpdate(action, message);
}

SplashOverlay::SplashOverlay(QWidget *parent) :
    QWidget(parent),
    so_ui_(new Ui::SplashOverlay),
    last_action_(RA_NONE),
    register_cur_(0)
{
    so_ui_->setupUi(this);

    int register_max = RA_BASE_COUNT;
#ifdef HAVE_LUA
    register_max++;
#endif
    register_max++;

    so_ui_->progressBar->setMaximum(register_max);
    elapsed_timer_.start();

    QColor bg = QColor(tango_aluminium_6);
    bg.setAlphaF(0.2);
    QPalette pal;
    pal.setColor(QPalette::Window, bg);
    setPalette(pal);
    setAutoFillBackground(true);

    setStyleSheet(QString(
                      "QFrame#progressBand {"
                      "  background: %1;"
                      "}"
                      "QLabel {"
                      "  color: white;"
                      "  background: transparent;"
                      "}"
                      "QProgressBar {"
                      "  height: 1em;"
                      "  width: 20em;"
                      "  border: 0.1em solid white;"
                      "  border-radius: 0.2em;"
                      "  color: white;"
                      "  background: transparent;"
                      "}"
                      "QProgressBar::chunk {"
                      "  width: 0.1em;"
                      "  background: rgba(255, 255, 255, 50%);"
                      "}"
                      )
                  .arg(QColor(tango_aluminium_4).name()));

    connect(wsApp, SIGNAL(splashUpdate(register_action_e,const char*)),
            this, SLOT(splashUpdate(register_action_e,const char*)));
}

SplashOverlay::~SplashOverlay()
{
    delete so_ui_;
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
        // Nothing to update yet
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
    so_ui_->actionLabel->setText(action_msg);

    so_ui_->progressBar->setValue(register_cur_);

    wsApp->processEvents(QEventLoop::ExcludeUserInputEvents | QEventLoop::ExcludeSocketNotifiers, 1);
    elapsed_timer_.restart();
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
