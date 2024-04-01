/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SPLASH_OVERLAY_H
#define SPLASH_OVERLAY_H

#include <config.h>

#include "epan/register.h"

#include <QWidget>
#include <QElapsedTimer>

void splash_update(register_action_e action, const char *message, void *dummy);

namespace Ui {
class SplashOverlay;
}

class SplashOverlay : public QWidget
{
    Q_OBJECT

public:
    explicit SplashOverlay(QWidget *parent = 0);
    ~SplashOverlay();

private:
    Ui::SplashOverlay *so_ui_;
    register_action_e last_action_;
    int register_cur_;
    QElapsedTimer elapsed_timer_;

private slots:
    void splashUpdate(register_action_e action, const char *message);
};

#endif // SPLASH_OVERLAY_H
