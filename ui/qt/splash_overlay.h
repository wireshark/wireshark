/* splash_overlay.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef SPLASH_OVERLAY_H
#define SPLASH_OVERLAY_H

#include "config.h"

#include <glib.h>

#include "register.h"

#include <QWidget>
#include <QTime>

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

protected:
    void paintEvent(QPaintEvent *event);

private:
    Ui::SplashOverlay *so_ui_;
    bool blurred_;
    register_action_e last_action_;
    int register_cur_;
    QTime time_;

private slots:
    void splashUpdate(register_action_e action, const char *message);
};

#endif // SPLASH_OVERLAY_H

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
