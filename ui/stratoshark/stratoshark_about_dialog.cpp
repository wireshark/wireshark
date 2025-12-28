/* stratoshark_about_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "about_dialog.h"
#include "stratoshark_about_dialog.h"

#include "main_application.h"

StratosharkAboutDialog::StratosharkAboutDialog(QWidget *parent) :
    AboutDialog(parent)
{
    setWindowTitle(tr("About Stratoshark"));
    tabWidget()->setTabText(tabWidget()->indexOf(tabWireshark()), tr("Stratoshark"));
    labelTitle()->setText(tr("<h3>System Call and Event Log Analyzer</h3>"));

    if (mainApp->devicePixelRatio() > 1.0) {
        QPixmap pm = QPixmap(":/about/sssplash@2x.png");
        pm.setDevicePixelRatio(2.0);
        labelLogo()->setPixmap(pm);
    }
    else {
        labelLogo()->setPixmap(QPixmap(":/about/sssplash.png"));
    }
}
