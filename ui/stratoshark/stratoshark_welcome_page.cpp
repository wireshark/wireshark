/* @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "stratoshark_welcome_page.h"

StratosharkWelcomePage::StratosharkWelcomePage(QWidget *parent) :
    WelcomePage(parent)
{
}

StratosharkWelcomePage::~StratosharkWelcomePage()
{
}

QString StratosharkWelcomePage::getReleaseLabel()
{
    return tr("You are running Stratoshark ");
}

QString StratosharkWelcomePage::getReleaseLabelGlue()
{
    return tr("You are sniffing the glue that holds your system together using Stratoshark ");
}
