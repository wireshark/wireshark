/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STRATOSHARK_WELCOME_PAGE_H
#define STRATOSHARK_WELCOME_PAGE_H

#include <QFrame>


#include "welcome_page.h"

namespace Ui {
    class StratosharkWelcomePage;
}

class StratosharkWelcomePage : public WelcomePage
{
    Q_OBJECT
public:
    explicit StratosharkWelcomePage(QWidget *parent = 0);
    virtual ~StratosharkWelcomePage();

protected:
    virtual QString getReleaseLabel() override;
    virtual QString getReleaseLabelGlue() override;
};

#endif // STRATOSHARK_WELCOME_PAGE_H
