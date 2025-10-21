/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STRATOSHARK_ABOUT_DIALOG_H
#define STRATOSHARK_ABOUT_DIALOG_H

#include "config.h"

#include "about_dialog.h"

class StratosharkAboutDialog : public AboutDialog
{
    Q_OBJECT

public:
    explicit StratosharkAboutDialog(QWidget *parent = 0);
    virtual ~StratosharkAboutDialog() {}

protected:
    virtual const char* getVCSVersion() override;
};

#endif // STRATOSHARK_ABOUT_DIALOG_H
