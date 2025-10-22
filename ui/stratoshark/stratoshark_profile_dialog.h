/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STRATOSHARK_PROFILE_DIALOG_H
#define STRATOSHARK_PROFILE_DIALOG_H

#include <config.h>

#include "profile_dialog.h"

namespace Ui {
class StratosharkProfileDialog;
}

class StratosharkProfileDialog : public ProfileDialog
{
    Q_OBJECT

public:
    explicit StratosharkProfileDialog(QWidget *parent = 0);
    virtual ~StratosharkProfileDialog();
};

#endif // STRATOSHARK_PROFILE_DIALOG_H
