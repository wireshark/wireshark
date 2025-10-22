/* stratoshark_profile_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "stratoshark_profile_dialog.h"

StratosharkProfileDialog::StratosharkProfileDialog(QWidget *parent) :
    ProfileDialog(parent)
{
    autoSwitchLimitLabel()->setText(tr("Auto switch event limit"));
}

StratosharkProfileDialog::~StratosharkProfileDialog()
{
}
