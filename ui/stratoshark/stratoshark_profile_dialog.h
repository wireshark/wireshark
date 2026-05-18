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

/**
 * @brief Stratoshark-specific specialisation of the profile management dialog.
 */
class StratosharkProfileDialog : public ProfileDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the dialog and initialises Stratoshark-specific profile UI.
     * @param parent Optional parent widget.
     */
    explicit StratosharkProfileDialog(QWidget *parent = 0);

    /** @brief Destroys the dialog. */
    virtual ~StratosharkProfileDialog();
};

#endif // STRATOSHARK_PROFILE_DIALOG_H
