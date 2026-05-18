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

/**
 * @brief Stratoshark-specific About dialog, extending the shared AboutDialog
 *        with Stratoshark branding and version information.
 */
class StratosharkAboutDialog : public AboutDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the Stratoshark About dialog.
     * @param parent Optional parent widget.
     */
    explicit StratosharkAboutDialog(QWidget *parent = 0);

    /**
     * @brief Destroys the dialog.
     */
    virtual ~StratosharkAboutDialog() {}
};

#endif // STRATOSHARK_ABOUT_DIALOG_H
