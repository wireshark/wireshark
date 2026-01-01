/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STRATOSHARK_MAIN_STATUS_BAR_H
#define STRATOSHARK_MAIN_STATUS_BAR_H

#include "config.h"
#include <ui/qt/main_status_bar.h>

class StratosharkMainStatusBar : public MainStatusBar
{
    Q_OBJECT
public:
    explicit StratosharkMainStatusBar(QWidget *parent = 0);
    virtual ~StratosharkMainStatusBar();

protected:
    void showCaptureStatistics() override;

};

#endif // STRATOSHARK_MAIN_STATUS_BAR_H
