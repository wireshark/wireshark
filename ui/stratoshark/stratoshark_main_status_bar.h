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

/**
 * @brief Stratoshark-specific main window status bar, overriding capture
 *        statistics display to use Stratoshark terminology and metrics
 *        (e.g. "events" in place of "packets").
 */
class StratosharkMainStatusBar : public MainStatusBar
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the Stratoshark main status bar.
     * @param parent Optional parent widget.
     */
    explicit StratosharkMainStatusBar(QWidget *parent = 0);

    /**
     * @brief Destroys the status bar.
     */
    virtual ~StratosharkMainStatusBar();

protected:
    /**
     * @brief Updates the status bar's capture statistics section with
     *        Stratoshark-appropriate event counts and display-filter statistics.
     */
    void showCaptureStatistics() override;
};

#endif // STRATOSHARK_MAIN_STATUS_BAR_H
