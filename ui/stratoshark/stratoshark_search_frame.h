/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STRATOSHARK_SEARCH_FRAME_H
#define STRATOSHARK_SEARCH_FRAME_H

#include <config.h>

#include "search_frame.h"

namespace Ui {
class StratosharkSearchFrame;
}

/**
 * @brief Stratoshark-specific search bar frame, extending the base SearchFrame
 *        with any Stratoshark-specific search behaviour or UI adjustments.
 */
class StratosharkSearchFrame : public SearchFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the Stratoshark search frame.
     * @param parent Optional parent widget.
     */
    explicit StratosharkSearchFrame(QWidget *parent = 0);

    /**
     * @brief Destroys the search frame.
     */
    virtual ~StratosharkSearchFrame();
};

#endif // STRATOSHARK_SEARCH_FRAME_H
