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

class StratosharkSearchFrame : public SearchFrame
{
    Q_OBJECT

public:
    explicit StratosharkSearchFrame(QWidget *parent = 0);
    virtual ~StratosharkSearchFrame();
};

#endif // STRATOSHARK_SEARCH_FRAME_H
