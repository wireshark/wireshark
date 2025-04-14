/** @file
 *
 * Stratoshark - System call and event log analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <main_application.h>

class StratosharkApplication : public MainApplication
{
public:
    explicit StratosharkApplication(int &argc, char **argv);
    ~StratosharkApplication();

private:
    void initializeIcons() override;
};

extern StratosharkApplication *ssApp;
