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

/**
 * @brief MainApplication subclass that initialises Stratoshark-specific
 *        resources and branding at application startup.
 */
class StratosharkApplication : public MainApplication
{
public:
    /**
     * @brief Constructs the StratosharkApplication and performs
     *        Stratoshark-specific initialisation.
     * @param argc Reference to the command-line argument count.
     * @param argv Command-line argument vector.
     */
    explicit StratosharkApplication(int &argc, char **argv);

    /**
     * @brief Destroys the application and releases all associated resources.
     */
    ~StratosharkApplication();

private:
    /**
     * @brief Loads and registers the Stratoshark application and window icons,
     *        overriding the base-class icon set with Stratoshark-specific assets.
     */
    void initializeIcons() override;
};

extern StratosharkApplication *ssApp;
