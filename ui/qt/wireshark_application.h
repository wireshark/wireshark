/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WIRESHARK_APPLICATION_H
#define WIRESHARK_APPLICATION_H

#include <main_application.h>

/**
 * @brief Top-level Qt application object for the Wireshark GUI.
 */
class WiresharkApplication : public MainApplication
{
public:
    /**
     * @brief Constructs the Wireshark application instance.
     * @param argc Reference to the command-line argument count.
     * @param argv Array of command-line argument strings.
     */
    explicit WiresharkApplication(int &argc, char **argv);

    /**
     * @brief Destroys the Wireshark application instance.
     */
    ~WiresharkApplication();

private:
    /**
     * @brief Initializes Wireshark-specific icons, overriding the base class implementation.
     */
    void initializeIcons() override;
};

/** @brief Global pointer to the single WiresharkApplication instance. */
extern WiresharkApplication *wsApp;

#endif // WIRESHARK_APPLICATION_H
