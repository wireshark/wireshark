/** @file
 *
 * This code is based upon:
 * https://forum.qt.io/topic/82609/remove-native-mac-menu-items-such-as-show-tab-bar
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COCOABRIDGE_H
#define COCOABRIDGE_H

/**
 * @brief A bridge class providing macOS Cocoa specific functionalities.
 */
class CocoaBridge
{

    /**
     * @brief Default constructor for CocoaBridge.
     */
    CocoaBridge() {}

public:
    /**
     * @brief Cleans up OS-generated menu items in macOS.
     */
    static void cleanOSGeneratedMenuItems();

    /**
     * @brief Reveals the specified file in the macOS Finder.
     * @param file_path The path to the file to show.
     */
    static void showInFinder(char const *file_path);

    /**
     * @brief Sets the application dock icon based on capture state.
     * @param capture_in_progress True if a capture is currently in progress, false otherwise.
     */
    static void setCaptureIcon(bool capture_in_progress);
};

#endif // COCOABRIDGE_H
