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

class CocoaBridge
{

    CocoaBridge() {}

public:
    static void cleanOSGeneratedMenuItems();

    static void showInFinder(char const *file_path);

};

#endif // COCOABRIDGE_H
