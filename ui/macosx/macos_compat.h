/* cocoa_bridge.h
    *
    * This code was taken directly from:
    * https://forum.qt.io/topic/82609/remove-native-mac-menu-items-such-as-show-tab-bar
    *
    * Wireshark - Network traffic analyzer
    * By Gerald Combs <gerald@wireshark.org>
    * Copyright 1998 Gerald Combs
    *
    * SPDX-License-Identifier: GPL-2.0-or-later
    */

#ifndef MACOS_COMPAT_H
#define MACOS_COMPAT_H

#import <Cocoa/Cocoa.h>

#if !defined(MAC_OS_X_VERSION_10_9)
#    define MAC_OS_X_VERSION_10_9 1090
#endif

#if !defined(MAC_OS_X_VERSION_10_10)
#    define MAC_OS_X_VERSION_10_10 101000
#endif

#if !defined(MAC_OS_X_VERSION_10_12)
#    define MAC_OS_X_VERSION_10_12 101200
#endif

#if (MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_X_VERSION_10_12)
@interface NSWindow (macOS10_12_SDK)
+ (void)setAllowsAutomaticWindowTabbing:(BOOL)allow;
@end
#endif

#endif // MACOS_COMPAT_H
