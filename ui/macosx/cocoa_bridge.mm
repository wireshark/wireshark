/* cocoa_bridge.mm
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/macosx/cocoa_bridge.h>
#include <ui/macosx/macos_compat.h>

#import <Cocoa/Cocoa.h>

void CocoaBridge::cleanOSGeneratedMenuItems()
{
    // This code was taken directly from:
    // https://forum.qt.io/topic/82609/remove-native-mac-menu-items-such-as-show-tab-bar

#ifdef AVAILABLE_MAC_OS_X_VERSION_10_12_AND_LATER
    // Remove (don't allow) the "Show Tab Bar" menu item from the "View" menu, if
    // supported

    if ([NSWindow respondsToSelector:@selector(setAllowsAutomaticWindowTabbing:)])
        [NSWindow setAllowsAutomaticWindowTabbing: NO];
#endif

    [[NSUserDefaults standardUserDefaults] setBool:NO forKey:@"NSFullScreenMenuItemEverywhere"];

    // Remove (disable) the "Start Dictation..." and "Emoji & Symbols" menu items
    // from the "Edit" menu

    [[NSUserDefaults standardUserDefaults] setBool:YES forKey:@"NSDisabledDictationMenuItem"];
    [[NSUserDefaults standardUserDefaults] setBool:NO forKey:@"NSDisabledCharacterPaletteMenuItem"];
}

void CocoaBridge::showInFinder(char const *file_path)
{
    NSURL *url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:file_path]];

    [[NSWorkspace sharedWorkspace] activateFileViewerSelectingURLs:@[url]];
}
