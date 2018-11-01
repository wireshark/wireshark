/* cocoa_bridge.mm
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

#include <ui/macosx/cocoa_bridge.h>
#include <ui/macosx/macos_compat.h>

#import <Cocoa/Cocoa.h>

void CocoaBridge::cleanOSGeneratedMenuItems()
{
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

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
