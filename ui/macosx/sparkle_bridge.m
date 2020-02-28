/* sparkle_bridge.m
 *
 * C wrapper for the Sparkle API
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/macosx/sparkle_bridge.h>

#import <Cocoa/Cocoa.h>

#import <Sparkle.h>

// https://sparkle-project.org/documentation/customization/
// Sparkle stores its state in ~/Library/Preferences/org.wireshark.Wireshark.plist

void sparkle_software_update_init(const char *url, bool enabled, int interval)
{
    [[SUUpdater sharedUpdater] setAutomaticallyChecksForUpdates: enabled];
    [[SUUpdater sharedUpdater] setUpdateCheckInterval: interval];
    [[SUUpdater sharedUpdater] setFeedURL: [NSURL URLWithString: [[NSString alloc] initWithUTF8String: url] ]];
}

void sparkle_software_update_check(void)
{
    [[SUUpdater sharedUpdater] checkForUpdates: [[NSApplication sharedApplication] delegate]];
}

// Sparkle requires NSApplicationWillTerminateNotification in order to
// properly update in the background.
//
// https://github.com/sparkle-project/Sparkle/issues/232
// https://github.com/sparkle-project/Sparkle/issues/892
// https://github.com/sparkle-project/Sparkle/issues/839
//
// This depends on the Sparkle framework being able to run Autoupdate.app.
// If that's not reliable we might want to disable SUAllowsAutomaticUpdates
// above.

void sparkle_software_update_cleanup()
{
    [[NSNotificationCenter defaultCenter]
            postNotificationName:@"NSApplicationWillTerminateNotification"
        object:nil];
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
