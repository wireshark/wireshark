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

// XXX Is there a more reliable way to do this?
#ifdef SPUUserUpdateState_h
#define HAVE_SPARKLE_2
#endif

// https://sparkle-project.org/documentation/customization/
// Sparkle stores its state in ~/Library/Preferences/org.wireshark.Wireshark.plist.
// You can check its log output via `log stream | grep -i sparkle`.

#ifdef HAVE_SPARKLE_2
// The Sparkle 1 UI provided a sharedUpdater singleton, which is deprecated
// in Sparkle 2:
//   https://sparkle-project.org/documentation/upgrading/
// Create our own singleton which uses the updated API.
//   https://sparkle-project.org/documentation/programmatic-setup/

@interface SparkleBridge : NSObject
+ (SPUStandardUpdaterController *)sharedStandardUpdaterController;
@end

@implementation SparkleBridge

+ (SPUStandardUpdaterController *)sharedStandardUpdaterController {
    static SPUStandardUpdaterController *sharedStandardUpdaterController_ = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedStandardUpdaterController_ = [[SPUStandardUpdaterController alloc] initWithUpdaterDelegate: nil userDriverDelegate: nil];
    });
    return sharedStandardUpdaterController_;
}

@end
#endif

void sparkle_software_update_init(const char *url, bool enabled, int interval)
{
#ifdef HAVE_SPARKLE_2
    [[[SparkleBridge sharedStandardUpdaterController] updater] setAutomaticallyChecksForUpdates: enabled];
    [[[SparkleBridge sharedStandardUpdaterController] updater] setUpdateCheckInterval: interval];
    [[[SparkleBridge sharedStandardUpdaterController] updater] setFeedURL: [NSURL URLWithString: [[NSString alloc] initWithUTF8String: url] ]];
#else
    [[SUUpdater sharedUpdater] setAutomaticallyChecksForUpdates: enabled];
    [[SUUpdater sharedUpdater] setUpdateCheckInterval: interval];
    [[SUUpdater sharedUpdater] setFeedURL: [NSURL URLWithString: [[NSString alloc] initWithUTF8String: url] ]];
#endif
}

void sparkle_software_update_check(void)
{
#ifdef HAVE_SPARKLE_2
    [[SparkleBridge sharedStandardUpdaterController] checkForUpdates: [[NSApplication sharedApplication] delegate]];
#else
    [[SUUpdater sharedUpdater] checkForUpdates: [[NSApplication sharedApplication] delegate]];
#endif
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
