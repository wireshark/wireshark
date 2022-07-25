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
// Sparkle stores its state in ~/Library/Preferences/org.wireshark.Wireshark.plist.
// You can check its log output via `log stream | grep -i sparkle`.

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

void sparkle_software_update_init(const char *url, bool enabled, int interval)
{
    [[[SparkleBridge sharedStandardUpdaterController] updater] setAutomaticallyChecksForUpdates: enabled];
    [[[SparkleBridge sharedStandardUpdaterController] updater] setUpdateCheckInterval: interval];
    [[[SparkleBridge sharedStandardUpdaterController] updater] setFeedURL: [NSURL URLWithString: [[NSString alloc] initWithUTF8String: url] ]];
}

void sparkle_software_update_check(void)
{
    [[SparkleBridge sharedStandardUpdaterController] checkForUpdates: [[NSApplication sharedApplication] delegate]];
}
