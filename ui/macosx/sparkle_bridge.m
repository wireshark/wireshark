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

#include <ws_diag_control.h>

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

// https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ObjectiveC/Introduction/introObjectiveC.html
// http://pierre.chachatelier.fr/programmation/fichiers/cpp-objc-en.pdf

// We should update this each time our preferences change.
static NSString *appUpdateURL = nil;

@interface AppUpdaterDelegate :NSObject <SPUUpdaterDelegate>
@end

@implementation AppUpdaterDelegate
- (nullable NSString *)feedURLStringForUpdater:(SPUUpdater *)updater {
    return appUpdateURL;
}

@end

@interface SparkleBridge : NSObject
+ (SPUStandardUpdaterController *)sharedStandardUpdaterController;
@end

@implementation SparkleBridge

+ (SPUStandardUpdaterController *)sharedStandardUpdaterController {
    static AppUpdaterDelegate *updaterDelegate_ = nil;
    static SPUStandardUpdaterController *sharedStandardUpdaterController_ = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        updaterDelegate_ = [AppUpdaterDelegate alloc];
        sharedStandardUpdaterController_ = [[SPUStandardUpdaterController alloc] initWithUpdaterDelegate: updaterDelegate_ userDriverDelegate: nil];
    });
    return sharedStandardUpdaterController_;
}

@end

DIAG_OFF(objc-method-access)

void sparkle_software_update_init(const char *url, bool enabled, int interval)
{
    appUpdateURL = [[NSString alloc] initWithUTF8String: url];
    [[[SparkleBridge sharedStandardUpdaterController] updater] setAutomaticallyChecksForUpdates: enabled];
    [[[SparkleBridge sharedStandardUpdaterController] updater] setUpdateCheckInterval: interval];
    // The documentation recommends calling clearFeedURLFromUserDefaults if we've called
    // setFeedURL (and we have in 4.4 and earlier), but it was added in Sparkle 2.4.0
    if ([[[SparkleBridge sharedStandardUpdaterController] updater] respondsToSelector:@selector(clearFeedURLFromUserDefaults:)]) {
        [[[SparkleBridge sharedStandardUpdaterController] updater] clearFeedURLFromUserDefaults];
    }
}

DIAG_ON(objc-method-access)

void sparkle_software_update_check(void)
{
    [[SparkleBridge sharedStandardUpdaterController] checkForUpdates: [[NSApplication sharedApplication] delegate]];
}
