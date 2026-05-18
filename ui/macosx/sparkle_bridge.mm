/* sparkle_bridge.mm
 *
 * Class wrapper for the macOS Sparkle update framework.
 *
 * This Objective-C file (.m) bridges between Wireshark's C/C++ code and
 * the Sparkle 2 framework, which provides native macOS software-update UI
 * and logic.  Think of it as the macOS counterpart to the WinSparkle calls
 * in the #ifdef _WIN32 section of software_update.c.
 *
 * Quick Objective-C primer for C++ developers
 * ============================================
 *
 * Syntax mapping (Objective-C → C++ equivalent):
 *
 *   @interface Foo : Bar        →  class Foo : public Bar {
 *   @end                        →  };
 *   @implementation Foo         →  (method definitions for Foo)
 *   + (Type)method              →  static method (class-level)
 *   - (Type)method              →  instance method
 *   [obj method]                →  obj->method()      (message send)
 *   [obj method: arg]           →  obj->method(arg)
 *   [Cls alloc]                 →  new Cls()           (allocate)
 *   [[Cls alloc] init]          →  new Cls()           (allocate + construct)
 *   nil                         →  nullptr
 *   @"string"                   →  NSString literal (like QString::fromUtf8("string"))
 *
 *   <SPUUpdaterDelegate>        →  implements an interface / pure virtual base
 *                                  (called a "protocol" in Objective-C)
 *
 *   dispatch_once(&token, ^{…}) →  std::call_once(flag, [&]{…})
 *                                  The ^{…} syntax is a "block" (≈ C++ lambda).
 *
 * Key Sparkle 2 types used here:
 *
 *   SPUStandardUpdaterController  — High-level controller that owns the
 *                                   updater and its UI.  Comparable to a
 *                                   QObject that bundles business logic
 *                                   and a dialog.
 *
 *   SPUUpdater                    — The updater engine accessed via the
 *                                   controller's `updater` property.
 *                                   Exposes settings like check interval,
 *                                   auto-check, and the feed URL.
 *
 *   SPUUpdaterDelegate            — Protocol (interface) that lets us
 *                                   supply the appcast URL dynamically
 *                                   rather than hard-coding it in
 *                                   Info.plist.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ws_diag_control.h>

#include <ui/macosx/sparkle_bridge.h>

/* Cocoa.h is the umbrella header for Apple's application framework
 * (AppKit + Foundation) — the macOS equivalent of #include <QtWidgets>. */
#import <Cocoa/Cocoa.h>

/* Public header of the Sparkle framework. */
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

/* Module-level variable holding the appcast feed URL.
 * Set once during sparkle_software_update_init() and returned to Sparkle
 * on demand via the delegate callback below. */
static NSString *appUpdateURL = nil;

/* Gentle-reminder callbacks registered from C++ via setGentleReminderCallbacks().
 * These are invoked on the main thread by the AppUserDriverDelegate below. */
static sparkle_update_attention_callback_t gentleAttentionCallback_ = NULL;

/* Relaunch-postponement callbacks registered from C++ via setRelaunchPostponementCallbacks().
 * These are invoked on the main thread by the AppUpdaterDelegate below. */
static sparkle_postpone_relaunch_callback_t postponeRelaunchCallback_ = NULL;
static sparkle_will_relaunch_callback_t     willRelaunchCallback_     = NULL;

/**
 * @brief AppUpdaterDelegate — implements the SPUUpdaterDelegate protocol.
 *
 * In C++ terms this is a small class that implements a single virtual
 * method from an interface.  Sparkle calls feedURLStringForUpdater:
 * whenever it needs the appcast URL, letting us supply it at runtime
 * instead of baking it into the application bundle's Info.plist.
 */
@interface AppUpdaterDelegate :NSObject <SPUUpdaterDelegate>
@end

@implementation AppUpdaterDelegate

- (nullable NSString *)feedURLStringForUpdater:(SPUUpdater *)updater {
    return appUpdateURL;
}

/* Called when Sparkle is about to relaunch the app for an update.
 *
 * Returning YES tells Sparkle: "wait — I'll call installHandler when
 * I'm done saving / cleaning up."  This is the place to save open
 * capture files, flush preferences, etc.
 *
 * The installHandler block is stored in a C-compatible trampoline so
 * the registered C++ callback can invoke it without knowing about
 * Objective-C blocks. */
- (BOOL)updater:(SPUUpdater *)updater
    shouldPostponeRelaunchForUpdate:(SUAppcastItem *)item
              untilInvokingBlock:(void (^)(void))installHandler {
    if (postponeRelaunchCallback_ == NULL) {
        return NO;
    }

    /* Copy the block to the heap and retain it manually.
     * Without ARC we are responsible for the reference count. */
    void (^savedHandler)(void) = [installHandler copy];

    postponeRelaunchCallback_(
        /* proceed function — called by C++ when ready: */
        [](void *ctx) {
            void (^handler)(void) = (void (^)(void))ctx;
            handler();
            [handler release];  /* Balance the copy/retain from above */
        },
        /* context — the copied block, cast to void*: */
        (void *)savedHandler
    );

    return YES;
}

/* Called immediately before Sparkle relaunches the application.
 * This is a last-chance notification — the relaunch will happen
 * regardless of what we do here. */
- (void)updaterWillRelaunchApplication:(SPUUpdater *)updater {
    if (willRelaunchCallback_ != NULL) {
        willRelaunchCallback_();
    }
}

@end

/**
 * @brief AppUserDriverDelegate — implements the SPUStandardUserDriverDelegate protocol
 * for gentle scheduled update reminders.
 *
 * Instead of immediately showing a modal update dialog for background checks,
 * Sparkle calls these delegate methods so the application can display a
 * non-intrusive hint (badge, toolbar button, sidebar item, etc.) and let the
 * user decide when to engage.
 *
 * See https://sparkle-project.org/documentation/gentle-reminders/
 *
 * In C++ terms this class implements a multi-method interface whose callbacks
 * are forwarded to plain C function pointers registered via
 * SparkleBridge::setGentleReminderCallbacks().
 */
@interface AppUserDriverDelegate : NSObject <SPUStandardUserDriverDelegate>
@end

@implementation AppUserDriverDelegate

/* Declare support for gentle reminders.  Without this Sparkle will not
 * call any of the other delegate methods below. */
- (BOOL)supportsGentleScheduledUpdateReminders {
    return YES;
}

/* Called when Sparkle wants to show a scheduled (non-user-initiated) update.
 *
 * - immediateFocus == YES:  the check happened close to app launch;
 *   return YES so Sparkle shows its normal, prominent update dialog.
 * - immediateFocus == NO:   the check was a quiet background poll;
 *   return NO so we can show our own gentle reminder instead. */
- (BOOL)standardUserDriverShouldHandleShowingScheduledUpdate:(SUAppcastItem *)update
                                          andInImmediateFocus:(BOOL)immediateFocus {
    return immediateFocus;
}

/* The user has engaged with the update alert (clicked the gentle reminder
 * or otherwise brought the Sparkle window into focus).  The application
 * should hide its custom reminder UI. */
- (void)standardUserDriverDidReceiveUserAttentionForUpdate:(SUAppcastItem *)update {
    if (gentleAttentionCallback_ != NULL) {
        gentleAttentionCallback_();
    }
}

@end

/**
 * @brief Singleton wrapper around SPUStandardUpdaterController for Sparkle 2.
 *
 * Sparkle 2 no longer provides a built-in shared instance (the Sparkle 1
 * [SUUpdater sharedUpdater] was deprecated). This class fills that gap
 * by creating exactly one SPUStandardUpdaterController on first access
 * using dispatch_once (equivalent to std::call_once / Q_GLOBAL_STATIC).
 *
 * The "+" prefix means sharedStandardUpdaterController is a class method
 * (like a C++ static method), so callers write:
 * @code
 *   [SparkleUpdateController sharedStandardUpdaterController]
 * @endcode
 * rather than creating an instance first.
 */
@interface SparkleUpdateController : NSObject

/**
 * @brief Returns the shared SPUStandardUpdaterController instance, creating it on first call.
 * @return The singleton SPUStandardUpdaterController used for all update operations.
 */
+ (SPUStandardUpdaterController *)sharedStandardUpdaterController;

@end

@implementation SparkleUpdateController

+ (SPUStandardUpdaterController *)sharedStandardUpdaterController {
    static AppUpdaterDelegate *updaterDelegate_ = nil;
    static AppUserDriverDelegate *userDriverDelegate_ = nil;
    static SPUStandardUpdaterController *sharedStandardUpdaterController_ = nil;
    static dispatch_once_t onceToken;
    /* dispatch_once guarantees thread-safe, one-time initialization —
     * same semantics as std::call_once or a Meyer's singleton in C++. */
    dispatch_once(&onceToken, ^{
        updaterDelegate_ = [AppUpdaterDelegate alloc];
        userDriverDelegate_ = [AppUserDriverDelegate alloc];
        /* SPUStandardUpdaterController is initialized with our delegate
         * (to supply the feed URL) and a userDriverDelegate (to support
         * gentle scheduled update reminders).  This is roughly:
         *   new SPUStandardUpdaterController(updaterDelegate_, userDriverDelegate_); */
        sharedStandardUpdaterController_ = [[SPUStandardUpdaterController alloc] initWithUpdaterDelegate: updaterDelegate_ userDriverDelegate: userDriverDelegate_];
    });
    return sharedStandardUpdaterController_;
}

@end

/* DIAG_OFF/ON suppress a compiler warning about calling
 * clearFeedURLFromUserDefaults, which may not exist at compile time
 * (we check at runtime via respondsToSelector:). */
DIAG_OFF(objc-method-access)

void SparkleBridge::updateInit(const char *url, bool enabled, int interval)
{
    /* Convert the C string to an NSString (≈ QString::fromUtf8). */
    appUpdateURL = [[NSString alloc] initWithUTF8String: url];

    /* Configure the updater via the controller's `updater` property.
     * The chained [[ ]] calls read as: controller->updater()->setX(value). */
    [[[SparkleUpdateController sharedStandardUpdaterController] updater] setAutomaticallyChecksForUpdates: enabled];
    [[[SparkleUpdateController sharedStandardUpdaterController] updater] setUpdateCheckInterval: interval];

    /* clearFeedURLFromUserDefaults removes any hard-coded feed URL that
     * may have been persisted by earlier Wireshark versions (≤ 4.4) which
     * called setFeedURL directly.  The method was added in Sparkle 2.4.0,
     * so we guard with respondsToSelector: (≈ runtime feature detection,
     * similar to checking a function pointer before calling it in C). */
    if ([[[SparkleUpdateController sharedStandardUpdaterController] updater] respondsToSelector:@selector(clearFeedURLFromUserDefaults:)]) {
        [[[SparkleUpdateController sharedStandardUpdaterController] updater] clearFeedURLFromUserDefaults];
    }
}

DIAG_ON(objc-method-access)

void SparkleBridge::updateCheck(void)
{
    /* Trigger a user-initiated update check.  Sparkle handles the entire
     * UI flow from here: progress indicator → release notes → download →
     * install prompt.  The sender argument (NSApp delegate) is an
     * Objective-C convention for the UI element that initiated the action
     * (similar to QObject *sender in Qt signals). */
    [[SparkleUpdateController sharedStandardUpdaterController] checkForUpdates: [[NSApplication sharedApplication] delegate]];
}

void SparkleBridge::setUpdateCallbacks(
    sparkle_update_attention_callback_t attention_cb,
    sparkle_postpone_relaunch_callback_t postpone_relaunch_cb,
    sparkle_will_relaunch_callback_t will_relaunch_cb)
{
    gentleAttentionCallback_  = attention_cb;
    postponeRelaunchCallback_ = postpone_relaunch_cb;
    willRelaunchCallback_     = will_relaunch_cb;
}

