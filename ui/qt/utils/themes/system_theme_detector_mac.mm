/* system_theme_detector_mac.mm
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * macOS back-end for SystemThemeDetector.  Uses AppKit directly so
 * that Wireshark's dark/light decision does not depend on Qt's own
 * color-scheme detection (which varies between Qt minor versions and
 * across platforms).
 *
 * Read:     NSApp.effectiveAppearance collapsed to Aqua / DarkAqua via
 *           -bestMatchFromAppearancesWithNames:.
 * Observe:  AppleInterfaceThemeChangedNotification on
 *           NSDistributedNotificationCenter, delivered on the main
 *           operation queue (i.e. the GUI thread).
 *
 * Pre-Mojave (< 10.14) macOS has no system-wide dark mode, so the
 * detector returns Light and installs no observer.
 */

#include "ui/qt/utils/themes/system_theme_detector.h"

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

namespace {

SystemThemeDetector::Scheme classifyAppearance(NSAppearance *appearance)
{
    if (!appearance)
        return SystemThemeDetector::Scheme::Unknown;

    if (@available(macOS 10.14, *)) {
        NSAppearanceName match = [appearance bestMatchFromAppearancesWithNames:@[
            NSAppearanceNameAqua,
            NSAppearanceNameDarkAqua
        ]];
        if ([match isEqualToString:NSAppearanceNameDarkAqua])
            return SystemThemeDetector::Scheme::Dark;
        if ([match isEqualToString:NSAppearanceNameAqua])
            return SystemThemeDetector::Scheme::Light;
    }
    return SystemThemeDetector::Scheme::Unknown;
}

SystemThemeDetector::Scheme readCurrent()
{
    if (@available(macOS 10.14, *)) {
        NSApplication *app = [NSApplication sharedApplication];
        if (!app)
            return SystemThemeDetector::Scheme::Unknown;
        return classifyAppearance([app effectiveAppearance]);
    }
    return SystemThemeDetector::Scheme::Light;
}

} // namespace

struct SystemThemeDetector::Impl {
    id     observer = nil;
    Scheme cached   = Scheme::Unknown;
    // What the desktop's "default"/no-preference scheme renders as on THIS
    // system.  effectiveAppearance normally answers Light/Dark outright on
    // 10.14+, but we still calibrate so the rare Unknown path (NSApp not
    // yet ready, pre-Mojave) resolves the same way the Unix back-end does.
    bool   defaultIsDark = false;

    explicit Impl(SystemThemeDetector *owner)
    {
        const Scheme initial = readCurrent();
        if (initial == Scheme::Dark)
            defaultIsDark = true;
        else if (initial == Scheme::Light)
            defaultIsDark = false;
        else
            defaultIsDark = SystemThemeDetector::calibrateDefaultIsDark();

        cached = SystemThemeDetector::resolveDefault(initial, defaultIsDark);

        if (@available(macOS 10.14, *)) {
            // The block captures `owner` and `this` by value.  Lifetime
            // is safe because ~Impl() removes the observer before the
            // SystemThemeDetector's base destruction runs, and both
            // ~Impl() and the notification block execute on the main
            // queue — so the block cannot fire concurrently with, or
            // after, observer removal.
            Impl *self = this;

            observer = [[NSDistributedNotificationCenter defaultCenter]
                addObserverForName:@"AppleInterfaceThemeChangedNotification"
                            object:nil
                             queue:[NSOperationQueue mainQueue]
                        usingBlock:^(NSNotification * _Nonnull) {
                    Scheme now = SystemThemeDetector::resolveDefault(
                        readCurrent(), self->defaultIsDark);
                    if (now == self->cached)
                        return;
                    self->cached = now;
                    // Main queue == GUI thread, so direct emit is safe.
                    emit owner->schemeChanged(now);
                }];
        }
    }

    ~Impl()
    {
        if (observer) {
            [[NSDistributedNotificationCenter defaultCenter]
                removeObserver:observer];
            observer = nil;
        }
    }
};

SystemThemeDetector::SystemThemeDetector(QObject *parent)
    : QObject(parent),
      impl_(new Impl(this))
{
}

SystemThemeDetector::~SystemThemeDetector() = default;

SystemThemeDetector::Scheme SystemThemeDetector::currentScheme() const
{
    // Impl always resolves cached_ to Light/Dark via the startup
    // calibration; Scheme::Unknown is only ever returned if construction
    // somehow failed to allocate impl_.
    return impl_ ? impl_->cached : Scheme::Unknown;
}
