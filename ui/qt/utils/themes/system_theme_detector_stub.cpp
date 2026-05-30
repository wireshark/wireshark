/* system_theme_detector_stub.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Placeholder SystemThemeDetector back-end used on platforms that do
 * not yet have a native implementation.  No native read or observer is
 * available, so the detector classifies the pristine OS palette once at
 * startup (via the shared calibration helper) and returns that value
 * for the lifetime of the process.  It never emits schemeChanged.
 *
 * Matches the Light/Dark-only contract of the other back-ends so
 * callers (notably ThemeManager::previewTheme()) can rely on
 * currentScheme() never returning Unknown.
 */

#include "ui/qt/utils/themes/system_theme_detector.h"

struct SystemThemeDetector::Impl {
    SystemThemeDetector::Scheme cached;

    Impl()
        : cached(SystemThemeDetector::calibrateDefaultIsDark()
                     ? SystemThemeDetector::Scheme::Dark
                     : SystemThemeDetector::Scheme::Light)
    {
    }
};

SystemThemeDetector::SystemThemeDetector(QObject *parent)
    : QObject(parent),
      impl_(new Impl())
{
}

SystemThemeDetector::~SystemThemeDetector() = default;

SystemThemeDetector::Scheme SystemThemeDetector::currentScheme() const
{
    return impl_ ? impl_->cached : Scheme::Unknown;
}
