/* system_theme_detector_stub.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Placeholder SystemThemeDetector back-end used on platforms that do
 * not yet have a native implementation (Windows and Linux, as of this
 * commit).  It always reports Scheme::Unknown and never emits
 * schemeChanged, which causes ThemeManager to fall back to its
 * existing non-native detection path for mode == System.
 *
 * Replaced by system_theme_detector_win.cpp / _unix.cpp once those
 * are implemented; see analysis/theme_mode_switching/.
 */

#include "ui/qt/utils/themes/system_theme_detector.h"

struct SystemThemeDetector::Impl {
    // Intentionally empty.
};

SystemThemeDetector::SystemThemeDetector(QObject *parent)
    : QObject(parent),
      impl_(new Impl())
{
}

SystemThemeDetector::~SystemThemeDetector() = default;

SystemThemeDetector::Scheme SystemThemeDetector::currentScheme() const
{
    return Scheme::Unknown;
}
