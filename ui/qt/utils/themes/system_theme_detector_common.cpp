/* system_theme_detector_common.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Cross-platform helpers shared by every SystemThemeDetector backend.
 * Kept in a separate TU so each platform-specific .cpp/.mm stays free
 * of dependencies on QGuiApplication and ColorMath — those only need
 * to be pulled in once, here.
 */

#include "ui/qt/utils/themes/system_theme_detector.h"

#include "ui/qt/utils/themes/color_math.h"

#include <QGuiApplication>
#include <QPalette>

bool SystemThemeDetector::calibrateDefaultIsDark()
{
    // Classify the pristine OS palette by WCAG relative luminance.  Must
    // be called while the palette is still untouched by any theme
    // override — every back-end invokes this from its Impl ctor, which
    // ThemeManager in turn constructs before applying its first theme.
    return ColorMath::isDark(QGuiApplication::palette().color(QPalette::Window));
}

SystemThemeDetector::Scheme
SystemThemeDetector::resolveDefault(Scheme s, bool defaultIsDark)
{
    if (s == Scheme::Unknown)
        return defaultIsDark ? Scheme::Dark : Scheme::Light;
    return s;
}
