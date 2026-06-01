/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COLOR_MATH_H
#define COLOR_MATH_H

#include <ui/qt/utils/theme_manager.h>

#include <QColor>

/**
 * Pure color-math helpers, independent of the running app's theme or
 * palette.
 *
 * Every method is static and side-effect-free except
 * contrastingText(QColor) which — when the surface has alpha — asks
 * ThemeManager for the current app mode to pick a fallback backdrop.
 * That coupling is deliberate: the caller wants "the right foreground
 * for this translucent surface as rendered right now", which is a
 * theme-runtime question.
 */
class ColorMath
{
public:
    // ---------------------------------------------------------------
    // Luminance & contrast
    // ---------------------------------------------------------------

    /** WCAG relative luminance in the [0, 1] range. */
    static double relativeLuminance(const QColor &color);

    /** WCAG contrast ratio between two opaque colors.  Higher values
     *  are more contrasty; 4.5 is the AA threshold for body text. */
    static qreal contrastRatio(const QColor &color1, const QColor &color2);

    /** Mix `c` toward contrastingText(bg) until contrastRatio(result, bg)
     *  >= minRatio.  Binary-searches the mix ratio (24 iterations →
     *  < 0.001 precision).  Used to enforce WCAG contrast on derived
     *  tokens (section headers against the base, header-gradient end
     *  against the title text) without forcing every theme author to
     *  hand-pick the values.  When `c` already meets the target it is
     *  returned unchanged.  If the math can't reach the target (rare;
     *  only when `c` is already on the same luminance side as
     *  contrastingText(bg) and saturated), returns contrastingText(bg)
     *  directly — favoring readability over hue. */
    static QColor ensureContrast(const QColor &c, const QColor &bg, qreal minRatio);

    /** Returns true if the given color's relative luminance is below
     *  the WCAG equal-contrast threshold (≈0.179).  Purely a color-
     *  math helper; independent of the running app's theme. */
    static bool isDark(const QColor &color);

    // ---------------------------------------------------------------
    // Mix / shade
    // ---------------------------------------------------------------

    /** Linear blend of two colors at ratio `r`.  r=0 returns a, r=1
     *  returns b.  Alpha-aware. */
    static QColor         mix(const QColor &a, const QColor &b, qreal ratio = 0.5);
    static ThemeColorPair mix(const ThemeColorPair &a, const ThemeColorPair &b, qreal ratio = 0.5);

    /** Mix the given color with black at percent %.  Hover typically
     *  8-12 %, pressed 16-20 %, gradient backdrop 50-65 %. */
    static QColor         darken(const QColor &c, int percent);
    static ThemeColorPair darken(const ThemeColorPair &p, int percent);

    /** Mix the given color with white at percent %.  Used for text on
     *  dark surfaces (30-70 %). */
    static QColor         lighten(const QColor &c, int percent);
    static ThemeColorPair lighten(const ThemeColorPair &p, int percent);

    // ---------------------------------------------------------------
    // Alpha
    // ---------------------------------------------------------------

    /** Set the alpha channel to an integer 0-255. */
    static QColor         withAlpha(const QColor &c, int alpha);
    static ThemeColorPair withAlpha(const ThemeColorPair &p, int alpha);

    /** Set the alpha channel to a float 0.0-1.0. */
    static QColor         withAlphaF(const QColor &c, qreal alpha);
    static ThemeColorPair withAlphaF(const ThemeColorPair &p, qreal alpha);

    // ---------------------------------------------------------------
    // Contrast & state
    // ---------------------------------------------------------------

    /** Returns Qt::black or Qt::white — whichever reads better on the
     *  given surface color.  If the surface is translucent, picks the
     *  app's current dark/light mode as the backdrop. */
    static QColor         contrastingText(const QColor &surface);
    static ThemeColorPair contrastingText(const ThemeColorPair &pair);

    /** Same as contrastingText(), but with the caller supplying the
     *  backdrop explicitly — useful when rendering onto a known
     *  surface (e.g. the blue header gradient) rather than the
     *  app palette. */
    static QColor         contrastingTextOver(const QColor &surface, const QColor &backdrop);

    /** Standard "disabled" fade: mix(color, background, 0.4). */
    static QColor         disabled(const QColor &c, const QColor &background);
    static ThemeColorPair disabled(const ThemeColorPair &p, const QColor &background);

    /** Subtle hover tint: mix(color, background, 0.1). */
    static QColor         hoverBg(const QColor &c, const QColor &background);
    static ThemeColorPair hoverBg(const ThemeColorPair &p, const QColor &background);
};

#endif /* COLOR_MATH_H */
