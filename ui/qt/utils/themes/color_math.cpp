/* color_math.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "ui/qt/utils/themes/color_math.h"

#include <cmath>

// 0.179 is the WCAG-derived threshold where contrast ratios against
// white and black are equal.  Above it, black reads better; below, white.
#define THRESHOLD_EQUALIBRIUM_WCAG 0.179

// WCAG relative-luminance sRGB linearization.
// https://www.w3.org/TR/WCAG21/#dfn-relative-luminance
static double srgbToLinear(double channel)
{
    // channel is in [0, 1]
    return (channel <= 0.03928)
        ? channel / 12.92
        : std::pow((channel + 0.055) / 1.055, 2.4);
}

// -------------------------------------------------------------------
// Luminance & contrast
// -------------------------------------------------------------------

double ColorMath::relativeLuminance(const QColor &color)
{
    const double r = srgbToLinear(color.redF());
    const double g = srgbToLinear(color.greenF());
    const double b = srgbToLinear(color.blueF());
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

qreal ColorMath::contrastRatio(const QColor &color1, const QColor &color2)
{
    const qreal la = relativeLuminance(color1);
    const qreal lb = relativeLuminance(color2);
    const qreal lighter = qMax(la, lb);
    const qreal darker  = qMin(la, lb);
    return (lighter + 0.05) / (darker + 0.05);
}

QColor ColorMath::ensureContrast(const QColor &c, const QColor &bg, qreal minRatio)
{
    if (contrastRatio(c, bg) >= minRatio) {
        return c;
    }
    const QColor target = contrastingText(bg);
    qreal lo = 0.0, hi = 1.0;
    for (int i = 0; i < 24; ++i) {
        const qreal m = (lo + hi) / 2.0;
        const QColor test = mix(c, target, m);
        if (contrastRatio(test, bg) >= minRatio) {
            hi = m;
        } else {
            lo = m;
        }
    }
    const QColor out = mix(c, target, hi);
    return contrastRatio(out, bg) >= minRatio ? out : target;
}

bool ColorMath::isDark(const QColor &color)
{
    return relativeLuminance(color) < THRESHOLD_EQUALIBRIUM_WCAG;
}

// -------------------------------------------------------------------
// Mix / shade
// -------------------------------------------------------------------

QColor ColorMath::mix(const QColor &color1, const QColor &color2, qreal ratio)
{
    ratio = qBound(0.0, ratio, 1.0);
    const qreal inverse = 1.0 - ratio;

    return QColor::fromRgbF(
        color1.redF()   * inverse + color2.redF()   * ratio,
        color1.greenF() * inverse + color2.greenF() * ratio,
        color1.blueF()  * inverse + color2.blueF()  * ratio,
        color1.alphaF() * inverse + color2.alphaF() * ratio
    );
}

ThemeColorPair ColorMath::mix(const ThemeColorPair &pair1, const ThemeColorPair &pair2, qreal ratio)
{
    return ThemeColorPair {
        mix(pair1.light, pair2.light, ratio),
        mix(pair1.dark,  pair2.dark,  ratio)
    };
}

QColor ColorMath::darken(const QColor &color, int percent)
{
    const int p = qBound(0, percent, 100);
    const int r = color.red()   * (100 - p) / 100;
    const int g = color.green() * (100 - p) / 100;
    const int b = color.blue()  * (100 - p) / 100;
    return QColor(r, g, b, color.alpha());
}

ThemeColorPair ColorMath::darken(const ThemeColorPair &pair, int percent)
{
    return ThemeColorPair { darken(pair.light, percent), darken(pair.dark, percent) };
}

QColor ColorMath::lighten(const QColor &color, int percent)
{
    const int p = qBound(0, percent, 100);
    const int r = color.red()   + (255 - color.red())   * p / 100;
    const int g = color.green() + (255 - color.green()) * p / 100;
    const int b = color.blue()  + (255 - color.blue())  * p / 100;
    return QColor(r, g, b, color.alpha());
}

ThemeColorPair ColorMath::lighten(const ThemeColorPair &pair, int percent)
{
    return ThemeColorPair { lighten(pair.light, percent), lighten(pair.dark, percent) };
}

// -------------------------------------------------------------------
// Alpha
// -------------------------------------------------------------------

QColor ColorMath::withAlpha(const QColor &color, int alpha)
{
    QColor c = color;
    c.setAlpha(alpha);
    return c;
}

ThemeColorPair ColorMath::withAlpha(const ThemeColorPair &pair, int alpha)
{
    return ThemeColorPair { withAlpha(pair.light, alpha), withAlpha(pair.dark, alpha) };
}

QColor ColorMath::withAlphaF(const QColor &color, qreal alpha)
{
    QColor c = color;
    c.setAlphaF(alpha);
    return c;
}

ThemeColorPair ColorMath::withAlphaF(const ThemeColorPair &pair, qreal alpha)
{
    return ThemeColorPair { withAlphaF(pair.light, alpha), withAlphaF(pair.dark, alpha) };
}

// -------------------------------------------------------------------
// Contrast & state
// -------------------------------------------------------------------

QColor ColorMath::contrastingText(const QColor &surface)
{
    if (surface.alphaF() >= 1.0) {
        // Fast path: backdrop doesn't matter for opaque surfaces.
        return relativeLuminance(surface) > THRESHOLD_EQUALIBRIUM_WCAG
            ? Qt::black
            : Qt::white;
    }
    // Translucent surface — pick the backdrop from the app's current
    // dark/light state so the alpha-composite reflects what the user
    // actually sees.
    const QColor backdrop = ThemeManager::instance()->isDarkMode() ? Qt::black : Qt::white;
    return contrastingTextOver(surface, backdrop);
}

ThemeColorPair ColorMath::contrastingText(const ThemeColorPair &surfacePair)
{
    return ThemeColorPair {
        contrastingText(surfacePair.light),
        contrastingText(surfacePair.dark)
    };
}

QColor ColorMath::contrastingTextOver(const QColor &surface, const QColor &backdrop)
{
    QColor effective = surface;

    // If the color is translucent, composite it over the backdrop
    // using standard alpha blending ("over" operator).
    if (surface.alphaF() < 1.0) {
        const qreal a = surface.alphaF();
        effective = QColor::fromRgbF(
            surface.redF()   * a + backdrop.redF()   * (1.0 - a),
            surface.greenF() * a + backdrop.greenF() * (1.0 - a),
            surface.blueF()  * a + backdrop.blueF()  * (1.0 - a)
        );
    }

    return relativeLuminance(effective) > THRESHOLD_EQUALIBRIUM_WCAG ? Qt::black : Qt::white;
}

QColor ColorMath::disabled(const QColor &color, const QColor &background)
{
    return mix(color, background, 0.4);
}

ThemeColorPair ColorMath::disabled(const ThemeColorPair &pair, const QColor &background)
{
    return ThemeColorPair { disabled(pair.light, background), disabled(pair.dark, background) };
}

QColor ColorMath::hoverBg(const QColor &color, const QColor &background)
{
    return mix(color, background, 0.1);
}

ThemeColorPair ColorMath::hoverBg(const ThemeColorPair &pair, const QColor &background)
{
    return ThemeColorPair { hoverBg(pair.light, background), hoverBg(pair.dark, background) };
}
