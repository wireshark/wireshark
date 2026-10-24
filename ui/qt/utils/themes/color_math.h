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
 * Pure color-math helpers, with two deliberate couplings to the running
 * theme:
 *
 *   - contrastingText(QColor), when the surface has alpha, asks
 *     ThemeManager for the current app mode to pick a fallback backdrop.
 *     The caller wants "the right foreground for this translucent
 *     surface as rendered right now", which is a theme-runtime question.
 *   - The active contrast ratio set.  setActiveContrast() changes it
 *     (process-global, GUI thread; ThemeManager sets it before each
 *     apply), and activeRatios() and every default `ratios` argument
 *     read it, so runtime consumers follow the applied level.  Code that
 *     may derive for another level (ThemeTokenHandler::deriveAll(),
 *     ThemePaletteBuilder::build(), theme previews) passes a set
 *     explicitly.
 *
 * Every other method is static and side-effect-free.
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
     *  tokens (section headers against the base, the welcome header
     *  against its title text) without forcing every theme author to
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

    /**
     * One set of derivation contrast ratios.  ratiosFor() builds the
     * Standard and the High set; activeRatios() is the set the
     * running theme was derived with.
     */
    struct ContrastRatios {
        ThemeContrast level;    ///< The contrast level this set belongs to
        /** Body text against its surface (WCAG AA, AAA in High). */
        qreal readableText;
        /** Text that may be quieter than body text: large or secondary
         *  text such as a version label or transient state text. */
        qreal largeText;
        /** Non-text elements (control borders, progress fills)
         *  against their neighbor. */
        qreal nonText;
        /** A divider or border line against the surface it sits on:
         *  separators on Base, card borders and lines drawn on a card. */
        qreal divider;
        /** A fill against a neighboring one it must read apart from: a
         *  hover tint against the selection it is derived from, the
         *  welcome header against the window. */
        qreal distinctSurface;
        /** A raised card against Base in dark mode.  Softer than
         *  distinctSurface: a card is a grouping, not a state.  Light
         *  mode needs no lift, because the card border sets the card
         *  apart on a light base. */
        qreal cardSurfaceDark;
        /** A contrast-adapted icon glyph against the surface it is
         *  drawn on. */
        qreal icon;
    };

    /** The ratio set for a contrast level. */
    static constexpr ContrastRatios ratiosFor(ThemeContrast level)
    {
        const bool high = level == ThemeContrast::High;
        ContrastRatios r {};
        r.level           = level;
        r.readableText    = high ? ReadableTextRatioHigh    : ReadableTextRatio;
        r.largeText       = high ? LargeTextRatioHigh       : LargeTextRatio;
        r.nonText         = high ? NonTextRatioHigh         : NonTextRatio;
        r.divider         = high ? DividerRatioHigh         : DividerRatio;
        r.distinctSurface = high ? DistinctSurfaceRatioHigh : DistinctSurfaceRatio;
        r.cardSurfaceDark = high ? CardSurfaceRatioDarkHigh : CardSurfaceRatioDark;
        r.icon            = high ? IconContrastRatioHigh    : IconContrastRatio;
        return r;
    }

    /** The ratio set of the applied contrast level (Standard until
     *  setActiveContrast() is called).  GUI thread only. */
    static const ContrastRatios &activeRatios();

    /** Make the ratio set of @p level the active one.  Called by
     *  ThemeManager before it derives the palette and tokens. */
    static void setActiveContrast(ThemeContrast level);

    /** A text color and the fill it is drawn on. */
    struct TextOnFill {
        QColor text;
        QColor fill;
    };

    /** `text` lifted to `minRatio` against `fill`; when it cannot get
     *  there, `fill` moves away from the lifted text until the pair
     *  reads at `minRatio`. */
    static TextOnFill readableOnFill(const QColor &text, const QColor &fill, qreal minRatio);

    /** `fill` unchanged when its contrastingText() reads on it at the
     *  set's readableText ratio, else moved away from that text until
     *  it does. */
    static QColor readableFill(const QColor &fill, const ContrastRatios &ratios = activeRatios());

    /** Hover fill and text for an item view: the fill is
     *  selectionHoverFill(), the text `text` made readable on it.  In
     *  High the fill moves toward readability of `text` as long as it
     *  stays distinct from `selection`. */
    static TextOnFill selectionHover(const QColor &base, const QColor &selection,
                                     const QColor &text,
                                     const ContrastRatios &ratios = activeRatios());

    /** Hover fill for an item view, derived from that view's own
     *  selection color so the view uses one highlight hue.  A 55 % tint
     *  of `selection` over `base`, pushed away from `selection` until
     *  the two are the set's distinctSurface ratio apart, so a hovered
     *  row never reads as a second selection.  Dark selections sit too
     *  close to the base for any in-between tint to be distinct from
     *  both, so in dark schemes the fill ends up lighter than the
     *  selection. */
    static QColor selectionHoverFill(const QColor &base, const QColor &selection,
                                     const ContrastRatios &ratios = activeRatios());

    /** `text` lifted to the set's readableText ratio against `surface`;
     *  returned unchanged when it already reads. */
    static QColor readableText(const QColor &text, const QColor &surface,
                               const ContrastRatios &ratios = activeRatios());

    /** True when `text` already reaches the set's readableText ratio
     *  against `surface`, i.e. readableText() would return it unchanged. */
    static bool isReadable(const QColor &text, const QColor &surface,
                           const ContrastRatios &ratios = activeRatios());

    // ---------------------------------------------------------------
    // Mix / shade
    // ---------------------------------------------------------------

    /** Linear blend of two colors at ratio `r`.  r=0 returns a, r=1
     *  returns b.  Alpha-aware. */
    static QColor         mix(const QColor &a, const QColor &b, qreal ratio = 0.5);
    static ThemeColorPair mix(const ThemeColorPair &a, const ThemeColorPair &b, qreal ratio = 0.5);

    /** Mix the given color with black at percent %.  Hover typically
     *  8-12 %, pressed 16-20 %, bar backdrop 50-65 %. */
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

    /** `surface` composited over the opaque `backdrop` with the "over"
     *  operator; an opaque `surface` is returned unchanged. */
    static QColor         compositeOver(const QColor &surface, const QColor &backdrop);

    /** Same as contrastingText(), but with the caller supplying the
     *  backdrop explicitly — useful when rendering onto a known
     *  surface (e.g. the welcome header bar) rather than the
     *  app palette. */
    static QColor         contrastingTextOver(const QColor &surface, const QColor &backdrop);

    /** Standard "disabled" fade: mix(color, background, 0.4). */
    static QColor         disabled(const QColor &c, const QColor &background);
    static ThemeColorPair disabled(const ThemeColorPair &p, const QColor &background);

    /** Subtle hover tint: mix(color, background, 0.1). */
    static QColor         hoverBg(const QColor &c, const QColor &background);
    static ThemeColorPair hoverBg(const ThemeColorPair &p, const QColor &background);

    /** Hover colour of an icon glyph whose icon names no explicit hover
     *  colour: `c.lighter(HoverEmphasisFactor)`, a slight brightening
     *  with the hue kept.  Shared by the theme icon engines so every
     *  glyph lights up alike. */
    static QColor         hoverEmphasis(const QColor &c);

private:
    // The ratio values behind ratiosFor().  Private so that every
    // consumer goes through a ContrastRatios set and follows the
    // active contrast level.  The ...High siblings are the high
    // contrast targets: WCAG AAA for text (7:1 body, 4.5:1 large
    // text) and stronger non-text, divider and surface distances.
    static constexpr qreal DistinctSurfaceRatio = 1.5;
    static constexpr qreal DistinctSurfaceRatioHigh = 3.0;
    static constexpr qreal ReadableTextRatio = 4.5;
    static constexpr qreal ReadableTextRatioHigh = 7.0;
    static constexpr qreal CardSurfaceRatioDark = 1.25;
    static constexpr qreal CardSurfaceRatioDarkHigh = 1.6;
    static constexpr qreal DividerRatio = 1.6;
    static constexpr qreal DividerRatioHigh = 3.0;
    static constexpr qreal NonTextRatio = 3.0;
    static constexpr qreal NonTextRatioHigh = 4.5;
    static constexpr qreal LargeTextRatio = 3.0;
    static constexpr qreal LargeTextRatioHigh = 4.5;
    static constexpr qreal IconContrastRatio = 1.6;
    static constexpr qreal IconContrastRatioHigh = 4.5;

    // Percentage passed to QColor::lighter() by hoverEmphasis().
    // lighter() multiplies the HSV value by factor / 100, so 115 makes a
    // glyph about 15% brighter and keeps its hue; a colour already at full
    // value loses saturation instead and moves toward white.  The step is
    // small on purpose: hover should read as the same glyph lighting up,
    // not as a different colour (a 30% mix toward the text colour was
    // rejected as too dark).  Legibility is not this factor's job: the
    // contrast-adapting icon engine runs the result through
    // ensureContrast() against the field afterwards.  An int, not a
    // qreal, because lighter() takes an integer percentage; the qreal
    // constants above are contrast ratios only.
    static constexpr int HoverEmphasisFactor = 115;
};

#endif /* COLOR_MATH_H */
