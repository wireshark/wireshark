/* theme_token_handler.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "ui/qt/utils/themes/theme_token_handler.h"
#include "ui/qt/utils/themes/color_math.h"

#include <QCoreApplication>
#include <QPalette>
#include <QRegularExpression>

using TokenMap = ThemeTokenHandler::TokenMap;
using ThemeToken = ThemeManager::ThemeToken;

namespace {

// Picks the effective color for a palette-override role, falling back
// to `palette` when the theme doesn't override that role.  Using the
// pre-built palette (rather than QApplication::palette()) ensures the
// correct values are used even before the palette has been pushed to
// QApplication — see ThemeTokenHandler::deriveAll() parameter docs.
QColor pickPaletteValue(const TokenMap &tokens,
                        ThemeToken role,
                        QPalette::ColorRole qtRole,
                        bool isDarkMode,
                        const QPalette &palette)
{
    if (tokens.contains(role)) {
        return tokens.value(role).forMode(isDarkMode);
    }
    return palette.color(qtRole);
}

// `text` lifted to `minRatio` against `fill`, for one side of a pair.
// A side the theme leaves invalid stays invalid, so assign() can still
// fill it later.
QColor liftSide(const QColor &text, const QColor &fill, qreal minRatio)
{
    return text.isValid() && fill.isValid() ? ColorMath::ensureContrast(text, fill, minRatio) : text;
}

// The update bar's dismiss button tints on `bar`: hover is a subtle
// tint of the bar's contrasting text, pressed the disabled() blend of
// that.  The standard derivation and the high-contrast rule (which
// recomputes them on the final bar) share them.
QColor dismissHoverBg(const QColor &bar)
{
    return ColorMath::hoverBg(ColorMath::contrastingText(bar), bar);
}

QColor dismissPressedBg(const QColor &bar)
{
    return ColorMath::disabled(dismissHoverBg(bar), bar);
}

// Text on a fill through ColorMath::readableOnFill() for the current side:
// the text is lifted first, and the fill gives way only when the text
// cannot reach the ratio on its own.  Sides the theme leaves invalid stay
// untouched.
void readableOnFillSide(TokenMap &tokens, ThemeToken textRole, ThemeToken fillRole,
                        bool isDarkMode, qreal minRatio)
{
    const QColor text = ThemeTokenHandler::sideOf(tokens, textRole, isDarkMode);
    const QColor fill = ThemeTokenHandler::sideOf(tokens, fillRole, isDarkMode);
    if (!text.isValid() || !fill.isValid())
        return;
    const ColorMath::TextOnFill pair = ColorMath::readableOnFill(text, fill, minRatio);
    tokens[textRole].setForMode(isDarkMode, pair.text);
    tokens[fillRole].setForMode(isDarkMode, pair.fill);
}

// The welcome header bar for its version label.  The label is the title
// faded 25 % toward the bar; the fade is what tells the version from the
// title, so instead of lifting the label back to the title the bar moves
// away from the title (toward contrastingText(title)) until the faded
// label reaches `ratio`.  Returns `bar` unchanged when it already does,
// else the smallest such move, found by bisection like ensureContrast().
QColor barForFadedLabel(const QColor &bar, const QColor &title, qreal ratio)
{
    const auto labelReads = [&title, ratio](const QColor &candidate) {
        return ColorMath::contrastRatio(ColorMath::mix(title, candidate, 0.25), candidate) >= ratio;
    };
    if (labelReads(bar))
        return bar;

    const QColor target = ColorMath::contrastingText(title);
    qreal lo = 0.0;
    qreal hi = 1.0;
    for (int i = 0; i < 24; ++i) {
        const qreal m = (lo + hi) / 2.0;
        if (labelReads(ColorMath::mix(bar, target, m)))
            hi = m;
        else
            lo = m;
    }
    return ColorMath::mix(bar, target, hi);
}

} // namespace

QColor ThemeTokenHandler::sideOf(const TokenMap &tokens, ThemeToken role, bool isDarkMode)
{
    if (role == ThemeManager::NoRole)
        return QColor();
    return tokens.value(role, ThemeColorPair()).forMode(isDarkMode);
}

void ThemeTokenHandler::deriveAll(TokenMap &tokens, bool isDarkMode, const QPalette &palette,
                                  const ColorMath::ContrastRatios &ratios, SourceMap *sources)
{
    // The high-contrast rules below run only at the High level, so the
    // Standard level derives exactly what the theme was designed with.
    const bool highContrast = ratios.level == ThemeContrast::High;

    // Only-if-missing: a side the theme already set is kept.  `overwrite`
    // forces the replacement; the state-text guard below uses it to rewrite
    // a pinned value that is not readable on its fill.  Each rule names
    // itself next to the math, so the Theme Designer shows the rule without
    // a copy of this function.
    auto assign = [&tokens, sources](ThemeToken role, const ThemeColorPair &value,
                                     const char *source, bool overwrite = false) {
        ThemeColorPair pair = tokens.value(role);
        if (overwrite || !pair.light.isValid())
            pair.light = value.light;
        if (overwrite || !pair.dark.isValid())
            pair.dark = value.dark;
        tokens[role] = pair;
        if (sources)
            sources->insert(role, source);
    };

    const ThemeColorPair successPair  = tokens.value(ThemeManager::AccentSuccess);
    const ThemeColorPair brandPrimary = tokens.value(ThemeManager::BrandPrimary);

    const QColor mid        = palette.color(QPalette::Mid);
    // Flat update bar; the dismiss button tints are computed on it.
    const ThemeColorPair updateBg   = ColorMath::darken(successPair, 60);
    const ThemeColorPair disabledBg = ColorMath::darken(successPair, 40);

    // Expert — alpha-blended accent variants.  The high-contrast rule
    // below walks the same table.
    const struct { ThemeToken fill; ThemeToken accent; const char *source; } expertFills[] = {
        { ThemeManager::ExpertNone,    ThemeManager::AccentInfo,
          QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.info at 40% opacity") },
        { ThemeManager::ExpertComment, ThemeManager::AccentSuccess,
          QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success at 40% opacity") },
        { ThemeManager::ExpertChat,    ThemeManager::AccentInfo,
          QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.info at 40% opacity") },
        { ThemeManager::ExpertNote,    ThemeManager::AccentInfo,
          QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.info at 40% opacity") },
        { ThemeManager::ExpertWarn,    ThemeManager::AccentWarning,
          QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.warning at 40% opacity") },
        { ThemeManager::ExpertError,   ThemeManager::AccentError,
          QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.error at 40% opacity") },
    };
    for (const auto &ef : expertFills)
        assign(ef.fill, ColorMath::withAlpha(tokens.value(ef.accent), 102), ef.source);
    assign(ThemeManager::ExpertForeground,
           ColorMath::contrastingText(tokens.value(ThemeManager::ExpertComment)), QT_TRANSLATE_NOOP("ThemeTokenHandler", "black or white on expert.comment"));

    // Packets / Conversation — need concrete Base / Text / WindowText
    // values.  Read them from the theme's palette overrides if set,
    // otherwise fall back to the current QApplication palette.
    const QColor baseColor   = pickPaletteValue(tokens, ThemeManager::PaletteBase,       QPalette::Base,       isDarkMode, palette);
    const QColor windowColor = pickPaletteValue(tokens, ThemeManager::PaletteWindow,     QPalette::Window,     isDarkMode, palette);
    const QColor textColor   = pickPaletteValue(tokens, ThemeManager::PaletteWindowText, QPalette::WindowText, isDarkMode, palette);

    const QColor paletteTextColor = pickPaletteValue(tokens, ThemeManager::PaletteText, QPalette::Text, isDarkMode, palette);

    // High contrast: the expert severity fills are translucent and drawn
    // over Base, where ExpertForeground must read on them at body-text
    // contrast.  Readability wins over the theme's pinned fill, so a fill
    // that misses is replaced by its composite on Base, moved until the
    // foreground reads.  The foreground is left as it is: it is shared by
    // every severity and by the expert icons.
    if (highContrast) {
        const QColor expertForeground = sideOf(tokens, ThemeManager::ExpertForeground, isDarkMode);
        for (const auto &ef : expertFills) {
            const QColor fill = sideOf(tokens, ef.fill, isDarkMode);
            if (!fill.isValid() || !expertForeground.isValid())
                continue;
            const QColor composite = ColorMath::compositeOver(fill, baseColor);
            if (ColorMath::contrastRatio(expertForeground, composite) < ratios.readableText) {
                tokens[ef.fill].setForMode(isDarkMode,
                        ColorMath::ensureContrast(composite, expertForeground, ratios.readableText));
            }
        }
    }

    assign(ThemeManager::PacketsSelection,
           ColorMath::mix(ThemeColorPair { baseColor,   baseColor   }, brandPrimary,                                0.30), QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 30% toward brand.primary"));
    assign(ThemeManager::PacketsInactive,
           ColorMath::mix(ThemeColorPair { windowColor, windowColor }, brandPrimary,                                0.40), QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.window 40% toward brand.primary"));
    assign(ThemeManager::PacketsMarked,   ColorMath::darken(brandPrimary, 65), QT_TRANSLATE_NOOP("ThemeTokenHandler", "brand.primary 65% darker"));
    // PacketsIgnored (bg) intentionally has no derivation — when the
    // theme omits it the consumer leaves the row's normal background
    // alone (matches the historical white-on-row visual).
    // Ignored and hidden rows fade the text toward Base, so they stay
    // readable on any background instead of drifting toward an accent.
    assign(ThemeManager::PacketsIgnoredText,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, ThemeColorPair { textColor, textColor }, 0.50), QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 50% toward palette.windowText"));
    assign(ThemeManager::PacketsHidden,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, ThemeColorPair { textColor, textColor }, 0.40), QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 40% toward palette.windowText"));
    // High contrast: ignored and hidden rows are still read, so their
    // faded text, pinned or derived, is lifted to body-text contrast
    // against Base.  Readability wins over the theme's pinned value.
    if (highContrast) {
        for (ThemeToken role : { ThemeManager::PacketsIgnoredText, ThemeManager::PacketsHidden }) {
            const QColor text = sideOf(tokens, role, isDarkMode);
            if (text.isValid())
                tokens[role].setForMode(isDarkMode,
                        ColorMath::ensureContrast(text, baseColor, ratios.readableText));
        }
    }

    // State text: the theme's pin, else black or white by WCAG luminance
    // against the state's fill.  Either way it is lifted to body-text
    // contrast against that fill, per mode, so a pin chosen for another
    // shade (or a fill derived from brand.primary) never turns unreadable.
    // The packet list and every other consumer read these tokens, so this
    // is the one place the state text is checked.
    const struct { ThemeToken text; ThemeToken fill; const char *source; } stateText[] = {
        { ThemeManager::PacketsSelectionText, ThemeManager::PacketsSelection,
          QT_TRANSLATE_NOOP("ThemeTokenHandler", "black or white on packets.selection, kept readable on it") },
        { ThemeManager::PacketsInactiveText,  ThemeManager::PacketsInactive,
          QT_TRANSLATE_NOOP("ThemeTokenHandler", "black or white on packets.inactive, kept readable on it") },
        { ThemeManager::PacketsMarkedText,    ThemeManager::PacketsMarked,
          QT_TRANSLATE_NOOP("ThemeTokenHandler", "black or white on packets.marked, kept readable on it") },
    };
    for (const auto &st : stateText) {
        const ThemeColorPair fill = tokens.value(st.fill);
        assign(st.text, ColorMath::contrastingText(fill), st.source);
        const ThemeColorPair text = tokens.value(st.text);
        assign(st.text,
               ThemeColorPair { liftSide(text.light, fill.light, ratios.readableText),
                                liftSide(text.dark,  fill.dark,  ratios.readableText) },
               st.source, true);
        // High contrast: readableText() falls back to black or white when
        // the pin cannot reach the target; when even that misses, the
        // fill gives way.  Readability wins over the theme's pinned fill.
        if (highContrast)
            readableOnFillSide(tokens, st.text, st.fill, isDarkMode, ratios.readableText);
    }

    // Conversation
    const ThemeColorPair accentError = tokens.value(ThemeManager::AccentError);
    assign(ThemeManager::ConversationClient,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, accentError, 102.0 / 255.0), QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 40% toward accent.error"));
    assign(ThemeManager::ConversationServer,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, brandPrimary, 102.0 / 255.0), QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 40% toward brand.primary"));
    // Stream-side text fallback: warm for client (saturated accent.error),
    // cool for server (saturated brand.primary).  Direction flips by mode
    // so the fg stays readable on both the light and dark bg tints.
    assign(ThemeManager::ConversationClientText,
           ThemeColorPair { ColorMath::darken (accentError.light, 30),
                            ColorMath::lighten(accentError.dark,  50) }, QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.error 30% darker (light) / 50% lighter (dark)"));
    assign(ThemeManager::ConversationServerText,
           ThemeColorPair { ColorMath::darken (brandPrimary.light, 30),
                            ColorMath::lighten(brandPrimary.dark,  50) }, QT_TRANSLATE_NOOP("ThemeTokenHandler", "brand.primary 30% darker (light) / 50% lighter (dark)"));
    // High contrast: the stream text reads on its tint at body-text
    // contrast, the tint giving way when the text cannot get there.
    // Readability wins over the theme's pinned values.
    if (highContrast) {
        readableOnFillSide(tokens, ThemeManager::ConversationClientText, ThemeManager::ConversationClient,
                           isDarkMode, ratios.readableText);
        readableOnFillSide(tokens, ThemeManager::ConversationServerText, ThemeManager::ConversationServer,
                           isDarkMode, ratios.readableText);
    }

    // Filter state — tinted accent-on-Base backgrounds.  Default alpha
    // is 85 (~33%) rather than the historical 102 (~40%); the lower
    // value keeps the default Material-leaning accents from
    // overpowering the field background.  Themes that prefer the
    // legacy saturated GTK look ship explicit hex values in
    // theme.filter and let assign()'s only-if-missing semantics keep
    // them intact.  The foreground on each tint is derived below as
    // TextOnFilter*, so the text stays readable whichever side of the
    // luminance threshold the tint lands on.
    const struct { ThemeToken tint; ThemeToken accent; const char *source; const char *highSource; } filterTints[] = {
        { ThemeManager::FilterValid,      ThemeManager::AccentSuccess,
          QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 33% toward accent.success"),
          QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 33% toward accent.success, moved until black or white text is readable on it") },
        { ThemeManager::FilterInvalid,    ThemeManager::AccentError,
          QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 33% toward accent.error"),
          QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 33% toward accent.error, moved until black or white text is readable on it") },
        { ThemeManager::FilterDeprecated, ThemeManager::AccentWarning,
          QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 33% toward accent.warning"),
          QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 33% toward accent.warning, moved until black or white text is readable on it") },
    };
    for (const auto &ft : filterTints)
        assign(ft.tint,
               ColorMath::mix(ThemeColorPair { baseColor, baseColor }, tokens.value(ft.accent), 85.0 / 255.0),
               ft.source);
    // High contrast: each tint, pinned or derived, moves away from its
    // black or white text until that text reads at body-text contrast;
    // the TextOnFilter* tokens below are then picked on the final tint.
    // Readability wins over the theme's pinned value.
    if (highContrast) {
        for (const auto &ft : filterTints) {
            const ThemeColorPair tint = tokens.value(ft.tint);
            assign(ft.tint,
                   ThemeColorPair { tint.light.isValid() ? ColorMath::readableFill(tint.light, ratios) : tint.light,
                                    tint.dark.isValid()  ? ColorMath::readableFill(tint.dark,  ratios) : tint.dark },
                   ft.highSource, true);
        }
    }

    // Filter Busy — bg and fg used while a capture filter compiles
    // off-thread.  Default bg is palette.base (no tint) and fg is the
    // text colour faded 50% into base, which matches the placeholder-
    // text look QLineEdit shows for empty fields.  Themes can ship a
    // more distinct look via theme.filter.busy / theme.filter.busyText.
    assign(ThemeManager::FilterBusy,
           ThemeColorPair { baseColor, baseColor }, QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base"));
    assign(ThemeManager::FilterBusyText,
           ColorMath::mix(ThemeColorPair { paletteTextColor, paletteTextColor },
                          ThemeColorPair { baseColor, baseColor },
                          0.5), QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.text 50% toward palette.base, lifted to the large text ratio on filter.busy"));
    // The busy text is transient state text: pinned or derived, it is
    // lifted to the large-text ratio against the busy fill, per mode, at
    // every contrast level.  The fade misses that ratio where Text and
    // Base are close; where it already reads, the lift leaves it alone.
    // Readability wins over the theme's pinned value.
    const ThemeColorPair busy     = tokens.value(ThemeManager::FilterBusy);
    const ThemeColorPair busyText = tokens.value(ThemeManager::FilterBusyText);
    tokens[ThemeManager::FilterBusyText] =
           ThemeColorPair { liftSide(busyText.light, busy.light, ratios.largeText),
                            liftSide(busyText.dark,  busy.dark,  ratios.largeText) };

    // Inline filter-affordance glyph colours (bookmark / clear / apply icon
    // fills).  These are full-strength glyph tints, not the alpha bg tints
    // above, so they default to the matching accent verbatim (no mix-with-base).
    // assign()'s only-if-missing semantics let a theme pin explicit values via
    // theme.filter.bookmark / .bookmarkcapture / .bookmarkmatch / .clear /
    // .apply while still guaranteeing every theme has the tokens defined.
    assign(ThemeManager::FilterBookmark,        tokens.value(ThemeManager::AccentInfo), QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.info"));
    assign(ThemeManager::FilterBookmarkCapture, tokens.value(ThemeManager::AccentSuccess), QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success"));
    assign(ThemeManager::FilterBookmarkMatch,   tokens.value(ThemeManager::AccentWarning), QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.warning"));
    assign(ThemeManager::FilterClear,           tokens.value(ThemeManager::AccentError), QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.error"));
    assign(ThemeManager::FilterApply,           tokens.value(ThemeManager::AccentInfo), QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.info"));

    // The recent-filters arrow reads as a subtle disclosure caret at rest, so it
    // defaults to palette.mid (a mode-aware gray) rather than a saturated accent.
    // It lightens slightly on hover/press (the emphasis binding in
    // filter-history.svg, contrast-guarded); this token only sets the resting
    // tint.  The default theme pins fixed grays via theme.filter.history.
    {
        const QColor midGray = pickPaletteValue(tokens, ThemeManager::PaletteMid, QPalette::Mid, isDarkMode, palette);
        assign(ThemeManager::FilterHistory, ThemeColorPair { midGray, midGray }, QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.mid"));
    }

    // Syntax highlighting — readable foreground text on PaletteBase.
    // Keys use the palette's Mid role, lifted to body-text
    // contrast against Base: on macOS dark mode Mid sits below Base.
    // String / number colours shift the accent away from the
    // background: darker in light mode (toward black), lighter in
    // dark mode (toward white).
    const QColor midColor = pickPaletteValue(tokens, ThemeManager::PaletteMid, QPalette::Mid, isDarkMode, palette);
    const ThemeColorPair accentSuccess = tokens.value(ThemeManager::AccentSuccess);
    const ThemeColorPair accentInfo    = tokens.value(ThemeManager::AccentInfo);
    const QColor keyColor = ColorMath::readableText(midColor, baseColor, ratios);
    assign(ThemeManager::SyntaxKey,
           ThemeColorPair { keyColor, keyColor }, QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.mid, kept readable on palette.base"));
    assign(ThemeManager::SyntaxString,
           ThemeColorPair { ColorMath::darken(accentSuccess.light, 30),
                            ColorMath::lighten(accentSuccess.dark,  30) }, QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success 30% darker (light) / lighter (dark)"));
    assign(ThemeManager::SyntaxNumber,
           ThemeColorPair { ColorMath::darken(accentInfo.light, 30),
                            ColorMath::lighten(accentInfo.dark,  30) }, QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.info 30% darker (light) / lighter (dark)"));

    // Welcome header bar: a flat, darkened shade of the selection color.
    // Highlight / HighlightedText come from the palette built for this
    // theme (palette.highlight, else packets.selection, else
    // brand.primary, as resolved by ThemePaletteBuilder), so the choice
    // is made in one place.  The bar is first kept apart from the
    // window so it never melts into it (a dark selection darkened by
    // 40 % lands almost on a dark window), then shifted only as far as
    // the title needs to read.  The version label is the title color
    // faded 25 % toward the bar, lifted back to the large-text ratio
    // (body-text ratio in high contrast) if that overshoots.
    const QColor highlight     = palette.color(QPalette::Active, QPalette::Highlight);
    const QColor highlightText = palette.color(QPalette::Active, QPalette::HighlightedText);
    QColor headerBg = ColorMath::ensureContrast(ColorMath::darken(highlight, 40),
                                                windowColor, ratios.distinctSurface);
    // The title keeps HighlightedText when that reads on the bar, else
    // it switches to black or white outright.  readableText() would stop
    // at a grey just at the threshold (inverted), too weak for a title.
    const QColor headerText = ColorMath::isReadable(highlightText, headerBg, ratios)
            ? highlightText : ColorMath::contrastingText(headerBg);
    headerBg = ColorMath::ensureContrast(headerBg, headerText,
            ratios.readableText);
    // High contrast: the version label must read at body-text contrast
    // too, so the bar moves away from the title until the faded label
    // gets there.  In dark mode the title and its label win over the
    // bar's distance from the window: a bar far enough from a near-black
    // window cannot also hold a white title at that contrast.  No border
    // is drawn to make up for it.
    if (highContrast)
        headerBg = barForFadedLabel(headerBg, headerText, ratios.readableText);
    const QColor headerMuted = ColorMath::ensureContrast(
            ColorMath::mix(headerText, headerBg, 0.25), headerBg,
            highContrast ? ratios.readableText : ratios.largeText);
    // The palette describes only the current mode; deriveAll() runs again
    // on every mode switch, so both halves carry the current value.
    assign(ThemeManager::HeaderBackground, ThemeColorPair { headerBg,    headerBg },
           QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.highlight 40% darker, kept apart from palette.window and readable under HeaderText"));
    assign(ThemeManager::HeaderText,       ThemeColorPair { headerText,  headerText },
           QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.highlightedText if readable on HeaderBackground, else black or white"));
    assign(ThemeManager::HeaderTextMuted,  ThemeColorPair { headerMuted, headerMuted },
           QT_TRANSLATE_NOOP("ThemeTokenHandler", "HeaderText 25% toward HeaderBackground, kept at the large text ratio (readable text ratio in high contrast)"));

    // Section headers — lifted to the readableText ratio against palette.base so
    // welcome-page labels ("Open", "Capture", "Learn") stay readable on
    // every shipped theme regardless of whether the theme overrides
    // palette.mid.  Replaces the legacy `mid, mid` assignment that left
    // the labels invisible on dark Wireshark.
    const QColor sectionHeader      = ColorMath::readableText(mid,               baseColor, ratios);
    const QColor sectionHeaderHover = ColorMath::readableText(brandPrimary.dark, baseColor, ratios);
    // Light-mode hover uses the light brand value; the off-mode slot is
    // unused at runtime but is filled symmetrically.
    const QColor sectionHeaderHoverLight = ColorMath::readableText(brandPrimary.light, baseColor, ratios);
    assign(ThemeManager::SectionHeader,
           ThemeColorPair { sectionHeader, sectionHeader }, QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.mid, kept readable on palette.base"));
    assign(ThemeManager::SectionHeaderHover,
           ThemeColorPair { sectionHeaderHoverLight, sectionHeaderHover }, QT_TRANSLATE_NOOP("ThemeTokenHandler", "brand.primary, kept readable on palette.base"));

    // Structural form chrome — FieldBorder frames interactive controls
    // (the nonText ratio against base, the WCAG non-text minimum).
    // Separator is a softer divider: a 53% mix of base toward mid,
    // lifted to the divider ratio against base.  The lift matters where the
    // platform's Mid sits at or below Base (macOS dark mode), which left
    // the plain mix indistinguishable from the page.  Themes can pin
    // Separator via the JSONC "separator" top-level key (Stratoshark
    // does, since its palette.mid intentionally doubles as muted text);
    // a pin is kept as authored.
    const QColor fieldBorder = ColorMath::ensureContrast(mid, baseColor, ratios.nonText);
    const QColor separator   = ColorMath::ensureContrast(
            ColorMath::mix(baseColor, mid, 135.0 / 255.0),
            baseColor, ratios.divider);
    assign(ThemeManager::FieldBorder,
           ThemeColorPair { fieldBorder, fieldBorder }, QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.mid, kept at the non-text ratio to palette.base"));
    assign(ThemeManager::Separator,
           ThemeColorPair { separator, separator }, QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 53% toward palette.mid, kept at the divider ratio to palette.base"));

    // Secondary text: Text faded 40 % toward Base, then lifted to
    // the readableText ratio (the WCAG text minimum) against Base.
    const QColor mutedText = ColorMath::ensureContrast(
            ColorMath::mix(paletteTextColor, baseColor, 0.40), baseColor,
            ratios.readableText);
    assign(ThemeManager::MutedText, ThemeColorPair { mutedText, mutedText }, QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.text 40% toward palette.base, kept readable on palette.base"));

    // Diff line tints and notice banners.  Only the current mode's base is
    // known here (as for the filter tints), so each side mixes that base
    // with its own accent.
    auto tint = [&baseColor](const ThemeColorPair &accent, qreal light, qreal dark) {
        return ThemeColorPair { ColorMath::mix(baseColor, accent.light, light),
                                ColorMath::mix(baseColor, accent.dark, dark) };
    };
    assign(ThemeManager::DiffAdded,         tint(accentSuccess, 0.16, 0.22), QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 16% (light) / 22% (dark) toward accent.success"));
    assign(ThemeManager::DiffChanged,       tint(accentInfo,    0.16, 0.30), QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 16% (light) / 30% (dark) toward accent.info"));
    assign(ThemeManager::DiffRemoved,       tint(accentError,   0.10, 0.22), QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 10% (light) / 22% (dark) toward accent.error"));
    assign(ThemeManager::NoticeInfo,        tint(accentInfo,    0.10, 0.22), QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 10% (light) / 22% (dark) toward accent.info"));
    assign(ThemeManager::NoticeInfoBorder,  tint(accentInfo,    0.45, 0.45), QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 45% toward accent.info"));
    assign(ThemeManager::NoticeError,       tint(accentError,   0.08, 0.22), QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 8% (light) / 22% (dark) toward accent.error"));
    assign(ThemeManager::NoticeErrorBorder, tint(accentError,   0.50, 0.50), QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.base 50% toward accent.error"));

    // Raised surfaces ("cards") on Base: the welcome page Learn card and
    // the overlay cards.  The platform AlternateBase is no usable source
    // (macOS reports an opaque light gray for it in dark mode), so the
    // card starts from the theme's own alternateBase when it pins one,
    // else from Base.  In dark mode it is moved toward white until it
    // reads as its own surface.  In light mode it is used as-is: its
    // border sets it apart on a light base, and a lift toward black
    // would turn a white base into a gray card.
    const ThemeColorPair altBasePin = tokens.value(ThemeManager::PaletteAlternateBase);
    const QColor altBaseSide = altBasePin.forMode(isDarkMode);
    const QColor cardSource = altBaseSide.isValid() ? altBaseSide : baseColor;
    const QColor cardBg = isDarkMode
            ? ColorMath::ensureContrast(cardSource, baseColor, ratios.cardSurfaceDark)
            : cardSource;

    // The card border and the lines drawn on the card start from
    // Separator (pinned or derived) and are kept the divider ratio apart from
    // the card: a pinned Separator can sit almost on the lifted card.
    const ThemeColorPair separatorPair = tokens.value(ThemeManager::Separator);
    const QColor separatorSide = separatorPair.forMode(isDarkMode);
    const QColor cardBorder = ColorMath::ensureContrast(separatorSide, cardBg, ratios.divider);

    // Text and states on the card.  Section header and link colors are
    // derived against Base and lose contrast on a lifted or pinned card, so
    // they are lifted again against it.
    // In dark mode the card link is lifted against the card only, far
    // enough that it reads on the item-view hover fill computed with the
    // card as base: WCAG ratios multiply along one luminance axis, so a
    // link the readableText ratio times the fill's own contrast to the
    // card away from the card reads at the readableText ratio on that fill.  A
    // rich-text anchor has one color for both states, so where the
    // link cannot get that far, the fill gives way and is moved until
    // the link reads on it.
    // In light mode the link keeps the application Link color, lifted
    // only when it does not read on the card, because a light card
    // leaves too little room to lift it past a distinct fill.  The
    // hover counts as transient state text there: the fill is moved
    // toward the card until the link reads on it at the large-text ratio,
    // so the fill stays the readable-text over large-text ratio apart
    // from the card, which is the distinct-surface ratio in the standard
    // set.  In high contrast the link target wins and the fill keeps
    // only about 1.55:1 from the card.
    // The focus ring is the selection color lifted to text contrast
    // against the card.
    const ThemeColorPair sectionHeaderPair      = tokens.value(ThemeManager::SectionHeader);
    const ThemeColorPair sectionHeaderHoverPair = tokens.value(ThemeManager::SectionHeaderHover);
    const QColor cardSectionHeader = ColorMath::readableText(
            sectionHeaderPair.forMode(isDarkMode), cardBg, ratios);
    const QColor cardSectionHeaderHover = ColorMath::readableText(
            sectionHeaderHoverPair.forMode(isDarkMode), cardBg, ratios);
    const QColor cardLinkHoverBase = ColorMath::selectionHoverFill(cardBg, highlight, ratios);
    const QColor paletteLink = palette.color(QPalette::Active, QPalette::Link);
    QColor cardLink;
    QColor cardLinkHover;
    if (isDarkMode) {
        cardLink = ColorMath::ensureContrast(
                paletteLink, cardBg,
                ratios.readableText * ColorMath::contrastRatio(cardLinkHoverBase, cardBg));
        cardLinkHover = ColorMath::ensureContrast(
                cardLinkHoverBase, cardLink, ratios.readableText);
    } else {
        cardLink = ColorMath::readableText(paletteLink, cardBg, ratios);
        cardLinkHover = ColorMath::ensureContrast(
                cardLinkHoverBase, cardLink, ratios.largeText);
    }
    const QColor cardFocusRing = ColorMath::readableText(highlight, cardBg, ratios);

    // Overlay cards sit over a black scrim, such as the startup splash.
    // The scrim darkens the window behind, so the card stands out best
    // as the lighter of Base and the card surface: the card in dark
    // mode, Base in light mode, where a gray card would sink into the
    // darkened window.
    const QColor overlayCardBg =
            ColorMath::relativeLuminance(cardBg) > ColorMath::relativeLuminance(baseColor)
            ? cardBg : baseColor;
    const QColor overlayCardBorder = ColorMath::ensureContrast(
            separatorSide, overlayCardBg, ratios.divider);

    // The palette describes only the current mode; both halves carry
    // the current value, as for the welcome header.
    assign(ThemeManager::CardBackground,         ThemeColorPair { cardBg,                 cardBg },
           QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.alternateBase when set, else palette.base; in dark mode kept at the dark card surface ratio to palette.base"));
    assign(ThemeManager::CardBorder,             ThemeColorPair { cardBorder,             cardBorder },
           QT_TRANSLATE_NOOP("ThemeTokenHandler", "Separator, kept at the divider ratio to CardBackground"));
    assign(ThemeManager::CardSectionHeader,      ThemeColorPair { cardSectionHeader,      cardSectionHeader },
           QT_TRANSLATE_NOOP("ThemeTokenHandler", "SectionHeader, kept readable on CardBackground"));
    assign(ThemeManager::CardSectionHeaderHover, ThemeColorPair { cardSectionHeaderHover, cardSectionHeaderHover },
           QT_TRANSLATE_NOOP("ThemeTokenHandler", "SectionHeaderHover, kept readable on CardBackground"));
    assign(ThemeManager::CardLink,               ThemeColorPair { cardLink,               cardLink },
           QT_TRANSLATE_NOOP("ThemeTokenHandler", "the palette link color, kept readable on CardBackground and on CardLinkHover"));
    assign(ThemeManager::CardLinkHover,          ThemeColorPair { cardLinkHover,          cardLinkHover },
           QT_TRANSLATE_NOOP("ThemeTokenHandler", "hover fill of palette.highlight on CardBackground, moved until CardLink reads on it"));
    assign(ThemeManager::CardFocusRing,          ThemeColorPair { cardFocusRing,          cardFocusRing },
           QT_TRANSLATE_NOOP("ThemeTokenHandler", "palette.highlight, kept readable on CardBackground"));
    assign(ThemeManager::OverlayCardBackground,  ThemeColorPair { overlayCardBg,          overlayCardBg },
           QT_TRANSLATE_NOOP("ThemeTokenHandler", "the lighter of palette.base and CardBackground"));
    assign(ThemeManager::OverlayCardBorder,      ThemeColorPair { overlayCardBorder,      overlayCardBorder },
           QT_TRANSLATE_NOOP("ThemeTokenHandler", "Separator, kept at the divider ratio to OverlayCardBackground"));

    // Foregrounds for solid accent surfaces — auto-pick black or white
    // per contrastingText().  These give QSS rules a single token to
    // paint text on accent backgrounds without each theme having to
    // hand-tune the contrast (or rely on one fixed text color
    // that may not fit a bright accent — see #headerBuildLabel and
    // #updateDownload in welcome-header.qss).
    assign(ThemeManager::TextOnSuccess,
           ColorMath::contrastingText(successPair), QT_TRANSLATE_NOOP("ThemeTokenHandler", "black or white on accent.success"));
    assign(ThemeManager::TextOnWarning,
           ColorMath::contrastingText(tokens.value(ThemeManager::AccentWarning)), QT_TRANSLATE_NOOP("ThemeTokenHandler", "black or white on accent.warning"));
    assign(ThemeManager::TextOnError,
           ColorMath::contrastingText(tokens.value(ThemeManager::AccentError)), QT_TRANSLATE_NOOP("ThemeTokenHandler", "black or white on accent.error"));
    assign(ThemeManager::TextOnInfo,
           ColorMath::contrastingText(tokens.value(ThemeManager::AccentInfo)), QT_TRANSLATE_NOOP("ThemeTokenHandler", "black or white on accent.info"));

    // Foreground for the filter validity tints.
    assign(ThemeManager::TextOnFilterValid,
           ColorMath::contrastingText(tokens.value(ThemeManager::FilterValid)), QT_TRANSLATE_NOOP("ThemeTokenHandler", "black or white on filter.valid"));
    assign(ThemeManager::TextOnFilterInvalid,
           ColorMath::contrastingText(tokens.value(ThemeManager::FilterInvalid)), QT_TRANSLATE_NOOP("ThemeTokenHandler", "black or white on filter.invalid"));
    assign(ThemeManager::TextOnFilterDeprecated,
           ColorMath::contrastingText(tokens.value(ThemeManager::FilterDeprecated)), QT_TRANSLATE_NOOP("ThemeTokenHandler", "black or white on filter.deprecated"));

    // Update bar — all from accent.success
    assign(ThemeManager::UpdateBackground,       updateBg, QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success 60% darker"));
    assign(ThemeManager::UpdateBorder,           ColorMath::withAlpha(successPair, 51), QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success at 20% opacity"));
    assign(ThemeManager::UpdateText,             ColorMath::lighten(successPair, 50), QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success 50% lighter"));
    assign(ThemeManager::UpdateTextHighlight,    ColorMath::lighten(successPair, 70), QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success 70% lighter"));
    assign(ThemeManager::UpdateLink,             ColorMath::lighten(successPair, 30), QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success 30% lighter"));
    assign(ThemeManager::UpdateLinkHover,        ColorMath::lighten(successPair, 50), QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success 50% lighter"));
    assign(ThemeManager::UpdateLinkPressed,      ColorMath::darken(successPair, 20), QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success 20% darker"));
    assign(ThemeManager::UpdateButtonBg,         successPair, QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success"));
    assign(ThemeManager::UpdateButtonHover,      ColorMath::darken(successPair, 8), QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success 8% darker"));
    assign(ThemeManager::UpdateButtonPressed,    ColorMath::darken(successPair, 16), QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success 16% darker"));
    assign(ThemeManager::UpdateButtonDisabledBg, disabledBg, QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success 40% darker"));
    // Disabled button text: contrasting text faded toward the disabled button bg
    assign(ThemeManager::UpdateButtonDisabledText,
           ThemeColorPair { ColorMath::disabled(ColorMath::contrastingText(disabledBg.light), disabledBg.light),
                            ColorMath::disabled(ColorMath::contrastingText(disabledBg.dark),  disabledBg.dark) }, QT_TRANSLATE_NOOP("ThemeTokenHandler", "black or white faded toward UpdateButtonDisabledBg"));
    // Dismiss hover: subtle tint of contrasting color onto the bar
    assign(ThemeManager::UpdateDismissHoverBg,
           ThemeColorPair { dismissHoverBg(updateBg.light), dismissHoverBg(updateBg.dark) }, QT_TRANSLATE_NOOP("ThemeTokenHandler", "hover tint on the update bar"));
    // Dismiss pressed: same pattern but use disabled() for a stronger blend
    assign(ThemeManager::UpdateDismissPressedBg,
           ThemeColorPair { dismissPressedBg(updateBg.light), dismissPressedBg(updateBg.dark) }, QT_TRANSLATE_NOOP("ThemeTokenHandler", "pressed tint on the update bar"));
    // The status dot; kept apart from the update bar in high contrast.
    assign(ThemeManager::UpdateDot,              successPair, QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success, kept at the non-text ratio to UpdateBackground in high contrast"));

    // High contrast: the bar's text and links read at body-text contrast
    // on it, the bar giving way when even its lightest text still misses;
    // the download button moves until TextOnSuccess reads on it; the dot
    // keeps the non-text ratio from the bar.  The dismiss tints follow
    // the final bar.  Readability wins over the theme's pinned values.
    // These tokens do not depend on the palette, so both sides are set.
    if (highContrast) {
        const qreal readable = ratios.readableText;
        for (const bool dark : { false, true }) {
            const QColor text = ColorMath::ensureContrast(
                    sideOf(tokens, ThemeManager::UpdateText, dark),
                    sideOf(tokens, ThemeManager::UpdateBackground, dark), readable);
            const QColor bar = ColorMath::ensureContrast(
                    sideOf(tokens, ThemeManager::UpdateBackground, dark), text, readable);
            tokens[ThemeManager::UpdateText].setForMode(dark, text);
            tokens[ThemeManager::UpdateBackground].setForMode(dark, bar);
            for (ThemeToken role : { ThemeManager::UpdateTextHighlight, ThemeManager::UpdateLink,
                                     ThemeManager::UpdateLinkHover, ThemeManager::UpdateLinkPressed }) {
                tokens[role].setForMode(dark,
                        ColorMath::ensureContrast(sideOf(tokens, role, dark), bar, readable));
            }
            const QColor buttonText = sideOf(tokens, ThemeManager::TextOnSuccess, dark);
            for (ThemeToken role : { ThemeManager::UpdateButtonBg, ThemeManager::UpdateButtonHover,
                                     ThemeManager::UpdateButtonPressed }) {
                tokens[role].setForMode(dark,
                        ColorMath::ensureContrast(sideOf(tokens, role, dark), buttonText, readable));
            }
            tokens[ThemeManager::UpdateDot].setForMode(dark,
                    ColorMath::ensureContrast(successPair.forMode(dark), bar, ratios.nonText));
            tokens[ThemeManager::UpdateDismissHoverBg].setForMode(dark, dismissHoverBg(bar));
            tokens[ThemeManager::UpdateDismissPressedBg].setForMode(dark, dismissPressedBg(bar));
        }
    }

    // Accent aliases (derived)
    assign(ThemeManager::HighlightColorOrange, tokens.value(ThemeManager::AccentWarning), QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.warning"));
    assign(ThemeManager::HighlightColorGreen,  successPair, QT_TRANSLATE_NOOP("ThemeTokenHandler", "accent.success"));
}

QList<ThemeManager::ThemeToken> ThemeTokenHandler::sourceTokens(const char *source)
{
    // Names follow ThemeManager's name rule: a dotted theme key
    // (palette.highlight) or an enumerator (HeaderText).  The test suite
    // reads this pattern from here and checks that every rule text resolves
    // with it, so this is the only copy.
    static const QRegularExpression names(
        QStringLiteral("\\b([a-z]+\\.[A-Za-z]+|[A-Z][A-Za-z0-9]+)\\b"));
    QList<ThemeManager::ThemeToken> out;
    if (!source)
        return out;
    QRegularExpressionMatchIterator it = names.globalMatch(QString::fromLatin1(source));
    while (it.hasNext()) {
        const ThemeManager::ThemeToken token = ThemeManager::instance()->tokenForName(it.next().captured(1));
        if (token != ThemeManager::NoRole && !out.contains(token))
            out << token;
    }
    return out;
}
