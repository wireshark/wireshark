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

#include <QPalette>

using TokenMap = ThemeTokenHandler::TokenMap;
using ThemeToken = ThemeManager::ThemeToken;

namespace {

// Only-if-missing assignment: leaves any theme-provided explicit value
// intact (matches the old ThemeManager::derive(..., overwrite=false)
// behavior).  `overwrite=true` forces the replacement; the state-text
// guard in deriveAll() uses it to rewrite a pinned value that is not
// readable on its fill.
void assign(TokenMap &tokens,
            ThemeToken role,
            const ThemeColorPair &newPair,
            bool overwrite = false)
{
    ThemeColorPair pair = tokens.value(role, ThemeColorPair());
    if (overwrite || !pair.light.isValid())
        pair.light = newPair.light;
    if (overwrite || !pair.dark.isValid())
        pair.dark = newPair.dark;
    tokens[role] = pair;
}

void assign(TokenMap &tokens,
            ThemeToken role,
            const QColor &light,
            const QColor &dark,
            bool overwrite = false)
{
    assign(tokens, role, ThemeColorPair { light, dark }, overwrite);
}

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
                                  const ColorMath::ContrastRatios &ratios)
{
    // The high-contrast rules below run only at the High level, so the
    // Standard level derives exactly what the theme was designed with.
    const bool highContrast = ratios.level == ThemeContrast::High;

    const ThemeColorPair successPair  = tokens.value(ThemeManager::AccentSuccess);
    const ThemeColorPair brandPrimary = tokens.value(ThemeManager::BrandPrimary);

    const QColor mid        = palette.color(QPalette::Mid);
    // Flat update bar; the dismiss button tints are computed on it.
    const ThemeColorPair updateBg   = ColorMath::darken(successPair, 60);
    const ThemeColorPair disabledBg = ColorMath::darken(successPair, 40);

    // Expert — alpha-blended accent variants.  The high-contrast rule
    // below walks the same table.
    const struct { ThemeToken fill; ThemeToken accent; } expertFills[] = {
        { ThemeManager::ExpertNone,    ThemeManager::AccentInfo    },
        { ThemeManager::ExpertComment, ThemeManager::AccentSuccess },
        { ThemeManager::ExpertChat,    ThemeManager::AccentInfo    },
        { ThemeManager::ExpertNote,    ThemeManager::AccentInfo    },
        { ThemeManager::ExpertWarn,    ThemeManager::AccentWarning },
        { ThemeManager::ExpertError,   ThemeManager::AccentError   },
    };
    for (const auto &ef : expertFills)
        assign(tokens, ef.fill, ColorMath::withAlpha(tokens.value(ef.accent), 102));
    assign(tokens, ThemeManager::ExpertForeground,
           ColorMath::contrastingText(tokens.value(ThemeManager::ExpertComment)));

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

    assign(tokens, ThemeManager::PacketsSelection,
           ColorMath::mix(ThemeColorPair { baseColor,   baseColor   }, brandPrimary,                                0.30));
    assign(tokens, ThemeManager::PacketsInactive,
           ColorMath::mix(ThemeColorPair { windowColor, windowColor }, brandPrimary,                                0.40));
    assign(tokens, ThemeManager::PacketsMarked,   ColorMath::darken(brandPrimary, 65));
    // PacketsIgnored (bg) intentionally has no derivation — when the
    // theme omits it the consumer leaves the row's normal background
    // alone (matches the historical white-on-row visual).
    // Ignored and hidden rows fade the text toward Base, so they stay
    // readable on any background instead of drifting toward an accent.
    assign(tokens, ThemeManager::PacketsIgnoredText,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, ThemeColorPair { textColor, textColor }, 0.50));
    assign(tokens, ThemeManager::PacketsHidden,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, ThemeColorPair { textColor, textColor }, 0.40));
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
    const struct { ThemeToken text; ThemeToken fill; } stateText[] = {
        { ThemeManager::PacketsSelectionText, ThemeManager::PacketsSelection },
        { ThemeManager::PacketsInactiveText,  ThemeManager::PacketsInactive  },
        { ThemeManager::PacketsMarkedText,    ThemeManager::PacketsMarked    },
    };
    for (const auto &st : stateText) {
        const ThemeColorPair fill = tokens.value(st.fill);
        assign(tokens, st.text, ColorMath::contrastingText(fill));
        const ThemeColorPair text = tokens.value(st.text);
        assign(tokens, st.text,
               ThemeColorPair { liftSide(text.light, fill.light, ratios.readableText),
                                liftSide(text.dark,  fill.dark,  ratios.readableText) },
               true);
        // High contrast: readableText() falls back to black or white when
        // the pin cannot reach the target; when even that misses, the
        // fill gives way.  Readability wins over the theme's pinned fill.
        if (highContrast)
            readableOnFillSide(tokens, st.text, st.fill, isDarkMode, ratios.readableText);
    }

    // Conversation
    const ThemeColorPair accentError = tokens.value(ThemeManager::AccentError);
    assign(tokens, ThemeManager::ConversationClient,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, accentError, 102.0 / 255.0));
    assign(tokens, ThemeManager::ConversationServer,
           ColorMath::mix(ThemeColorPair { baseColor, baseColor }, brandPrimary, 102.0 / 255.0));
    // Stream-side text fallback: warm for client (saturated accent.error),
    // cool for server (saturated brand.primary).  Direction flips by mode
    // so the fg stays readable on both the light and dark bg tints.
    assign(tokens, ThemeManager::ConversationClientText,
           ThemeColorPair { ColorMath::darken (accentError.light, 30),
                            ColorMath::lighten(accentError.dark,  50) });
    assign(tokens, ThemeManager::ConversationServerText,
           ThemeColorPair { ColorMath::darken (brandPrimary.light, 30),
                            ColorMath::lighten(brandPrimary.dark,  50) });
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
    const struct { ThemeToken tint; ThemeToken accent; ThemeToken text; } filterTints[] = {
        { ThemeManager::FilterValid,      ThemeManager::AccentSuccess, ThemeManager::TextOnFilterValid      },
        { ThemeManager::FilterInvalid,    ThemeManager::AccentError,   ThemeManager::TextOnFilterInvalid    },
        { ThemeManager::FilterDeprecated, ThemeManager::AccentWarning, ThemeManager::TextOnFilterDeprecated },
    };
    for (const auto &ft : filterTints)
        assign(tokens, ft.tint,
               ColorMath::mix(ThemeColorPair { baseColor, baseColor }, tokens.value(ft.accent), 85.0 / 255.0));
    // High contrast: each tint, pinned or derived, moves away from its
    // black or white text until that text reads at body-text contrast;
    // the TextOnFilter* tokens below are then picked on the final tint.
    // Readability wins over the theme's pinned value.
    if (highContrast) {
        for (const auto &ft : filterTints) {
            const ThemeColorPair tint = tokens.value(ft.tint);
            assign(tokens, ft.tint,
                   ThemeColorPair { tint.light.isValid() ? ColorMath::readableFill(tint.light, ratios) : tint.light,
                                    tint.dark.isValid()  ? ColorMath::readableFill(tint.dark,  ratios) : tint.dark },
                   true);
        }
    }

    // Filter Busy — bg and fg used while a capture filter compiles
    // off-thread.  Default bg is palette.base (no tint) and fg is the
    // text colour faded 50% into base, which matches the placeholder-
    // text look QLineEdit shows for empty fields.  Themes can ship a
    // more distinct look via theme.filter.busy / theme.filter.busyText.
    assign(tokens, ThemeManager::FilterBusy,
           ThemeColorPair { baseColor, baseColor });
    assign(tokens, ThemeManager::FilterBusyText,
           ColorMath::mix(ThemeColorPair { paletteTextColor, paletteTextColor },
                          ThemeColorPair { baseColor, baseColor },
                          0.5));
    // High contrast: the busy text is transient state text, lifted to the
    // large-text ratio against the busy fill.  Readability wins over the
    // theme's pinned value.
    if (highContrast) {
        const ThemeColorPair busy     = tokens.value(ThemeManager::FilterBusy);
        const ThemeColorPair busyText = tokens.value(ThemeManager::FilterBusyText);
        assign(tokens, ThemeManager::FilterBusyText,
               ThemeColorPair { liftSide(busyText.light, busy.light, ratios.largeText),
                                liftSide(busyText.dark,  busy.dark,  ratios.largeText) },
               true);
    }

    // Inline filter-affordance glyph colours (bookmark / clear / apply icon
    // fills).  These are full-strength glyph tints, not the alpha bg tints
    // above, so they default to the matching accent verbatim (no mix-with-base).
    // assign()'s only-if-missing semantics let a theme pin explicit values via
    // theme.filter.bookmark / .bookmarkcapture / .bookmarkmatch / .clear /
    // .apply while still guaranteeing every theme has the tokens defined.
    assign(tokens, ThemeManager::FilterBookmark,        tokens.value(ThemeManager::AccentInfo));
    assign(tokens, ThemeManager::FilterBookmarkCapture, tokens.value(ThemeManager::AccentSuccess));
    assign(tokens, ThemeManager::FilterBookmarkMatch,   tokens.value(ThemeManager::AccentWarning));
    assign(tokens, ThemeManager::FilterClear,           tokens.value(ThemeManager::AccentError));
    assign(tokens, ThemeManager::FilterApply,           tokens.value(ThemeManager::AccentInfo));

    // The recent-filters arrow reads as a subtle disclosure caret at rest, so it
    // defaults to palette.mid (a mode-aware gray) rather than a saturated accent.
    // It brightens to a strong colour on hover/press, supplied per-mode by the
    // button's ThemedIcon; this token only sets the resting tint.  The default
    // theme pins fixed grays via theme.filter.history.
    {
        const QColor midGray = pickPaletteValue(tokens, ThemeManager::PaletteMid, QPalette::Mid, isDarkMode, palette);
        assign(tokens, ThemeManager::FilterHistory, ThemeColorPair { midGray, midGray });
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
    assign(tokens, ThemeManager::SyntaxKey,
           ThemeColorPair { keyColor, keyColor });
    assign(tokens, ThemeManager::SyntaxString,
           ThemeColorPair { ColorMath::darken(accentSuccess.light, 30),
                            ColorMath::lighten(accentSuccess.dark,  30) });
    assign(tokens, ThemeManager::SyntaxNumber,
           ThemeColorPair { ColorMath::darken(accentInfo.light, 30),
                            ColorMath::lighten(accentInfo.dark,  30) });

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
    // at a grey just at the threshold (inverted, midnight-blue light),
    // too weak for a title.
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
    assign(tokens, ThemeManager::HeaderBackground, ThemeColorPair { headerBg,    headerBg });
    assign(tokens, ThemeManager::HeaderText,        ThemeColorPair { headerText,  headerText });
    assign(tokens, ThemeManager::HeaderTextMuted,   ThemeColorPair { headerMuted, headerMuted });

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
    assign(tokens, ThemeManager::SectionHeader,
           ThemeColorPair { sectionHeader, sectionHeader });
    assign(tokens, ThemeManager::SectionHeaderHover,
           ThemeColorPair { sectionHeaderHoverLight, sectionHeaderHover });

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
    assign(tokens, ThemeManager::FieldBorder,
           ThemeColorPair { fieldBorder, fieldBorder });
    assign(tokens, ThemeManager::Separator,
           ThemeColorPair { separator, separator });

    // Secondary text: Text faded 40 % toward Base, then lifted to
    // the readableText ratio (the WCAG text minimum) against Base.
    const QColor mutedText = ColorMath::ensureContrast(
            ColorMath::mix(paletteTextColor, baseColor, 0.40), baseColor,
            ratios.readableText);
    assign(tokens, ThemeManager::MutedText, ThemeColorPair { mutedText, mutedText });

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
    assign(tokens, ThemeManager::CardBackground,         ThemeColorPair { cardBg,                 cardBg });
    assign(tokens, ThemeManager::CardBorder,             ThemeColorPair { cardBorder,             cardBorder });
    assign(tokens, ThemeManager::CardSectionHeader,      ThemeColorPair { cardSectionHeader,      cardSectionHeader });
    assign(tokens, ThemeManager::CardSectionHeaderHover, ThemeColorPair { cardSectionHeaderHover, cardSectionHeaderHover });
    assign(tokens, ThemeManager::CardLink,               ThemeColorPair { cardLink,               cardLink });
    assign(tokens, ThemeManager::CardLinkHover,          ThemeColorPair { cardLinkHover,          cardLinkHover });
    assign(tokens, ThemeManager::CardFocusRing,          ThemeColorPair { cardFocusRing,          cardFocusRing });
    assign(tokens, ThemeManager::OverlayCardBackground,  ThemeColorPair { overlayCardBg,          overlayCardBg });
    assign(tokens, ThemeManager::OverlayCardBorder,      ThemeColorPair { overlayCardBorder,      overlayCardBorder });

    // Foregrounds for solid accent surfaces — auto-pick black or white
    // per contrastingText().  These give QSS rules a single token to
    // paint text on accent backgrounds without each theme having to
    // hand-tune the contrast (or rely on one fixed text color
    // that may not fit a bright accent — see #headerBuildLabel and
    // #updateDownload in welcome-header.qss).
    assign(tokens, ThemeManager::TextOnSuccess,
           ColorMath::contrastingText(successPair));
    assign(tokens, ThemeManager::TextOnWarning,
           ColorMath::contrastingText(tokens.value(ThemeManager::AccentWarning)));
    assign(tokens, ThemeManager::TextOnError,
           ColorMath::contrastingText(tokens.value(ThemeManager::AccentError)));
    assign(tokens, ThemeManager::TextOnInfo,
           ColorMath::contrastingText(tokens.value(ThemeManager::AccentInfo)));

    // Foreground for the filter validity tints.
    for (const auto &ft : filterTints)
        assign(tokens, ft.text, ColorMath::contrastingText(tokens.value(ft.tint)));

    // Update bar — all from accent.success
    assign(tokens, ThemeManager::UpdateBackground,       updateBg);
    assign(tokens, ThemeManager::UpdateBorder,           ColorMath::withAlpha(successPair, 51));
    assign(tokens, ThemeManager::UpdateText,             ColorMath::lighten(successPair, 50));
    assign(tokens, ThemeManager::UpdateTextHighlight,    ColorMath::lighten(successPair, 70));
    assign(tokens, ThemeManager::UpdateLink,             ColorMath::lighten(successPair, 30));
    assign(tokens, ThemeManager::UpdateLinkHover,        ColorMath::lighten(successPair, 50));
    assign(tokens, ThemeManager::UpdateLinkPressed,      ColorMath::darken(successPair, 20));
    assign(tokens, ThemeManager::UpdateButtonBg,         successPair);
    assign(tokens, ThemeManager::UpdateButtonHover,      ColorMath::darken(successPair, 8));
    assign(tokens, ThemeManager::UpdateButtonPressed,    ColorMath::darken(successPair, 16));
    assign(tokens, ThemeManager::UpdateButtonDisabledBg, disabledBg);
    // Disabled button text: contrasting text faded toward the disabled button bg
    assign(tokens, ThemeManager::UpdateButtonDisabledText,
           ColorMath::disabled(ColorMath::contrastingText(disabledBg.light), disabledBg.light),
           ColorMath::disabled(ColorMath::contrastingText(disabledBg.dark),  disabledBg.dark));
    // Dismiss hover: subtle tint of contrasting color onto the bar
    assign(tokens, ThemeManager::UpdateDismissHoverBg,
           dismissHoverBg(updateBg.light), dismissHoverBg(updateBg.dark));
    // Dismiss pressed: same pattern but use disabled() for a stronger blend
    assign(tokens, ThemeManager::UpdateDismissPressedBg,
           dismissPressedBg(updateBg.light), dismissPressedBg(updateBg.dark));
    // The status dot; kept apart from the update bar in high contrast.
    assign(tokens, ThemeManager::UpdateDot,              successPair);

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
    assign(tokens, ThemeManager::HighlightColorOrange, tokens.value(ThemeManager::AccentWarning));
    assign(tokens, ThemeManager::HighlightColorGreen,  successPair);
}
