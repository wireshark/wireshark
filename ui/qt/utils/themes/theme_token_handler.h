/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_TOKEN_HANDLER_H
#define THEME_TOKEN_HANDLER_H

#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/color_math.h>

#include <QHash>
#include <QList>
#include <QPalette>

/**
 * Computes every derived token from the mandatory brand+accent colors
 * (plus the current QPalette for section-header-style derivations).
 *
 * The handler reads the already-populated token map (brand / accent
 * / expert / packets / conversation / palette from the theme), and
 * enriches it in place with the generated tokens:
 *
 *   SectionHeader / SectionHeaderHover   (from brand + QPalette::Mid)
 *   FieldBorder / Separator       (from QPalette::Mid + Base)
 *   Card* / OverlayCard*          (from palette.alternateBase pin or Base,
 *                                 Separator, Highlight, Link)
 *   SyntaxKey                     (from QPalette::Mid + Base)
 *   HeaderBackground / HeaderText / HeaderTextMuted
 *                                 (from QPalette Highlight / HighlightedText / Window)
 *   Update*                       (from accent.success)
 *   Packets*                      (from brand + palette base/text)
 *   Conversation*                 (from brand + accent + base)
 *   Expert*                       (from accent variants — alpha-blend)
 *   Filter*                       (from accent + base)
 *   Syntax*                       (from palette.mid + accent)
 *   FieldBorder / Separator / MutedText  (from palette base/mid/text)
 *   TextOn*                       (black or white on accent / filter tints)
 *   Diff* / Notice*               (from base + accent)
 *   HighlightColorOrange / HighlightColorGreen  (aliases from accent)
 *
 * Only-if-missing semantics: if a theme has already supplied a
 * specific token explicitly (e.g. a theme that overrides
 * `PacketsSelection`), the derivation leaves that value alone.
 * Matches the behavior ThemeManager::derive() had with
 * overwrite=false.
 */
class ThemeTokenHandler
{
public:
    using TokenMap = QHash<ThemeManager::ThemeToken, ThemeColorPair>;
    /** Rule text per token, untranslated; translate in the "ThemeTokenHandler" context. */
    using SourceMap = QHash<ThemeManager::ThemeToken, const char *>;

    /**
     * The color of @p role for one mode: the dark side when
     * @p isDarkMode, else the light side.  Invalid when @p role is
     * NoRole, absent from @p tokens, or has no valid color on that side.
     */
    static QColor sideOf(const TokenMap &tokens, ThemeManager::ThemeToken role, bool isDarkMode);

    /**
     * Enriches `tokens` in-place with every derived role.
     *
     * @param tokens     Map populated from theme.jsonc parsing.
     *                   Must contain the mandatory brand + accent
     *                   colors; the derivation will read them and
     *                   write back the generated entries.
     * @param isDarkMode Selects which side of palette-override color
     *                   pairs to consult for Packets/Conversation
     *                   derivations.  Does not affect tokens that
     *                   store both light/dark variants — those are
     *                   derived from the pair wholesale.
     * @param palette    The palette to read Mid and other base roles
     *                   from.  Pass the palette returned by
     *                   ThemePaletteBuilder::build() so derivation
     *                   uses the new values even before the palette
     *                   has been pushed to QApplication (fixes Qt 5
     *                   signal-ordering: ApplicationPaletteChanged
     *                   fires synchronously inside setPalette(), so
     *                   tokens must be ready before that call).
     *                   Defaults to QApplication::palette() for
     *                   backwards-compatible call sites.
     * @param ratios     The contrast ratio set every derivation targets.
     *                   Passed explicitly rather than read from
     *                   ColorMath::activeRatios(), so a preview can
     *                   derive for a contrast level that is not applied.
     * @param sources    When not null, receives for every token this
     *                   function assigns the rule it applied, as written
     *                   next to the rule (QT_TRANSLATE_NOOP).  Recorded
     *                   whether or not the theme already set the token.
     */
    static void deriveAll(TokenMap &tokens, bool isDarkMode, const QPalette &palette,
                          const ColorMath::ContrastRatios &ratios,
                          SourceMap *sources = nullptr);

    /**
     * The colors an untranslated rule text names, in order of first
     * appearance (the main source first), without duplicates.
     *
     * @param source  a rule text as recorded by deriveAll() or
     *                ThemePaletteBuilder::build().
     */
    static QList<ThemeManager::ThemeToken> sourceTokens(const char *source);
};

#endif /* THEME_TOKEN_HANDLER_H */
