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

#include <QHash>
#include <QPalette>

/**
 * Computes every derived token from the mandatory brand+accent colors
 * (plus the current QPalette for section-header-style derivations).
 *
 * The handler reads the already-populated token map (brand / accent
 * / expert / packets / conversation / palette from the theme), and
 * enriches it in place with the generated tokens:
 *
 *   Header*                       (from brand)
 *   SectionHeader / SectionHeaderHover   (from brand + QPalette::Mid)
 *   TextOnDark / TextOnDarkMuted  (from brand.deep)
 *   Update*                       (from accent.success)
 *   Packets*                      (from brand + palette base/text)
 *   Conversation*                 (from brand + accent + base)
 *   Expert*                       (from accent variants — alpha-blend)
 *   AccentOrange / AccentGreen    (aliases from accent.success)
 *
 * Only-if-missing semantics: if a theme has already supplied a
 * specific token explicitly (e.g. a theme that overrides
 * `HeaderGradientStart`), the derivation leaves that value alone.
 * Matches the behavior ThemeManager::derive() had with
 * overwrite=false.
 */
class ThemeTokenHandler
{
public:
    using TokenMap = QHash<ThemeManager::ThemeToken, ThemeColorPair>;

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
     */
    static void deriveAll(TokenMap &tokens, bool isDarkMode, const QPalette &palette);
};

#endif /* THEME_TOKEN_HANDLER_H */
