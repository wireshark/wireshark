/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LEGACY_COLOR_PREFS_MIGRATION_H
#define LEGACY_COLOR_PREFS_MIGRATION_H

/**
 * One-shot migration of the legacy per-color preferences
 * (gui.active_frame.*, gui.marked_frame.*, gui.stream.client.*, …) into a
 * personal theme JSONC file.
 *
 * The legacy color preferences were removed when the theme manager landed.
 * Users who had customized any of them lost their visual settings.  This
 * migration recovers them: if the personal themes directory is empty (i.e.
 * the user has never installed a custom theme yet) AND the Default profile's
 * preferences file still has uncommented legacy color keys whose values
 * differ from the pre-removal defaults, we synthesize a personal theme that
 * preserves those colors.
 *
 * Design choices (deliberate):
 *   - Default profile only.  Per-profile color customizations are not
 *     migrated; themes are global in recent_common, so picking one
 *     profile's customizations and applying them across all profiles is
 *     the cleanest mapping.  The Default profile is the natural source.
 *   - Light/dark side: chosen via ThemeManager::isDarkMode() at migration
 *     time.  Old prefs stored a single color value, but theme tokens are
 *     {light, dark} pairs.  We fill in the side that matches the user's
 *     current appearance and leave the other side blank so it falls back
 *     to the default theme's value.
 *   - Auto-select: on success, recent.gui_theme_name is set to "personal"
 *     so the freshly created theme is loaded immediately on this same
 *     startup, no user action required.
 *   - Idempotency: the Default profile's preferences file is rewritten
 *     with the legacy color keys stripped (uncommented entries only).
 *     This turns the trigger condition false on the next startup, so the
 *     migration is a true one-shot.
 *   - Debug gate: setting WIRESHARK_THEME_KEEP_LEGACY_PREFS=1 in the
 *     environment skips the strip step.  Combined with deleting the
 *     generated personal.jsonc, this forces re-migration on every launch,
 *     which is useful when iterating on the migration logic itself.
 */
namespace LegacyColorPrefsMigration
{
    /**
     * Run the migration if all preconditions hold.
     *
     * Preconditions:
     *   - WorkspaceState::personalThemesPath() is missing or contains
     *     no *.jsonc files.
     *   - The Default profile's preferences file has at least one
     *     uncommented legacy color key whose value differs from the
     *     pre-removal hardcoded default.
     *
     * Side effects on success:
     *   - Creates <personalThemesDir>/personal.jsonc with one theme
     *     section per migrated color group.
     *   - Sets recent.gui_theme_name = "personal".
     *   - Strips legacy color keys from the Default profile's
     *     preferences file (unless WIRESHARK_THEME_KEEP_LEGACY_PREFS
     *     is set in the environment).
     *
     * @return true if migration ran and produced a theme file, false
     *         in every other case (gate failed, no customizations
     *         found, or write error).
     */
    bool runIfNeeded();
}

#endif /* LEGACY_COLOR_PREFS_MIGRATION_H */
