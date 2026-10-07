/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <ui/qt/utils/theme_manager.h>

#include <QApplication>
#include <QColor>
#include <QPalette>

#include <memory>
#include <optional>

/**
 * @brief Palette override shared between an icon object and its engine, so that
 *        ThemedIcon::setPalette() / ContrastAdaptIcon::setPalette() reach the
 *        engine even though QIcon hides it.  Empty means "use the application
 *        palette".
 */
using IconPaletteRef = std::shared_ptr<std::optional<QPalette>>;

inline IconPaletteRef makeIconPaletteRef()
{
    return std::make_shared<std::optional<QPalette>>();
}

inline const QPalette *iconPalettePtr(const IconPaletteRef &ref)
{
    return (ref && ref->has_value()) ? &ref->value() : nullptr;
}

/**
 * @brief Resolve a theme token for an icon engine, optionally against a
 *        caller-supplied palette.
 *
 * When @p palette is non-null, the Palette* tokens that mirror a QPalette role
 * (PaletteWindow, PaletteText, ...) are read from it, so an icon can be
 * previewed against a palette other than the application's.  Every other token
 * — and any Palette* token with no matching role — comes from the live
 * ThemeManager.  If that is also invalid the result is the palette's (or the
 * application's) Text colour.
 */
inline QColor resolveIconToken(ThemeManager::ThemeToken token, const QPalette *palette)
{
    if (palette) {
        switch (token) {
        case ThemeManager::PaletteWindow:          return palette->color(QPalette::Window);
        case ThemeManager::PaletteBase:            return palette->color(QPalette::Base);
        case ThemeManager::PaletteText:            return palette->color(QPalette::Text);
        case ThemeManager::PaletteWindowText:      return palette->color(QPalette::WindowText);
        case ThemeManager::PaletteAlternateBase:   return palette->color(QPalette::AlternateBase);
        case ThemeManager::PaletteMid:             return palette->color(QPalette::Mid);
        case ThemeManager::PaletteMidLight:        return palette->color(QPalette::Midlight);
        case ThemeManager::PaletteHighlightedText: return palette->color(QPalette::HighlightedText);
        default: break;
        }
    }
    const QColor c = ThemeManager::instance()->color(token);
    if (c.isValid())
        return c;
    return (palette ? *palette : qApp->palette()).color(QPalette::Text);
}
