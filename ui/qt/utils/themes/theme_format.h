/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_FORMAT_H
#define THEME_FORMAT_H

#include <QLatin1String>
#include <QString>

/**
 * Key names of the theme file format (theme.jsonc), shared by ThemeParser,
 * ThemeWriter and the Theme Designer.  Color sections and their keys are
 * not listed here: ThemeManager derives them from the ThemeToken enum and
 * its sections_ table.
 */
namespace ThemeFormat {

// Root keys that are not color sections.
inline const QLatin1String Meta("meta");
inline const QLatin1String Contrast("contrast");
inline const QLatin1String Separator("separator");
inline const QLatin1String Graphs("graphs");
inline const QLatin1String Fonts("fonts");
inline const QLatin1String Syntax("syntax"); ///< accepted, not read yet
inline const QLatin1String Images("images"); ///< accepted, not read yet

/** Every root key besides the color sections. */
inline const QLatin1String NonSectionRootKeys[] = {
    Meta, Contrast, Separator, Graphs, Fonts, Syntax, Images
};

/**
 * @param index  0-based position in the file's "graphs" array.
 * @return "graphs[<index>]" as used in the file and in messages about it.
 */
inline QString graphPath(int index)
{
    return QStringLiteral("%1[%2]").arg(Graphs).arg(index);
}

// Values of the contrast key.
inline const QLatin1String ContrastStandard("standard");
inline const QLatin1String ContrastHigh("high");

// Sides of a color pair.
inline const QLatin1String Light("light");
inline const QLatin1String Dark("dark");

// Keys of the meta object.
inline const QLatin1String MetaName("name");
inline const QLatin1String MetaVersion("version");
inline const QLatin1String MetaAuthor("author");
inline const QLatin1String MetaDescription("description");

// Keys of the fonts object and of each font in it.
inline const QLatin1String FontRegular("regular");
inline const QLatin1String FontMonospace("monospace");
inline const QLatin1String FontFamily("family");
inline const QLatin1String FontSize("size");

} // namespace ThemeFormat

#endif // THEME_FORMAT_H
