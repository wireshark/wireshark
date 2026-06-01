/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_PARSER_H
#define THEME_PARSER_H

#include <ui/qt/utils/theme_manager.h>

#include <QFont>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QString>

/**
 * Companion parser for ThemeManager.  Handles every aspect of reading a
 * theme.jsonc file: comment stripping, JSON parsing, section/role/color
 * decoding, graph colors, font hints.  Has no opinion on palette
 * application, derived tokens, stylesheets, or runtime mode — those
 * remain ThemeManager's responsibility.
 *
 * Constructed with const references to the section definitions and the
 * role-name → ThemeToken cache owned by ThemeManager; never modifies
 * them.  A single ThemeParser instance can parse successive themes.
 *
 * Private to the theme subsystem.  Outside callers should go through
 * ThemeManager.
 */
class ThemeParser
{
public:
    /**
     * Populated by parse() on success.  On failure, contents are
     * undefined and should be discarded.
     */
    struct Result {
        ThemeInfo                                       info;
        QHash<ThemeManager::ThemeToken, ThemeColorPair>  colors;
        QList<ThemeColorPair>                           graphColors;
        QString                                         regularFontName;   ///< theme's declared regular font descriptor; empty if unset
        QString                                         monospaceFontName; ///< theme's declared monospace font descriptor; empty if unset
    };

    ThemeParser(const QHash<QString, ThemeSectionInfo>       &sections,
                const QHash<QString, ThemeManager::ThemeToken> &roleCache);

    /**
     * Reads and parses the theme JSONC at the given Qt resource path.
     *
     * @param internalName  short name (e.g. "default"); stored on the result.
     * @param resourcePath  full Qt resource URL (e.g. ":/themes/default/theme.jsonc").
     * @param out           populated on success.
     * @return true on a usable parse, false on a hard error (file missing,
     *         invalid JSON, required section missing).
     */
    bool parse(const QString &internalName,
               const QString &resourcePath,
               Result        &out);

private:
    static QByteArray       stripJsoncComments(const QByteArray &jsonc);
    static QColor           parseColor(const QString &colorStr);
    static ThemeColorPair   parseColorPair(const QJsonObject &obj);
    void                    parseSection(const QJsonObject        &root,
                                         const QString            &sectionName,
                                         const ThemeSectionInfo   &sectionInfo,
                                         const ThemeInfo          &info,
                                         QHash<ThemeManager::ThemeToken, ThemeColorPair> &out);
    static QString          fontDescriptor(const QJsonObject &obj);
    static void             parseFonts(const QJsonObject &fontsObj, Result &out);

    ThemeManager::ThemeToken stringToToken(const QString &token) const;

    const QHash<QString, ThemeSectionInfo>        &sections_;
    const QHash<QString, ThemeManager::ThemeToken> &roleCache_;
};

#endif /* THEME_PARSER_H */
