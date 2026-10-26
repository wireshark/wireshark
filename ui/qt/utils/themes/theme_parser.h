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

#include <ui/qt/utils/jsonc_document.h>
#include <ui/qt/utils/theme_manager.h>

#include <QCoreApplication>
#include <QFont>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QString>

/**
 * Companion parser for ThemeManager.  Handles every aspect of reading a
 * theme.jsonc file: JSONC reading (JsoncDocument), JSON parsing,
 * section/role/color decoding, graph colors, font hints.  Has no opinion on
 * palette application, derived tokens, stylesheets, or runtime mode — those
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
    Q_DECLARE_TR_FUNCTIONS(ThemeParser)
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
        ThemeFontHint                                   regularFont;       ///< regular font as family/size; unset when the theme declares none
        ThemeFontHint                                   monospaceFont;     ///< monospace font as family/size; unset when the theme declares none
        ThemeParseReport                                report;            ///< non-fatal findings, filled by parseData()
    };

    ThemeParser(const QHash<QString, ThemeSectionInfo>       &sections,
                const QHash<QString, ThemeManager::ThemeToken> &roleCache);

    /**
     * Reads and parses the theme JSONC at the given Qt resource path.
     *
     * @param internalName  short name (e.g. "default"); stored on the result.
     * @param resourcePath  full Qt resource URL (e.g. ":/themes/default/theme.jsonc").
     * @param out           populated on success.
     * @param errorString   optional; set to the fatal error on failure.
     * @return true on a usable parse, false on a hard error (file missing,
     *         invalid JSON, required section missing).
     */
    bool parse(const QString &internalName,
               const QString &resourcePath,
               Result        &out,
               QString       *errorString = nullptr);

    /**
     * Parses theme JSONC that is already in memory.  parse() reads the
     * file and delegates here.
     *
     * JSON syntax errors are reported as "Line L, column C: <message>".
     * Non-fatal findings (invalid colors, unknown keys, ...) go to
     * out.report.
     *
     * @param internalName  short name; stored on the result.
     * @param raw           theme file content, comments allowed.
     * @param out           populated on success.
     * @param errorString   optional; set to the fatal error on failure.
     * @return true on a usable parse, false on a hard error.
     */
    bool parseData(const QString    &internalName,
                   const QByteArray &raw,
                   Result           &out,
                   QString          *errorString = nullptr);

    /**
     * QFont::toString() descriptor of the font @p hint asks for, or an
     * empty string when the hint is unset.  No resolution happens here;
     * FontManager::themeFont() owns it.
     */
    static QString          fontDescriptor(const ThemeFontHint &hint);

private:
    static QColor           parseColor(const QString &colorStr);
    static ThemeColorPair   parseColorPair(const QJsonObject &obj);
    void                    parseSection(const QJsonObject        &root,
                                         const QString            &sectionName,
                                         const ThemeSectionInfo   &sectionInfo,
                                         const ThemeInfo          &info,
                                         Result                   &result);
    void                    checkColorPair(const QJsonObject &obj,
                                           const QString     &path,
                                           const QString     &section,
                                           const QString     &key,
                                           Result            &out);
    static QString          withLine(int line, const QString &message);
    static void             parseFonts(const QJsonObject &fontsObj, Result &out);
    static ThemeFontHint    fontHint(const QJsonObject &obj);

    ThemeManager::ThemeToken stringToToken(const QString &token) const;

    const QHash<QString, ThemeSectionInfo>        &sections_;
    const QHash<QString, ThemeManager::ThemeToken> &roleCache_;
    JsoncDocument                                  jsonc_; ///< document of the parseData() call in progress, for line lookups
};

#endif /* THEME_PARSER_H */
