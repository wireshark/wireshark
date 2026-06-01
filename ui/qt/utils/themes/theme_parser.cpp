/* theme_parser.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "ui/qt/utils/themes/theme_parser.h"

#include <QColor>
#include <QDebug>
#include <QFile>
#include <QFont>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QStringList>

// --------------------------------------------------------------------
// ThemeParser
// --------------------------------------------------------------------

ThemeParser::ThemeParser(const QHash<QString, ThemeSectionInfo>       &sections,
                         const QHash<QString, ThemeManager::ThemeToken> &roleCache)
    : sections_(sections),
      roleCache_(roleCache)
{
}

bool ThemeParser::parse(const QString &internalName,
                        const QString &resourcePath,
                        Result        &out)
{
    QFile f(resourcePath);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning("ThemeParser: failed to open theme \"%s\" (%s)",
                 qUtf8Printable(internalName), qUtf8Printable(resourcePath));
        return false;
    }

    const QByteArray raw  = f.readAll();
    const QByteArray json = stripJsoncComments(raw);

    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(json, &parseError);
    if (doc.isNull()) {
        qWarning().noquote().nospace()
            << "ThemeParser: failed to parse " << resourcePath
            << ": " << parseError.errorString()
            << " (offset " << parseError.offset << ")";
        return false;
    }

    const QJsonObject root = doc.object();

    // Step 1 - meta section
    const QJsonObject meta = root.value(QStringLiteral("meta")).toObject();
    out.info               = ThemeInfo();
    out.info.name          = meta.value(QStringLiteral("name")).toString();
    out.info.internalName  = internalName;
    out.info.version       = meta.value(QStringLiteral("version")).toInt();
    out.info.description   = meta.value(QStringLiteral("description")).toString();
    out.info.author        = meta.value(QStringLiteral("author")).toString();

    // Step 2 - color sections
    out.colors.clear();
    for (auto it = sections_.constBegin(); it != sections_.constEnd(); ++it) {
        const QString         &sectionName = it.key();
        const ThemeSectionInfo &sectionInfo = it.value();
        if (sectionInfo.required && !root.contains(sectionName)) {
            qWarning("ThemeParser: missing required section \"%s\" in theme \"%s\"",
                     qUtf8Printable(sectionName), qUtf8Printable(out.info.name));
            return false;
        }
        parseSection(root, sectionName, sectionInfo, out.info, out.colors);
    }

    // Step 2b - separator (single top-level ColorPair, not a section-
    // with-subkeys).  Kept outside sections_ because the JSON shape is
    // { "separator": { "light": "...", "dark": "..." } } rather than
    // the section-with-subkeys form parseSection() expects.  When
    // absent ThemeTokenHandler derives Separator from palette.base +
    // palette.mid.
    if (root.contains(QStringLiteral("separator"))) {
        const QJsonObject sepObj = root.value(QStringLiteral("separator")).toObject();
        if (!sepObj.isEmpty())
            out.colors[ThemeManager::Separator] = parseColorPair(sepObj);
    }

    // Step 3 - graphs
    out.graphColors.clear();
    const QJsonArray graphs = root.value(QStringLiteral("graphs")).toArray();
    for (int i = 0; i < graphs.size(); ++i)
        out.graphColors << parseColorPair(graphs[i].toObject());

    // Step 4 - fonts
    parseFonts(root.value(QStringLiteral("fonts")).toObject(), out);

    return true;
}

// --------------------------------------------------------------------
// Helpers — moved verbatim from the former ThemeManager implementation.
// --------------------------------------------------------------------

QByteArray ThemeParser::stripJsoncComments(const QByteArray &jsonc)
{
    QByteArray result;
    result.reserve(jsonc.size());

    const auto len = jsonc.size();
    int i = 0;
    while (i < len) {
        const char c = jsonc.at(i);

        // --- Inside a string literal: copy verbatim ---
        if (c == '"') {
            result.append(c);
            i++;
            while (i < len) {
                char sc = jsonc.at(i);
                result.append(sc);
                i++;
                if (sc == '\\' && i < len) {
                    result.append(jsonc.at(i));
                    i++;
                } else if (sc == '"') {
                    break;
                }
            }
            continue;
        }

        // --- Line comment: // until end of line ---
        if (c == '/' && i + 1 < len && jsonc.at(i + 1) == '/') {
            i += 2;
            while (i < len && jsonc.at(i) != '\n')
                i++;
            // Keep the newline so that line numbers stay meaningful
            // in parse-error messages
            continue;
        }

        // --- Block comment: /* ... */ ---
        if (c == '/' && i + 1 < len && jsonc.at(i + 1) == '*') {
            i += 2;
            while (i + 1 < len) {
                if (jsonc.at(i) == '*' && jsonc.at(i + 1) == '/') {
                    i += 2;
                    break;
                }
                // Preserve newlines for line-number accuracy
                if (jsonc.at(i) == '\n')
                    result.append('\n');
                i++;
            }
            continue;
        }

        // --- Ordinary character ---
        result.append(c);
        i++;
    }

    return result;
}

QColor ThemeParser::parseColor(const QString &colorStr)
{
    QColor color(colorStr);
    if (!color.isValid())
        qWarning("ThemeParser: invalid color string \"%s\"", qUtf8Printable(colorStr));
    return color;
}

ThemeColorPair ThemeParser::parseColorPair(const QJsonObject &obj)
{
    QColor light = parseColor(obj.value(QStringLiteral("light")).toString());
    QColor dark  = parseColor(obj.value(QStringLiteral("dark")).toString());

    if (!light.isValid() && !dark.isValid()) {
        qWarning("ThemeParser: color token has no \"light\" or \"dark\" value");
        return ThemeColorPair { QColor(), QColor() };
    }

    if (!light.isValid() || !dark.isValid()) {
        // Warn about only one color token, but allow it.  Some colors
        // may be intentionally left undefined in one mode so fall
        // back by using one color for both.
        const QColor validVal = light.isValid() ? light : dark;
        light = validVal;
        dark  = validVal;
        qWarning("ThemeParser: only one color token defined; using the same value for both light and dark modes");
    }

    return ThemeColorPair { light, dark };
}

ThemeManager::ThemeToken ThemeParser::stringToToken(const QString &token) const
{
    return roleCache_.value(token.toLower(), ThemeManager::NoRole);
}

void ThemeParser::parseSection(const QJsonObject                               &root,
                               const QString                                   &sectionName,
                               const ThemeSectionInfo                          &sectionInfo,
                               const ThemeInfo                                 &info,
                               QHash<ThemeManager::ThemeToken, ThemeColorPair>  &out)
{
    QJsonObject section  = root.value(sectionName).toObject();
    QStringList tokenList = sectionInfo.tokens;

    for (auto it = section.begin(); it != section.end(); ++it) {
        const QString key = it.key().toLower();
        if (!it.value().isObject()) {
            qWarning("ThemeParser: expected object for token \"%s%s\" in theme \"%s\"; skipping",
                     qUtf8Printable(sectionName), qUtf8Printable(key),
                     qUtf8Printable(info.name));
            continue;
        }
        if (!tokenList.contains(key)) {
            qWarning("ThemeParser: unknown/invalid token \"%s%s\" in theme \"%s\"; skipping",
                     qUtf8Printable(sectionName), qUtf8Printable(key),
                     qUtf8Printable(info.name));
            continue;
        }
        if (sectionInfo.required)
            tokenList.removeAll(key);

        const ThemeManager::ThemeToken role =
            stringToToken(QStringLiteral("%1%2").arg(sectionName, key));
        if (role != ThemeManager::NoRole)
            out[role] = parseColorPair(it.value().toObject());
    }

    if (sectionInfo.required && !tokenList.isEmpty()) {
        qWarning("ThemeParser: missing required token(s) \"%s\" in section \"%s\" of theme \"%s\"",
                 qUtf8Printable(tokenList.join(", ")),
                 qUtf8Printable(sectionName),
                 qUtf8Printable(info.name));
    }
}

QString ThemeParser::fontDescriptor(const QJsonObject &obj)
{
    // Returns a QFont::toString() descriptor for the theme's declared font, or
    // an empty string when the theme specifies nothing.  No resolution,
    // validation, or fallback happens here — FontManager owns all of that.
    if (obj.isEmpty())
        return QString();

    QFont f;
    const QString family = obj.value(QStringLiteral("family")).toString();
    const int     size   = obj.value(QStringLiteral("size")).toInt(0);

    if (!family.isEmpty())
        f.setFamily(family);
    if (size > 0)
        f.setPointSize(size);

    return f.toString();
}

void ThemeParser::parseFonts(const QJsonObject &fontsObj, Result &out)
{
    // Extract only what the theme declares.  All resolution policy — the
    // gui.font_name precedence, the fixed-pitch guarantee, and the system
    // fallback — now lives in FontManager.  An empty descriptor means the
    // theme specifies nothing for that font.
    out.regularFontName   = fontDescriptor(fontsObj.value(QStringLiteral("regular")).toObject());
    out.monospaceFontName = fontDescriptor(fontsObj.value(QStringLiteral("monospace")).toObject());
}
