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

#include <epan/prefs.h>

#include <QColor>
#include <QDebug>
#include <QFile>
#include <QFontDatabase>
#include <QFontInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QStringList>

// --------------------------------------------------------------------
// File-local helpers for font handling (previously in theme_manager.cpp)
// --------------------------------------------------------------------

static QStringList monospaceFallbacks()
{
#if defined(Q_OS_MACOS)
    return QStringList() << "SF Mono" << "Menlo" << "Monaco" << "Courier New";
#elif defined(Q_OS_WIN)
    return QStringList() << "Cascadia Mono" << "Cascadia Code" << "Consolas" << "Lucida Console" << "Courier New";
#else // Linux / X11 / other Unix
    return QStringList() << "DejaVu Sans Mono" << "Liberation Mono" << "Noto Sans Mono" << "Ubuntu Mono"
                         << "Bitstream Vera Sans Mono" << "FreeMono";
#endif
}

static QFont guaranteeMonospaceFont(const QFont &font)
{
    QFont cleanFont = font;

    // On some systems (Linux in particular) Qt may hand back a non-
    // fixed-pitch font when asked for the monospace face.  Force a
    // known-good fallback in that case.
    if (!QFontInfo(cleanFont).fixedPitch()) {
        cleanFont.setFamilies(monospaceFallbacks());
        cleanFont.setStyleHint(QFont::Monospace);
    }

    cleanFont.setStyle(QFont::StyleNormal);

#if defined(Q_OS_WIN) && QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    // On Windows with Qt 5 the system font sizes render smaller than ideal.
    cleanFont.setPixelSize(cleanFont.pointSize() + 2);
#endif

    return cleanFont;
}

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

QFont ThemeParser::parseFontFamily(const QJsonObject &obj, QFont defaultFont)
{
    if (obj.isEmpty())
        return defaultFont;

    QFont newFont = defaultFont;
    const QString family = obj.value(QStringLiteral("family")).toString();
    const int     size   = obj.value(QStringLiteral("size")).toInt(0);

    if (!family.isEmpty())
        newFont.setFamily(family);
    if (size > 0)
        newFont.setPointSize(size);

    return newFont;
}

void ThemeParser::parseFonts(const QJsonObject &fontsObj, Result &out)
{
    const QFont systemMonospace = guaranteeMonospaceFont(
        QFontDatabase::systemFont(QFontDatabase::FixedFont));
    out.regularFont = QFontDatabase::systemFont(QFontDatabase::GeneralFont);

    // User preference (gui.fonts.qt.font_name) always wins if it parses
    // to a fixed-pitch font.
    const QString fontString = QString(prefs.gui_font_name);
    if (!fontString.isEmpty()) {
        QFont userFont;
        if (!userFont.fromString(fontString)) {
            // Qt 5 couldn't parse a Qt 6-format string (or it was malformed).
            // Fall back: strip the extra trailing fields to the 10/11 Qt 5 expects.
            const QStringList parts = fontString.split(QLatin1Char(','));
            if (parts.size() >= 11) {
                QStringList trimmed = parts.mid(0, 10);
                // Preserve the optional style name if present (last field in both formats)
                if (!parts.last().isEmpty() && !parts.last().at(0).isDigit())
                    trimmed << parts.last();
                userFont.fromString(trimmed.join(QLatin1Char(',')));
            }
        }
        if (QFontInfo(userFont).fixedPitch()) {
            out.monospaceFont = guaranteeMonospaceFont(userFont);
            return;
        }
    }

    // No valid user font specified, try to load fonts from the theme.
    if (!fontsObj.isEmpty()) {
        const QFont systemRegular = guaranteeMonospaceFont(
            QFontDatabase::systemFont(QFontDatabase::GeneralFont));
        out.regularFont =
            parseFontFamily(fontsObj.value(QStringLiteral("regular")).toObject(), systemRegular);

        const QFont parsedMonospace =
            parseFontFamily(fontsObj.value(QStringLiteral("monospace")).toObject(), systemMonospace);
        out.monospaceFont = guaranteeMonospaceFont(parsedMonospace);
        return;
    }

    // No theme fonts specified, fall back to system defaults.
    out.monospaceFont = systemMonospace;
}
