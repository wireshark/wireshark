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
#include "ui/qt/utils/themes/theme_format.h"
#include "ui/qt/utils/themes/theme_writer.h"

#include <QColor>
#include <QDebug>
#include <QFile>
#include <QFont>
#include <QJsonArray>
#include <QJsonObject>
#include <QStringList>

#include <algorithm>
#include <iterator>

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
                        Result        &out,
                        QString       *errorString)
{
    QFile f(resourcePath);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning("ThemeParser: failed to open theme \"%s\" (%s)",
                 qUtf8Printable(internalName), qUtf8Printable(resourcePath));
        if (errorString)
            *errorString = tr("Could not open \"%1\".").arg(resourcePath);
        return false;
    }

    return parseData(internalName, f.readAll(), out, errorString);
}

bool ThemeParser::parseData(const QString    &internalName,
                            const QByteArray &raw,
                            Result           &out,
                            QString          *errorString)
{
    out.report = ThemeParseReport();
    if (!jsonc_.parse(raw)) {
        qWarning().noquote().nospace()
            << "ThemeParser: failed to parse theme \"" << internalName
            << "\": " << jsonc_.errorString()
            << " (line " << jsonc_.errorLine() << ", column " << jsonc_.errorColumn() << ")";
        if (errorString) {
            *errorString = jsonc_.errorLine() > 0
                ? tr("Line %1, column %2: %3").arg(jsonc_.errorLine()).arg(jsonc_.errorColumn()).arg(jsonc_.errorString())
                : jsonc_.errorString();
        }
        return false;
    }

    const QJsonObject root = jsonc_.document().object();

    // Step 1 - meta section
    const QJsonObject meta = root.value(ThemeFormat::Meta).toObject();
    out.info               = ThemeInfo();
    out.info.name          = meta.value(ThemeFormat::MetaName).toString();
    out.info.internalName  = internalName;
    out.info.version       = meta.value(ThemeFormat::MetaVersion).toInt();
    out.info.description   = meta.value(ThemeFormat::MetaDescription).toString();
    out.info.author        = meta.value(ThemeFormat::MetaAuthor).toString();

    // The top-level "contrast" field sits beside "meta": it selects the
    // ratio set the derived colors are computed with, not descriptive data.
    // An unknown value falls back to standard so a typo never fails the load.
    const QString contrast = root.value(ThemeFormat::Contrast).toString();
    if (contrast == ThemeFormat::ContrastHigh) {
        out.info.contrast = ThemeContrast::High;
    } else if (!contrast.isEmpty() && contrast != ThemeFormat::ContrastStandard) {
        qWarning("ThemeParser: unknown contrast \"%s\" in theme \"%s\"; using standard",
                 qUtf8Printable(contrast), qUtf8Printable(out.info.name));
    }

    // Step 2 - color sections
    out.colors.clear();
    for (auto it = sections_.constBegin(); it != sections_.constEnd(); ++it) {
        const QString         &sectionName = it.key();
        const ThemeSectionInfo &sectionInfo = it.value();
        if (sectionInfo.required && !root.contains(sectionName)) {
            qWarning("ThemeParser: missing required section \"%s\" in theme \"%s\"",
                     qUtf8Printable(sectionName), qUtf8Printable(out.info.name));
            if (errorString)
                *errorString = tr("missing required section \"%1\"").arg(sectionName);
            return false;
        }
        parseSection(root, sectionName, sectionInfo, out.info, out);
    }

    // Step 2b - separator (single top-level ColorPair, not a section-
    // with-subkeys).  Kept outside sections_ because the JSON shape is
    // an object holding the light and dark colors rather than
    // the section-with-subkeys form parseSection() expects.  When
    // absent ThemeTokenHandler derives Separator from palette.base +
    // palette.mid.
    if (root.contains(ThemeFormat::Separator)) {
        const QJsonObject sepObj = root.value(ThemeFormat::Separator).toObject();
        if (!sepObj.isEmpty()) {
            checkColorPair(sepObj, ThemeFormat::Separator,
                           ThemeFormat::Separator, QString(), out);
            out.colors[ThemeManager::Separator] = parseColorPair(sepObj);
        }
    }

    // Step 3 - graphs
    out.graphColors.clear();
    const QJsonArray graphs = root.value(ThemeFormat::Graphs).toArray();
    for (int i = 0; i < graphs.size(); ++i) {
        const QJsonObject graphObj = graphs[i].toObject();
        checkColorPair(graphObj, ThemeFormat::graphPath(i),
                       ThemeFormat::Graphs, QString(), out);
        out.graphColors << parseColorPair(graphObj);
    }

    // Step 4 - fonts
    parseFonts(root.value(ThemeFormat::Fonts).toObject(), out);

    // Step 5 - root keys the format does not know
    for (auto it = root.constBegin(); it != root.constEnd(); ++it) {
        if (std::find(std::begin(ThemeFormat::NonSectionRootKeys),
                      std::end(ThemeFormat::NonSectionRootKeys),
                      it.key()) != std::end(ThemeFormat::NonSectionRootKeys)
            || sections_.contains(it.key()))
            continue;
        out.report.messages << withLine(jsonc_.lineOf(it.key()),
            tr("unknown section \"%1\".").arg(it.key()));
        out.report.unknownTopLevelKeys++;
    }

    return true;
}

QString ThemeParser::withLine(int line, const QString &message)
{
    return line > 0 ? tr("Line %1: %2").arg(line).arg(message) : message;
}

void ThemeParser::checkColorPair(const QJsonObject &obj,
                                 const QString     &path,
                                 const QString     &section,
                                 const QString     &key,
                                 Result            &out)
{
    static const QStringList sides = { ThemeFormat::Light, ThemeFormat::Dark };
    int present = 0;
    int validSides = 0;
    for (const QString &side : sides) {
        if (!obj.contains(side))
            continue;
        present++;
        const QJsonValue v = obj.value(side);
        if (v.isString() && QColor(v.toString()).isValid()) {
            validSides++;
            continue;
        }
        const QString text = v.isString() ? v.toString() : v.toVariant().toString();
        out.report.messages << withLine(jsonc_.lineOf(section, key),
            tr("%1.%2: \"%3\" is not a color.").arg(path, side, text));
        out.report.invalidValues++;
    }

    if (present == 1 && validSides == 1) {
        out.report.messages << withLine(jsonc_.lineOf(section, key),
            tr("%1: only one side set, the other side uses the same value.").arg(path));
    }
}

// --------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------

QColor ThemeParser::parseColor(const QString &colorStr)
{
    QColor color(colorStr);
    if (!color.isValid())
        qWarning("ThemeParser: invalid color string \"%s\"", qUtf8Printable(colorStr));
    return color;
}

ThemeColorPair ThemeParser::parseColorPair(const QJsonObject &obj)
{
    QColor light = parseColor(obj.value(ThemeFormat::Light).toString());
    QColor dark  = parseColor(obj.value(ThemeFormat::Dark).toString());

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
                               Result                                          &result)
{
    QJsonObject section  = root.value(sectionName).toObject();
    QStringList tokenList = sectionInfo.tokens;

    for (auto it = section.begin(); it != section.end(); ++it) {
        const QString key = it.key().toLower();
        if (!it.value().isObject()) {
            qWarning("ThemeParser: expected object for token \"%s%s\" in theme \"%s\"; skipping",
                     qUtf8Printable(sectionName), qUtf8Printable(it.key()),
                     qUtf8Printable(info.name));
            result.report.messages << withLine(jsonc_.lineOf(sectionName, it.key()),
                tr("%1.%2: not a color pair.").arg(sectionName, it.key()));
            result.report.invalidValues++;
            continue;
        }
        if (!tokenList.contains(key)) {
            qWarning("ThemeParser: unknown/invalid token \"%s%s\" in theme \"%s\"; skipping",
                     qUtf8Printable(sectionName), qUtf8Printable(it.key()),
                     qUtf8Printable(info.name));
            result.report.messages << withLine(jsonc_.lineOf(sectionName, it.key()),
                tr("%1.%2: unknown color, skipped.").arg(sectionName, it.key()));
            continue;
        }
        if (sectionInfo.required)
            tokenList.removeAll(key);

        const ThemeManager::ThemeToken role =
            stringToToken(QStringLiteral("%1%2").arg(sectionName, key));
        if (role != ThemeManager::NoRole) {
            const QJsonObject pairObj = it.value().toObject();
            checkColorPair(pairObj, ThemeWriter::keyPath(role),
                           sectionName, it.key(), result);
            result.colors[role] = parseColorPair(pairObj);
        }
    }

    if (sectionInfo.required && !tokenList.isEmpty()) {
        qWarning("ThemeParser: missing required token(s) \"%s\" in section \"%s\" of theme \"%s\"",
                 qUtf8Printable(tokenList.join(", ")),
                 qUtf8Printable(sectionName),
                 qUtf8Printable(info.name));
        for (const QString &missing : std::as_const(tokenList)) {
            result.report.messages << tr("%1: missing required color \"%2\".")
                                          .arg(sectionName, missing);
        }
    }
}

QString ThemeParser::fontDescriptor(const ThemeFontHint &hint)
{
    // Returns a QFont::toString() descriptor for the theme's declared font, or
    // an empty string when the theme specifies nothing.  No resolution,
    // validation, or fallback happens here — FontManager owns all of that.
    if (!hint.isSet())
        return QString();

    QFont f;
    if (!hint.family.isEmpty())
        f.setFamily(hint.family);
    if (hint.pointSize > 0)
        f.setPointSize(hint.pointSize);

    return f.toString();
}

ThemeFontHint ThemeParser::fontHint(const QJsonObject &obj)
{
    ThemeFontHint hint;
    hint.family    = obj.value(ThemeFormat::FontFamily).toString();
    const int size = obj.value(ThemeFormat::FontSize).toInt(0);
    hint.pointSize = qMax(size, 0);
    return hint;
}

void ThemeParser::parseFonts(const QJsonObject &fontsObj, Result &out)
{
    // Extract only what the theme declares.  All resolution policy — the
    // gui.font_name precedence, the fixed-pitch guarantee, and the system
    // fallback — now lives in FontManager.  An empty descriptor means the
    // theme specifies nothing for that font.
    out.regularFont       = fontHint(fontsObj.value(ThemeFormat::FontRegular).toObject());
    out.monospaceFont     = fontHint(fontsObj.value(ThemeFormat::FontMonospace).toObject());
    out.regularFontName   = fontDescriptor(out.regularFont);
    out.monospaceFontName = fontDescriptor(out.monospaceFont);
}
