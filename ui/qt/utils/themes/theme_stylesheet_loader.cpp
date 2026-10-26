/* theme_stylesheet_loader.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "ui/qt/utils/themes/theme_stylesheet_loader.h"

#include <QColor>
#include <QFile>
#include <QIODevice>
#include <QMetaEnum>
#include <QRegularExpression>
#include <QSet>

namespace {

// Names of the palette roles in Qt's style sheet grammar, derived from the
// QPalette::ColorRole enumerators (AlternateBase -> alternate-base).
const QHash<QString, QPalette::ColorRole> &paletteRoleNames()
{
    static const QHash<QString, QPalette::ColorRole> names = [] {
        QHash<QString, QPalette::ColorRole> hash;
        const QMetaEnum roles = QMetaEnum::fromType<QPalette::ColorRole>();
        for (int i = 0; i < roles.keyCount(); ++i) {
            const int value = roles.value(i);
            if (value == QPalette::NoRole || value == QPalette::NColorRoles)
                continue;
            const QString key = QString::fromLatin1(roles.key(i));
            QString name;
            for (qsizetype j = 0; j < key.size(); ++j) {
                if (j > 0 && key.at(j).isUpper())
                    name += QLatin1Char('-');
                name += key.at(j).toLower();
            }
            // Qt's grammar spells the tool tip roles tooltip-base and tooltip-text
            name.replace(QStringLiteral("tool-tip-"), QStringLiteral("tooltip-"));
            hash.insert(name, static_cast<QPalette::ColorRole>(value));
        }
        return hash;
    }();
    return names;
}

} // namespace

QString ThemeStyleSheetLoader::load(const QString  &name,
                                    const TokenMap &tokens,
                                    bool            isDarkMode)
{
    // Stylesheets are always looked up under the built-in resource
    // prefix :/stylesheets/.  The caller passes a logical name such
    // as "widgets/learn-card" (no extension, no leading slash).
    // The name is sanitized to prevent escaping the stylesheet root
    // via "../" or absolute paths, and the function fails silently
    // if the resulting resource cannot be opened.
    static const QRegularExpression validNameRe(
        QStringLiteral("^[A-Za-z0-9_][A-Za-z0-9_./-]*$"));

    if (name.isEmpty() || !validNameRe.match(name).hasMatch())
        return QString();

    if (name.contains(QStringLiteral(".."))
        || name.contains(QLatin1Char('\\'))
        || name.startsWith(QLatin1Char('/'))
        || name.startsWith(QLatin1Char('.')))
        return QString();

    const QString resourcePath = QStringLiteral(":/stylesheets/") + name
                               + QStringLiteral(".qss");

    QFile f(resourcePath);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return QString();

    QString qss = QString::fromUtf8(f.readAll());

    // Replace all wstheme(RoleName) references with resolved color
    // values.  RoleName must match a ThemeToken enum identifier
    // exactly (case-sensitive), e.g. wstheme(HeaderBackground).
    static const QRegularExpression tokenRe(
        QStringLiteral("wstheme\\(\\s*([A-Za-z][A-Za-z0-9]*)\\s*\\)"));

    qsizetype offset = 0;
    QRegularExpressionMatch match;
    while ((match = tokenRe.match(qss, offset)).hasMatch()) {
        const QString token = match.captured(1);
        const ThemeManager::ThemeToken role = ThemeManager::tokenFromName(token);
        QColor value;
        if (role != ThemeManager::NoRole)
            value = tokens.value(role, ThemeColorPair()).forMode(isDarkMode);
        if (value.isValid()) {
            qss.replace(match.capturedStart(), match.capturedLength(), value.name());
            offset = match.capturedStart() + value.name().length();
        } else {
            // Unknown or unresolved role — strip it from the output
            // and warn.  Qt's QSS parser is all-or-nothing per
            // object, so leaving a literal "wstheme(Foo)" in place
            // would silently drop the entire rule on a single typo.
            // Stripping keeps the rest of the rules valid; the
            // warning surfaces the typo.
            qWarning("ThemeStyleSheetLoader: unknown/unresolved role \"wstheme(%s)\" in stylesheet \"%s\"; stripping",
                     qUtf8Printable(token), qUtf8Printable(name));
            qss.remove(match.capturedStart(), match.capturedLength());
            offset = match.capturedStart();
        }
    }

    return qss;
}

QString ThemeStyleSheetLoader::resolvePaletteRoles(const QString &sheet, const QPalette &palette)
{
    static const QRegularExpression re(QStringLiteral("palette\\(\\s*([A-Za-z-]+)\\s*\\)"),
                                       QRegularExpression::CaseInsensitiveOption);
    const QHash<QString, QPalette::ColorRole> &roles = paletteRoleNames();
    QString out;
    qsizetype last = 0;
    QRegularExpressionMatchIterator it = re.globalMatch(sheet);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        const QString name = m.captured(1).toLower();
        QString replacement = m.captured(0);
        const auto role = roles.constFind(name);
        if (role != roles.constEnd()) {
            replacement = palette.color(QPalette::Active, role.value()).name();
        } else {
            // An unknown name comes from a shipped sheet, not from the colors
            // being previewed, so report it once instead of on every update.
            static QSet<QString> warned;
            if (!warned.contains(name)) {
                warned.insert(name);
                qWarning("ThemeStyleSheetLoader: unknown palette role \"palette(%s)\"; left as written",
                         qUtf8Printable(name));
            }
        }
        out += sheet.mid(last, m.capturedStart() - last) + replacement;
        last = m.capturedEnd();
    }
    out += sheet.mid(last);
    return out;
}
