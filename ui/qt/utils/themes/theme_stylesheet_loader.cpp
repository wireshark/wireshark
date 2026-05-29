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

    // Replace the `%wsmode%` placeholder with the current effective
    // mode as a plain string — "dark" or "light".  Intended for QSS
    // that needs to pick a mode-specific asset by filename (e.g.
    //   image: url(:/stock_icons/14x14/x-filter-dropdown.%wsmode%.png);
    // ).  Placeholder takes no arguments; it's a simple textual
    // substitution done before the wstheme(...) regex so the
    // resolver's grammar stays purely color-typed.
    qss.replace(QStringLiteral("%wsmode%"),
                isDarkMode ? QStringLiteral("dark") : QStringLiteral("light"));

    // Replace all wstheme(RoleName) references with resolved color
    // values.  RoleName must match a ThemeToken enum identifier
    // exactly (case-sensitive), e.g. wstheme(HeaderGradientStart).
    static const QRegularExpression tokenRe(
        QStringLiteral("wstheme\\(\\s*([A-Za-z][A-Za-z0-9]*)\\s*\\)"));

    static const QMetaEnum roleEnum =
        QMetaEnum::fromType<ThemeManager::ThemeToken>();

    qsizetype offset = 0;
    QRegularExpressionMatch match;
    while ((match = tokenRe.match(qss, offset)).hasMatch()) {
        const QString token = match.captured(1);
        bool ok = false;
        const int roleInt = roleEnum.keyToValue(token.toUtf8().constData(), &ok);
        QColor value;
        if (ok && roleInt != ThemeManager::NoRole) {
            const ThemeColorPair pair = tokens.value(
                static_cast<ThemeManager::ThemeToken>(roleInt), ThemeColorPair());
            value = isDarkMode ? pair.dark : pair.light;
        }
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
