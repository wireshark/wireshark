/* theme_writer.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "ui/qt/utils/themes/theme_writer.h"

#include "ui/qt/utils/themes/theme_format.h"
#include "ui/qt/utils/unique_name.h"

#include <wsutil/filesystem.h>

#include <QColor>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QSaveFile>
#include <QStringList>

#include <glib.h>

#include <utility>

namespace {

// The output is JSONC with comments, a fixed key order and an aligned layout,
// which QJsonDocument cannot produce, so only the values go through Qt.
QString quoted(const QString &text)
{
    // QJsonDocument cannot serialize a bare string, so wrap it in an array
    // and cut the brackets off again.
    const QByteArray json = QJsonDocument(QJsonArray{QJsonValue(text)}).toJson(QJsonDocument::Compact);
    return QString::fromUtf8(json.mid(1, json.size() - 2));
}

// A light/dark pair as an inline object: { light: #rrggbb, dark: #rrggbb } with both names and values quoted.
QString pairText(const ThemeColorPair &pair)
{
    return QStringLiteral("{ %1: \"%2\", %3: \"%4\" }")
        .arg(quoted(ThemeFormat::Light), ThemeWriter::colorText(pair.light),
             quoted(ThemeFormat::Dark), ThemeWriter::colorText(pair.dark));
}

// Lines `"key": value` with the values aligned after the longest key; minWidth
// widens the key column beyond the keys given.
QStringList alignedLines(const QList<std::pair<QString, QString>> &rows, int minWidth = 0)
{
    int longest = minWidth;
    for (const auto &row : rows)
        longest = qMax(longest, int(row.first.size()));
    QStringList lines;
    for (const auto &row : rows) {
        lines << QStringLiteral("%1:%2 %3")
                     .arg(quoted(row.first), QString(longest - int(row.first.size()), QLatin1Char(' ')),
                          row.second);
    }
    return lines;
}

// A `"name": { ... }` block whose lines are already formatted and padded.
QString objectBlock(const QString &name, const QStringList &lines)
{
    return QStringLiteral("\t%1: {\n\t\t%2\n\t}").arg(quoted(name), lines.join(QStringLiteral(",\n\t\t")));
}

QString fontText(const ThemeFontHint &hint)
{
    QStringList parts;
    if (!hint.family.isEmpty())
        parts << QStringLiteral("%1: %2").arg(quoted(ThemeFormat::FontFamily), quoted(hint.family));
    if (hint.pointSize >= 1)
        parts << QStringLiteral("%1: %2").arg(quoted(ThemeFormat::FontSize)).arg(hint.pointSize);
    return QStringLiteral("{ %1 }").arg(parts.join(QStringLiteral(", ")));
}

// The keyTable() row of a token, or nullptr for a token that is not settable.
const ThemeWriter::KeyInfo *findKey(ThemeManager::ThemeToken token)
{
    for (const ThemeWriter::KeyInfo &info : ThemeWriter::keyTable()) {
        if (info.token == token)
            return &info;
    }
    return nullptr;
}

// What each settable color is used for, shown by the Theme Designer.  The
// section and key of a token come from ThemeManager::settableKeys().
// test/suite_theme.py checks that this lists every settable token once;
// keep one entry per line in exactly this shape.
const struct { ThemeManager::ThemeToken token; const char *text; } kDescriptions[] = {
    { ThemeManager::BrandPrimary, QT_TRANSLATE_NOOP("ThemeWriter", "Main brand hue: section header hover, link fallback, last selection fallback.") },
    { ThemeManager::AccentSuccess, QT_TRANSLATE_NOOP("ThemeWriter", "Update bar, valid filter tint fallback, capture bookmark glyph.") },
    { ThemeManager::AccentWarning, QT_TRANSLATE_NOOP("ThemeWriter", "Development Build badge, deprecated filter tint fallback.") },
    { ThemeManager::AccentError, QT_TRANSLATE_NOOP("ThemeWriter", "Invalid filter tint fallback, clear glyph, client stream text fallback.") },
    { ThemeManager::AccentInfo, QT_TRANSLATE_NOOP("ThemeWriter", "Bookmark and apply glyphs, expert chat and note fallback.") },
    { ThemeManager::ExpertNone, QT_TRANSLATE_NOOP("ThemeWriter", "Expert item background without severity.") },
    { ThemeManager::ExpertComment, QT_TRANSLATE_NOOP("ThemeWriter", "Expert comment background.") },
    { ThemeManager::ExpertChat, QT_TRANSLATE_NOOP("ThemeWriter", "Expert chat background.") },
    { ThemeManager::ExpertNote, QT_TRANSLATE_NOOP("ThemeWriter", "Expert note background.") },
    { ThemeManager::ExpertWarn, QT_TRANSLATE_NOOP("ThemeWriter", "Expert warning background.") },
    { ThemeManager::ExpertError, QT_TRANSLATE_NOOP("ThemeWriter", "Expert error background.") },
    { ThemeManager::ExpertForeground, QT_TRANSLATE_NOOP("ThemeWriter", "Text on expert backgrounds.") },
    { ThemeManager::PacketsSelection, QT_TRANSLATE_NOOP("ThemeWriter", "Selected packet row background; selection in other lists when palette.highlight is not set.") },
    { ThemeManager::PacketsSelectionText, QT_TRANSLATE_NOOP("ThemeWriter", "Selected packet row text.") },
    { ThemeManager::PacketsInactive, QT_TRANSLATE_NOOP("ThemeWriter", "Selection background when the view has no focus.") },
    { ThemeManager::PacketsInactiveText, QT_TRANSLATE_NOOP("ThemeWriter", "Inactive selection text.") },
    { ThemeManager::PacketsMarked, QT_TRANSLATE_NOOP("ThemeWriter", "Marked packet background.") },
    { ThemeManager::PacketsMarkedText, QT_TRANSLATE_NOOP("ThemeWriter", "Marked packet text.") },
    { ThemeManager::PacketsIgnored, QT_TRANSLATE_NOOP("ThemeWriter", "Ignored packet background. Auto: the normal row background.") },
    { ThemeManager::PacketsIgnoredText, QT_TRANSLATE_NOOP("ThemeWriter", "Ignored packet text.") },
    { ThemeManager::PacketsHidden, QT_TRANSLATE_NOOP("ThemeWriter", "Dimmed text for hidden items.") },
    { ThemeManager::FilterValid, QT_TRANSLATE_NOOP("ThemeWriter", "Display filter background, valid expression.") },
    { ThemeManager::FilterInvalid, QT_TRANSLATE_NOOP("ThemeWriter", "Display filter background, invalid expression.") },
    { ThemeManager::FilterDeprecated, QT_TRANSLATE_NOOP("ThemeWriter", "Display filter background, deprecated syntax.") },
    { ThemeManager::FilterBusy, QT_TRANSLATE_NOOP("ThemeWriter", "Capture filter background while compiling.") },
    { ThemeManager::FilterBusyText, QT_TRANSLATE_NOOP("ThemeWriter", "Capture filter text while compiling.") },
    { ThemeManager::FilterBookmark, QT_TRANSLATE_NOOP("ThemeWriter", "Bookmark glyph in the display filter.") },
    { ThemeManager::FilterBookmarkCapture, QT_TRANSLATE_NOOP("ThemeWriter", "Bookmark glyph in the capture filter.") },
    { ThemeManager::FilterBookmarkMatch, QT_TRANSLATE_NOOP("ThemeWriter", "Bookmark glyph when the filter matches a saved one.") },
    { ThemeManager::FilterClear, QT_TRANSLATE_NOOP("ThemeWriter", "Clear glyph.") },
    { ThemeManager::FilterApply, QT_TRANSLATE_NOOP("ThemeWriter", "Apply glyph.") },
    { ThemeManager::FilterHistory, QT_TRANSLATE_NOOP("ThemeWriter", "Recent filters arrow at rest.") },
    { ThemeManager::ConversationClient, QT_TRANSLATE_NOOP("ThemeWriter", "Follow Stream client background.") },
    { ThemeManager::ConversationClientText, QT_TRANSLATE_NOOP("ThemeWriter", "Follow Stream client text.") },
    { ThemeManager::ConversationServer, QT_TRANSLATE_NOOP("ThemeWriter", "Follow Stream server background.") },
    { ThemeManager::ConversationServerText, QT_TRANSLATE_NOOP("ThemeWriter", "Follow Stream server text.") },
    { ThemeManager::PaletteWindow, QT_TRANSLATE_NOOP("ThemeWriter", "Window background (QPalette::Window).") },
    { ThemeManager::PaletteBase, QT_TRANSLATE_NOOP("ThemeWriter", "View background (lists, editors).") },
    { ThemeManager::PaletteText, QT_TRANSLATE_NOOP("ThemeWriter", "View text.") },
    { ThemeManager::PaletteWindowText, QT_TRANSLATE_NOOP("ThemeWriter", "Window text.") },
    { ThemeManager::PaletteAlternateBase, QT_TRANSLATE_NOOP("ThemeWriter", "Alternate rows in lists and tables.") },
    { ThemeManager::PaletteMid, QT_TRANSLATE_NOOP("ThemeWriter", "Mid gray: borders, section headers, separators.") },
    { ThemeManager::PaletteMidlight, QT_TRANSLATE_NOOP("ThemeWriter", "Light bevel shade (QPalette::Midlight).") },
    { ThemeManager::PaletteHighlight, QT_TRANSLATE_NOOP("ThemeWriter", "Selection in all lists except the packet list; the welcome header and hover fills derive from it. Auto: packets.selection, else brand.primary.") },
    { ThemeManager::PaletteHighlightedText, QT_TRANSLATE_NOOP("ThemeWriter", "Text on highlight, kept readable on it.") },
#if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
    { ThemeManager::PaletteAccent, QT_TRANSLATE_NOOP("ThemeWriter", "QPalette::Accent (Qt 6.6 and later). Auto: brand.primary.") },
#endif
};

} // namespace

const QList<ThemeWriter::KeyInfo> &ThemeWriter::keyTable()
{
    static const QList<KeyInfo> table = [] {
        QList<KeyInfo> rows;
        for (const ThemeManager::SettableKey &k : ThemeManager::instance()->settableKeys()) {
            const char *description = "";
            for (const auto &d : kDescriptions) {
                if (d.token == k.token) {
                    description = d.text;
                    break;
                }
            }
            Q_ASSERT_X(*description, "ThemeWriter::keyTable", "settable token without a description");
            rows << KeyInfo { k.token, k.section, k.key, description };
        }
        return rows;
    }();
    return table;
}

QString ThemeWriter::keyPath(ThemeManager::ThemeToken token)
{
    const KeyInfo *info = findKey(token);
    return info ? keyPath(*info) : QString();
}

QString ThemeWriter::keyPath(const KeyInfo &info)
{
    return QStringLiteral("%1.%2").arg(info.section, info.key);
}

QString ThemeWriter::colorText(const QColor &color)
{
    if (!color.isValid())
        return QString();
    return color.alpha() == 255 ? color.name(QColor::HexRgb) : color.name(QColor::HexArgb);
}

QByteArray ThemeWriter::toJsonc(const ThemeDraft &draft)
{
    QStringList blocks;

    // meta
    QStringList metaLines;
    metaLines << QStringLiteral("%1: %2").arg(quoted(ThemeFormat::MetaName), quoted(draft.info.name));
    metaLines << QStringLiteral("%1: 1").arg(quoted(ThemeFormat::MetaVersion));
    if (!draft.info.author.isEmpty())
        metaLines << QStringLiteral("%1: %2").arg(quoted(ThemeFormat::MetaAuthor), quoted(draft.info.author));
    if (!draft.info.description.isEmpty())
        metaLines << QStringLiteral("%1: %2").arg(quoted(ThemeFormat::MetaDescription), quoted(draft.info.description));
    blocks << objectBlock(ThemeFormat::Meta, metaLines);

    // Standard is the default and is not written.
    if (draft.info.contrast == ThemeContrast::High)
        blocks << QStringLiteral("\t%1: %2").arg(quoted(ThemeFormat::Contrast), quoted(ThemeFormat::ContrastHigh));

    // Group the table rows that the draft sets, per section.
    QHash<QString, QList<const KeyInfo *>> bySection;
    for (const KeyInfo &info : keyTable()) {
        auto it = draft.colors.constFind(info.token);
        if (it == draft.colors.constEnd())
            continue;
        if (!it.value().isValid()) {
            Q_ASSERT_X(false, "ThemeWriter::toJsonc", "invalid color in draft");
            continue;
        }
        bySection[info.section] << &info;
    }

    auto sectionBlock = [&](const QString &section) {
        const QList<const KeyInfo *> rows = bySection.value(section);
        if (rows.isEmpty())
            return QString();
        QList<std::pair<QString, QString>> lines;
        for (const KeyInfo *row : rows)
            lines.append({ row->key, pairText(draft.colors.value(row->token)) });
        return objectBlock(section, alignedLines(lines));
    };

    // Sections in the order of their first row in keyTable(), which is the
    // file order.
    QStringList order;
    for (const KeyInfo &info : keyTable()) {
        if (!order.contains(info.section))
            order << info.section;
    }

    // Fonts are not colors; they go right before the section of the palette
    // colors.
    const KeyInfo *palette_row = findKey(ThemeManager::PaletteWindow);
    const QString fonts_before = palette_row ? palette_row->section : QString();

    QString fonts;
    {
        const std::pair<QLatin1String, const ThemeFontHint *> font_rows[] = {
            { ThemeFormat::FontRegular,   &draft.regularFont },
            { ThemeFormat::FontMonospace, &draft.monospaceFont },
        };
        // Aligned over both keys, set or not, so the layout does not
        // depend on which fonts a theme sets.
        QList<std::pair<QString, QString>> lines;
        int keyWidth = 0;
        for (const auto &row : font_rows) {
            keyWidth = qMax(keyWidth, int(row.first.size()));
            if (row.second->isSet())
                lines.append({ row.first, fontText(*row.second) });
        }
        if (!lines.isEmpty())
            fonts = objectBlock(ThemeFormat::Fonts,
                                alignedLines(lines, keyWidth));
    }

    for (const QString &section : std::as_const(order)) {
        if (!fonts.isEmpty() && section == fonts_before) {
            blocks << fonts;
            fonts.clear();
        }
        const QString block = sectionBlock(section);
        if (!block.isEmpty())
            blocks << block;
    }
    if (!fonts.isEmpty())
        blocks << fonts;

    // separator: a single pair, not a section
    auto sep = draft.colors.constFind(ThemeManager::Separator);
    if (sep != draft.colors.constEnd()) {
        if (sep.value().isValid())
            blocks << QStringLiteral("\t%1: %2").arg(quoted(ThemeFormat::Separator), pairText(sep.value()));
        else
            Q_ASSERT_X(false, "ThemeWriter::toJsonc", "invalid separator in draft");
    }

    // graphs
    QStringList graphLines;
    for (const ThemeColorPair &pair : draft.graphColors) {
        if (!pair.isValid()) {
            Q_ASSERT_X(false, "ThemeWriter::toJsonc", "invalid graph color in draft");
            continue;
        }
        graphLines << pairText(pair);
    }
    if (!graphLines.isEmpty()) {
        blocks << QStringLiteral("\t%1: [\n\t\t%2\n\t]")
                      .arg(quoted(ThemeFormat::Graphs), graphLines.join(QStringLiteral(",\n\t\t")));
    }

    // The name goes into a line comment, so it must not contain a line break.
    QString commentName = draft.info.name;
    commentName.replace(QLatin1Char('\n'), QLatin1Char(' ')).replace(QLatin1Char('\r'), QLatin1Char(' '));

    const QString text =
        QStringLiteral("// %1\n"
                       "// Theme file for Wireshark and Stratoshark. Edit with View > Internals > Theme Designer.\n"
                       "{\n%2\n}\n")
            .arg(commentName, blocks.join(QStringLiteral(",\n")));
    return text.toUtf8();
}

QString ThemeWriter::sanitizeStem(const QString &name)
{
    // The platform rule for file names has one owner in wsutil; the stem
    // policy on top keeps lowercase ASCII letters, digits, '-' and '_'.
    char *safe = filename_sanitize(name.toUtf8().constData(), '-');
    const QString platform_safe = QString::fromUtf8(safe);
    g_free(safe);

    QString stem;
    for (const QChar ch : platform_safe.toLower()) {
        const bool keep = (ch >= QLatin1Char('a') && ch <= QLatin1Char('z'))
                          || (ch >= QLatin1Char('0') && ch <= QLatin1Char('9'))
                          || ch == QLatin1Char('-') || ch == QLatin1Char('_');
        const QChar out = keep ? ch : QLatin1Char('-');
        // Collapse runs of '-' that came from replaced characters.
        if (out == QLatin1Char('-') && stem.endsWith(QLatin1Char('-')))
            continue;
        stem += out;
    }

    auto trimmable = [](QChar ch) {
        return ch == QLatin1Char('-') || ch == QLatin1Char('_') || ch == QLatin1Char('.');
    };
    while (!stem.isEmpty() && trimmable(stem.front()))
        stem.remove(0, 1);
    while (!stem.isEmpty() && trimmable(stem.back()))
        stem.chop(1);

    if (stem.size() > 64) {
        stem.truncate(64);
        while (!stem.isEmpty() && trimmable(stem.back()))
            stem.chop(1);
    }
    return stem.isEmpty() ? QStringLiteral("theme") : stem;
}

QString ThemeWriter::uniqueStem(const QString &wanted, const QString &ignoreStem)
{
    const QString base = sanitizeStem(wanted);
    return uniqueName(
        [&base](int n) { return n == 0 ? base : QStringLiteral("%1-%2").arg(base).arg(n + 1); },
        [&ignoreStem](const QString &stem) {
            if (!ignoreStem.isEmpty() && stem == ignoreStem)
                return false;
            return ThemeManager::isBuiltInTheme(stem)
                   || QFileInfo::exists(ThemeManager::personalThemePath(stem));
        });
}

bool ThemeWriter::writeFile(const ThemeDraft &draft, const QString &path, QString *errorString)
{
    const QFileInfo info(path);
    if (!QDir().mkpath(info.absolutePath())) {
        if (errorString)
            *errorString = tr("Could not create \"%1\".").arg(info.absolutePath());
        return false;
    }

    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        if (errorString)
            *errorString = file.errorString();
        return false;
    }
    file.write(toJsonc(draft));
    if (!file.commit()) {
        if (errorString)
            *errorString = file.errorString();
        return false;
    }
    return true;
}
