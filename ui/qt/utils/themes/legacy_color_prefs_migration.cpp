/* legacy_color_prefs_migration.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "ui/qt/utils/themes/legacy_color_prefs_migration.h"

#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/workspace_state.h>

#include <app/application_flavor.h>
#include <epan/prefs.h>
#include <ui/recent.h>
#include <wsutil/filesystem.h>

#include <glib.h>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QTextStream>

namespace {

// Every entry maps an old preference key to its replacement theme token
// plus the pre-removal hardcoded default (as written by the prefs
// serializer: lowercase 6-digit hex, no leading "#").  Migration only
// fires for keys whose current value differs from this default.
struct LegacyKey {
    const char *prefKey;
    const char *jsoncSection;
    const char *jsoncToken;
    const char *oldDefaultHex;
};

// The 12 mappable keys.  gui.color_filter_* and gui.*_frame.style have no
// direct theme equivalent and are deliberately omitted from this table;
// they are still listed in kKeysToStrip below so that stale uncommented
// entries do not keep producing "No such preference" warnings.
constexpr LegacyKey kLegacyKeys[] = {
    { "gui.active_frame.fg",   "packets",      "selectionText", "000000" },
    { "gui.active_frame.bg",   "packets",      "selection",     "cbe8ff" },
    { "gui.inactive_frame.fg", "packets",      "inactiveText",  "000000" },
    { "gui.inactive_frame.bg", "packets",      "inactive",      "efefef" },
    { "gui.marked_frame.fg",   "packets",      "markedText",    "ffffff" },
    { "gui.marked_frame.bg",   "packets",      "marked",        "00202a" },
    { "gui.ignored_frame.fg",  "packets",      "ignoredText",   "7f7f7f" },
    { "gui.ignored_frame.bg",  "packets",      "ignored",       "ffffff" },
    { "gui.stream.client.fg",  "conversation", "clientText",    "7f0000" },
    { "gui.stream.client.bg",  "conversation", "client",        "fbeded" },
    { "gui.stream.server.fg",  "conversation", "serverText",    "00007f" },
    { "gui.stream.server.bg",  "conversation", "server",        "ededfb" },
};

// All unregistered legacy color-related keys.  Uncommented occurrences in
// the prefs file are removed after migration: keeps the trigger condition
// false on the next launch AND silences the unknown-pref warnings that
// would otherwise fire for every entry on every startup.
const char *kKeysToStrip[] = {
    "gui.active_frame.fg",
    "gui.active_frame.bg",
    "gui.active_frame.style",
    "gui.inactive_frame.fg",
    "gui.inactive_frame.bg",
    "gui.inactive_frame.style",
    "gui.marked_frame.fg",
    "gui.marked_frame.bg",
    "gui.ignored_frame.fg",
    "gui.ignored_frame.bg",
    "gui.stream.client.fg",
    "gui.stream.client.bg",
    "gui.stream.server.fg",
    "gui.stream.server.bg",
    "gui.color_filter_fg.valid",
    "gui.color_filter_bg.valid",
    "gui.color_filter_fg.invalid",
    "gui.color_filter_bg.invalid",
    "gui.color_filter_fg.deprecated",
    "gui.color_filter_bg.deprecated",
};

QString defaultProfilePrefsPath()
{
    const char *envPrefix = application_configuration_environment_prefix();
    // from_profile=false -> Default profile location (personal config
    // root directly, not under profiles/<name>/).
    char *raw = get_persconffile_path("preferences", false, envPrefix);
    QString path = QString::fromUtf8(raw);
    g_free(raw);
    return path;
}

bool personalThemesDirIsEmpty(const QString &dir)
{
    QDir d(dir);
    if (!d.exists())
        return true;
    const QStringList themes = d.entryList(
        QStringList() << QStringLiteral("*.jsonc"),
        QDir::Files | QDir::Readable);
    return themes.isEmpty();
}

// Parses the prefs file, returning legacy key -> hex value for entries
// that are (a) uncommented and (b) different from the pre-removal default.
// Matching values are skipped because they would produce a personal theme
// that is byte-identical to the bundled default — pointless churn.
QHash<QString, QString> readUserCustomizations(const QString &prefsPath)
{
    QHash<QString, QString> result;
    QFile f(prefsPath);
    if (!f.exists() || !f.open(QIODevice::ReadOnly | QIODevice::Text))
        return result;

    QHash<QString, QString> defaults;
    for (const auto &k : kLegacyKeys) {
        defaults.insert(QString::fromLatin1(k.prefKey),
                        QString::fromLatin1(k.oldDefaultHex));
    }

    QTextStream in(&f);
    while (!in.atEnd()) {
        const QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith('#'))
            continue;
        const qsizetype colon = line.indexOf(':');
        if (colon <= 0)
            continue;
        const QString key = line.left(colon).trimmed();
        if (!defaults.contains(key))
            continue;
        QString value = line.mid(colon + 1).trimmed().toLower();
        if (value.startsWith('#'))
            value = value.mid(1);
        if (value.length() != 6)
            continue;
        bool ok = false;
        value.toUInt(&ok, 16);
        if (!ok)
            continue;
        if (value == defaults.value(key))
            continue;
        result.insert(key, value);
    }
    return result;
}

// Returns the most descriptive name available for the user running
// Wireshark.  Prefers the full name from the OS (GECOS on Unix, the
// user database on Windows) and falls back to the login name when
// glib reports "Unknown" — typically a freshly created account or a
// container with no real-name field configured.
QString currentUserDisplayName()
{
    const QString real = QString::fromUtf8(g_get_real_name());
    if (!real.isEmpty() && real != QStringLiteral("Unknown"))
        return real;
    return QString::fromUtf8(g_get_user_name());
}

// Escapes the few characters JSON strings cannot carry as-is.  Names
// flow in from the OS so we cannot assume they are well-formed JSON
// payloads; without this, a real name containing a double quote or a
// backslash would produce an invalid file.
QString jsonStringEscape(const QString &raw)
{
    QString out;
    out.reserve(raw.size());
    for (QChar c : raw) {
        switch (c.unicode()) {
        case '\\': out += QStringLiteral("\\\\"); break;
        case '"':  out += QStringLiteral("\\\""); break;
        case '\b': out += QStringLiteral("\\b");  break;
        case '\f': out += QStringLiteral("\\f");  break;
        case '\n': out += QStringLiteral("\\n");  break;
        case '\r': out += QStringLiteral("\\r");  break;
        case '\t': out += QStringLiteral("\\t");  break;
        default:   out += c; break;
        }
    }
    return out;
}

QString buildJsonc(const QHash<QString, QString> &customizations)
{
    // Group the migrated values by JSONC section.  Each section becomes
    // a JSONC object containing only the tokens that were customized;
    // unset tokens fall back to the bundled default theme.
    QHash<QString, QHash<QString, QString>> bySection;
    for (const auto &k : kLegacyKeys) {
        const QString key = QString::fromLatin1(k.prefKey);
        if (!customizations.contains(key))
            continue;
        bySection[QString::fromLatin1(k.jsoncSection)]
            .insert(QString::fromLatin1(k.jsoncToken),
                    customizations.value(key));
    }

    const QString author = jsonStringEscape(currentUserDisplayName());

    QString out;
    out += QStringLiteral(
        "// =====================================================================\n"
        "// Wireshark Personal Theme — migrated from legacy color preferences\n"
        "// =====================================================================\n"
        "//\n"
        "// This file was generated automatically the first time Wireshark ran\n"
        "// after the per-color preferences (gui.active_frame.*, gui.marked_frame.*,\n"
        "// gui.stream.*, ...) were removed and replaced by the theme system.\n"
        "//\n"
        "// The values below were copied from the Default profile's preferences\n"
        "// file and preserve the visual customizations that would otherwise have\n"
        "// been lost.  The legacy preference keys have been removed from that\n"
        "// preferences file so this migration only runs once.\n"
        "//\n"
        "// Each migrated color is written to both the light and dark sides\n"
        "// of its token.  The original prefs only stored a single value, so\n"
        "// the customization is preserved regardless of which appearance\n"
        "// mode is active.  Any tokens not overridden here fall back to the\n"
        "// bundled default theme.\n"
        "//\n"
        "// Feel free to edit, rename, or delete this file.\n"
        "// =====================================================================\n\n");

    out += QStringLiteral("{\n");
    out += QStringLiteral("\t\"meta\": {\n");
    out += QStringLiteral("\t\t\"name\": \"Personal (Migrated)\",\n");
    out += QStringLiteral("\t\t\"version\": 1,\n");
    out += QStringLiteral("\t\t\"author\": \"%1\",\n").arg(author);
    out += QStringLiteral("\t\t\"description\": \"Personal theme generated from the legacy color preferences (active/inactive/marked/ignored frame colors and follow-stream client/server colors) that lived in the Default profile before the theme system landed.\"\n");
    out += QStringLiteral("\t},\n\n");

    // brand and accent are required by the schema (see
    // resources/themes/theme.schema.json) and by ThemeParser
    // ("missing required section ...").  The legacy color prefs only
    // covered packets/conversation tokens, so we ship the bundled
    // default-theme values verbatim here.  Hardcoded rather than read
    // from the default theme at runtime because (a) the migration is a
    // one-shot operation and (b) keeping the emitted JSONC fully
    // self-contained means a user who later tweaks personal.jsonc by
    // hand sees the exact baseline they are starting from.  If the
    // bundled defaults shift in a future release, the migrated theme
    // intentionally stays pinned to the values at migration time so
    // the user's visual state does not drift under them.
    out += QStringLiteral(
        "\t\"brand\": {\n"
        "\t\t\"primary\": { \"light\": \"#2c6fb5\", \"dark\": \"#5b9ee6\" },\n"
        "\t\t\"deep\":    { \"light\": \"#1e3a5f\", \"dark\": \"#0f1b30\" }\n"
        "\t},\n\n"
        "\t\"accent\": {\n"
        "\t\t\"success\": { \"light\": \"#4caf50\", \"dark\": \"#4caf50\" },\n"
        "\t\t\"warning\": { \"light\": \"#e8652d\", \"dark\": \"#e8652d\" },\n"
        "\t\t\"error\":   { \"light\": \"#cc0000\", \"dark\": \"#ef2929\" },\n"
        "\t\t\"info\":    { \"light\": \"#3465a4\", \"dark\": \"#729fcf\" }\n"
        "\t}");

    // Each token receives the migrated hex on BOTH light and dark sides.
    // ThemeParser warns ("invalid color string", "only one color token
    // defined") when a pair is incomplete — even though it then falls
    // back to the defined side for both modes.  Mirroring the value here
    // produces a quieter load and matches the original semantics: the
    // legacy prefs stored a single value, so the user's customization
    // should persist regardless of the active appearance mode.
    auto emitSection = [&](const QString &section,
                           const QStringList &orderedTokens) {
        if (!bySection.contains(section))
            return;
        const auto &tokens = bySection.value(section);
        QStringList lines;
        for (const QString &tok : orderedTokens) {
            if (!tokens.contains(tok))
                continue;
            const QString hex = tokens.value(tok);
            lines << QStringLiteral("\t\t\"%1\": { \"light\": \"#%2\", \"dark\": \"#%2\" }")
                          .arg(tok, hex);
        }
        if (lines.isEmpty())
            return;
        out += QStringLiteral(",\n\n\t\"%1\": {\n").arg(section);
        out += lines.join(QStringLiteral(",\n"));
        out += QStringLiteral("\n\t}");
    };

    // Preserve the visual order from resources/themes/default/theme.jsonc
    // so the migrated file reads similarly to the reference theme.
    emitSection(QStringLiteral("packets"), {
        QStringLiteral("selection"),     QStringLiteral("selectionText"),
        QStringLiteral("inactive"),      QStringLiteral("inactiveText"),
        QStringLiteral("marked"),        QStringLiteral("markedText"),
        QStringLiteral("ignored"),       QStringLiteral("ignoredText"),
    });
    emitSection(QStringLiteral("conversation"), {
        QStringLiteral("client"),     QStringLiteral("clientText"),
        QStringLiteral("server"),     QStringLiteral("serverText"),
    });

    out += QStringLiteral("\n}\n");
    return out;
}

// Removes uncommented kKeysToStrip entries from the prefs file.  Commented
// (#-prefixed) entries are left as-is because they are not processed by
// prefs.c and cause no warnings; the next time prefs are saved through the
// normal channels the serializer will drop them naturally since none of
// these keys are registered any more.
bool stripLegacyKeysFromPrefs(const QString &prefsPath)
{
    QFile in(prefsPath);
    if (!in.exists() || !in.open(QIODevice::ReadOnly | QIODevice::Text))
        return false;

    QSet<QString> keys;
    for (const char *k : kKeysToStrip)
        keys.insert(QString::fromLatin1(k));

    QStringList outLines;
    bool changed = false;
    QTextStream stream(&in);
    while (!stream.atEnd()) {
        const QString raw = stream.readLine();
        const QString trimmed = raw.trimmed();
        bool drop = false;
        if (!trimmed.isEmpty() && !trimmed.startsWith('#')) {
            const qsizetype colon = trimmed.indexOf(':');
            if (colon > 0
                && keys.contains(trimmed.left(colon).trimmed())) {
                drop = true;
                changed = true;
            }
        }
        if (!drop)
            outLines << raw;
    }
    in.close();

    if (!changed)
        return false;

    QFile out(prefsPath);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
        return false;
    QTextStream w(&out);
    for (const QString &line : outLines)
        w << line << '\n';
    return true;
}

} // namespace

namespace LegacyColorPrefsMigration {

bool runIfNeeded()
{
    const QString themesDir = WorkspaceState::instance()->personalThemesPath();
    if (themesDir.isEmpty())
        return false;
    if (!personalThemesDirIsEmpty(themesDir))
        return false;

    const QString prefsPath = defaultProfilePrefsPath();
    const QHash<QString, QString> customizations = readUserCustomizations(prefsPath);
    if (customizations.isEmpty())
        return false;

    if (!QDir().mkpath(themesDir)) {
        qWarning("LegacyColorPrefsMigration: failed to create themes directory %s",
                 qUtf8Printable(themesDir));
        return false;
    }

    const QString outPath = QDir(themesDir).filePath(QStringLiteral("personal.jsonc"));
    QFile out(outPath);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        qWarning("LegacyColorPrefsMigration: failed to write %s",
                 qUtf8Printable(outPath));
        return false;
    }
    {
        QTextStream w(&out);
        w << buildJsonc(customizations);
    }
    out.close();

    // Validate the file before committing to it.  ThemeManager::loadTheme()
    // emits warnings and silently falls back to "default" on parse failure,
    // so a broken personal.jsonc would otherwise leave the user stuck with
    // recent.gui_theme_name = "personal" pointing at a file that never loads.
    // The validator runs the same parser loadTheme() would, so a pass here
    // guarantees the auto-selection below will succeed.
    if (!ThemeManager::instance()->validateThemeFile(outPath)) {
        qWarning("LegacyColorPrefsMigration: generated theme failed validation; "
                 "removing %s and leaving prefs untouched",
                 qUtf8Printable(outPath));
        QFile::remove(outPath);
        return false;
    }

    // Auto-activate the migrated theme so the user sees their old colors
    // immediately on this same startup.  Persisted to recent_common on
    // clean shutdown, so the choice carries over to the next launch.
    g_free(recent.gui_theme_name);
    recent.gui_theme_name = g_strdup("personal");

    // Drop the legacy keys from the Default profile prefs.  This is the
    // idempotency mechanism — next startup, readUserCustomizations() returns
    // an empty hash so we no-op.  Deliberately performed AFTER validation
    // so a failed migration leaves the user's original prefs untouched.
    // WIRESHARK_THEME_KEEP_LEGACY_PREFS=1 skips this step so the migration
    // can be exercised repeatedly during development by deleting
    // personal.jsonc and relaunching.
    if (qEnvironmentVariableIsEmpty("WIRESHARK_THEME_KEEP_LEGACY_PREFS"))
        stripLegacyKeysFromPrefs(prefsPath);

    return true;
}

} // namespace LegacyColorPrefsMigration
