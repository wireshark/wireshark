/* theme_manager.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "ui/qt/utils/theme_manager.h"

#include <ui/qt/main_application.h>
#include <ui/qt/utils/font_manager.h>
#include <ui/qt/utils/themes/color_math.h>
#include <ui/qt/utils/themes/legacy_color_prefs_migration.h>
#include <ui/qt/utils/themes/system_theme_detector.h>
#include <ui/qt/utils/themes/theme_palette_builder.h>
#include <ui/qt/utils/themes/theme_parser.h>
#include <ui/qt/utils/themes/theme_stylesheet_loader.h>
#include <ui/qt/utils/themes/theme_token_handler.h>
#include <ui/qt/utils/workspace_state.h>

#include <epan/prefs.h>

#include <app/application_flavor.h>

#include <ui/recent.h>

#include <QApplication>
#include <QColor>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QMetaEnum>
#include <QPalette>
#include <QRegularExpression>
#include <QSet>
#include <QStyle>
#include <QStyleHints>
#include <QWidget>

ThemeManager* ThemeManager::instance_{nullptr};
QMutex ThemeManager::mutex_;

namespace {

/**
 * Resolves a theme's internal name to a JSONC path the parser can open.
 *
 * Built-in themes live at `:/themes/<name>/theme.jsonc` (each in its own
 * directory).  Personal themes are bare `<name>.jsonc` files dropped into
 * WorkspaceState::personalThemesPath().
 *
 * Lookup order matches the design decision documented in the .h: built-in
 * resources are checked first, so the bundled "default" can never be shadowed
 * by a broken or partial personal override — important because loadTheme()'s
 * self-recovery path retries with "default" after a parse failure, and that
 * fallback must always succeed.  Only when no built-in matches do we look in
 * the personal directory.
 *
 * @return Resolved path on success (Qt resource URL or filesystem path), or
 *         an empty string when neither location yields a readable file.
 */
QString resolveThemePath(const QString &internalName)
{
    const QString builtin = QStringLiteral(":/themes/") + internalName
                          + QStringLiteral("/theme.jsonc");
    if (QFile::exists(builtin))
        return builtin;

    const QString personalDir = WorkspaceState::instance()->personalThemesPath();
    if (personalDir.isEmpty())
        return QString();

    const QString personal = QDir(personalDir).filePath(
        internalName + QStringLiteral(".jsonc"));
    if (QFile::exists(personal))
        return personal;

    return QString();
}

} // namespace

ThemeManager::ThemeManager(QObject *parent)
    : QObject(parent)
{
    // Snapshot the pristine OS palette BEFORE anything else in this
    // constructor runs.  applyToStyleHints() (Qt ≥ 6.8) and loadTheme()
    // both end up touching QApplication's palette via setPalette(); once
    // that has happened, QApplication::palette() returns the customized
    // palette, not the OS-native one.  Capturing here guarantees the
    // builder always has a clean baseline to start from, so themes that
    // omit palette overrides (e.g. "default") fully restore the OS
    // palette after a theme with overrides (e.g. "inverted") was active.
    osBaseline_ = QApplication::palette();

    // Construct the platform-native scheme detector NOW — while the palette
    // captured above is still pristine and BEFORE applyToStyleHints() (which
    // on Qt ≥ 6.8 can nudge the palette).  The detector calibrates what the
    // OS "default"/no-preference scheme renders as from this untouched
    // palette, so its answer is never skewed by a theme override we apply
    // later.  It begins observing the OS preference immediately; we only react
    // to its notifications when mode_ == System (Dark/Light are hard
    // overrides).  Qt parent-child ownership deletes it with the ThemeManager.
    detector_ = new SystemThemeDetector(this);
    connect(detector_, &SystemThemeDetector::schemeChanged, this,
            [this](SystemThemeDetector::Scheme) {
        if (mode_ != ThemeMode::System)
            return;
        reapplyForSchemeChange();
    });

    /** CONVENIENCE PRE-CACHING
     *
     * These pre-caches make it cheap to answer "which theme.jsonc
     * section does this token belong to?" and "which QPalette role
     * does this palette-prefixed token map to?" at runtime.  The
     * parser and the palette builder both consult them by string
     * name during a load.
     *
     * Adding a new token only requires:
     *   - Append the new ThemeToken to the enum in the header.
     *   - If a new top-level section is introduced, list it in
     *     sections_ below with its required/optional flag.
     *
     * Everything else (section-to-token grouping, palette-role
     * lookup) falls out of the Q_ENUM metaobject scanning in the
     * loops below.
     */

    QMetaEnum me = QMetaEnum::fromType<ThemeManager::ThemeToken>();

    sections_ = {
        { "brand", { true, { } } },
        { "accent", { true, { } } },
        { "expert", { false, { } } },
        { "packets", { false, { } } },
        { "conversation", { false, { } } },
        { "palette", { false, { } } },
        // Filter validity tints — every subkey optional.  When a
        // theme omits the section ThemeTokenHandler derives all five
        // tokens from accent + palette.base.  An explicit theme.filter
        // entry wins per-token (auto-grouping picks up FilterValid →
        // "valid", FilterBusyText → "busytext", etc).
        { "filter", { false, { } } }
    };

    // convenience mapping from string to QPalette::ColorRole
    me = QMetaEnum::fromType<QPalette::ColorRole>();
    for (int i = 0; i < me.keyCount(); ++i)
        paletteRoleCache_.insert(QString("%1%2").arg("palette").arg(me.key(i)).toLower(), static_cast<QPalette::ColorRole>(me.value(i)));

    // gather all allowed palette overrides
    me = QMetaEnum::fromType<ThemeManager::ThemeToken>();
    QStringList sectionKeys = sections_.keys();
    for (int i = 0; i < me.keyCount(); ++i) {
        QString key = QString(me.key(i)).toLower();
        colorRoleCache_.insert(key, static_cast<ThemeToken>(me.value(i)));

        foreach (QString sectionKey, sectionKeys) {
            if (key.startsWith(sectionKey)) {
                sections_[sectionKey].tokens << key.mid(sectionKey.length());
                break;
            }
        }
    }

    connect(mainApp, &MainApplication::preferencesChanged, this, [this]() {
        // Mode may have changed via the appearance-mode setting.  Sync
        // first so downstream subscribers of preferencesChanged that read
        // isDarkMode() (Lua debugger, PacketList selection stylesheet, …) see
        // the new value.  ThemeManager is constructed during
        // MainApplication's ctor, long before any dialog or widget, so
        // its connect lands first in the slot queue — downstream slots
        // fire after setMode() has run.  setMode() is a no-op if
        // unchanged.
        setMode(modeFromPrefs(recent.gui_color_scheme));

        // The active theme name lives in recent_common (recent.gui_theme_name).
        // Re-load on every preferencesChanged so both theme switches AND
        // font-pref changes refresh (loadTheme re-parses the JSONC so it
        // re-evaluates the fonts section against the updated prefs).  If
        // the preferred theme is missing or fails to parse, loadTheme
        // itself falls back to the flavor default then the ultimate
        // wireshark fallback.  resolveThemeName() also maps the legacy
        // "default" sentinel (written by builds that pre-date the
        // wireshark/stratoshark split) to the right flavor default.
        loadTheme(resolveThemeName(QString::fromUtf8(recent.gui_theme_name)));
    });

    // Pick up the initial mode from recent_common.  recent_read() has
    // already run by the time ThemeManager is constructed (ThemeManager::init()
    // is invoked from the MainApplication constructor, after recent load).
    mode_ = modeFromPrefs(recent.gui_color_scheme);
    applyToStyleHints();

    // Initiate the FontManager singleton.  It owns all font state and policy
    // (resolution, the systemwide regular-font push, zoom, OS-change
    // handling, and the prefs.gui_font_name write-back).  ThemeManager only
    // feeds it the configured font names during loadTheme().
    FontManager::instance();

    // Zoom changes the stylesheet output (loadStyleSheet scales font sizes by
    // the zoom factor), so a zoom is a "themed stylesheets changed" event for
    // stylesheet consumers.  Re-emit it as themeChanged so they reload.
    connect(FontManager::instance(), &FontManager::zoomChanged,
            this, &ThemeManager::themeChanged);
}

ThemeManager::~ThemeManager()
{
    instance_ = nullptr;
}

ThemeManager* ThemeManager::instance()
{
    QMutexLocker locker(&mutex_);
    if (instance_ == nullptr) {
        instance_ = new ThemeManager();
    }
    return instance_;
}

QString ThemeManager::defaultThemeName()
{
    // Wireshark is the universal default; only Stratoshark overrides
    // it.  Phrased as "wireshark unless stratoshark" so any future
    // flavor that doesn't ship its own theme directory still inherits
    // a working, fully-tested default — no separate "ultimate
    // fallback" knob needed.
    //
    // Keep the literal names in sync with the directories added by
    // add_theme(...) in ui/qt/CMakeLists.txt and the layout under
    // resources/themes/.
    if (!application_flavor_is_wireshark())
        return QStringLiteral("stratoshark");
    return QStringLiteral("wireshark");
}

QString ThemeManager::resolveThemeName(const QString &name)
{
    // Empty -> the flavor's default theme.
    // "default" -> legacy sentinel from pre-split builds (the single
    //              bundled theme used to live at resources/themes/default/).
    //              Re-map silently so existing recent_common files
    //              don't lose their selection across the upgrade.
    if (name.isEmpty() || name == QStringLiteral("default"))
        return defaultThemeName();
    return name;
}

void ThemeManager::init(const QString &theme)
{
    // Construct the singleton first so the migration can query
    // isDarkMode() (it relies on the ctor-initialized mode_, detector,
    // and osBaseline_).  loadTheme() has not run yet at this point —
    // the ThemeManager state is mode/palette only.
    ThemeManager *self = instance();

    // One-shot migration of legacy per-color preferences into a
    // personal theme.  No-op once the personal themes directory has
    // any *.jsonc file, so this is idempotent across launches.  On
    // success it sets recent.gui_theme_name = "personal" so the
    // freshly generated theme is loaded below instead of the value
    // we were called with.
    QString effectiveTheme = theme;
    if (LegacyColorPrefsMigration::runIfNeeded()) {
        const QString migrated = QString::fromUtf8(recent.gui_theme_name);
        if (!migrated.isEmpty())
            effectiveTheme = migrated;
    }

    self->loadTheme(effectiveTheme);
}

void ThemeManager::cleanup()
{
    themeColors_.clear();
    graphColors_.clear();
    info_ = ThemeInfo();
}

ThemeInfo ThemeManager::info() const
{
    return info_;
}

QList<ThemeInfo> ThemeManager::availableThemes()
{
    // Built-in themes live at :/themes/<name>/theme.jsonc; personal
    // themes are bare <name>.jsonc files under
    // WorkspaceState::personalThemesPath().  We enumerate both sources
    // here so a single picker can present them together.
    //
    // We reuse the live singleton's section definitions and role cache
    // so the parser sees the same role vocabulary as a real theme load —
    // parse warnings (if any) match what the user would see loading that
    // theme.
    QList<ThemeInfo> list;
    QSet<QString> seen;     // internalNames already emitted; gate for the
                            // "built-in wins" rule below.
    ThemeManager *self = instance();
    if (!self)
        return list;

    ThemeParser parser(self->sections_, self->colorRoleCache_);

    // Pass 1 — built-in themes.  Iterating these first means a built-in
    // entry always claims its internalName, so a later personal file with
    // a colliding stem is silently skipped (see Pass 2 comment).
    QDir builtinDir(QStringLiteral(":/themes/"));
    const QStringList builtinEntries = builtinDir.entryList(
        QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);

    for (const QString &name : builtinEntries) {
        const QString resourcePath = QStringLiteral(":/themes/") + name
                                   + QStringLiteral("/theme.jsonc");
        if (!QFile::exists(resourcePath))
            continue;
        ThemeParser::Result result;
        if (!parser.parse(name, resourcePath, result))
            continue;
        list.append(result.info);
        seen.insert(name);
    }

    // Pass 2 — personal themes from the user's themes directory.  Each
    // *.jsonc file becomes a theme whose internal name is the filename
    // stem.  Files whose stem collides with a built-in are skipped with
    // a qWarning so the user can spot accidental shadowing; this matches
    // the "Built-in wins" conflict policy.
    const QString personalDir = WorkspaceState::instance()->personalThemesPath();
    if (!personalDir.isEmpty()) {
        QDir userDir(personalDir);
        if (userDir.exists()) {
            const QStringList userEntries = userDir.entryList(
                QStringList() << QStringLiteral("*.jsonc"),
                QDir::Files | QDir::Readable, QDir::Name);
            for (const QString &fileName : userEntries) {
                const QString internalName = QFileInfo(fileName).completeBaseName();
                if (internalName.isEmpty())
                    continue;
                if (seen.contains(internalName)) {
                    qWarning("ThemeManager: personal theme \"%s\" shadows a "
                             "built-in of the same name; the personal copy is ignored.",
                             qUtf8Printable(internalName));
                    continue;
                }
                const QString fullPath = userDir.filePath(fileName);
                ThemeParser::Result result;
                if (!parser.parse(internalName, fullPath, result))
                    continue;
                list.append(result.info);
                seen.insert(internalName);
            }
        }
    }

    return list;
}

bool ThemeManager::isDark()
{
    return instance()->isDarkMode();
}

bool ThemeManager::isDarkMode() const
{
    switch (mode_) {
        case ThemeMode::Dark:
            return true;
        case ThemeMode::Light:
            return false;
        case ThemeMode::System:
            break;
    }

    if (detector_) {
        switch (detector_->currentScheme()) {
        case SystemThemeDetector::Scheme::Dark:
            return true;
        case SystemThemeDetector::Scheme::Light:
            return false;
        case SystemThemeDetector::Scheme::Unknown:
        case SystemThemeDetector::Scheme::Invalid:
            // Platform could not decide (stub back-end, or a native API that
            // returned no value).  The Unix detector already resolves
            // "default" internally, so this is reached only on those edge
            // back-ends.  Fall through to the palette heuristic below.
            break;
        }
    }

    // Last-resort fallback: classify the *pristine* OS palette (captured
    // before we applied any override) by its WCAG relative luminance.  We use
    // osBaseline_ rather than qApp->palette() so our own theme override can't
    // skew the answer, and we deliberately skip styleHints()->colorScheme():
    // it is unreliable on Linux (any Qt version) and on Windows up to Qt 6.8.
    return ColorMath::isDark(osBaseline_.color(QPalette::Window));
}

ThemeManager::ThemeMode ThemeManager::mode() const
{
    return mode_;
}

void ThemeManager::setMode(ThemeMode newMode)
{
    if (newMode == mode_)
        return;
    mode_ = newMode;
    // reapplyForSchemeChange() pushes the new effective scheme into
    // QStyleHints, rebuilds the palette, re-derives tokens, and emits
    // themeChanged.  The palette-builder baseline picks up the fresh
    // styleHints scheme and — on Qt < 6.8 non-Apple — falls back to
    // its own built-in dark palette when the style isn't scheme-aware.
    reapplyForSchemeChange();
}

void ThemeManager::applyToStyleHints()
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 8, 0)
    // Push the raw *mode* to Qt's styleHints, NOT the isDarkMode()
    // answer.  Rationale: on macOS, Qt translates
    // setColorScheme(Light/Dark) into *pinning* NSApp.appearance to
    // Aqua / DarkAqua.  Once pinned, NSApp.effectiveAppearance stops
    // following OS flips — and our SystemThemeDetector (which reads
    // effectiveAppearance) goes blind to subsequent OS changes.
    //
    // When mode is System, pass Qt::ColorScheme::Unknown so Qt leaves
    // NSApp unpinned and AppKit continues to drive it from the OS.
    // Only when the user explicitly picks Light or Dark do we pin.
    Qt::ColorScheme scheme;
    switch (mode_) {
        case ThemeMode::Light:  scheme = Qt::ColorScheme::Light;   break;
        case ThemeMode::Dark:   scheme = Qt::ColorScheme::Dark;    break;
        case ThemeMode::System:
        default:                scheme = Qt::ColorScheme::Unknown; break;
    }
    qApp->styleHints()->setColorScheme(scheme);
#endif
}

QPalette ThemeManager::baselineForBuild() const
{
    // osBaseline_ reflects the *OS* appearance.  When the user forces a
    // mode that disagrees with the OS (e.g. Dark in Wireshark while macOS
    // is Light), that snapshot is the wrong mode and native controls draw
    // light-on-dark.  Detect the divergence and fall back to the complete
    // built-in palette for the intended mode.  When the modes match — or
    // the OS scheme can't be determined — keep osBaseline_ so the common
    // case retains native platform integration.
    const SystemThemeDetector::Scheme os =
        detector_ ? detector_->currentScheme()
                  : SystemThemeDetector::Scheme::Unknown;
    const bool dark = isDarkMode();

    if (os == SystemThemeDetector::Scheme::Dark && !dark)
        return ThemePaletteBuilder::builtInLightPalette();
    if (os == SystemThemeDetector::Scheme::Light && dark)
        return ThemePaletteBuilder::builtInDarkPalette();
    return osBaseline_;
}

void ThemeManager::reapplyForSchemeChange()
{
    applyToStyleHints();

    // Refresh the OS baseline AFTER applyToStyleHints() — on Qt ≥ 6.8 the
    // setColorScheme() pin propagates synchronously into the platform
    // style, so qApp->style()->standardPalette() now reflects the new
    // scheme.  standardPalette() is the style's own definition; unlike
    // QApplication::palette() it is independent of any prior setPalette()
    // calls, so it cannot carry overrides from a previous theme.  Only
    // refresh on platforms where the OS palette is trusted; on Linux and
    // Qt < 6.8 Windows the baseline is the built-in light/dark palette
    // and osBaseline_ is unused.
#if defined(Q_OS_MACOS) || (defined(Q_OS_WIN) && QT_VERSION >= QT_VERSION_CHECK(6, 8, 0))
    if (QStyle *s = qApp->style())
        osBaseline_ = s->standardPalette();
#endif

    // Build the palette first, derive tokens against it, THEN push it to
    // QApplication.  On Qt 5, QApplication::setPalette() dispatches
    // ApplicationPaletteChange synchronously before returning, so any widget
    // that reacts to that event and reads a ThemeManager token must find the
    // token map already up to date.  Building the palette without applying it
    // first lets us complete token derivation before the signal fires.
    const QPalette newPalette = ThemePaletteBuilder::build(themeColors_, isDarkMode(), colorRoleCache_, paletteRoleCache_, baselineForBuild());
    ThemeTokenHandler::deriveAll(themeColors_, isDarkMode(), newPalette);
    QApplication::setPalette(newPalette);
    applyApplicationStyleSheet();
    emit themeChanged();
}

void ThemeManager::applyApplicationStyleSheet()
{
    if (!qApp)
        return;
    qApp->setStyleSheet(loadStyleSheet(QStringLiteral("application")));
}

ThemeManager::ThemeMode ThemeManager::modeFromPrefs(int gui_color_scheme)
{
    switch (gui_color_scheme) {
        case COLOR_SCHEME_LIGHT: return ThemeMode::Light;
        case COLOR_SCHEME_DARK:  return ThemeMode::Dark;
        case COLOR_SCHEME_DEFAULT:
        default:
            return ThemeMode::System;
    }
}

QColor ThemeManager::color(ThemeToken role) const
{
    if (role == NoRole)
        return QColor();

    auto it = themeColors_.constFind(role);
    if (it != themeColors_.constEnd()) {
        const QColor c = isDarkMode() ? it.value().dark : it.value().light;
        if (c.isValid())
            return c;
    }

    // Palette tokens that the active theme doesn't override aren't stored in
    // themeColors_ (deriveAll reads the palette roles but never writes them
    // back).  Fall back to the live application palette — which ThemeManager
    // itself sets — so callers always get a valid, mode-correct color instead
    // of an invalid QColor.
    switch (role) {
    case PaletteBase:       return QApplication::palette().color(QPalette::Base);
    case PaletteWindow:     return QApplication::palette().color(QPalette::Window);
    case PaletteText:       return QApplication::palette().color(QPalette::Text);
    case PaletteWindowText: return QApplication::palette().color(QPalette::WindowText);
    case PaletteMid:        return QApplication::palette().color(QPalette::Mid);
    default:                return QColor();
    }
}

namespace {
// Qt stylesheets express font size both as "font-size: Npx" and inside the
// "font:" shorthand (e.g. "font: bold 14px ..."), and only support absolute
// px/pt units (no relative em/%).  Scale the size component of either form by
// the current zoom factor so themed text zooms with the rest of the UI.
// No-op at zoom level 0 (factor 1.0).
QString scaleStyleSheetFontSizes(const QString &qss, qreal factor)
{
    if (qFuzzyCompare(factor, qreal(1.0)))
        return qss;

    // "font:" or "font-size:" with the value up to ';' or '}'.  The optional
    // "-size" is anchored to ':' so this never matches font-weight/-family/etc.
    static const QRegularExpression propRe(
        QStringLiteral("\\bfont(?:-size)?\\s*:\\s*([^;}]*)"));
    // A size token (the only px/pt token inside a font value).
    static const QRegularExpression sizeRe(
        QStringLiteral("([0-9]+(?:\\.[0-9]+)?)(px|pt)"));

    QString out;
    out.reserve(qss.size());
    qsizetype last = 0;
    auto it = propRe.globalMatch(qss);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        out += qss.mid(last, m.capturedStart(1) - last);

        const QString value = m.captured(1);
        QString scaledValue;
        scaledValue.reserve(value.size());
        qsizetype vlast = 0;
        auto vit = sizeRe.globalMatch(value);
        while (vit.hasNext()) {
            const QRegularExpressionMatch vm = vit.next();
            scaledValue += value.mid(vlast, vm.capturedStart() - vlast);
            const double scaled = vm.captured(1).toDouble() * factor;
            scaledValue += QStringLiteral("%1%2")
                               .arg(qMax(1, qRound(scaled)))
                               .arg(vm.captured(2));
            vlast = vm.capturedEnd();
        }
        scaledValue += value.mid(vlast);

        out += scaledValue;
        last = m.capturedEnd(1);
    }
    out += qss.mid(last);
    return out;
}
} // namespace

QString ThemeManager::loadStyleSheet(const QString &name) const
{
    const QString qss = ThemeStyleSheetLoader::load(name, themeColors_, isDarkMode());
    // The FontManager owns text zoom; apply it to the resolved stylesheet here
    // so callers just re-fetch the stylesheet to pick up a new zoom level.
    return scaleStyleSheetFontSizes(qss, FontManager::zoomFactor());
}

QString ThemeManager::styleSheet(const QString &name)
{
    return instance()->loadStyleSheet(name);
}

void ThemeManager::setValidationState(QWidget *w, const QString &state)
{
    if (!w)
        return;
    w->setProperty("wsValidation", state.isEmpty() ? QVariant() : QVariant(state));
    w->style()->unpolish(w);
    w->style()->polish(w);
    w->update();
}

QHash<ThemeManager::ThemeToken, QColor>
ThemeManager::previewTheme(const QString &internalName, PreviewScheme scheme) const
{
    // Mirrors the loadTheme() pipeline (parse → build palette → derive
    // tokens) but operates on stack-local data so the live theme state,
    // QApplication palette, and stylesheet are not touched.  See the
    // header for the public contract.
    QHash<ThemeToken, QColor> empty;

    // Resolve the caller's PreviewScheme into a concrete light/dark
    // bool here so the rest of the pipeline stays a pure function of
    // wantDark.  PreferLight/PreferDark pin the side regardless of the
    // live mode or OS preference — which is what makes the preview
    // correct when the user changes the Appearance-mode dropdown
    // without applying yet.  Default defers to the detector, which is
    // guaranteed to be non-null (ThemeManager constructs it in its own
    // ctor) and to return Light or Dark (every back-end resolves the
    // "no preference" case via SystemThemeDetector::resolveDefault).
    bool wantDark;
    switch (scheme) {
    case PreviewScheme::PreferLight:
        wantDark = false;
        break;
    case PreviewScheme::PreferDark:
        wantDark = true;
        break;
    case PreviewScheme::Default:
    default:
        wantDark = detector_->currentScheme() == SystemThemeDetector::Scheme::Dark;
        break;
    }

    // resolveThemePath() applies the same built-in-then-personal lookup
    // chain as loadTheme(), so a preview of a personal theme produces
    // the same colors that an actual load would.
    const QString resourcePath = resolveThemePath(internalName);
    if (resourcePath.isEmpty())
        return empty;

    ThemeParser parser(sections_, colorRoleCache_);
    ThemeParser::Result result;
    if (!parser.parse(internalName, resourcePath, result))
        return empty;

    // Pick the built-in light/dark palette as the baseline for the
    // requested mode instead of osBaseline_.  The captured OS baseline
    // reflects the *current* effective scheme, so reusing it when
    // previewing the opposite mode would feed a wrong-mode baseline
    // into the derivation.  The built-in palettes are mode-correct
    // by construction and are what the live builder falls back to on
    // platforms whose OS palette cannot be trusted to flip.
    const QPalette previewBaseline = wantDark
        ? ThemePaletteBuilder::builtInDarkPalette()
        : ThemePaletteBuilder::builtInLightPalette();
    const QPalette previewPalette = ThemePaletteBuilder::build(
        result.colors, wantDark, colorRoleCache_, paletteRoleCache_, previewBaseline);
    ThemeTokenHandler::deriveAll(result.colors, wantDark, previewPalette);

    QHash<ThemeToken, QColor> out;
    out.reserve(result.colors.size());
    for (auto it = result.colors.constBegin(); it != result.colors.constEnd(); ++it) {
        out.insert(it.key(), wantDark ? it.value().dark : it.value().light);
    }

    // deriveAll() only *reads* the palette tokens (to derive tints); it
    // never writes them back, so a theme that leaves them to the baseline
    // palette — like the bundled default — carries no PaletteBase/Window/…
    // entry here.  A consumer that reads them directly (the preview mockup)
    // would then fall back to the *live* QApplication palette, i.e. the
    // mode the app is currently in, not the previewed one.  Pin them from
    // the mode-correct previewPalette built above so the preview tracks the
    // requested light/dark choice regardless of what the theme overrides.
    const struct { ThemeToken token; QPalette::ColorRole role; } paletteTokens[] = {
        { PaletteBase,          QPalette::Base          },
        { PaletteWindow,        QPalette::Window        },
        { PaletteText,          QPalette::Text          },
        { PaletteWindowText,    QPalette::WindowText    },
        { PaletteMid,           QPalette::Mid           },
        { PaletteAlternateBase, QPalette::AlternateBase },
        { PaletteMidLight,      QPalette::Midlight      },
    };
    for (const auto &pt : paletteTokens) {
        if (!out.value(pt.token).isValid())
            out.insert(pt.token, previewPalette.color(pt.role));
    }
    return out;
}

bool ThemeManager::validateThemeFile(const QString &filePath) const
{
    // Mirrors the parse step of loadTheme() / previewTheme() without
    // applying any results to the live theme state.  ThemeParser emits
    // qWarning() on any structural problem (missing required section,
    // unknown token, malformed color value) so the caller sees the
    // reason in the log alongside our own "validation failed" message.
    ThemeParser parser(sections_, colorRoleCache_);
    ThemeParser::Result throwaway;
    return parser.parse(QStringLiteral("__validate__"), filePath, throwaway);
}

// --------------------------------------------------------------------
// Theme loading — delegates all JSONC parsing to ThemeParser and then
// applies the result (palette + derived tokens).
// --------------------------------------------------------------------
bool ThemeManager::loadTheme(const QString &theme)
{
    // Build the ordered list of candidate themes:
    //   1. The caller's request (after legacy-name + empty resolution).
    //   2. The flavor's preferred default — wireshark for everything
    //      except Stratoshark, which makes it the natural ultimate
    //      fallback for the common case without a separate knob.
    // Duplicates are dropped so we don't re-attempt the same theme on
    // a hard parse failure.
    QStringList candidates;
    candidates << resolveThemeName(theme);
    const QString flavorDefault = defaultThemeName();
    if (!candidates.contains(flavorDefault))
        candidates << flavorDefault;

    ThemeParser::Result result;
    bool parsed = false;

    auto tryParse = [&](const QString &name) {
        // resolveThemePath() returns the bundled :/themes/<name>/theme.jsonc
        // when present, falling back to <personalDir>/<name>.jsonc.  Built-in
        // takes precedence — see resolveThemePath() for why.
        const QString resourcePath = resolveThemePath(name);
        if (resourcePath.isEmpty())
            return false;
        ThemeParser parser(sections_, colorRoleCache_);
        return parser.parse(name, resourcePath, result);
    };

    for (const QString &name : candidates) {
        if (tryParse(name)) {
            parsed = true;
            break;
        }
        // The parser already emitted a specific qWarning for the cause.
        qWarning("ThemeManager: failed to load theme \"%s\"", qUtf8Printable(name));
    }

    if (!parsed) {
        qWarning("ThemeManager: no usable theme found (tried %s); leaving existing state intact",
                 qUtf8Printable(candidates.join(QStringLiteral(", "))));
        return false;
    }

    // Adopt the parsed data.  The parser emits per-field warnings for
    // soft failures (missing optional keys, malformed sub-objects) and
    // returns false only for hard failures, so on success we can take
    // the result wholesale.
    info_           = result.info;
    themeColors_    = result.colors;
    graphColors_    = result.graphColors;

    // Build the palette, derive tokens against it, then push it to
    // QApplication.  Order matters: on Qt 5, setPalette() dispatches
    // ApplicationPaletteChange synchronously before returning, so widgets
    // reacting to that event must find the token map already populated.
    // Building without applying first lets derivation complete before the
    // signal fires.  osBaseline_ is the pristine OS palette captured at
    // construction (refreshed on scheme flips), so each theme load starts
    // from a clean baseline and overrides from a previous theme — including
    // ones the new theme does not re-declare — are discarded here.
    const QPalette newPalette = ThemePaletteBuilder::build(themeColors_, isDarkMode(), colorRoleCache_, paletteRoleCache_, baselineForBuild());
    ThemeTokenHandler::deriveAll(themeColors_, isDarkMode(), newPalette);
    QApplication::setPalette(newPalette);
    applyApplicationStyleSheet();

    // Notify consumers.  At first-startup time this is a no-op (the GUI
    // hasn't been built yet, no listeners), but on every later load —
    // mode flip, user-initiated theme switch, font-pref reapply —
    // widgets that cached resolved wstheme(...) output need to re-run
    // loadStyleSheet() against the fresh token table.
    emit themeChanged();

    // Apply fonts after the theme is fully in place, so the font change is
    // sequenced after themeChanged rather than racing it.  The FontManager
    // resolves, pushes the app font, and emits on a real change.
    FontManager::instance()->setRegularFont(result.regularFontName);
    FontManager::instance()->setMonospaceFont(result.monospaceFontName);

    return true;
}

QColor ThemeManager::graphColor(int idx) const
{
    Q_ASSERT_X(idx >= 0, "ThemeManager::graphColor", "Graph color index must be non-negative");

    if (graphColors_.isEmpty()) {
        qWarning("ThemeManager: no graph colors defined in theme \"%s\"", qUtf8Printable(info_.name));
        return QColor();
    }

    const ThemeColorPair &p = graphColors_.at(idx % graphColors_.size());

    return isDarkMode() ? p.dark : p.light;
}

// TODO: the default color should be defined by switch in the theme file itself
QColor ThemeManager::graphDefaultColor() const
{
    if (graphColors_.isEmpty()) {
        qWarning("ThemeManager: no graph colors defined in theme \"%s\"", qUtf8Printable(info_.name));
        return QColor();
    }

    const ThemeColorPair &p = graphColors_.first();
    return isDarkMode() ? p.dark : p.light;
}


qsizetype ThemeManager::graphColorCount() const
{
    return graphColors_.size();
}

bool ThemeManager::colorIsAvailable(const ThemeManager::ThemeToken role) const
{
    return themeColors_.contains(role);
}

