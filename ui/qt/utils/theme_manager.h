/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef THEME_MANAGER_H
#define THEME_MANAGER_H

#include <QColor>
#include <QFont>
#include <QHash>
#include <QMutex>
#include <QObject>
#include <QPalette>
#include <QString>

class SystemThemeDetector;

/**
 * Theme metadata from the "meta" section of theme.jsonc.
 */
struct ThemeInfo {
    QString name;           ///< Display name, e.g. "Wireshark Default"
    QString internalName;   ///< Internal name, e.g. "default"
    int     version = 0;    ///< Schema version (currently 1)
    QString description;    ///< One-line description shown in preferences
    QString author;         ///< Theme author or organization
};

struct ThemeSectionInfo {
    bool required;
    QStringList tokens;
};

struct ThemeColorPair {
    QColor light;
    QColor dark;
};

/**
 * Gateway for Wireshark's theme system.
 *
 * Owns the process-wide theme state (current theme, mode, token map,
 * font choices, the platform scheme detector) and fronts the public
 * API.  Non-trivial work is delegated to helpers under
 * `ui/qt/utils/themes/`, split by responsibility:
 *
 *   themes/theme_parser.{h,cpp}            — reads theme.jsonc
 *   themes/theme_token_handler.{h,cpp}     — derives Header* / Update* / …
 *                                            from the brand + accent inputs
 *   themes/theme_palette_builder.{h,cpp}   — constructs the QPalette
 *                                            and pushes it via setPalette()
 *   themes/theme_stylesheet_loader.{h,cpp} — reads :/stylesheets/ and
 *                                            resolves wstheme(...) tokens
 *   themes/color_math.{h,cpp}              — pure color-math statics
 *                                            (mix/darken/lighten/contrast/…)
 *   themes/system_theme_detector*.{h,cpp,mm} — platform-native OS
 *                                            light/dark detection.
 *
 * A theme file (resources/themes/<name>/theme.jsonc) declares six
 * mandatory colors — `brand.primary`, `brand.deep`, and four
 * `accent.*` values.  Every other token the UI consumes (Header*,
 * Section*, Update*, Packets*, Conversation*, Expert*, TextOnDark*,
 * …) is derived from those inputs by ThemeTokenHandler at load time.
 *
 * Stylesheets reference tokens via `wstheme(TokenName)`.  The loader
 * rewrites each occurrence to the resolved `#rrggbb` hex value at
 * the widget's setStyleSheet() call site.
 */
class ThemeManager : public QObject {
    Q_OBJECT
public:

    /**
     * Selects how the app decides between the light and dark sides of
     * the current theme.
     *
     *   System — follow the OS preference (default).  Flips live when
     *            the user changes the OS appearance.
     *   Dark   — always return the dark side, regardless of the OS.
     *   Light  — always return the light side, regardless of the OS.
     */
    enum class ThemeMode {
        System,
        Dark,
        Light
    };
    Q_ENUM(ThemeMode)

    enum ThemeToken {
        // Brand
        BrandPrimary,
        BrandDeep,

        // Accent
        AccentSuccess,
        AccentWarning,
        AccentError,
        AccentInfo,

        // Expert
        ExpertComment,
        ExpertChat,
        ExpertNote,
        ExpertWarn,
        ExpertError,
        ExpertForeground,

        // Packets — for each state, <Name> is the row background tint and
        // <Name>Text is the foreground.  Hidden is text-only by design (it
        // dims an item that otherwise renders with the normal row bg).
        // When a theme omits a Text token, ThemeTokenHandler derives it
        // from contrastingText(<Name>) or PaletteText as appropriate.
        PacketsSelection,
        PacketsSelectionText,
        PacketsInactive,
        PacketsInactiveText,
        PacketsMarked,
        PacketsMarkedText,
        PacketsIgnored,
        PacketsIgnoredText,
        PacketsHidden,

        // Conversation — same fg/bg convention as Packets.
        ConversationClient,
        ConversationClientText,
        ConversationServer,
        ConversationServerText,

        // Filter state (single color per state — use as bg tint; pair
        // with QPalette::Text for foreground).  Derived from accent.
        FilterValid,
        FilterInvalid,
        FilterDeprecated,

        // Syntax highlighting — foreground text colours for code- and
        // data-viewers (JSON, hex, Lua debugger, etc.).  Derived so
        // the variant is darker in light mode and lighter in dark
        // mode, keeping enough contrast against PaletteBase.
        SyntaxKey,
        SyntaxString,
        SyntaxNumber,

        // Palette Overrides
        PaletteWindow,
        PaletteBase,
        PaletteText,
        PaletteWindowText,
        PaletteAlternateBase,
        PaletteMid,
        PaletteMidLight,
#if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
        PaletteAccent,
#endif

        // Header (derived from brand)
        HeaderGradientStart,
        HeaderGradientEnd,

        // Section headers (derived from brand + QPalette)
        SectionHeader,
        SectionHeaderHover,

        // Text on dark surfaces (derived from brand)
        TextOnDark,
        TextOnDarkMuted,

        // Update bar (derived from accent.success)
        UpdateGradientStart,
        UpdateGradientEnd,
        UpdateBorder,
        UpdateText,
        UpdateTextHighlight,
        UpdateLink,
        UpdateLinkHover,
        UpdateLinkPressed,
        UpdateButtonBg,
        UpdateButtonHover,
        UpdateButtonPressed,
        UpdateButtonDisabledBg,
        UpdateButtonDisabledText,
        UpdateDismissHoverBg,
        UpdateDismissPressedBg,

        // Accent aliases (derived)
        HighlightColorOrange,
        HighlightColorGreen,

        // None
        NoRole
    };
    Q_ENUM(ThemeToken)

    static ThemeManager* instance();

    /**
     * Initializes the ThemeManager by loading the default theme from
     * the built-in resources.  Call once during application startup
     * after QApplication is constructed.
     */
    static void init(const QString &theme = QStringLiteral("default"));

    void cleanup();

    /**
     * Returns metadata about the currently loaded theme.
     */
    ThemeInfo info() const;

    /**
     * Enumerates every theme bundled under `:/themes/`.  For each one
     * the JSONC file is parsed to extract its metadata (display name,
     * author, description, internal name).  Intended for populating a
     * theme picker in the preferences dialog.
     *
     * Themes whose JSONC fails to parse are skipped silently (a
     * warning is logged by ThemeParser).  The returned list is not
     * sorted — callers that want alphabetical order should sort by
     * display name themselves.
     */
    static QList<ThemeInfo> availableThemes();

    /**
     * Returns the resolved color value for a given ThemeToken in
     * the current light/dark mode.
     *
     * @param role  The ThemeToken enum value, e.g. ThemeManager::HeaderGradientStart
     * @return The color defined for the role in the current mode, or an invalid QColor if
     *         the role is not defined.
     */
    QColor color(ThemeToken role) const;

    bool colorIsAvailable(ThemeToken role) const;

    /**
     * Resolves the color table for a named theme in the requested
     * light/dark mode without altering live application state.
     *
     * Runs the same parser + derive pipeline as loadTheme(), but on a
     * stack-local copy of the parsed result — the active theme,
     * application palette, and stylesheet are untouched.  Useful for
     * offering a "preview" of a theme inside the preferences dialog:
     * the dropdown can drive a swatch / mockup widget with no risk of
     * leaking partial state into the running app.
     *
     * Returns an empty hash if the theme cannot be found or fails to
     * parse — callers should treat that as "fall back to the live
     * ThemeManager's colors".
     *
     * @param internalName  internal theme name (e.g. "default").
     * @param wantDark      true for the dark side, false for light.
     * @return token → resolved QColor for the requested mode.
     */
    QHash<ThemeToken, QColor> previewTheme(const QString &internalName,
                                           bool wantDark) const;

    /**
     * Runs ThemeParser on @p filePath and returns true if it produces a
     * usable result.  Reuses the live section / role caches so the
     * validation criteria match what a real load would apply — required
     * sections, required tokens, schema-typed values.
     *
     * Intended for callers that have just written a theme file and need
     * to confirm it parses before persisting a reference to it (e.g. the
     * legacy color prefs migration, which avoids stamping
     * recent.gui_theme_name with a name that points at a broken file).
     *
     * @param filePath  Absolute filesystem path to the candidate JSONC.
     * @return true if the file parses cleanly; false on any parse error.
     */
    bool validateThemeFile(const QString &filePath) const;

    /**
     * Loads a QSS stylesheet from the built-in :/stylesheets/ resource
     * tree and replaces all `wstheme(TokenName)` references with their
     * resolved color values.  Thin delegator; see
     * `ThemeStyleSheetLoader::load()` for the full semantics.
     *
     * The stylesheet is always looked up under :/stylesheets/, with a
     * ".qss" extension automatically appended.  The name is sanitized
     * to prevent path traversal: it must consist of alphanumerics,
     * underscores, hyphens, dots and forward slashes only, must not
     * start with '/' or '.', and must not contain "..".  Invalid or
     * missing stylesheets fail silently and return an empty string.
     *
     * @param name  Logical stylesheet name relative to :/stylesheets/,
     *              without extension, e.g. "widgets/learn-card".
     * @return The processed stylesheet string, or an empty string if
     *         the name is invalid or the file could not be read.
     */
    QString loadStyleSheet(const QString &name) const;

    /**
     * Convenience static accessor equivalent to
     *   ThemeManager::instance()->loadStyleSheet(name)
     *
     * Allows callers to load a themed stylesheet without first
     * resolving the singleton, e.g.
     *   widget->setStyleSheet(ThemeManager::styleSheet("widgets/learn-card"));
     *
     * @param name  Logical stylesheet name relative to :/stylesheets/,
     *              without extension, e.g. "widgets/learn-card".
     * @return The processed stylesheet string, or an empty string if
     *         the name is invalid or the file could not be read.
     */
    static QString styleSheet(const QString &name);

    /**
     * Marks a widget as being in a named validation state for QSS
     * rule matching.  Sets the dynamic property `wsValidation` on
     * @p w and re-polishes the widget so selectors in
     * ui/stylesheets/application.qss (e.g. `QLineEdit[wsValidation="invalid"]`)
     * take effect immediately.
     *
     * Pass an empty QString to clear the state and fall back to the
     * default palette.  Conventional values are `"valid"`,
     * `"invalid"`, and `"deprecated"` — see application.qss.
     */
    static void setValidationState(QWidget *w, const QString &state);

    /** Convenience shortcut for ThemeManager::instance()->isDarkMode().
     *
     *  The color-manipulation helpers (mix, darken, contrastingText, …)
     *  previously declared here have moved to ColorMath in
     *  ui/qt/utils/themes/color_math.h. */
    static bool isDark();

    /**
     * Returns true if the current appearance is dark.
     *
     * Resolves in this order:
     *   - ThemeMode::Dark  → true
     *   - ThemeMode::Light → false
     *   - ThemeMode::System → value reported by the platform-native
     *                         SystemThemeDetector.  If the detector
     *                         cannot determine the OS preference, falls
     *                         back to Qt's own QStyleHints::colorScheme()
     *                         (Qt ≥ 6.5), and finally to a QPalette
     *                         window/text luminance comparison.
     *
     * This is the single authority for the "is the app dark?" question.
     * The static isDark() convenience delegates here.
     *
     * Named *Mode because the class also has a static isDark(QColor)
     * luminance helper; keeping the instance method's name distinct
     * avoids overload confusion at call sites.
     */
    bool isDarkMode() const;

    /**
     * Returns the currently active mode.  Reflects whichever of
     * gui.color_scheme the user picked at app start plus any live
     * setMode() calls (setMode is currently only invoked by the
     * preferences re-apply path).
     */
    ThemeMode mode() const;

    /**
     * Switches the mode.  If the new mode differs from the current
     * one, re-runs the theme's derive/apply path and emits
     * themeChanged so cached stylesheets reload.  Does NOT persist to
     * preferences; that is the caller's responsibility.
     */
    void setMode(ThemeMode mode);

    /**
     * @brief Returns the graph color for the given index, cycling through available graph colors if necessary.
     *
     * NOTE: if no graph colors are defined, this will return an invalid QColor.
     * NOTE: the index will be modulo'd by the number of available graph colors,
     *   so callers can safely pass any index and it will cycle through the defined colors.
     *
     * @param idx the index for the graph color.
     * @return QColor
     */
    QColor graphColor(int idx) const;

    QColor graphDefaultColor() const;

    /**
     * @brief Returns the number of graph colors defined in the theme.
     *
     * @return int > 0 if graph colors are defined, 0 if not.
     */
    qsizetype graphColorCount() const;

    QFont regularFont() const;
    QFont monospaceFont() const;

signals:
    void themeChanged();

protected:
    explicit ThemeManager(QObject *parent = nullptr);
    ~ThemeManager();

private:
    static ThemeManager* instance_;
    static QMutex mutex_;

    ThemeInfo info_;

    // Flattened token -> color value, one map per mode
    QHash<ThemeManager::ThemeToken, ThemeColorPair> themeColors_;
    QList<ThemeColorPair> graphColors_;

    QFont regular_font_;
    QFont monospace_font_;

    QHash<QString, ThemeSectionInfo> sections_;

    // mapping caches for role and palette resolution
    QHash<QString, ThemeToken> colorRoleCache_;
    QHash<QString, QPalette::ColorRole> paletteRoleCache_;

    // Light/dark selection: user's explicit choice plus the detector
    // that tracks the OS preference when mode == System.  The detector
    // is a private member — external code never sees it.  Lifetime is
    // managed via Qt's parent-child ownership: constructed with `this`
    // as parent, destroyed automatically with the ThemeManager.
    ThemeMode mode_ = ThemeMode::System;
    SystemThemeDetector *detector_ = nullptr;

    // Pristine OS palette snapshot used as the baseline when the palette
    // builder constructs a new theme palette.  Captured once at ctor
    // entry (before any setPalette() call could pollute QApplication's
    // live palette), and refreshed from `qApp->style()->standardPalette()`
    // whenever the effective light/dark scheme changes (mode flip or OS
    // notification).  Using this snapshot instead of
    // QApplication::palette() prevents the previous theme's palette
    // overrides from leaking into the next theme's baseline — without it,
    // switching from a theme with palette overrides (e.g. "inverted") to
    // one without (e.g. "default") would leave the prior overrides
    // visible.  Only consulted on platforms where the OS palette is
    // trusted (macOS, Windows Qt ≥ 6.8); ignored elsewhere.
    QPalette osBaseline_;

    /**
     * Picks the baseline palette handed to ThemePaletteBuilder::build()
     * for the live theme paths.  Returns osBaseline_ when the intended
     * mode matches the OS appearance (or the OS scheme is unknown),
     * preserving native integration.  When the forced mode diverges
     * from the OS — e.g. forced Dark on a Light macOS — the OS palette
     * is the wrong mode, so this returns the complete built-in palette
     * for the intended mode instead.  No-op on Linux / Qt < 6.8 Windows,
     * where the builder ignores its baseline argument anyway.
     */
    QPalette baselineForBuild() const;

    /**
     * Re-applies the current theme to the application palette and
     * re-derives the token table, then emits themeChanged.  Invoked
     * when the effective light/dark state flips for any reason
     * (explicit setMode or a System-mode OS flip).
     */
    void reapplyForSchemeChange();

    /**
     * Maps prefs.gui_color_scheme (COLOR_SCHEME_DEFAULT / _LIGHT /
     * _DARK) to ThemeMode.  Defined in the .cpp to keep prefs.h out
     * of this header.
     */
    static ThemeMode modeFromPrefs(int gui_color_scheme);

    /**
     * Pushes the current mode into Qt's style-hints layer (Qt ≥ 6.8),
     * so native widget chrome (combobox dropdowns, menu surfaces) renders
     * consistently with our theme's light/dark decision.  No-op on older
     * Qt.  Called whenever mode_ changes.
     */
    void applyToStyleHints();

    /**
     * Loads `:/stylesheets/application.qss`, resolves its wstheme(...)
     * tokens against the current palette, and pushes the result onto
     * qApp via setStyleSheet().  Invoked on every theme/mode flip so
     * the global rules stay in sync with the active mode.
     */
    void applyApplicationStyleSheet();

    /**
     * Loads a theme.jsonc file by delegating to ThemeParser, then
     * populates the light/dark color maps, applies the palette, and
     * derives tokens.
     *
     * @param themeName  The name of the theme to load, defaults to "default".
     * @return true if the theme was loaded successfully.
     */
    bool loadTheme(const QString &themeName = QStringLiteral("default"));

};

#endif /* THEME_MANAGER_H */
