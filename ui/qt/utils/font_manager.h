/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FONT_MANAGER_H
#define FONT_MANAGER_H

#include <QByteArray>
#include <QFont>
#include <QList>
#include <QMutex>
#include <QObject>
#include <QPair>

/**
 * Single authority for the application's fonts.
 *
 * A singleton (like ThemeManager): access via FontManager::instance().  Its
 * lifecycle is initiated by ThemeManager at startup — ThemeManager forces the
 * instance into existence and feeds it the configured font names — but every
 * font decision lives here: resolution/validation, the systemwide
 * regular-font push, zoom, catching external (OS) font changes, and
 * notification.
 *
 * ThemeManager's entire font role is to read a configured font name and hand
 * it to setRegularFont()/setMonospaceFont().  It performs no validation,
 * fixed-pitch checking, or fallback — that is exclusively this class.
 *
 * Three independent sources can change the font, and all converge here:
 *   - a theme switch (ThemeManager applies the theme fully, then calls the
 *     setters, so this class emits its normal font signals once the theme is
 *     in place — no separate silent path);
 *   - a zoom action (zoomIn/zoomOut/resetZoom);
 *   - the OS changing the system font (caught via QEvent::ThemeChange, after
 *     which the system general font is re-read and adopted unless a theme or
 *     preference overrides the regular font).
 *
 * Per-class fonts: the platform gives some widget classes their own font
 * (on macOS menus, tool buttons and small/mini controls are smaller than the
 * general font).  QApplication::setFont() without a class name discards
 * them, so the constructor captures every class font the platform defined,
 * and each push of the application font re-pushes them, zoomed.  While the
 * regular font is the platform general font the captured class fonts are
 * used as they are; otherwise each class font is the regular font with the
 * platform's size ratio between that class and the general font.
 *
 * Consumer contract: a font-using widget owns its own font handling.  In its
 * constructor it seeds the current font from the static accessors (e.g.
 * zoomedMonospaceFont()) and connects to the signal it needs
 * (applicationFontChanged and/or monospaceFontChanged) for later theme, zoom,
 * and OS changes.  No external party wires a widget's fonts for it, so a widget
 * created at any time is correct immediately and stays in sync on its own.
 */
class FontManager : public QObject
{
    Q_OBJECT
public:
    /**
     * Whether a zoom step scales the whole application or only content views.
     *
     *   AppWide     — zoom changes the app-default font via QApplication, so
     *                 chrome (menus/toolbars/dialogs) scales too.
     *   ContentOnly — the app-default font stays at the base size; only
     *                 widgets that explicitly pull the zoomed fonts scale.
     *
     * v1 fixes this in the constructor.  v2 will drive it from a preference
     * on the "Font & Themes" page.
     */
    enum class ZoomScope {
        AppWide,
        ContentOnly
    };

    /** Returns the process-wide singleton, constructing it on first use. */
    static FontManager *instance();

    // --- Value accessors: static only (single instance, no instance
    //     duplicates, so there is no static/instance name clash) ---

    /** Base (unzoomed) regular/proportional font. */
    static QFont font();
    /** Base (unzoomed) monospace font. */
    static QFont monospaceFont();
    /** Regular font with the current zoom level applied. */
    static QFont zoomedFont();
    /** Monospace font with the current zoom level applied. */
    static QFont zoomedMonospaceFont();

    /** Current zoom multiplier relative to the base regular font (1.0 at zoom
     *  level 0).  For fractional values such as stylesheet font sizes; scale
     *  pixel values with ZoomScaling::scaledPixels() and fonts with
     *  scaledFont() instead of multiplying by this factor. */
    static qreal zoomFactor();

    /** @p base with the current zoom level applied, in the same way as the
     *  regular and monospace fonts. */
    static QFont scaledFont(const QFont &base);

    /** Resolves a font descriptor (QFont::toString() form) or bare family name
     *  without touching FontManager state. */
    static QFont fontFromName(const QString &name);
    /** Family, style name and point size with one decimal, e.g. "Menlo Regular 12.0". */
    static QString displayName(const QFont &font);
    /** Returns @p font, or a fixed-pitch substitute when it is proportional.
     *  Only the substitute is reset to the normal (upright) style. */
    static QFont guaranteeMonospace(const QFont &font);
    /**
     * The font a theme's font descriptor resolves to, without the
     * gui.font_name preference: the system general (or fixed) font when
     * @p fontName is empty, else fontFromName(); a monospace result is
     * passed through guaranteeMonospace().
     */
    static QFont themeFont(const QString &fontName, bool monospace);
    /**
     * The monospace font the gui.font_name preference resolves to. A family the
     * user picked is used as chosen, also a proportional one; a family that is
     * not installed, or a fixed-pitch family Qt matched to a proportional face,
     * is passed through guaranteeMonospace().
     */
    static QFont preferenceMonospaceFont(const QFont &font);

    // --- Mutators & queries ---

    /**
     * Sets the regular (proportional) font from a font descriptor string
     * (QFont::toString() form, or a bare family name).  An empty string means
     * "no preference" and falls back to the system general font.
     *
     * Emits applicationFontChanged when the resolved font actually changes,
     * and always reconciles the QApplication font.
     *
     * @param fontName  font descriptor, or empty for the system default.
     */
    void setRegularFont(const QString &fontName);

    /**
     * Sets the monospace font.  The user preference gui.font_name always wins
     * when set; otherwise @p fontName; otherwise the system fixed font.  A
     * theme or system font is guaranteed to be fixed-pitch; the preference
     * font is resolved by preferenceMonospaceFont().  Emits
     * monospaceFontChanged when the resolved font actually changes.
     *
     * @param fontName  font descriptor, or empty.
     */
    void setMonospaceFont(const QString &fontName);

    void zoomIn();
    void zoomOut();
    void resetZoom();
    /**
     * Sets the zoom level, clamped to MinZoomLevel..MaxZoomLevel, and stores
     * the clamped level in recent.gui_zoom_level, also when it is unchanged.
     */
    void setZoomLevel(int level);

    /**
     * Applies the stored zoom level (recent.gui_zoom_level).  Call it
     * after every recent_read_profile_static() (at startup before the
     * main window is created, and after a profile switch) and after
     * the command line recent overrides (-o gui.zoom_level:N).
     */
    void restoreZoomLevel();
    int  zoomLevel() const { return zoom_level_; }

    /** Lowest and highest zoom level. */
    static constexpr int MinZoomLevel = -10;
    static constexpr int MaxZoomLevel = 10;
    /** Whether zoomIn() would change the zoom level. */
    bool canZoomIn() const { return zoom_level_ < MaxZoomLevel; }
    /** Whether zoomOut() would change the zoom level. */
    bool canZoomOut() const { return zoom_level_ > MinZoomLevel; }

    /**
     * Pushes the application font and every captured per-class font again,
     * and notifies all widgets, even when the application font did not
     * change.  Needed after QApplication::setStyle(), which rebuilds Qt's
     * per-class font table from the platform theme.
     */
    void reapplyApplicationFonts();

signals:
    /** The regular font changed (theme load excepted — see class docs). */
    void applicationFontChanged(QFont font);
    /** The monospace font changed (theme load excepted). */
    void monospaceFontChanged(QFont font);
    /** The zoom level changed.  ThemeManager turns this into a themeChanged so
     *  stylesheet-driven widgets reload their zoom-scaled stylesheets. */
    void zoomChanged();

protected:
    explicit FontManager(QObject *parent = nullptr);
    ~FontManager();

    // Catches two events on qApp.
    //
    // QEvent::ThemeChange: Qt sends it after a platform theme change (an OS
    // font change, but also a light/dark switch).  The system general font is
    // re-read and, when it differs from the last value seen and no theme/pref
    // overrides regular, adopted as the new base regular font.
    //
    // QEvent::ApplicationFontChange: a third-party QApplication::setFont()
    // call.  Distinguishes our own push from it by comparing the now-current
    // qApp->font() against applicationFont() (the value we would push): when
    // they match the change is ours and is ignored; when they differ the
    // font is adopted (unless a theme/pref overrides regular).
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    static FontManager *instance_;
    static QMutex       mutex_;

    QFont     base_regular_;
    QFont     base_monospace_;
    int       zoom_level_ = 0;
    ZoomScope zoom_scope_;

    // True when a theme or pref explicitly set the regular font; while set,
    // an external OS font change is NOT adopted (our override wins).
    bool regular_overridden_ = false;

    // System general font at construction.  While base_regular_ equals it,
    // the captured class fonts are used as they are (see classFont()).
    QFont base_platform_general_;
    // System general font as last seen by the QEvent::ThemeChange handler.
    QFont last_system_general_;
    // Per-class fonts the platform defined (hash key, font), captured in the
    // constructor before the first QApplication::setFont(), which discards
    // them.  Only keys the platform actually set are listed.
    QList<QPair<QByteArray, QFont>> base_class_fonts_;

    /// Adopts @p font as the base regular font, re-pushes fonts and notifies.
    void adoptRegularFont(const QFont &font);

    QFont applicationFont() const;          ///< what gets pushed to QApplication
    QFont zoomed(const QFont &base) const;  ///< base with the zoom factor applied
    /// Unzoomed font for a class whose platform font is @p platformClass.
    QFont classFont(const QFont &platformClass) const;
    /// Push applicationFont() onto qApp when it differs (or always when
    /// @p force), then the per-class fonts, then notify all widgets.
    void  applyApplicationFont(bool force = false);
    void  applyZoom();                      ///< re-push + emit after a zoom change
    void  syncMonospacePref();              ///< mirror base_monospace_ into prefs.gui_font_name
};

#endif /* FONT_MANAGER_H */
