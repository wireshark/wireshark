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

#include <QFont>
#include <QMutex>
#include <QObject>

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
 *   - the OS changing the system font (caught via QEvent::ApplicationFontChange).
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
     *  level 0).  Use to scale sizes that are not expressed as a QFont — e.g.
     *  absolute font sizes baked into a stylesheet. */
    static qreal zoomFactor();

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
     * when set; otherwise @p fontName; otherwise the system fixed font.  The
     * result is guaranteed to be fixed-pitch.  Emits monospaceFontChanged when
     * the resolved font actually changes.
     *
     * @param fontName  font descriptor, or empty.
     */
    void setMonospaceFont(const QString &fontName);

    void zoomIn();
    void zoomOut();
    void resetZoom();
    void setZoomLevel(int level);
    int  zoomLevel() const { return zoom_level_; }

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

    // Catches QEvent::ApplicationFontChange on qApp.  Distinguishes our own
    // push from an external/OS change by comparing the now-current
    // qApp->font() against applicationFont() (the value we would push): when
    // they match the change is ours and is ignored; when they differ the OS
    // changed the font and we adopt it (unless a theme/pref overrides regular).
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

    QFont applicationFont() const;          ///< what gets pushed to QApplication
    QFont zoomed(const QFont &base) const;  ///< base with the zoom factor applied
    void  applyApplicationFont();           ///< push applicationFont() onto qApp
    void  applyZoom();                      ///< re-push + emit after a zoom change
    void  syncMonospacePref();              ///< mirror base_monospace_ into prefs.gui_font_name

    static QFont fontFromName(const QString &name);  ///< fromString() or bare family
    static QFont guaranteeMonospace(const QFont &font);
};

#endif /* FONT_MANAGER_H */
