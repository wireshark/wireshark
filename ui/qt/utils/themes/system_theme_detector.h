/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SYSTEM_THEME_DETECTOR_H
#define SYSTEM_THEME_DETECTOR_H

#include <QObject>
#include <QScopedPointer>

/**
 * Platform-native detector for the OS-level light/dark preference.
 *
 * Owned and operated exclusively by ThemeManager.  No other component
 * in Wireshark should construct, query, or connect to a detector
 * instance; everything outside the theme subsystem asks
 * ThemeManager::isDark() instead.
 *
 * The detector begins observing the system setting in its constructor
 * and tears the observer down in its destructor (RAII).  There is
 * deliberately no start()/stop() pair.
 *
 * The actual observation mechanism is platform-specific.  A concrete
 * Impl is provided per platform in
 *   ui/qt/utils/themes/system_theme_detector_mac.mm    (macOS)
 *   ui/qt/utils/themes/system_theme_detector_win.cpp   (Windows)
 *   ui/qt/utils/themes/system_theme_detector_unix.cpp  (Linux/BSD)
 *   ui/qt/utils/themes/system_theme_detector_stub.cpp  (all other builds)
 *
 * CMake selects exactly one of those for the build.
 */
class SystemThemeDetector : public QObject
{
    Q_OBJECT
public:
    enum class Scheme {
        Unknown,    ///< Internal sentinel for "native query returned no value
                    ///< yet" — every back-end resolves this to a concrete
                    ///< Light or Dark before caching, using the per-system
                    ///< startup calibration of what the desktop's
                    ///< "default"/no-preference scheme renders as.
                    ///< currentScheme() therefore never returns Unknown
                    ///< unless impl_ is null (a degenerate construction
                    ///< failure).
        Light,
        Dark,
        Invalid     ///< A particular detection source could not be read, so
                    ///< the next source should be tried.  Internal to the
                    ///< platform back-ends; currentScheme() never returns it.
    };
    Q_ENUM(Scheme)

    explicit SystemThemeDetector(QObject *parent = nullptr);
    ~SystemThemeDetector();

    /**
     * Current OS-level preference, always resolved to Light or Dark.
     * Cached value returned synchronously; safe to call from any thread
     * that can touch the detector.
     */
    Scheme currentScheme() const;

    /**
     * Calibrates "what does this system render the desktop's
     * default/no-preference scheme as?" from the pristine OS palette.
     * Each back-end calls this from its Impl ctor (while the palette is
     * still untouched by any theme override) and stores the result in a
     * defaultIsDark field that resolveDefault() consults.
     *
     * Defined here so every back-end resolves "default" the same way
     * without each one having to pull in QGuiApplication and ColorMath
     * directly — the implementation lives in
     * `system_theme_detector_common.cpp`.
     */
    static bool calibrateDefaultIsDark();

    /**
     * Maps a raw native reading onto a concrete scheme.  Unknown becomes
     * Light or Dark according to @p defaultIsDark (the per-system
     * calibration from calibrateDefaultIsDark()).  Light/Dark readings
     * pass through unchanged so explicit OS preferences are honored
     * verbatim.
     *
     * Used by every back-end so they all collapse the "no preference"
     * case the same way; currentScheme() therefore never surfaces
     * Unknown to callers.
     */
    static Scheme resolveDefault(Scheme s, bool defaultIsDark);

signals:
    /**
     * Emitted when the OS preference transitions between Light and
     * Dark.  Suppressed for no-op re-reads.  Always delivered on the
     * main (GUI) thread.
     */
    void schemeChanged(Scheme scheme);

private:
    struct Impl;
    QScopedPointer<Impl> impl_;
};

#endif /* SYSTEM_THEME_DETECTOR_H */
