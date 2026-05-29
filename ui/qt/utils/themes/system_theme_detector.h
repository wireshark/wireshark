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
        Unknown,    ///< The platform could not determine a preference (stub
                    ///< back-end, or a native query that returned no value);
                    ///< ThemeManager then classifies the OS palette luminance.
                    ///< The Unix back-end resolves the desktop's "default"/
                    ///< no-preference scheme to a concrete Light/Dark value
                    ///< internally, so it does not surface Unknown for that.
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
     * Current OS-level preference.  Cached value returned synchronously;
     * safe to call from any thread that can touch the detector.
     */
    Scheme currentScheme() const;

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
