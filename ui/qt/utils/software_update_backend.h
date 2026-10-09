/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SOFTWARE_UPDATE_BACKEND_H
#define SOFTWARE_UPDATE_BACKEND_H

#include <QString>
#include <QUrl>

/**
 * Platform-specific part of the software update handling.
 *
 * Owned and operated exclusively by SoftwareUpdate. Backends report back
 * through the SoftwareUpdate signals.
 *
 * A concrete backend is provided per platform in
 *   ui/qt/utils/software_update_backend_win.cpp    (Windows, WinSparkle)
 *   ui/qt/utils/software_update_backend_mac.cpp    (macOS, Sparkle)
 *   ui/qt/utils/software_update_backend_linux.cpp  (Linux, PackageKit)
 *   ui/qt/utils/software_update_backend_stub.cpp   (no update support)
 *
 * CMake selects exactly one of those for the build.
 */
class SoftwareUpdateBackend
{
public:
    /**
     * @brief Create the backend for this platform.
     * @return A new backend, or nullptr if software updates are not supported.
     */
    static SoftwareUpdateBackend *create();

    virtual ~SoftwareUpdateBackend() = default;

    /**
     * @brief Name of the update framework, shown in the feature list.
     */
    virtual QString info() const = 0;

    /**
     * @brief Whether updates come from our appcast servers.
     *
     * Must be decided explicitly by every backend. Backends returning false
     * (e.g. distribution package managers) never cause a request to our servers.
     */
    virtual bool supportsAppcast() const = 0;

    /**
     * @brief OS name used for the appcast URL and the appcast "os" filter.
     *
     * Only used if supportsAppcast() returns true.
     */
    virtual QString osName() const { return QString(); }

    /**
     * @brief Initialize the update framework.
     * @param appcastUrl            The appcast feed URL, empty if
     *                              supportsAppcast() returns false.
     * @param runWithoutSilentCheck See SoftwareUpdate::init().
     */
    virtual void init(const QUrl &appcastUrl, bool runWithoutSilentCheck) = 0;

    /**
     * @brief Start the user-visible update process.
     */
    virtual void performUIUpdate() = 0;

    /**
     * @brief Release resources held by the update framework.
     */
    virtual void cleanup() {}

    /**
     * @brief Run a background update check through the platform mechanism.
     *
     * This function is called by SoftwareUpdate to check for updates.
     * Backends that handle updates themselves (PackageKit on Linux) should return true.
     * Backends that rely on the appcast (Windows, Apple) should return false. Note
     * that for AppCast to work, server updates are required supporting the appcast format.
     *
     * @return true if the backend handles the check itself, false if
     *         SoftwareUpdate should query the appcast feed instead.
     *         Ignored for backends that do not support the appcast.
     */
    virtual bool checkForUpdates() { return false; }
};

#endif /* SOFTWARE_UPDATE_BACKEND_H */
