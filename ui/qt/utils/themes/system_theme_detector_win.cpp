/* system_theme_detector_win.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Windows back-end for SystemThemeDetector.
 *
 * Read:    HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize
 *          \AppsUseLightTheme (REG_DWORD; 0 = dark, 1 = light).  Missing
 *          key (pre-Windows 10 1809 / older server SKUs / Windows 7) is
 *          treated as Light — those systems have no app-level dark mode.
 *
 * Observe: WM_SETTINGCHANGE with lParam == L"ImmersiveColorSet", caught
 *          via QAbstractNativeEventFilter so we do not depend on any
 *          Qt-internal color-scheme detection.
 *
 * Threading: the native event filter runs on the Qt main (message-pump)
 * thread, so schemeChanged is emitted directly without marshaling.
 */

#include "ui/qt/utils/themes/system_theme_detector.h"

#include <QAbstractNativeEventFilter>
#include <QByteArray>
#include <QCoreApplication>

#include <windows.h>
#include <winreg.h>

#include <cwchar>

namespace {

SystemThemeDetector::Scheme readCurrent()
{
    HKEY key = nullptr;
    LONG rc = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        0, KEY_READ, &key);
    if (rc != ERROR_SUCCESS)
        return SystemThemeDetector::Scheme::Light;

    DWORD value = 1;
    DWORD size  = sizeof(value);
    DWORD type  = 0;
    rc = RegQueryValueExW(key, L"AppsUseLightTheme", nullptr,
                          &type, reinterpret_cast<LPBYTE>(&value), &size);
    RegCloseKey(key);

    if (rc != ERROR_SUCCESS || type != REG_DWORD)
        return SystemThemeDetector::Scheme::Unknown;

    return value == 0 ? SystemThemeDetector::Scheme::Dark
                      : SystemThemeDetector::Scheme::Light;
}

class WinThemeFilter : public QAbstractNativeEventFilter
{
public:
    WinThemeFilter(SystemThemeDetector *owner,
                   SystemThemeDetector::Scheme *cached)
        : owner_(owner), cached_(cached)
    {
    }

    bool nativeEventFilter(const QByteArray &eventType,
                           void *message,
                           qintptr * /*result*/) override
    {
        if (eventType != "windows_generic_MSG")
            return false;

        const MSG *msg = static_cast<const MSG *>(message);
        if (msg->message != WM_SETTINGCHANGE)
            return false;

        // lParam on WM_SETTINGCHANGE is a wide-character string naming
        // the area that changed.  For the light/dark toggle it is
        // "ImmersiveColorSet"; the same area is also broadcast on
        // accent-color / transparency changes, which our readCurrent()
        // guard tolerates by only emitting on a genuine transition.
        const wchar_t *area = reinterpret_cast<const wchar_t *>(msg->lParam);
        if (!area || std::wcscmp(area, L"ImmersiveColorSet") != 0)
            return false;

        const SystemThemeDetector::Scheme now = readCurrent();
        if (now != *cached_) {
            *cached_ = now;
            emit owner_->schemeChanged(now);
        }
        // Return false so Qt's own handlers (and any other installed
        // filter) still receive the broadcast.
        return false;
    }

private:
    SystemThemeDetector        *owner_;
    SystemThemeDetector::Scheme *cached_;
};

} // namespace

struct SystemThemeDetector::Impl {
    Scheme          cached = Scheme::Unknown;
    WinThemeFilter *filter = nullptr;

    explicit Impl(SystemThemeDetector *owner)
    {
        cached = readCurrent();
        filter = new WinThemeFilter(owner, &cached);
        if (QCoreApplication *app = QCoreApplication::instance())
            app->installNativeEventFilter(filter);
    }

    ~Impl()
    {
        if (filter) {
            if (QCoreApplication *app = QCoreApplication::instance())
                app->removeNativeEventFilter(filter);
            delete filter;
            filter = nullptr;
        }
    }
};

SystemThemeDetector::SystemThemeDetector(QObject *parent)
    : QObject(parent),
      impl_(new Impl(this))
{
}

SystemThemeDetector::~SystemThemeDetector() = default;

SystemThemeDetector::Scheme SystemThemeDetector::currentScheme() const
{
    return impl_ ? impl_->cached : Scheme::Unknown;
}
