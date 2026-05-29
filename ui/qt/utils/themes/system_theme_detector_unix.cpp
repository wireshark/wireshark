/* system_theme_detector_unix.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Linux/BSD back-end for SystemThemeDetector.  No Qt color-scheme
 * detection is used; we ask the desktop directly.
 *
 * Primary (live): XDG Desktop Portal
 *     service   = org.freedesktop.portal.Desktop
 *     path      = /org/freedesktop/portal/desktop
 *     interface = org.freedesktop.portal.Settings
 *     Read(namespace=org.freedesktop.appearance, key=color-scheme) -> uint
 *         0 = no preference, 1 = prefer dark, 2 = prefer light
 *     SettingChanged signal fires on user-initiated changes.
 *
 * Fallback (startup only):
 *     - gsettings get org.gnome.desktop.interface color-scheme
 *     - kreadconfig6 / kreadconfig5 --group General --key ColorScheme
 *
 * Ultimate fallback: Light.
 *
 * Build variants:
 *   QT_DBUS_LIB defined  -> portal + SettingChanged live updates, with
 *                           GSettings/KDE as startup fallbacks.
 *   QT_DBUS_LIB absent   -> GSettings/KDE startup detection only; no
 *                           live updates.  User must restart the app
 *                           after a system theme change.
 */

#include <config.h>

#include "ui/qt/utils/themes/system_theme_detector.h"

#include <ui/qt/utils/themes/color_math.h>

#include <QByteArray>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QPalette>
#include <QProcess>
#include <QString>

#ifdef QT_DBUS_LIB
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDBusInterface>
#include <QDBusReply>
#include <QDBusVariant>
#endif

namespace {

#ifdef QT_DBUS_LIB
constexpr const char *kPortalService    = "org.freedesktop.portal.Desktop";
constexpr const char *kPortalPath       = "/org/freedesktop/portal/desktop";
constexpr const char *kSettingsIface    = "org.freedesktop.portal.Settings";
constexpr const char *kAppearanceNs     = "org.freedesktop.appearance";
constexpr const char *kColorSchemeKey   = "color-scheme";
constexpr const char *kSettingChangedSig = "SettingChanged";

SystemThemeDetector::Scheme classifyPortalValue(uint v)
{
    switch (v) {
    case 1: return SystemThemeDetector::Scheme::Dark;
    case 2: return SystemThemeDetector::Scheme::Light;
    default: return SystemThemeDetector::Scheme::Unknown;  // 0 = no preference
    }
}

SystemThemeDetector::Scheme readViaPortal()
{
    QDBusInterface iface(
        QLatin1String(kPortalService),
        QLatin1String(kPortalPath),
        QLatin1String(kSettingsIface),
        QDBusConnection::sessionBus());

    if (!iface.isValid())
        return SystemThemeDetector::Scheme::Invalid;

    QDBusReply<QDBusVariant> reply = iface.call(
        QStringLiteral("Read"),
        QLatin1String(kAppearanceNs),
        QLatin1String(kColorSchemeKey));

    if (!reply.isValid())
        return SystemThemeDetector::Scheme::Invalid;

    // A successful read is authoritative — value 0 ("no preference") becomes
    // Unknown, not Invalid, so the caller stops here instead of falling
    // through to the theme-name heuristics.
    return classifyPortalValue(reply.value().variant().toUInt());
}

bool portalAvailable()
{
    auto *iface = QDBusConnection::sessionBus().interface();
    return iface && iface->isServiceRegistered(QLatin1String(kPortalService));
}
#endif // QT_DBUS_LIB

// Map a raw reading onto a concrete scheme.  "No preference" (Unknown) becomes
// Light or Dark according to defaultIsDark — the per-system calibration of what
// the desktop's "default" scheme actually renders as, captured at startup.
// Light/Dark readings pass through unchanged so explicit prefer-light/prefer-
// dark preferences are always honored verbatim.
SystemThemeDetector::Scheme resolveDefault(SystemThemeDetector::Scheme s, bool defaultIsDark)
{
    if (s == SystemThemeDetector::Scheme::Unknown)
        return defaultIsDark ? SystemThemeDetector::Scheme::Dark
                             : SystemThemeDetector::Scheme::Light;
    return s;
}

SystemThemeDetector::Scheme readViaGSettings()
{
    // Shell out to gsettings rather than linking against gio directly;
    // Wireshark already transitively depends on glib but this keeps the
    // detector self-contained and avoids pulling Gio symbols into this
    // translation unit.  The call is a one-shot at startup, so the
    // process spawn cost is negligible.
    QProcess p;
    p.start(QStringLiteral("gsettings"), QStringList{
        QStringLiteral("get"),
        QStringLiteral("org.gnome.desktop.interface"),
        QStringLiteral("color-scheme")
    });
    if (!p.waitForFinished(500))
        return SystemThemeDetector::Scheme::Invalid;
    if (p.exitStatus() != QProcess::NormalExit || p.exitCode() != 0)
        return SystemThemeDetector::Scheme::Invalid;

    // Output is a single quoted string, e.g. "'prefer-dark'\n".  "default" is
    // a real preference ("no preference") and maps to Unknown so callers stop
    // here; anything unrecognised means the key is unusable -> Invalid.
    const QString out = QString::fromUtf8(p.readAllStandardOutput()).trimmed();
    if (out.contains(QStringLiteral("prefer-dark")))
        return SystemThemeDetector::Scheme::Dark;
    if (out.contains(QStringLiteral("prefer-light")))
        return SystemThemeDetector::Scheme::Light;
    if (out.contains(QStringLiteral("default")))
        return SystemThemeDetector::Scheme::Unknown;
    return SystemThemeDetector::Scheme::Invalid;
}

SystemThemeDetector::Scheme readViaKDE()
{
    // kreadconfig6 on Plasma 6, kreadconfig5 on older installs.  Name-
    // based heuristic for the returned scheme: stock Breeze / BreezeDark
    // names classify correctly; custom-named user schemes may not.  KDE
    // Plasma 5.26+ ships a portal backend that makes this fallback
    // unnecessary on up-to-date systems.
    const QStringList cmds = {
        QStringLiteral("kreadconfig6"),
        QStringLiteral("kreadconfig5")
    };
    for (const QString &cmd : cmds) {
        QProcess p;
        p.start(cmd, QStringList{
            QStringLiteral("--group"), QStringLiteral("General"),
            QStringLiteral("--key"),   QStringLiteral("ColorScheme")
        });
        if (!p.waitForFinished(500))
            continue;
        if (p.exitStatus() != QProcess::NormalExit || p.exitCode() != 0)
            continue;

        const QString name = QString::fromUtf8(p.readAllStandardOutput()).trimmed();
        if (name.isEmpty())
            continue;
        if (name.contains(QStringLiteral("Dark"), Qt::CaseInsensitive))
            return SystemThemeDetector::Scheme::Dark;
        if (name.contains(QStringLiteral("Light"), Qt::CaseInsensitive)
            || name.contains(QStringLiteral("Breeze")))
            return SystemThemeDetector::Scheme::Light;
    }
    return SystemThemeDetector::Scheme::Invalid;
}

// Older GNOME (< 42) has no color-scheme preference; users selected a dark
// variant of a GTK theme (e.g. "Adwaita-dark") instead.  Read the gtk-theme
// name and treat any name that contains "dark" as a dark preference.
// This is startup-only — there is no live signal for gtk-theme changes on
// GNOME 3, but that is acceptable since users on those systems don't switch
// themes dynamically.
SystemThemeDetector::Scheme readViaGTKThemeName()
{
    QProcess p;
    p.start(QStringLiteral("gsettings"), QStringList{
        QStringLiteral("get"),
        QStringLiteral("org.gnome.desktop.interface"),
        QStringLiteral("gtk-theme")
    });
    if (!p.waitForFinished(500))
        return SystemThemeDetector::Scheme::Invalid;
    if (p.exitStatus() != QProcess::NormalExit || p.exitCode() != 0)
        return SystemThemeDetector::Scheme::Invalid;

    const QString name = QString::fromUtf8(p.readAllStandardOutput()).trimmed();
    if (name.contains(QStringLiteral("dark"), Qt::CaseInsensitive))
        return SystemThemeDetector::Scheme::Dark;
    return SystemThemeDetector::Scheme::Invalid;
}

SystemThemeDetector::Scheme readCurrent()
{
    // The freedesktop color-scheme preference is authoritative.  A reported
    // value of "default"/0 maps to Unknown ON PURPOSE: what "default" renders
    // as on this system is decided once at startup by the Impl calibration
    // (resolveDefault + defaultIsDark), so we must NOT second-guess it from
    // GTK/KDE theme *names* here.  The name heuristics are a last resort, used
    // only when no color-scheme preference is exposed at all (pre-color-scheme
    // GNOME, minimal window managers).
#ifdef QT_DBUS_LIB
    // Only touch DBus when the portal is actually on the bus; this keeps
    // desktops without a Settings portal silent (no failed-call warnings).
    if (portalAvailable()) {
        SystemThemeDetector::Scheme s = readViaPortal();
        if (s != SystemThemeDetector::Scheme::Invalid)
            return s;
    }
#endif
    SystemThemeDetector::Scheme s = readViaGSettings();
    if (s != SystemThemeDetector::Scheme::Invalid)
        return s;

    s = readViaGTKThemeName();
    if (s != SystemThemeDetector::Scheme::Invalid)
        return s;
    s = readViaKDE();
    if (s != SystemThemeDetector::Scheme::Invalid)
        return s;

    // Nothing exposed a preference: report Unknown.  The caller resolves this
    // to a concrete scheme via resolveDefault() and the startup calibration.
    return SystemThemeDetector::Scheme::Unknown;
}

} // namespace

#ifdef QT_DBUS_LIB
/*
 * Private QObject that hosts the DBus slot for SettingChanged.  Lives
 * entirely in this translation unit so QDBusVariant etc. do not leak
 * into system_theme_detector.h.  AUTOMOC handles the Q_OBJECT via the
 * trailing .moc include at the bottom of this file.
 */
class PortalWatcher : public QObject
{
    Q_OBJECT
public:
    PortalWatcher(SystemThemeDetector *owner,
                  SystemThemeDetector::Scheme *cached,
                  bool defaultIsDark,
                  QObject *parent = nullptr)
        : QObject(parent), owner_(owner), cached_(cached),
          defaultIsDark_(defaultIsDark)
    {
        QDBusConnection::sessionBus().connect(
            QLatin1String(kPortalService),
            QLatin1String(kPortalPath),
            QLatin1String(kSettingsIface),
            QLatin1String(kSettingChangedSig),
            this,
            SLOT(onSettingChanged(QString,QString,QDBusVariant)));
    }

private slots:
    void onSettingChanged(const QString &nsName,
                          const QString &key,
                          const QDBusVariant &value)
    {
        if (nsName != QLatin1String(kAppearanceNs)
            || key != QLatin1String(kColorSchemeKey))
            return;

        // The signal carries the authoritative value: 1 -> Dark, 2 -> Light,
        // 0 -> "no preference".  resolveDefault() cleans the last case into a
        // concrete Light/Dark using the startup calibration, so subscribers
        // always receive an unambiguous scheme.
        SystemThemeDetector::Scheme now =
            resolveDefault(classifyPortalValue(value.variant().toUInt()),
                           defaultIsDark_);
        if (now != *cached_) {
            *cached_ = now;
            emit owner_->schemeChanged(now);
        }
    }

private:
    SystemThemeDetector         *owner_;
    SystemThemeDetector::Scheme *cached_;
    bool                         defaultIsDark_;
};
#endif // QT_DBUS_LIB

struct SystemThemeDetector::Impl {
    Scheme cached = Scheme::Unknown;
    // What the desktop's "default"/no-preference scheme renders as on THIS
    // system.  Decided once, here, while the application palette is still
    // pristine (ThemeManager constructs the detector before it applies any
    // theme override), so it is never skewed by our own palette.
    bool   defaultIsDark = false;
#ifdef QT_DBUS_LIB
    PortalWatcher *watcher = nullptr;
#endif

    explicit Impl(SystemThemeDetector *owner)
    {
        // Calibrate "default": an explicit prefer-dark/prefer-light at startup
        // wins outright; only a genuine "no preference" falls back to the
        // luminance of the pristine OS palette.  This covers styles whose
        // palette does not track the OS scheme (e.g. Fusion stays light even
        // in an OS dark setup) — there the explicit preference is trusted.
        const Scheme initial = readCurrent();
        if (initial == Scheme::Dark)
            defaultIsDark = true;
        else if (initial == Scheme::Light)
            defaultIsDark = false;
        else
            defaultIsDark = ColorMath::isDark(
                QGuiApplication::palette().color(QPalette::Window));

        cached = resolveDefault(initial, defaultIsDark);
#ifdef QT_DBUS_LIB
        // Only install the portal watcher if the portal service is
        // actually on the bus.  Without a backend we get no live
        // updates — that is documented behavior on non-portal setups.
        if (portalAvailable())
            watcher = new PortalWatcher(owner, &cached, defaultIsDark, owner);
#else
        Q_UNUSED(owner);
#endif
    }

    ~Impl()
    {
#ifdef QT_DBUS_LIB
        // watcher is parented to the owner; Qt deletes it with the
        // owner.  Clearing the pointer here is defensive.
        watcher = nullptr;
#endif
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

#ifdef QT_DBUS_LIB
#include "system_theme_detector_unix.moc"
#endif
