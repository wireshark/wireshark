/* software_update_backend_linux.cpp
 *
 * On Linux we do not query our own servers. Instead PackageKit is asked
 * whether the distribution offers an update for the package that installed
 * the running executable. Self-compiled builds are not owned by any package
 * and never report updates.
 *
 * PackageKit is talked to directly over D-Bus instead of through
 * packagekit-glib2, which would drag gobject/gio into the link.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "app/application_flavor.h"

#include "ui/qt/utils/software_update_backend.h"
#include "ui/qt/utils/software_update.h"

/* CMake only selects this backend with Qt DBus, guard anyway */
#ifdef QT_DBUS_LIB

#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusObjectPath>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDesktopServices>

#include <functional>

namespace {

constexpr const char *kPkService = "org.freedesktop.PackageKit";
constexpr const char *kPkPath = "/org/freedesktop/PackageKit";
constexpr const char *kPkIface = "org.freedesktop.PackageKit";
constexpr const char *kPkTransactionIface = "org.freedesktop.PackageKit.Transaction";

/* PkFilterEnum values as bitfield (1 << enum), see pk-enum.h */
constexpr qulonglong kPkFilterNone = 1ULL << 1;
constexpr qulonglong kPkFilterInstalled = 1ULL << 2;

/* A package id is "name;version;arch;data" */
QString packageIdPart(const QString &packageId, int part)
{
    return packageId.section(';', part, part);
}

} // namespace

/**
 * One PackageKit transaction: creates it, runs a single method on it and
 * collects the package ids it reports. Deletes itself once finished.
 * finished is called exactly once, with the packages reported so far, also
 * if the transaction failed.
 */
class PackageKitTransaction : public QObject
{
    Q_OBJECT

public:
    PackageKitTransaction(QObject *parent, const QString &method, const QVariantList &args,
                          std::function<void(const QStringList &)> finished) :
        QObject(parent),
        method_(method),
        args_(args),
        finished_(std::move(finished))
    {
        QDBusMessage msg = QDBusMessage::createMethodCall(kPkService, kPkPath, kPkIface, "CreateTransaction");
        watch(QDBusConnection::systemBus().asyncCall(msg), &PackageKitTransaction::onCreated);
    }

private slots:
    void onPackage(uint, const QString &packageId, const QString &)
    {
        packageIds_ << packageId;
    }

    void onErrorCode(uint, const QString &details)
    {
        qWarning("SoftwareUpdate: PackageKit: %s", qPrintable(details));
    }

    void onFinished(uint, uint)
    {
        finish();
    }

private:
    QString method_;
    QVariantList args_;
    std::function<void(const QStringList &)> finished_;
    QStringList packageIds_;
    bool done_ = false;

    void watch(const QDBusPendingCall &call, void (PackageKitTransaction::*handler)(QDBusPendingCallWatcher *))
    {
        QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(call, this);
        connect(watcher, &QDBusPendingCallWatcher::finished, this, handler);
    }

    /* Reports D-Bus errors and finishes the transaction on failure */
    bool failed(QDBusPendingCallWatcher *watcher)
    {
        watcher->deleteLater();
        if (!watcher->isError()) {
            return false;
        }
        qWarning("SoftwareUpdate: PackageKit: %s", qPrintable(watcher->error().message()));
        finish();
        return true;
    }

    void onCreated(QDBusPendingCallWatcher *watcher)
    {
        if (failed(watcher)) {
            return;
        }
        const QString path = QDBusPendingReply<QDBusObjectPath>(*watcher).value().path();

        /* Signals must be connected before the method runs or results may be missed */
        QDBusConnection bus = QDBusConnection::systemBus();
        bus.connect(kPkService, path, kPkTransactionIface, "Package", this, SLOT(onPackage(uint,QString,QString)));
        bus.connect(kPkService, path, kPkTransactionIface, "ErrorCode", this, SLOT(onErrorCode(uint,QString)));
        bus.connect(kPkService, path, kPkTransactionIface, "Finished", this, SLOT(onFinished(uint,uint)));

        QDBusMessage msg = QDBusMessage::createMethodCall(kPkService, path, kPkTransactionIface, method_);
        msg.setArguments(args_);
        watch(bus.asyncCall(msg), &PackageKitTransaction::onStarted);
    }

    void onStarted(QDBusPendingCallWatcher *watcher)
    {
        /* Results arrive through the signals; only failures matter here */
        failed(watcher);
    }

    void finish()
    {
        if (done_) {
            return;
        }
        done_ = true;
        finished_(packageIds_);
        deleteLater();
    }
};

// ponytail: in-flight transactions are dropped, not cancelled on the daemon.
// They are read-only queries, so letting them run to completion is harmless.
class PackageKitUpdateBackend : public SoftwareUpdateBackend
{
public:
    QString info() const override
    {
        return QStringLiteral("PackageKit");
    }

    /* Updates come from the distribution, never from our servers */
    bool supportsAppcast() const override { return false; }

    void init(const QUrl &, bool) override
    {
        /* Find the installed package that owns our executable */
        const QVariantList args { kPkFilterInstalled, QStringList { QCoreApplication::applicationFilePath() } };
        new PackageKitTransaction(&transactions_, "SearchFiles", args, [this](const QStringList &packageIds) {
            if (!packageIds.isEmpty()) {
                packageName_ = packageIdPart(packageIds.first(), 0);
            }
        });
    }

    /* PackageKit is only used for checking. Installing is left to the
     * desktop's software center (GNOME Software, KDE Discover, ...). */
    void performUIUpdate() override
    {
        QUrl url(QString("appstream://org.wireshark.%1").arg(application_flavor_name_proper()));
        if (!QDesktopServices::openUrl(url)) {
            qWarning("SoftwareUpdate: no software center handles %s", qPrintable(url.toString()));
        }
    }

    void cleanup() override
    {
        /* Deleting the transactions disconnects them, no callback touches us afterwards */
        const QObjectList transactions = transactions_.children();
        qDeleteAll(transactions);
        checkRunning_ = false;
    }

    bool checkForUpdates() override
    {
        /* Unknown or self-compiled: nothing to ask PackageKit about.
         * A query still in flight is not started a second time. */
        if (packageName_.isEmpty() || checkRunning_) {
            return true;
        }

        checkRunning_ = true;
        new PackageKitTransaction(&transactions_, "GetUpdates", { kPkFilterNone }, [this](const QStringList &packageIds) {
            checkRunning_ = false;
            for (const QString &packageId : packageIds) {
                if (packageIdPart(packageId, 0) == packageName_) {
                    emit SoftwareUpdate::instance()->updateAvailable(packageIdPart(packageId, 1), QString());
                    break;
                }
            }
        });
        return true;
    }

private:
    QObject transactions_; /**< Parent of all in-flight transactions. */
    QString packageName_; /**< Empty if the executable is not owned by a package. */
    bool checkRunning_ = false; /**< A get-updates query is in flight. */
};

SoftwareUpdateBackend *SoftwareUpdateBackend::create()
{
    return new PackageKitUpdateBackend();
}

#include "software_update_backend_linux.moc"

#else /* QT_DBUS_LIB */

SoftwareUpdateBackend *SoftwareUpdateBackend::create()
{
    return nullptr;
}

#endif /* QT_DBUS_LIB */
