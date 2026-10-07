/* software_update_backend_linux.cpp
 *
 * On Linux we do not query our own servers. Instead PackageKit is asked
 * whether the distribution offers an update for the package that installed
 * the running executable. Self-compiled builds are not owned by any package
 * and never report updates.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

/*
 * PackageKit 1.1.x (e.g. RHEL 8) still declared the packagekit-glib2 API as
 * unstable, and packagekit.h stops with an #error unless the caller defines
 * I_KNOW_THE_PACKAGEKIT_GLIB2_API_IS_SUBJECT_TO_CHANGE. Starting with 1.2.0
 * the API is considered stable and the check is gone. The version has to
 * come from CMake: PK_CHECK_VERSION lives in pk-version.h, which can only be
 * included through packagekit.h, after the check already happened.
 */
#ifdef PACKAGEKIT_REQUIRES_API_ACK
#define I_KNOW_THE_PACKAGEKIT_GLIB2_API_IS_SUBJECT_TO_CHANGE
#endif

/* Must come before any Qt header, gio uses "signals" as an identifier */
#include <packagekit-glib2/packagekit.h>

#include "app/application_flavor.h"

#include "ui/qt/utils/software_update_backend.h"
#include "ui/qt/utils/software_update.h"

#include <QCoreApplication>
#include <QDesktopServices>

// ponytail: async callbacks are delivered through the GLib main context, which
// Qt drives on Linux by default. Running with QT_NO_GLIB=1 silences update checks.
class PackageKitUpdateBackend : public SoftwareUpdateBackend
{
public:
    PackageKitUpdateBackend() :
        client_(pk_client_new()),
        cancellable_(g_cancellable_new())
    {}

    ~PackageKitUpdateBackend() override
    {
        g_cancellable_cancel(cancellable_);
        g_object_unref(cancellable_);
        g_object_unref(client_);
    }

    QString info() const override
    {
        return QString("PackageKit %1.%2.%3").arg(PK_MAJOR_VERSION).arg(PK_MINOR_VERSION).arg(PK_MICRO_VERSION);
    }

    /* Updates come from the distribution, never from our servers */
    bool supportsAppcast() const override { return false; }

    void init(const QUrl &, bool) override
    {
        /* Find the installed package that owns our executable */
        QByteArray exePath = QCoreApplication::applicationFilePath().toUtf8();
        gchar *values[] = { exePath.data(), NULL };
        pk_client_search_files_async(client_, pk_bitfield_value(PK_FILTER_ENUM_INSTALLED), values,
                                     cancellable_, NULL, NULL, &PackageKitUpdateBackend::onSearchFilesFinished, this);
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
        /* The callback of a cancelled query must not touch the backend (it
         * may already be gone), so the in-flight state is reset here instead.
         * A fresh cancellable keeps the backend usable; a cancelled one stays
         * cancelled and g_cancellable_reset() is undefined while in use. */
        g_cancellable_cancel(cancellable_);
        g_object_unref(cancellable_);
        cancellable_ = g_cancellable_new();
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
        pk_client_get_updates_async(client_, pk_bitfield_value(PK_FILTER_ENUM_NONE),
                                    cancellable_, NULL, NULL, &PackageKitUpdateBackend::onGetUpdatesFinished, this);
        return true;
    }

private:
    PkClient *client_;
    GCancellable *cancellable_;
    QString packageName_; /**< Empty if the executable is not owned by a package. */
    bool checkRunning_ = false; /**< A get-updates query is in flight. */

    /**
     * @brief Finish an async PackageKit call and return its packages.
     * @param packages Set to the packages, or nullptr if the call failed.
     *                 The caller owns the returned array.
     * @return false if the call was cancelled. The backend may already be
     *         gone then and must not be touched.
     */
    static bool finishPackages(GObject *source, GAsyncResult *res, GPtrArray **packages)
    {
        GError *error = NULL;
        PkResults *results = pk_client_generic_finish(PK_CLIENT(source), res, &error);
        *packages = nullptr;
        if (!results) {
            bool cancelled = g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
            if (!cancelled) {
                qWarning("SoftwareUpdate: PackageKit: %s", error->message);
            }
            g_error_free(error);
            return !cancelled;
        }
        *packages = pk_results_get_package_array(results);
        g_object_unref(results);
        return true;
    }

    static void onSearchFilesFinished(GObject *source, GAsyncResult *res, gpointer user_data)
    {
        GPtrArray *packages;
        if (!finishPackages(source, res, &packages) || !packages) {
            return;
        }

        if (packages->len > 0) {
            PkPackage *package = PK_PACKAGE(g_ptr_array_index(packages, 0));
            static_cast<PackageKitUpdateBackend *>(user_data)->packageName_ = pk_package_get_name(package);
        }
        g_ptr_array_unref(packages);
    }

    static void onGetUpdatesFinished(GObject *source, GAsyncResult *res, gpointer user_data)
    {
        GPtrArray *packages;
        if (!finishPackages(source, res, &packages)) {
            return;
        }

        PackageKitUpdateBackend *backend = static_cast<PackageKitUpdateBackend *>(user_data);
        backend->checkRunning_ = false;
        if (!packages) {
            return;
        }

        const QString packageName = backend->packageName_;
        for (unsigned i = 0; i < packages->len; i++) {
            PkPackage *package = PK_PACKAGE(g_ptr_array_index(packages, i));
            if (packageName == pk_package_get_name(package)) {
                emit SoftwareUpdate::instance()->updateAvailable(pk_package_get_version(package), QString());
                break;
            }
        }
        g_ptr_array_unref(packages);
    }
};

SoftwareUpdateBackend *SoftwareUpdateBackend::create()
{
    return new PackageKitUpdateBackend();
}
