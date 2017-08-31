/* wireshark_application.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

// warning C4267: 'argument' : conversion from 'size_t' to 'int', possible loss of data
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4267)
#endif

#include "wireshark_application.h"

#include <algorithm>
#include <errno.h>

#include "wsutil/filesystem.h"

#include "epan/addr_resolv.h"
#include "epan/disabled_protos.h"
#include "epan/ftypes/ftypes.h"
#include "epan/prefs.h"
#include "epan/proto.h"
#include "epan/tap.h"
#include "epan/timestamp.h"
#include "epan/decode_as.h"

#include "ui/decode_as_utils.h"
#include "ui/preference_utils.h"
#include "ui/iface_lists.h"
#include "ui/language.h"
#include "ui/recent.h"
#include "ui/simple_dialog.h"
#include "ui/util.h"

#include "qt_ui_utils.h"
#include "color_utils.h"
#include "coloring_rules_dialog.h"

#include "epan/color_filters.h"
#include "log.h"
#include "recent_file_status.h"

#ifdef HAVE_EXTCAP
#include "extcap.h"
#endif
#ifdef HAVE_LIBPCAP
#include <caputils/iface_monitor.h>
#endif

#include "ui/capture.h"
#include "ui/filter_files.h"
#include "ui/capture_globals.h"
#include "ui/software_update.h"
#include "ui/last_open_dir.h"
#include "ui/recent_utils.h"

#include "wsutil/utf8_entities.h"

#ifdef _WIN32
#  include "ui/win32/console_win32.h"
#  include "wsutil/file_util.h"
#  include <QMessageBox>
#  include <QSettings>
#endif /* _WIN32 */

#include <QAction>
#include <QApplication>
#include <QDesktopServices>
#include <QDir>
#include <QEvent>
#include <QFileOpenEvent>
#include <QFontMetrics>
#include <QFontInfo>
#include <QLibraryInfo>
#include <QLocale>
#include <QMainWindow>
#include <QMutableListIterator>
#include <QSocketNotifier>
#include <QThread>
#include <QUrl>
#include <QColorDialog>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

WiresharkApplication *wsApp = NULL;

// XXX - Copied from ui/gtk/file_dlg.c

// MUST be UTF-8
static char *last_open_dir = NULL;
static QList<recent_item_status *> recent_captures_;
static QHash<int, QList<QAction *> > dynamic_menu_groups_;
static QHash<int, QList<QAction *> > added_menu_groups_;
static QHash<int, QList<QAction *> > removed_menu_groups_;

QString WiresharkApplication::window_title_separator_ = QString::fromUtf8(" " UTF8_MIDDLE_DOT " ");

void
topic_action(topic_action_e action)
{
    if (wsApp) wsApp->helpTopicAction(action);
}

extern "C" char *
get_last_open_dir(void)
{
    return last_open_dir;
}

void
set_last_open_dir(const char *dirname)
{
    if (wsApp) wsApp->setLastOpenDir(dirname);
}

/*
 * Add the capture filename to the application-wide "Recent Files" list.
 * Contrary to the name this isn't limited to the "recent" menu.
 */
/*
 * XXX - We might want to call SHAddToRecentDocs under Windows 7:
 * http://stackoverflow.com/questions/437212/how-do-you-register-a-most-recently-used-list-with-windows-in-preparation-for-win
 */
extern "C" void
add_menu_recent_capture_file(const gchar *cf_name) {
    QString normalized_cf_name = QString::fromUtf8(cf_name);
    QDir cf_path;

    cf_path.setPath(normalized_cf_name);
    normalized_cf_name = cf_path.absolutePath();
    normalized_cf_name = QDir::cleanPath(normalized_cf_name);
    normalized_cf_name = QDir::toNativeSeparators(normalized_cf_name);

    /* Iterate through the recent items list, removing duplicate entries and every
     * item above count_max
     */
    unsigned int cnt = 1;
    QMutableListIterator<recent_item_status *> rii(recent_captures_);
    while (rii.hasNext()) {
        recent_item_status *ri = rii.next();
        /* if this element string is one of our special items (separator, ...) or
         * already in the list or
         * this element is above maximum count (too old), remove it
         */
        if (ri->filename.length() < 1 ||
#ifdef _WIN32
            /* do a case insensitive compare on win32 */
            ri->filename.compare(normalized_cf_name, Qt::CaseInsensitive) == 0 ||
#else   /* _WIN32 */
            /*
             * Do a case sensitive compare on UN*Xes.
             *
             * XXX - on UN*Xes such as macOS, where you can use pathconf()
             * to check whether a given file system is case-sensitive or
             * not, we should check whether this particular file system
             * is case-sensitive and do the appropriate comparison.
             */
            ri->filename.compare(normalized_cf_name) == 0 ||
#endif
            cnt >= prefs.gui_recent_files_count_max) {
            rii.remove();
            delete(ri);
            cnt--;
        }
        cnt++;
    }
    wsApp->addRecentItem(normalized_cf_name, 0, false);
}

/* write all capture filenames of the menu to the user's recent file */
extern "C" void menu_recent_file_write_all(FILE *rf) {

    /* we have to iterate backwards through the children's list,
     * so we get the latest item last in the file.
     */
    QListIterator<recent_item_status *> rii(recent_captures_);
    rii.toBack();
    while (rii.hasPrevious()) {
        QString cf_name;
        /* get capture filename from the menu item label */
        cf_name = rii.previous()->filename;
        if (cf_name != NULL) {
            fprintf (rf, RECENT_KEY_CAPTURE_FILE ": %s\n", cf_name.toUtf8().constData());
        }
    }
}

#ifdef HAVE_SOFTWARE_UPDATE
/** Check to see if Wireshark can shut down safely (e.g. offer to save the
 *  current capture).
 */
extern "C" int software_update_can_shutdown_callback(void) {
    return wsApp->softwareUpdateCanShutdown();
}

/** Shut down Wireshark in preparation for an upgrade.
 */
extern "C" void software_update_shutdown_request_callback(void) {
    wsApp->softwareUpdateShutdownRequest();
}
#endif // HAVE_SOFTWARE_UPDATE

// Check each recent item in a separate thread so that we don't hang while
// calling stat(). This is called periodically because files and entire
// volumes can disappear and reappear at any time.
void WiresharkApplication::refreshRecentCaptures(void) {
    recent_item_status *ri;
    RecentFileStatus *rf_status;

    // We're in the middle of a capture. Don't create traffic.
    if (active_captures_ > 0) return;

    foreach (ri, recent_captures_) {
        if (ri->in_thread) {
            continue;
        }

        rf_status = new RecentFileStatus(ri->filename, this);

        connect(rf_status, SIGNAL(statusFound(QString, qint64, bool)),
                this, SLOT(itemStatusFinished(QString, qint64, bool)), Qt::QueuedConnection);
        connect(rf_status, SIGNAL(finished()), rf_status, SLOT(deleteLater()));
        rf_status->start();
    }
}

void WiresharkApplication::refreshAddressResolution()
{
    // Anything new show up?
    if (host_name_lookup_process()) {
        emit addressResolutionChanged();
    }
}

void WiresharkApplication::updateTaps()
{
    draw_tap_listeners(FALSE);
}

QDir WiresharkApplication::lastOpenDir() {
    return QDir(last_open_dir);
}

void WiresharkApplication::setLastOpenDir(QString *dir_str) {
    setLastOpenDir(dir_str->toUtf8().constData());
}

void WiresharkApplication::helpTopicAction(topic_action_e action)
{
    QString url = gchar_free_to_qstring(topic_action_url(action));

    if(!url.isEmpty()) {
        QDesktopServices::openUrl(QUrl(url));
    }
}

void WiresharkApplication::setMonospaceFont(const char *font_string) {

    if (font_string && strlen(font_string) > 0) {
        mono_font_.fromString(font_string);

        // Only accept the font name if it actually exists.
        if (mono_font_.family() == QFontInfo(mono_font_).family()) {
            return;
        }
    }

    // http://en.wikipedia.org/wiki/Category:Monospaced_typefaces
    const char *win_default_font = "Consolas";
    const char *win_alt_font = "Lucida Console";
    // SF Mono might be a system font someday. Right now (Oct 2016) it appears
    // to be limited to Xcode and Terminal.
    // http://www.openradar.me/26790072
    // http://www.openradar.me/26862220
    const char *osx_default_font = "SF Mono";
    const QStringList osx_alt_fonts = QStringList() << "Menlo" << "Monaco";
    // XXX Detect Ubuntu systems (e.g. via /etc/os-release and/or
    // /etc/lsb_release) and add "Ubuntu Mono Regular" there.
    // http://font.ubuntu.com/
    const char *x11_default_font = "Liberation Mono";
    const QStringList x11_alt_fonts = QStringList() << "DejaVu Sans Mono" << "Bitstream Vera Sans Mono";
    const QStringList fallback_fonts = QStringList() << "Lucida Sans Typewriter" << "Inconsolata" << "Droid Sans Mono" << "Andale Mono" << "Courier New" << "monospace";
    QStringList substitutes;
    int font_size_adjust = 0;

    // Try to pick the latest, shiniest fixed-width font for our OS.
#if defined(Q_OS_WIN)
    const char *default_font = win_default_font;
    substitutes << win_alt_font << osx_default_font << osx_alt_fonts << x11_default_font << x11_alt_fonts << fallback_fonts;
    font_size_adjust = 2;
#elif defined(Q_OS_MAC)
    const char *default_font = osx_default_font;
    substitutes << osx_alt_fonts << win_default_font << win_alt_font << x11_default_font << x11_alt_fonts << fallback_fonts;
#else
    const char *default_font = x11_default_font;
    substitutes << x11_alt_fonts << win_default_font << win_alt_font << osx_default_font << osx_alt_fonts << fallback_fonts;
#endif

    mono_font_.setFamily(default_font);
    mono_font_.insertSubstitutions(default_font, substitutes);
    mono_font_.setPointSize(wsApp->font().pointSize() + font_size_adjust);
    mono_font_.setBold(false);

    // Retrieve the effective font and apply it.
    mono_font_.setFamily(QFontInfo(mono_font_).family());

    g_free(prefs.gui_qt_font_name);
    prefs.gui_qt_font_name = qstring_strdup(mono_font_.toString());
}

int WiresharkApplication::monospaceTextSize(const char *str)
{
    QFontMetrics fm(mono_font_);

    return fm.width(str);
}

void WiresharkApplication::setConfigurationProfile(const gchar *profile_name, bool write_recent)
{
    char  *rf_path;
    int    rf_open_errno;
    gchar *err_msg = NULL;

    /* First check if profile exists */
    if (!profile_exists(profile_name, FALSE)) {
        if (profile_exists(profile_name, TRUE)) {
            char  *pf_dir_path, *pf_dir_path2, *pf_filename;
            /* Copy from global profile */
            if (create_persconffile_profile(profile_name, &pf_dir_path) == -1) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "Can't create directory\n\"%s\":\n%s.",
                    pf_dir_path, g_strerror(errno));

                g_free(pf_dir_path);
            }

            if (copy_persconffile_profile(profile_name, profile_name, TRUE, &pf_filename,
                    &pf_dir_path, &pf_dir_path2) == -1) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "Can't copy file \"%s\" in directory\n\"%s\" to\n\"%s\":\n%s.",
                    pf_filename, pf_dir_path2, pf_dir_path, g_strerror(errno));

                g_free(pf_filename);
                g_free(pf_dir_path);
                g_free(pf_dir_path2);
            }
        } else {
            /* No personal and no global profile exists */
            return;
        }
    }

    /* Then check if changing to another profile */
    if (profile_name && strcmp (profile_name, get_profile_name()) == 0) {
        return;
    }

    /* Get the current geometry, before writing it to disk */
    emit profileChanging();

    if (write_recent && profile_exists(get_profile_name(), FALSE))
    {
        /* Write recent file for profile we are leaving, if it still exists */
        write_profile_recent();
    }

    /* Set profile name and update the status bar */
    set_profile_name (profile_name);
    emit profileNameChanged(profile_name);

    /* Apply new preferences */
    readConfigurationFiles(true);

    if (!recent_read_profile_static(&rf_path, &rf_open_errno)) {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
            "Could not open common recent file\n\"%s\": %s.",
            rf_path, g_strerror(rf_open_errno));
        g_free(rf_path);
    }
    if (recent.gui_fileopen_remembered_dir &&
        test_for_directory(recent.gui_fileopen_remembered_dir) == EISDIR) {
        set_last_open_dir(recent.gui_fileopen_remembered_dir);
    }
    timestamp_set_type(recent.gui_time_format);
    timestamp_set_precision(recent.gui_time_precision);
    timestamp_set_seconds_type (recent.gui_seconds_format);
    packet_list_enable_color(recent.packet_list_colorize);
    tap_update_timer_.setInterval(prefs.tap_update_interval);

    prefs_to_capture_opts();
    prefs_apply_all();
#ifdef HAVE_LIBPCAP
    update_local_interfaces();
#endif

    setMonospaceFont(prefs.gui_qt_font_name);

    emit columnsChanged();
    emit preferencesChanged();
    emit recentPreferencesRead();
    emit filterExpressionsChanged();
    emit checkDisplayFilter();
    emit captureFilterListChanged();
    emit displayFilterListChanged();

    /* Reload color filters */
    if (!color_filters_reload(&err_msg, color_filter_add_cb)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_msg);
        g_free(err_msg);
    }

    emit localInterfaceListChanged();
    emit packetDissectionChanged();
}

void WiresharkApplication::reloadLuaPluginsDelayed()
{
    QTimer::singleShot(0, this, SIGNAL(reloadLuaPlugins()));
}

const QString WiresharkApplication::windowTitleString(QStringList title_parts)
{
    QMutableStringListIterator tii(title_parts);
    while (tii.hasNext()) {
        QString ti = tii.next();
        if (ti.isEmpty()) tii.remove();
    }
    title_parts.prepend(applicationName());
    return title_parts.join(window_title_separator_);
}

void WiresharkApplication::applyCustomColorsFromRecent()
{
    int i = 0;
    bool ok;
    for (GList *custom_color = recent.custom_colors; custom_color; custom_color = custom_color->next) {
        QRgb rgb = QString((const char *)custom_color->data).toUInt(&ok, 16);
        if (ok) {
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
            QColorDialog::setCustomColor(i++, rgb);
#else
            QColorDialog::setCustomColor(i++, QColor(rgb));
#endif
        }
    }
}

// Return the first top-level QMainWindow.
QWidget *WiresharkApplication::mainWindow()
{
    foreach (QWidget *tlw, topLevelWidgets()) {
        QMainWindow *tlmw = qobject_cast<QMainWindow *>(tlw);
        if (tlmw && tlmw->isVisible()) {
            return tlmw;
        }
    }
    return 0;
}

void WiresharkApplication::storeCustomColorsInRecent()
{
    if (QColorDialog::customCount()) {
        prefs_clear_string_list(recent.custom_colors);
        recent.custom_colors = NULL;
        for (int i = 0; i < QColorDialog::customCount(); i++) {
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
            QRgb rgb = QColorDialog::customColor(i);
#else
            QRgb rgb = QColorDialog::customColor(i).rgb();
#endif
            recent.custom_colors = g_list_append(recent.custom_colors, g_strdup_printf("%08x", rgb));
        }
    }
}

#ifdef _WIN32
// Dell Backup and Recovery is awful and terrible.
// https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12036
// https://bugreports.qt.io/browse/QTBUG-41416
// http://en.community.dell.com/support-forums/software-os/f/3526/t/19634253
// http://stackoverflow.com/a/33697140/82195
//
// According to https://www.portraitprofessional.com/support/?qid=79 , which
// points to http://cloudfront.portraitprofessional.com/Tools/unregister_dell_backup.cmd
// DBAR's shell extension DLLs are named DBROverlayIconBackuped.dll,
// DBROverlayIconNotBackuped.dll, and DBRShellExtension.dll.
//
// Look for them in the registry and show a warning if we find any of them.
//
// This is obnoxious, but so is crashing. Hopefully we can remove it at some
// point.

// Returns only the most significant (major + minor) 32 bits of the version number.
unsigned int WiresharkApplication::fileVersion(QString file_path) {
    unsigned int version = 0;
    DWORD gfvi_size = GetFileVersionInfoSize((LPCWSTR) file_path.utf16(), NULL);

    if (gfvi_size == 0) {
        return 0;
    }

    LPSTR version_info = new char[gfvi_size];
    if (GetFileVersionInfo((LPCWSTR) file_path.utf16(), 0, gfvi_size, version_info)) {
        void *vqv_buffer = NULL;
        UINT vqv_size = 0;
        if (VerQueryValue(version_info, TEXT("\\"), &vqv_buffer, &vqv_size)) {
            VS_FIXEDFILEINFO *vqv_fileinfo = (VS_FIXEDFILEINFO *)vqv_buffer;
            if (vqv_size && vqv_buffer && vqv_fileinfo->dwSignature == 0xfeef04bd) {
                version = vqv_fileinfo->dwFileVersionMS;
            }
        }
    }

    delete[] version_info;
    return version;
}

void WiresharkApplication::checkForDbar()
{
    QStringList dbar_dlls = QStringList()
        // << "7-Zip.dll" // For testing. I don't have DBAR.
        // << "shell32.dll"
        << "DBROverlayIconBackuped.dll"
        << "DBROverlayIconNotBackuped.dll"
        << "DBRShellExtension.dll";
    // List of HKCR subkeys in which to look for "shellex\ContextMenuHandlers".
    // This may be incomplete.
    // https://msdn.microsoft.com/en-us/library/windows/desktop/cc144110
    QStringList hkcr_subkeys = QStringList()
        << "*"
        << "AllFileSystemObjects"
        << "Folder"
        << "Directory"
        << "Drive";
    QRegExp uuid_re("^\\{.+\\}");
    QSet<QString> clsids;

    // Look for context menu handler CLSIDs. We might want to skip this and
    // just iterate through all of the CLSID subkeys below.
    foreach (QString subkey, hkcr_subkeys) {
        QString cmh_path = QString("HKEY_CLASSES_ROOT\\%1\\shellex\\ContextMenuHandlers").arg(subkey);
        QSettings cmh_reg(cmh_path, QSettings::NativeFormat);
        foreach (QString cmh_key, cmh_reg.allKeys()) {
            // Add anything that looks like a UUID.
            if (!cmh_key.endsWith("/.")) continue; // No default key?

            // "Registering Shell Extension Handlers" says the subkey name
            // should be the class ID...
            if (cmh_key.contains(uuid_re)) {
                cmh_key.chop(2);
                clsids += cmh_key;
                continue;
            }

            // ...it then gives an example with the subkey named after the
            // application, with the default key containing the class ID.
            QString cmh_default = cmh_reg.value(cmh_key).toString();
            if (cmh_default.contains(uuid_re)) clsids += cmh_default;

        }
    }

    // We have a list of context menu handler CLSIDs. Now look for
    // offending DLLs.
    foreach (QString clsid, clsids.toList()) {
        QString inproc_path = QString("HKEY_CLASSES_ROOT\\CLSID\\%1\\InprocServer32").arg(clsid);
        QSettings inproc_reg(inproc_path, QSettings::NativeFormat);
        QString inproc_default = inproc_reg.value(".").toString();
        if (inproc_default.isEmpty()) continue;

        foreach (QString dbar_dll, dbar_dlls) {
            // XXX We don't expand environment variables in the path.
            unsigned int dll_version = fileVersion(inproc_default);
            unsigned int bad_version = 1 << 16 | 8; // Offending DBAR version is 1.8.
            if (inproc_default.contains(dbar_dll, Qt::CaseInsensitive) && dll_version == bad_version) {
                QMessageBox dbar_msgbox;
                dbar_msgbox.setIcon(QMessageBox::Warning);
                dbar_msgbox.setStandardButtons(QMessageBox::Ok);
                dbar_msgbox.setWindowTitle(tr("Dell Backup and Recovery Found"));
                dbar_msgbox.setText(tr("You appear to be running Dell Backup and Recovery 1.8."));
                dbar_msgbox.setInformativeText(tr(
                    "DBAR can make many applications crash"
                    " <a href=\"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=12036\">including Wireshark</a>."
                ));
                dbar_msgbox.setDetailedText(tr("Offending DLL: %1").arg(inproc_default));
                dbar_msgbox.exec();
                return;
            }
        }
    }
}
#endif

void WiresharkApplication::setLastOpenDir(const char *dir_name)
{
    qint64 len;
    gchar *new_last_open_dir;

    if (dir_name && dir_name[0]) {
        len = strlen(dir_name);
        if (dir_name[len-1] == G_DIR_SEPARATOR) {
            new_last_open_dir = g_strconcat(dir_name, (char *)NULL);
        }
        else {
            new_last_open_dir = g_strconcat(dir_name,
                                            G_DIR_SEPARATOR_S, (char *)NULL);
        }
    } else {
        new_last_open_dir = NULL;
    }

    g_free(last_open_dir);
    last_open_dir = new_last_open_dir;
}

bool WiresharkApplication::event(QEvent *event)
{
    QString display_filter = NULL;
    if (event->type() == QEvent::FileOpen) {
        QFileOpenEvent *foe = static_cast<QFileOpenEvent *>(event);
        if (foe && foe->file().length() > 0) {
            QString cf_path(foe->file());
            if (initialized_) {
                emit openCaptureFile(cf_path, display_filter, WTAP_TYPE_AUTO);
            } else {
                pending_open_files_.append(cf_path);
            }
        }
        return true;
    }
    return QApplication::event(event);
}

void WiresharkApplication::captureStarted()
{
    active_captures_++;
    emit captureActive(active_captures_);
}

void WiresharkApplication::captureFinished()
{
    active_captures_--;
    emit captureActive(active_captures_);
}

void WiresharkApplication::clearRecentCaptures() {
    qDeleteAll(recent_captures_);
    recent_captures_.clear();
    emit updateRecentCaptureStatus(NULL, 0, false);
}

void WiresharkApplication::captureFileReadStarted()
{
    // Doesn't appear to do anything. Logic probably needs to be in file.c.
    QTimer::singleShot(TAP_UPDATE_DEFAULT_INTERVAL / 5, this, SLOT(updateTaps()));
    QTimer::singleShot(TAP_UPDATE_DEFAULT_INTERVAL / 2, this, SLOT(updateTaps()));
}

void WiresharkApplication::cleanup()
{
    software_update_cleanup();
    storeCustomColorsInRecent();
    // Write the user's recent file(s) to disk.
    write_profile_recent();
    write_recent();

    qDeleteAll(recent_captures_);
    recent_captures_.clear();
}

void WiresharkApplication::itemStatusFinished(const QString filename, qint64 size, bool accessible) {
    recent_item_status *ri;

    foreach (ri, recent_captures_) {
        if (filename == ri->filename && (size != ri->size || accessible != ri->accessible)) {
            ri->size = size;
            ri->accessible = accessible;
            ri->in_thread = false;

            emit updateRecentCaptureStatus(filename, size, accessible);
        }
    }
}

WiresharkApplication::WiresharkApplication(int &argc,  char **argv) :
    QApplication(argc, argv),
    initialized_(false),
    is_reloading_lua_(false),
    if_notifier_(NULL),
    active_captures_(0)
{
    wsApp = this;
    setApplicationName("Wireshark");

    Q_INIT_RESOURCE(about);
    Q_INIT_RESOURCE(i18n);
    Q_INIT_RESOURCE(layout);
    Q_INIT_RESOURCE(toolbar);
    Q_INIT_RESOURCE(wsicon);
    Q_INIT_RESOURCE(languages);

#ifdef Q_OS_WIN
    /* RichEd20.DLL is needed for native file dialog filter entries. */
    ws_load_library("riched20.dll");
#endif // Q_OS_WIN

#if (QT_VERSION >= QT_VERSION_CHECK(5, 1, 0))
    setAttribute(Qt::AA_UseHighDpiPixmaps);
#endif

    QList<int> icon_sizes = QList<int>() << 16 << 24 << 32 << 48 << 64 << 128 << 256 << 512 << 1024;
    foreach (int icon_size, icon_sizes) {
        QString icon_path = QString(":/wsicon/wsicon%1.png").arg(icon_size);
        normal_icon_.addFile(icon_path);
        icon_path = QString(":/wsicon/wsiconcap%1.png").arg(icon_size);
        capture_icon_.addFile(icon_path);
    }

    //
    // XXX - this means we try to check for the existence of all files
    // in the recent list every 2 seconds; that causes noticeable network
    // traffic if any of them are stored on file servers.
    //
    // QFileSystemWatcher should allow us to watch for files being
    // removed or renamed.  It uses kqueues and EVFILT_VNODE on FreeBSD,
    // NetBSD, FSEvents on macOS, inotify on Linux if available, and
    // FindFirstChagneNotification() on Windows.  On all other platforms,
    // it just periodically polls, as we're doing now.
    //
    // For unmounts:
    //
    // macOS and FreeBSD deliver NOTE_REVOKE notes for EVFILT_VNODE, and
    // QFileSystemWatcher delivers signals for them, just as it does for
    // NOTE_DELETE and NOTE_RENAME.
    //
    // On Linux, inotify:
    //
    //    http://man7.org/linux/man-pages/man7/inotify.7.html
    //
    // appears to deliver "filesystem containing watched object was
    // unmounted" events.  It looks as if Qt turns them into "changed"
    // events.
    //
    // On Windows, it's not clearly documented what happens on a handle
    // opened with FindFirstChangeNotification() if the volume on which
    // the path handed to FindFirstChangeNotification() is removed, or
    // ejected, or whatever the Windowsese is for "unmounted".  The
    // handle obviously isn't valid any more, but whether it just hangs
    // around and never delivers any notifications or delivers an
    // event that turns into an error indication doesn't seem to be
    // documented.  If it just hangs around, I think our main loop will
    // receive a WM_DEVICECHANGE Windows message with DBT_DEVICEREMOVECOMPLETE
    // if an unmount occurs - even for network devices.  If we need to watch
    // for those, we can use the winEvent method of the QWidget for the
    // top-level window to get Windows messages.
    //
    // Note also that remote file systems might not report file
    // removal or renames if they're done on the server or done by
    // another client.  At least on macOS, they *will* get reported
    // if they're done on the machine running the program doing the
    // kqueue stuff, and, at least in newer versions, should get
    // reported on SMB-mounted (and AFP-mounted?) file systems
    // even if done on the server or another client.
    //
    // But, when push comes to shove, the file manager(s) on the
    // OSes in question probably use the same mechanisms to
    // monitor folders in folder windows or open/save dialogs or...,
    // so my inclination is just to use QFileSystemWatcher.
    //
    // However, that wouldn't catch files that become *re*-accessible
    // by virtue of a file system being re-mounted.  The only way to
    // catch *that* would be to watch for mounts and re-check all
    // marked-as-inaccessible files.
    //
    // macOS and FreeBSD also support EVFILT_FS events, which notify you
    // of file system mounts and unmounts.  We'd need to add our own
    // kqueue for that, if we can check those with QSocketNotifier.
    //
    // On Linux, at least as of 2006, you're supposed to poll /proc/mounts:
    //
    //    https://lkml.org/lkml/2006/2/22/169
    //
    // to discover mounts.
    //
    // On Windows, you'd probably have to watch for WM_DEVICECHANGE events.
    //
    // Then again, with an automounter, a file system containing a
    // recent capture might get unmounted automatically if you haven't
    // referred to anything on that file system for a while, and get
    // treated as inaccessible.  However, if you try to access it,
    // the automounter will attempt to re-mount it, so the access *will*
    // succeed if the automounter can remount the file.
    //
    // (Speaking of automounters, repeatedly polling recent files will
    // keep the file system from being unmounted, for what that's worth.)
    //
    // At least on macOS, you can determine whether a file is on an
    // automounted file system by calling statfs() on its path and
    // checking whether MNT_AUTOMOUNTED is set in f_flags.  FreeBSD
    // appears to support that flag as well, but no other *BSD appears
    // to.
    //
    // I'm not sure what can be done on Linux.
    //
    recent_timer_.setParent(this);
    connect(&recent_timer_, SIGNAL(timeout()), this, SLOT(refreshRecentCaptures()));
    recent_timer_.start(2000);

    addr_resolv_timer_.setParent(this);
    connect(&addr_resolv_timer_, SIGNAL(timeout()), this, SLOT(refreshAddressResolution()));
    addr_resolv_timer_.start(1000);

    tap_update_timer_.setParent(this);
    tap_update_timer_.setInterval(TAP_UPDATE_DEFAULT_INTERVAL);
    connect(this, SIGNAL(appInitialized()), &tap_update_timer_, SLOT(start()));
    connect(&tap_update_timer_, SIGNAL(timeout()), this, SLOT(updateTaps()));

    // Application-wide style sheet
    QString app_style_sheet = qApp->styleSheet();
#if defined(Q_OS_MAC) && QT_VERSION < QT_VERSION_CHECK(5, 6, 0)
    // Qt uses the HITheme API to draw splitters. In recent versions of macOS
    // this looks particularly bad: https://bugreports.qt.io/browse/QTBUG-43425
    // This doesn't look native but it looks better than Yosemite's bit-rotten
    // rendering of HIThemeSplitterDrawInfo.
    app_style_sheet +=
            "QSplitter::handle:vertical { height: 0px; }\n"
            "QSplitter::handle:horizontal { width: 0px; }\n";
#endif
    qApp->setStyleSheet(app_style_sheet);

    // If our window text is lighter than the window background, assume the theme is dark.
    QPalette gui_pal = qApp->palette();
    prefs_set_gui_theme_is_dark(gui_pal.windowText().color().value() > gui_pal.window().color().value());

#ifdef HAVE_SOFTWARE_UPDATE
    connect(this, SIGNAL(softwareUpdateQuit()), this, SLOT(quit()), Qt::QueuedConnection);
#endif

#ifdef _WIN32
    checkForDbar();
#endif

    connect(qApp, SIGNAL(aboutToQuit()), this, SLOT(cleanup()));
}

WiresharkApplication::~WiresharkApplication()
{
    free_filter_lists();
}

void WiresharkApplication::registerUpdate(register_action_e action, const char *message)
{
    emit splashUpdate(action, message);
}

void WiresharkApplication::emitAppSignal(AppSignal signal)
{
    switch (signal) {
    case ColumnsChanged:
        emit columnsChanged();
        break;
    case CaptureFilterListChanged:
        emit captureFilterListChanged();
        break;
    case DisplayFilterListChanged:
        emit displayFilterListChanged();
        break;
    case FilterExpressionsChanged:
        emit filterExpressionsChanged();
        break;
    case LocalInterfacesChanged:
        emit localInterfaceListChanged();
        break;
    case NameResolutionChanged:
        emit addressResolutionChanged();
        break;
    case PreferencesChanged:
        emit preferencesChanged();
        break;
    case PacketDissectionChanged:
        emit packetDissectionChanged();
        break;
    case RecentCapturesChanged:
        emit updateRecentCaptureStatus(NULL, 0, false);
        break;
    case RecentPreferencesRead:
        emit recentPreferencesRead();
        break;
    case FieldsChanged:
        emit fieldsChanged();
        break;
    default:
        break;
    }
}

// Flush any collected app signals.
//
// On macOS emitting PacketDissectionChanged from a dialog can
// render the application unusable:
// https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=11361
// https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=11448
// Work around the problem by queueing up app signals and emitting them
// after the dialog is closed.
//
// The following bugs might be related although they don't describe the
// exact behavior we're working around here:
// https://bugreports.qt.io/browse/QTBUG-38512
// https://bugreports.qt.io/browse/QTBUG-38600
void WiresharkApplication::flushAppSignals()
{
    while (!app_signals_.isEmpty()) {
        wsApp->emitAppSignal(app_signals_.takeFirst());
    }
}

void WiresharkApplication::emitStatCommandSignal(const QString &menu_path, const char *arg, void *userdata)
{
    emit openStatCommandDialog(menu_path, arg, userdata);
}

void WiresharkApplication::emitTapParameterSignal(const QString cfg_abbr, const QString arg, void *userdata)
{
    emit openTapParameterDialog(cfg_abbr, arg, userdata);
}

// XXX Combine statistics and funnel routines into addGroupItem + groupItems?
void WiresharkApplication::addDynamicMenuGroupItem(int group, QAction *sg_action)
{
    if (!dynamic_menu_groups_.contains(group)) {
        dynamic_menu_groups_[group] = QList<QAction *>();
    }
    dynamic_menu_groups_[group] << sg_action;
}

void WiresharkApplication::appendDynamicMenuGroupItem(int group, QAction *sg_action)
{
    if (!added_menu_groups_.contains(group)) {
        added_menu_groups_[group] = QList<QAction *>();
    }
    added_menu_groups_[group] << sg_action;
    addDynamicMenuGroupItem(group, sg_action);
}

void WiresharkApplication::removeDynamicMenuGroupItem(int group, QAction *sg_action)
{
    if (!removed_menu_groups_.contains(group)) {
        removed_menu_groups_[group] = QList<QAction *>();
    }
    removed_menu_groups_[group] << sg_action;
    dynamic_menu_groups_[group].removeAll(sg_action);
}

QList<QAction *> WiresharkApplication::dynamicMenuGroupItems(int group)
{
    if (!dynamic_menu_groups_.contains(group)) {
        return QList<QAction *>();
    }

    QList<QAction *> sgi_list = dynamic_menu_groups_[group];
    std::sort(sgi_list.begin(), sgi_list.end(), qActionLessThan);
    return sgi_list;
}

QList<QAction *> WiresharkApplication::addedMenuGroupItems(int group)
{
    if (!added_menu_groups_.contains(group)) {
        return QList<QAction *>();
    }

    QList<QAction *> sgi_list = added_menu_groups_[group];
    std::sort(sgi_list.begin(), sgi_list.end(), qActionLessThan);
    return sgi_list;
}

QList<QAction *> WiresharkApplication::removedMenuGroupItems(int group)
{
    if (!removed_menu_groups_.contains(group)) {
        return QList<QAction *>();
    }

    QList<QAction *> sgi_list = removed_menu_groups_[group];
    std::sort(sgi_list.begin(), sgi_list.end(), qActionLessThan);
    return sgi_list;
}

void WiresharkApplication::clearAddedMenuGroupItems()
{
    foreach (int group, added_menu_groups_.uniqueKeys()) {
        added_menu_groups_[group].clear();
    }
}

void WiresharkApplication::clearRemovedMenuGroupItems()
{
    foreach (int group, removed_menu_groups_.uniqueKeys()) {
        foreach (QAction *action, removed_menu_groups_[group]) {
            delete action;
        }
        removed_menu_groups_[group].clear();
    }
}

#ifdef HAVE_LIBPCAP

static void
iface_mon_event_cb(const char *iface, int up)
{
    int present = 0;
    guint ifs, j;
    interface_t device;
    interface_options interface_opts;

    for (ifs = 0; ifs < global_capture_opts.all_ifaces->len; ifs++) {
        device = g_array_index(global_capture_opts.all_ifaces, interface_t, ifs);
        if (strcmp(device.name, iface) == 0) {
            present = 1;
            if (!up) {
                /*
                 * Interface went down or disappeared; remove all instances
                 * of it from the current list of interfaces selected
                 * for capturing.
                 */
                for (j = 0; j < global_capture_opts.ifaces->len; j++) {
                    interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, j);
                    if (strcmp(interface_opts.name, device.name) == 0) {
                        g_array_remove_index(global_capture_opts.ifaces, j);
                }
             }
          }
        }
    }

    if (present != up) {
        /*
         * We've been told that there's a new interface or that an old
         * interface is gone; reload the local interface list.
         */
        wsApp->refreshLocalInterfaces();
    }
}

#endif

void WiresharkApplication::ifChangeEventsAvailable()
{
#ifdef HAVE_LIBPCAP
    /*
     * Something's readable from the descriptor for interface
     * monitoring.
     *
     * Have the interface-monitoring code Read whatever interface-change
     * events are available, and call the callback for them.
     */
    iface_mon_event();
#endif
}

void WiresharkApplication::refreshLocalInterfaces()
{
#ifdef HAVE_EXTCAP
    extcap_clear_interfaces();
#endif

#ifdef HAVE_LIBPCAP
    /*
     * Reload the local interface list.
     */
    scan_local_interfaces(main_window_update);

    /*
     * Now emit a signal to indicate that the list changed, so that all
     * places displaying the list will get updated.
     *
     * XXX - only if it *did* change.
     */
    emit localInterfaceListChanged();
#endif
}

void WiresharkApplication::allSystemsGo()
{
    QString display_filter = NULL;
    initialized_ = true;
    emit appInitialized();
    while (pending_open_files_.length() > 0) {
        emit openCaptureFile(pending_open_files_.front(), display_filter, WTAP_TYPE_AUTO);
        pending_open_files_.pop_front();
    }
    software_update_init();

#ifdef HAVE_LIBPCAP
    int err;
    err = iface_mon_start(&iface_mon_event_cb);
    if (err == 0) {
        if_notifier_ = new QSocketNotifier(iface_mon_get_sock(),
                                           QSocketNotifier::Read, this);
        connect(if_notifier_, SIGNAL(activated(int)), SLOT(ifChangeEventsAvailable()));
    }
#endif
}

_e_prefs *WiresharkApplication::readConfigurationFiles(bool reset)
{
    e_prefs             *prefs_p;

    if (reset) {
        //
        // Reset current preferences and enabled/disabled protocols and
        // heuristic dissectors before reading.
        // (Needed except when this is called at startup.)
        //
        prefs_reset();
        proto_reenable_all();
    }

    /* Load libwireshark settings from the current profile. */
    prefs_p = epan_load_settings();

#ifdef _WIN32
    /* if the user wants a console to be always there, well, we should open one for him */
    if (prefs_p->gui_console_open == console_open_always) {
        create_console();
    }
#endif

    /* Read the capture filter file. */
    read_filter_list(CFILTER_LIST);

    /* Read the display filter file. */
    read_filter_list(DFILTER_LIST);

    return prefs_p;
}

QList<recent_item_status *> WiresharkApplication::recentItems() const {
    return recent_captures_;
}

void WiresharkApplication::addRecentItem(const QString filename, qint64 size, bool accessible) {
    recent_item_status *ri = new(recent_item_status);

    ri->filename = filename;
    ri->size = size;
    ri->accessible = accessible;
    ri->in_thread = false;
    recent_captures_.prepend(ri);

    itemStatusFinished(filename, size, accessible);
}

void WiresharkApplication::removeRecentItem(const QString &filename)
{
    QMutableListIterator<recent_item_status *> rii(recent_captures_);

    while (rii.hasNext()) {
        recent_item_status *ri = rii.next();
#ifdef _WIN32
        /* Do a case insensitive compare on win32 */
        if (ri->filename.compare(filename, Qt::CaseInsensitive) == 0) {
#else
        /* Do a case sensitive compare on UN*Xes.
         *
         * XXX - on UN*Xes such as macOS, where you can use pathconf()
         * to check whether a given file system is case-sensitive or
         * not, we should check whether this particular file system
         * is case-sensitive and do the appropriate comparison.
         */
        if (ri->filename.compare(filename) == 0) {
#endif
            rii.remove();
            delete(ri);
        }
    }

    emit updateRecentCaptureStatus(NULL, 0, false);
}

static void switchTranslator(QTranslator& myTranslator, const QString& filename,
    const QString& searchPath)
{
    wsApp->removeTranslator(&myTranslator);

    if (myTranslator.load(filename, searchPath))
        wsApp->installTranslator(&myTranslator);
}

void WiresharkApplication::loadLanguage(const QString newLanguage)
{
    QLocale locale;
    QString localeLanguage;

    if (newLanguage.isEmpty() || newLanguage == USE_SYSTEM_LANGUAGE) {
        localeLanguage = QLocale::system().name();
    } else {
        localeLanguage = newLanguage;
    }

    locale = QLocale(localeLanguage);
    QLocale::setDefault(locale);
    switchTranslator(wsApp->translator,
            QString("wireshark_%1.qm").arg(localeLanguage), QString(":/i18n/"));
    if (QFile::exists(QString("%1/%2/wireshark_%3.qm")
            .arg(get_datafile_dir()).arg("languages").arg(localeLanguage)))
        switchTranslator(wsApp->translator,
                QString("wireshark_%1.qm").arg(localeLanguage), QString(get_datafile_dir()) + QString("/languages"));
    if (QFile::exists(QString("%1/wireshark_%3.qm")
            .arg(gchar_free_to_qstring(get_persconffile_path("languages", FALSE))).arg(localeLanguage)))
        switchTranslator(wsApp->translator,
                QString("wireshark_%1.qm").arg(localeLanguage), gchar_free_to_qstring(get_persconffile_path("languages", FALSE)));
    if (QFile::exists(QString("%1/qt_%2.qm")
            .arg(get_datafile_dir()).arg(localeLanguage))) {
        switchTranslator(wsApp->translatorQt,
                QString("qt_%1.qm").arg(localeLanguage), QString(get_datafile_dir()));
    } else if (QFile::exists(QString("%1/qt_%2.qm")
            .arg(get_datafile_dir()).arg(localeLanguage.left(localeLanguage.lastIndexOf('_'))))) {
        switchTranslator(wsApp->translatorQt,
                QString("qt_%1.qm").arg(localeLanguage.left(localeLanguage.lastIndexOf('_'))), QString(get_datafile_dir()));
    } else {
    switchTranslator(wsApp->translatorQt,
            QString("qt_%1.qm").arg(localeLanguage),
            QLibraryInfo::location(QLibraryInfo::TranslationsPath));
    }
}

void WiresharkApplication::doTriggerMenuItem(MainMenuItem menuItem)
{
    switch (menuItem)
    {
    case FileOpenDialog:
        emit openCaptureFile(QString(), QString(), WTAP_TYPE_AUTO);
        break;
    case CaptureOptionsDialog:
        emit openCaptureOptions();
        break;
    }
}

#ifdef HAVE_SOFTWARE_UPDATE
bool WiresharkApplication::softwareUpdateCanShutdown() {
    software_update_ok_ = true;
    // At this point the update is ready to install, but WinSparkle has
    // not yet run the installer. We need to close our "Wireshark is
    // running" mutexes along with those of our child processes, e.g.
    // dumpcap.

    // Step 1: See if we have any open files.
    emit softwareUpdateRequested();
    if (software_update_ok_ == true) {

        // Step 2: Close the "running" mutexes.
        emit softwareUpdateClose();
        close_app_running_mutex();
    }
    return software_update_ok_;
}

void WiresharkApplication::softwareUpdateShutdownRequest() {
    // At this point the installer has been launched. Neither Wireshark nor
    // its children should have any "Wireshark is running" mutexes open.
    // The main window should be closed.

    // Step 3: Quit.
    emit softwareUpdateQuit();
}
#endif

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
