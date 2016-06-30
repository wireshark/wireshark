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

#ifdef HAVE_LIBPCAP
#include <caputils/iface_monitor.h>
#endif

#include "ui/capture.h"
#include "filter_files.h"
#include "ui/capture_globals.h"
#include "ui/software_update.h"
#include "ui/last_open_dir.h"
#include "ui/recent_utils.h"

#include "wsutil/utf8_entities.h"

#ifdef _WIN32
#  include "ui/win32/console_win32.h"
#  include "wsutil/file_util.h"
#endif /* _WIN32 */

#include <QAction>
#include <QDesktopServices>
#include <QDir>
#include <QEvent>
#include <QFileOpenEvent>
#include <QFontMetrics>
#include <QLibraryInfo>
#include <QLocale>
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
static QList<recent_item_status *> recent_items_;
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
    QMutableListIterator<recent_item_status *> rii(recent_items_);
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
            /* do a case sensitive compare on unix */
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
    QListIterator<recent_item_status *> rii(recent_items_);
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

// Check each recent item in a separate thread so that we don't hang while
// calling stat(). This is called periodically because files and entire
// volumes can disappear and reappear at any time.
void WiresharkApplication::refreshRecentFiles(void) {
    recent_item_status *ri;
    RecentFileStatus *rf_status;

    // We're in the middle of a capture. Don't create traffic.
    if (active_captures_ > 0) return;

    foreach (ri, recent_items_) {
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
//        mono_bold_font_ = QFont(mono_regular_font_);
//        mono_bold_font_.setBold(true);
        return;
    }

    // http://en.wikipedia.org/wiki/Category:Monospaced_typefaces
    const char *win_default_font = "Consolas";
    const char *win_alt_font = "Lucida Console";
    const char *osx_default_font = "Menlo";
    const char *osx_alt_font = "Monaco";
    const char *x11_default_font = "Liberation Mono";
    const QStringList x11_alt_fonts = QStringList() << "DejaVu Sans Mono" << "Bitstream Vera Sans Mono";
    const QStringList fallback_fonts = QStringList() << "Lucida Sans Typewriter" << "Inconsolata" << "Droid Sans Mono" << "Andale Mono" << "Courier New" << "monospace";
    QStringList substitutes;
    int font_size_adjust = 0;

    // Try to pick the latest, shiniest fixed-width font for our OS.
#if defined(Q_OS_WIN)
    const char *default_font = win_default_font;
    substitutes << win_alt_font << osx_default_font << osx_alt_font << x11_default_font << x11_alt_fonts << fallback_fonts;
    font_size_adjust = 2;
#elif defined(Q_OS_MAC)
    const char *default_font = osx_default_font;
    substitutes << osx_alt_font << win_default_font << win_alt_font << x11_default_font << x11_alt_fonts << fallback_fonts;
#else
    const char *default_font = x11_default_font;
    substitutes << x11_alt_fonts << win_default_font << win_alt_font << osx_default_font << osx_alt_font << fallback_fonts;
#endif

    mono_font_.setFamily(default_font);
    mono_font_.insertSubstitutions(default_font, substitutes);
    mono_font_.setPointSize(wsApp->font().pointSize() + font_size_adjust);
    mono_font_.setBold(false);

//    mono_bold_font_ = QFont(mono_font_);
//    mono_bold_font_.setBold(true);

    g_free(prefs.gui_qt_font_name);
    prefs.gui_qt_font_name = qstring_strdup(mono_font_.toString());
}

int WiresharkApplication::monospaceTextSize(const char *str)
{
    QFontMetrics fm(mono_font_);

    return fm.width(str);
}

void WiresharkApplication::setConfigurationProfile(const gchar *profile_name)
{
    char  *gdp_path, *dp_path;
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

    if (profile_exists(get_profile_name(), FALSE)) {
        /* Write recent file for profile we are leaving, if it still exists */
        write_profile_recent();
    }

    /* Set profile name and update the status bar */
    set_profile_name (profile_name);
    emit profileNameChanged(profile_name);

    /* Apply new preferences */
    readConfigurationFiles (&gdp_path, &dp_path, true);

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
    emit recentFilesRead();
    emit filterExpressionsChanged();
    emit checkDisplayFilter();
    emit captureFilterListChanged();
    emit displayFilterListChanged();

    /* Enable all protocols and disable from the disabled list */
    proto_enable_all();
    if (gdp_path == NULL && dp_path == NULL) {
        set_disabled_protos_list();
        set_disabled_heur_dissector_list();
    }

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

void WiresharkApplication::clearRecentItems() {
    qDeleteAll(recent_items_);
    recent_items_.clear();
    emit updateRecentItemStatus(NULL, 0, false);
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

    qDeleteAll(recent_items_);
    recent_items_.clear();
}

void WiresharkApplication::itemStatusFinished(const QString filename, qint64 size, bool accessible) {
    recent_item_status *ri;

    foreach (ri, recent_items_) {
        if (filename == ri->filename && (size != ri->size || accessible != ri->accessible)) {
            ri->size = size;
            ri->accessible = accessible;
            ri->in_thread = false;

            emit updateRecentItemStatus(filename, size, accessible);
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
    // NetBSD, FSEvents on OS X, inotify on Linux if available, and
    // FindFirstChagneNotification() on Windows.  On all other platforms,
    // it just periodically polls, as we're doing now.
    //
    // For unmounts:
    //
    // OS X and FreeBSD deliver NOTE_REVOKE notes for EVFILT_VNODE, and
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
    // another client.  At least on OS X, they *will* get reported
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
    // OS X and FreeBSD also support EVFILT_FS events, which notify you
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
    // At least on OS X, you can determine whether a file is on an
    // automounted file system by calling statfs() on its path and
    // checking whether MNT_AUTOMOUNTED is set in f_flags.  FreeBSD
    // appears to support that flag as well, but no other *BSD appears
    // to.
    //
    // I'm not sure what can be done on Linux.
    //
    recent_timer_.setParent(this);
    connect(&recent_timer_, SIGNAL(timeout()), this, SLOT(refreshRecentFiles()));
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
    // Qt uses the HITheme API to draw splitters. In recent versions of OS X
    // this looks particularly bad: https://bugreports.qt.io/browse/QTBUG-43425
    // This doesn't look native but it looks better than Yosemite's bit-rotten
    // rendering of HIThemeSplitterDrawInfo.
    app_style_sheet +=
            "QSplitter::handle:vertical { height: 0px; }\n"
            "QSplitter::handle:horizontal { width: 0px; }\n";
#endif
    qApp->setStyleSheet(app_style_sheet);

    connect(qApp, SIGNAL(aboutToQuit()), this, SLOT(cleanup()));
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
    case NameResolutionChanged:
        emit addressResolutionChanged();
        break;
    case PreferencesChanged:
        emit preferencesChanged();
        break;
    case PacketDissectionChanged:
        emit packetDissectionChanged();
        break;
    case RecentFilesRead:
        emit recentFilesRead();
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
// On OS X emitting PacketDissectionChanged from a dialog can
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
                                           QSocketNotifier::Read);
        connect(if_notifier_, SIGNAL(activated(int)), SLOT(ifChangeEventsAvailable()));
    }
#endif
}

_e_prefs *WiresharkApplication::readConfigurationFiles(char **gdp_path, char **dp_path, bool reset)
{
    int                  gpf_open_errno, gpf_read_errno;
    int                  cf_open_errno, df_open_errno;
    int                  gdp_open_errno, gdp_read_errno;
    int                  dp_open_errno, dp_read_errno;
    char                *gpf_path, *pf_path;
    char                *cf_path, *df_path;
    int                  pf_open_errno, pf_read_errno;
    e_prefs             *prefs_p;

    if (reset) {
        // reset preferences before reading
        prefs_reset();
    }

    /* load the decode as entries of this profile */
    load_decode_as_entries();

    /* Read the preference files. */
    prefs_p = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
                         &pf_open_errno, &pf_read_errno, &pf_path);

    if (gpf_path != NULL) {
        if (gpf_open_errno != 0) {
            simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                          "Could not open global preferences file\n\"%s\": %s.", gpf_path,
                          g_strerror(gpf_open_errno));
        }
        if (gpf_read_errno != 0) {
            simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                          "I/O error reading global preferences file\n\"%s\": %s.", gpf_path,
                          g_strerror(gpf_read_errno));
        }
    }
    if (pf_path != NULL) {
        if (pf_open_errno != 0) {
            simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                          "Could not open your preferences file\n\"%s\": %s.", pf_path,
                          g_strerror(pf_open_errno));
        }
        if (pf_read_errno != 0) {
            simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                          "I/O error reading your preferences file\n\"%s\": %s.", pf_path,
                          g_strerror(pf_read_errno));
        }
        g_free(pf_path);
        pf_path = NULL;
    }

#ifdef _WIN32
    /* if the user wants a console to be always there, well, we should open one for him */
    if (prefs_p->gui_console_open == console_open_always) {
        create_console();
    }
#endif

    /* Read the capture filter file. */
    read_filter_list(CFILTER_LIST, &cf_path, &cf_open_errno);
    if (cf_path != NULL) {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                      "Could not open your capture filter file\n\"%s\": %s.", cf_path,
                      g_strerror(cf_open_errno));
        g_free(cf_path);
    }

    /* Read the display filter file. */
    read_filter_list(DFILTER_LIST, &df_path, &df_open_errno);
    if (df_path != NULL) {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                      "Could not open your display filter file\n\"%s\": %s.", df_path,
                      g_strerror(df_open_errno));
        g_free(df_path);
    }

    /* Read the disabled protocols file. */
    read_disabled_protos_list(gdp_path, &gdp_open_errno, &gdp_read_errno,
                              dp_path, &dp_open_errno, &dp_read_errno);
    read_disabled_heur_dissector_list(gdp_path, &gdp_open_errno, &gdp_read_errno,
                              dp_path, &dp_open_errno, &dp_read_errno);
    if (*gdp_path != NULL) {
        if (gdp_open_errno != 0) {
            simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                          "Could not open global disabled protocols file\n\"%s\": %s.",
                          *gdp_path, g_strerror(gdp_open_errno));
        }
        if (gdp_read_errno != 0) {
            simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                          "I/O error reading global disabled protocols file\n\"%s\": %s.",
                          *gdp_path, g_strerror(gdp_read_errno));
        }
        g_free(*gdp_path);
        *gdp_path = NULL;
    }
    if (*dp_path != NULL) {
        if (dp_open_errno != 0) {
            simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                          "Could not open your disabled protocols file\n\"%s\": %s.", *dp_path,
                          g_strerror(dp_open_errno));
        }
        if (dp_read_errno != 0) {
            simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                          "I/O error reading your disabled protocols file\n\"%s\": %s.", *dp_path,
                          g_strerror(dp_read_errno));
        }
        g_free(*dp_path);
        *dp_path = NULL;
    }

    return prefs_p;
}

QList<recent_item_status *> WiresharkApplication::recentItems() const {
    return recent_items_;
}

void WiresharkApplication::addRecentItem(const QString filename, qint64 size, bool accessible) {
    recent_item_status *ri = new(recent_item_status);

    ri->filename = filename;
    ri->size = size;
    ri->accessible = accessible;
    ri->in_thread = false;
    recent_items_.prepend(ri);

    itemStatusFinished(filename, size, accessible);
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
