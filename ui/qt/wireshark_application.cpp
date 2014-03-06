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

#include "wireshark_application.h"

#include "wsutil/filesystem.h"

#include "epan/disabled_protos.h"
#include "epan/tap.h"
#include "epan/timestamp.h"

#include "ui/decode_as_utils.h"
#include "ui/preference_utils.h"
#include "ui/recent.h"
#include "ui/simple_dialog.h"
#include "ui/util.h"

#include "qt_ui_utils.h"

#include "capture.h"
#include "color_filters.h"
#include "filters.h"
#include "log.h"
#include "recent_file_status.h"

#include "ui/capture_globals.h"
#include "ui/software_update.h"
#include "ui/last_open_dir.h"
#include "ui/recent_utils.h"

#ifdef _WIN32
#  include "ui/win32/console_win32.h"
#endif /* _WIN32 */

#include <QDesktopServices>
#include <QDir>
#include <QEvent>
#include <QFileOpenEvent>
#include <QFontMetrics>
#include <QTimer>
#include <QUrl>

#ifdef Q_OS_WIN
#include <QDebug>
#include <QLibrary>
#endif

WiresharkApplication *wsApp = NULL;

// XXX - Copied from ui/gtk/file_dlg.c

// MUST be UTF-8
static char *last_open_dir = NULL;
static bool updated_last_open_dir = FALSE;
static QList<recent_item_status *> recent_items;

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
//    QDir cf_path;

//    cf_path.setPath(normalized_cf_name);
//    normalized_cf_name = cf_path.absolutePath();
    normalized_cf_name = QDir::cleanPath(normalized_cf_name);
    normalized_cf_name = QDir::toNativeSeparators(normalized_cf_name);

    recent_item_status *ri;

    /* Iterate through the recent items list, removing duplicate entries and every
     * item above count_max
     */
    unsigned int cnt = 1;
    foreach (ri, wsApp->recentItems()) {
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
            wsApp->recentItems().removeOne(ri);
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
    QListIterator<recent_item_status *> rii(recent_items);
    rii.toBack();
    while (rii.hasPrevious()) {
        QString cf_name;
        /* get capture filename from the menu item label */
        cf_name = rii.previous()->filename;
        if (cf_name != NULL) {
//            if(u3_active())
//                fprintf (rf, RECENT_KEY_CAPTURE_FILE ": %s\n", u3_contract_device_path(cf_name));
//            else
                fprintf (rf, RECENT_KEY_CAPTURE_FILE ": %s\n", cf_name.toUtf8().constData());
        }
    }
}

void WiresharkApplication::refreshRecentFiles(void) {
    recent_item_status *ri;
    RecentFileStatus *rf_status;
    QThread *rf_thread;

    foreach (ri, recent_items) {
        if (ri->in_thread) {
            continue;
        }

        rf_thread = new QThread;
        rf_status = new RecentFileStatus(ri->filename);

        rf_status->moveToThread(rf_thread);

        connect(rf_thread, SIGNAL(started()), rf_status, SLOT(start()));

        connect(rf_status, SIGNAL(statusFound(QString, qint64, bool)), this, SLOT(itemStatusFinished(QString, qint64, bool)));
        connect(rf_status, SIGNAL(finished()), rf_thread, SLOT(quit()));
        connect(rf_status, SIGNAL(finished()), rf_status, SLOT(deleteLater()));

        rf_thread->start();
    }
}

void WiresharkApplication::updateTaps()
{
    draw_tap_listeners(FALSE);
}

void WiresharkApplication::captureCallback(int event _U_, capture_session *cap_session _U_)
{
#ifdef HAVE_LIBPCAP
    switch(event) {
    case(capture_cb_capture_prepared):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture prepared");
        emit captureCapturePrepared(cap_session);
        break;
    case(capture_cb_capture_update_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update started");
        emit captureCaptureUpdateStarted(cap_session);
        break;
    case(capture_cb_capture_update_continue):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update continue");
        emit captureCaptureUpdateContinue(cap_session);
        break;
    case(capture_cb_capture_update_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update finished");
        emit captureCaptureUpdateFinished(cap_session);
        break;
    case(capture_cb_capture_fixed_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed started");
        emit captureCaptureFixedStarted(cap_session);
        break;
    case(capture_cb_capture_fixed_continue):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed continue");
        break;
    case(capture_cb_capture_fixed_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed finished");
        emit captureCaptureFixedFinished(cap_session);
        break;
    case(capture_cb_capture_stopping):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture stopping");
        /* Beware: this state won't be called, if the capture child
         * closes the capturing on it's own! */
        emit captureCaptureStopping(cap_session);
        break;
    case(capture_cb_capture_failed):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture failed");
        emit captureCaptureFailed(cap_session);
        break;
    default:
        g_warning("main_capture_callback: event %u unknown", event);
        g_assert_not_reached();
    }
#endif // HAVE_LIBPCAP
}

void WiresharkApplication::captureFileCallback(int event, void * data)
{
    capture_file *cf = (capture_file *) data;

    switch(event) {

    case(cf_cb_file_opened):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Opened");
        emit captureFileOpened(cf);
        break;
    case(cf_cb_file_closing):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Closing");
        emit captureFileClosing(cf);
        break;
    case(cf_cb_file_closed):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Closed");
        emit captureFileClosed(cf);
        break;
    case(cf_cb_file_read_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Read started");
        emit captureFileReadStarted(cf);
        break;
    case(cf_cb_file_read_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Read finished");
        emit captureFileReadFinished(cf);
        break;
    case(cf_cb_file_reload_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Reload started");
        emit captureFileReadStarted(cf);
        break;
    case(cf_cb_file_reload_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Reload finished");
        emit captureFileReadFinished(cf);
        break;

    case(cf_cb_packet_selected):
    case(cf_cb_packet_unselected):
    case(cf_cb_field_unselected):
        // Pure signals and slots
        break;

//    case(cf_cb_file_save_started): // data = string
//        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Save started");
//        break;
//    case(cf_cb_file_save_finished):
//        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Save finished");
//        break;
//    case(cf_cb_file_save_failed):
//        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Save failed");
//        break;
    default:
        g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: main_cf_callback %d %p", event, data);
//        g_warning("main_cf_callback: event %u unknown", event);
//        g_assert_not_reached();
    }
}

QDir WiresharkApplication::lastOpenDir() {
    return QDir(last_open_dir);
}

void WiresharkApplication::setLastOpenDir(QString *dir_str) {
    setLastOpenDir(dir_str->toUtf8().constData());
}

void WiresharkApplication::helpTopicAction(topic_action_e action)
{
    char *url;

    url = topic_action_url(action);

    if(url != NULL) {
        QDesktopServices::openUrl(QUrl(url));
        g_free(url);
    }
}

void WiresharkApplication::setMonospaceFont(const char *font_string) {

    if (font_string && strlen(font_string) > 0) {
        mono_regular_font_.fromString(font_string);
        mono_bold_font_ = QFont(mono_regular_font_);
        mono_bold_font_.setBold(true);
        return;
    }

    // http://en.wikipedia.org/wiki/Category:Monospaced_typefaces
    const char *win_default_font = "Consolas";
    const char *win_alt_font = "Lucida Console";
    const char *osx_default_font = "Menlo";
    const char *osx_alt_font = "Monaco";
    const char *x11_default_font = "Bitstream Vera Sans Mono";
    const QStringList x11_alt_fonts = QStringList() << "Liberation Mono" << "DejaVu Sans Mono";
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

    mono_regular_font_.setFamily(default_font);
    mono_regular_font_.insertSubstitutions(default_font, substitutes);
    mono_regular_font_.setPointSize(wsApp->font().pointSize() + font_size_adjust);
    mono_regular_font_.setBold(false);

    mono_bold_font_ = QFont(mono_regular_font_);
    mono_bold_font_.setBold(true);

    g_free(prefs.gui_qt_font_name);
    prefs.gui_qt_font_name = g_strdup(mono_regular_font_.toString().toUtf8().constData());
}

int WiresharkApplication::monospaceTextSize(const char *str, bool bold)
{
    QFontMetrics *fm;

    if (bold)
        fm = new QFontMetrics(mono_bold_font_);
    else
        fm = new QFontMetrics(mono_regular_font_);

    return fm->width(str);
}

QFont WiresharkApplication::monospaceFont(bool bold)
{
    return bold ? mono_bold_font_ : mono_regular_font_;
}

void WiresharkApplication::setConfigurationProfile(const gchar *profile_name)
{
    char  *gdp_path, *dp_path;
    char  *rf_path;
    int    rf_open_errno;

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
//    main_save_window_geometry(top_level);

    if (profile_exists(get_profile_name(), FALSE)) {
        /* Write recent file for profile we are leaving, if it still exists */
        write_profile_recent();
    }

    /* Set profile name and update the status bar */
    set_profile_name (profile_name);
    emit configurationProfileChanged(profile_name);

    /* Reset current preferences and apply the new */
    prefs_reset();
//    menu_prefs_reset();

    (void) readConfigurationFiles (&gdp_path, &dp_path);

    recent_read_profile_static(&rf_path, &rf_open_errno);
    if (rf_path != NULL && rf_open_errno != 0) {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
            "Could not open common recent file\n\"%s\": %s.",
            rf_path, g_strerror(rf_open_errno));
    }
    if (recent.gui_fileopen_remembered_dir &&
        test_for_directory(recent.gui_fileopen_remembered_dir) == EISDIR) {
        set_last_open_dir(recent.gui_fileopen_remembered_dir);
    }
    timestamp_set_type (recent.gui_time_format);
    timestamp_set_seconds_type (recent.gui_seconds_format);
    color_filters_enable(recent.packet_list_colorize);
    tap_update_timer_.setInterval(prefs.tap_update_interval);

    prefs_to_capture_opts();
    prefs_apply_all();
    emit filterExpressionsChanged();
//    macros_post_update();

    /* Enable all protocols and disable from the disabled list */
    proto_enable_all();
    if (gdp_path == NULL && dp_path == NULL) {
        set_disabled_protos_list();
    }

    /* Reload color filters */
    color_filters_reload();

//    user_font_apply();

    /* Update menus with new recent values */
//    menu_recent_read_finished();
}

void WiresharkApplication::setLastOpenDir(const char *dir_name)
{
    qint64 len;
    gchar *new_last_open_dir;

    if (dir_name) {
        len = strlen(dir_name);
        if (dir_name[len-1] == G_DIR_SEPARATOR) {
            new_last_open_dir = g_strconcat(dir_name, (char *)NULL);
        }
        else {
            new_last_open_dir = g_strconcat(dir_name,
                                            G_DIR_SEPARATOR_S, (char *)NULL);
        }

        if (last_open_dir == NULL ||
            strcmp(last_open_dir, new_last_open_dir) != 0)
            updated_last_open_dir = TRUE;
    }
    else {
        new_last_open_dir = NULL;
        if (last_open_dir != NULL)
            updated_last_open_dir = TRUE;
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
    recent_item_status *ri;

    foreach (ri, recent_items) {
        recent_items.removeOne(ri);
        delete(ri);
    }
    emit updateRecentItemStatus(NULL, 0, false);
}

void WiresharkApplication::cleanup()
{
    software_update_cleanup();
    /* write user's recent file to disk
     * It is no problem to write this file, even if we do not quit */
    write_profile_recent();
    write_recent();
}

void WiresharkApplication::itemStatusFinished(const QString &filename, qint64 size, bool accessible) {
    recent_item_status *ri;
    RecentFileStatus *rf_status = qobject_cast<RecentFileStatus *>(QObject::sender());

//    g_log(NULL, G_LOG_LEVEL_DEBUG, "rf isf %d", recent_items.count());
    foreach (ri, recent_items) {
        if (filename == ri->filename && (size != ri->size || accessible != ri->accessible)) {
            ri->size = size;
            ri->accessible = accessible;
            ri->in_thread = false;

//            g_log(NULL, G_LOG_LEVEL_DEBUG, "rf update %s", filename.toUtf8().constData());
            emit updateRecentItemStatus(filename, size, accessible);
        }
    }

    if (rf_status) {
        rf_status->quit();
    }
}

WiresharkApplication::WiresharkApplication(int &argc,  char **argv) :
    QApplication(argc, argv),
    initialized_(false)
{
    wsApp = this;

    Q_INIT_RESOURCE(about);
    Q_INIT_RESOURCE(display_filter);
    Q_INIT_RESOURCE(i18n);
    Q_INIT_RESOURCE(layout);
    Q_INIT_RESOURCE(status);
    Q_INIT_RESOURCE(toolbar);
    Q_INIT_RESOURCE(welcome);

#ifdef Q_OS_WIN
    /* RichEd20.DLL is needed for native file dialog filter entries. */
    if (QLibrary::isLibrary("riched20.dll")) {
        QLibrary riched20("riched20.dll");
        riched20.load();
        if (!riched20.isLoaded()) {
            qDebug() << riched20.errorString();
        }
    }
#endif // Q_OS_WIN

    setAttribute(Qt::AA_DontShowIconsInMenus, true);

    recent_timer_.setParent(this);
    connect(&recent_timer_, SIGNAL(timeout()), this, SLOT(refreshRecentFiles()));
    recent_timer_.start(2000);

    tap_update_timer_.setParent(this);
    tap_update_timer_.setInterval(TAP_UPDATE_DEFAULT_INTERVAL);
    connect(this, SIGNAL(appInitialized()), &tap_update_timer_, SLOT(start()));
    connect(&tap_update_timer_, SIGNAL(timeout()), this, SLOT(updateTaps()));

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
    case FilterExpressionsChanged:
        emit filterExpressionsChanged();
    case PreferencesChanged:
        emit preferencesChanged();
        break;
    case PacketDissectionChanged:
        emit packetDissectionChanged();
        break;
    case StaticRecentFilesRead:
        emit recentFilesRead();
        break;
    default:
        break;
    }
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
}

e_prefs * WiresharkApplication::readConfigurationFiles(char **gdp_path, char **dp_path)
{
    int                  gpf_open_errno, gpf_read_errno;
    int                  cf_open_errno, df_open_errno;
    int                  gdp_open_errno, gdp_read_errno;
    int                  dp_open_errno, dp_read_errno;
    char                *gpf_path, *pf_path;
    char                *cf_path, *df_path;
    int                  pf_open_errno, pf_read_errno;
    e_prefs             *prefs_p;

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
    return recent_items;
}

void WiresharkApplication::addRecentItem(const QString &filename, qint64 size, bool accessible) {
    recent_item_status *ri = new(recent_item_status);

    ri->filename = filename;
    ri->size = size;
    ri->accessible = accessible;
    ri->in_thread = false;
    recent_items.prepend(ri);

    itemStatusFinished(filename, size, accessible);
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
