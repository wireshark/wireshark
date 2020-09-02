/* main.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <glib.h>

#include <locale.h>

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#include <wchar.h>
#include <shellapi.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifndef HAVE_GETOPT_LONG
#include "wsutil/wsgetopt.h"
#endif

#include <ui/clopts_common.h>
#include <ui/cmdarg_err.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/socket.h>
#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif
#include <wsutil/report_message.h>
#include <wsutil/please_report_bug.h>
#include <wsutil/unicode-utils.h>
#include <version_info.h>

#include <epan/addr_resolv.h>
#include <epan/ex-opt.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/column.h>
#include <epan/disabled_protos.h>
#include <epan/prefs.h>

#ifdef HAVE_KERBEROS
#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/dissectors/packet-kerberos.h>
#endif

#include <wsutil/codecs.h>

#include <extcap.h>

/* general (not Qt specific) */
#include "file.h"
#include "epan/color_filters.h"
#include "log.h"

#include "epan/rtd_table.h"
#include "epan/srt_table.h"

#include "ui/alert_box.h"
#include "ui/console.h"
#include "ui/iface_lists.h"
#include "ui/language.h"
#include "ui/persfilepath_opt.h"
#include "ui/recent.h"
#include "ui/simple_dialog.h"
#include "ui/util.h"
#include "ui/dissect_opts.h"
#include "ui/commandline.h"
#include "ui/capture_ui_utils.h"
#include "ui/preference_utils.h"
#include "ui/software_update.h"
#include "ui/taps.h"

#include "ui/qt/conversation_dialog.h"
#include "ui/qt/utils/color_utils.h"
#include "ui/qt/coloring_rules_dialog.h"
#include "ui/qt/endpoint_dialog.h"
#include "ui/qt/main_window.h"
#include "ui/qt/response_time_delay_dialog.h"
#include "ui/qt/service_response_time_dialog.h"
#include "ui/qt/simple_dialog.h"
#include "ui/qt/simple_statistics_dialog.h"
#include <ui/qt/widgets/splash_overlay.h>
#include "ui/qt/wireshark_application.h"

#include "caputils/capture-pcap-util.h"

#include <QMessageBox>
#include <QScreen>

#ifdef _WIN32
#  include "caputils/capture-wpcap.h"
#  include <wsutil/file_util.h>
#endif /* _WIN32 */

#ifdef HAVE_AIRPCAP
#  include <caputils/airpcap.h>
#  include <caputils/airpcap_loader.h>
//#  include "airpcap_dlg.h"
//#  include "airpcap_gui_utils.h"
#endif

#include "epan/crypt/dot11decrypt_ws.h"

/* Handle the addition of View menu items without request */
#if defined(Q_OS_MAC)
#include <ui/macosx/cocoa_bridge.h>
#endif

#include <ui/qt/utils/qt_ui_utils.h>

#define INVALID_OPTION 1
#define INIT_FAILED 2
#define INVALID_CAPABILITY 2
#define INVALID_LINK_TYPE 2

//#define DEBUG_STARTUP_TIME 1
/*
# Log level
# Console log level (for debugging)
# A bitmask of log levels:
# ERROR    = 4
# CRITICAL = 8
# WARNING  = 16
# MESSAGE  = 32
# INFO     = 64
# DEBUG    = 128

#define DEBUG_STARTUP_TIME_LOGLEVEL 252
*/

/* update the main window */
void main_window_update(void)
{
    WiresharkApplication::processEvents();
}

#ifdef HAVE_LIBPCAP

/* quit the main window */
void main_window_quit(void)
{
    wsApp->quit();
}

#endif /* HAVE_LIBPCAP */

void exit_application(int status) {
    if (wsApp) {
        wsApp->quit();
    }
    exit(status);
}

/*
 * Report an error in command-line arguments.
 * Creates a console on Windows.
 */
// xxx copied from ../gtk/main.c
static void
wireshark_cmdarg_err(const char *fmt, va_list ap)
{
#ifdef _WIN32
    create_console();
#endif
    fprintf(stderr, "wireshark: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

/*
 * Report additional information for an error in command-line arguments.
 * Creates a console on Windows.
 * XXX - pop this up in a window of some sort on UNIX+X11 if the controlling
 * terminal isn't the standard error?
 */
// xxx copied from ../gtk/main.c
static void
wireshark_cmdarg_err_cont(const char *fmt, va_list ap)
{
#ifdef _WIN32
    create_console();
#endif
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

// xxx based from ../gtk/main.c:get_gtk_compiled_info
void
get_wireshark_qt_compiled_info(GString *str)
{
    g_string_append(str, "with ");
    g_string_append_printf(str,
#ifdef QT_VERSION
                    "Qt %s", QT_VERSION_STR);
#else
                    "Qt (version unknown)");
#endif

    /* Capture libraries */
    g_string_append(str, ", ");
    get_compiled_caplibs_version(str);
}

// xxx copied from ../gtk/main.c
void
get_gui_compiled_info(GString *str)
{
    epan_get_compiled_version_info(str);

    g_string_append(str, ", ");
#ifdef QT_MULTIMEDIA_LIB
    g_string_append(str, "with QtMultimedia");
#else
    g_string_append(str, "without QtMultimedia");
#endif

    g_string_append(str, ", ");
    const char *update_info = software_update_info();
    if (update_info) {
        g_string_append_printf(str, "with automatic updates using %s", update_info);
    } else {
        g_string_append_printf(str, "without automatic updates");
    }

#ifdef _WIN32
    g_string_append(str, ", ");
#ifdef HAVE_AIRPCAP
    get_compiled_airpcap_version(str);
#else
    g_string_append(str, "without AirPcap");
#endif
#endif /* _WIN32 */

#ifdef HAVE_SPEEXDSP
    g_string_append(str, ", with SpeexDSP (using system library)");
#else
    g_string_append(str, ", with SpeexDSP (using bundled resampler)");
#endif
}

// xxx copied from ../gtk/main.c
void
get_wireshark_runtime_info(GString *str)
{
    if (wsApp) {
        // Display information
        const char *display_mode = ColorUtils::themeIsDark() ? "dark" : "light";
        g_string_append_printf(str, ", with %s display mode", display_mode);

        int hidpi_count = 0;
        foreach (QScreen *screen, wsApp->screens()) {
            if (screen->devicePixelRatio() > 1.0) {
                hidpi_count++;
            }
        }
        if (hidpi_count == wsApp->screens().count()) {
            g_string_append(str, ", with HiDPI");
        } else if (hidpi_count) {
            g_string_append(str, ", with mixed DPI");
        } else {
            g_string_append(str, ", without HiDPI");
        }
    }

#ifdef HAVE_LIBPCAP
    /* Capture libraries */
    g_string_append(str, ", ");
    get_runtime_caplibs_version(str);
#endif

    /* stuff used by libwireshark */
    epan_get_runtime_version_info(str);

#ifdef HAVE_AIRPCAP
    g_string_append(str, ", ");
    get_runtime_airpcap_version(str);
#endif
}

static void
g_log_message_handler(QtMsgType type, const QMessageLogContext &, const QString &msg)
{
    GLogLevelFlags log_level = G_LOG_LEVEL_DEBUG;

    switch (type) {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 5, 0))
    case QtInfoMsg:
        log_level = G_LOG_LEVEL_INFO;
        break;
#endif
    // We want qDebug() messages to show up at our default log level.
    case QtDebugMsg:
    case QtWarningMsg:
        log_level = G_LOG_LEVEL_WARNING;
        break;
    case QtCriticalMsg:
        log_level = G_LOG_LEVEL_CRITICAL;
        break;
    case QtFatalMsg:
        log_level = G_LOG_FLAG_FATAL;
        break;
    default:
        break;
    }
    g_log(LOG_DOMAIN_MAIN, log_level, "%s", qUtf8Printable(msg));
}

#ifdef HAVE_LIBPCAP
/*  Check if there's something important to tell the user during startup.
 *  We want to do this *after* showing the main window so that any windows
 *  we pop up will be above the main window.
 */
static void
check_and_warn_user_startup()
{
    gchar               *cur_user, *cur_group;

    /* Tell the user not to run as root. */
    if (running_with_special_privs() && recent.privs_warn_if_elevated) {
        cur_user = get_cur_username();
        cur_group = get_cur_groupname();
        simple_message_box(ESD_TYPE_WARN, &recent.privs_warn_if_elevated,
        "Running as user \"%s\" and group \"%s\".\n"
        "This could be dangerous.\n\n"
        "If you're running Wireshark this way in order to perform live capture, "
        "you may want to be aware that there is a better way documented at\n"
        "https://wiki.wireshark.org/CaptureSetup/CapturePrivileges", cur_user, cur_group);
        g_free(cur_user);
        g_free(cur_group);
    }
}
#endif

#ifdef _WIN32
// Try to avoid library search path collisions. QCoreApplication will
// search QT_INSTALL_PREFIX/plugins for platform DLLs before searching
// the application directory. If
//
// - You have Qt version 5.x.y installed in the default location
//   (C:\Qt\5.x) on your machine.
//
// and
//
// - You install Wireshark that was built on a machine with Qt version
//   5.x.z installed in the default location.
//
// Qt5Core.dll will load qwindows.dll from your local C:\Qt\5.x\...\plugins
// directory. This may not be compatible with qwindows.dll from that
// same path on the build machine. At any rate, loading DLLs from paths
// you don't control is ill-advised. We work around this by removing every
// path except our application directory.

static inline void
reset_library_path(void)
{
    QString app_path = QDir(get_progfile_dir()).path();
    foreach (QString path, QCoreApplication::libraryPaths()) {
        QCoreApplication::removeLibraryPath(path);
    }
    QCoreApplication::addLibraryPath(app_path);
}
#endif

/* And now our feature presentation... [ fade to music ] */
int main(int argc, char *qt_argv[])
{
    MainWindow *main_w;

#ifdef _WIN32
    LPWSTR              *wc_argv;
    int                  wc_argc;
#endif
    int                  ret_val = EXIT_SUCCESS;
    char               **argv = qt_argv;

    char                *rf_path;
    int                  rf_open_errno;
#ifdef HAVE_LIBPCAP
    gchar               *err_str;
#else
#ifdef _WIN32
#ifdef HAVE_AIRPCAP
    gchar               *err_str;
#endif
#endif
#endif
    gchar               *err_msg = NULL;

    QString              dfilter, read_filter;
#ifdef HAVE_LIBPCAP
    int                  caps_queries = 0;
#endif
    /* Start time in microseconds */
    guint64 start_time = g_get_monotonic_time();
#ifdef DEBUG_STARTUP_TIME
    /* At least on Windows there is a problem with the logging as the preferences is taken
     * into account and the preferences are loaded pretty late in the startup process.
     */
    prefs.console_log_level = DEBUG_STARTUP_TIME_LOGLEVEL;
    prefs.gui_console_open = console_open_always;
#endif /* DEBUG_STARTUP_TIME */
    cmdarg_err_init(wireshark_cmdarg_err, wireshark_cmdarg_err_cont);

#if defined(Q_OS_MAC)
    /* Disable automatic addition of tab menu entries in view menu */
    CocoaBridge::cleanOSGeneratedMenuItems();
#endif

    /*
     * Set the C-language locale to the native environment and set the
     * code page to UTF-8 on Windows.
     */
#ifdef _WIN32
    setlocale(LC_ALL, ".UTF-8");
#else
    setlocale(LC_ALL, "");
#endif

#ifdef _WIN32
    //
    // On Windows, QCoreApplication has its own WinMain(), which gets the
    // command line using GetCommandLineW(), breaks it into individual
    // arguments using CommandLineToArgvW(), and then "helpfully"
    // converts those UTF-16LE arguments into strings in the local code
    // page.
    //
    // We don't want that, because not all file names can be represented
    // in the local code page, so we do the same, but we convert the
    // strings into UTF-8.
    //
    wc_argv = CommandLineToArgvW(GetCommandLineW(), &wc_argc);
    if (wc_argv) {
        argc = wc_argc;
        argv = arg_list_utf_16to8(wc_argc, wc_argv);
        LocalFree(wc_argv);
    } /* XXX else bail because something is horribly, horribly wrong? */

    create_app_running_mutex();
#endif /* _WIN32 */

    /*
     * Get credential information for later use, and drop privileges
     * before doing anything else.
     * Let the user know if anything happened.
     */
    init_process_policies();
    relinquish_special_privs_perm();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    /* init_progfile_dir_error = */ init_progfile_dir(argv[0]);
    g_log(NULL, G_LOG_LEVEL_DEBUG, "progfile_dir: %s", get_progfile_dir());

#ifdef _WIN32
    ws_init_dll_search_path();
    /* Load wpcap if possible. Do this before collecting the run-time version information */
    load_wpcap();

#ifdef HAVE_AIRPCAP
    /* Load the airpcap.dll.  This must also be done before collecting
     * run-time version information. */
    load_airpcap();
#if 0
    airpcap_dll_ret_val = load_airpcap();

    switch (airpcap_dll_ret_val) {
    case AIRPCAP_DLL_OK:
        /* load the airpcap interfaces */
        g_airpcap_if_list = get_airpcap_interface_list(&err, &err_str);

        if (g_airpcap_if_list == NULL || g_list_length(g_airpcap_if_list) == 0) {
            if (err == CANT_GET_AIRPCAP_INTERFACE_LIST && err_str != NULL) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", "Failed to open Airpcap Adapters.");
                g_free(err_str);
            }
            airpcap_if_active = NULL;

        } else {

            /* select the first ad default (THIS SHOULD BE CHANGED) */
            airpcap_if_active = airpcap_get_default_if(airpcap_if_list);
        }
        break;
    /*
     * XXX - Maybe we need to warn the user if one of the following happens???
     */
    case AIRPCAP_DLL_OLD:
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s","AIRPCAP_DLL_OLD\n");
        break;

    case AIRPCAP_DLL_ERROR:
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s","AIRPCAP_DLL_ERROR\n");
        break;

    case AIRPCAP_DLL_NOT_FOUND:
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s","AIRPCAP_DDL_NOT_FOUND\n");
        break;
    }
#endif
#endif /* HAVE_AIRPCAP */
#endif /* _WIN32 */

    /* Get the compile-time version information string */
    ws_init_version_info("Wireshark", get_wireshark_qt_compiled_info,
                         get_gui_compiled_info, get_wireshark_runtime_info);

    /* Create the user profiles directory */
    if (create_profiles_dir(&rf_path) == -1) {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                      "Could not create profiles directory\n\"%s\": %s.",
                      rf_path, strerror(errno));
        g_free (rf_path);
    }

    profile_store_persconffiles(TRUE);
    recent_init();

    /* Read the profile independent recent file.  We have to do this here so we can */
    /* set the profile before it can be set from the command line parameter */
    if (!recent_read_static(&rf_path, &rf_open_errno)) {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                      "Could not open common recent file\n\"%s\": %s.",
                      rf_path, strerror(rf_open_errno));
        g_free(rf_path);
    }

    commandline_early_options(argc, argv);

#ifdef _WIN32
    reset_library_path();
#endif

    // Handle DPI scaling on Windows. This causes problems in at least
    // one case on X11 and we don't yet support Android.
    // We do the equivalent on macOS by setting NSHighResolutionCapable
    // in Info.plist.
    // Note that this enables Windows 8.1-style Per-monitor DPI
    // awareness but not Windows 10-style Per-monitor v2 awareness.
    // https://doc.qt.io/qt-5/scalability.html
    // https://doc.qt.io/qt-5/highdpi.html
    // https://bugreports.qt.io/browse/QTBUG-53022 - The device pixel ratio is pretty much bogus on Windows.
    // https://bugreports.qt.io/browse/QTBUG-55510 - Windows have wrong size
#if defined(Q_OS_WIN) && QT_VERSION >= QT_VERSION_CHECK(5, 6, 0)
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
#endif

    /* Create The Wireshark app */
    WiresharkApplication ws_app(argc, qt_argv);

    /* initialize the funnel mini-api */
    // xxx qtshark
    //initialize_funnel_ops();

    Dot11DecryptInitContext(&dot11decrypt_ctx);

    QString cf_name;
    unsigned int in_file_type = WTAP_TYPE_AUTO;

    err_msg = ws_init_sockets();
    if (err_msg != NULL)
    {
        cmdarg_err("%s", err_msg);
        g_free(err_msg);
        cmdarg_err_cont("%s", please_report_bug());
        ret_val = INIT_FAILED;
        goto clean_exit;
    }

    /* Read the profile dependent (static part) of the recent file. */
    /* Only the static part of it will be read, as we don't have the gui now to fill the */
    /* recent lists which is done in the dynamic part. */
    /* We have to do this already here, so command line parameters can overwrite these values. */
    if (!recent_read_profile_static(&rf_path, &rf_open_errno)) {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                      "Could not open recent file\n\"%s\": %s.",
                      rf_path, g_strerror(rf_open_errno));
        g_free(rf_path);
    }
    wsApp->applyCustomColorsFromRecent();

    // Initialize our language
    read_language_prefs();
    wsApp->loadLanguage(language);

    g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Translator %s", language);

    // Init the main window (and splash)
    main_w = new(MainWindow);
    main_w->show();
    // We may not need a queued connection here but it would seem to make sense
    // to force the issue.
    main_w->connect(&ws_app, SIGNAL(openCaptureFile(QString,QString,unsigned int)),
            main_w, SLOT(openCaptureFile(QString,QString,unsigned int)));
    main_w->connect(&ws_app, SIGNAL(openCaptureOptions()),
            main_w, SLOT(on_actionCaptureOptions_triggered()));

    /* Init the "Open file" dialog directory */
    /* (do this after the path settings are processed) */
    if (recent.gui_fileopen_remembered_dir &&
        test_for_directory(recent.gui_fileopen_remembered_dir) == EISDIR) {
      wsApp->setLastOpenDir(recent.gui_fileopen_remembered_dir);
    } else {
      wsApp->setLastOpenDir(get_persdatafile_dir());
    }

    set_console_log_handler();
    qInstallMessageHandler(g_log_message_handler);
#ifdef DEBUG_STARTUP_TIME
    g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_INFO, "set_console_log_handler, elapsed time %" G_GUINT64_FORMAT " us \n", g_get_monotonic_time() - start_time);
#endif

#ifdef HAVE_LIBPCAP
    /* Set the initial values in the capture options. This might be overwritten
       by preference settings and then again by the command line parameters. */
    capture_opts_init(&global_capture_opts);
#endif

    init_report_message(vfailure_alert_box, vwarning_alert_box,
                        open_failure_alert_box, read_failure_alert_box,
                        write_failure_alert_box);

    wtap_init(TRUE);

    splash_update(RA_DISSECTORS, NULL, NULL);
#ifdef DEBUG_STARTUP_TIME
    g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_INFO, "Calling epan init, elapsed time %" G_GUINT64_FORMAT " us \n", g_get_monotonic_time() - start_time);
#endif
    /* Register all dissectors; we must do this before checking for the
       "-G" flag, as the "-G" flag dumps information registered by the
       dissectors, and we must do it before we read the preferences, in
       case any dissectors register preferences. */
    if (!epan_init(splash_update, NULL, TRUE)) {
        SimpleDialog::displayQueuedMessages(main_w);
        ret_val = INIT_FAILED;
        goto clean_exit;
    }
#ifdef DEBUG_STARTUP_TIME
    /* epan_init resets the preferences */
    prefs.console_log_level = DEBUG_STARTUP_TIME_LOGLEVEL;
    prefs.gui_console_open = console_open_always;
    g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_INFO, "epan done, elapsed time %" G_GUINT64_FORMAT " us \n", g_get_monotonic_time() - start_time);
#endif

    /* Register all audio codecs. */
    codecs_init();

    // Read the dynamic part of the recent file. This determines whether or
    // not the recent list appears in the main window so the earlier we can
    // call this the better.
    if (!recent_read_dynamic(&rf_path, &rf_open_errno)) {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                      "Could not open recent file\n\"%s\": %s.",
                      rf_path, g_strerror(rf_open_errno));
        g_free(rf_path);
    }
    wsApp->refreshRecentCaptures();

    splash_update(RA_LISTENERS, NULL, NULL);
#ifdef DEBUG_STARTUP_TIME
    g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_INFO, "Register all tap listeners, elapsed time %" G_GUINT64_FORMAT " us \n", g_get_monotonic_time() - start_time);
#endif
    /* Register all tap listeners; we do this before we parse the arguments,
       as the "-z" argument can specify a registered tap. */

    /* we register the plugin taps before the other taps because
            stats_tree taps plugins will be registered as tap listeners
            by stats_tree_stat.c and need to registered before that */
#ifdef HAVE_PLUGINS
    register_all_plugin_tap_listeners();
#endif

    /* Register all tap listeners. */
    for (tap_reg_t *t = tap_reg_listener; t->cb_func != NULL; t++) {
        t->cb_func();
    }
    conversation_table_set_gui_info(init_conversation_table);
    hostlist_table_set_gui_info(init_endpoint_table);
    srt_table_iterate_tables(register_service_response_tables, NULL);
    rtd_table_iterate_tables(register_response_time_delay_tables, NULL);
    stat_tap_iterate_tables(register_simple_stat_tables, NULL);

    if (ex_opt_count("read_format") > 0) {
        in_file_type = open_info_name_to_type(ex_opt_get_next("read_format"));
    }

#ifdef DEBUG_STARTUP_TIME
    g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_INFO, "Calling extcap_register_preferences, elapsed time %" G_GUINT64_FORMAT " us \n", g_get_monotonic_time() - start_time);
#endif
    splash_update(RA_EXTCAP, NULL, NULL);
    extcap_register_preferences();
    splash_update(RA_PREFERENCES, NULL, NULL);
#ifdef DEBUG_STARTUP_TIME
    g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_INFO, "Calling module preferences, elapsed time %" G_GUINT64_FORMAT " us \n", g_get_monotonic_time() - start_time);
#endif

    global_commandline_info.prefs_p = ws_app.readConfigurationFiles(false);

    /* Now get our args */
    commandline_other_options(argc, argv, TRUE);

    /* Convert some command-line parameters to QStrings */
    if (global_commandline_info.cf_name != NULL)
        cf_name = QString(global_commandline_info.cf_name);
    if (global_commandline_info.rfilter != NULL)
        read_filter = QString(global_commandline_info.rfilter);
    if (global_commandline_info.dfilter != NULL)
        dfilter = QString(global_commandline_info.dfilter);

    timestamp_set_type(recent.gui_time_format);
    timestamp_set_precision(recent.gui_time_precision);
    timestamp_set_seconds_type (recent.gui_seconds_format);

#ifdef HAVE_LIBPCAP
#ifdef DEBUG_STARTUP_TIME
    g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_INFO, "Calling fill_in_local_interfaces, elapsed time %" G_GUINT64_FORMAT " us \n", g_get_monotonic_time() - start_time);
#endif
    splash_update(RA_INTERFACES, NULL, NULL);

    if (!global_commandline_info.cf_name && !prefs.capture_no_interface_load)
        fill_in_local_interfaces(main_window_update);

    if  (global_commandline_info.list_link_layer_types)
        caps_queries |= CAPS_QUERY_LINK_TYPES;
     if (global_commandline_info.list_timestamp_types)
        caps_queries |= CAPS_QUERY_TIMESTAMP_TYPES;

    if (global_commandline_info.start_capture || caps_queries) {
        /* We're supposed to do a live capture or get a list of link-layer/timestamp
           types for a live capture device; if the user didn't specify an
           interface to use, pick a default. */
        ret_val = capture_opts_default_iface_if_necessary(&global_capture_opts,
        ((global_commandline_info.prefs_p->capture_device) && (*global_commandline_info.prefs_p->capture_device != '\0')) ? get_if_name(global_commandline_info.prefs_p->capture_device) : NULL);
        if (ret_val != 0) {
            goto clean_exit;
        }
    }

    if (caps_queries) {
        /* Get the list of link-layer types for the capture devices. */
        if_capabilities_t *caps;
        guint i;
        interface_t *device;
        for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            int if_caps_queries = caps_queries;
            device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (device->selected) {
#if defined(HAVE_PCAP_CREATE)
                caps = capture_get_if_capabilities(device->name, device->monitor_mode_supported, NULL, &err_str, main_window_update);
#else
                caps = capture_get_if_capabilities(device->name, FALSE, NULL, &err_str,main_window_update);
#endif
                if (caps == NULL) {
                    cmdarg_err("%s", err_str);
                    g_free(err_str);
                    ret_val = INVALID_CAPABILITY;
                    goto clean_exit;
                }
            if (caps->data_link_types == NULL) {
                cmdarg_err("The capture device \"%s\" has no data link types.", device->name);
                ret_val = INVALID_LINK_TYPE;
                goto clean_exit;
            }
#ifdef _WIN32
            create_console();
#endif /* _WIN32 */
#if defined(HAVE_PCAP_CREATE)
            if (device->monitor_mode_supported)
                if_caps_queries |= CAPS_MONITOR_MODE;
#endif
            capture_opts_print_if_capabilities(caps, device->name, if_caps_queries);
#ifdef _WIN32
            destroy_console();
#endif /* _WIN32 */
            free_if_capabilities(caps);
            }
        }
        ret_val = EXIT_SUCCESS;
        goto clean_exit;
    }

    capture_opts_trim_snaplen(&global_capture_opts, MIN_PACKET_SIZE);
    capture_opts_trim_ring_num_files(&global_capture_opts);
#endif /* HAVE_LIBPCAP */

    /* Notify all registered modules that have had any of their preferences
       changed either from one of the preferences file or from the command
       line that their preferences have changed. */
#ifdef DEBUG_STARTUP_TIME
    g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_INFO, "Calling prefs_apply_all, elapsed time %" G_GUINT64_FORMAT " us \n", g_get_monotonic_time() - start_time);
#endif
    prefs_apply_all();
    prefs_to_capture_opts();
    wsApp->emitAppSignal(WiresharkApplication::PreferencesChanged);

#ifdef HAVE_LIBPCAP
    if ((global_capture_opts.num_selected == 0) &&
            (prefs.capture_device != NULL)) {
        guint i;
        interface_t *device;
        for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (!device->hidden && strcmp(device->display_name, prefs.capture_device) == 0) {
                device->selected = TRUE;
                global_capture_opts.num_selected++;
                break;
            }
        }
    }
#endif

    /*
     * Enabled and disabled protocols and heuristic dissectors as per
     * command-line options.
     */
    if (!setup_enabled_and_disabled_protocols()) {
        ret_val = INVALID_OPTION;
        goto clean_exit;
    }

    build_column_format_array(&CaptureFile::globalCapFile()->cinfo, global_commandline_info.prefs_p->num_cols, TRUE);
    wsApp->emitAppSignal(WiresharkApplication::ColumnsChanged); // We read "recent" widths above.
    wsApp->emitAppSignal(WiresharkApplication::RecentPreferencesRead); // Must be emitted after PreferencesChanged.

    wsApp->setMonospaceFont(prefs.gui_qt_font_name);

    /* For update of WindowTitle (When use gui.window_title preference) */
    main_w->setWSWindowTitle();

    if (!color_filters_init(&err_msg, color_filter_add_cb)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_msg);
        g_free(err_msg);
    }

    wsApp->allSystemsGo();
    g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_INFO, "Wireshark is up and ready to go, elapsed time %.3fs\n", (float) (g_get_monotonic_time() - start_time) / 1000000);
    SimpleDialog::displayQueuedMessages(main_w);

    /* User could specify filename, or display filter, or both */
    if (!dfilter.isEmpty())
        main_w->filterPackets(dfilter, false);
    if (!cf_name.isEmpty()) {
        if (main_w->openCaptureFile(cf_name, read_filter, in_file_type)) {

            /* Open stat windows; we do so after creating the main window,
               to avoid Qt warnings, and after successfully opening the
               capture file, so we know we have something to compute stats
               on, and after registering all dissectors, so that MATE will
               have registered its field array and we can have a tap filter
               with one of MATE's late-registered fields as part of the
               filter. */
            start_requested_stats();

            if (global_commandline_info.go_to_packet != 0) {
                /* Jump to the specified frame number, kept for backward
                   compatibility. */
                cf_goto_frame(CaptureFile::globalCapFile(), global_commandline_info.go_to_packet);
            } else if (global_commandline_info.jfilter != NULL) {
                dfilter_t *jump_to_filter = NULL;
                /* try to compile given filter */
                if (!dfilter_compile(global_commandline_info.jfilter, &jump_to_filter, &err_msg)) {
                    // Similar code in MainWindow::mergeCaptureFile().
                    QMessageBox::warning(main_w, QObject::tr("Invalid Display Filter"),
                                         QObject::tr("The filter expression %1 isn't a valid display filter. (%2).")
                                                 .arg(global_commandline_info.jfilter, err_msg),
                                         QMessageBox::Ok);
                    g_free(err_msg);
                } else {
                    /* Filter ok, jump to the first packet matching the filter
                       conditions. Default search direction is forward, but if
                       option d was given, search backwards */
                    cf_find_packet_dfilter(CaptureFile::globalCapFile(), jump_to_filter, global_commandline_info.jump_backwards);
                }
            }
        }
    }
#ifdef HAVE_LIBPCAP
    else {
        if (global_commandline_info.start_capture) {
            if (global_capture_opts.save_file != NULL) {
                /* Save the directory name for future file dialogs. */
                /* (get_dirname overwrites filename) */
                gchar *s = g_strdup(global_capture_opts.save_file);
                set_last_open_dir(get_dirname(s));
                g_free(s);
            }
            /* "-k" was specified; start a capture. */
            check_and_warn_user_startup();

            /* If no user interfaces were specified on the command line,
               copy the list of selected interfaces to the set of interfaces
               to use for this capture. */
            if (global_capture_opts.ifaces->len == 0)
                collect_ifaces(&global_capture_opts);
            CaptureFile::globalCapFile()->window = main_w;
            if (capture_start(&global_capture_opts, main_w->captureSession(), main_w->captureInfoData(), main_window_update)) {
                /* The capture started.  Open stat windows; we do so after creating
                   the main window, to avoid GTK warnings, and after successfully
                   opening the capture file, so we know we have something to compute
                   stats on, and after registering all dissectors, so that MATE will
                   have registered its field array and we can have a tap filter with
                   one of MATE's late-registered fields as part of the filter. */
                start_requested_stats();
            }
        }
        /* if the user didn't supply a capture filter, use the one to filter out remote connections like SSH */
        if (!global_commandline_info.start_capture && !global_capture_opts.default_options.cfilter) {
            global_capture_opts.default_options.cfilter = g_strdup(get_conn_cfilter());
        }
    }
#endif /* HAVE_LIBPCAP */

    // UAT files used in configuration profiles which are used in Qt dialogs
    // are not registered during startup because they only get loaded when
    // the dialog is shown.  Register them here.
    g_free(get_persconffile_path("io_graphs", TRUE));

    profile_store_persconffiles(FALSE);

    ret_val = wsApp->exec();
    wsApp = NULL;

    delete main_w;
    recent_cleanup();
    epan_cleanup();

    extcap_cleanup();

    Dot11DecryptDestroyContext(&dot11decrypt_ctx);

    ws_cleanup_sockets();

#ifdef _WIN32
    /* For some unknown reason, the "atexit()" call in "create_console()"
       doesn't arrange that "destroy_console()" be called when we exit,
       so we call it here if a console was created. */
    destroy_console();
#endif /* _WIN32 */

clean_exit:
#ifdef HAVE_LIBPCAP
    capture_opts_cleanup(&global_capture_opts);
#endif
    col_cleanup(&CaptureFile::globalCapFile()->cinfo);
    codecs_cleanup();
    wtap_cleanup();
    free_progdirs();
    exit_application(ret_val);
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
