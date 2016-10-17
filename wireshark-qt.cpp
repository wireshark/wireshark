/* wireshark-qt.cpp
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

#include <config.h>

#include <glib.h>

#ifdef Q_OS_UNIX
#include <signal.h>
#endif

#include <locale.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifndef HAVE_GETOPT_LONG
#include "wsutil/wsgetopt.h"
#endif

#include <wsutil/clopts_common.h>
#include <wsutil/cmdarg_err.h>
#include <wsutil/crash_info.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif
#include <wsutil/report_err.h>
#include <wsutil/unicode-utils.h>
#include <ws_version_info.h>

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

#ifdef HAVE_PLUGINS
#include <codecs/codecs.h>
#endif

#ifdef HAVE_EXTCAP
#include <extcap.h>
#endif

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
#include "ui/commandline.h"

#include "ui/qt/conversation_dialog.h"
#include "ui/qt/color_utils.h"
#include "ui/qt/coloring_rules_dialog.h"
#include "ui/qt/endpoint_dialog.h"
#include "ui/qt/main_window.h"
#include "ui/qt/response_time_delay_dialog.h"
#include "ui/qt/service_response_time_dialog.h"
#include "ui/qt/simple_dialog.h"
#include "ui/qt/simple_statistics_dialog.h"
#include "ui/qt/splash_overlay.h"
#include "ui/qt/wireshark_application.h"

#include "caputils/capture-pcap-util.h"

#ifdef _WIN32
#  include "caputils/capture-wpcap.h"
#  include "caputils/capture_wpcap_packet.h"
#  include <tchar.h> /* Needed for Unicode */
#  include <wsutil/file_util.h>
#  include <wsutil/os_version_info.h>
#endif /* _WIN32 */

#ifdef HAVE_AIRPCAP
#  include <caputils/airpcap.h>
#  include <caputils/airpcap_loader.h>
//#  include "airpcap_dlg.h"
//#  include "airpcap_gui_utils.h"
#endif

#include "epan/crypt/airpdcap_ws.h"

#if (QT_VERSION < QT_VERSION_CHECK(5, 0, 0))
#include <QTextCodec>
#endif

/* update the main window */
void main_window_update(void)
{
    WiresharkApplication::processEvents();
}

#ifdef HAVE_LIBPCAP

/* quit a nested main window */
void main_window_nested_quit(void)
{
//    if (gtk_main_level() > 0)
    wsApp->quit();
}

/* quit the main window */
void main_window_quit(void)
{
    wsApp->quit();
}

#endif /* HAVE_LIBPCAP */

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
#ifdef HAVE_AIRPCAP
    get_compiled_airpcap_version(str);
#else
    g_string_append(str, "without AirPcap");
#endif
}

// xxx copied from ../gtk/main.c
void
get_wireshark_runtime_info(GString *str)
{
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

#ifdef HAVE_LIBPCAP
/*  Check if there's something important to tell the user during startup.
 *  We want to do this *after* showing the main window so that any windows
 *  we pop up will be above the main window.
 */
static void
check_and_warn_user_startup(const QString &cf_name)
{
#ifndef _WIN32
    Q_UNUSED(cf_name)
#endif
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

#ifdef _WIN32
    /* Warn the user if npf.sys isn't loaded. */
    if (!get_stdin_capture() && cf_name.isEmpty() && !npf_sys_is_running() && recent.privs_warn_if_no_npf && get_windows_major_version() >= 6) {
        simple_message_box(ESD_TYPE_WARN, &recent.privs_warn_if_no_npf, "%s",
        "The NPF driver isn't running. You may have trouble\n"
        "capturing or listing interfaces.");
    }
#endif

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
    int                  opt;
#endif
    int                  ret_val;
    char               **argv = qt_argv;

#ifdef _WIN32
    WSADATA              wsaData;
#endif  /* _WIN32 */

    char                *rf_path;
    int                  rf_open_errno;
    char                *gdp_path, *dp_path;
#ifdef HAVE_LIBPCAP
    gchar               *err_str;
    int                  status;
#else
#ifdef _WIN32
#ifdef HAVE_AIRPCAP
    gchar               *err_str;
#endif
#endif
#endif
    GString             *comp_info_str = NULL;
    GString             *runtime_info_str = NULL;

    QString              dfilter, read_filter;

    cmdarg_err_init(wireshark_cmdarg_err, wireshark_cmdarg_err_cont);

    // In Qt 5, C strings are treated always as UTF-8 when converted to
    // QStrings; in Qt 4, the codec must be set to make that happen
#if (QT_VERSION < QT_VERSION_CHECK(5, 0, 0))
    // Hopefully we won't have to use QString::fromUtf8() in as many places.
    QTextCodec *utf8codec = QTextCodec::codecForName("UTF-8");
    QTextCodec::setCodecForCStrings(utf8codec);
    // XXX - QObject doesn't *have* a tr method in 5.0, as far as I can see...
    QTextCodec::setCodecForTr(utf8codec);
#endif

    /* Set the C-language locale to the native environment. */
    setlocale(LC_ALL, "");

#ifdef _WIN32
    // QCoreApplication clobbers argv. Let's have a local copy.
    argv = (char **) g_malloc(sizeof(char *) * argc);
    for (opt = 0; opt < argc; opt++) {
        argv[opt] = qt_argv[opt];
    }
    arg_list_utf_16to8(argc, argv);
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
    /* init_progfile_dir_error = */ init_progfile_dir(argv[0],
        (int (*)(int, char **)) get_gui_compiled_info);
    g_log(NULL, G_LOG_LEVEL_DEBUG, "progfile_dir: %s", get_progfile_dir());

#ifdef _WIN32
    ws_init_dll_search_path();
    /* Load wpcap if possible. Do this before collecting the run-time version information */
    load_wpcap();

    /* ... and also load the packet.dll from wpcap */
    wpcap_packet_load();

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

        if (g_airpcap_if_list == NULL || g_list_length(g_airpcap_if_list) == 0){
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
    comp_info_str = get_compiled_version_info(get_wireshark_qt_compiled_info,
                                              get_gui_compiled_info);

    /* Assemble the run-time version information string */
    runtime_info_str = get_runtime_version_info(get_wireshark_runtime_info);

    profile_store_persconffiles(TRUE);

    /* Read the profile independent recent file.  We have to do this here so we can */
    /* set the profile before it can be set from the command line parameter */
    if (!recent_read_static(&rf_path, &rf_open_errno)) {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                      "Could not open common recent file\n\"%s\": %s.",
                      rf_path, strerror(rf_open_errno));
        g_free(rf_path);
    }

    commandline_early_options(argc, argv, comp_info_str, runtime_info_str);

#ifdef _WIN32
    reset_library_path();
#endif

    /* Create The Wireshark app */
    WiresharkApplication ws_app(argc, qt_argv);

    /* initialize the funnel mini-api */
    // xxx qtshark
    //initialize_funnel_ops();

    AirPDcapInitContext(&airpdcap_ctx);

    QString cf_name;
    unsigned int in_file_type = WTAP_TYPE_AUTO;

    /* Add it to the information to be reported on a crash. */
    ws_add_crash_info("Wireshark %s\n"
           "\n"
           "%s"
           "\n"
           "%s",
        get_ws_vcs_version_info(), comp_info_str->str, runtime_info_str->str);

#ifdef _WIN32
    /* Start windows sockets */
    WSAStartup( MAKEWORD( 1, 1 ), &wsaData );
#endif  /* _WIN32 */

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

    /* Init the "Open file" dialog directory */
    /* (do this after the path settings are processed) */
    if (recent.gui_fileopen_remembered_dir &&
        test_for_directory(recent.gui_fileopen_remembered_dir) == EISDIR) {
      wsApp->setLastOpenDir(recent.gui_fileopen_remembered_dir);
    } else {
      wsApp->setLastOpenDir(get_persdatafile_dir());
    }

#ifdef Q_OS_UNIX
    // Replicates behavior in gtk_init();
    signal(SIGPIPE, SIG_IGN);
#endif

    set_console_log_handler();

#ifdef HAVE_LIBPCAP
    /* Set the initial values in the capture options. This might be overwritten
       by preference settings and then again by the command line parameters. */
    capture_opts_init(&global_capture_opts);
#endif

    init_report_err(vfailure_alert_box, open_failure_alert_box,
                    read_failure_alert_box, write_failure_alert_box);

    wtap_init();

#ifdef HAVE_PLUGINS
    /* Register all the plugin types we have. */
    epan_register_plugin_types(); /* Types known to libwireshark */
    codec_register_plugin_types(); /* Types known to libwscodecs */

    /* Scan for plugins.  This does *not* call their registration routines;
       that's done later. */
    scan_plugins();

    /* Register all libwiretap plugin modules. */
    register_all_wiretap_modules();

    /* Register all audio codec plugins. */
    register_all_codecs();
#endif

    /* Register all dissectors; we must do this before checking for the
       "-G" flag, as the "-G" flag dumps information registered by the
       dissectors, and we must do it before we read the preferences, in
       case any dissectors register preferences. */
    if (!epan_init(register_all_protocols,register_all_protocol_handoffs,
                   splash_update, NULL)) {
        SimpleDialog::displayQueuedMessages(main_w);
        return 2;
    }

    // Read the dynamic part of the recent file. This determines whether or
    // not the recent list appears in the main window so the earlier we can
    // call this the better.
    if (!recent_read_dynamic(&rf_path, &rf_open_errno)) {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                      "Could not open recent file\n\"%s\": %s.",
                      rf_path, g_strerror(rf_open_errno));
        g_free(rf_path);
    }

    splash_update(RA_LISTENERS, NULL, NULL);

    /* Register all tap listeners; we do this before we parse the arguments,
       as the "-z" argument can specify a registered tap. */

    /* we register the plugin taps before the other taps because
            stats_tree taps plugins will be registered as tap listeners
            by stats_tree_stat.c and need to registered before that */
#ifdef HAVE_PLUGINS
    register_all_plugin_tap_listeners();
#endif

#ifdef HAVE_EXTCAP
    extcap_register_preferences();
#endif

    register_all_tap_listeners();
    conversation_table_set_gui_info(init_conversation_table);
    hostlist_table_set_gui_info(init_endpoint_table);
    srt_table_iterate_tables(register_service_response_tables, NULL);
    rtd_table_iterate_tables(register_response_time_delay_tables, NULL);
    new_stat_tap_iterate_tables(register_simple_stat_tables, NULL);

    if (ex_opt_count("read_format") > 0) {
        in_file_type = open_info_name_to_type(ex_opt_get_next("read_format"));
    }

    splash_update(RA_PREFERENCES, NULL, NULL);

    global_commandline_info.prefs_p = ws_app.readConfigurationFiles(&gdp_path, &dp_path, false);

    /* Now get our args */
    commandline_other_options(argc, argv, TRUE);

    /* Convert some command-line parameters to QStrings */
    if (global_commandline_info.cf_name != NULL)
        cf_name = QString(global_commandline_info.cf_name);
    if (global_commandline_info.rfilter != NULL)
        read_filter = QString(global_commandline_info.rfilter);
    if (global_commandline_info.dfilter != NULL)
        dfilter = QString(global_commandline_info.dfilter);

    /* Removed thread code:
     * https://code.wireshark.org/review/gitweb?p=wireshark.git;a=commit;h=9e277ae6154fd04bf6a0a34ec5655a73e5a736a3
     */

    timestamp_set_type(recent.gui_time_format);
    timestamp_set_precision(recent.gui_time_precision);
    timestamp_set_seconds_type (recent.gui_seconds_format);

#ifdef HAVE_LIBPCAP
    splash_update(RA_INTERFACES, NULL, NULL);

    fill_in_local_interfaces(main_window_update);

    if (global_commandline_info.start_capture || global_commandline_info.list_link_layer_types) {
        /* We're supposed to do a live capture or get a list of link-layer
           types for a live capture device; if the user didn't specify an
           interface to use, pick a default. */
        status = capture_opts_default_iface_if_necessary(&global_capture_opts,
        ((global_commandline_info.prefs_p->capture_device) && (*global_commandline_info.prefs_p->capture_device != '\0')) ? get_if_name(global_commandline_info.prefs_p->capture_device) : NULL);
        if (status != 0) {
            exit(status);
        }
    }

    if (global_commandline_info.list_link_layer_types) {
        /* Get the list of link-layer types for the capture devices. */
        if_capabilities_t *caps;
        guint i;
        interface_t device;
        for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {

            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (device.selected) {
#if defined(HAVE_PCAP_CREATE)
                caps = capture_get_if_capabilities(device.name, device.monitor_mode_supported, NULL, &err_str, main_window_update);
#else
                caps = capture_get_if_capabilities(device.name, FALSE, NULL, &err_str,main_window_update);
#endif
                if (caps == NULL) {
                    cmdarg_err("%s", err_str);
                    g_free(err_str);
                    exit(2);
                }
            if (caps->data_link_types == NULL) {
                cmdarg_err("The capture device \"%s\" has no data link types.", device.name);
                exit(2);
            }
#ifdef _WIN32
            create_console();
#endif /* _WIN32 */
#if defined(HAVE_PCAP_CREATE)
            capture_opts_print_if_capabilities(caps, device.name, device.monitor_mode_supported);
#else
            capture_opts_print_if_capabilities(caps, device.name, FALSE);
#endif
#ifdef _WIN32
            destroy_console();
#endif /* _WIN32 */
            free_if_capabilities(caps);
            }
        }
        exit(0);
    }

    capture_opts_trim_snaplen(&global_capture_opts, MIN_PACKET_SIZE);
    capture_opts_trim_ring_num_files(&global_capture_opts);
#endif /* HAVE_LIBPCAP */

    /* Notify all registered modules that have had any of their preferences
       changed either from one of the preferences file or from the command
       line that their preferences have changed. */
    prefs_apply_all();
    wsApp->emitAppSignal(WiresharkApplication::PreferencesChanged);

#ifdef HAVE_LIBPCAP
    if ((global_capture_opts.num_selected == 0) &&
            (prefs.capture_device != NULL)) {
        guint i;
        interface_t device;
        for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (!device.hidden && strcmp(device.display_name, prefs.capture_device) == 0) {
                device.selected = TRUE;
                global_capture_opts.num_selected++;
                global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
                g_array_insert_val(global_capture_opts.all_ifaces, i, device);
                break;
            }
        }
    }
#endif

    /* disabled protocols as per configuration file */
    if (gdp_path == NULL && dp_path == NULL) {
        set_disabled_protos_list();
        set_disabled_heur_dissector_list();
    }

    if(global_commandline_info.disable_protocol_slist) {
        GSList *proto_disable;
        for (proto_disable = global_commandline_info.disable_protocol_slist; proto_disable != NULL; proto_disable = g_slist_next(proto_disable))
        {
            proto_disable_proto_by_name((char*)proto_disable->data);
        }
    }

    if(global_commandline_info.enable_heur_slist) {
        GSList *heur_enable;
        for (heur_enable = global_commandline_info.enable_heur_slist; heur_enable != NULL; heur_enable = g_slist_next(heur_enable))
        {
            proto_enable_heuristic_by_name((char*)heur_enable->data, TRUE);
        }
    }

    if(global_commandline_info.disable_heur_slist) {
        GSList *heur_disable;
        for (heur_disable = global_commandline_info.disable_heur_slist; heur_disable != NULL; heur_disable = g_slist_next(heur_disable))
        {
            proto_enable_heuristic_by_name((char*)heur_disable->data, FALSE);
        }
    }

    build_column_format_array(&CaptureFile::globalCapFile()->cinfo, global_commandline_info.prefs_p->num_cols, TRUE);
    wsApp->emitAppSignal(WiresharkApplication::ColumnsChanged); // We read "recent" widths above.
    wsApp->emitAppSignal(WiresharkApplication::RecentFilesRead); // Must be emitted after PreferencesChanged.

    wsApp->setMonospaceFont(prefs.gui_qt_font_name);

    /* For update of WindowTitle (When use gui.window_title preference) */
    main_w->setWSWindowTitle();
////////

    packet_list_enable_color(recent.packet_list_colorize);

    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: fetch recent color settings");
    packet_list_enable_color(TRUE);

////////


////////
    gchar* err_msg = NULL;
    if (!color_filters_init(&err_msg, color_filter_add_cb)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_msg);
        g_free(err_msg);
    }

////////

#ifdef HAVE_LIBPCAP
    /* if the user didn't supply a capture filter, use the one to filter out remote connections like SSH */
    if (!global_commandline_info.start_capture && !global_capture_opts.default_options.cfilter) {
        global_capture_opts.default_options.cfilter = g_strdup(get_conn_cfilter());
    }
#else /* HAVE_LIBPCAP */
    ////////
#endif /* HAVE_LIBPCAP */

    wsApp->allSystemsGo();
    g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_INFO, "Wireshark is up and ready to go");
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

            if(global_commandline_info.go_to_packet != 0) {
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
//            show_main_window(FALSE);
            check_and_warn_user_startup(cf_name);

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

    profile_store_persconffiles(FALSE);

    ret_val = wsApp->exec();

    epan_cleanup();

#ifdef HAVE_EXTCAP
    extcap_cleanup();
#endif

    AirPDcapDestroyContext(&airpdcap_ctx);

#ifdef _WIN32
    /* Shutdown windows sockets */
    WSACleanup();

    /* For some unknown reason, the "atexit()" call in "create_console()"
       doesn't arrange that "destroy_console()" be called when we exit,
       so we call it here if a console was created. */
    destroy_console();
#endif /* _WIN32 */

    return ret_val;
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
