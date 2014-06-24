/* main.cpp
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

#include "config.h"

#include "wireshark_application.h"
#include "main_window.h"

#include <ctype.h>
#include "globals.h"

#include <glib.h>

#include <signal.h>

#ifdef HAVE_LIBZ
#include <zlib.h>	/* to get the libz version number */
#endif

#ifndef HAVE_GETOPT
#  include "wsutil/wsgetopt.h"
#else
#  include <getopt.h>
#endif

#include <wsutil/crash_info.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif
#include <wsutil/report_err.h>
#include <wsutil/u3.h>
#include <wsutil/copyright_info.h>
#include <wsutil/ws_version_info.h>

#include <wiretap/merge.h>

#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/timestamp.h>
#include <epan/packet.h>
#include <epan/dfilter/dfilter.h>
#include <epan/strutil.h>
#include <epan/addr_resolv.h>
#include <epan/emem.h>
#include <epan/ex-opt.h>
#include <epan/funnel.h>
#include <epan/expert.h>
#include <epan/frequency-utils.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/tap.h>
#include <epan/stat_cmd_args.h>
#include <epan/uat.h>
#include <epan/column.h>
#include <epan/disabled_protos.h>
#include <epan/print.h>

#ifdef HAVE_PLUGINS
#include <codecs/codecs.h>
#endif

/* general (not Qt specific) */
#include "file.h"
#include "summary.h"
#include "color.h"
#include "color_filters.h"
#include "register.h"
#include "ringbuffer.h"
#include "ui/util.h"
#include "clopts_common.h"
#include "cmdarg_err.h"
#include "version_info.h"
#include "log.h"

#include "ui/alert_box.h"
#include "ui/capture_globals.h"
#include "ui/iface_lists.h"
#include "ui/main_statusbar.h"
#include "ui/persfilepath_opt.h"
#include "ui/recent.h"
#include "ui/simple_dialog.h"
#include "ui/ui_util.h"

#ifdef HAVE_LIBPCAP
#  include "capture_ui_utils.h"
#  include "capture-pcap-util.h"
#  include <capchild/capture_ifinfo.h>
#  include "capture.h"
#  include <capchild/capture_sync.h>
#endif

#ifdef _WIN32
#  include "capture-wpcap.h"
#  include "capture_wpcap_packet.h"
#  include <tchar.h> /* Needed for Unicode */
#  include <wsutil/unicode-utils.h>
#  include <commctrl.h>
#  include <shellapi.h>
#  include <conio.h>
#  include "ui/win32/console_win32.h"
#endif /* _WIN32 */

#ifdef HAVE_AIRPCAP
#  include <airpcap.h>
#  include "airpcap_loader.h"
//#  include "airpcap_dlg.h"
//#  include "airpcap_gui_utils.h"
#endif

#include <epan/crypt/airpdcap_ws.h>

#include <QDebug>
#include <QDateTime>
#if (QT_VERSION < QT_VERSION_CHECK(5, 0, 0))
#include <QTextCodec>
#endif
#include <qtranslator.h>
#include <qlocale.h>
#include <qlibraryinfo.h>

#ifdef HAVE_LIBPCAP
capture_options global_capture_opts;
capture_session global_capture_session;
#endif

capture_file cfile;

#ifdef HAVE_AIRPCAP
int    airpcap_dll_ret_val = -1;
#endif

GString *comp_info_str, *runtime_info_str;

//static gboolean have_capture_file = FALSE; /* XXX - is there an equivalent in cfile? */

static void console_log_handler(const char *log_domain,
    GLogLevelFlags log_level, const char *message, gpointer user_data);


#ifdef HAVE_LIBPCAP
extern capture_options global_capture_opts;

static void
main_capture_callback(gint event, capture_session *cap_session, gpointer user_data )
{
    Q_UNUSED(user_data);
    wsApp->captureCallback(event, cap_session);
}
#endif // HAVE_LIBPCAP

static void
main_cf_callback(gint event, gpointer data, gpointer user_data )
{
    Q_UNUSED(user_data);
    wsApp->captureFileCallback(event, data);
}

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


// xxx copied from ../gtk/main.c
static void
print_usage(gboolean print_ver) {
    FILE *output;

#ifdef _WIN32
    create_console();
#endif

    if (print_ver) {
        output = stdout;
        fprintf(output, "Wireshark %s\n"
                "Interactively dump and analyze network traffic.\n"
                "See http://www.wireshark.org for more information.\n"
                "\n"
                "%s",
                get_ws_vcs_version_info(), get_copyright_info());
    } else {
        output = stderr;
    }
    fprintf(output, "\n");
    fprintf(output, "Usage: wireshark [options] ... [ <infile> ]\n");
    fprintf(output, "\n");

#ifdef HAVE_LIBPCAP
    fprintf(output, "Capture interface:\n");
    fprintf(output, "  -i <interface>           name or idx of interface (def: first non-loopback)\n");
    fprintf(output, "  -f <capture filter>      packet filter in libpcap filter syntax\n");
    fprintf(output, "  -s <snaplen>             packet snapshot length (def: 65535)\n");
    fprintf(output, "  -p                       don't capture in promiscuous mode\n");
    fprintf(output, "  -k                       start capturing immediately (def: do nothing)\n");
    fprintf(output, "  -Q                       quit Wireshark after capturing\n");
    fprintf(output, "  -S                       update packet display when new packets are captured\n");
    fprintf(output, "  -l                       turn on automatic scrolling while -S is in use\n");
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    fprintf(output, "  -B <buffer size>         size of kernel buffer (def: %dMB)\n", DEFAULT_CAPTURE_BUFFER_SIZE);
#endif
    fprintf(output, "  -y <link type>           link layer type (def: first appropriate)\n");
    fprintf(output, "  -D                       print list of interfaces and exit\n");
    fprintf(output, "  -L                       print list of link-layer types of iface and exit\n");
    fprintf(output, "\n");
    fprintf(output, "Capture stop conditions:\n");
    fprintf(output, "  -c <packet count>        stop after n packets (def: infinite)\n");
    fprintf(output, "  -a <autostop cond.> ...  duration:NUM - stop after NUM seconds\n");
    fprintf(output, "                           filesize:NUM - stop this file after NUM KB\n");
    fprintf(output, "                              files:NUM - stop after NUM files\n");
    /*fprintf(output, "\n");*/
    fprintf(output, "Capture output:\n");
    fprintf(output, "  -b <ringbuffer opt.> ... duration:NUM - switch to next file after NUM secs\n");
    fprintf(output, "                           filesize:NUM - switch to next file after NUM KB\n");
    fprintf(output, "                              files:NUM - ringbuffer: replace after NUM files\n");
#endif  /* HAVE_LIBPCAP */

    /*fprintf(output, "\n");*/
    fprintf(output, "Input file:\n");
    fprintf(output, "  -r <infile>              set the filename to read from (no pipes or stdin!)\n");

    fprintf(output, "\n");
    fprintf(output, "Processing:\n");
    fprintf(output, "  -R <read filter>         packet filter in Wireshark display filter syntax\n");
    fprintf(output, "  -n                       disable all name resolutions (def: all enabled)\n");
    fprintf(output, "  -N <name resolve flags>  enable specific name resolution(s): \"mntC\"\n");

    fprintf(output, "\n");
    fprintf(output, "User interface:\n");
    fprintf(output, "  -C <config profile>      start with specified configuration profile\n");
    fprintf(output, "  -g <packet number>       go to specified packet number after \"-r\"\n");
    fprintf(output, "  -J <jump filter>         jump to the first packet matching the (display)\n");
    fprintf(output, "                           filter\n");
    fprintf(output, "  -j                       search backwards for a matching packet after \"-J\"\n");
    fprintf(output, "  -m <font>                set the font name used for most text\n");
    fprintf(output, "  -t ad|a|r|d|dd|e         output format of time stamps (def: r: rel. to first)\n");
    fprintf(output, "  -u s|hms                 output format of seconds (def: s: seconds)\n");
    fprintf(output, "  -X <key>:<value>         eXtension options, see man page for details\n");
    fprintf(output, "  -z <statistics>          show various statistics, see man page for details\n");

    fprintf(output, "\n");
    fprintf(output, "Output:\n");
    fprintf(output, "  -w <outfile|->           set the output filename (or '-' for stdout)\n");

    fprintf(output, "\n");
    fprintf(output, "Miscellaneous:\n");
    fprintf(output, "  -h                       display this help and exit\n");
    fprintf(output, "  -v                       display version info and exit\n");
    fprintf(output, "  -P <key>:<path>          persconf:path - personal configuration files\n");
    fprintf(output, "                           persdata:path - personal data files\n");
    fprintf(output, "  -o <name>:<value> ...    override preference or recent setting\n");
    fprintf(output, "  -K <keytab>              keytab file to use for kerberos decryption\n");
#ifndef _WIN32
    fprintf(output, "  --display=DISPLAY        X display to use\n");
#endif

#ifdef _WIN32
    destroy_console();
#endif
}

// xxx copied from ../gtk/main.c
static void
show_version(void)
{
    printf(PACKAGE " %s\n"
           "\n"
           "%s"
           "\n"
           "%s"
           "\n"
           "%s",
           get_ws_vcs_version_info(), get_copyright_info(), comp_info_str->str,
           runtime_info_str->str);
}

/*
 * Report an error in command-line arguments.
 * Creates a console on Windows.
 */
// xxx copied from ../gtk/main.c
void
cmdarg_err(const char *fmt, ...)
{
    va_list ap;

#ifdef _WIN32
    create_console();
#endif
    fprintf(stderr, "wireshark: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

/*
 * Report additional information for an error in command-line arguments.
 * Creates a console on Windows.
 * XXX - pop this up in a window of some sort on UNIX+X11 if the controlling
 * terminal isn't the standard error?
 */
// xxx copied from ../gtk/main.c
void
cmdarg_err_cont(const char *fmt, ...)
{
    va_list ap;

#ifdef _WIN32
    create_console();
#endif
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static void
console_log_handler(const char *log_domain, GLogLevelFlags log_level,
                    const char *message, gpointer user_data)
{
    Q_UNUSED(user_data);
    QString level;
    QString hmsz = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");

// xxx qtshark: We want all of the messages for now.
//    /* ignore log message, if log_level isn't interesting based
//     upon the console log preferences.
//     If the preferences haven't been loaded loaded yet, display the
//     message anyway.

//     The default console_log_level preference value is such that only
//       ERROR, CRITICAL and WARNING level messages are processed;
//       MESSAGE, INFO and DEBUG level messages are ignored.  */
//    if((log_level & G_LOG_LEVEL_MASK & prefs.console_log_level) == 0 &&
//       prefs.console_log_level != 0) {
//        return;

        switch(log_level & G_LOG_LEVEL_MASK) {
        case G_LOG_LEVEL_ERROR:
            level = "Err ";
            break;
        case G_LOG_LEVEL_CRITICAL:
            level = "Crit";
            break;
        case G_LOG_LEVEL_WARNING:
            level = "Warn";
            break;
        case G_LOG_LEVEL_MESSAGE:
            level = "Msg ";
            break;
        case G_LOG_LEVEL_INFO:
            level = "Info";
            break;
        case G_LOG_LEVEL_DEBUG:
            level = "Dbg ";
            break;
        default:
            qDebug("%s unknown log_level %u", hmsz.toUtf8().constData(), log_level);
            g_assert_not_reached();
        }

        qDebug("%s %s %s %s", hmsz.toUtf8().constData(), log_domain, level.toUtf8().constData(), message);
    }

// xxx based from ../gtk/main.c:get_gtk_compiled_info
static void
get_qt_compiled_info(GString *str)
{
    g_string_append(str, "with ");
    g_string_append_printf(str,
#ifdef QT_VERSION
                    "Qt %s ", QT_VERSION_STR);
#else
                    "Qt (version unknown) ");
#endif
}

// xxx copied from ../gtk/main.c
static void
get_gui_compiled_info(GString *str)
{
    epan_get_compiled_version_info(str);

    g_string_append(str, ", ");
    g_string_append(str, "without PortAudio");

    g_string_append(str, ", ");
#ifdef HAVE_AIRPCAP
    get_compiled_airpcap_version(str);
#else
    g_string_append(str, "without AirPcap");
#endif
}

// xxx copied from ../gtk/main.c
static void
get_wireshark_runtime_info(GString *str)
{
#ifdef HAVE_LIBPCAP
    /* Libpcap */
    g_string_append(str, ", ");
    get_runtime_pcap_version(str);
#endif

    /* zlib */
#if defined(HAVE_LIBZ) && !defined(_WIN32)
    g_string_append_printf(str, ", with libz %s", zlibVersion());
#endif

    /* stuff used by libwireshark */
    epan_get_runtime_version_info(str);

#ifdef HAVE_AIRPCAP
    g_string_append(str, ", ");
    get_runtime_airpcap_version(str);
#endif

    if(u3_active()) {
        g_string_append(str, ", ");
        u3_runtime_info(str);
    }
}

/* And now our feature presentation... [ fade to music ] */
int main(int argc, char *argv[])
{
    WiresharkApplication ws_app(argc, argv);
    MainWindow *main_w;

    int                  opt;
    gboolean             arg_error = FALSE;

#ifdef _WIN32
    WSADATA	       wsaData;
#endif  /* _WIN32 */

    char                *rf_path;
    int                  rf_open_errno;
    char                *gdp_path, *dp_path;
#ifdef HAVE_LIBPCAP
    int                  err;
    gboolean             start_capture = FALSE;
//    gboolean             list_link_layer_types = FALSE;
    GList               *if_list;
    gchar               *err_str;
#else
    gboolean             capture_option_specified = FALSE;
#ifdef _WIN32
#ifdef HAVE_AIRPCAP
    gchar               *err_str;
#endif
#endif
#endif
    e_prefs             *prefs_p;
    GLogLevelFlags       log_flags;

#ifdef _WIN32
    create_app_running_mutex();
#endif

    QString locale;
    QString *cf_name = NULL;
    QString *display_filter = NULL;
    int optind_initial;
    unsigned int in_file_type = WTAP_TYPE_AUTO;

    // In Qt 5, C strings are treated always as UTF-8 when converted to
    // QStrings; in Qt 4, the codec must be set to make that happen
#if (QT_VERSION < QT_VERSION_CHECK(5, 0, 0))
    // Hopefully we won't have to use QString::fromUtf8() in as many places.
    QTextCodec *utf8codec = QTextCodec::codecForName("UTF-8");
    QTextCodec::setCodecForCStrings(utf8codec);
    // XXX - QObject doesn't *have* a tr method in 5.0, as far as I can see...
    QTextCodec::setCodecForTr(utf8codec);
#endif


    // XXX Should the remaining code be in WiresharkApplcation::WiresharkApplication?
#define OPTSTRING OPTSTRING_CAPTURE_COMMON "C:g:Hh" "jJ:kK:lm:nN:o:P:Qr:R:St:u:vw:X:z:"
    static const struct option long_options[] = {
        {(char *)"help", no_argument, NULL, 'h'},
        {(char *)"read-file", required_argument, NULL, 'r' },
        {(char *)"version", no_argument, NULL, 'v'},
        LONGOPT_CAPTURE_COMMON
        {0, 0, 0, 0 }
    };
    static const char optstring[] = OPTSTRING;

    /* Assemble the compile-time version information string */
    comp_info_str = g_string_new("Compiled ");

    // xxx qtshark
    get_compiled_version_info(comp_info_str, get_qt_compiled_info, get_gui_compiled_info);

    /* Assemble the run-time version information string */
    runtime_info_str = g_string_new("Running ");
    // xxx qtshark
    get_runtime_version_info(runtime_info_str, get_wireshark_runtime_info);

    ws_add_crash_info(PACKAGE " %s\n"
           "\n"
           "%s"
           "\n"
           "%s",
        get_ws_vcs_version_info(), comp_info_str->str, runtime_info_str->str);

    /*
     * Get credential information for later use, and drop privileges
     * before doing anything else.
     * Let the user know if anything happened.
     */
    init_process_policies();
    relinquish_special_privs_perm();

    /*
     * Attempt to get the pathname of the executable file.
     */
    /* init_progfile_dir_error = */ init_progfile_dir(QCoreApplication::applicationFilePath().toUtf8().constData(), NULL);
    g_log(NULL, G_LOG_LEVEL_DEBUG, "progfile_dir: %s", get_progfile_dir());

    /* initialize the funnel mini-api */
    // xxx qtshark
    //initialize_funnel_ops();

    AirPDcapInitContext(&airpdcap_ctx);

// xxx qtshark
#ifdef _WIN32
    /* Load wpcap if possible. Do this before collecting the run-time version information */
    load_wpcap();

    /* ... and also load the packet.dll from wpcap */
    wpcap_packet_load();

#ifdef HAVE_AIRPCAP
    /* Load the airpcap.dll.  This must also be done before collecting
     * run-time version information. */
    airpcap_dll_ret_val = load_airpcap();

    switch (airpcap_dll_ret_val) {
    case AIRPCAP_DLL_OK:
        /* load the airpcap interfaces */
        airpcap_if_list = get_airpcap_interface_list(&err, &err_str);

        if (airpcap_if_list == NULL || g_list_length(airpcap_if_list) == 0){
            if (err == CANT_GET_AIRPCAP_INTERFACE_LIST && err_str != NULL) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", "Failed to open Airpcap Adapters!");
                g_free(err_str);
            }
            airpcap_if_active = NULL;

        } else {

            /* select the first ad default (THIS SHOULD BE CHANGED) */
            airpcap_if_active = airpcap_get_default_if(airpcap_if_list);
        }
        break;
#if 0
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
#endif
    }
#endif /* HAVE_AIRPCAP */

    /* Start windows sockets */
    WSAStartup( MAKEWORD( 1, 1 ), &wsaData );
#endif  /* _WIN32 */

    profile_store_persconffiles (TRUE);

    /* Read the profile independent recent file.  We have to do this here so we can */
    /* set the profile before it can be set from the command line parameter */
    recent_read_static(&rf_path, &rf_open_errno);
    if (rf_path != NULL && rf_open_errno != 0) {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                      "Could not open common recent file\n\"%s\": %s.",
                      rf_path, strerror(rf_open_errno));
    }
    wsApp->emitAppSignal(WiresharkApplication::StaticRecentFilesRead);


    /* "pre-scan" the command line parameters, if we have "console only"
       parameters.  We do this so we don't start Qt if we're only showing
       command-line help or version information.

        XXX - this pre-scan is done before we start Qt. That means that Qt
       arguments have not been removed from the argument list; those arguments
       begin with "--", and will be treated as an error by getopt().

       We thus ignore errors - *and* set "opterr" to 0 to suppress the
       error messages.*/

    opterr = 0;
    optind_initial = optind;
    while ((opt = getopt(argc, argv, optstring)) != -1) {
        switch (opt) {
            case 'C':        /* Configuration Profile */
                if (profile_exists (optarg, FALSE)) {
                    set_profile_name (optarg);
                } else {
                    cmdarg_err("Configuration Profile \"%s\" does not exist", optarg);
                    exit(1);
                }
                break;
            case 'D':        /* Print a list of capture devices and exit */
#ifdef HAVE_LIBPCAP
                if_list = capture_interface_list(&err, &err_str,main_window_update);
                if (if_list == NULL) {
                    switch (err) {
                        case CANT_GET_INTERFACE_LIST:
                        case DONT_HAVE_PCAP:
                            cmdarg_err("%s", err_str);
                            g_free(err_str);
                            break;

                        case NO_INTERFACES_FOUND:
                            cmdarg_err("There are no interfaces on which a capture can be done");
                            break;
                    }
                    exit(2);
                }
#ifdef _WIN32
                create_console();
#endif /* _WIN32 */
                capture_opts_print_interfaces(if_list);
                free_interface_list(if_list);
#ifdef _WIN32
                destroy_console();
#endif /* _WIN32 */
                exit(0);
#else /* HAVE_LIBPCAP */
                capture_option_specified = TRUE;
                arg_error = TRUE;
#endif /* HAVE_LIBPCAP */
                break;
            case 'h':        /* Print help and exit */
                print_usage(TRUE);
                exit(0);
                break;
#ifdef _WIN32
            case 'i':
                if (strcmp(optarg, "-") == 0)
                    set_stdin_capture(TRUE);
                break;
#endif
            case 'P':        /* Personal file directory path settings - change these before the Preferences and alike are processed */
                if (!persfilepath_opt(opt, optarg)) {
                    cmdarg_err("-P flag \"%s\" failed (hint: is it quoted and existing?)", optarg);
                    exit(2);
                }
                break;
            case 'v':        /* Show version and exit */
#ifdef _WIN32
                create_console();
#endif
                show_version();
#ifdef _WIN32
                destroy_console();
#endif
                exit(0);
                break;
            case 'X':
                /*
                 *  Extension command line options have to be processed before
                 *  we call epan_init() as they are supposed to be used by dissectors
                 *  or taps very early in the registration process.
                 */
                ex_opt_add(optarg);
                break;
            case '?':        /* Ignore errors - the "real" scan will catch them. */
                break;
        }
    }

    /* Init the "Open file" dialog directory */
    /* (do this after the path settings are processed) */

    /* Read the profile dependent (static part) of the recent file. */
    /* Only the static part of it will be read, as we don't have the gui now to fill the */
    /* recent lists which is done in the dynamic part. */
    /* We have to do this already here, so command line parameters can overwrite these values. */
    recent_read_profile_static(&rf_path, &rf_open_errno);
    if (rf_path != NULL && rf_open_errno != 0) {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                      "Could not open recent file\n\"%s\": %s.",
                      rf_path, g_strerror(rf_open_errno));
    }


    /* Set getopt index back to initial value, so it will start with the
       first command line parameter again.  Also reset opterr to 1, so that
       error messages are printed by getopt().

       XXX - this seems to work on most platforms, but time will tell.
       The Single UNIX Specification says "The getopt() function need
       not be reentrant", so this isn't guaranteed to work.  The Mac
       OS X 10.4[.x] getopt() man page says

         In order to use getopt() to evaluate multiple sets of arguments, or to
         evaluate a single set of arguments multiple times, the variable optreset
         must be set to 1 before the second and each additional set of calls to
         getopt(), and the variable optind must be reinitialized.

           ...

         The optreset variable was added to make it possible to call the getopt()
         function multiple times.  This is an extension to the IEEE Std 1003.2
         (``POSIX.2'') specification.

       which I think comes from one of the other BSDs.

       XXX - if we want to control all the command-line option errors, so
       that we can display them where we choose (e.g., in a window), we'd
       want to leave opterr as 0, and produce our own messages using optopt.
       We'd have to check the value of optopt to see if it's a valid option
       letter, in which case *presumably* the error is "this option requires
       an argument but none was specified", or not a valid option letter,
       in which case *presumably* the error is "this option isn't valid".
       Some versions of getopt() let you supply a option string beginning
       with ':', which means that getopt() will return ':' rather than '?'
       for "this option requires an argument but none was specified", but
       not all do. */
    optind = optind_initial;
    opterr = 1;

    // Init the main window (and splash)
    main_w = new(MainWindow);
    main_w->show();
    // We may not need a queued connection here but it would seem to make sense
    // to force the issue.
    main_w->connect(&ws_app, SIGNAL(openCaptureFile(QString&,QString&,unsigned int)),
            main_w, SLOT(openCaptureFile(QString&,QString&,unsigned int)));

    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        switch (opt) {
        case 'r':
            cf_name = new QString(optarg);
            break;
        case '?':
            print_usage(TRUE);
            exit(0);
            break;
        }
    }

    if (!arg_error) {
        argc -= optind;
        argv += optind;
        if (argc >= 1) {
            if (cf_name != NULL) {
                /*
                 * Input file name specified with "-r" *and* specified as a regular
                 * command-line argument.
                 */
                cmdarg_err("File name specified both with -r and regular argument");
                arg_error = TRUE;
            } else {
                /*
                 * Input file name not specified with "-r", and a command-line argument
                 * was specified; treat it as the input file name.
                 *
                 * Yes, this is different from tshark, where non-flag command-line
                 * arguments are a filter, but this works better on GUI desktops
                 * where a command can be specified to be run to open a particular
                 * file - yes, you could have "-r" as the last part of the command,
                 * but that's a bit ugly.
                 */
                cf_name = new QString(g_strdup(argv[0]));

            }
            argc--;
            argv++;
        }

        if (argc != 0) {
            /*
             * Extra command line arguments were specified; complain.
             */
            cmdarg_err("Invalid argument: %s", argv[0]);
            arg_error = TRUE;
        }
    }
    if (arg_error) {
#ifndef HAVE_LIBPCAP
        if (capture_option_specified) {
            cmdarg_err("This version of Wireshark was not built with support for capturing packets.");
        }
#endif
        print_usage(FALSE);
        exit(1);
    }

    /* Init the "Open file" dialog directory */
    /* (do this after the path settings are processed) */

    /* Read the profile dependent (static part) of the recent file. */
    /* Only the static part of it will be read, as we don't have the gui now to fill the */
    /* recent lists which is done in the dynamic part. */
    /* We have to do this already here, so command line parameters can overwrite these values. */
    recent_read_profile_static(&rf_path, &rf_open_errno);
    if (rf_path != NULL && rf_open_errno != 0) {
      simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
            "Could not open recent file\n\"%s\": %s.",
            rf_path, g_strerror(rf_open_errno));
    }

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

#ifdef HAVE_LIBPCAP
    capture_callback_add(main_capture_callback, NULL);
#endif
    cf_callback_add(main_cf_callback, NULL);

    /* Arrange that if we have no console window, and a GLib message logging
       routine is called to log a message, we pop up a console window.

       We do that by inserting our own handler for all messages logged
       to the default domain; that handler pops up a console if necessary,
       and then calls the default handler. */

    /* We might want to have component specific log levels later ... */

    log_flags = (GLogLevelFlags) (
            G_LOG_LEVEL_ERROR|
            G_LOG_LEVEL_CRITICAL|
            G_LOG_LEVEL_WARNING|
            G_LOG_LEVEL_MESSAGE|
            G_LOG_LEVEL_INFO|
            G_LOG_LEVEL_DEBUG|
            G_LOG_FLAG_FATAL|G_LOG_FLAG_RECURSION );

    g_log_set_handler(NULL,
                      log_flags,
                      console_log_handler, NULL /* user_data */);
    g_log_set_handler(LOG_DOMAIN_MAIN,
                      log_flags,
                      console_log_handler, NULL /* user_data */);

#ifdef HAVE_LIBPCAP
    g_log_set_handler(LOG_DOMAIN_CAPTURE,
                      log_flags,
                      console_log_handler, NULL /* user_data */);
    g_log_set_handler(LOG_DOMAIN_CAPTURE_CHILD,
                      log_flags,
                      console_log_handler, NULL /* user_data */);

    /* Set the initial values in the capture options. This might be overwritten
       by preference settings and then again by the command line parameters. */
    capture_opts_init(&global_capture_opts);

    capture_session_init(&global_capture_session, (void *)&cfile);
#endif

    init_report_err(failure_alert_box, open_failure_alert_box,
                    read_failure_alert_box, write_failure_alert_box);

    init_open_routines();

#ifdef HAVE_PLUGINS
    /* Register all the plugin types we have. */
    epan_register_plugin_types(); /* Types known to libwireshark */
    wtap_register_plugin_types(); /* Types known to libwiretap */
    codec_register_plugin_types(); /* Types known to libcodec */

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
    epan_init(register_all_protocols,register_all_protocol_handoffs,
              splash_update, NULL);

    splash_update(RA_LISTENERS, NULL, NULL);

    /* Register all tap listeners; we do this before we parse the arguments,
       as the "-z" argument can specify a registered tap. */

    /* we register the plugin taps before the other taps because
            stats_tree taps plugins will be registered as tap listeners
            by stats_tree_stat.c and need to registered before that */

    g_log(NULL, G_LOG_LEVEL_DEBUG, "plugin_dir: %s", get_plugin_dir());
#ifdef HAVE_PLUGINS
    register_all_plugin_tap_listeners();
#endif

    register_all_tap_listeners();

    if (ex_opt_count("read_format") > 0) {
        in_file_type = open_info_name_to_type(ex_opt_get_next("read_format"));
    }

    splash_update(RA_PREFERENCES, NULL, NULL);
    prefs_p = ws_app.readConfigurationFiles (&gdp_path, &dp_path);

    // Initialize our language

    /*TODO: Enhance... may be get the locale from the enum gui_qt_language */
    switch(prefs_p->gui_qt_language){
        case 1: /* English */
        locale = "en";
        break;
        case 2: /* French */
        locale = "fr";
        break;
        case 3: /* German */
        locale = "de";
        break;
        case 4: /* Chinese */
        locale = "zh_CN";
        break;
        case 5: /* Polish */
        locale = "pl";
        break;
        default: /* Auto-Detect */
        locale = QLocale::system().name();
        break;
    }
    g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Translator %s", locale.toStdString().c_str());
    QTranslator translator;
    translator.load(QString(":/i18n/qtshark_") + locale);
    wsApp->installTranslator(&translator);

    QTranslator qtTranslator;
    qtTranslator.load("qt_" + locale, QLibraryInfo::location(QLibraryInfo::TranslationsPath));
    wsApp->installTranslator(&qtTranslator);

    /* Removed thread code:
     * https://code.wireshark.org/review/gitweb?p=wireshark.git;a=commit;h=9e277ae6154fd04bf6a0a34ec5655a73e5a736a3
     */

    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: timestamp types should be set elsewhere");
    timestamp_set_type(TS_RELATIVE);
    timestamp_set_precision(TS_PREC_AUTO_USEC);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

#ifdef HAVE_LIBPCAP
    fill_in_local_interfaces(main_window_update);

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
    }

    build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

    wsApp->setMonospaceFont(prefs.gui_qt_font_name);

////////

    /* Read the dynamic part of the recent file, as we have the gui now ready for
       it. */
    recent_read_dynamic(&rf_path, &rf_open_errno);
    if (rf_path != NULL && rf_open_errno != 0) {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
                      "Could not open recent file\n\"%s\": %s.",
                      rf_path, g_strerror(rf_open_errno));
    }

    color_filters_enable(recent.packet_list_colorize);

    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: fetch recent color settings");
    color_filters_enable(TRUE);

////////


////////
    color_filters_init();

////////

#ifdef HAVE_LIBPCAP
    /* if the user didn't supply a capture filter, use the one to filter out remote connections like SSH */
    if (!start_capture && !global_capture_opts.default_options.cfilter) {
        global_capture_opts.default_options.cfilter = g_strdup(get_conn_cfilter());
    }
#else /* HAVE_LIBPCAP */
    ////////
#endif /* HAVE_LIBPCAP */

//    w->setEnabled(true);
    wsApp->allSystemsGo();
    g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_INFO, "Wireshark is up and ready to go");

    /* user could specify filename, or display filter, or both */
    if (cf_name != NULL || display_filter != NULL) {
        if (display_filter == NULL)
            display_filter = new QString();
        if (cf_name == NULL)
            cf_name = new QString();
        main_w->openCaptureFile(*cf_name, *display_filter, in_file_type);
    }

    g_main_loop_new(NULL, FALSE);
    return wsApp->exec();
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
