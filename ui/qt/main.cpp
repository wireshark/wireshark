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

#include "simple_dialog.h"
#include "main_window.h"
#include "wireshark_application.h"

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

#include <wsutil/clopts_common.h>
#include <wsutil/cmdarg_err.h>
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
#include <epan/conversation_table.h>
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
#include "version_info.h"
#include "log.h"

#include "ui/alert_box.h"
#include "ui/capture_globals.h"
#ifdef HAVE_LIBPCAP
#  include "ui/capture_ui_utils.h"
#endif
#include "ui/console.h"
#include "ui/iface_lists.h"
#include "ui/main_statusbar.h"
#include "ui/persfilepath_opt.h"
#include "ui/recent.h"
#include "ui/simple_dialog.h"
#include "ui/ui_util.h"

#include "caputils/capture-pcap-util.h"

#ifdef HAVE_LIBPCAP
#  include "caputils/capture_ifinfo.h"
#  include "ui/capture.h"
#  include "capchild/capture_sync.h"
#endif

#ifdef _WIN32
#  include "caputils/capture-wpcap.h"
#  include "caputils/capture_wpcap_packet.h"
#  include <tchar.h> /* Needed for Unicode */
#  include <wsutil/os_version_info.h>
#  include <wsutil/unicode-utils.h>
#  include <commctrl.h>
#  include <shellapi.h>
#endif /* _WIN32 */

#ifdef HAVE_AIRPCAP
#  include <caputils/airpcap.h>
#  include <caputils/airpcap_loader.h>
//#  include "airpcap_dlg.h"
//#  include "airpcap_gui_utils.h"
#endif

#include "epan/crypt/airpdcap_ws.h"

#include <QDateTime>
#include <QLibraryInfo>
#include <QLocale>
#include <QMessageBox>
#if (QT_VERSION < QT_VERSION_CHECK(5, 0, 0))
#include <QTextCodec>
#endif
#include <QTranslator>

#include "conversation_dialog.h"
#include "endpoint_dialog.h"

#ifdef HAVE_LIBPCAP
capture_options global_capture_opts;
#endif

capture_file cfile;

#ifdef HAVE_AIRPCAP
int    airpcap_dll_ret_val = -1;
#endif

GString *comp_info_str, *runtime_info_str;

//static gboolean have_capture_file = FALSE; /* XXX - is there an equivalent in cfile? */

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
print_usage(gboolean for_help_option) {
    FILE *output;

#ifdef _WIN32
    create_console();
#endif

    if (for_help_option) {
        output = stdout;
        fprintf(output, "Wireshark %s\n"
                "Interactively dump and analyze network traffic.\n"
                "See http://www.wireshark.org for more information.\n",
                get_ws_vcs_version_info());
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
    fprintf(output, "  -S                       update packet display when new packets are captured\n");
    fprintf(output, "  -l                       turn on automatic scrolling while -S is in use\n");
#ifdef HAVE_PCAP_CREATE
    fprintf(output, "  -I                       capture in monitor mode, if available\n");
#endif
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
#ifdef HAVE_PCAP_REMOTE
    fprintf(output, "RPCAP options:\n");
    fprintf(output, "  -A <user>:<password>     use RPCAP password authentication\n");
#endif
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
    fprintf(output, "  -Y <display filter>      start with the given display filter\n");
    fprintf(output, "  -g <packet number>       go to specified packet number after \"-r\"\n");
    fprintf(output, "  -J <jump filter>         jump to the first packet matching the (display)\n");
    fprintf(output, "                           filter\n");
    fprintf(output, "  -j                       search backwards for a matching packet after \"-J\"\n");
    fprintf(output, "  -m <font>                set the font name used for most text\n");
    fprintf(output, "  -t a|ad|d|dd|e|r|u|ud    output format of time stamps (def: r: rel. to first)\n");
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
    fprintf(output, "\nNOTE: Not all options are implemented in the Qt port.\n");

#ifdef _WIN32
    destroy_console();
#endif
}

// xxx copied from ../gtk/main.c
static void
show_version(void)
{
    printf("Wireshark %s\n"
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
static void
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

    /* LIBZ */
    g_string_append(str, ", ");
#ifdef HAVE_LIBZ
    g_string_append(str, "with libz ");
#ifdef ZLIB_VERSION
    g_string_append(str, ZLIB_VERSION);
#else /* ZLIB_VERSION */
    g_string_append(str, "(version unknown)");
#endif /* ZLIB_VERSION */
#else /* HAVE_LIBZ */
    g_string_append(str, "without libz");
#endif /* HAVE_LIBZ */
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
    /* Capture libraries */
    g_string_append(str, ", ");
    get_runtime_caplibs_version(str);
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
        "http://wiki.wireshark.org/CaptureSetup/CapturePrivileges", cur_user, cur_group);
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
    gboolean             list_link_layer_types = FALSE;
    GList               *if_list;
    gchar               *err_str;
    int                  status;
#else
    gboolean             capture_option_specified = FALSE;
#ifdef _WIN32
#ifdef HAVE_AIRPCAP
    gchar               *err_str;
#endif
#endif
#endif
    e_prefs             *prefs_p;
    char                 badopt;
    guint                go_to_packet = 0;

    cmdarg_err_init(wireshark_cmdarg_err, wireshark_cmdarg_err_cont);

#ifdef _WIN32
    create_app_running_mutex();
#endif

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
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", "Failed to open Airpcap Adapters.");
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
#endif /* _WIN32 */

    QString locale;
    QString cf_name;
    QString display_filter;
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
#define OPTSTRING OPTSTRING_CAPTURE_COMMON "C:g:Hh" "jJ:kK:lm:nN:o:P:r:R:St:u:vw:X:Y:z:"
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
    get_compiled_version_info(comp_info_str, get_wireshark_qt_compiled_info,
                              get_gui_compiled_info);

    /* Assemble the run-time version information string */
    runtime_info_str = g_string_new("Running ");
    // xxx qtshark
    get_runtime_version_info(runtime_info_str, get_wireshark_runtime_info);

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
                    if (err == 0)
                        cmdarg_err("There are no interfaces on which a capture can be done");
                    else {
                        cmdarg_err("%s", err_str);
                        g_free(err_str);
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
    SimpleDialog::displayQueuedMessages(main_w);
    // We may not need a queued connection here but it would seem to make sense
    // to force the issue.
    main_w->connect(&ws_app, SIGNAL(openCaptureFile(QString&,QString&,unsigned int)),
            main_w, SLOT(openCaptureFile(QString&,QString&,unsigned int)));

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
    wsApp->emitAppSignal(WiresharkApplication::StaticRecentFilesRead);

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

    set_console_log_handler();

#ifdef HAVE_LIBPCAP
    /* Set the initial values in the capture options. This might be overwritten
       by preference settings and then again by the command line parameters. */
    capture_opts_init(&global_capture_opts);
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
    conversation_table_set_gui_info(init_conversation_table);
    hostlist_table_set_gui_info(init_endpoint_table);

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
        case 6: /* Japanese */
        locale = "ja_JP";
        break;
        case 7: /* Italian */
        locale = "it";
        break;
        default: /* Auto-Detect */
        locale = QLocale::system().name();
        break;
    }
    g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Translator %s", locale.toStdString().c_str());
    QTranslator translator;
    translator.load(QString(":/i18n/wireshark_") + locale);
    wsApp->installTranslator(&translator);

    QTranslator qtTranslator;
    qtTranslator.load("qt_" + locale, QLibraryInfo::location(QLibraryInfo::TranslationsPath));
    wsApp->installTranslator(&qtTranslator);

    /* Now get our args */
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        switch (opt) {
        /*** capture option specific ***/
        case 'a':        /* autostop criteria */
        case 'b':        /* Ringbuffer option */
        case 'c':        /* Capture xxx packets */
        case 'f':        /* capture filter */
        case 'k':        /* Start capture immediately */
        case 'H':        /* Hide capture info dialog box */
        case 'p':        /* Don't capture in promiscuous mode */
        case 'i':        /* Use interface x */
#ifdef HAVE_PCAP_CREATE
        case 'I':        /* Capture in monitor mode, if available */
#endif
#ifdef HAVE_PCAP_REMOTE
        case 'A':        /* Authentication */
#endif
        case 's':        /* Set the snapshot (capture) length */
        case 'S':        /* "Sync" mode: used for following file ala tail -f */
        case 'w':        /* Write to capture file xxx */
        case 'y':        /* Set the pcap data link type */
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
        case 'B':        /* Buffer size */
#endif /* _WIN32 or HAVE_PCAP_CREATE */
#ifdef HAVE_LIBPCAP
            status = capture_opts_add_opt(&global_capture_opts, opt, optarg,
                                          &start_capture);
            if(status != 0) {
                exit(status);
            }
#else
            capture_option_specified = TRUE;
            arg_error = TRUE;
#endif
            break;
#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
        case 'K':        /* Kerberos keytab file */
                read_keytab_file(optarg);
            break;
#endif
        case 'C':
            /* Configuration profile settings were already processed just ignore them this time*/
            break;
        case 'j':        /* Search backwards for a matching packet from filter in option J */
            /* Not supported yet */
            break;
        case 'g':        /* Go to packet with the given packet number */
            go_to_packet = get_positive_int(optarg, "go to packet");
            break;
        case 'J':        /* Jump to the first packet which matches the filter criteria */
            /* Not supported yet */
            break;
        case 'l':        /* Automatic scrolling in live capture mode */
            /* Not supported yet */
            break;
        case 'L':        /* Print list of link-layer types and exit */
#ifdef HAVE_LIBPCAP
                list_link_layer_types = TRUE;
#else
                capture_option_specified = TRUE;
                arg_error = TRUE;
#endif
            break;
        case 'm':        /* Fixed-width font for the display */
            /* Not supported yet */
            break;
        case 'n':        /* No name resolution */
            gbl_resolv_flags.mac_name = FALSE;
            gbl_resolv_flags.network_name = FALSE;
            gbl_resolv_flags.transport_name = FALSE;
            gbl_resolv_flags.concurrent_dns = FALSE;
            break;
        case 'N':        /* Select what types of addresses/port #s to resolve */
            badopt = string_to_name_resolve(optarg, &gbl_resolv_flags);
            if (badopt != '\0') {
                cmdarg_err("-N specifies unknown resolving option '%c'; valid options are 'm', 'n', and 't'",
                           badopt);
                exit(1);
            }
            break;
        case 'o':        /* Override preference from command line */
            switch (prefs_set_pref(optarg)) {
                case PREFS_SET_OK:
                    break;
                case PREFS_SET_SYNTAX_ERR:
                    cmdarg_err("Invalid -o flag \"%s\"", optarg);
                    exit(1);
                    break;
                case PREFS_SET_NO_SUCH_PREF:
                /* not a preference, might be a recent setting */
                    switch (recent_set_arg(optarg)) {
                        case PREFS_SET_OK:
                            break;
                        case PREFS_SET_SYNTAX_ERR:
                            /* shouldn't happen, checked already above */
                            cmdarg_err("Invalid -o flag \"%s\"", optarg);
                            exit(1);
                            break;
                        case PREFS_SET_NO_SUCH_PREF:
                        case PREFS_SET_OBSOLETE:
                            cmdarg_err("-o flag \"%s\" specifies unknown preference/recent value",
                                       optarg);
                            exit(1);
                            break;
                        default:
                            g_assert_not_reached();
                    }
                    break;
                case PREFS_SET_OBSOLETE:
                    cmdarg_err("-o flag \"%s\" specifies obsolete preference",
                               optarg);
                    exit(1);
                    break;
                default:
                    g_assert_not_reached();
            }
            break;
        case 'P':
            /* Path settings were already processed just ignore them this time*/
            break;
        case 'r':
            cf_name = optarg;
            break;
        case 'R':        /* Read file filter */
            /* Not supported yet */
            break;
        case 't':        /* Time stamp type */
            if (strcmp(optarg, "r") == 0)
                timestamp_set_type(TS_RELATIVE);
            else if (strcmp(optarg, "a") == 0)
                timestamp_set_type(TS_ABSOLUTE);
            else if (strcmp(optarg, "ad") == 0)
                timestamp_set_type(TS_ABSOLUTE_WITH_YMD);
            else if (strcmp(optarg, "adoy") == 0)
                timestamp_set_type(TS_ABSOLUTE_WITH_YDOY);
            else if (strcmp(optarg, "d") == 0)
                timestamp_set_type(TS_DELTA);
            else if (strcmp(optarg, "dd") == 0)
                timestamp_set_type(TS_DELTA_DIS);
            else if (strcmp(optarg, "e") == 0)
                timestamp_set_type(TS_EPOCH);
            else if (strcmp(optarg, "u") == 0)
                timestamp_set_type(TS_UTC);
            else if (strcmp(optarg, "ud") == 0)
                timestamp_set_type(TS_UTC_WITH_YMD);
            else if (strcmp(optarg, "udoy") == 0)
                timestamp_set_type(TS_UTC_WITH_YDOY);
            else {
                cmdarg_err("Invalid time stamp type \"%s\"", optarg);
                cmdarg_err_cont(
"It must be \"a\" for absolute, \"ad\" for absolute with YYYY-MM-DD date,");
                cmdarg_err_cont(
"\"adoy\" for absolute with YYYY/DOY date, \"d\" for delta,");
                cmdarg_err_cont(
"\"dd\" for delta displayed, \"e\" for epoch, \"r\" for relative,");
                cmdarg_err_cont(
"\"u\" for absolute UTC, \"ud\" for absolute UTC with YYYY-MM-DD date,");
                cmdarg_err_cont(
"or \"udoy\" for absolute UTC with YYYY/DOY date.");
                exit(1);
            }
            break;
        case 'u':        /* Seconds type */
            if (strcmp(optarg, "s") == 0)
                timestamp_set_seconds_type(TS_SECONDS_DEFAULT);
            else if (strcmp(optarg, "hms") == 0)
                timestamp_set_seconds_type(TS_SECONDS_HOUR_MIN_SEC);
            else {
                cmdarg_err("Invalid seconds type \"%s\"", optarg);
                cmdarg_err_cont(
"It must be \"s\" for seconds or \"hms\" for hours, minutes and seconds.");
                exit(1);
            }
            break;
        case 'X':
            /* ext ops were already processed just ignore them this time*/
            break;
        case 'Y':
            /* Not supported yet */
            break;
        case 'z':
            /* We won't call the init function for the stat this soon
             as it would disallow MATE's fields (which are registered
             by the preferences set callback) from being used as
             part of a tap filter.  Instead, we just add the argument
             to a list of stat arguments. */
            if (!process_stat_cmd_arg(optarg)) {
                cmdarg_err("Invalid -z argument.");
                cmdarg_err_cont("  -z argument must be one of :");
                list_stat_cmd_args();
                exit(1);
            }
            break;
        default:
        case '?':
            print_usage(FALSE);
            exit(0);
            break;
        }
    }

    if (!arg_error) {
        argc -= optind;
        argv += optind;
        if (argc >= 1) {
            if (!cf_name.isEmpty()) {
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
                cf_name = argv[0];

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

    /* Removed thread code:
     * https://code.wireshark.org/review/gitweb?p=wireshark.git;a=commit;h=9e277ae6154fd04bf6a0a34ec5655a73e5a736a3
     */

    // XXX Is there a better place to set the timestamp format & precision?
    timestamp_set_type(recent.gui_time_format);
    timestamp_set_precision(recent.gui_time_precision);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

#ifdef HAVE_LIBPCAP
    fill_in_local_interfaces(main_window_update);

    if (start_capture && list_link_layer_types) {
        /* Specifying *both* is bogus. */
        cmdarg_err("You can't specify both -L and a live capture.");
        exit(1);
    }

    if (list_link_layer_types) {
        /* We're supposed to list the link-layer types for an interface;
           did the user also specify a capture file to be read? */
        if (!cf_name.isEmpty()) {
            /* Yes - that's bogus. */
            cmdarg_err("You can't specify -L and a capture file to be read.");
        exit(1);
        }
        /* No - did they specify a ring buffer option? */
        if (global_capture_opts.multi_files_on) {
            cmdarg_err("Ring buffer requested, but a capture isn't being done.");
            exit(1);
        }
    } else {
        /* We're supposed to do a live capture; did the user also specify
           a capture file to be read? */
        if (start_capture && !cf_name.isEmpty()) {
            /* Yes - that's bogus. */
            cmdarg_err("You can't specify both a live capture and a capture file to be read.");
            exit(1);
        }

        /* No - was the ring buffer option specified and, if so, does it make
           sense? */
        if (global_capture_opts.multi_files_on) {
            /* Ring buffer works only under certain conditions:
             a) ring buffer does not work with temporary files;
             b) real_time_mode and multi_files_on are mutually exclusive -
             real_time_mode takes precedence;
             c) it makes no sense to enable the ring buffer if the maximum
             file size is set to "infinite". */
            if (global_capture_opts.save_file == NULL) {
                cmdarg_err("Ring buffer requested, but capture isn't being saved to a permanent file.");
                global_capture_opts.multi_files_on = FALSE;
            }
            if (!global_capture_opts.has_autostop_filesize && !global_capture_opts.has_file_duration) {
                cmdarg_err("Ring buffer requested, but no maximum capture file size or duration were specified.");
                /* XXX - this must be redesigned as the conditions changed */
            }
        }
    }

    if (start_capture || list_link_layer_types) {
        /* We're supposed to do a live capture or get a list of link-layer
           types for a live capture device; if the user didn't specify an
           interface to use, pick a default. */
        status = capture_opts_default_iface_if_necessary(&global_capture_opts,
        ((prefs_p->capture_device) && (*prefs_p->capture_device != '\0')) ? get_if_name(prefs_p->capture_device) : NULL);
        if (status != 0) {
            exit(status);
        }
    }

    if (list_link_layer_types) {
        /* Get the list of link-layer types for the capture devices. */
        if_capabilities_t *caps;
        guint i;
        interface_t device;
        for (i = 0; i < global_capture_opts.all_ifaces->len; i++) {

            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (device.selected) {
#if defined(HAVE_PCAP_CREATE)
                caps = capture_get_if_capabilities(device.name, device.monitor_mode_supported, &err_str, main_window_update);
#else
                caps = capture_get_if_capabilities(device.name, FALSE, &err_str,main_window_update);
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
    if (!cf_name.isEmpty()) {

        /* Open stat windows; we do so after creating the main window,
           to avoid Qt warnings, and after successfully opening the
           capture file, so we know we have something to compute stats
           on, and after registering all dissectors, so that MATE will
           have registered its field array and we can have a tap filter
           with one of MATE's late-registered fields as part of the
           filter. */
        start_requested_stats();

        // XXX The GTK+ UI does error checking here.
        main_w->openCaptureFile(cf_name, display_filter, in_file_type);
        if(go_to_packet != 0) {
            /* Jump to the specified frame number, kept for backward
               compatibility. */
            cf_goto_frame(&cfile, go_to_packet);
        }
    }
#ifdef HAVE_LIBPCAP
    else {
        if (start_capture) {
            if (global_capture_opts.save_file != NULL) {
                /* Save the directory name for future file dialogs. */
                /* (get_dirname overwrites filename) */
                gchar *s = get_dirname(g_strdup(global_capture_opts.save_file));
                set_last_open_dir(s);
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
            cfile.window = main_w;
            if (capture_start(&global_capture_opts, main_w->captureSession(), main_window_update)) {
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
        if (!start_capture && !global_capture_opts.default_options.cfilter) {
            global_capture_opts.default_options.cfilter = g_strdup(get_conn_cfilter());
        }
    }
#endif /* HAVE_LIBPCAP */

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
