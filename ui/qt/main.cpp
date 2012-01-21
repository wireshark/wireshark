/* main.cpp
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "wireshark_application.h"
#include "main_window.h"

#include "config.h"

#include "globals.h"

#include <glib.h>

#ifndef HAVE_GETOPT
#include "wsutil/wsgetopt.h"
#endif

#ifdef HAVE_LIBPORTAUDIO
#include <portaudio.h>
#endif /* HAVE_LIBPORTAUDIO */

#include <epan/epan.h>
#include <epan/filesystem.h>
#include <wsutil/privileges.h>
#include <epan/epan_dissect.h>
#include <epan/timestamp.h>
#include <epan/packet.h>
#include <epan/plugins.h>
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

/* general (not Qt specific) */
#include "file.h"
#include "summary.h"
#include "filters.h"
#include "disabled_protos.h"
#include "color.h"
#include "color_filters.h"
#include "print.h"
#include "register.h"
#include "ringbuffer.h"
#include "util.h"
#include "clopts_common.h"
#include "console_io.h"
#include "cmdarg_err.h"
#include "version_info.h"
#include "merge.h"
#include "log.h"
#include "u3.h"
#include <wsutil/file_util.h>

#include "ui/alert_box.h"
#include "ui/main_statusbar.h"
#include "ui/recent.h"
#include "ui/simple_dialog.h"
#include "ui/ui_util.h"

#ifdef HAVE_LIBPCAP
#include "capture_ui_utils.h"
#include "capture-pcap-util.h"
#include "capture_ifinfo.h"
#include "capture.h"
#include "capture_sync.h"
#endif

#ifdef _WIN32
#include "capture-wpcap.h"
#include "capture_wpcap_packet.h"
#include <tchar.h> /* Needed for Unicode */
#include <wsutil/unicode-utils.h>
#include <commctrl.h>
#include <shellapi.h>
#endif /* _WIN32 */

#ifdef HAVE_AIRPCAP
#include <airpcap.h>
#include "airpcap_loader.h"
//#include "airpcap_dlg.h"
//#include "airpcap_gui_utils.h"
#endif

#include <epan/crypt/airpdcap_ws.h>

#include "monospace_font.h"

#include <QDebug>
#include <QDateTime>
#include <QTextCodec>

capture_file cfile;

#ifdef HAVE_AIRPCAP
int    airpcap_dll_ret_val = -1;
#endif

GString *comp_info_str, *runtime_info_str;

static gboolean have_capture_file = FALSE; /* XXX - is there an equivalent in cfile? */

static guint  tap_update_timer_id;

#ifdef _WIN32
static gboolean has_console;	/* TRUE if app has console */
static gboolean console_wait;	/* "Press any key..." */
//static void destroy_console(void);
static gboolean stdin_capture = FALSE; /* Don't grab stdin & stdout if TRUE */
#endif
static void console_log_handler(const char *log_domain,
    GLogLevelFlags log_level, const char *message, gpointer user_data);

void create_console(void);

#ifdef HAVE_LIBPCAP
capture_options global_capture_opts;
#endif

// Copied from ui/gtk/gui_utils.c
void pipe_input_set_handler(gint source, gpointer user_data, int *child_process, pipe_input_cb_t input_cb)
{
//    static pipe_input_t pipe_input;

//    pipe_input.source        = source;
//    pipe_input.child_process = child_process;
//    pipe_input.user_data     = user_data;
//    pipe_input.input_cb      = input_cb;

    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: pipe_input_set_handler");
//#ifdef _WIN32
//    /* Tricky to use pipes in win9x, as no concept of wait.  NT can
//       do this but that doesn't cover all win32 platforms.  GTK can do
//       this but doesn't seem to work over processes.  Attempt to do
//       something similar here, start a timer and check for data on every
//       timeout. */
//    /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_input_set_handler: new");*/
//    pipe_input.pipe_input_id = g_timeout_add(200, pipe_timer_cb, &pipe_input);
//#else
//    pipe_input.channel = g_io_channel_unix_new(source);
//    g_io_channel_set_encoding(pipe_input.channel, NULL, NULL);
//    pipe_input.pipe_input_id = g_io_add_watch_full(pipe_input.channel,
//                                                   G_PRIORITY_HIGH,
//                                                   G_IO_IN|G_IO_ERR|G_IO_HUP,
//                                                   pipe_input_cb,
//                                                   &pipe_input,
//                                                   NULL);
//#endif
}

static void
main_cf_callback(gint event, gpointer data, gpointer user_data )
{
    Q_UNUSED(user_data);
    wsApp->captureFileCallback(event, data);
}

// XXX Copied from ui/gtk/main.c. This should be moved to a common location.
static e_prefs *
read_configuration_files(char **gdp_path, char **dp_path)
{
  int                  gpf_open_errno, gpf_read_errno;
  int                  cf_open_errno, df_open_errno;
  int                  gdp_open_errno, gdp_read_errno;
  int                  dp_open_errno, dp_read_errno;
  char                *gpf_path, *pf_path;
  char                *cf_path, *df_path;
  int                  pf_open_errno, pf_read_errno;
  e_prefs             *prefs_p;

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

/* update the main window */
void main_window_update(void)
{
    WiresharkApplication::processEvents();
}

/* exit the main window */
void main_window_exit(void)
{
    exit(0);
}

#ifdef HAVE_LIBPCAP

/* quit a nested main window */
void main_window_nested_quit(void)
{
//    if (gtk_main_level() > 0)
    WiresharkApplication::quit();
}

/* quit the main window */
void main_window_quit(void)
{
    WiresharkApplication::quit();
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
        fprintf(output, "Wireshark " VERSION "%s\n"
                "Interactively dump and analyze network traffic.\n"
                "See http://www.wireshark.org for more information.\n"
                "\n"
                "%s",
                wireshark_svnversion, get_copyright_info());
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
    fprintf(output, "  -B <buffer size>         size of kernel buffer (def: 1MB)\n");
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
//    destroy_console();
#endif
}

// xxx copied from ../gtk/main.c
static void
show_version(void)
{
#ifdef _WIN32
    create_console();
#endif

    printf(PACKAGE " " VERSION "%s\n"
           "\n"
           "%s"
           "\n"
           "%s"
           "\n"
           "%s",
           wireshark_svnversion, get_copyright_info(), comp_info_str->str,
           runtime_info_str->str);

#ifdef _WIN32
//    destroy_console();
#endif
}

/*
 * Print to the standard error.  On Windows, create a console for the
 * standard error to show up on, if necessary.
 * XXX - pop this up in a window of some sort on UNIX+X11 if the controlling
 * terminal isn't the standard error?
 */
// xxx copied from ../gtk/main.c
void
vfprintf_stderr(const char *fmt, va_list ap)
{
#ifdef _WIN32
    create_console();
#endif
    vfprintf(stderr, fmt, ap);
}

void
fprintf_stderr(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf_stderr(fmt, ap);
    va_end(ap);
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

    fprintf_stderr("wireshark: ");
    va_start(ap, fmt);
    vfprintf_stderr(fmt, ap);
    va_end(ap);
    fprintf_stderr("\n");
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

    va_start(ap, fmt);
    vfprintf_stderr(fmt, ap);
    fprintf_stderr("\n");
    va_end(ap);
}

static void
console_log_handler(const char *log_domain, GLogLevelFlags log_level,
                    const char *message, gpointer user_data)
{
    Q_UNUSED(user_data);
    QString level;
    QDateTime qt = QDateTime::currentDateTime();

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
            level = "unknown log_level %u";
            level.arg(log_level);
            qDebug() << level;
            g_assert_not_reached();
        }

        qDebug() << qt.toString() << log_domain << " " << level << message;
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
#ifdef HAVE_LIBPORTAUDIO
#ifdef PORTAUDIO_API_1
  g_string_append(str, "with PortAudio <= V18");
#else /* PORTAUDIO_API_1 */
  g_string_append(str, "with ");
  g_string_append(str, Pa_GetVersionText());
#endif /* PORTAUDIO_API_1 */
#else /* HAVE_LIBPORTAUDIO */
  g_string_append(str, "without PortAudio");
#endif /* HAVE_LIBPORTAUDIO */

  g_string_append(str, ", ");
#ifdef HAVE_AIRPCAP
  get_compiled_airpcap_version(str);
#else
  g_string_append(str, "without AirPcap");
#endif
}

// xxx copied from ../gtk/main.c
static void
get_gui_runtime_info(GString *str)
{
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
    WiresharkApplication a(argc, argv);
    MainWindow *w;

    char                *init_progfile_dir_error;
    char                *s;
    int                  opt;
    gboolean             arg_error = FALSE;

    extern int           info_update_freq;  /* Found in about_dlg.c. */
    const gchar         *filter;

#ifdef _WIN32
    WSADATA 	       wsaData;
#endif  /* _WIN32 */

    char                *rf_path;
    int                  rf_open_errno;
    char                *gdp_path, *dp_path;
    int                  err;
#ifdef HAVE_LIBPCAP
    gboolean             start_capture = FALSE;
    gboolean             list_link_layer_types = FALSE;
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
    gint                 pl_size = 280, tv_size = 95, bv_size = 75;
    gchar               *rc_file, *cf_name = NULL, *rfilter = NULL, *jfilter = NULL;
    dfilter_t           *rfcode = NULL;
    gboolean             rfilter_parse_failed = FALSE;
    e_prefs             *prefs_p;
    char                 badopt;
    //GtkWidget           *splash_win = NULL;
    GLogLevelFlags       log_flags;
    guint                go_to_packet = 0;
    gboolean             jump_backwards = FALSE;
    dfilter_t           *jump_to_filter = NULL;
    int                  optind_initial;
    int                  status;

    // Hopefully we won't have to use QString::fromUtf8() in as many places.
    QTextCodec *utf8codec = QTextCodec::codecForName("UTF-8");
    QTextCodec::setCodecForCStrings(utf8codec);
    QTextCodec::setCodecForTr(utf8codec);

#ifdef HAVE_LIBPCAP
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
#define OPTSTRING_B "B:"
#else
#define OPTSTRING_B ""
#endif  /* _WIN32 or HAVE_PCAP_CREATE */
#else /* HAVE_LIBPCAP */
#define OPTSTRING_B ""
#endif  /* HAVE_LIBPCAP */

#ifdef HAVE_PCAP_CREATE
#define OPTSTRING_I "I"
#else
#define OPTSTRING_I ""
#endif

#define OPTSTRING "a:b:" OPTSTRING_B "c:C:Df:g:Hhi:" OPTSTRING_I "jJ:kK:lLm:nN:o:P:pQr:R:Ss:t:u:vw:X:y:z:"

    static const char optstring[] = OPTSTRING;

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
    init_progfile_dir_error = init_progfile_dir(argv[0], main);
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

    /* Assemble the compile-time version information string */
    comp_info_str = g_string_new("Compiled ");

    // xxx qtshark
    get_compiled_version_info(comp_info_str, get_qt_compiled_info, get_gui_compiled_info);

    /* Assemble the run-time version information string */
    runtime_info_str = g_string_new("Running ");
    // xxx qtshark
    get_runtime_version_info(runtime_info_str, get_gui_runtime_info);

    /* Read the profile independent recent file.  We have to do this here so we can */
    /* set the profile before it can be set from the command line parameterts */
    // xxx qtshark
    //recent_read_static(&rf_path, &rf_open_errno);
    //if (rf_path != NULL && rf_open_errno != 0) {
    //    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
    //                  "Could not open common recent file\n\"%s\": %s.",
    //                  rf_path, strerror(rf_open_errno));
    //}

    /* "pre-scan" the command line parameters, if we have "console only"
       parameters.  We do this so we don't start GTK+ if we're only showing
       command-line help or version information.

       XXX - this pre-scan is done before we start GTK+, so we haven't
       run gtk_init() on the arguments.  That means that GTK+ arguments
       have not been removed from the argument list; those arguments
       begin with "--", and will be treated as an error by getopt().

       We thus ignore errors - *and* set "opterr" to 0 to suppress the
       error messages. */
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
            if_list = capture_interface_list(&err, &err_str);
            if (if_list == NULL) {
                switch (err) {
                case CANT_GET_INTERFACE_LIST:
                    cmdarg_err("%s", err_str);
                    g_free(err_str);
                    break;

                case NO_INTERFACES_FOUND:
                    cmdarg_err("There are no interfaces on which a capture can be done");
                    break;
                }
                exit(2);
            }
            capture_opts_print_interfaces(if_list);
            free_interface_list(if_list);
            exit(0);
#else
            capture_option_specified = TRUE;
            arg_error = TRUE;
#endif
            break;
        case 'h':        /* Print help and exit */
            print_usage(TRUE);
            exit(0);
            break;
#ifdef _WIN32
        case 'i':
            if (strcmp(optarg, "-") == 0)
                stdin_capture = TRUE;
            break;
#endif
        case 'P':        /* Path settings - change these before the Preferences and alike are processed */
            status = filesystem_opt(opt, optarg);
            if(status != 0) {
                cmdarg_err("-P flag \"%s\" failed (hint: is it quoted and existing?)", optarg);
                exit(status);
            }
            break;
        case 'v':        /* Show version and exit */
            show_version();
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
    capture_opts_init(&global_capture_opts, &cfile);
#endif

    /* Register all dissectors; we must do this before checking for the
       "-G" flag, as the "-G" flag dumps information registered by the
       dissectors, and we must do it before we read the preferences, in
       case any dissectors register preferences. */
    epan_init(register_all_protocols,register_all_protocol_handoffs,
              NULL, NULL, NULL, NULL, NULL, NULL
//              splash_update, (gpointer) splash_win,
//              failure_alert_box,open_failure_alert_box,read_failure_alert_box,
//              write_failure_alert_box
              );

//    splash_update(RA_LISTENERS, NULL, (gpointer)splash_win);

    /* Register all tap listeners; we do this before we parse the arguments,
       as the "-z" argument can specify a registered tap. */

    /* we register the plugin taps before the other taps because
            stats_tree taps plugins will be registered as tap listeners
            by stats_tree_stat.c and need to registered before that */

    g_log(NULL, G_LOG_LEVEL_DEBUG, "plugin_dir: %s", get_plugin_dir());
  #ifdef HAVE_PLUGINS
    register_all_plugin_tap_listeners();
  #endif

//    register_all_tap_listeners();

//    splash_update(RA_PREFERENCES, NULL, (gpointer)splash_win);

    /* Now register the preferences for any non-dissector modules.
       We must do that before we read the preferences as well. */
    prefs_register_modules();

    prefs_p = read_configuration_files (&gdp_path, &dp_path);
    /* Removed thread code:
     * http://anonsvn.wireshark.org/viewvc/viewvc.cgi?view=rev&revision=35027
     */

    g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: timestamp types should be set elsewhere");
    timestamp_set_type(TS_RELATIVE);
    timestamp_set_precision(TS_PREC_AUTO_USEC);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

/////////

    build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

    font_init();

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

    switch (user_font_apply()) {
    case FA_SUCCESS:
        break;
    case FA_FONT_NOT_RESIZEABLE:
        /* "user_font_apply()" popped up an alert box. */
        /* turn off zooming - font can't be resized */
    case FA_FONT_NOT_AVAILABLE:
        /* XXX - did we successfully load the un-zoomed version earlier?
        If so, this *probably* means the font is available, but not at
        this particular zoom level, but perhaps some other failure
        occurred; I'm not sure you can determine which is the case,
        however. */
        /* turn off zooming - zoom level is unavailable */
    default:
        /* in any other case than FA_SUCCESS, turn off zooming */
//        recent.gui_zoom_level = 0;
        /* XXX: would it be a good idea to disable zooming (insensitive GUI)? */
        break;
    }

////////
    color_filters_init();

////////
    w = new(MainWindow);
    w->show();

    return a.exec();
}

void
create_console(void) {

}
