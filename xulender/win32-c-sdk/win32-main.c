/* win32-main.c
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer (Windows C SDK Frontend)
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 2004 Gerald Combs
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
 *
 */

/*
 * This is the main entry point for wethereal, a version of Ethereal that
 * uses the native Windows SDK interface.  A _lot_ of code has been copied
 * from gtk/main.c.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#endif

#include "register.h"

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "globals.h"

#ifdef NEED_GETOPT_H
#include "getopt.h"
#endif

#include <fcntl.h>
#include <conio.h>

#include <epan/epan.h>
#include <epan/filesystem.h>
#include <epan/epan_dissect.h>

#include <glib.h>
#include "util.h"
#include "clopts_common.h"
#include "version_info.h"
#include <epan/timestamp.h>
#include "capture.h"
#include "filters.h"
#include <epan/addr_resolv.h>

#include "color.h"
#include "color_filters.h"
#include "ringbuffer.h"
#include "ui_util.h"
#include "pcap-util.h"
#include "disabled_protos.h"
#include <epan/prefs.h>
#include "prefs-recent.h"
#include "alert_box.h"
#include "capture-wpcap.h"
#include "simple_dialog.h"
#include "prefs-dlg.h"
#include "about-dlg.h"
#include "statusbar.h"
#include "toolbar-util.h"

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-menu.h"
#include "win32-statusbar.h"
#include "capture-util.h"
#include "color-util.h"
#include "filter-util.h"
#include "find-util.h"
#include "font-util.h"
#include "goto-util.h"
#include "packet-win-util.h"
#include "proto-util.h"

#include "ethereal-main.h"
#include "capture-dialog.h"
#include "capture-info-dialog.h"
#include "coloring-rules-dialog.h"
#include "edit-color-filter-dialog.h"
#include "filter-dialog.h"
#include "find-packet-dialog.h"
#include "goto-packet-dialog.h"
#include "preferences-dialog.h"
#include "win32-file-dlg.h"

#include "localelements/ethereal-elements.h"

LRESULT CALLBACK win32_main_wnd_proc( HWND, UINT, WPARAM, LPARAM);

/** Action to take for reftime_frame_cb() */
typedef enum {
    REFTIME_TOGGLE,     /**< toggle ref frame */
    REFTIME_FIND_NEXT,  /**< find next ref frame */
    REFTIME_FIND_PREV   /**< find previous ref frame */
} REFTIME_ACTION_E;

/** "Apply as Filter" / "Prepare a Filter" action type. */
typedef enum {
    MATCH_SELECTED_REPLACE, /**< "Selected" */
    MATCH_SELECTED_AND,     /**< "and Selected" */
    MATCH_SELECTED_OR,      /**< "or Selected" */
    MATCH_SELECTED_NOT,     /**< "Not Selected" */
    MATCH_SELECTED_AND_NOT, /**< "and not Selected" */
    MATCH_SELECTED_OR_NOT   /**< "or not Selected" */
} MATCH_SELECTED_E;

/** mask MATCH_SELECTED_E values (internally used) */
#define MATCH_SELECTED_MASK         0x0ff

/** "bitwise or" this with MATCH_SELECTED_E value for instant apply instead of prepare only */
#define MATCH_SELECTED_APPLY_NOW    0x100

/*
 * XXX - A single, global cfile keeps us from having multiple files open
 * at the same time.
 */

#ifdef HAVE_LIBPCAP
#define DEF_READY_MESSAGE " Ready to load or capture"
#else
#define DEF_READY_MESSAGE " Ready to load file"
#endif

capture_file cfile;
ts_type timestamp_type = RELATIVE;

GString *comp_info_str, *runtime_info_str;
gchar   *ethereal_path = NULL;

/* XXX: use a preference for this setting! */
static guint dfilter_combo_max_recent = 10;

static gboolean has_no_console = TRUE; /* TRUE if app has no console */
static gboolean console_was_created = FALSE; /* TRUE if console was created */
static void create_console(void);
static void destroy_console(void);
static void console_log_handler(const char *log_domain,
    GLogLevelFlags log_level, const char *message, gpointer user_data);
static void main_load_window_geometry(HWND hw_mainwin);
static void main_save_window_geometry(HWND hw_mainwin);
static void file_save_as_cmd(void);
static void file_quit_cmd(HWND hw_mainwin);
static void reftime_frame_cb(REFTIME_ACTION_E action);
static void collapse_all_cb();
static void expand_all_cb();
static void expand_tree_cb();
static void match_selected_ptree_cb(MATCH_SELECTED_E action);
static void match_selected_cb_do(int action, gchar *text);

#ifdef HAVE_LIBPCAP
static gboolean list_link_layer_types;
#endif

/* XXX - We can probably get rid of all of these with the possible exception
 * of g_hw_mainwin */
HWND g_hw_mainwin, g_hw_capture_dlg = NULL;
HWND g_hw_capture_info_dlg = NULL;
HFONT m_r_font = NULL, m_b_font;

/* XXX - Copied from gtk/main.c.  We need to consolidate this. */
static void
print_usage(gboolean print_ver) {

    FILE *output;

    if (print_ver) {
	output = stdout;
	fprintf(output, "This is GNU " PACKAGE " " VERSION
#ifdef CVSVERSION
	    " (" CVSVERSION ")"
#endif
	    "\n%s\n%s\n",
	    comp_info_str->str, runtime_info_str->str);
    } else {
	output = stderr;
    }
#ifdef HAVE_LIBPCAP
    fprintf(output, "\n%s [ -vh ] [ -klLnpQS ] [ -a <capture autostop condition> ] ...\n",
	PACKAGE);
    fprintf(output, "\t[ -b <number of ringbuffer files>[:<duration>] ]\n");
    fprintf(output, "\t[ -B <byte view height> ] [ -c <count> ] [ -f <capture filter> ]\n");
    fprintf(output, "\t[ -i <interface> ] [ -m <medium font> ] [ -N <resolving> ]\n");
    fprintf(output, "\t[ -o <preference setting> ] ... [ -P <packet list height> ]\n");
    fprintf(output, "\t[ -r <infile> ] [ -R <read filter> ] [ -s <snaplen> ] \n");
    fprintf(output, "\t[ -t <time stamp format> ] [ -T <tree view height> ]\n");
    fprintf(output, "\t[ -w <savefile> ] [ -y <link type> ] [ -z <statistics string> ]\n");
    fprintf(output, "\t[ <infile> ]\n");
#else
    fprintf(output, "\n%s [ -vh ] [ -n ] [ -B <byte view height> ] [ -m <medium font> ]\n",
	PACKAGE);
    fprintf(output, "\t[ -N <resolving> ] [ -o <preference setting> ...\n");
    fprintf(output, "\t[ -P <packet list height> ] [ -r <infile> ] [ -R <read filter> ]\n");
    fprintf(output, "\t[ -t <time stamp format> ] [ -T <tree view height> ]\n");
    fprintf(output, "\t[ -z <statistics string> ] [ <infile> ]\n");
#endif
}

/* XXX - Copied from gtk/main.c.  We need to consolidate this. */
static void
show_version(void)
{
#ifdef WIN32
    create_console();
#endif

    printf(PACKAGE " " VERSION
#ifdef CVSVERSION
	" (" CVSVERSION ")"
#endif
	"\n%s\n%s\n",
	comp_info_str->str, runtime_info_str->str);
}

/* XXX - Copied from gtk/main.c.  We need to consolidate this. */
static int
get_natural_int(const char *string, const char *name)
{
    long number;
    char *p;

    number = strtol(string, &p, 10);
    if (p == string || *p != '\0') {
	fprintf(stderr, "ethereal: The specified %s \"%s\" is not a decimal number\n",
		name, string);
	exit(1);
    }
    if (number < 0) {
	fprintf(stderr, "ethereal: The specified %s \"%s\" is a negative number\n",
		name, string);
	exit(1);
    }
    if (number > INT_MAX) {
	fprintf(stderr, "ethereal: The specified %s \"%s\" is too large (greater than %d)\n",
		name, string, INT_MAX);
	exit(1);
    }
    return number;
}

/* XXX - Copied from gtk/main.c.  We need to consolidate this. */
static int
get_positive_int(const char *string, const char *name)
{
    long number;

    number = get_natural_int(string, name);

    if (number == 0) {
	fprintf(stderr, "ethereal: The specified %s is zero\n",
		name);
	exit(1);
    }

    return number;
}

#ifdef HAVE_LIBPCAP
/*
 * Given a string of the form "<autostop criterion>:<value>", as might appear
 * as an argument to a "-a" option, parse it and set the criterion in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
/* XXX - Copied from gtk/main.c.  We need to consolidate this. */
static gboolean
set_autostop_criterion(const char *autostoparg)
{
    gchar *p, *colonp;

    colonp = strchr(autostoparg, ':');
    if (colonp == NULL)
	return FALSE;

    p = colonp;
    *p++ = '\0';

    /*
     * Skip over any white space (there probably won't be any, but
     * as we allow it in the preferences file, we might as well
     * allow it here).
     */
    while (isspace((guchar)*p))
	p++;
    if (*p == '\0') {
	/*
	 * Put the colon back, so if our caller uses, in an
	 * error message, the string they passed us, the message
	 * looks correct.
	 */
	*colonp = ':';
	return FALSE;
    }
    if (strcmp(autostoparg,"duration") == 0) {
	capture_opts.has_autostop_duration = TRUE;
	capture_opts.autostop_duration = get_positive_int(p,"autostop duration");
    } else if (strcmp(autostoparg,"filesize") == 0) {
	capture_opts.has_autostop_filesize = TRUE;
	capture_opts.autostop_filesize = get_positive_int(p,"autostop filesize");
    } else {
	return FALSE;
    }
    *colonp = ':'; /* put the colon back */
    return TRUE;
}

/*
 * Given a string of the form "<ring buffer file>:<duration>", as might appear
 * as an argument to a "-b" option, parse it and set the arguments in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
/* XXX - Copied from gtk/main.c.  We need to consolidate this. */
static gboolean
get_ring_arguments(const char *arg)
{
    gchar *p = NULL, *colonp;

    colonp = strchr(arg, ':');

    if (colonp != NULL) {
	p = colonp;
	*p++ = '\0';
    }

    capture_opts.ring_num_files =
	get_natural_int(arg, "number of ring buffer files");

    if (colonp == NULL)
	return TRUE;
    /*
     * Skip over any white space (there probably won't be any, but
     * as we allow it in the preferences file, we might as well
     * allow it here).
     */
    while (isspace((guchar)*p))
	p++;
    if (*p == '\0') {
      /*
       * Put the colon back, so if our caller uses, in an
       * error message, the string they passed us, the message
       * looks correct.
       */
	*colonp = ':';
	return FALSE;
    }

    capture_opts.has_file_duration = TRUE;
    capture_opts.file_duration = get_positive_int(p, "ring buffer duration");

    *colonp = ':';        /* put the colon back */
    return TRUE;
}

#endif /* HAVE_LIBPCAP */

/*
 * Create a console window for standard input, output and error.
 */
/* XXX - Copied from gtk/main.c.  We need to consolidate this. */
static void
create_console(void)
{
    if (has_no_console) {
	/* We have no console to which to print the version string, so
	   create one and make it the standard input, output, and error. */
	if (!AllocConsole())
	    return;   /* couldn't create console */
	freopen("CONIN$", "r", stdin);
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);

	/* Well, we have a console now. */
	has_no_console = FALSE;
	console_was_created = TRUE;

	/* Now register "destroy_console()" as a routine to be called just
	   before the application exits, so that we can destroy the console
	   after the user has typed a key (so that the console doesn't just
	   disappear out from under them, giving the user no chance to see
	   the message(s) we put in there). */
	atexit(destroy_console);
    }
}

/* XXX - Copied from gtk/main.c.  We need to consolidate this. */
static void
destroy_console(void)
{
    printf("\n\nPress any key to exit\n");
    _getch();
    FreeConsole();
}

/* This routine should not be necessary, at least as I read the GLib
   source code, as it looks as if GLib is, on Win32, *supposed* to
   create a console window into which to display its output.

   That doesn't happen, however.  I suspect there's something completely
   broken about that code in GLib-for-Win32, and that it may be related
   to the breakage that forces us to just call "printf()" on the message
   rather than passing the message on to "g_log_default_handler()"
   (which is the routine that does the aforementioned non-functional
   console window creation). */

/* XXX - Copied from gtk/main.c.  We need to consolidate this. */
static void
console_log_handler(const char *log_domain, GLogLevelFlags log_level,
                    const char *message, gpointer user_data)
{
    create_console();
    if (console_was_created) {
	/* For some unknown reason, the above doesn't appear to actually cause
	   anything to be sent to the standard output, so we'll just splat the
	   message out directly, just to make sure it gets out. */
	printf("%s\n", message);
    } else
	g_log_default_handler(log_domain, log_level, message, user_data);
}

int PASCAL
WinMain( HINSTANCE h_instance, HINSTANCE h_prev_instance, LPSTR lpsz_cmd_line, int n_cmd_show )
{
    WNDCLASS               wc;
    MSG                    msg;
    win32_element_t       *dfilter_bt;
    char                  *s;
    int                    i;
    char                  *rf_path;
    int                    rf_open_errno;
    char                  *gpf_path, *pf_path;
    char                  *cf_path, *df_path;
    char                  *gdp_path, *dp_path;
    int                    gpf_open_errno, gpf_read_errno;
    int                    pf_open_errno, pf_read_errno;
    int                    cf_open_errno, df_open_errno;
    int                    gdp_open_errno, gdp_read_errno;
    int                    dp_open_errno, dp_read_errno;
    e_prefs               *prefs;
    INITCOMMONCONTROLSEX   comm_ctrl;
    int                    argc = __argc;
    char                 **argv = __argv;
    WSADATA                wsaData;
    int                    opt;
    extern char           *optarg;
    gboolean               arg_error = FALSE;
#ifdef HAVE_LIBPCAP
    char                  *command_name;
    int                    err;
    gboolean               start_capture = FALSE;
    gchar                 *save_file = NULL;
    GList                 *if_list;
    if_info_t             *if_info;
    GList                 *lt_list, *lt_entry;
    data_link_info_t      *data_link_info;
    gchar                  err_str[PCAP_ERRBUF_SIZE];
    gboolean               stats_known;
    struct pcap_stat       stats;
#else
    gboolean               capture_option_specified = FALSE;
#endif
    gint                   pl_size = 280, tv_size = 95, bv_size = 75;
    gchar                 *cf_name = NULL, *rfilter = NULL;
    dfilter_t             *rfcode = NULL;
    gboolean               rfilter_parse_failed = FALSE;
    char                   badopt;
//    ethereal_tap_list     *tli = NULL;

#define OPTSTRING_INIT "a:b:B:c:f:Hhi:klLm:nN:o:pP:Qr:R:Ss:t:T:w:vy:z:"

#ifdef HAVE_LIBPCAP
#define OPTSTRING_CHILD "W:Z:"
#else
#define OPTSTRING_CHILD ""
#endif  /* HAVE_LIBPCAP */

    char optstring[sizeof(OPTSTRING_INIT) + sizeof(OPTSTRING_CHILD) - 1] =
	OPTSTRING_INIT;

    ethereal_path = argv[0];

    /* Arrange that if we have no console window, and a GLib message logging
       routine is called to log a message, we pop up a console window.

       We do that by inserting our own handler for all messages logged
       to the default domain; that handler pops up a console if necessary,
       and then calls the default handler. */
    g_log_set_handler(NULL,
	    G_LOG_LEVEL_ERROR|
	    G_LOG_LEVEL_CRITICAL|
	    G_LOG_LEVEL_WARNING|
	    G_LOG_LEVEL_MESSAGE|
	    G_LOG_LEVEL_INFO|
	    G_LOG_LEVEL_DEBUG|
	    G_LOG_FLAG_FATAL|G_LOG_FLAG_RECURSION,
	    console_log_handler, NULL);

#ifdef HAVE_LIBPCAP
    command_name = get_basename(ethereal_path);
    /* Set "capture_child" to indicate whether this is going to be a child
       process for a "-S" capture. */
    capture_child = (strcmp(command_name, CHILD_NAME) == 0);
    if (capture_child)
	strcat(optstring, OPTSTRING_CHILD);
#endif

    set_timestamp_setting(TS_RELATIVE);

    /* Register all dissectors; we must do this before checking for the
       "-G" flag, as the "-G" flag dumps information registered by the
       dissectors, and we must do it before we read the preferences, in
       case any dissectors register preferences. */

    epan_init(PLUGIN_DIR,register_all_protocols,register_all_protocol_handoffs,
	failure_alert_box, open_failure_alert_box, read_failure_alert_box);

    /* Register all tap listeners; we do this before we parse the arguments,
       as the "-z" argument can specify a registered tap. */

    register_all_tap_listeners();

    /* Now register the preferences for any non-dissector modules.
       We must do that before we read the preferences as well. */

    prefs_register_modules();

    /* If invoked with the "-G" flag, we dump out information based on
       the argument to the "-G" flag; if no argument is specified,
       for backwards compatibility we dump out a glossary of display
       filter symbols.

       We must do this before calling "gtk_init()", because "gtk_init()"
       tries to open an X display, and we don't want to have to do any X
       stuff just to do a build.

       Given that we call "gtk_init()" before doing the regular argument
       list processing, so that it can handle X and GTK+ arguments and
       remove them from the list at which we look, this means we must do
       this before doing the regular argument list processing, as well.

       This means that:

	 you must give the "-G" flag as the first flag on the command line;

	 you must give it as "-G", nothing more, nothing less;

	 the first argument after the "-G" flag, if present, will be used
	 to specify the information to dump;

	 arguments after that will not be used. */

    /* XXX - This doesn't currently work in wethereal. Does it need to? */

    handle_dashG_option(argc, argv, "ethereal");

    /* Read the preference files. */
    prefs = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
	&pf_open_errno, &pf_read_errno, &pf_path);


#ifdef HAVE_LIBPCAP
    capture_opts.has_snaplen = FALSE;
    capture_opts.snaplen = MIN_PACKET_SIZE;
    capture_opts.linktype = -1;
#ifdef _WIN32
    capture_opts.buffer_size = 1;
#endif

    capture_opts.has_autostop_packets = FALSE;
    capture_opts.autostop_packets = 1;
    capture_opts.has_autostop_duration = FALSE;
    capture_opts.autostop_duration = 1;
    capture_opts.has_autostop_filesize = FALSE;
    capture_opts.autostop_filesize = 1;
    capture_opts.has_autostop_files = FALSE;
    capture_opts.autostop_files = 1;

    capture_opts.multi_files_on = FALSE;
    capture_opts.has_ring_num_files = TRUE;
    capture_opts.ring_num_files = 2;
    capture_opts.has_file_duration = FALSE;
    capture_opts.file_duration = 1;

  /* If this is a capture child process, it should pay no attention
     to the "prefs.capture_prom_mode" setting in the preferences file;
     it should do what the parent process tells it to do, and if
     the parent process wants it not to run in promiscuous mode, it'll
     tell it so with a "-p" flag.

     Otherwise, set promiscuous mode from the preferences setting. */
  /* the same applies to other preferences settings as well. */
  if (capture_child) {
	capture_opts.promisc_mode = TRUE;	/* maybe changed by command line below */
	capture_opts.show_info    = TRUE;	/* maybe changed by command line below */
	capture_opts.sync_mode    = TRUE;	/* always true in child process */
	auto_scroll_live          = FALSE;	/* doesn't matter in child process */
    } else {
	capture_opts.promisc_mode = prefs->capture_prom_mode;
	capture_opts.show_info    = prefs->capture_show_info;
	capture_opts.sync_mode    = prefs->capture_real_time;
	auto_scroll_live          = prefs->capture_auto_scroll;
    }

#endif /* HAVE_LIBPCAP */

    /* Set the name resolution code's flags from the preferences. */
    g_resolv_flags = prefs->name_resolve;

    /* Read the capture filter file. */
    read_filter_list(CFILTER_LIST, &cf_path, &cf_open_errno);

    /* Read the display filter file. */
    read_filter_list(DFILTER_LIST, &df_path, &df_open_errno);

    /* Read the disabled protocols file. */
    read_disabled_protos_list(&gdp_path, &gdp_open_errno, &gdp_read_errno,
                              &dp_path, &dp_open_errno, &dp_read_errno);

    init_cap_file(&cfile);

    /* Initialize our XUL elements. */
    win32_identifier_init();

    /* Load wpcap if possible. Do this before collecting the run-time version information */
    load_wpcap();


    /* Start windows sockets */
    WSAStartup( MAKEWORD( 1, 1 ), &wsaData );

    /* Assemble the compile-time version information string */
    comp_info_str = g_string_new("Compiled with the Windows C SDK, ");
    get_compiled_version_info(comp_info_str);

    /* Assemble the run-time version information string */
    runtime_info_str = g_string_new("Running ");
    get_runtime_version_info(runtime_info_str);


    /* Initialize our controls. */
    memset (&comm_ctrl, 0, sizeof(comm_ctrl));
    comm_ctrl.dwSize = sizeof(comm_ctrl);
    /* Includes the animate, header, hot key, list view, progress bar,
     * status bar, tab, tooltip, toolbar, trackbar, tree view, and
     * up-down controls
     */
    comm_ctrl.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&comm_ctrl);

    /* RichEd20.DLL is needed by the byte view. */
    LoadLibrary("riched20.dll");

    /* Now get our args */
    while ((opt = getopt(argc, argv, optstring)) != -1) {
	switch (opt) {
	    case 'a':        /* autostop criteria */
#ifdef HAVE_LIBPCAP
		if (set_autostop_criterion(optarg) == FALSE) {
		    fprintf(stderr, "ethereal: Invalid or unknown -a flag \"%s\"\n", optarg);
		    exit(1);
		}
#else
		capture_option_specified = TRUE;
		arg_error = TRUE;
#endif
		break;

	    case 'b':        /* Ringbuffer option */
#ifdef HAVE_LIBPCAP
		capture_opts.multi_files_on = TRUE;
		capture_opts.has_ring_num_files = TRUE;
		if (get_ring_arguments(optarg) == FALSE) {
		    fprintf(stderr, "ethereal: Invalid or unknown -b arg \"%s\"\n", optarg);
		    exit(1);
		}
#else
		capture_option_specified = TRUE;
		arg_error = TRUE;
#endif
		break;

	    case 'B':        /* Byte view pane height */
		bv_size = get_positive_int(optarg, "byte view pane height");
		break;
	    case 'c':        /* Capture xxx packets */
#ifdef HAVE_LIBPCAP
		capture_opts.has_autostop_packets = TRUE;
		capture_opts.autostop_packets = get_positive_int(optarg, "packet count");
#else
		capture_option_specified = TRUE;
		arg_error = TRUE;
#endif
		break;

	    case 'f':
#ifdef HAVE_LIBPCAP
		if (cfile.cfilter)
		    g_free(cfile.cfilter);
		cfile.cfilter = g_strdup(optarg);
#else
		capture_option_specified = TRUE;
		arg_error = TRUE;
#endif
		break;
	    case 'h':        /* Print help and exit */
		print_usage(TRUE);
		exit(0);
		break;
	    case 'H':        /* Hide capture info dialog box */
#ifdef HAVE_LIBPCAP
		capture_opts.show_info = FALSE;
#else
		capture_option_specified = TRUE;
		arg_error = TRUE;
#endif
		break;
	    case 'i':        /* Use interface xxx */
#ifdef HAVE_LIBPCAP
		cfile.iface = g_strdup(optarg);
#else
		capture_option_specified = TRUE;
		arg_error = TRUE;
#endif
		break;
	    case 'k':        /* Start capture immediately */
#ifdef HAVE_LIBPCAP
		start_capture = TRUE;
#else
		capture_option_specified = TRUE;
		arg_error = TRUE;
#endif
		break;

	    case 'l':        /* Automatic scrolling in live capture mode */
#ifdef HAVE_LIBPCAP
		auto_scroll_live = TRUE;
#else
		capture_option_specified = TRUE;
		arg_error = TRUE;
#endif
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
		if (prefs->PREFS_GUI_FONT_NAME != NULL)
		    g_free(prefs->PREFS_GUI_FONT_NAME);
		prefs->PREFS_GUI_FONT_NAME = g_strdup(optarg);
		break;
	    case 'n':        /* No name resolution */
		g_resolv_flags = RESOLV_NONE;
		break;
	    case 'N':        /* Select what types of addresses/port #s to resolve */
		if (g_resolv_flags == RESOLV_ALL)
		    g_resolv_flags = RESOLV_NONE;
		badopt = string_to_name_resolve(optarg, &g_resolv_flags);
		if (badopt != '\0') {
		    fprintf(stderr, "ethereal: -N specifies unknown resolving option '%c'; valid options are 'm', 'n', and 't'\n",
			badopt);
		    exit(1);
		}
		break;
	    case 'o':        /* Override preference from command line */
		switch (prefs_set_pref(optarg)) {

		    case PREFS_SET_SYNTAX_ERR:
			fprintf(stderr, "ethereal: Invalid -o flag \"%s\"\n", optarg);
			exit(1);
			break;

		    case PREFS_SET_NO_SUCH_PREF:
		    case PREFS_SET_OBSOLETE:
			fprintf(stderr, "ethereal: -o flag \"%s\" specifies unknown preference\n",
			    optarg);
		        exit(1);
		        break;
		}
		break;
	    case 'p':        /* Don't capture in promiscuous mode */
#ifdef HAVE_LIBPCAP
		capture_opts.promisc_mode = FALSE;
#else
		capture_option_specified = TRUE;
		arg_error = TRUE;
#endif
		break;
	    case 'P':        /* Packet list pane height */
		pl_size = get_positive_int(optarg, "packet list pane height");
		break;
	    case 'Q':        /* Quit after capture (just capture to file) */
#ifdef HAVE_LIBPCAP
		quit_after_cap  = TRUE;
		start_capture   = TRUE;  /*** -Q implies -k !! ***/
#else
		capture_option_specified = TRUE;
		arg_error = TRUE;
#endif
		break;
	    case 'r':        /* Read capture file xxx */
		/* We may set "last_open_dir" to "cf_name", and if we change
		   "last_open_dir" later, we free the old value, so we have to
		   set "cf_name" to something that's been allocated. */
		cf_name = g_strdup(optarg);
		break;
	    case 'R':        /* Read file filter */
		rfilter = optarg;
		break;
	    case 's':        /* Set the snapshot (capture) length */
#ifdef HAVE_LIBPCAP
		capture_opts.has_snaplen = TRUE;
		capture_opts.snaplen = get_positive_int(optarg, "snapshot length");
#else
		capture_option_specified = TRUE;
		arg_error = TRUE;
#endif
		break;
	    case 'S':        /* "Sync" mode: used for following file ala tail -f */
#ifdef HAVE_LIBPCAP
		capture_opts.sync_mode = TRUE;
#else
		capture_option_specified = TRUE;
		arg_error = TRUE;
#endif
	    break;
	    case 't':        /* Time stamp type */
		if (strcmp(optarg, "r") == 0)
		    set_timestamp_setting(TS_RELATIVE);
		else if (strcmp(optarg, "a") == 0)
		    set_timestamp_setting(TS_ABSOLUTE);
		else if (strcmp(optarg, "ad") == 0)
		    set_timestamp_setting(TS_ABSOLUTE_WITH_DATE);
		else if (strcmp(optarg, "d") == 0)
		    set_timestamp_setting(TS_DELTA);
		else {
		    fprintf(stderr, "ethereal: Invalid time stamp type \"%s\"\n",
		    optarg);
		    fprintf(stderr, "It must be \"r\" for relative, \"a\" for absolute,\n");
		    fprintf(stderr, "\"ad\" for absolute with date, or \"d\" for delta.\n");
		    exit(1);
		}
		break;
	    case 'T':        /* Tree view pane height */
		tv_size = get_positive_int(optarg, "tree view pane height");
		break;
	    case 'v':        /* Show version and exit */
		show_version();
		if (console_was_created)
		    destroy_console();
		exit(0);
		break;
	    case 'w':        /* Write to capture file xxx */
#ifdef HAVE_LIBPCAP
		save_file = g_strdup(optarg);
#else
		capture_option_specified = TRUE;
		arg_error = TRUE;
#endif
	    break;
	    case 'y':        /* Set the pcap data link type */
#ifdef HAVE_LIBPCAP
#ifdef HAVE_PCAP_DATALINK_NAME_TO_VAL
		capture_opts.linktype = pcap_datalink_name_to_val(optarg);
		if (capture_opts.linktype == -1) {
		    fprintf(stderr, "ethereal: The specified data link type \"%s\" is not valid\n",
			optarg);
		    exit(1);
		}
#else /* HAVE_PCAP_DATALINK_NAME_TO_VAL */
		/* XXX - just treat it as a number */
		capture_opts.linktype = get_natural_int(optarg, "data link type");
#endif /* HAVE_PCAP_DATALINK_NAME_TO_VAL */
#else /* HAVE_LIBPCAP */
		capture_option_specified = TRUE;
		arg_error = TRUE;
#endif /* HAVE_LIBPCAP */
		break;
#ifdef HAVE_LIBPCAP
	    case 'W':        /* Write to capture file FD xxx */
		cfile.save_file_fd = atoi(optarg);
		break;
#endif
/* XXX - Add tap support */
//	    case 'z':
//		for(tli=tap_list;tli;tli=tli->next){
//		    if(!strncmp(tli->cmd,optarg,strlen(tli->cmd))){
//			tap_opt = g_strdup(optarg);
//			break;
//		    }
//		}
//		if(!tli){
//		    fprintf(stderr,"ethereal: invalid -z argument.\n");
//		    fprintf(stderr,"  -z argument must be one of :\n");
//		    for(tli=tap_list;tli;tli=tli->next){
//			fprintf(stderr,"     %s\n",tli->cmd);
//		    }
//		    exit(1);
//		}
//		break;
#ifdef HAVE_LIBPCAP
	    /* Hidden option supporting Sync mode */
	    case 'Z':        /* Write to pipe FD XXX */
		/* associate stdout with pipe */
		i = atoi(optarg);
		if (dup2(i, 1) < 0) {
		    fprintf(stderr, "Unable to dup pipe handle\n");
		    exit(1);
		}
		break;
#endif /* HAVE_LIBPCAP */

	    default:
	    case '?':        /* Bad flag - print usage message */
		arg_error = TRUE;
		break;
	}
    }

    argc -= optind;
    argv += optind;
    if (argc >= 1) {
	if (cf_name != NULL) {
	    /*
	     * Input file name specified with "-r" *and* specified as a regular
	     * command-line argument.
	     */
	    arg_error = TRUE;
	} else {
	    /*
	     * Input file name not specified with "-r", and a command-line argument
	     * was specified; treat it as the input file name.
	     *
	     * Yes, this is different from tethereal, where non-flag command-line
	     * arguments are a filter, but this works better on GUI desktops
	     * where a command can be specified to be run to open a particular
	     * file - yes, you could have "-r" as the last part of the command,
	     * but that's a bit ugly.
	     */
	    cf_name = g_strdup(argv[0]);
	}
	argc--;
	argv++;
    }

    if (argc != 0) {
	/*
	 * Extra command line arguments were specified; complain.
	 */
	fprintf(stderr, "Invalid argument: %s\n", argv[0]);
	arg_error = TRUE;
    }

#ifndef HAVE_LIBPCAP
    if (capture_option_specified)
	fprintf(stderr, "This version of Ethereal was not built with support for capturing packets.\n");
#endif
    if (arg_error) {
	print_usage(FALSE);
	exit(1);
    }

#ifdef HAVE_LIBPCAP
    if (start_capture && list_link_layer_types) {
	/* Specifying *both* is bogus. */
	fprintf(stderr, "ethereal: You cannot specify both -L and a live capture.\n");
	exit(1);
    }

    if (list_link_layer_types) {
	/* We're supposed to list the link-layer types for an interface;
	   did the user also specify a capture file to be read? */
	if (cf_name) {
	    /* Yes - that's bogus. */
	    fprintf(stderr, "ethereal: You cannot specify -L and a capture file to beread.\n");
	    exit(1);
	}
	/* No - did they specify a ring buffer option? */
	if (capture_opts.multi_files_on) {
	    fprintf(stderr, "ethereal: Ring buffer requested, but a capture is not being done.\n");
	    exit(1);
	}
    } else {
	/* We're supposed to do a live capture; did the user also specify
	   a capture file to be read? */
	if (start_capture && cf_name) {
	    /* Yes - that's bogus. */
	    fprintf(stderr, "ethereal: You cannot specify both a live capture and a capture file to be read.\n");
	    exit(1);
	}

	/* No - was the ring buffer option specified and, if so, does it make
	   sense? */
	if (capture_opts.multi_files_on) {
	    /* Ring buffer works only under certain conditions:
	       a) ring buffer does not work with temporary files;
	       b) sync_mode and capture_opts.ringbuffer_on are mutually exclusive -
		  sync_mode takes precedence;
	       c) it makes no sense to enable the ring buffer if the maximum
		  file size is set to "infinite". */
	    if (save_file == NULL) {
		fprintf(stderr, "ethereal: Ring buffer requested, but capture isn't being saved to a permanent file.\n");
		capture_opts.multi_files_on = FALSE;
	    }
	    if (capture_opts.sync_mode) {
		fprintf(stderr, "ethereal: Ring buffer requested, but an \"Update list of packets in real time\" capture is being done.\n");
		capture_opts.multi_files_on = FALSE;
	    }
	    if (!capture_opts.has_autostop_filesize) {
		fprintf(stderr, "ethereal: Ring buffer requested, but no maximum capture file size was specified.\n");
		capture_opts.multi_files_on = FALSE;
	    }
	}
    }

    if (start_capture || list_link_layer_types) {
	/* Did the user specify an interface to use? */
	if (cfile.iface == NULL) {
	    /* No - is a default specified in the preferences file? */
	    if (prefs->capture_device != NULL) {
		/* Yes - use it. */
		cfile.iface = g_strdup(prefs->capture_device);
	    } else {
		/* No - pick the first one from the list of interfaces. */
		if_list = get_interface_list(&err, err_str);
		if (if_list == NULL) {
		    switch (err) {

		      case CANT_GET_INTERFACE_LIST:
			  fprintf(stderr, "ethereal: Can't get list of interfaces: %s\n",
			      err_str);
			  break;

		      case NO_INTERFACES_FOUND:
			  fprintf(stderr, "ethereal: There are no interfaces on which a capture can be done\n");
			  break;
		    }
		    exit(2);
		}
		if_info = if_list->data;        /* first interface */
		cfile.iface = g_strdup(if_info->name);
		free_interface_list(if_list);
	    }
	}
    }

    if (capture_child) {
	if (cfile.save_file_fd == -1) {
	    /* XXX - send this to the standard output as something our parent
	       should put in an error message box? */
	    fprintf(stderr, "%s: \"-W\" flag not specified\n", CHILD_NAME);
	    exit(1);
	}
    }

    if (list_link_layer_types) {
	/* Get the list of link-layer types for the capture device. */
	lt_list = get_pcap_linktype_list(cfile.iface, err_str);
	if (lt_list == NULL) {
	    if (err_str[0] != '\0') {
		fprintf(stderr, "ethereal: The list of data link types for the capture device could not be obtained (%s).\n"
		    "Please check to make sure you have sufficient permissions, and that\n"
		    "you have the proper interface or pipe specified.\n", err_str);
	    } else
		fprintf(stderr, "ethereal: The capture device has no data link types.\n");
	    exit(2);
	}
	fprintf(stderr, "Data link types (use option -y to set):\n");
	for (lt_entry = lt_list; lt_entry != NULL; lt_entry = g_list_next(lt_entry)) {
	    data_link_info = lt_entry->data;
	    fprintf(stderr, "  %s", data_link_info->name);
	    if (data_link_info->description != NULL)
		fprintf(stderr, " (%s)", data_link_info->description);
	    else
		fprintf(stderr, " (not supported)");
	    putchar('\n');
	}
	free_pcap_linktype_list(lt_list);
	exit(0);
    }
#endif /* HAVE_LIBPCAP */

    prefs_apply_all();

    /* disabled protocols as per configuration file */
    if (gdp_path == NULL && dp_path == NULL) {
      set_disabled_protos_list();
    }

#ifdef HAVE_LIBPCAP
    if (capture_opts.has_snaplen) {
	if (capture_opts.snaplen < 1)
	    capture_opts.snaplen = WTAP_MAX_PACKET_SIZE;
	else if (capture_opts.snaplen < MIN_PACKET_SIZE)
	    capture_opts.snaplen = MIN_PACKET_SIZE;
    }

    /* Check the value range of the ringbuffer_num_files parameter */
    if (capture_opts.ring_num_files > RINGBUFFER_MAX_NUM_FILES)
	capture_opts.ring_num_files = RINGBUFFER_MAX_NUM_FILES;
#if RINGBUFFER_MIN_NUM_FILES > 0
    else if (capture_opts.num_files < RINGBUFFER_MIN_NUM_FILES)
	capture_opts.ring_num_files = RINGBUFFER_MIN_NUM_FILES;
#endif
#endif

    if (!capture_child)
	font_init();

    colfilter_init();



    // XXX - This should be done in win32csdk.py.
    if( !h_prev_instance )
    {
	wc.lpszClassName = "ethereal_main";
	wc.lpfnWndProc = win32_main_wnd_proc;
	wc.style = CS_OWNDC | CS_VREDRAW | CS_HREDRAW;
	wc.hInstance = h_instance;
	wc.hIcon = LoadImage(h_instance, "ETHEREAL_ICON", IMAGE_ICON, 16, 16, LR_DEFAULTSIZE);
	wc.hCursor = LoadCursor( NULL, IDC_ARROW );
	wc.hbrBackground = (HBRUSH)( COLOR_WINDOW+1 );
	wc.lpszMenuName = "ETHEREAL_MAIN_MENU";
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;

	RegisterClass( &wc );

    }

    // Set our globals and instance variables
    // XXX - There's some overlap here that needs to be cleaned up.

#ifdef HAVE_LIBPCAP
    /* Is this a "child" ethereal, which is only supposed to pop up a
       capture box to let us stop the capture, and run a capture
       to a file that our parent will read? */
    if (! capture_child) {
#endif
	/* Create and show the main window */
	g_hw_mainwin = ethereal_main_window_create(h_instance);

	dfilter_bt = win32_identifier_get_str("dfilter-button");
	win32_element_hwnd_set_data(g_hw_mainwin, E_FILT_BT_PTR_KEY, dfilter_bt);

	info_bar_init(DEF_READY_MESSAGE);
	packets_bar_update();

	/* Read the recent file, as we have the gui now ready for it. */
	read_recent(&rf_path, &rf_open_errno);

	/* Size the window before it's displayed. */
	main_load_window_geometry(g_hw_mainwin);

	main_widgets_show_or_hide();

	ethereal_main_window_show(g_hw_mainwin, n_cmd_show);

	menus_init(g_hw_mainwin);

	toolbar_new();

	menu_update_view_items();

	main_window_update();

	/* If we were given the name of a capture file, read it in now;
	   we defer it until now, so that, if we can't open it, and pop
	   up an alert box, the alert box is more likely to come up on
	   top of the main window - but before the preference-file-error
	   alert box, so, if we get one of those, it's more likely to come
	   up on top of us. */
	if (cf_name) {
	    if (rfilter != NULL) {
		if (!dfilter_compile(rfilter, &rfcode)) {
		    bad_dfilter_alert_box(rfilter);
		    rfilter_parse_failed = TRUE;
		}
	    }
	    if (!rfilter_parse_failed) {
		if ((err = cf_open(cf_name, FALSE, &cfile)) == 0) {
		    /* "cf_open()" succeeded, so it closed the previous
			capture file, and thus destroyed any previous read filter
			attached to "cf". */
		    cfile.rfcode = rfcode;

		    /* Open tap windows; we do so after creating the main window,
		       to avoid GTK warnings, and after successfully opening the
		       capture file, so we know we have something to tap. */
//		    if (tap_opt && tli) {
//			(*tli->func)(tap_opt);
//			g_free(tap_opt);
//		    }

		    /* Read the capture file. */
		    switch (cf_read(&cfile)) {

			case READ_SUCCESS:
			case READ_ERROR:
			    /* Just because we got an error, that doesn't mean we were unable
			       to read any of the file; we handle what we could get from the
			       file. */
			    break;

			case READ_ABORTED:
			    /* Exit now. */
			    PostQuitMessage(0);
			    break;
		    }
		    /* Save the name of the containing directory specified in the
		       path name, if any; we can write over cf_name, which is a
		       good thing, given that "get_dirname()" does write over its
		       argument. */
		    s = get_dirname(cf_name);
		    /* we might already set this from the recent file, don't overwrite this */

		    if(get_last_open_dir() == NULL)
			set_last_open_dir(s);
		    g_free(cf_name);
		    cf_name = NULL;
		} else {
		    if (rfcode != NULL)
			dfilter_free(rfcode);
		    cfile.rfcode = NULL;
		}
	    }
	}
#ifdef HAVE_LIBPCAP
    }
#endif

    /* If the global preferences file exists but we failed to open it
       or had an error reading it, pop up an alert box; we defer that
       until now, so that the alert box is more likely to come up on top of
       the main window. */
    if (gpf_path != NULL) {
	if (gpf_open_errno != 0) {
	    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
		"Could not open global preferences file\n\"%s\": %s.", gpf_path,
		strerror(gpf_open_errno));
	}
	if (gpf_read_errno != 0) {
	    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
		"I/O error reading global preferences file\n\"%s\": %s.", gpf_path,
		strerror(gpf_read_errno));
	}
    }

    /* If the user's preferences file exists but we failed to open it
       or had an error reading it, pop up an alert box; we defer that
       until now, so that the alert box is more likely to come up on top of
       the main window. */
    if (pf_path != NULL) {
	if (pf_open_errno != 0) {
	    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
		"Could not open your preferences file\n\"%s\": %s.", pf_path,
		strerror(pf_open_errno));
	}
	if (pf_read_errno != 0) {
	    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
		"I/O error reading your preferences file\n\"%s\": %s.", pf_path,
		strerror(pf_read_errno));
	}
	g_free(pf_path);
	pf_path = NULL;
    }

    /* If the user's capture filter file exists but we failed to open it,
       pop up an alert box; we defer that until now, so that the alert
       box is more likely to come up on top of the main window. */
    if (cf_path != NULL) {
	  simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
	      "Could not open your capture filter file\n\"%s\": %s.", cf_path,
	      strerror(cf_open_errno));
	  g_free(cf_path);
    }

    /* If the user's display filter file exists but we failed to open it,
       pop up an alert box; we defer that until now, so that the alert
       box is more likely to come up on top of the main window. */
    if (df_path != NULL) {
	  simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
	      "Could not open your display filter file\n\"%s\": %s.", df_path,
	      strerror(df_open_errno));
	  g_free(df_path);
    }

    /* If the global disabled protocols file exists but we failed to open it,
       or had an error reading it, pop up an alert box; we defer that until now,
       so that the alert box is more likely to come up on top of the main
       window. */
    if (gdp_path != NULL) {
	if (gdp_open_errno != 0) {
	    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
		"Could not open global disabled protocols file\n\"%s\": %s.",
		gdp_path, strerror(gdp_open_errno));
	}
	if (gdp_read_errno != 0) {
	    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
		"I/O error reading global disabled protocols file\n\"%s\": %s.",
		gdp_path, strerror(gdp_read_errno));
	}
	g_free(gdp_path);
    }

    /* If the user's disabled protocols file exists but we failed to open it,
       or had an error reading it, pop up an alert box; we defer that until now,
       so that the alert box is more likely to come up on top of the main
       window. */
    if (dp_path != NULL) {
	if (dp_open_errno != 0) {
	    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
		"Could not open your disabled protocols file\n\"%s\": %s.", dp_path,
		strerror(dp_open_errno));
	}
	if (dp_read_errno != 0) {
	    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
		"I/O error reading your disabled protocols file\n\"%s\": %s.", dp_path,
		strerror(dp_read_errno));
	}
	g_free(dp_path);
    }

#ifdef HAVE_LIBPCAP
    if (capture_child) {
	/* This is the child process for a sync mode or fork mode capture,
	   so just do the low-level work of a capture - don't create
	   a temporary file and fork off *another* child process (so don't
	   call "do_capture()"). */

	   /* XXX - hand these stats to the parent process */
	   capture(&stats_known, &stats);

	   /* The capture is done; there's nothing more for us to do. */
	   PostQuitMessage(0);
    } else {
	if (start_capture) {
	    /* "-k" was specified; start a capture. */
	    if (do_capture(save_file)) {
		/* The capture started.  Open tap windows; we do so after creating
		   the main window, to avoid GTK warnings, and after starting the
		   capture, so we know we have something to tap. */
//		if (tap_opt && tli) {
//		    (*tli->func)(tap_opt);
//		    g_free(tap_opt);
//		}
	    }
	    if (save_file != NULL) {
		/* Save the directory name for future file dialogs. */
		s = get_dirname(save_file);  /* Overwrites save_file */
		set_last_open_dir(s);
		g_free(save_file);
		save_file = NULL;
	    }
	}
	else {
	    set_menus_for_capture_in_progress(FALSE);
	}
    }
    if (!start_capture && (cfile.cfilter == NULL || strlen(cfile.cfilter) == 0)) {
	if (cfile.cfilter) {
	    g_free(cfile.cfilter);
	}
	cfile.cfilter = g_strdup(get_conn_cfilter());
    }
#else
    set_menus_for_capture_in_progress(FALSE);
#endif

    while( GetMessage( &msg, NULL, 0, 0 ) != 0) {
	TranslateMessage( &msg );
	DispatchMessage( &msg );
    }

    epan_cleanup();

    /* Shutdown windows sockets */
    WSACleanup();

    /* For some unknown reason, the "atexit()" call in "create_console()"
       doesn't arrange that "destroy_console()" be called when we exit,
       so we call it here if a console was created. */
    if (console_was_created)
        destroy_console();

    return msg.wParam;
}

/* XXX - How do we fold this into ethereal-main.c? */
LRESULT CALLBACK
win32_main_wnd_proc(HWND hw_mainwin, UINT msg, WPARAM w_param, LPARAM l_param)
{
    win32_element_t *el;

    switch(msg) {
	case WM_CREATE:
	    ethereal_main_handle_wm_create(hw_mainwin);
	    break;

	case WM_NOTIFY:
	    break;

	case WM_SIZE:
	    ethereal_main_handle_wm_size(hw_mainwin, (int) LOWORD(l_param), (int) HIWORD(l_param));
	    break;

	case WM_COMMAND:
		/* XXX - It would be nice if we implemented the <command> element;
		 * we could then handle all of this as a set of <command> callbacks. */
		switch(w_param) {
		    case IDM_ETHEREAL_MAIN_OPEN:
		    case IDB_MAIN_TOOLBAR_OPEN:
			if (win32_open_file(hw_mainwin))
			    ethereal_packetlist_init(&cfile);
			break;
		    case IDM_ETHEREAL_MAIN_OPEN_RECENT_CLEAR:
			clear_menu_recent(hw_mainwin);
			break;
		    case IDM_ETHEREAL_MAIN_MERGE:
			win32_merge_file(hw_mainwin);
			break;
		    case IDM_ETHEREAL_MAIN_EXPORT_FILE:
			win32_export_file(hw_mainwin);
			break;
		    case IDM_ETHEREAL_MAIN_EXPORT_SELECTED:
			win32_export_raw_file(hw_mainwin);
			break;
		    case IDM_ETHEREAL_MAIN_CLOSE:
		    case IDB_MAIN_TOOLBAR_CLOSE:
			/* XXX - Prompt the user if we have an unsaved file */
			cf_close(&cfile);
			break;
		    case IDM_ETHEREAL_MAIN_SAVE:
		    case IDB_MAIN_TOOLBAR_SAVE:
			if (cfile.user_saved)
			    break;
			win32_save_as_file(hw_mainwin, after_save_no_action, NULL);
			break;
		    case IDM_ETHEREAL_MAIN_SAVE_AS:
		    case IDB_MAIN_TOOLBAR_SAVE_AS:
			win32_save_as_file(hw_mainwin, after_save_no_action, NULL);
			break;

		    case IDM_ETHEREAL_MAIN_EDIT_FIND_PACKET:
		    case IDB_MAIN_TOOLBAR_FIND:
			find_dialog_init();
			break;
		    case IDM_ETHEREAL_MAIN_EDIT_FIND_NEXT:
		    case IDB_MAIN_TOOLBAR_FIND_NEXT:
			find_previous_next(FALSE);
			break;
		    case IDM_ETHEREAL_MAIN_EDIT_FIND_PREVIOUS:
		    case IDB_MAIN_TOOLBAR_FIND_PREV:
			find_previous_next(TRUE);
			break;
		    case IDM_ETHEREAL_MAIN_EDIT_TIME_REF_TOGGLE:
			reftime_frame_cb(REFTIME_TOGGLE);
			break;
		    case IDM_ETHEREAL_MAIN_EDIT_TIME_REF_NEXT:
			reftime_frame_cb(REFTIME_FIND_NEXT);
			break;
		    case IDM_ETHEREAL_MAIN_EDIT_TIME_REF_PREV:
			reftime_frame_cb(REFTIME_FIND_PREV);
			break;
		    case IDM_ETHEREAL_MAIN_EDIT_MARK_PACKET:
			mark_current_frame();
			break;
		    case IDM_ETHEREAL_MAIN_EDIT_MARK_ALL_PACKETS:
			mark_all_frames(TRUE);
			break;
		    case IDM_ETHEREAL_MAIN_EDIT_UNMARK_ALL_PACKETS:
			mark_all_frames(FALSE);
			break;
		    case IDM_ETHEREAL_MAIN_EDIT_PREFERENCES:
		    case IDB_MAIN_TOOLBAR_PREFS:
			prefs_dialog_init(hw_mainwin);
			break;

		    case IDM_ETHEREAL_MAIN_VIEW_MAIN_TOOLBAR:
			recent.main_toolbar_show = ! recent.main_toolbar_show;
			menu_update_view_items();
			main_widgets_show_or_hide();
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_FILTER_TOOLBAR:
			recent.filter_toolbar_show = ! recent.filter_toolbar_show;
			menu_update_view_items();
			main_widgets_show_or_hide();
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_STATUSBAR:
			recent.statusbar_show = ! recent.statusbar_show;
			menu_update_view_items();
			main_widgets_show_or_hide();
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_PACKET_LIST:
			recent.packet_list_show = ! recent.packet_list_show;
			menu_update_view_items();
			main_widgets_show_or_hide();
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_PACKET_DETAILS:
			recent.tree_view_show = ! recent.tree_view_show;
			menu_update_view_items();
			main_widgets_show_or_hide();
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_PACKET_BYTES:
			recent.byte_view_show = ! recent.byte_view_show;
			menu_update_view_items();
			main_widgets_show_or_hide();
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_TIMEDF_TOD:
			menu_toggle_timestamps(TS_ABSOLUTE);
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_TIMEDF_DATOD:
			menu_toggle_timestamps(TS_ABSOLUTE_WITH_DATE);
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_TIMEDF_SECSBEG:
			menu_toggle_timestamps(TS_RELATIVE);
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_TIMEDF_SECSPREV:
			menu_toggle_timestamps(TS_DELTA);
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_NAMERES_MAC:
		    case IDM_ETHEREAL_MAIN_VIEW_NAMERES_NETWORK:
		    case IDM_ETHEREAL_MAIN_VIEW_NAMERES_TRANSPORT:
			menu_toggle_name_resolution(hw_mainwin, w_param);
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_AUTOSCROLL:
			menu_toggle_auto_scroll();
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_ZOOMIN:
		    case IDB_MAIN_TOOLBAR_ZOOMIN:
			view_zoom_in();
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_ZOOMOUT:
		    case IDB_MAIN_TOOLBAR_ZOOMOUT:
			view_zoom_out();
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_NORMALSZ:
		    case IDB_MAIN_TOOLBAR_NORMALSZ:
			view_zoom_100();
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_COLLAPSEALL:
			collapse_all_cb();
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_EXPANDALL:
			expand_all_cb();
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_EXPANDTREE:
			expand_tree_cb();
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_COLORING:
		    case IDB_MAIN_TOOLBAR_COLOR_DLG:
			coloring_rules_dialog_init(hw_mainwin);
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_NEWWINDOW:
			packet_window_init(hw_mainwin);
			break;
		    case IDM_ETHEREAL_MAIN_VIEW_RELOAD:
		    case IDB_MAIN_TOOLBAR_RELOAD:
			cf_reload();
			break;

		    case IDM_ETHEREAL_MAIN_GO_TOPACKET:
		    case IDB_MAIN_TOOLBAR_GOTO_NUM:
			goto_dialog_init(hw_mainwin);
			break;
		    case IDM_ETHEREAL_MAIN_GO_CORRESPONDING:
			goto_framenum(&cfile);
			break;
		    case IDM_ETHEREAL_MAIN_GO_FIRST:
		    case IDB_MAIN_TOOLBAR_GOTO_FIRST:
			goto_top_frame(&cfile);
			break;
		    case IDM_ETHEREAL_MAIN_GO_LAST:
		    case IDB_MAIN_TOOLBAR_GOTO_LAST:
			goto_bottom_frame(&cfile);
			break;

		    case IDM_ETHEREAL_MAIN_CAPTURE_START:
		    case IDB_MAIN_TOOLBAR_CAPTURE_START:
			capture_start_prep();
			break;
		    case IDM_ETHEREAL_MAIN_CAPTURE_STOP:
		    case IDB_MAIN_TOOLBAR_CAPTURE_STOP:
			capture_stop();
			break;
		    case IDM_ETHEREAL_MAIN_CAPTURE_INTERFACES:
			capture_interfaces_dialog_init(hw_mainwin);
			break;
		    case IDM_ETHEREAL_MAIN_CAPTURE_FILTERS:
		    case IDB_MAIN_TOOLBAR_CAP_FILT:
			cfilter_dialog();
			break;

		    case IDM_ETHEREAL_MAIN_ANALYZE_DF:
		    case IDB_MAIN_TOOLBAR_DISP_FILT:
			el = win32_identifier_get_str("main-toolbar");
			win32_element_assert(el);
		 	filter_dialog_cb(el);
		 	break;
		    case IDM_ETHEREAL_MAIN_ANALYZE_AAF_SELECTED:
			match_selected_ptree_cb(MATCH_SELECTED_REPLACE|MATCH_SELECTED_APPLY_NOW);
			break;
		    case IDM_ETHEREAL_MAIN_ANALYZE_AAF_NOTSELECTED:
			match_selected_ptree_cb(MATCH_SELECTED_NOT|MATCH_SELECTED_APPLY_NOW);
			break;
		    case IDM_ETHEREAL_MAIN_ANALYZE_AAF_ANDSELECTED:
			match_selected_ptree_cb(MATCH_SELECTED_AND|MATCH_SELECTED_APPLY_NOW);
			break;
		    case IDM_ETHEREAL_MAIN_ANALYZE_AAF_ORSELECTED:
			match_selected_ptree_cb(MATCH_SELECTED_OR|MATCH_SELECTED_APPLY_NOW);
			break;
		    case IDM_ETHEREAL_MAIN_ANALYZE_AAF_ANDNOTSELECTED:
			match_selected_ptree_cb(MATCH_SELECTED_AND_NOT|MATCH_SELECTED_APPLY_NOW);
			break;
		    case IDM_ETHEREAL_MAIN_ANALYZE_AAF_ORNOTSELECTED:
			match_selected_ptree_cb(MATCH_SELECTED_OR_NOT|MATCH_SELECTED_APPLY_NOW);
			break;
		    case IDM_ETHEREAL_MAIN_ANALYZE_PAF_SELECTED:
			match_selected_ptree_cb(MATCH_SELECTED_REPLACE);
			break;
		    case IDM_ETHEREAL_MAIN_ANALYZE_PAF_NOTSELECTED:
			match_selected_ptree_cb(MATCH_SELECTED_NOT);
			break;
		    case IDM_ETHEREAL_MAIN_ANALYZE_PAF_ANDSELECTED:
			match_selected_ptree_cb(MATCH_SELECTED_AND);
			break;
		    case IDM_ETHEREAL_MAIN_ANALYZE_PAF_ORSELECTED:
			match_selected_ptree_cb(MATCH_SELECTED_OR);
			break;
		    case IDM_ETHEREAL_MAIN_ANALYZE_PAF_ANDNOTSELECTED:
			match_selected_ptree_cb(MATCH_SELECTED_AND_NOT);
			break;
		    case IDM_ETHEREAL_MAIN_ANALYZE_PAF_ORNOTSELECTED:
			match_selected_ptree_cb(MATCH_SELECTED_OR_NOT);
			break;
		    case IDM_ETHEREAL_MAIN_ANALYZE_ENAPROTO:
			enabled_protocols_dialog_init(hw_mainwin);
			break;

		    case IDM_ETHEREAL_MAIN_ABOUT_ETHEREAL:
			about_dialog_init(hw_mainwin);
			break;
		    case IDM_ETHEREAL_MAIN_EXIT:
			file_quit_cmd(hw_mainwin);
			break;

		    default:
			if (w_param >= IDM_RECENT_FILE_START && w_param < IDM_RECENT_FILE_START + prefs.gui_recent_files_count_max) {
			    open_menu_recent_capture_file(hw_mainwin, w_param);
			}
			break;
		}
		break;

	case WM_DESTROY:
	    main_do_quit();
	    break;

	default:
	    return( DefWindowProc( hw_mainwin, msg, w_param, l_param ));
	    break;
    }

    return 0;
}

BOOL CALLBACK
capture_dialog_dlg_proc(HWND hw_capture, UINT msg, WPARAM w_param, LPARAM l_param)
{
    win32_element_t *dlg_box;

    switch( msg ) {
	case WM_INITDIALOG:
	    capture_dialog_handle_wm_initdialog(hw_capture);
	    dlg_box = (win32_element_t *) GetWindowLong(hw_capture, GWL_USERDATA);
	    win32_element_assert (dlg_box);
	    win32_element_resize(dlg_box, -1, -1);
	    return 0;
	    break;
	case WM_COMMAND:
	    return 0;
	    break;
	case WM_CLOSE:
	    capture_dialog_dialog_hide(hw_capture);
	    return 1;
	    break;
	default:
	    return 0;
    }
    return 0;
}

BOOL CALLBACK
capture_info_dialog_dlg_proc(HWND hw_cap_info, UINT msg, WPARAM w_param, LPARAM l_param)
{
    win32_element_t *dlg_box;

    switch( msg ) {
	case WM_INITDIALOG:
	    capture_info_dialog_handle_wm_initdialog(hw_cap_info);
	    dlg_box = (win32_element_t *) GetWindowLong(hw_cap_info, GWL_USERDATA);
	    win32_element_assert (dlg_box);
	    win32_element_resize(dlg_box, -1, -1);
	    return 0;
	    break;
	case WM_COMMAND:
	    g_warning("w_param: %04x", LOWORD(w_param));
	    return 0;
	    break;
	case WM_CLOSE:
	    dlg_box = (win32_element_t *) GetWindowLong(hw_cap_info, GWL_USERDATA);
	    win32_element_assert (dlg_box);
	    capture_info_dialog_stop_capture(dlg_box);
	    return 1;
	    break;
	default:
	    return 0;
    }
    return 0;
}

/* Call filter_packets() and add this filter string to the recent filter list */
/* Taken from gtk/main.c. */
/* XXX - The routines that call this set the filter text by hand beforehand.
 * Should we do that here instead? */
int
main_filter_packets(capture_file *cf, gchar *dftext)
{
    win32_element_t *dfilter_el = win32_identifier_get_str("dfilter-entry");
    int              filter_packets_ret;
    gboolean         add_filter = TRUE;

    win32_element_assert(dfilter_el);

    if ((filter_packets_ret = filter_packets(cf, dftext, FALSE))) {
	if (SendMessage(dfilter_el->h_wnd, CB_FINDSTRINGEXACT, (WPARAM) -1, (LPARAM) (LPCTSTR) dftext) == CB_ERR) {
	    if (dftext[0] != '\0')
		SendMessage(dfilter_el->h_wnd, CB_ADDSTRING, 0, (LPARAM) (LPCTSTR) dftext);
	}
    }

    filter_tb_syntax_check(dfilter_el->h_wnd, NULL);

    return filter_packets_ret;
}

/* Bring up the display filter dialog */
void
filter_dialog_cb(win32_element_t *btn_el) {
    win32_element_t *dfilter_el = win32_identifier_get_str("dfilter-entry");

    static construct_args_t args = {
	"Ethereal: Display Filter",
	TRUE,
	TRUE
    };

    display_filter_construct(btn_el, dfilter_el, &args);
}

/* Apply the current display filter */
void
filter_apply_cb(win32_element_t *el) {
    win32_element_t *dfilter_el = win32_identifier_get_str("dfilter-entry");
    int              len;
    gchar           *dftext;

    win32_element_assert(dfilter_el);

    len = SendMessage(dfilter_el->h_wnd, WM_GETTEXTLENGTH, 0, 0);
    if (len > 0) {
	len++;
	dftext = g_malloc(len);
	SendMessage(dfilter_el->h_wnd, WM_GETTEXT, (WPARAM) len, (LPARAM) dftext);
	main_filter_packets(&cfile, dftext);
	g_free (dftext);
    }
}

/* Clear the display filter */
void
filter_clear_cb(win32_element_t *el) {
    win32_element_t *dfilter_el = win32_identifier_get_str("dfilter-entry");

    win32_element_assert(dfilter_el);

    SendMessage(dfilter_el->h_wnd, WM_SETTEXT, 0, (LPARAM)(LPCTSTR) "");
    main_filter_packets(&cfile, "");
}

/* Check the syntax of the display filter */
void
filter_changed_cb(win32_element_t *el) {
    win32_element_t *dfilter_el = win32_identifier_get_str("dfilter-entry");
    gchar           *filter_text;
    gint             cur_sel, len;

    win32_element_assert(dfilter_el);

    cur_sel = SendMessage(dfilter_el->h_wnd, CB_GETCURSEL, 0, 0);
    if (cur_sel != CB_ERR) {	/* The user selected something */
	len = SendMessage(dfilter_el->h_wnd, CB_GETLBTEXTLEN, (WPARAM) cur_sel, 0);
	if (len >= 0) {
	    len++;
	    filter_text = g_malloc(len);
	    SendMessage(dfilter_el->h_wnd, CB_GETLBTEXT, (WPARAM) cur_sel, (LPARAM) filter_text);
	    filter_tb_syntax_check(dfilter_el->h_wnd, filter_text);
	    g_free(filter_text);
	}
    } else {	/* The user typed something in */
	filter_tb_syntax_check(dfilter_el->h_wnd, NULL);
    }
    RedrawWindow(dfilter_el->h_wnd, NULL, NULL, RDW_INVALIDATE);
}

/* Write all non empty display filters (until maximum count)
 * of the combo box list to the user's recent file */
void
dfilter_recent_combo_write_all(FILE *rf) {
    win32_element_t *dfilter_el = win32_identifier_get_str("dfilter-entry");
    guint            count = 0, cb_item = 0, cb_count;
    gchar           *dftext;
    LRESULT          len = 256, new_len;

    win32_element_assert(dfilter_el);
    dftext = g_malloc(len);

    /* We have to pay attention to the number of items in the combobox _and_
     * the number of items we've written, so we use two counters. */
    cb_count = SendMessage(dfilter_el->h_wnd, CB_GETCOUNT, 0, 0);
    while (cb_item < cb_count && count < dfilter_combo_max_recent) {
	new_len = SendMessage(dfilter_el->h_wnd, CB_GETLBTEXTLEN, (WPARAM) cb_item, 0);
	if (new_len > len) {
	    len = new_len;
	    dftext = g_realloc(dftext, len);
	}
	if (SendMessage(dfilter_el->h_wnd, CB_GETLBTEXT, (WPARAM) cb_item, (LPARAM) (LPCSTR) dftext)) {
	    fprintf (rf, RECENT_KEY_DISPLAY_FILTER ": %s\n", dftext);
	    count++;
	}
	cb_item++;
    }
    g_free(dftext);
}

/* Empty the combobox entry field */
void
dfilter_combo_add_empty(void) {
    filter_clear_cb(NULL);
}

/* Add a display filter coming from the user's recent file to the dfilter combo box */
gboolean
dfilter_combo_add_recent(gchar *dftext) {
    win32_element_t *dfilter_el = win32_identifier_get_str("dfilter-entry");

    if (SendMessage(dfilter_el->h_wnd, CB_FINDSTRINGEXACT, (WPARAM) -1, (LPARAM) (LPCTSTR) dftext) == CB_ERR) {
	if (SendMessage(dfilter_el->h_wnd, CB_ADDSTRING, 0, (LPARAM) (LPCTSTR) dftext) != CB_ERR) {
	    return TRUE;
	}
    }

    return FALSE;
}

/* XXX - Copied verbatim from gtk/main.c */
gboolean
main_do_quit(void)
{
    gchar *rec_path;

    /* get the current geometry, before writing it to disk */
    main_save_window_geometry(g_hw_mainwin);

    /* write user's recent file to disk
     * It is no problem to write this file, even if we do not quit */
    write_recent(&rec_path);

    /* XXX - should we check whether the capture file is an
       unsaved temporary file for a live capture and, if so,
       pop up a "do you want to exit without saving the capture
       file?" dialog, and then just return, leaving said dialog
       box to forcibly quit if the user clicks "OK"?

       If so, note that this should be done in a subroutine that
       returns TRUE if we do so, and FALSE otherwise, and if it
       returns TRUE we should return TRUE without nuking anything.

       Note that, if we do that, we might also want to check if
       an "Update list of packets in real time" capture is in
       progress and, if so, ask whether they want to terminate
       the capture and discard it, and return TRUE, before nuking
       any child capture, if they say they don't want to do so. */

#ifdef HAVE_LIBPCAP
    /* Nuke any child capture in progress. */
    kill_capture_child();
#endif

    /* Are we in the middle of reading a capture? */
    if (cfile.state == FILE_READ_IN_PROGRESS) {
	/* Yes, so we can't just close the file and quit, as
	   that may yank the rug out from under the read in
	   progress; instead, just set the state to
	   "FILE_READ_ABORTED" and return - the code doing the read
	   will check for that and, if it sees that, will clean
	   up and quit. */
	cfile.state = FILE_READ_ABORTED;

	/* Say that the window should *not* be deleted;
	   that'll be done by the code that cleans up. */
	return TRUE;
    } else {
	/* Close any capture file we have open; on some OSes, you
	   can't unlink a temporary capture file if you have it
	   open.
	   "cf_close()" will unlink it after closing it if
	   it's a temporary file.

	   We do this here, rather than after the main loop returns,
	   as, after the main loop returns, the main window may have
	   been destroyed (if this is called due to a "destroy"
	   even on the main window rather than due to the user
	   selecting a menu item), and there may be a crash
	   or other problem when "cf_close()" tries to
	   clean up stuff in the main window.

	   XXX - is there a better place to put this?
	   Or should we have a routine that *just* closes the
	   capture file, and doesn't do anything with the UI,
	   which we'd call here, and another routine that
	   calls that routine and also cleans up the UI, which
	   we'd call elsewhere? */
	cf_close(&cfile);

	/* Exit by leaving the main loop, so that any quit functions
	   we registered get called. */
	PostQuitMessage(0);

	/* Say that the window should be deleted. */
	return FALSE;
    }
}

HICON
get_ethereal_icon_small(HWND hwnd) {
    static HICON eicon = NULL;
    HINSTANCE    h_instance = (HINSTANCE) GetWindowLong(hwnd, GWL_HINSTANCE);

    if (eicon == NULL)
	eicon = LoadImage(h_instance, "ETHEREAL_ICON", IMAGE_ICON, 16, 16, LR_DEFAULTSIZE);

    return eicon;
}

HICON
get_ethereal_icon_large(HWND hwnd) {
    static HICON eicon = NULL;
    HINSTANCE    h_instance = (HINSTANCE) GetWindowLong(hwnd, GWL_HINSTANCE);

    if (eicon == NULL)
	eicon = LoadImage(h_instance, "ETHEREAL_ICON", IMAGE_ICON, 32, 32, LR_DEFAULTSIZE);

    return eicon;
}


/* Routines defined elsewhere that we need to handle */


/* Routines defined in ui_util.h */

/* Set the name of the top-level window. */
void set_main_window_name(gchar *window_name) {
    SetWindowText(g_hw_mainwin, window_name);
}

/* create byte views in the main window */
/* XXX - Move to ethereal-byteview.c? */
void add_main_byte_views(epan_dissect_t *edt) {
    win32_element_t *byteview = win32_identifier_get_str("main-byteview");
    win32_element_t *treeview = win32_identifier_get_str("main-treeview");

    win32_element_assert(byteview);
    win32_element_assert(treeview);
    ethereal_byteview_add(edt, byteview, treeview);
}

/* display the protocol tree in the main widow */
/* XXX - Move to ethereal-treeview.c? */
void main_proto_tree_draw(proto_tree *protocol_tree) {
    win32_element_t *treeview = win32_identifier_get_str("main-treeview");
    win32_element_t *byteview = win32_identifier_get_str("main-byteview");

    win32_element_assert(treeview);
    win32_element_assert(byteview);

    ethereal_treeview_draw(treeview, protocol_tree, byteview);
}

void clear_tree_and_hex_views(void) {
    win32_element_t *byteview = win32_identifier_get_str("main-byteview");
    win32_element_t *treeview = win32_identifier_get_str("main-treeview");

    ethereal_treeview_clear(treeview);
    ethereal_byteview_clear(byteview);
}

/* Destroy all popup packet windows. */
void destroy_packet_wins(void) {
}

gint packet_list_get_sort_column(void) {
    return 0;
}

/* Destroy the save as dialog */
void file_save_as_destroy(void) {
}

/* Defined in tap_dfilter_dlg.h */

/* This will update the titles of the dialog windows when we load a new capture
file. */
void tap_dfilter_dlg_update (void) {
}


static void
main_save_window_geometry(HWND hwnd)
{
    window_geometry_t geom;

    window_get_geometry(hwnd, &geom);

    if (prefs.gui_geometry_save_position) {
	recent.gui_geometry_main_x = geom.x;
	recent.gui_geometry_main_y = geom.y;
    }

    if (prefs.gui_geometry_save_size) {
	recent.gui_geometry_main_width  = geom.width,
	recent.gui_geometry_main_height = geom.height;
    }
    /* XXX - Pane sizes */
}

static void
main_load_window_geometry(HWND hw_mainwin) {
    window_geometry_t geom;

    geom.set_pos        = prefs.gui_geometry_save_position;
    geom.x              = recent.gui_geometry_main_x;
    geom.y              = recent.gui_geometry_main_y;
    geom.set_size       = prefs.gui_geometry_save_size;
    if (recent.gui_geometry_main_width > 0 &&
	recent.gui_geometry_main_height > 0) {
	geom.width          = recent.gui_geometry_main_width;
	geom.height         = recent.gui_geometry_main_height;
	geom.set_maximized  = prefs.gui_geometry_save_maximized;
    } else {
	/* We assume this means the width and height weren't set in
	   the "recent" file (or that there is no "recent" file),
	   and weren't set to a default value, so we don't set the
	   size.  (The "recent" file code rejects non-positive width
	   and height values.) */
       geom.set_size = FALSE;
    }
    geom.maximized      = recent.gui_geometry_main_maximized;

    window_set_geometry(hw_mainwin, &geom);
    /* XXX - Size our panes */
}

void
main_widgets_show_or_hide() {
    win32_element_t *cur_el;
    RECT             wr;

    cur_el = win32_identifier_get_str("main-toolbox");
    win32_element_assert(cur_el);
    ShowWindow(cur_el->h_wnd, recent.main_toolbar_show ? SW_SHOW : SW_HIDE);

    /*
     * Show the status hbox if either:
     *
     *    1) we're showing the filter toolbar and we want it in the status
     *       line
     *
     * or
     *
     *    2) we're showing the status bar.
     */
    cur_el = win32_identifier_get_str("main-status-hbox");
    win32_element_assert(cur_el);
    if ((recent.filter_toolbar_show && prefs.filter_toolbar_show_in_statusbar) ||
	     recent.statusbar_show) {
	ShowWindow(cur_el->h_wnd, SW_SHOW);
    } else {
	ShowWindow(cur_el->h_wnd, SW_HIDE);
    }

    cur_el = win32_identifier_get_str("main-statusbar");
    win32_element_assert(cur_el);
    ShowWindow(cur_el->h_wnd, recent.statusbar_show ? SW_SHOW : SW_HIDE);

    cur_el = win32_identifier_get_str("main-filter");
    win32_element_assert(cur_el);
    ShowWindow(cur_el->h_wnd, recent.filter_toolbar_show ? SW_SHOW : SW_HIDE);

    cur_el = win32_identifier_get_str("main-packetlist");
    win32_element_assert(cur_el);
    ShowWindow(cur_el->h_wnd, recent.packet_list_show ? SW_SHOW : SW_HIDE);

    cur_el = win32_identifier_get_str("main-splitter-pltv");
    win32_element_assert(cur_el);
    if (recent.packet_list_show && recent.tree_view_show)
	ShowWindow(cur_el->h_wnd, SW_SHOW);
    else
	ShowWindow(cur_el->h_wnd, SW_HIDE);

    cur_el = win32_identifier_get_str("main-treeview");
    win32_element_assert(cur_el);
    ShowWindow(cur_el->h_wnd, recent.tree_view_show ? SW_SHOW : SW_HIDE);

    cur_el = win32_identifier_get_str("main-splitter-tvbv");
    win32_element_assert(cur_el);
    if (recent.packet_list_show || (recent.tree_view_show && recent.byte_view_show))
	ShowWindow(cur_el->h_wnd, SW_SHOW);
    else
	ShowWindow(cur_el->h_wnd, SW_HIDE);

    cur_el = win32_identifier_get_str("main-byteview");
    win32_element_assert(cur_el);
    ShowWindow(cur_el->h_wnd, recent.byte_view_show ? SW_SHOW : SW_HIDE);

    cur_el = win32_identifier_get_str("main-vbox");
    win32_element_assert(cur_el);
    GetWindowRect(cur_el->h_wnd, &wr);
    win32_element_resize(cur_el, wr.right - wr.left, wr.bottom - wr.top);
}

static void
file_save_as_cmd(void) {
}

static void
file_quit_cmd(HWND hw_mainwin) {
    gint btn;

    if((cfile.state != FILE_CLOSED) && !cfile.user_saved && prefs.gui_ask_unsaved) {
	/* user didn't saved his current file, ask him */
	btn = (gint) simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_SAVE_DONTSAVE_CANCEL,
		"Save capture file before program quit?\n\n"
		"If you quit the program without saving, your capture data will be discarded.");
	switch(btn) {
	    case(ESD_BTN_SAVE):
		/* save file first */
		win32_save_as_file(hw_mainwin, after_save_exit, NULL);
		break;
	    case(ESD_BTN_DONT_SAVE):
		main_do_quit();
		break;
	    case(ESD_BTN_CANCEL):
		break;
	    default:
		g_assert_not_reached();
	}
    } else {
	/* unchanged file, just exit */
	main_do_quit();
    }
}

/* XXX - Copied verbatim from gtk/main.c */
/* mark as reference time frame */
static void
set_frame_reftime(gboolean set, frame_data *frame, gint row) {
    if (row == -1)
	return;
    if (set) {
	frame->flags.ref_time=1;
    } else {
	frame->flags.ref_time=0;
    }
    reftime_packets(&cfile);
}

/* XXX - Copied (mostly) verbatim from gtk/main.c */
static void
reftime_frame_cb(REFTIME_ACTION_E action) {

    switch(action) {
	case REFTIME_TOGGLE:
	    if (cfile.current_frame) {
		/* XXX hum, should better have a "cfile->current_row" here ... */
		set_frame_reftime(!cfile.current_frame->flags.ref_time,
			cfile.current_frame,
			packet_list_find_row_from_data(cfile.current_frame));
	    }
	    break;
	case REFTIME_FIND_NEXT:
	    find_previous_next_frame_with_filter("frame.ref_time", FALSE);
	    break;
	case REFTIME_FIND_PREV:
	    find_previous_next_frame_with_filter("frame.ref_time", TRUE);
	    break;
    }
}

static void
collapse_all_cb() {
    win32_element_t *treeview = win32_identifier_get_str("main-treeview");

    win32_element_assert(treeview);

    ethereal_treeview_collapse_all(treeview);
}

static void
expand_all_cb() {
    win32_element_t *treeview = win32_identifier_get_str("main-treeview");

    win32_element_assert(treeview);

    ethereal_treeview_expand_all(treeview);
}

static void
expand_tree_cb() {
    win32_element_t *treeview = win32_identifier_get_str("main-treeview");

    win32_element_assert(treeview);

    ethereal_treeview_expand_tree(treeview);
}

static void
match_selected_ptree_cb(MATCH_SELECTED_E action)
{
    if (cfile.finfo_selected)
	match_selected_cb_do(action,
	    proto_construct_dfilter_string(cfile.finfo_selected, cfile.edt));
}


/* Match selected byte pattern */
static void
match_selected_cb_do(int action, gchar *text)
{
    win32_element_t *filter_cb = win32_identifier_get_str("dfilter-entry");
    char            *cur_filter, *new_filter;
    gint             len;

    if (!text)
	return;
    win32_element_assert(filter_cb);

    len = GetWindowTextLength(filter_cb->h_wnd) + 1;
    cur_filter = g_malloc(len);
    GetWindowText(filter_cb->h_wnd, cur_filter, len);

    switch (action&MATCH_SELECTED_MASK) {

    case MATCH_SELECTED_REPLACE:
	new_filter = g_strdup(text);
	break;

    case MATCH_SELECTED_AND:
	if ((!cur_filter) || (0 == strlen(cur_filter)))
	    new_filter = g_strdup(text);
	else
	    new_filter = g_strconcat("(", cur_filter, ") && (", text, ")", NULL);
	break;

    case MATCH_SELECTED_OR:
	if ((!cur_filter) || (0 == strlen(cur_filter)))
	    new_filter = g_strdup(text);
	else
	    new_filter = g_strconcat("(", cur_filter, ") || (", text, ")", NULL);
	break;

    case MATCH_SELECTED_NOT:
	new_filter = g_strconcat("!(", text, ")", NULL);
	break;

    case MATCH_SELECTED_AND_NOT:
	if ((!cur_filter) || (0 == strlen(cur_filter)))
	    new_filter = g_strconcat("!(", text, ")", NULL);
	else
	    new_filter = g_strconcat("(", cur_filter, ") && !(", text, ")", NULL);
	break;

    case MATCH_SELECTED_OR_NOT:
	if ((!cur_filter) || (0 == strlen(cur_filter)))
	    new_filter = g_strconcat("!(", text, ")", NULL);
	else
	    new_filter = g_strconcat("(", cur_filter, ") || !(", text, ")", NULL);
	break;

    default:
	g_assert_not_reached();
	new_filter = NULL;
	break;
    }

    /* Free up the copy we got of the old filter text. */
    g_free(cur_filter);

    /* create a new one and set the display filter entry accordingly */
    SetWindowText(filter_cb->h_wnd, new_filter);

    /* Run the display filter so it goes in effect. */
    if (action&MATCH_SELECTED_APPLY_NOW)
	main_filter_packets(&cfile, new_filter);

    /* Free up the new filter text. */
    g_free(new_filter);

    /* Free up the generated text we were handed. */
    g_free(text);
}
