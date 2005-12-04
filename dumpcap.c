/* dumpcap.c
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <string.h>
#include <ctype.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef NEED_GETOPT_H
#include "getopt.h"
#endif

#ifdef _WIN32 /* Needed for console I/O */
#include <conio.h>
#endif

#include "ringbuffer.h"
#include "clopts_common.h"
#include "cmdarg_err.h"
#include "version_info.h"

#include <pcap.h>
#include "pcap-util.h"

#ifdef _WIN32
#include "capture-wpcap.h"
#include "capture_wpcap_packet.h"
#endif

#include "capture.h"
#include "capture_loop.h"
#include "capture_sync.h"

#include "simple_dialog.h"
#include "util.h"
#include "log.h"
#include "file_util.h"



GString *comp_info_str, *runtime_info_str;
gchar       *ethereal_path = NULL;

#ifdef _WIN32
static gboolean has_console = TRUE;	/* TRUE if app has console */
static void create_console(void);
static void destroy_console(void);
#endif
static void
console_log_handler(const char *log_domain, GLogLevelFlags log_level,
		    const char *message, gpointer user_data _U_);

capture_options global_capture_opts;
capture_options *capture_opts = &global_capture_opts;



static void
print_usage(gboolean print_ver) {

  FILE *output;

#ifdef _WIN32
  create_console();
#endif

  if (print_ver) {
    output = stdout;
    fprintf(output, "This is dumpcap " VERSION "%s"
        "\n (C) 1998-2005 Gerald Combs <gerald@ethereal.com>"
	"\n\n%s\n\n%s\n",
	svnversion, comp_info_str->str, runtime_info_str->str);
  } else {
    output = stderr;
  }
  fprintf(output, "\n%s [ -vh ] [ -Lp ] [ -a <capture autostop condition> ] ...\n", PACKAGE);	  
  fprintf(output, "\t[ -b <capture ring buffer option> ] ...\n");
#ifdef _WIN32
  fprintf(output, "\t[ -B <capture buffer size> ]\n");
#endif
  fprintf(output, "\t[ -c <capture packet count> ] [ -f <capture filter> ]\n");
  fprintf(output, "\t[ -i <capture interface> ]\n");
  fprintf(output, "\t[ -s <capture snaplen> ]\n");
  fprintf(output, "\t[ -w <savefile> ] [ -y <capture link type> ]\n");
}

static void
show_version(void)
{
  printf("dumpcap " VERSION "%s\n\n%s\n\n%s\n",
      svnversion, comp_info_str->str, runtime_info_str->str);
}

/*
 * Report an error in command-line arguments.
 * Creates a console on Windows.
 * XXX - pop this up in a window of some sort on UNIX+X11 if the controlling
 * terminal isn't the standard error?
 */
void
cmdarg_err(const char *fmt, ...)
{
  va_list ap;

#ifdef _WIN32
  create_console();
#endif
  va_start(ap, fmt);
  fprintf(stderr, "dumpcap: ");
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
}

/*
 * Report additional information for an error in command-line arguments.
 * Creates a console on Windows.
 * XXX - pop this up in a window of some sort on UNIX+X11 if the controlling
 * terminal isn't the standard error?
 */
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


#ifdef _WIN32
BOOL WINAPI ConsoleCtrlHandlerRoutine(DWORD dwCtrlType)
{
    /*printf("Event: %u", dwCtrlType);*/
    capture_loop_stop();

    return TRUE;
}
#endif

void
exit_main(int err) {
#ifdef _WIN32
  /* Shutdown windows sockets */
  WSACleanup();

  destroy_console();
#endif

  exit(err);
}


/* And now our feature presentation... [ fade to music ] */
int
main(int argc, char *argv[])
{
  int                  opt;
  extern char         *optarg;
  gboolean             arg_error = FALSE;

#ifdef _WIN32
  WSADATA              wsaData;
#endif  /* _WIN32 */

  int                  err;
  gboolean             start_capture = TRUE;
  GList               *if_list;
  if_info_t           *if_info;
  GList               *lt_list, *lt_entry;
  data_link_info_t    *data_link_info;
  gchar                err_str[PCAP_ERRBUF_SIZE];
  gchar               *cant_get_if_list_errstr;
  gboolean             stats_known;
  struct pcap_stat     stats;
  GLogLevelFlags       log_flags;
  gboolean             list_link_layer_types = FALSE;

#define OPTSTRING_INIT "a:b:c:f:Hhi:Lps:vW:w:y:"

#ifdef _WIN32
#define OPTSTRING_WIN32 "B:Z:"
#else
#define OPTSTRING_WIN32 ""
#endif  /* _WIN32 */

  char optstring[sizeof(OPTSTRING_INIT) + sizeof(OPTSTRING_WIN32) - 1] =
    OPTSTRING_INIT OPTSTRING_WIN32;

  /*** create the compile and runtime version strings ***/
#ifdef _WIN32
  /* Load wpcap if possible. Do this before collecting the run-time version information */
  load_wpcap();

  /* ... and also load the packet.dll from wpcap */
  wpcap_packet_load();

  /* Start windows sockets */
  WSAStartup( MAKEWORD( 1, 1 ), &wsaData );


  
  SetConsoleCtrlHandler(&ConsoleCtrlHandlerRoutine, TRUE);
#endif  /* _WIN32 */

  /* Assemble the compile-time version information string */
  comp_info_str = g_string_new("Compiled ");
  g_string_append(comp_info_str, "with ");
  get_compiled_version_info(comp_info_str);

  /* Assemble the run-time version information string */
  runtime_info_str = g_string_new("Running ");
  get_runtime_version_info(runtime_info_str);

  ethereal_path = argv[0];

  /* Arrange that if we have no console window, and a GLib message logging
     routine is called to log a message, we pop up a console window.

     We do that by inserting our own handler for all messages logged
     to the default domain; that handler pops up a console if necessary,
     and then calls the default handler. */

  /* We might want to have component specific log levels later ... */

  /* the default_log_handler will use stdout, which makes trouble with the */
  /* capture child, as it uses stdout for it's sync_pipe */
  /* so do the filtering in the console_log_handler and not here */
  log_flags = 
		    G_LOG_LEVEL_ERROR|
		    G_LOG_LEVEL_CRITICAL|
		    G_LOG_LEVEL_WARNING|
		    G_LOG_LEVEL_MESSAGE|
		    G_LOG_LEVEL_INFO|
		    G_LOG_LEVEL_DEBUG|
		    G_LOG_FLAG_FATAL|G_LOG_FLAG_RECURSION;

  g_log_set_handler(NULL,
		    log_flags,
		    console_log_handler, NULL /* user_data */);
  g_log_set_handler(LOG_DOMAIN_MAIN,
		    log_flags,
		    console_log_handler, NULL /* user_data */);
  g_log_set_handler(LOG_DOMAIN_CAPTURE,
		    log_flags,
            console_log_handler, NULL /* user_data */);
  g_log_set_handler(LOG_DOMAIN_CAPTURE_CHILD,
		    log_flags,
            console_log_handler, NULL /* user_data */);

  /* Set the initial values in the capture_opts. This might be overwritten 
     by preference settings and then again by the command line parameters. */
  capture_opts_init(capture_opts, NULL);

  capture_opts->snaplen             = MIN_PACKET_SIZE;
  capture_opts->has_ring_num_files  = TRUE;

  /* Now get our args */
  while ((opt = getopt(argc, argv, optstring)) != -1) {
    switch (opt) {
      case 'h':        /* Print help and exit */
        print_usage(TRUE);
        exit_main(0);
        break;
      case 'v':        /* Show version and exit */
        show_version();
        exit_main(0);
        break;
      /*** capture option specific ***/
      case 'a':        /* autostop criteria */
      case 'b':        /* Ringbuffer option */
      case 'c':        /* Capture xxx packets */
      case 'f':        /* capture filter */
      case 'H':        /* Hide capture info dialog box */
      case 'i':        /* Use interface xxx */
      case 'p':        /* Don't capture in promiscuous mode */
      case 's':        /* Set the snapshot (capture) length */
      case 'w':        /* Write to capture file xxx */
      case 'y':        /* Set the pcap data link type */
#ifdef _WIN32
      case 'B':        /* Buffer size */
      /* Hidden option supporting Sync mode */
      case 'Z':        /* Write to pipe FD XXX */
#endif /* _WIN32 */
        capture_opts_add_opt(capture_opts, opt, optarg, &start_capture);
        break;
      /* This is a hidden option supporting Sync mode, so we don't set
       * the error flags for the user in the non-libpcap case.
       */
      case 'W':        /* Write to capture file FD xxx */
        capture_opts_add_opt(capture_opts, opt, optarg, &start_capture);
	break;

      /*** all non capture option specific ***/
      case 'L':        /* Print list of link-layer types and exit */
        list_link_layer_types = TRUE;
        break;
      default:
      case '?':        /* Bad flag - print usage message */
        arg_error = TRUE;
        break;
    }
  }
  argc -= optind;
  argv += optind;
  if (argc >= 1) {
      /* user specified file name as regular command-line argument */
      /* XXX - use it as the capture file name (or somthing else)? */
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

  if (arg_error) {
    print_usage(FALSE);
    exit_main(1);
  }

  if (list_link_layer_types) {
    /* We're supposed to list the link-layer types for an interface;
       did the user also specify a capture file to be read? */
    /* No - did they specify a ring buffer option? */
    if (capture_opts->multi_files_on) {
      cmdarg_err("Ring buffer requested, but a capture isn't being done.");
      exit_main(1);
    }
  } else {
    /* No - was the ring buffer option specified and, if so, does it make
       sense? */
    if (capture_opts->multi_files_on) {
      /* Ring buffer works only under certain conditions:
	 a) ring buffer does not work with temporary files;
	 b) it makes no sense to enable the ring buffer if the maximum
	    file size is set to "infinite". */
      if (capture_opts->save_file == NULL) {
	cmdarg_err("Ring buffer requested, but capture isn't being saved to a permanent file.");
	capture_opts->multi_files_on = FALSE;
      }
      if (!capture_opts->has_autostop_filesize && !capture_opts->has_file_duration) {
	cmdarg_err("Ring buffer requested, but no maximum capture file size or duration were specified.");
/* XXX - this must be redesigned as the conditions changed */
/*	capture_opts->multi_files_on = FALSE;*/
      }
    }
  }

/* Did the user specify an interface to use? */
if (capture_opts->iface == NULL) {
    /* No - pick the first one from the list of interfaces. */
    if_list = get_interface_list(&err, err_str);
    if (if_list == NULL) {
      switch (err) {

      case CANT_GET_INTERFACE_LIST:
          cant_get_if_list_errstr = cant_get_if_list_error_message(err_str);
          cmdarg_err("%s", cant_get_if_list_errstr);
          g_free(cant_get_if_list_errstr);
          break;

      case NO_INTERFACES_FOUND:
          cmdarg_err("There are no interfaces on which a capture can be done");
          break;
      }
      exit_main(2);
    }
    if_info = if_list->data;	/* first interface */
    capture_opts->iface = g_strdup(if_info->name);
    free_interface_list(if_list);
  }

  if (list_link_layer_types) {
    /* Get the list of link-layer types for the capture device. */
    lt_list = get_pcap_linktype_list(capture_opts->iface, err_str);
    if (lt_list == NULL) {
      if (err_str[0] != '\0') {
	cmdarg_err("The list of data link types for the capture device could not be obtained (%s)."
	  "Please check to make sure you have sufficient permissions, and that\n"
	  "you have the proper interface or pipe specified.\n", err_str);
      } else
	cmdarg_err("The capture device has no data link types.");
      exit_main(2);
    }
    g_warning("Data link types (use option -y to set):");
    for (lt_entry = lt_list; lt_entry != NULL;
         lt_entry = g_list_next(lt_entry)) {
      data_link_info = lt_entry->data;
      g_warning("  %s", data_link_info->name);
      if (data_link_info->description != NULL)
	g_warning(" (%s)", data_link_info->description);
      else
	g_warning(" (not supported)");
      putchar('\n');
    }
    free_pcap_linktype_list(lt_list);
    exit_main(0);
  }

  if (capture_opts->has_snaplen) {
    if (capture_opts->snaplen < 1)
      capture_opts->snaplen = WTAP_MAX_PACKET_SIZE;
    else if (capture_opts->snaplen < MIN_PACKET_SIZE)
      capture_opts->snaplen = MIN_PACKET_SIZE;
  }

  /* Check the value range of the ringbuffer_num_files parameter */
  if (capture_opts->ring_num_files > RINGBUFFER_MAX_NUM_FILES)
    capture_opts->ring_num_files = RINGBUFFER_MAX_NUM_FILES;
#if RINGBUFFER_MIN_NUM_FILES > 0
  else if (capture_opts->num_files < RINGBUFFER_MIN_NUM_FILES)
    capture_opts->ring_num_files = RINGBUFFER_MIN_NUM_FILES;
#endif

  /* Now start the capture. */

  /* XXX - hand the stats to the parent process */
  if(capture_loop_start(capture_opts, &stats_known, &stats) == TRUE) {
      /* capture ok */
      err = 0;
  } else {
      /* capture failed */
      err = 1;
  }

  /* the capture is done; there's nothing more for us to do. */
  exit_main(err);
}

#ifdef _WIN32

/* We build this as a GUI subsystem application on Win32, so
   "WinMain()", not "main()", gets called.

   Hack shamelessly stolen from the Win32 port of the GIMP. */
#ifdef __GNUC__
#define _stdcall  __attribute__((stdcall))
#endif

int _stdcall
WinMain (struct HINSTANCE__ *hInstance,
	 struct HINSTANCE__ *hPrevInstance,
	 char               *lpszCmdLine,
	 int                 nCmdShow)
{
  has_console = FALSE;
  return main (__argc, __argv);
}

/*
 * If this application has no console window to which its standard output
 * would go, create one.
 */
void
create_console(void)
{
  if (!has_console) {
    /* We have no console to which to print the version string, so
       create one and make it the standard input, output, and error. */
    if (!AllocConsole())
      return;   /* couldn't create console */
    eth_freopen("CONIN$", "r", stdin);
    eth_freopen("CONOUT$", "w", stdout);
    eth_freopen("CONOUT$", "w", stderr);

    /* Well, we have a console now. */
    has_console = TRUE;

    /* Now register "destroy_console()" as a routine to be called just
       before the application exits, so that we can destroy the console
       after the user has typed a key (so that the console doesn't just
       disappear out from under them, giving the user no chance to see
       the message(s) we put in there). */
    atexit(destroy_console);

    SetConsoleTitle("Dumpcap Console");
  }
}

static void
destroy_console(void)
{
  if (has_console) {
    printf("\n\nPress any key to exit\n");
    _getch();
    FreeConsole();
  }
}
#endif /* _WIN32 */


/* This routine should not be necessary, at least as I read the GLib
   source code, as it looks as if GLib is, on Win32, *supposed* to
   create a console window into which to display its output.

   That doesn't happen, however.  I suspect there's something completely
   broken about that code in GLib-for-Win32, and that it may be related
   to the breakage that forces us to just call "printf()" on the message
   rather than passing the message on to "g_log_default_handler()"
   (which is the routine that does the aforementioned non-functional
   console window creation). */
static void
console_log_handler(const char *log_domain, GLogLevelFlags log_level,
		    const char *message, gpointer user_data _U_)
{
  time_t curr;
  struct tm *today;
  const char *level;


  /* ignore log message, if log_level isn't interesting */
  if( !(log_level & G_LOG_LEVEL_MASK & ~G_LOG_LEVEL_DEBUG /*prefs.console_log_level*/)) {
    return;
  }

  /* create a "timestamp" */
  time(&curr);
  today = localtime(&curr);    

#ifdef _WIN32
/*  if (prefs.gui_console_open != console_open_never) {*/
    create_console();
/*  }*/
  if (has_console) {
    /* For some unknown reason, the above doesn't appear to actually cause
       anything to be sent to the standard output, so we'll just splat the
       message out directly, just to make sure it gets out. */
#endif
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
        fprintf(stderr, "unknown log_level %u\n", log_level);
        level = NULL;
        g_assert_not_reached();
    }

    /* don't use printf (stdout), as the capture child uses stdout for it's sync_pipe */
    fprintf(stderr, "%02u:%02u:%02u %8s %s %s\n",
            today->tm_hour, today->tm_min, today->tm_sec,
            log_domain != NULL ? log_domain : "",
            level, message);
#ifdef _WIN32
  } else {
    g_log_default_handler(log_domain, log_level, message, user_data);
  }
#endif
}

/****************************************************************************************************************/
/* sync_pipe "dummies" */

static void
pipe_write_block(int pipe, char indicator, int len, const char *msg)
{
}

void
sync_pipe_packet_count_to_parent(int packet_count)
{
    char tmp[SP_DECISIZE+1+1];

    g_snprintf(tmp, sizeof(tmp), "%d", packet_count);

    /*g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "sync_pipe_packet_count_to_parent: %s", tmp);*/

    pipe_write_block(1, SP_PACKET_COUNT, strlen(tmp)+1, tmp);
}

void
sync_pipe_filename_to_parent(const char *filename)
{
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "File: %s", filename);

    pipe_write_block(1, SP_FILE, strlen(filename)+1, filename);
}

void
sync_pipe_errmsg_to_parent(const char *errmsg)
{
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "sync_pipe_errmsg_to_parent: %s", errmsg);

    pipe_write_block(1, SP_ERROR_MSG, strlen(errmsg)+1, errmsg);
}

void
sync_pipe_drops_to_parent(int drops)
{
    char tmp[SP_DECISIZE+1+1];


    g_snprintf(tmp, sizeof(tmp), "%d", drops);

    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "sync_pipe_drops_to_parent: %s", tmp);

    pipe_write_block(1, SP_DROPS, strlen(tmp)+1, tmp);
}



/****************************************************************************************************************/
/* simple_dialog "dummies" */


static gpointer *
display_simple_dialog(gint type, gint btn_mask, char *message)
{
    printf("%s", message);

    return NULL;
}

char *simple_dialog_primary_start(void)
{
    return "";
}

char *simple_dialog_primary_end(void)
{
    return "";
}

/* Simple dialog function - Displays a dialog box with the supplied message
 * text.
 *
 * Args:
 * type       : One of ESD_TYPE_*.
 * btn_mask   : The value passed in determines which buttons are displayed.
 * msg_format : Sprintf-style format of the text displayed in the dialog.
 * ...        : Argument list for msg_format
 */

gpointer
vsimple_dialog(ESD_TYPE_E type, gint btn_mask, const gchar *msg_format, va_list ap)
{
  gchar             *vmessage;
  gchar             *message;
  gpointer          *win;
#if GTK_MAJOR_VERSION >= 2
  GdkWindowState state = 0;
#endif

  /* Format the message. */
  vmessage = g_strdup_vprintf(msg_format, ap);

#if GTK_MAJOR_VERSION >= 2
  /* convert character encoding from locale to UTF8 (using iconv) */
  message = g_locale_to_utf8(vmessage, -1, NULL, NULL, NULL);
  g_free(vmessage);
#else
  message = vmessage;
#endif

  win = display_simple_dialog(type, btn_mask, message);

  g_free(message);

  return win;
}

gpointer
simple_dialog(ESD_TYPE_E type, gint btn_mask, const gchar *msg_format, ...)
{
  va_list ap;
  gpointer ret;

  va_start(ap, msg_format);
  ret = vsimple_dialog(type, btn_mask, msg_format, ap);
  va_end(ap);
  return ret;
}

char *
simple_dialog_format_message(const char *msg)
{
    char *str;

    if (msg) {
#if GTK_MAJOR_VERSION < 2
	str = g_strdup(msg);
#else
	str = xml_escape(msg);
#endif
    } else {
	str = NULL;
    }
    return str;
}


/*
 * Find out whether a hostname resolves to an ip or ipv6 address
 * Return "ip6" if it is IPv6, "ip" otherwise (including the case
 * that we don't know)
 */
const char* host_ip_af(const char *host
#ifndef HAVE_GETHOSTBYNAME2
_U_
#endif
)
{
#ifdef HAVE_GETHOSTBYNAME2
	struct hostent *h;
	return (h = gethostbyname2(host, AF_INET6)) && h->h_addrtype == AF_INET6 ? "ip6" : "ip";
#else
	return "ip";
#endif
}

