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

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef _WIN32 /* Needed for console I/O */
#include <conio.h>
#endif

#include "ringbuffer.h"
#include "clopts_common.h"
#include "cmdarg_err.h"
#include "version_info.h"

#include <pcap.h>
#include "capture-pcap-util.h"

#ifdef _WIN32
#include "capture-wpcap.h"
/*#include "capture_wpcap_packet.h"*/
#endif

#include "capture.h"
#include "capture_loop.h"
#include "capture_sync.h"

#include "simple_dialog.h"
#include "util.h"
#include "log.h"
#include "file_util.h"



/* Win32 console handling */
#ifdef _WIN32
static gboolean has_console = TRUE;	        /* TRUE if app has console */
static void create_console(void);
static void destroy_console(void);
#endif
static void
console_log_handler(const char *log_domain, GLogLevelFlags log_level,
		    const char *message, gpointer user_data _U_);

/* capture related options */
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
    fprintf(output,
        "Dumpcap " VERSION "%s\n"
        "Capture network packets and dump them into a libpcap file.\n"
        "See http://www.ethereal.com for more information.\n",
        svnversion);
  } else {
    output = stderr;
  }
  fprintf(output, "\nUsage: dumpcap [option] ...\n");
  fprintf(output, "\n");
  fprintf(output, "Capture interface:\n");
  fprintf(output, "  -i <interface>           name or idx of interface (def: first none loopback)\n");
  fprintf(output, "  -f <capture filter>      packet filter in libpcap format\n");
  fprintf(output, "  -s <snaplen>             packet snapshot length (def: 65535)\n");
  fprintf(output, "  -p                       don't capture in promiscuous mode\n");
#ifdef _WIN32
  fprintf(output, "  -B <buffer size>         size of kernel buffer (def: 1MB)\n");
#endif
  fprintf(output, "  -y <link type>           link layer type (def: first appropriate)\n");
  fprintf(output, "\n");
  fprintf(output, "Stop conditions:\n");
  fprintf(output, "  -c <packet count>        stop after n packets (def: infinite)\n");
  fprintf(output, "  -a <autostop cond.> ...  duration:NUM - stop after NUM seconds\n");
  fprintf(output, "                           filesize:NUM - stop this file after NUM KB\n");
  fprintf(output, "                              files:NUM - stop after NUM files\n");
  /*fprintf(output, "\n");*/
  fprintf(output, "Output (files):\n");
  fprintf(output, "  -w <filename>            name of file to save (def: tempfile)\n");
  fprintf(output, "  -b <ringbuffer opt.> ... duration:NUM - switch to next file after NUM secs\n");
  fprintf(output, "                           filesize:NUM - switch to next file after NUM KB\n");
  fprintf(output, "                              files:NUM - ringbuffer: replace after NUM files\n");
  /*fprintf(output, "\n");*/
  fprintf(output, "Miscellaneous:\n");
  fprintf(output, "  -v                       print version information and exit\n");
  fprintf(output, "  -h                       display this help and exit\n");
  fprintf(output, "  -D                       print list of interfaces and exit\n");
  fprintf(output, "  -L                       print list of link-layer types of iface and exit\n");
  fprintf(output, "\n");
  fprintf(output, "Example: dumpcap -i eth0 -a duration:60 -w output.pcap\n");
  fprintf(output, "\"Capture network packets from interface eth0 until 60s passed into output.pcap\"\n");
  fprintf(output, "\n");
  fprintf(output, "Use Ctrl-C to stop capturing at any time.\n");
}

static void
show_version(GString *comp_info_str, GString *runtime_info_str)
{
#ifdef _WIN32
  create_console();
#endif

  printf(
        "Dumpcap " VERSION "%s\n"
        "\n"
        "(C) 1998-2005 Gerald Combs <gerald@ethereal.com>\n"
        "See http://www.ethereal.com for more information.\n"
        "\n"
        "%s\n"
        "\n"
        "%s\n",
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
  GString             *comp_info_str;
  GString             *runtime_info_str;

#ifdef _WIN32
  WSADATA              wsaData;
#endif  /* _WIN32 */

  gboolean             start_capture = TRUE;
  gboolean             stats_known;
  struct pcap_stat     stats;
  GLogLevelFlags       log_flags;
  gboolean             list_link_layer_types = FALSE;

#define OPTSTRING_INIT "a:b:c:Df:hi:Lps:vw:y:"

#ifdef _WIN32
#define OPTSTRING_WIN32 "B:Z:"
#else
#define OPTSTRING_WIN32 ""
#endif  /* _WIN32 */

  char optstring[sizeof(OPTSTRING_INIT) + sizeof(OPTSTRING_WIN32) - 1] =
    OPTSTRING_INIT OPTSTRING_WIN32;



#ifdef _WIN32
  /* Load wpcap if possible. Do this before collecting the run-time version information */
  load_wpcap();

  /* ... and also load the packet.dll from wpcap */
  /* XXX - currently not required, may change later. */
  /*wpcap_packet_load();*/

  /* Start windows sockets */
  WSAStartup( MAKEWORD( 1, 1 ), &wsaData );

  /* Set handler for Ctrl+C key */
  SetConsoleCtrlHandler(&ConsoleCtrlHandlerRoutine, TRUE);
#endif  /* _WIN32 */

  /* Assemble the compile-time version information string */
  comp_info_str = g_string_new("Compiled ");
  g_string_append(comp_info_str, "with ");
  get_compiled_version_info(comp_info_str);

  /* Assemble the run-time version information string */
  runtime_info_str = g_string_new("Running ");
  get_runtime_version_info(runtime_info_str);

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
     by the command line parameters. */
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
        show_version(comp_info_str, runtime_info_str);
        exit_main(0);
        break;
      /*** capture option specific ***/
      case 'a':        /* autostop criteria */
      case 'b':        /* Ringbuffer option */
      case 'c':        /* Capture x packets */
      case 'f':        /* capture filter */
      case 'i':        /* Use interface x */
      case 'p':        /* Don't capture in promiscuous mode */
      case 's':        /* Set the snapshot (capture) length */
      case 'w':        /* Write to capture file x */
      case 'y':        /* Set the pcap data link type */
#ifdef _WIN32
      case 'B':        /* Buffer size */
      /* Hidden option supporting Sync mode */
      case 'Z':        /* Write to pipe FD x */
#endif /* _WIN32 */
        capture_opts_add_opt(capture_opts, opt, optarg, &start_capture);
        break;

      /*** all non capture option specific ***/
      case 'D':        /* Print a list of capture devices and exit */
        capture_opts_list_interfaces();
        exit(0);
        break;
      case 'L':        /* Print list of link-layer types and exit */
        list_link_layer_types = TRUE;
        break;
      default:
      case '?':        /* Bad flag - print usage message */
        cmdarg_err("Invalid Option: %s", argv[optind-1]);
        arg_error = TRUE;
        break;
    }
  }
  argc -= optind;
  argv += optind;
  if (argc >= 1) {
      /* user specified file name as regular command-line argument */
      /* XXX - use it as the capture file name (or something else)? */
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

  capture_opts_trim_iface(capture_opts, NULL);

  /* Let the user know what interface was chosen. */
/*  descr = get_interface_descriptive_name(capture_opts.iface);
  fprintf(stderr, "Capturing on %s\n", descr);
  g_free(descr);*/
  fprintf(stderr, "Capturing on %s\n", capture_opts->iface);
  

  if (list_link_layer_types) {
    capture_opts_list_link_layer_types(capture_opts);
    exit_main(0);
  }

  capture_opts_trim_snaplen(capture_opts, MIN_PACKET_SIZE);
  capture_opts_trim_ring_num_files(capture_opts);

  /* Now start the capture. */

  /* XXX - hand the stats to the parent process */
  if(capture_loop_start(capture_opts, &stats_known, &stats) == TRUE) {
      /* capture ok */
      exit_main(0);
  } else {
      /* capture failed */
      exit_main(1);
  }
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
/* XXX - doesn't make sense while we're linked as a console application */
/*    printf("\n\nPress any key to exit\n");
    _getch();*/
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
  if( !(log_level & G_LOG_LEVEL_MASK & ~(G_LOG_LEVEL_DEBUG|G_LOG_LEVEL_INFO) /*prefs.console_log_level*/)) {
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

/*
 * Maximum length of sync pipe message data.  Must be < 2^24, as the
 * message length is 3 bytes.
 * XXX - this must be large enough to handle a Really Big Filter
 * Expression, as the error message for an incorrect filter expression
 * is a bit larger than the filter expression.
 */
#define SP_MAX_MSG_LEN	4096


 /* write a message to the recipient pipe in the standard format 
   (3 digit message length (excluding length and indicator field), 
   1 byte message indicator and the rest is the message) */
static void
pipe_write_block(int pipe, char indicator, int len, const char *msg)
{
    guchar header[3+1]; /* indicator + 3-byte len */
    int ret;

    /*g_warning("write %d enter", pipe);*/

    /* XXX - find a suitable way to switch between pipe and console output */
    return;

    g_assert(indicator < '0' || indicator > '9');
    g_assert(len <= SP_MAX_MSG_LEN);

    /* write header (indicator + 3-byte len) */
    header[0] = indicator;
    header[1] = (len >> 16) & 0xFF;
    header[2] = (len >> 8) & 0xFF;
    header[3] = (len >> 0) & 0xFF;

    ret = write(pipe, header, sizeof header);
    if(ret == -1) {
        return;
    }

    /* write value (if we have one) */
    if(len) {
        /*g_warning("write %d indicator: %c value len: %u msg: %s", pipe, indicator, len, msg);*/
        ret = write(pipe, msg, len);
        if(ret == -1) {
            return;
        }
    } else {
        /*g_warning("write %d indicator: %c no value", pipe, indicator);*/
    }

    /*g_warning("write %d leave", pipe);*/
}


int count = 0;

void
sync_pipe_packet_count_to_parent(int packet_count)
{
    char tmp[SP_DECISIZE+1+1];


    count += packet_count;
    fprintf(stderr, "\r%u", count);
    /* stderr could be line buffered */
    fflush(stderr);


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


char *simple_dialog_primary_start(void)
{
    return "";
}

char *simple_dialog_primary_end(void)
{
    return "";
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

/****************************************************************************************************************/
/* link "dummies" */


const char *netsnmp_get_version(void) { return ""; }

gboolean dfilter_compile(const gchar *text, dfilter_t **dfp) { return NULL; }

void dfilter_free(dfilter_t *df) {}


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

