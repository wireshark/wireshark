/* dumpcap.c
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h> /* for exit() */
#include <glib.h>

#include <string.h>
#include <ctype.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <signal.h>

#ifdef NEED_GETOPT_H
#include "getopt.h"
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_LIBCAP
# include <sys/prctl.h>
# include <sys/capability.h>
# include <stdio.h>
#endif

#include "ringbuffer.h"
#include "clopts_common.h"
#include "cmdarg_err.h"
#include "version_info.h"

#include <pcap.h>
#include "capture-pcap-util.h"

#ifdef _WIN32
#include "capture-wpcap.h"
#endif

#ifdef _WIN32
#include "epan/unicode-utils.h"
#endif

#ifdef HAVE_LIBCAP
#include "epan/privileges.h"
#endif

#include "sync_pipe.h"

#include "capture.h"
#include "capture_loop.h"
#include "capture_sync.h"

#include "simple_dialog.h"
#include "util.h"
#include "log.h"
#include "file_util.h"


/*#define DEBUG_DUMPCAP*/

gboolean capture_child = FALSE; /* FALSE: standalone call, TRUE: this is an Wireshark capture child */
#ifdef _WIN32
gchar *sig_pipe_name = NULL;
HANDLE sig_pipe_handle = NULL;
#endif

static void
console_log_handler(const char *log_domain, GLogLevelFlags log_level,
		    const char *message, gpointer user_data _U_);

/* capture related options */
capture_options global_capture_opts;
capture_options *capture_opts = &global_capture_opts;

#if __GNUC__ >= 2
void exit_main(int err) __attribute__ ((noreturn));
#else
void exit_main(int err);
#endif


static void
print_usage(gboolean print_ver) {

  FILE *output;


  if (print_ver) {
    output = stdout;
    fprintf(output,
        "Dumpcap " VERSION "%s\n"
        "Capture network packets and dump them into a libpcap file.\n"
        "See http://www.wireshark.org for more information.\n",
        wireshark_svnversion);
  } else {
    output = stderr;
  }
  fprintf(output, "\nUsage: dumpcap [options] ...\n");
  fprintf(output, "\n");
  fprintf(output, "Capture interface:\n");
  fprintf(output, "  -i <interface>           name or idx of interface (def: first none loopback)\n");
  fprintf(output, "  -f <capture filter>      packet filter in libpcap filter syntax\n");
  fprintf(output, "  -s <snaplen>             packet snapshot length (def: 65535)\n");
  fprintf(output, "  -p                       don't capture in promiscuous mode\n");
#ifdef _WIN32
  fprintf(output, "  -B <buffer size>         size of kernel buffer (def: 1MB)\n");
#endif
  fprintf(output, "  -y <link type>           link layer type (def: first appropriate)\n");
  fprintf(output, "  -D                       print list of interfaces and exit\n");
  fprintf(output, "  -L                       print list of link-layer types of iface and exit\n");
  fprintf(output, "  -S                       print statistics for each interface once every second\n");
  fprintf(output, "  -M                       for -D, -L, and -S produce machine-readable output\n");
  fprintf(output, "\n");
#ifdef HAVE_PCAP_REMOTE
  fprintf(output, "\nRPCAP options:\n");
  fprintf(output, "  -r                       don't ignore own RPCAP traffic in capture\n");
  fprintf(output, "  -u                       use UDP for RPCAP data transfer\n");
  fprintf(output, "  -A <user>:<password>     use RPCAP password authentication\n");
#ifdef HAVE_PCAP_SETSAMPLING
  fprintf(output, "  -m <sampling type>       use packet sampling\n");
  fprintf(output, "                           count:NUM - capture one packet of every NUM\n");
  fprintf(output, "                           timer:NUM - capture no more than 1 packet in NUM ms\n");
#endif
#endif
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
  fprintf(output, "\n");
  fprintf(output, "Example: dumpcap -i eth0 -a duration:60 -w output.pcap\n");
  fprintf(output, "\"Capture network packets from interface eth0 until 60s passed into output.pcap\"\n");
  fprintf(output, "\n");
  fprintf(output, "Use Ctrl-C to stop capturing at any time.\n");
}

static void
show_version(GString *comp_info_str, GString *runtime_info_str)
{

  printf(
        "Dumpcap " VERSION "%s\n"
        "\n"
        "%s\n"
        "%s\n"
        "%s\n"
        "See http://www.wireshark.org for more information.\n",
        wireshark_svnversion, get_copyright_info() ,comp_info_str->str, runtime_info_str->str);
}

/*
 * Report an error in command-line arguments.
 */
void
cmdarg_err(const char *fmt, ...)
{
  va_list ap;

  if(capture_child) {
    /* Print a bare error */
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
  } else {
    va_start(ap, fmt);
    fprintf(stderr, "dumpcap: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
  }
}

/*
 * Report additional information for an error in command-line arguments.
 */
void
cmdarg_err_cont(const char *fmt, ...)
{
  va_list ap;

  if(capture_child) {
    /* XXX - convert to g_log */
  } else {
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
  }
}


#ifdef _WIN32
static BOOL WINAPI
capture_cleanup(DWORD dwCtrlType)
{
    /* CTRL_C_EVENT is sort of like SIGINT, CTRL_BREAK_EVENT is unique to
       Windows, CTRL_CLOSE_EVENT is sort of like SIGHUP, CTRL_LOGOFF_EVENT
       is also sort of like SIGHUP, and CTRL_SHUTDOWN_EVENT is sort of
       like SIGTERM at least when the machine's shutting down.

       For now, if we're running as a command rather than a capture child,
       we handle all but CTRL_LOGOFF_EVENT as indications that we should
       clean up and quit, just as we handle SIGINT, SIGHUP, and SIGTERM
       in that way on UN*X.

       If we're not running as a capture child, we might be running as
       a service; ignore CTRL_LOGOFF_EVENT, so we keep running after the
       user logs out.  (XXX - can we explicitly check whether we're
       running as a service?) */

    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO,
        "Console: Control signal");
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
        "Console: Control signal, CtrlType: %u", dwCtrlType);

    /* Keep capture running if we're a service and a user logs off */
    if (capture_child || (dwCtrlType != CTRL_LOGOFF_EVENT)) {
        capture_loop_stop();
        return TRUE;
    } else {
        return FALSE;
    }
}
#else
static void
capture_cleanup(int signum)
{
    /* On UN*X, we cleanly shut down the capture on SIGINT, SIGHUP, and
       SIGTERM.  We assume that if the user wanted it to keep running
       after they logged out, they'd have nohupped it. */

    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO,
        "Console: Signal");
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
        "Console: Signal, signal value: %u", signum);

    capture_loop_stop();
}
#endif

void exit_main(int status)
{
#ifdef _WIN32
  /* Shutdown windows sockets */
  WSACleanup();

  /* can be helpful for debugging */
#ifdef DEBUG_DUMPCAP
  printf("Press any key\n");
  _getch();
#endif

#endif /* _WIN32 */

  exit(status);
}

#ifdef HAVE_LIBCAP
/*
 * If we were linked with libcap (not libpcap), make sure we have
 * CAP_NET_ADMIN and CAP_NET_RAW, then relinquish our permissions.
 */

void
#if 0 /* Set to enable capability debugging */
print_caps(char *pfx) {
    cap_t caps = cap_get_proc();
    fprintf(stderr, "%s: EUID: %d  Capabilities: %s\n", pfx,
            geteuid(), cap_to_text(caps, NULL));
    cap_free(caps);
#else
print_caps(char *pfx _U_) {
#endif
}

void
relinquish_privs_except_capture(void)
{
    /* CAP_NET_ADMIN: Promiscuous mode and a truckload of other
     *                stuff we don't need (and shouldn't have).
     * CAP_NET_RAW:   Packet capture (raw sockets).
     */
    cap_value_t cap_list[2] = { CAP_NET_ADMIN, CAP_NET_RAW };
    cap_t caps = cap_init();
    int cl_len = sizeof(cap_list) / sizeof(cap_value_t);

    if (started_with_special_privs()) {
        print_caps("Pre drop, pre set");
        if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
            perror("prctl()");
        }

        cap_set_flag(caps, CAP_PERMITTED,   cl_len, cap_list, CAP_SET);
        cap_set_flag(caps, CAP_INHERITABLE, cl_len, cap_list, CAP_SET);

        if (cap_set_proc(caps)) {
            perror("capset()");
        }
        print_caps("Pre drop, post set");
    }

    relinquish_special_privs_perm();

    print_caps("Post drop, pre set");
    cap_set_flag(caps, CAP_EFFECTIVE,   cl_len, cap_list, CAP_SET);
    if (cap_set_proc(caps)) {
        perror("capset()");
    }
    print_caps("Post drop, post set");
    cap_free(caps);
}
#endif /* HAVE_LIBCAP */


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
#ifndef _WIN32
  struct sigaction action, oldaction;
#endif

  gboolean             start_capture = TRUE;
  gboolean             stats_known;
  struct pcap_stat     stats;
  GLogLevelFlags       log_flags;
  gboolean             list_interfaces = FALSE;
  gboolean             list_link_layer_types = FALSE;
  gboolean             machine_readable = FALSE;
  gboolean             print_statistics = FALSE;
  int                  status, run_once_args = 0;

#ifdef HAVE_PCAP_REMOTE
#define OPTSTRING_INIT "a:A:b:c:Df:hi:Lm:MprSs:uvw:y:Z:"
#else
#define OPTSTRING_INIT "a:b:c:Df:hi:LMpSs:vw:y:Z:"
#endif

#ifdef _WIN32
#define OPTSTRING_WIN32 "B:"
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
  SetConsoleCtrlHandler(capture_cleanup, TRUE);
#else
  /* Catch SIGINT and SIGTERM and, if we get either of them, clean up
     and exit. */
  action.sa_handler = capture_cleanup;
  action.sa_flags = 0;
  sigemptyset(&action.sa_mask);
  sigaction(SIGTERM, &action, NULL);
  sigaction(SIGINT, &action, NULL);
  sigaction(SIGHUP, NULL, &oldaction);
  if (oldaction.sa_handler == SIG_DFL)
    sigaction(SIGHUP, &action, NULL);
#endif  /* _WIN32 */

#ifdef HAVE_LIBCAP
  get_credential_info();
  relinquish_privs_except_capture();
#endif

  /* the default_log_handler will use stdout, which makes trouble in */
  /* capture child mode, as it uses stdout for it's sync_pipe */
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

  /* Default to capturing the entire packet. */
  capture_opts->snaplen             = WTAP_MAX_PACKET_SIZE;

  /* We always save to a file - if no file was specified, we save to a
     temporary file. */
  capture_opts->saving_to_file      = TRUE;
  capture_opts->has_ring_num_files  = TRUE;

  /* Now get our args */
  while ((opt = getopt(argc, argv, optstring)) != -1) {
    switch (opt) {
      case 'h':        /* Print help and exit */
        print_usage(TRUE);
        exit_main(0);
        break;
      case 'v':        /* Show version and exit */
      {
        GString             *comp_info_str;
        GString             *runtime_info_str;
        /* Assemble the compile-time version information string */
        comp_info_str = g_string_new("Compiled ");
        get_compiled_version_info(comp_info_str, NULL);

        /* Assemble the run-time version information string */
        runtime_info_str = g_string_new("Running ");
        get_runtime_version_info(runtime_info_str, NULL);
        show_version(comp_info_str, runtime_info_str);
        g_string_free(comp_info_str, TRUE);
        g_string_free(runtime_info_str, TRUE);
        exit_main(0);
        break;
      }
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
#ifdef HAVE_PCAP_REMOTE
      case 'u':        /* Use UDP for data transfer */
      case 'r':        /* Capture own RPCAP traffic too */
      case 'A':        /* Authentication */
#endif
#ifdef HAVE_PCAP_SETSAMPLING
      case 'm':        /* Sampling */
#endif
#ifdef _WIN32
      case 'B':        /* Buffer size */
#endif /* _WIN32 */
        status = capture_opts_add_opt(capture_opts, opt, optarg, &start_capture);
        if(status != 0) {
            exit_main(status);
        }
        break;
      /*** hidden option: Wireshark child mode (using binary output messages) ***/
      case 'Z':
          capture_child = TRUE;
#ifdef _WIN32
          /* set output pipe to binary mode, to avoid ugly text conversions */
	  _setmode(2, O_BINARY);
          /*
           * optarg = the control ID, aka the PPID, currently used for the
           * signal pipe name.
           */
          if (strcmp(optarg, SIGNAL_PIPE_CTRL_ID_NONE) != 0) {
              sig_pipe_name = g_strdup_printf(SIGNAL_PIPE_FORMAT,
                  optarg);
              sig_pipe_handle = CreateFile(utf_8to16(sig_pipe_name),
                  GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

              if (sig_pipe_handle == INVALID_HANDLE_VALUE) {
                  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO,
                      "Signal pipe: Unable to open %s.  Dead parent?",
                      sig_pipe_name);
                  exit_main(1);
              }
          }
#endif
          break;

      /*** all non capture option specific ***/
      case 'D':        /* Print a list of capture devices and exit */
        list_interfaces = TRUE;
        run_once_args++;
        break;
      case 'L':        /* Print list of link-layer types and exit */
        list_link_layer_types = TRUE;
        run_once_args++;
        break;
      case 'S':        /* Print interface statistics once a second */
        print_statistics = TRUE;
        run_once_args++;
        break;
      case 'M':        /* For -D and -L, print machine-readable output */
        machine_readable = TRUE;
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
     * XXX - interpret as capture filter, as tcpdump and tshark do?
     */
    cmdarg_err("Invalid argument: %s", argv[0]);
    arg_error = TRUE;
  }

  if (arg_error) {
    print_usage(FALSE);
    exit_main(1);
  }

  if (run_once_args > 1) {
    cmdarg_err("Only one of -D, -L, or -S may be supplied.");
    exit_main(1);
  } else if (list_link_layer_types) {
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

  if (capture_opts_trim_iface(capture_opts, NULL) == FALSE) {
	cmdarg_err("No capture interfaces available (maybe lack of privileges?).");
    exit_main(1);
  }

  /* Let the user know what interface was chosen. */
  /* get_interface_descriptive_name() is not available! */
  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "Interface: %s\n", capture_opts->iface);

  if (list_interfaces) {
    status = capture_opts_list_interfaces(machine_readable);
    exit_main(status);
  } else if (list_link_layer_types) {
    status = capture_opts_list_link_layer_types(capture_opts, machine_readable);
    exit_main(status);
  } else if (print_statistics) {
    status = capture_opts_print_statistics(machine_readable);
    exit_main(status);
  }

  capture_opts_trim_snaplen(capture_opts, MIN_PACKET_SIZE);
  capture_opts_trim_ring_num_files(capture_opts);

  /* Now start the capture. */

  if(capture_loop_start(capture_opts, &stats_known, &stats) == TRUE) {
      /* capture ok */
      exit_main(0);
  } else {
      /* capture failed */
      exit_main(1);
  }
}


static void
console_log_handler(const char *log_domain, GLogLevelFlags log_level,
		    const char *message, gpointer user_data _U_)
{
  time_t curr;
  struct tm *today;
  const char *level;


  /* ignore log message, if log_level isn't interesting */
  if( !(log_level & G_LOG_LEVEL_MASK & ~(G_LOG_LEVEL_DEBUG|G_LOG_LEVEL_INFO))) {
#ifndef DEBUG_DUMPCAP
    return;
#endif
  }

  /* create a "timestamp" */
  time(&curr);
  today = localtime(&curr);

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

  /* don't use printf (stdout), in child mode we're using stdout for the sync_pipe */
  if(log_level & G_LOG_LEVEL_MESSAGE) {
    /* normal user messages without additional infos */
    fprintf(stderr, "%s\n", message);
    fflush(stderr);
  } else {
    /* info/debug messages with additional infos */
    fprintf(stderr, "%02u:%02u:%02u %8s %s %s\n",
            today->tm_hour, today->tm_min, today->tm_sec,
            log_domain != NULL ? log_domain : "",
            level, message);
    fflush(stderr);
  }
}


/****************************************************************************************************************/
/* indication report routines */


void
report_packet_count(int packet_count)
{
    char tmp[SP_DECISIZE+1+1];
    static int count = 0;

    if(capture_child) {
        g_snprintf(tmp, sizeof(tmp), "%d", packet_count);
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "Packets: %s", tmp);
        pipe_write_block(2, SP_PACKET_COUNT, tmp);
    } else {
        count += packet_count;
        fprintf(stderr, "\rPackets: %u ", count);
        /* stderr could be line buffered */
        fflush(stderr);
    }
}

void
report_new_capture_file(const char *filename)
{
    if(capture_child) {
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "File: %s", filename);
        pipe_write_block(2, SP_FILE, filename);
    } else {
        fprintf(stderr, "File: %s\n", filename);
        /* stderr could be line buffered */
        fflush(stderr);
    }
}

void
report_cfilter_error(const char *cfilter, const char *errmsg)
{
    if (capture_child) {
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "Capture filter error: %s", errmsg);
        pipe_write_block(2, SP_BAD_FILTER, errmsg);
    } else {
        fprintf(stderr,
          "Invalid capture filter: \"%s\"!\n"
          "\n"
          "That string isn't a valid capture filter (%s).\n"
          "See the User's Guide for a description of the capture filter syntax.\n",
          cfilter, errmsg);
    }
}

void
report_capture_error(const char *error_msg, const char *secondary_error_msg)
{
    if(capture_child) {
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
            "Primary Error: %s", error_msg);
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
            "Secondary Error: %s", secondary_error_msg);
    	sync_pipe_errmsg_to_parent(2, error_msg, secondary_error_msg);
    } else {
        fprintf(stderr, "%s\n%s\n", error_msg, secondary_error_msg);
    }
}

void
report_packet_drops(int drops)
{
    char tmp[SP_DECISIZE+1+1];

    g_snprintf(tmp, sizeof(tmp), "%d", drops);

    if(capture_child) {
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "Packets dropped: %s", tmp);
        pipe_write_block(2, SP_DROPS, tmp);
    } else {
        fprintf(stderr, "Packets dropped: %s\n", tmp);
        /* stderr could be line buffered */
        fflush(stderr);
    }
}


/****************************************************************************************************************/
/* signal_pipe handling */


#ifdef _WIN32
gboolean
signal_pipe_check_running(void)
{
    /* any news from our parent? -> just stop the capture */
    DWORD avail = 0;
    gboolean result;

    /* if we are running standalone, no check required */
    if(!capture_child) {
        return TRUE;
    }

    if(!sig_pipe_name || !sig_pipe_handle) {
        /* This shouldn't happen */
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO,
            "Signal pipe: No name or handle");
        return FALSE;
    }

    /*
     * XXX - We should have the process ID of the parent (from the "-Z" flag)
     * at this point.  Should we check to see if the parent is still alive,
     * e.g. by using OpenProcess?
     */

    result = PeekNamedPipe(sig_pipe_handle, NULL, 0, NULL, &avail, NULL);

    if(!result || avail > 0) {
        /* peek failed or some bytes really available */
        /* (if not piping from stdin this would fail) */
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO,
            "Signal pipe: Stop capture: %s", sig_pipe_name);
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
            "Signal pipe: %s (%p) result: %u avail: %u", sig_pipe_name,
            sig_pipe_handle, result, avail);
        return FALSE;
    } else {
        /* pipe ok and no bytes available */
        return TRUE;
    }
}
#endif
