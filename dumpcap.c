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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <signal.h>
#include <errno.h>

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
#include "pcapio.h"

#include "capture-pcap-util.h"

#ifdef _WIN32
#include "capture-wpcap.h"
#endif

#ifdef _WIN32
#include <wsutil/unicode-utils.h>
#endif

#include <wsutil/privileges.h>

#include "sync_pipe.h"

#include "capture_opts.h"
#include "capture_sync.h"

#include "conditions.h"
#include "capture_stop_conditions.h"

#include "tempfile.h"
#include "log.h"
#include "wsutil/file_util.h"

/*
 * Get information about libpcap format from "wiretap/libpcap.h".
 * XXX - can we just use pcap_open_offline() to read the pipe?
 */
#include "wiretap/libpcap.h"

/**#define DEBUG_DUMPCAP**/
/**#define DEBUG_CHILD_DUMPCAP**/

#ifdef DEBUG_CHILD_DUMPCAP
FILE *debug_log;   /* for logging debug messages to  */
                   /*  a file if DEBUG_CHILD_DUMPCAP */
                   /*  is defined                    */
#endif

static gboolean capture_child = FALSE; /* FALSE: standalone call, TRUE: this is an Wireshark capture child */
#ifdef _WIN32
static gchar *sig_pipe_name = NULL;
static HANDLE sig_pipe_handle = NULL;
#endif

/** Stop a low-level capture (stops the capture child). */
static void capture_loop_stop(void);

#if !defined (__linux__)
#ifndef HAVE_PCAP_BREAKLOOP
/*
 * We don't have pcap_breakloop(), which is the only way to ensure that
 * pcap_dispatch(), pcap_loop(), or even pcap_next() or pcap_next_ex()
 * won't, if the call to read the next packet or batch of packets is
 * is interrupted by a signal on UN*X, just go back and try again to
 * read again.
 *
 * On UN*X, we catch SIGUSR1 as a "stop capturing" signal, and, in
 * the signal handler, set a flag to stop capturing; however, without
 * a guarantee of that sort, we can't guarantee that we'll stop capturing
 * if the read will be retried and won't time out if no packets arrive.
 *
 * Therefore, on at least some platforms, we work around the lack of
 * pcap_breakloop() by doing a select() on the pcap_t's file descriptor
 * to wait for packets to arrive, so that we're probably going to be
 * blocked in the select() when the signal arrives, and can just bail
 * out of the loop at that point.
 *
 * However, we don't want to that on BSD (because "select()" doesn't work
 * correctly on BPF devices on at least some releases of some flavors of
 * BSD), and we don't want to do it on Windows (because "select()" is
 * something for sockets, not for arbitrary handles).  (Note that "Windows"
 * here includes Cygwin; even in its pretend-it's-UNIX environment, we're
 * using WinPcap, not a UNIX libpcap.)
 *
 * Fortunately, we don't need to do it on BSD, because the libpcap timeout
 * on BSD times out even if no packets have arrived, so we'll eventually
 * exit pcap_dispatch() with an indication that no packets have arrived,
 * and will break out of the capture loop at that point.
 *
 * On Windows, we can't send a SIGUSR1 to stop capturing, so none of this
 * applies in any case.
 *
 * XXX - the various BSDs appear to define BSD in <sys/param.h>; we don't
 * want to include it if it's not present on this platform, however.
 */
# if !defined(__FreeBSD__) && !defined(__NetBSD__) && !defined(__OpenBSD__) && \
    !defined(__bsdi__) && !defined(__APPLE__) && !defined(_WIN32) && \
    !defined(__CYGWIN__)
#  define MUST_DO_SELECT
# endif /* avoid select */
#endif /* HAVE_PCAP_BREAKLOOP */
#else /* linux */
/* whatever the deal with pcap_breakloop, linux doesn't support timeouts
 * in pcap_dispatch(); on the other hand, select() works just fine there.
 * Hence we use a select for that come what may.
 */
#define MUST_DO_SELECT
#endif

/** init the capture filter */
typedef enum {
  INITFILTER_NO_ERROR,
  INITFILTER_BAD_FILTER,
  INITFILTER_OTHER_ERROR
} initfilter_status_t;

typedef struct _loop_data {
  /* common */
  gboolean       go;                    /* TRUE as long as we're supposed to keep capturing */
  int            err;                   /* if non-zero, error seen while capturing */
  gint           packet_count;          /* Number of packets we have already captured */
  gint           packet_max;            /* Number of packets we're supposed to capture - 0 means infinite */

  /* pcap "input file" */
  pcap_t        *pcap_h;                /* pcap handle */
  gboolean       pcap_err;              /* TRUE if error from pcap */
#ifdef MUST_DO_SELECT
  int            pcap_fd;               /* pcap file descriptor */
#endif

  /* capture pipe (unix only "input file") */
  gboolean       from_cap_pipe;         /* TRUE if we are capturing data from a capture pipe */
  struct pcap_hdr cap_pipe_hdr;         /* Pcap header when capturing from a pipe */
  struct pcaprec_modified_hdr cap_pipe_rechdr;  /* Pcap record header when capturing from a pipe */
  int            cap_pipe_fd;           /* the file descriptor of the capture pipe */
  gboolean       cap_pipe_modified;     /* TRUE if data in the pipe uses modified pcap headers */
  gboolean       cap_pipe_byte_swapped; /* TRUE if data in the pipe is byte swapped */
  unsigned int   cap_pipe_bytes_to_read;/* Used by cap_pipe_dispatch */
  unsigned int   cap_pipe_bytes_read;   /* Used by cap_pipe_dispatch */
  enum {
         STATE_EXPECT_REC_HDR,
         STATE_READ_REC_HDR,
         STATE_EXPECT_DATA,
         STATE_READ_DATA
       } cap_pipe_state;
  enum { PIPOK, PIPEOF, PIPERR, PIPNEXIST } cap_pipe_err;

  /* output file */
  FILE          *pdh;
  int            linktype;
  int            file_snaplen;
  gint           wtap_linktype;
  long           bytes_written;

} loop_data;

/*
 * Standard secondary message for unexpected errors.
 */
static const char please_report[] =
    "Please report this to the Wireshark developers.\n"
    "(This is not a crash; please do not report it as such.)";

/*
 * This needs to be static, so that the SIGUSR1 handler can clear the "go"
 * flag.
 */
static loop_data   global_ld;


/*
 * Timeout, in milliseconds, for reads from the stream of captured packets.
 */
#define	CAP_READ_TIMEOUT	250
static char *cap_pipe_err_str;

static void
console_log_handler(const char *log_domain, GLogLevelFlags log_level,
		    const char *message, gpointer user_data _U_);

/* capture related options */
static capture_options global_capture_opts;

static void capture_loop_packet_cb(u_char *user, const struct pcap_pkthdr *phdr,
  const u_char *pd);
static void capture_loop_get_errmsg(char *errmsg, int errmsglen, const char *fname,
			  int err, gboolean is_close);


#if __GNUC__ >= 2
static void exit_main(int err) __attribute__ ((noreturn));
#else
static void exit_main(int err);
#endif

static void report_new_capture_file(const char *filename);
static void report_packet_count(int packet_count);
static void report_packet_drops(guint32 drops);
static void report_capture_error(const char *error_msg, const char *secondary_error_msg);
static void report_cfilter_error(const char *cfilter, const char *errmsg);

#ifdef _WIN32
static gboolean signal_pipe_check_running(void);
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
  fprintf(output, "  -i <interface>           name or idx of interface (def: first non-loopback)\n");
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
  fprintf(output, "  -n                       use pcapng format instead of pcap\n");
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
    gchar *msg;
    /* Generate a 'special format' message back to parent */
    va_start(ap, fmt);
    msg = g_strdup_vprintf(fmt, ap);
    sync_pipe_errmsg_to_parent(2, msg, "");
    g_free(msg);
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
    gchar *msg;
    va_start(ap, fmt);
    msg = g_strdup_vprintf(fmt, ap);
    sync_pipe_errmsg_to_parent(2, msg, "");
    g_free(msg);
    va_end(ap);
  } else {
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
  }
}

typedef struct {
    char *name;
    pcap_t *pch;
} if_stat_t;

/* Print the number of packets captured for each interface until we're killed. */
static int
print_statistics_loop(gboolean machine_readable)
{
    GList       *if_list, *if_entry, *stat_list = NULL, *stat_entry;
    if_info_t   *if_info;
    if_stat_t   *if_stat;
    int         err;
    gchar       *err_str;
    pcap_t      *pch;
    char        errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_stat ps;

    if_list = get_interface_list(&err, &err_str);
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
        return err;
    }

    for (if_entry = g_list_first(if_list); if_entry != NULL; if_entry = g_list_next(if_entry)) {
        if_info = if_entry->data;
#ifdef HAVE_PCAP_OPEN
        pch = pcap_open(if_info->name, MIN_PACKET_SIZE, 0, 0, NULL, errbuf);
#else
        pch = pcap_open_live(if_info->name, MIN_PACKET_SIZE, 0, 0, errbuf);
#endif

        if (pch) {
            if_stat = g_malloc(sizeof(if_stat_t));
            if_stat->name = g_strdup(if_info->name);
            if_stat->pch = pch;
            stat_list = g_list_append(stat_list, if_stat);
        }
    }

    if (!stat_list) {
        cmdarg_err("There are no interfaces on which a capture can be done");
        return 2;
    }

    if (!machine_readable) {
        printf("%-15s  %10s  %10s\n", "Interface", "Received",
            "Dropped");
    }

    global_ld.go = TRUE;
    while (global_ld.go) {
        for (stat_entry = g_list_first(stat_list); stat_entry != NULL; stat_entry = g_list_next(stat_entry)) {
            if_stat = stat_entry->data;
            pcap_stats(if_stat->pch, &ps);

            if (!machine_readable) {
                printf("%-15s  %10u  %10u\n", if_stat->name,
                    ps.ps_recv, ps.ps_drop);
            } else {
                printf("%s\t%u\t%u\n", if_stat->name,
                    ps.ps_recv, ps.ps_drop);
                fflush(stdout);
            }
        }
#ifdef _WIN32
        Sleep(1 * 1000);
#else
        sleep(1);
#endif
    }

    /* XXX - Not reached.  Should we look for 'q' in stdin? */
    for (stat_entry = g_list_first(stat_list); stat_entry != NULL; stat_entry = g_list_next(stat_entry)) {
        if_stat = stat_entry->data;
        pcap_close(if_stat->pch);
        g_free(if_stat->name);
        g_free(if_stat);
    }
    g_list_free(stat_list);
    free_interface_list(if_list);

    return 0;
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

static void exit_main(int status)
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
 * (See comment in main() for details)
 */

static void
#if 0 /* Set to enable capability debugging */
/* see 'man cap_to_text()' for explanation of output                         */
/* '='   means 'all= '  ie: no capabilities                                  */
/* '=ip' means 'all=ip' ie: all capabilities are permissible and inheritable */
/* ....                                                                      */
print_caps(char *pfx) {
    cap_t caps = cap_get_proc();
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
          "%s: EUID: %d  Capabilities: %s", pfx,
          geteuid(), cap_to_text(caps, NULL));
    cap_free(caps);
#else
print_caps(char *pfx _U_) {
#endif
}

static void
relinquish_privs_except_capture(void)
{
    /* If 'started_with_special_privs' (ie: suid) then enable for
     *  ourself the  NET_ADMIN and NET_RAW capabilities and then
     *  drop our suid privileges.
     *
     * CAP_NET_ADMIN: Promiscuous mode and a truckload of other
     *                stuff we don't need (and shouldn't have).
     * CAP_NET_RAW:   Packet capture (raw sockets).
     */

    if (started_with_special_privs()) {
        cap_value_t cap_list[2] = { CAP_NET_ADMIN, CAP_NET_RAW };
        int cl_len = sizeof(cap_list) / sizeof(cap_value_t);

        cap_t caps = cap_init();    /* all capabilities initialized to off */

        print_caps("Pre drop, pre set");

        if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
            cmdarg_err("prctl() fail return: %s", strerror(errno));
        }

        cap_set_flag(caps, CAP_PERMITTED,   cl_len, cap_list, CAP_SET);
        cap_set_flag(caps, CAP_INHERITABLE, cl_len, cap_list, CAP_SET);

        if (cap_set_proc(caps)) {
            cmdarg_err("cap_set_proc() fail return: %s", strerror(errno));
        }
        print_caps("Pre drop, post set");

        relinquish_special_privs_perm();

        print_caps("Post drop, pre set");
        cap_set_flag(caps, CAP_EFFECTIVE,   cl_len, cap_list, CAP_SET);
        if (cap_set_proc(caps)) {
            cmdarg_err("cap_set_proc() fail return: %s", strerror(errno));
        }
        print_caps("Post drop, post set");

        cap_free(caps);
    }
}


static void
relinquish_all_capabilities()
{
    /* Drop any and all capabilities this process may have.            */
    /* Allowed whether or not process has any privileges.              */
    cap_t caps = cap_init();    /* all capabilities initialized to off */
    print_caps("Pre-clear");
    if (cap_set_proc(caps)) {
        cmdarg_err("cap_set_proc() fail return: %s", strerror(errno));
    }
    print_caps("Post-clear");
    cap_free(caps);
}

#endif /* HAVE_LIBCAP */

/* Take care of byte order in the libpcap headers read from pipes.
 * (function taken from wiretap/libpcap.c) */
static void
cap_pipe_adjust_header(gboolean byte_swapped, struct pcap_hdr *hdr, struct pcaprec_hdr *rechdr)
{
  if (byte_swapped) {
    /* Byte-swap the record header fields. */
    rechdr->ts_sec = BSWAP32(rechdr->ts_sec);
    rechdr->ts_usec = BSWAP32(rechdr->ts_usec);
    rechdr->incl_len = BSWAP32(rechdr->incl_len);
    rechdr->orig_len = BSWAP32(rechdr->orig_len);
  }

  /* In file format version 2.3, the "incl_len" and "orig_len" fields were
     swapped, in order to match the BPF header layout.

     Unfortunately, some files were, according to a comment in the "libpcap"
     source, written with version 2.3 in their headers but without the
     interchanged fields, so if "incl_len" is greater than "orig_len" - which
     would make no sense - we assume that we need to swap them.  */
  if (hdr->version_major == 2 &&
      (hdr->version_minor < 3 ||
       (hdr->version_minor == 3 && rechdr->incl_len > rechdr->orig_len))) {
    guint32 temp;

    temp = rechdr->orig_len;
    rechdr->orig_len = rechdr->incl_len;
    rechdr->incl_len = temp;
  }
}

/* Provide select() functionality for a single file descriptor
 * on both UNIX/POSIX and Windows.
 *
 * The Windows version calls WaitForSingleObject instead of
 * select().
 *
 * Returns the same values as select.  If an error is returned,
 * the string cap_pipe_err_str should be used instead of errno.
 */
static int
cap_pipe_select(int pipe_fd) {
#ifndef _WIN32
  fd_set      rfds;
  struct timeval timeout, *pto;
  int sel_ret;

  cap_pipe_err_str = "Unknown error";

  FD_ZERO(&rfds);
  FD_SET(pipe_fd, &rfds);

  timeout.tv_sec = 0;
  timeout.tv_usec = CAP_READ_TIMEOUT * 1000;
  pto = &timeout;

  sel_ret = select(pipe_fd+1, &rfds, NULL, NULL, pto);
  if (sel_ret < 0)
    cap_pipe_err_str = strerror(errno);
  return sel_ret;
}
#else
  /* XXX - Should we just use file handles exclusively under Windows?
   * Otherwise we have to convert between file handles and file descriptors
   * here and when we open a named pipe.
   */
  HANDLE hPipe = (HANDLE) _get_osfhandle(pipe_fd);
  wchar_t *err_str;
  DWORD wait_ret;

  if (hPipe == INVALID_HANDLE_VALUE) {
    cap_pipe_err_str = "Could not open standard input";
    return -1;
  }

  cap_pipe_err_str = "Unknown error";

  wait_ret = WaitForSingleObject(hPipe, CAP_READ_TIMEOUT);
  switch (wait_ret) {
    /* XXX - This probably isn't correct */
    case WAIT_ABANDONED:
      errno = EINTR;
      return -1;
    case WAIT_OBJECT_0:
      return 1;
    case WAIT_TIMEOUT:
      return 0;
    case WAIT_FAILED:
      FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
        NULL, GetLastError(), 0, (LPTSTR) &err_str, 0, NULL);
      cap_pipe_err_str = utf_16to8(err_str);
      LocalFree(err_str);
      return -1;
    default:
      g_assert_not_reached();
      return -1;
  }
}
#endif


/* Mimic pcap_open_live() for pipe captures
 * We check if "pipename" is "-" (stdin) or a FIFO, open it, and read the
 * header.
 * N.B. : we can't read the libpcap formats used in RedHat 6.1 or SuSE 6.3
 * because we can't seek on pipes (see wiretap/libpcap.c for details) */
static int
cap_pipe_open_live(char *pipename, struct pcap_hdr *hdr, loop_data *ld,
                 char *errmsg, int errmsgl)
{
#ifndef _WIN32
  struct stat pipe_stat;
#else
#if 1
  char *pncopy, *pos;
  wchar_t *err_str;
#endif
  HANDLE hPipe = NULL;
#endif
  int          sel_ret;
  int          fd;
  int          b;
  guint32       magic;
  unsigned int bytes_read;

  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "cap_pipe_open_live: %s", pipename);

  /*
   * XXX (T)Wireshark blocks until we return
   */
  if (strcmp(pipename, "-") == 0) {
    fd = 0; /* read from stdin */
#ifdef _WIN32
    /*
     * This is needed to set the stdin pipe into binary mode, otherwise
     * CR/LF are mangled...
     */
    _setmode(0, _O_BINARY);
#endif  /* _WIN32 */
  } else {
#ifndef _WIN32
    if (ws_stat(pipename, &pipe_stat) < 0) {
      if (errno == ENOENT || errno == ENOTDIR)
        ld->cap_pipe_err = PIPNEXIST;
      else {
        g_snprintf(errmsg, errmsgl,
          "The capture session could not be initiated "
          "due to error on pipe: %s", strerror(errno));
        ld->cap_pipe_err = PIPERR;
      }
      return -1;
    }
    if (! S_ISFIFO(pipe_stat.st_mode)) {
      if (S_ISCHR(pipe_stat.st_mode)) {
        /*
         * Assume the user specified an interface on a system where
         * interfaces are in /dev.  Pretend we haven't seen it.
         */
         ld->cap_pipe_err = PIPNEXIST;
      } else
      {
        g_snprintf(errmsg, errmsgl,
            "The capture session could not be initiated because\n"
            "\"%s\" is neither an interface nor a pipe", pipename);
        ld->cap_pipe_err = PIPERR;
      }
      return -1;
    }
    fd = ws_open(pipename, O_RDONLY | O_NONBLOCK, 0000 /* no creation so don't matter */);
    if (fd == -1) {
      g_snprintf(errmsg, errmsgl,
          "The capture session could not be initiated "
          "due to error on pipe open: %s", strerror(errno));
      ld->cap_pipe_err = PIPERR;
      return -1;
    }
#else /* _WIN32 */
#define PIPE_STR "\\pipe\\"
    /* Under Windows, named pipes _must_ have the form
     * "\\<server>\pipe\<pipename>".  <server> may be "." for localhost.
     */
    pncopy = g_strdup(pipename);
    if ( (pos=strstr(pncopy, "\\\\")) == pncopy) {
      pos = strchr(pncopy + 3, '\\');
      if (pos && g_ascii_strncasecmp(pos, PIPE_STR, strlen(PIPE_STR)) != 0)
        pos = NULL;
    }

    g_free(pncopy);

    if (!pos) {
      g_snprintf(errmsg, errmsgl,
          "The capture session could not be initiated because\n"
          "\"%s\" is neither an interface nor a pipe", pipename);
      ld->cap_pipe_err = PIPNEXIST;
      return -1;
    }

    /* Wait for the pipe to appear */
    while (1) {
      hPipe = CreateFile(utf_8to16(pipename), GENERIC_READ, 0, NULL,
          OPEN_EXISTING, 0, NULL);

      if (hPipe != INVALID_HANDLE_VALUE)
        break;

      if (GetLastError() != ERROR_PIPE_BUSY) {
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
          NULL, GetLastError(), 0, (LPTSTR) &err_str, 0, NULL);
        g_snprintf(errmsg, errmsgl,
            "The capture session on \"%s\" could not be initiated "
            "due to error on pipe open: pipe busy: %s (error %d)",
	    pipename, utf_16to8(err_str), GetLastError());
        LocalFree(err_str);
        ld->cap_pipe_err = PIPERR;
        return -1;
      }

      if (!WaitNamedPipe(utf_8to16(pipename), 30 * 1000)) {
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
          NULL, GetLastError(), 0, (LPTSTR) &err_str, 0, NULL);
        g_snprintf(errmsg, errmsgl,
            "The capture session could not be initiated "
            "due to error on named pipe open: %s (error %d)",
	    utf_16to8(err_str), GetLastError());
        LocalFree(err_str);
        ld->cap_pipe_err = PIPERR;
        return -1;
      }
    }

    fd = _open_osfhandle((long) hPipe, _O_RDONLY);
    if (fd == -1) {
      g_snprintf(errmsg, errmsgl,
          "The capture session could not be initiated "
          "due to error on pipe open: %s", strerror(errno));
      ld->cap_pipe_err = PIPERR;
      return -1;
    }
#endif /* _WIN32 */
  }

  ld->from_cap_pipe = TRUE;

  /* read the pcap header */
  bytes_read = 0;
  while (bytes_read < sizeof magic) {
    sel_ret = cap_pipe_select(fd);
    if (sel_ret < 0) {
      g_snprintf(errmsg, errmsgl,
        "Unexpected error from select: %s", strerror(errno));
      goto error;
    } else if (sel_ret > 0) {
      b = read(fd, ((char *)&magic)+bytes_read, sizeof magic-bytes_read);
      if (b <= 0) {
        if (b == 0)
          g_snprintf(errmsg, errmsgl, "End of file on pipe during open");
        else
          g_snprintf(errmsg, errmsgl, "Error on pipe during open: %s",
            strerror(errno));
        goto error;
      }
      bytes_read += b;
    }
  }

  switch (magic) {
  case PCAP_MAGIC:
    /* Host that wrote it has our byte order, and was running
       a program using either standard or ss990417 libpcap. */
    ld->cap_pipe_byte_swapped = FALSE;
    ld->cap_pipe_modified = FALSE;
    break;
  case PCAP_MODIFIED_MAGIC:
    /* Host that wrote it has our byte order, but was running
       a program using either ss990915 or ss991029 libpcap. */
    ld->cap_pipe_byte_swapped = FALSE;
    ld->cap_pipe_modified = TRUE;
    break;
  case PCAP_SWAPPED_MAGIC:
    /* Host that wrote it has a byte order opposite to ours,
       and was running a program using either standard or
       ss990417 libpcap. */
    ld->cap_pipe_byte_swapped = TRUE;
    ld->cap_pipe_modified = FALSE;
    break;
  case PCAP_SWAPPED_MODIFIED_MAGIC:
    /* Host that wrote it out has a byte order opposite to
       ours, and was running a program using either ss990915
       or ss991029 libpcap. */
    ld->cap_pipe_byte_swapped = TRUE;
    ld->cap_pipe_modified = TRUE;
    break;
  default:
    /* Not a "libpcap" type we know about. */
    g_snprintf(errmsg, errmsgl, "Unrecognized libpcap format");
    goto error;
  }

  /* Read the rest of the header */
  bytes_read = 0;
  while (bytes_read < sizeof(struct pcap_hdr)) {
    sel_ret = cap_pipe_select(fd);
    if (sel_ret < 0) {
      g_snprintf(errmsg, errmsgl,
        "Unexpected error from select: %s", strerror(errno));
      goto error;
    } else if (sel_ret > 0) {
      b = read(fd, ((char *)hdr)+bytes_read,
            sizeof(struct pcap_hdr) - bytes_read);
      if (b <= 0) {
        if (b == 0)
          g_snprintf(errmsg, errmsgl, "End of file on pipe during open");
        else
          g_snprintf(errmsg, errmsgl, "Error on pipe during open: %s",
            strerror(errno));
        goto error;
      }
      bytes_read += b;
    }
  }

  if (ld->cap_pipe_byte_swapped) {
    /* Byte-swap the header fields about which we care. */
    hdr->version_major = BSWAP16(hdr->version_major);
    hdr->version_minor = BSWAP16(hdr->version_minor);
    hdr->snaplen = BSWAP32(hdr->snaplen);
    hdr->network = BSWAP32(hdr->network);
  }
  ld->linktype = hdr->network;

  if (hdr->version_major < 2) {
    g_snprintf(errmsg, errmsgl, "Unable to read old libpcap format");
    goto error;
  }

  ld->cap_pipe_state = STATE_EXPECT_REC_HDR;
  ld->cap_pipe_err = PIPOK;
  return fd;

error:
  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "cap_pipe_open_live: error %s", errmsg);
  ld->cap_pipe_err = PIPERR;
  ws_close(fd);
  return -1;

}


/* We read one record from the pipe, take care of byte order in the record
 * header, write the record to the capture file, and update capture statistics. */
static int
cap_pipe_dispatch(loop_data *ld, guchar *data, char *errmsg, int errmsgl)
{
  struct pcap_pkthdr phdr;
  int b;
  enum { PD_REC_HDR_READ, PD_DATA_READ, PD_PIPE_EOF, PD_PIPE_ERR,
          PD_ERR } result;


#ifdef LOG_CAPTURE_VERBOSE
  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "cap_pipe_dispatch");
#endif

  switch (ld->cap_pipe_state) {

  case STATE_EXPECT_REC_HDR:
    ld->cap_pipe_bytes_to_read = ld->cap_pipe_modified ?
      sizeof(struct pcaprec_modified_hdr) : sizeof(struct pcaprec_hdr);
    ld->cap_pipe_bytes_read = 0;
    ld->cap_pipe_state = STATE_READ_REC_HDR;
    /* Fall through */

  case STATE_READ_REC_HDR:
    b = read(ld->cap_pipe_fd, ((char *)&ld->cap_pipe_rechdr)+ld->cap_pipe_bytes_read,
             ld->cap_pipe_bytes_to_read - ld->cap_pipe_bytes_read);
    if (b <= 0) {
      if (b == 0)
        result = PD_PIPE_EOF;
      else
        result = PD_PIPE_ERR;
      break;
    }
    if ((ld->cap_pipe_bytes_read += b) < ld->cap_pipe_bytes_to_read)
        return 0;
    result = PD_REC_HDR_READ;
    break;

  case STATE_EXPECT_DATA:
    ld->cap_pipe_bytes_read = 0;
    ld->cap_pipe_state = STATE_READ_DATA;
    /* Fall through */

  case STATE_READ_DATA:
    b = read(ld->cap_pipe_fd, data+ld->cap_pipe_bytes_read,
             ld->cap_pipe_rechdr.hdr.incl_len - ld->cap_pipe_bytes_read);
    if (b <= 0) {
      if (b == 0)
        result = PD_PIPE_EOF;
      else
        result = PD_PIPE_ERR;
      break;
    }
    if ((ld->cap_pipe_bytes_read += b) < ld->cap_pipe_rechdr.hdr.incl_len)
      return 0;
    result = PD_DATA_READ;
    break;

  default:
    g_snprintf(errmsg, errmsgl, "cap_pipe_dispatch: invalid state");
    result = PD_ERR;

  } /* switch (ld->cap_pipe_state) */

  /*
   * We've now read as much data as we were expecting, so process it.
   */
  switch (result) {

  case PD_REC_HDR_READ:
    /* We've read the header. Take care of byte order. */
    cap_pipe_adjust_header(ld->cap_pipe_byte_swapped, &ld->cap_pipe_hdr,
                           &ld->cap_pipe_rechdr.hdr);
    if (ld->cap_pipe_rechdr.hdr.incl_len > WTAP_MAX_PACKET_SIZE) {
      g_snprintf(errmsg, errmsgl, "Frame %u too long (%d bytes)",
        ld->packet_count+1, ld->cap_pipe_rechdr.hdr.incl_len);
      break;
    }
    ld->cap_pipe_state = STATE_EXPECT_DATA;
    return 0;

  case PD_DATA_READ:
    /* Fill in a "struct pcap_pkthdr", and process the packet. */
    phdr.ts.tv_sec = ld->cap_pipe_rechdr.hdr.ts_sec;
    phdr.ts.tv_usec = ld->cap_pipe_rechdr.hdr.ts_usec;
    phdr.caplen = ld->cap_pipe_rechdr.hdr.incl_len;
    phdr.len = ld->cap_pipe_rechdr.hdr.orig_len;

    capture_loop_packet_cb((u_char *)ld, &phdr, data);

    ld->cap_pipe_state = STATE_EXPECT_REC_HDR;
    return 1;

  case PD_PIPE_EOF:
    ld->cap_pipe_err = PIPEOF;
    return -1;

  case PD_PIPE_ERR:
    g_snprintf(errmsg, errmsgl, "Error reading from pipe: %s",
      strerror(errno));
    /* Fall through */
  case PD_ERR:
    break;
  }

  ld->cap_pipe_err = PIPERR;
  /* Return here rather than inside the switch to prevent GCC warning */
  return -1;
}


/** Open the capture input file (pcap or capture pipe).
 *  Returns TRUE if it succeeds, FALSE otherwise. */
static gboolean
capture_loop_open_input(capture_options *capture_opts, loop_data *ld,
                        char *errmsg, size_t errmsg_len,
                        char *secondary_errmsg, size_t secondary_errmsg_len)
{
  gchar       open_err_str[PCAP_ERRBUF_SIZE];
  gchar      *sync_msg_str;
  static const char ppamsg[] = "can't find PPA for ";
  const char *set_linktype_err_str;
  const char  *libpcap_warn;
#ifdef _WIN32
  gchar      *sync_secondary_msg_str;
  int         err;
  WORD        wVersionRequested;
  WSADATA     wsaData;
#endif
#ifdef HAVE_PCAP_REMOTE
  struct pcap_rmtauth auth;
#endif


  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_open_input : %s", capture_opts->iface);


/* XXX - opening Winsock on tshark? */

  /* Initialize Windows Socket if we are in a WIN32 OS
     This needs to be done before querying the interface for network/netmask */
#ifdef _WIN32
  /* XXX - do we really require 1.1 or earlier?
     Are there any versions that support only 2.0 or higher? */
  wVersionRequested = MAKEWORD(1, 1);
  err = WSAStartup(wVersionRequested, &wsaData);
  if (err != 0) {
    switch (err) {

    case WSASYSNOTREADY:
      g_snprintf(errmsg, (gulong) errmsg_len,
        "Couldn't initialize Windows Sockets: Network system not ready for network communication");
      break;

    case WSAVERNOTSUPPORTED:
      g_snprintf(errmsg, (gulong) errmsg_len,
        "Couldn't initialize Windows Sockets: Windows Sockets version %u.%u not supported",
        LOBYTE(wVersionRequested), HIBYTE(wVersionRequested));
      break;

    case WSAEINPROGRESS:
      g_snprintf(errmsg, (gulong) errmsg_len,
        "Couldn't initialize Windows Sockets: Blocking operation is in progress");
      break;

    case WSAEPROCLIM:
      g_snprintf(errmsg, (gulong) errmsg_len,
        "Couldn't initialize Windows Sockets: Limit on the number of tasks supported by this WinSock implementation has been reached");
      break;

    case WSAEFAULT:
      g_snprintf(errmsg, (gulong) errmsg_len,
        "Couldn't initialize Windows Sockets: Bad pointer passed to WSAStartup");
      break;

    default:
      g_snprintf(errmsg, (gulong) errmsg_len,
        "Couldn't initialize Windows Sockets: error %d", err);
      break;
    }
    g_snprintf(secondary_errmsg, (gulong) secondary_errmsg_len, please_report);
    return FALSE;
  }
#endif

  /* Open the network interface to capture from it.
     Some versions of libpcap may put warnings into the error buffer
     if they succeed; to tell if that's happened, we have to clear
     the error buffer, and check if it's still a null string.  */
  open_err_str[0] = '\0';
#ifdef HAVE_PCAP_OPEN
  auth.type = capture_opts->auth_type == CAPTURE_AUTH_PWD ?
                    RPCAP_RMTAUTH_PWD : RPCAP_RMTAUTH_NULL;
  auth.username = capture_opts->auth_username;
  auth.password = capture_opts->auth_password;

  ld->pcap_h = pcap_open(capture_opts->iface,
               capture_opts->has_snaplen ? capture_opts->snaplen :
                          WTAP_MAX_PACKET_SIZE,
               /* flags */
               (capture_opts->promisc_mode ? PCAP_OPENFLAG_PROMISCUOUS : 0) |
               (capture_opts->datatx_udp ? PCAP_OPENFLAG_DATATX_UDP : 0) |
               (capture_opts->nocap_rpcap ? PCAP_OPENFLAG_NOCAPTURE_RPCAP : 0),
               CAP_READ_TIMEOUT, &auth, open_err_str);
#else
  ld->pcap_h = pcap_open_live(capture_opts->iface,
		       capture_opts->has_snaplen ? capture_opts->snaplen :
						  WTAP_MAX_PACKET_SIZE,
		       capture_opts->promisc_mode, CAP_READ_TIMEOUT,
		       open_err_str);
#endif

/* If not using libcap: we now can now set euid/egid to ruid/rgid         */
/*  to remove any suid privileges.                                        */
/* If using libcap: we can now remove NET_RAW and NET_ADMIN capabilities  */
/*  (euid/egid have already previously been set to ruid/rgid.             */
/* (See comment in main() for details)                                    */
#ifndef HAVE_LIBCAP
  relinquish_special_privs_perm();
#else
  relinquish_all_capabilities();
#endif

  if (ld->pcap_h != NULL) {
    /* we've opened "iface" as a network device */
#ifdef _WIN32
    /* try to set the capture buffer size */
    if (capture_opts->buffer_size > 1 &&
	pcap_setbuff(ld->pcap_h, capture_opts->buffer_size * 1024 * 1024) != 0) {
        sync_secondary_msg_str = g_strdup_printf(
          "The capture buffer size of %luMB seems to be too high for your machine,\n"
          "the default of 1MB will be used.\n"
          "\n"
          "Nonetheless, the capture is started.\n",
          capture_opts->buffer_size);
        report_capture_error("Couldn't set the capture buffer size!",
                                   sync_secondary_msg_str);
        g_free(sync_secondary_msg_str);
    }
#endif

#if defined(HAVE_PCAP_REMOTE) && defined(HAVE_PCAP_SETSAMPLING)
    if (capture_opts->sampling_method != CAPTURE_SAMP_NONE)
    {
        struct pcap_samp *samp;

        if ((samp = pcap_setsampling(ld->pcap_h)) != NULL)
        {
            switch (capture_opts->sampling_method)
            {
                case CAPTURE_SAMP_BY_COUNT:
                    samp->method = PCAP_SAMP_1_EVERY_N;
                    break;

                case CAPTURE_SAMP_BY_TIMER:
                    samp->method = PCAP_SAMP_FIRST_AFTER_N_MS;
                    break;

                default:
                    sync_msg_str = g_strdup_printf(
                            "Unknown sampling method %d specified,\n"
                            "continue without packet sampling",
                            capture_opts->sampling_method);
                    report_capture_error("Couldn't set the capture "
                            "sampling", sync_msg_str);
                    g_free(sync_msg_str);
            }
            samp->value = capture_opts->sampling_param;
        }
        else
        {
            report_capture_error("Couldn't set the capture sampling",
                    "Cannot get packet sampling data structure");
        }

    }
#endif

    /* setting the data link type only works on real interfaces */
    if (capture_opts->linktype != -1) {
      set_linktype_err_str = set_pcap_linktype(ld->pcap_h, capture_opts->iface,
	capture_opts->linktype);
      if (set_linktype_err_str != NULL) {
	g_snprintf(errmsg, (gulong) errmsg_len, "Unable to set data link type (%s).",
	           set_linktype_err_str);
        g_snprintf(secondary_errmsg, (gulong) secondary_errmsg_len, please_report);
	return FALSE;
      }
    }
    ld->linktype = get_pcap_linktype(ld->pcap_h, capture_opts->iface);
  } else {
    /* We couldn't open "iface" as a network device. */
    /* Try to open it as a pipe */
    ld->cap_pipe_fd = cap_pipe_open_live(capture_opts->iface, &ld->cap_pipe_hdr, ld, errmsg, (int) errmsg_len);

    if (ld->cap_pipe_fd == -1) {

      if (ld->cap_pipe_err == PIPNEXIST) {
	/* Pipe doesn't exist, so output message for interface */

	/* If we got a "can't find PPA for X" message, warn the user (who
	   is running (T)Wireshark on HP-UX) that they don't have a version
	   of libpcap that properly handles HP-UX (libpcap 0.6.x and later
	   versions, which properly handle HP-UX, say "can't find /dev/dlpi
	   PPA for X" rather than "can't find PPA for X"). */
	if (strncmp(open_err_str, ppamsg, sizeof ppamsg - 1) == 0)
	  libpcap_warn =
	    "\n\n"
	    "You are running (T)Wireshark with a version of the libpcap library\n"
	    "that doesn't handle HP-UX network devices well; this means that\n"
	    "(T)Wireshark may not be able to capture packets.\n"
	    "\n"
	    "To fix this, you should install libpcap 0.6.2, or a later version\n"
	    "of libpcap, rather than libpcap 0.4 or 0.5.x.  It is available in\n"
	    "packaged binary form from the Software Porting And Archive Centre\n"
	    "for HP-UX; the Centre is at http://hpux.connect.org.uk/ - the page\n"
	    "at the URL lists a number of mirror sites.";
	else
	  libpcap_warn = "";
	g_snprintf(errmsg, (gulong) errmsg_len,
	  "The capture session could not be initiated (%s).", open_err_str);
#ifndef _WIN32
	g_snprintf(secondary_errmsg, (gulong) secondary_errmsg_len,
"Please check to make sure you have sufficient permissions, and that you have "
"the proper interface or pipe specified.%s", libpcap_warn);
#else
    g_snprintf(secondary_errmsg, (gulong) secondary_errmsg_len,
"\n"
"Please check that \"%s\" is the proper interface.\n"
"\n"
"\n"
"Help can be found at:\n"
"\n"
"       http://wiki.wireshark.org/WinPcap\n"
"       http://wiki.wireshark.org/CaptureSetup\n",
    capture_opts->iface);
#endif /* _WIN32 */
      }
      /*
       * Else pipe (or file) does exist and cap_pipe_open_live() has
       * filled in errmsg
       */
      return FALSE;
    } else
      /* cap_pipe_open_live() succeeded; don't want
         error message from pcap_open_live() */
      open_err_str[0] = '\0';
  }

/* XXX - will this work for tshark? */
#ifdef MUST_DO_SELECT
  if (!ld->from_cap_pipe) {
#ifdef HAVE_PCAP_GET_SELECTABLE_FD
    ld->pcap_fd = pcap_get_selectable_fd(ld->pcap_h);
#else
    ld->pcap_fd = pcap_fileno(ld->pcap_h);
#endif
  }
#endif

  /* Does "open_err_str" contain a non-empty string?  If so, "pcap_open_live()"
     returned a warning; print it, but keep capturing. */
  if (open_err_str[0] != '\0') {
    sync_msg_str = g_strdup_printf("%s.", open_err_str);
    report_capture_error(sync_msg_str, "");
    g_free(sync_msg_str);
  }

  return TRUE;
}


/* close the capture input file (pcap or capture pipe) */
static void capture_loop_close_input(loop_data *ld) {

  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_close_input");

  /* if open, close the capture pipe "input file" */
  if (ld->cap_pipe_fd >= 0) {
    g_assert(ld->from_cap_pipe);
    ws_close(ld->cap_pipe_fd);
    ld->cap_pipe_fd = 0;
  }

  /* if open, close the pcap "input file" */
  if(ld->pcap_h != NULL) {
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_close_input: closing %p", ld->pcap_h);
    g_assert(!ld->from_cap_pipe);
    pcap_close(ld->pcap_h);
    ld->pcap_h = NULL;
  }

  ld->go = FALSE;

#ifdef _WIN32
  /* Shut down windows sockets */
  WSACleanup();
#endif
}


/* init the capture filter */
static initfilter_status_t
capture_loop_init_filter(pcap_t *pcap_h, gboolean from_cap_pipe, gchar * iface, gchar * cfilter) {
  bpf_u_int32 netnum, netmask;
  gchar       lookup_net_err_str[PCAP_ERRBUF_SIZE];
  struct bpf_program fcode;


  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_init_filter: %s", cfilter);

  /* capture filters only work on real interfaces */
  if (cfilter && !from_cap_pipe) {
    /* A capture filter was specified; set it up. */
    if (pcap_lookupnet(iface, &netnum, &netmask, lookup_net_err_str) < 0) {
      /*
       * Well, we can't get the netmask for this interface; it's used
       * only for filters that check for broadcast IP addresses, so
       * we just punt and use 0.  It might be nice to warn the user,
       * but that's a pain in a GUI application, as it'd involve popping
       * up a message box, and it's not clear how often this would make
       * a difference (only filters that check for IP broadcast addresses
       * use the netmask).
       */
      /*cmdarg_err(
        "Warning:  Couldn't obtain netmask info (%s).", lookup_net_err_str);*/
      netmask = 0;
    }
    if (pcap_compile(pcap_h, &fcode, cfilter, 1, netmask) < 0) {
      /* Treat this specially - our caller might try to compile this
         as a display filter and, if that succeeds, warn the user that
         the display and capture filter syntaxes are different. */
      return INITFILTER_BAD_FILTER;
    }
    if (pcap_setfilter(pcap_h, &fcode) < 0) {
#ifdef HAVE_PCAP_FREECODE
      pcap_freecode(&fcode);
#endif
      return INITFILTER_OTHER_ERROR;
    }
#ifdef HAVE_PCAP_FREECODE
    pcap_freecode(&fcode);
#endif
  }

  return INITFILTER_NO_ERROR;
}


/* set up to write to the already-opened capture output file/files */
static gboolean
capture_loop_init_output(capture_options *capture_opts, int save_file_fd, loop_data *ld, char *errmsg, int errmsg_len) {
  int         err;


  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_init_output");

  /* get snaplen */
  if (ld->from_cap_pipe) {
    ld->file_snaplen = ld->cap_pipe_hdr.snaplen;
  } else
  {
    ld->file_snaplen = pcap_snapshot(ld->pcap_h);
  }

  /* Set up to write to the capture file. */
  if (capture_opts->multi_files_on) {
    ld->pdh = ringbuf_init_libpcap_fdopen(&err);
  } else {
    ld->pdh = libpcap_fdopen(save_file_fd, &err);
  }
  if (ld->pdh) {
    gboolean successful;
    
    ld->bytes_written = 0;
    if (capture_opts->use_pcapng) {
      char appname[100];

      g_snprintf(appname, sizeof(appname), "Dumpcap " VERSION "%s", wireshark_svnversion);
      successful = libpcap_write_session_header_block(ld->pdh, appname, &ld->bytes_written, &err) &&
                   libpcap_write_interface_description_block(ld->pdh, capture_opts->iface, capture_opts->cfilter, ld->linktype, ld->file_snaplen, &ld->bytes_written, &err);
    } else {
      successful = libpcap_write_file_header(ld->pdh, ld->linktype, ld->file_snaplen,
                                             &ld->bytes_written, &err);
    }
    if (!successful) {
      fclose(ld->pdh);
      ld->pdh = NULL;
    }
  }

  if (ld->pdh == NULL) {
    /* We couldn't set up to write to the capture file. */
    /* XXX - use cf_open_error_message from tshark instead? */
    switch (err) {

    case WTAP_ERR_CANT_OPEN:
      g_snprintf(errmsg, errmsg_len, "The file to which the capture would be saved"
               " couldn't be created for some unknown reason.");
      break;

    case WTAP_ERR_SHORT_WRITE:
      g_snprintf(errmsg, errmsg_len, "A full header couldn't be written to the file"
               " to which the capture would be saved.");
      break;

    default:
      if (err < 0) {
        g_snprintf(errmsg, errmsg_len,
		     "The file to which the capture would be"
                     " saved (\"%s\") could not be opened: Error %d.",
 			capture_opts->save_file, err);
      } else {
        g_snprintf(errmsg, errmsg_len,
		     "The file to which the capture would be"
                     " saved (\"%s\") could not be opened: %s.",
 			capture_opts->save_file, strerror(err));
      }
      break;
    }

    return FALSE;
  }

  return TRUE;
}

static gboolean
capture_loop_close_output(capture_options *capture_opts, loop_data *ld, int *err_close) {

  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_close_output");

  if (capture_opts->multi_files_on) {
    return ringbuf_libpcap_dump_close(&capture_opts->save_file, err_close);
  } else {
    if (capture_opts->use_pcapng) {
      libpcap_write_interface_statistics_block(ld->pdh, 0, ld->pcap_h, &ld->bytes_written, err_close);
    }
    return libpcap_dump_close(ld->pdh, err_close);
  }
}

/* dispatch incoming packets (pcap or capture pipe)
 *
 * Waits for incoming packets to be available, and calls pcap_dispatch()
 * to cause them to be processed.
 *
 * Returns the number of packets which were processed.
 *
 * Times out (returning zero) after CAP_READ_TIMEOUT ms; this ensures that the
 * packet-batching behaviour does not cause packets to get held back
 * indefinitely.
 */
static int
capture_loop_dispatch(capture_options *capture_opts _U_, loop_data *ld,
		      char *errmsg, int errmsg_len)
{
  int       inpkts;
  int       sel_ret;
  gint      packet_count_before;
  guchar    pcap_data[WTAP_MAX_PACKET_SIZE];

  packet_count_before = ld->packet_count;
  if (ld->from_cap_pipe) {
    /* dispatch from capture pipe */
#ifdef LOG_CAPTURE_VERBOSE
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_dispatch: from capture pipe");
#endif
    sel_ret = cap_pipe_select(ld->cap_pipe_fd);
    if (sel_ret <= 0) {
      inpkts = 0;
      if (sel_ret < 0 && errno != EINTR) {
        g_snprintf(errmsg, errmsg_len,
          "Unexpected error from select: %s", strerror(errno));
        report_capture_error(errmsg, please_report);
        ld->go = FALSE;
      }
    } else {
      /*
       * "select()" says we can read from the pipe without blocking
       */
      inpkts = cap_pipe_dispatch(ld, pcap_data, errmsg, errmsg_len);
      if (inpkts < 0) {
        ld->go = FALSE;
      }
    }
  }
  else
  {
    /* dispatch from pcap */
#ifdef MUST_DO_SELECT
    /*
     * If we have "pcap_get_selectable_fd()", we use it to get the
     * descriptor on which to select; if that's -1, it means there
     * is no descriptor on which you can do a "select()" (perhaps
     * because you're capturing on a special device, and that device's
     * driver unfortunately doesn't support "select()", in which case
     * we don't do the select - which means it might not be possible
     * to stop a capture until a packet arrives.  If that's unacceptable,
     * plead with whoever supplies the software for that device to add
     * "select()" support, or upgrade to libpcap 0.8.1 or later, and
     * rebuild Wireshark or get a version built with libpcap 0.8.1 or
     * later, so it can use pcap_breakloop().
     */
#ifdef LOG_CAPTURE_VERBOSE
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_dispatch: from pcap_dispatch with select");
#endif
    if (ld->pcap_fd != -1) {
      sel_ret = cap_pipe_select(ld->pcap_fd);
      if (sel_ret > 0) {
        /*
         * "select()" says we can read from it without blocking; go for
         * it.
         *
         * We don't have pcap_breakloop(), so we only process one packet
         * per pcap_dispatch() call, to allow a signal to stop the
         * processing immediately, rather than processing all packets
         * in a batch before quitting.
         */
        inpkts = pcap_dispatch(ld->pcap_h, 1, capture_loop_packet_cb,
                               (u_char *)ld);
        if (inpkts < 0) {
            if (inpkts == -1) {
                /* Error, rather than pcap_breakloop(). */
                ld->pcap_err = TRUE;
            }
          ld->go = FALSE; /* error or pcap_breakloop() - stop capturing */
        }
      } else {
        if (sel_ret < 0 && errno != EINTR) {
          g_snprintf(errmsg, errmsg_len,
            "Unexpected error from select: %s", strerror(errno));
          report_capture_error(errmsg, please_report);
          ld->go = FALSE;
        }
      }
    }
    else
#endif /* MUST_DO_SELECT */
    {
      /* dispatch from pcap without select */
#if 1
#ifdef LOG_CAPTURE_VERBOSE
      g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_dispatch: from pcap_dispatch");
#endif
#ifdef _WIN32
      /*
       * On Windows, we don't support asynchronously telling a process to
       * stop capturing; instead, we check for an indication on a pipe
       * after processing packets.  We therefore process only one packet
       * at a time, so that we can check the pipe after every packet.
       */
      inpkts = pcap_dispatch(ld->pcap_h, 1, capture_loop_packet_cb, (u_char *) ld);
#else
      inpkts = pcap_dispatch(ld->pcap_h, -1, capture_loop_packet_cb, (u_char *) ld);
#endif
      if (inpkts < 0) {
        if (inpkts == -1) {
          /* Error, rather than pcap_breakloop(). */
          ld->pcap_err = TRUE;
        }
        ld->go = FALSE; /* error or pcap_breakloop() - stop capturing */
      }
#else /* pcap_next_ex */
#ifdef LOG_CAPTURE_VERBOSE
      g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_dispatch: from pcap_next_ex");
#endif
      /* XXX - this is currently unused, as there is some confusion with pcap_next_ex() vs. pcap_dispatch() */

      /*
       * WinPcap's remote capturing feature doesn't work with pcap_dispatch(),
       * see http://wiki.wireshark.org/CaptureSetup_2fWinPcapRemote
       * This should be fixed in the WinPcap 4.0 alpha release.
       *
       * For reference, an example remote interface:
       * rpcap://[1.2.3.4]/\Device\NPF_{39993D68-7C9B-4439-A329-F2D888DA7C5C}
       */

      /* emulate dispatch from pcap */
      {
        int in;
        struct pcap_pkthdr *pkt_header;
        u_char *pkt_data;

        in = 0;
        while(ld->go &&
              (in = pcap_next_ex(ld->pcap_h, &pkt_header, &pkt_data)) == 1)
          capture_loop_packet_cb( (u_char *) ld, pkt_header, pkt_data);

        if(in < 0) {
          ld->pcap_err = TRUE;
          ld->go = FALSE;
        }
      }
#endif /* pcap_next_ex */
    }
  }

#ifdef LOG_CAPTURE_VERBOSE
  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_dispatch: %d new packet%s", inpkts, plurality(inpkts, "", "s"));
#endif

  return ld->packet_count - packet_count_before;
}


/* open the output file (temporary/specified name/ringbuffer/named pipe/stdout) */
/* Returns TRUE if the file opened successfully, FALSE otherwise. */
static gboolean
capture_loop_open_output(capture_options *capture_opts, int *save_file_fd,
		      char *errmsg, int errmsg_len) {

  char *tmpname;
  gchar *capfile_name;
  gboolean is_tempfile;
#ifndef _WIN32
  int ret;
#endif

  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_open_output: %s",
      (capture_opts->save_file) ? capture_opts->save_file : "");

  if (capture_opts->save_file != NULL) {
    /* We return to the caller while the capture is in progress.
     * Therefore we need to take a copy of save_file in
     * case the caller destroys it after we return.
     */
    capfile_name = g_strdup(capture_opts->save_file);

    if (capture_opts->output_to_pipe == TRUE) { /* either "-" or named pipe */
      if (capture_opts->multi_files_on) {
        /* ringbuffer is enabled; that doesn't work with standard output or a named pipe */
        g_snprintf(errmsg, errmsg_len,
	    "Ring buffer requested, but capture is being written to standard output or to a named pipe.");
        g_free(capfile_name);
        return FALSE;
      }
      if (strcmp(capfile_name, "-") == 0) {
        /* write to stdout */
        *save_file_fd = 1;
#ifdef _WIN32
        /* set output pipe to binary mode to avoid Windows text-mode processing (eg: for CR/LF)  */
        _setmode(1, O_BINARY);
#endif
      }
    } /* if (...output_to_pipe ... */

    else {
      if (capture_opts->multi_files_on) {
        /* ringbuffer is enabled */
        *save_file_fd = ringbuf_init(capfile_name,
            (capture_opts->has_ring_num_files) ? capture_opts->ring_num_files : 0);

        /* we need the ringbuf name */
        if(*save_file_fd != -1) {
            g_free(capfile_name);
            capfile_name = g_strdup(ringbuf_current_filename());
        }
      } else {
        /* Try to open/create the specified file for use as a capture buffer. */
        *save_file_fd = ws_open(capfile_name, O_RDWR|O_BINARY|O_TRUNC|O_CREAT,
                             0600);
      }
    }
    is_tempfile = FALSE;
  } else {
    /* Choose a random name for the temporary capture buffer */
    *save_file_fd = create_tempfile(&tmpname, "wireshark");
    capfile_name = g_strdup(tmpname);
    is_tempfile = TRUE;
  }

  /* did we fail to open the output file? */
  if (*save_file_fd == -1) {
    if (is_tempfile) {
      g_snprintf(errmsg, errmsg_len,
	"The temporary file to which the capture would be saved (\"%s\") "
	"could not be opened: %s.", capfile_name, strerror(errno));
    } else {
      if (capture_opts->multi_files_on) {
        ringbuf_error_cleanup();
      }

      g_snprintf(errmsg, errmsg_len,
	    "The file to which the capture would be saved (\"%s\") "
        "could not be opened: %s.", capfile_name,
        strerror(errno));
    }
    g_free(capfile_name);
    return FALSE;
  }

  if(capture_opts->save_file != NULL) {
    g_free(capture_opts->save_file);
  }
  capture_opts->save_file = capfile_name;
  /* capture_opts.save_file is "g_free"ed later, which is equivalent to
     "g_free(capfile_name)". */
#ifndef _WIN32
  ret = fchown(*save_file_fd, capture_opts->owner, capture_opts->group);
#endif

  return TRUE;
}


static void
capture_loop_stop_signal_handler(int signo _U_)
{
  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Signal: Stop capture");
  capture_loop_stop();
}

#ifdef _WIN32
#define TIME_GET() GetTickCount()
#else
#define TIME_GET() time(NULL)
#endif

/* Do the low-level work of a capture.
   Returns TRUE if it succeeds, FALSE otherwise. */
static gboolean
capture_loop_start(capture_options *capture_opts, gboolean *stats_known, struct pcap_stat *stats)
{
#ifndef _WIN32
  struct sigaction act;
#endif
  time_t      upd_time, cur_time;
  time_t      start_time;
  int         err_close;
  int         inpkts;
  gint        inpkts_to_sync_pipe = 0;     /* packets not already send out to the sync_pipe */
  condition  *cnd_file_duration = NULL;
  condition  *cnd_autostop_files = NULL;
  condition  *cnd_autostop_size = NULL;
  condition  *cnd_autostop_duration = NULL;
  guint32     autostop_files = 0;
  gboolean    write_ok;
  gboolean    close_ok;
  gboolean    cfilter_error = FALSE;
#define MSG_MAX_LENGTH 4096
  char        errmsg[MSG_MAX_LENGTH+1];
  char        secondary_errmsg[MSG_MAX_LENGTH+1];
  int         save_file_fd = -1;

  *errmsg           = '\0';
  *secondary_errmsg = '\0';

  /* init the loop data */
  global_ld.go                 = TRUE;
  global_ld.packet_count       = 0;
  if (capture_opts->has_autostop_packets)
    global_ld.packet_max       = capture_opts->autostop_packets;
  else
    global_ld.packet_max       = 0;	/* no limit */
  global_ld.err                = 0;	/* no error seen yet */
  global_ld.wtap_linktype      = WTAP_ENCAP_UNKNOWN;
  global_ld.pcap_err           = FALSE;
  global_ld.from_cap_pipe      = FALSE;
  global_ld.pdh                = NULL;
  global_ld.cap_pipe_fd        = -1;
#ifdef MUST_DO_SELECT
  global_ld.pcap_fd            = 0;
#endif

  /* We haven't yet gotten the capture statistics. */
  *stats_known      = FALSE;

#ifndef _WIN32
  /*
   * Catch SIGUSR1, so that we exit cleanly if the parent process
   * kills us with it due to the user selecting "Capture->Stop".
   */
  act.sa_handler = capture_loop_stop_signal_handler;
  /*
   * Arrange that system calls not get restarted, because when
   * our signal handler returns we don't want to restart
   * a call that was waiting for packets to arrive.
   */
  act.sa_flags = 0;
  sigemptyset(&act.sa_mask);
  sigaction(SIGUSR1, &act, NULL);
#endif /* _WIN32 */

  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Capture loop starting ...");
  capture_opts_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, capture_opts);

  /* open the "input file" from network interface or capture pipe */
  if (!capture_loop_open_input(capture_opts, &global_ld, errmsg, sizeof(errmsg),
                               secondary_errmsg, sizeof(secondary_errmsg))) {
    goto error;
  }

  /* init the input filter from the network interface (capture pipe will do nothing) */
  switch (capture_loop_init_filter(global_ld.pcap_h, global_ld.from_cap_pipe,
                                   capture_opts->iface,
				   capture_opts->cfilter)) {

  case INITFILTER_NO_ERROR:
    break;

  case INITFILTER_BAD_FILTER:
    cfilter_error = TRUE;
    g_snprintf(errmsg, sizeof(errmsg), "%s", pcap_geterr(global_ld.pcap_h));
    goto error;

  case INITFILTER_OTHER_ERROR:
    g_snprintf(errmsg, sizeof(errmsg), "Can't install filter (%s).",
               pcap_geterr(global_ld.pcap_h));
    g_snprintf(secondary_errmsg, sizeof(secondary_errmsg), "%s", please_report);
    goto error;
  }

  /* If we're supposed to write to a capture file, open it for output
     (temporary/specified name/ringbuffer) */
  if (capture_opts->saving_to_file) {
    if (!capture_loop_open_output(capture_opts, &save_file_fd, errmsg, sizeof(errmsg))) {
      goto error;
    }

    /* set up to write to the already-opened capture output file/files */
    if (!capture_loop_init_output(capture_opts, save_file_fd, &global_ld,
                                  errmsg, sizeof(errmsg))) {
      goto error;
    }

  /* XXX - capture SIGTERM and close the capture, in case we're on a
     Linux 2.0[.x] system and you have to explicitly close the capture
     stream in order to turn promiscuous mode off?  We need to do that
     in other places as well - and I don't think that works all the
     time in any case, due to libpcap bugs. */

    /* Well, we should be able to start capturing.

       Sync out the capture file, so the header makes it to the file system,
       and send a "capture started successfully and capture file created"
       message to our parent so that they'll open the capture file and
       update its windows to indicate that we have a live capture in
       progress. */
    libpcap_dump_flush(global_ld.pdh, NULL);
    report_new_capture_file(capture_opts->save_file);
  }

  /* initialize capture stop (and alike) conditions */
  init_capture_stop_conditions();
  /* create stop conditions */
  if (capture_opts->has_autostop_filesize)
    cnd_autostop_size =
        cnd_new(CND_CLASS_CAPTURESIZE,(long)capture_opts->autostop_filesize * 1024);
  if (capture_opts->has_autostop_duration)
    cnd_autostop_duration =
        cnd_new(CND_CLASS_TIMEOUT,(gint32)capture_opts->autostop_duration);

  if (capture_opts->multi_files_on) {
      if (capture_opts->has_file_duration)
        cnd_file_duration =
	    cnd_new(CND_CLASS_TIMEOUT, capture_opts->file_duration);

      if (capture_opts->has_autostop_files)
        cnd_autostop_files =
	    cnd_new(CND_CLASS_CAPTURESIZE, capture_opts->autostop_files);
  }

  /* init the time values */
  start_time = TIME_GET();
  upd_time = TIME_GET();

  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Capture loop running!");

  /* WOW, everything is prepared! */
  /* please fasten your seat belts, we will enter now the actual capture loop */
  while (global_ld.go) {
    /* dispatch incoming packets */
    inpkts = capture_loop_dispatch(capture_opts, &global_ld, errmsg,
                                   sizeof(errmsg));

#ifdef _WIN32
    /* any news from our parent (signal pipe)? -> just stop the capture */
    if (!signal_pipe_check_running()) {
      global_ld.go = FALSE;
    }
#endif

    if (inpkts > 0) {
      inpkts_to_sync_pipe += inpkts;

      /* check capture size condition */
      if (cnd_autostop_size != NULL &&
          cnd_eval(cnd_autostop_size, (guint32)global_ld.bytes_written)){
        /* Capture size limit reached, do we have another file? */
        if (capture_opts->multi_files_on) {
          if (cnd_autostop_files != NULL &&
              cnd_eval(cnd_autostop_files, ++autostop_files)) {
             /* no files left: stop here */
            global_ld.go = FALSE;
            continue;
          }

          /* Switch to the next ringbuffer file */
          if (ringbuf_switch_file(&global_ld.pdh, &capture_opts->save_file,
                                  &save_file_fd, &global_ld.err)) {
            gboolean successful;
            
            /* File switch succeeded: reset the conditions */
            global_ld.bytes_written = 0;
            if (capture_opts->use_pcapng) {
              char appname[100];

              g_snprintf(appname, sizeof(appname), "Dumpcap " VERSION "%s", wireshark_svnversion);
              successful = libpcap_write_session_header_block(global_ld.pdh, appname, &global_ld.bytes_written, &global_ld.err) &&
                           libpcap_write_interface_description_block(global_ld.pdh, capture_opts->iface, capture_opts->cfilter, global_ld.linktype, global_ld.file_snaplen, &global_ld.bytes_written, &global_ld.err);
            } else {
              successful = libpcap_write_file_header(global_ld.pdh, global_ld.linktype, global_ld.file_snaplen,
                                                     &global_ld.bytes_written, &global_ld.err);
            }
            if (!successful) {
              fclose(global_ld.pdh);
              global_ld.pdh = NULL;
              global_ld.go = FALSE;
              continue;
            }
            cnd_reset(cnd_autostop_size);
            if (cnd_file_duration) {
              cnd_reset(cnd_file_duration);
            }
            libpcap_dump_flush(global_ld.pdh, NULL);
            report_packet_count(inpkts_to_sync_pipe);
            inpkts_to_sync_pipe = 0;
            report_new_capture_file(capture_opts->save_file);
          } else {
            /* File switch failed: stop here */
            global_ld.go = FALSE;
            continue;
          }
        } else {
          /* single file, stop now */
          global_ld.go = FALSE;
          continue;
        }
      } /* cnd_autostop_size */
      if (capture_opts->output_to_pipe) {
        libpcap_dump_flush(global_ld.pdh, NULL);
      }
    } /* inpkts */

    /* Only update once a second (Win32: 500ms) so as not to overload slow
     * displays. This also prevents too much context-switching between the
     * dumpcap and wireshark processes */
    cur_time = TIME_GET();
#ifdef _WIN32
    if ( (cur_time - upd_time) > 500) {
#else
    if (cur_time - upd_time > 0) {
#endif
        upd_time = cur_time;

      /*if (pcap_stats(pch, stats) >= 0) {
        *stats_known = TRUE;
      }*/

      /* Let the parent process know. */
      if (inpkts_to_sync_pipe) {
        /* do sync here */
        libpcap_dump_flush(global_ld.pdh, NULL);

        /* Send our parent a message saying we've written out "inpkts_to_sync_pipe"
           packets to the capture file. */
        report_packet_count(inpkts_to_sync_pipe);

        inpkts_to_sync_pipe = 0;
      }

      /* check capture duration condition */
      if (cnd_autostop_duration != NULL && cnd_eval(cnd_autostop_duration)) {
        /* The maximum capture time has elapsed; stop the capture. */
        global_ld.go = FALSE;
        continue;
      }

      /* check capture file duration condition */
      if (cnd_file_duration != NULL && cnd_eval(cnd_file_duration)) {
        /* duration limit reached, do we have another file? */
        if (capture_opts->multi_files_on) {
          if (cnd_autostop_files != NULL &&
              cnd_eval(cnd_autostop_files, ++autostop_files)) {
            /* no files left: stop here */
            global_ld.go = FALSE;
            continue;
          }

          /* Switch to the next ringbuffer file */
          if (ringbuf_switch_file(&global_ld.pdh, &capture_opts->save_file,
                                  &save_file_fd, &global_ld.err)) {
            gboolean successful;

            /* file switch succeeded: reset the conditions */
            global_ld.bytes_written = 0;
            if (capture_opts->use_pcapng) {
              char appname[100];

              g_snprintf(appname, sizeof(appname), "Dumpcap " VERSION "%s", wireshark_svnversion);
              successful = libpcap_write_session_header_block(global_ld.pdh, appname, &global_ld.bytes_written, &global_ld.err) &&
                           libpcap_write_interface_description_block(global_ld.pdh, capture_opts->iface, capture_opts->cfilter, global_ld.linktype, global_ld.file_snaplen, &global_ld.bytes_written, &global_ld.err);
            } else {
              successful = libpcap_write_file_header(global_ld.pdh, global_ld.linktype, global_ld.file_snaplen,
                                                     &global_ld.bytes_written, &global_ld.err);
            }
            if (!successful) {
              fclose(global_ld.pdh);
              global_ld.pdh = NULL;
              global_ld.go = FALSE;
              continue;
            }
            cnd_reset(cnd_file_duration);
            if(cnd_autostop_size)
              cnd_reset(cnd_autostop_size);
            libpcap_dump_flush(global_ld.pdh, NULL);
            report_packet_count(inpkts_to_sync_pipe);
            inpkts_to_sync_pipe = 0;
            report_new_capture_file(capture_opts->save_file);
          } else {
            /* File switch failed: stop here */
            global_ld.go = FALSE;
            continue;
          }
        } else {
          /* single file, stop now */
          global_ld.go = FALSE;
          continue;
        }
      } /* cnd_file_duration */
    }

  } /* while (global_ld.go) */

  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Capture loop stopping ...");

  /* delete stop conditions */
  if (cnd_file_duration != NULL)
    cnd_delete(cnd_file_duration);
  if (cnd_autostop_files != NULL)
    cnd_delete(cnd_autostop_files);
  if (cnd_autostop_size != NULL)
    cnd_delete(cnd_autostop_size);
  if (cnd_autostop_duration != NULL)
    cnd_delete(cnd_autostop_duration);

  /* did we had a pcap (input) error? */
  if (global_ld.pcap_err) {
    /* On Linux, if an interface goes down while you're capturing on it,
       you'll get a "recvfrom: Network is down" error (ENETDOWN).
       (At least you will if strerror() doesn't show a local translation
       of the error.)

       On FreeBSD and OS X, if a network adapter disappears while
       you're capturing on it, you'll get a "read: Device not configured"
       error (ENXIO).  (See previous parenthetical note.)

       On OpenBSD, you get "read: I/O error" (EIO) in the same case.

       These should *not* be reported to the Wireshark developers. */
    char *cap_err_str;

    cap_err_str = pcap_geterr(global_ld.pcap_h);
    if (strcmp(cap_err_str, "recvfrom: Network is down") == 0 ||
        strcmp(cap_err_str, "read: Device not configured") == 0 ||
        strcmp(cap_err_str, "read: I/O error") == 0) {
      report_capture_error("The network adapter on which the capture was being done "
                           "is no longer running; the capture has stopped.",
                           "");
    } else {
      g_snprintf(errmsg, sizeof(errmsg), "Error while capturing packets: %s",
        cap_err_str);
      report_capture_error(errmsg, please_report);
    }
  }
  else if (global_ld.from_cap_pipe && global_ld.cap_pipe_err == PIPERR)
    report_capture_error(errmsg, "");

  /* did we had an error while capturing? */
  if (global_ld.err == 0) {
    write_ok = TRUE;
  } else {
    capture_loop_get_errmsg(errmsg, sizeof(errmsg), capture_opts->save_file,
                            global_ld.err, FALSE);
    report_capture_error(errmsg, please_report);
    write_ok = FALSE;
  }

  if (capture_opts->saving_to_file) {
    /* close the wiretap (output) file */
    close_ok = capture_loop_close_output(capture_opts, &global_ld, &err_close);
  } else
    close_ok = TRUE;

  /* there might be packets not yet notified to the parent */
  /* (do this after closing the file, so all packets are already flushed) */
  if(inpkts_to_sync_pipe) {
    report_packet_count(inpkts_to_sync_pipe);
    inpkts_to_sync_pipe = 0;
  }

  /* If we've displayed a message about a write error, there's no point
     in displaying another message about an error on close. */
  if (!close_ok && write_ok) {
    capture_loop_get_errmsg(errmsg, sizeof(errmsg), capture_opts->save_file, err_close,
		TRUE);
    report_capture_error(errmsg, "");
  }

  /*
   * XXX We exhibit different behaviour between normal mode and sync mode
   * when the pipe is stdin and not already at EOF.  If we're a child, the
   * parent's stdin isn't closed, so if the user starts another capture,
   * cap_pipe_open_live() will very likely not see the expected magic bytes and
   * will say "Unrecognized libpcap format".  On the other hand, in normal
   * mode, cap_pipe_open_live() will say "End of file on pipe during open".
   */

  /* get packet drop statistics from pcap */
  if(global_ld.pcap_h != NULL) {
    g_assert(!global_ld.from_cap_pipe);
    /* Get the capture statistics, so we know how many packets were
       dropped. */
    if (pcap_stats(global_ld.pcap_h, stats) >= 0) {
      *stats_known = TRUE;
      /* Let the parent process know. */
      report_packet_drops(stats->ps_drop);
    } else {
      g_snprintf(errmsg, sizeof(errmsg),
		"Can't get packet-drop statistics: %s",
		pcap_geterr(global_ld.pcap_h));
      report_capture_error(errmsg, please_report);
    }
  }

  /* close the input file (pcap or capture pipe) */
  capture_loop_close_input(&global_ld);

  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Capture loop stopped!");

  /* ok, if the write and the close were successful. */
  return write_ok && close_ok;

error:
  if (capture_opts->multi_files_on) {
    /* cleanup ringbuffer */
    ringbuf_error_cleanup();
  } else {
    /* We can't use the save file, and we have no FILE * for the stream
       to close in order to close it, so close the FD directly. */
    if(save_file_fd != -1) {
      ws_close(save_file_fd);
    }

    /* We couldn't even start the capture, so get rid of the capture
       file. */
    if(capture_opts->save_file != NULL) {
      ws_unlink(capture_opts->save_file);
      g_free(capture_opts->save_file);
    }
  }
  capture_opts->save_file = NULL;
  if (cfilter_error)
    report_cfilter_error(capture_opts->cfilter, errmsg);
  else
    report_capture_error(errmsg, secondary_errmsg);

  /* close the input file (pcap or cap_pipe) */
  capture_loop_close_input(&global_ld);

  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Capture loop stopped with error");

  return FALSE;
}


static void capture_loop_stop(void)
{
#ifdef HAVE_PCAP_BREAKLOOP
  if(global_ld.pcap_h != NULL)
    pcap_breakloop(global_ld.pcap_h);
#endif
  global_ld.go = FALSE;
}


static void
capture_loop_get_errmsg(char *errmsg, int errmsglen, const char *fname,
			  int err, gboolean is_close)
{
  switch (err) {

  case ENOSPC:
    g_snprintf(errmsg, errmsglen,
		"Not all the packets could be written to the file"
		" to which the capture was being saved\n"
		"(\"%s\") because there is no space left on the file system\n"
		"on which that file resides.",
		fname);
    break;

#ifdef EDQUOT
  case EDQUOT:
    g_snprintf(errmsg, errmsglen,
		"Not all the packets could be written to the file"
		" to which the capture was being saved\n"
		"(\"%s\") because you are too close to, or over,"
		" your disk quota\n"
		"on the file system on which that file resides.",
		fname);
  break;
#endif

  case WTAP_ERR_CANT_CLOSE:
    g_snprintf(errmsg, errmsglen,
		"The file to which the capture was being saved"
		" couldn't be closed for some unknown reason.");
    break;

  case WTAP_ERR_SHORT_WRITE:
    g_snprintf(errmsg, errmsglen,
		"Not all the packets could be written to the file"
		" to which the capture was being saved\n"
		"(\"%s\").",
		fname);
    break;

  default:
    if (is_close) {
      g_snprintf(errmsg, errmsglen,
		"The file to which the capture was being saved\n"
		"(\"%s\") could not be closed: %s.",
		fname, wtap_strerror(err));
    } else {
      g_snprintf(errmsg, errmsglen,
		"An error occurred while writing to the file"
		" to which the capture was being saved\n"
		"(\"%s\"): %s.",
		fname, wtap_strerror(err));
    }
    break;
  }
}


/* one packet was captured, process it */
static void
capture_loop_packet_cb(u_char *user, const struct pcap_pkthdr *phdr,
  const u_char *pd)
{
  loop_data *ld = (void *) user;
  int err;

  /* We may be called multiple times from pcap_dispatch(); if we've set
     the "stop capturing" flag, ignore this packet, as we're not
     supposed to be saving any more packets. */
  if (!ld->go)
    return;

  if (ld->pdh) {
    gboolean successful;
    /* We're supposed to write the packet to a file; do so.
       If this fails, set "ld->go" to FALSE, to stop the capture, and set
       "ld->err" to the error. */
    if (global_capture_opts.use_pcapng) {
      successful = libpcap_write_enhanced_packet_block(ld->pdh, phdr, 0, pd, &ld->bytes_written, &err);
    } else {
      successful = libpcap_write_packet(ld->pdh, phdr, pd, &ld->bytes_written, &err);
    }
    if (!successful) {
      ld->go = FALSE;
      ld->err = err;
    } else {
      ld->packet_count++;
      /* if the user told us to stop after x packets, do we already have enough? */
      if ((ld->packet_max > 0) && (ld->packet_count >= ld->packet_max))
      {
        ld->go = FALSE;
      }
    }
  }
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
#else
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
  gint                 i;

#ifdef HAVE_PCAP_REMOTE
#define OPTSTRING_INIT "a:A:b:c:Df:hi:Lm:MnprSs:uvw:y:Z:"
#else
#define OPTSTRING_INIT "a:b:c:Df:hi:LMnpSs:vw:y:Z:"
#endif

#ifdef _WIN32
#define OPTSTRING_WIN32 "B:"
#else
#define OPTSTRING_WIN32 ""
#endif  /* _WIN32 */

  char optstring[sizeof(OPTSTRING_INIT) + sizeof(OPTSTRING_WIN32) - 1] =
    OPTSTRING_INIT OPTSTRING_WIN32;

#ifdef DEBUG_CHILD_DUMPCAP
  if ((debug_log = ws_fopen("dumpcap_debug_log.tmp","w")) == NULL) {
          fprintf (stderr, "Unable to open debug log file !\n");
          exit (1);
  }
#endif

  /* Determine if dumpcap is being requested to run in a special       */
  /* capture_child mode by going thru the command line args to see if  */
  /* a -Z is present. (-Z is a hidden option).                         */
  /* The primary result of running in capture_child mode is that       */
  /* all messages sent out on stderr are in a special type/len/string  */
  /* format to allow message processing by type.                       */
  /* These messages include various 'status' messages which are sent   */
  /* when an actual capture is in progress. Capture_child mode         */
  /* would normally be requested by a parent process which invokes     */
  /* dumpcap and obtains dumpcap stderr output via a pipe to which     */
  /* dumpcap stderr has been redirected.                               */
  /* Capture_child mode needs to be determined immediately upon        */
  /* startup so that any messages generated by dumpcap in this mode    */
  /* (eg: during initialization) will be formatted properly.           */

  for (i=1; i<argc; i++) {
    if (strcmp("-Z", argv[i]) == 0) {
      capture_child = TRUE;
#ifdef _WIN32
      /* set output pipe to binary mode, to avoid ugly text conversions */
      _setmode(2, O_BINARY);
#endif
    }
  }

  /* The default_log_handler will use stdout, which makes trouble in   */
  /* capture child mode, as it uses stdout for it's sync_pipe.         */
  /* So: the filtering is done in the console_log_handler and not here.*/
  /* We set the log handlers right up front to make sure that any log  */
  /* messages when running as child will be sent back to the parent    */
  /* with the correct format.                                          */

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
  sigaction(SIGPIPE, &action, NULL);
  sigaction(SIGHUP, NULL, &oldaction);
  if (oldaction.sa_handler == SIG_DFL)
    sigaction(SIGHUP, &action, NULL);
#endif  /* _WIN32 */

  /* ----------------------------------------------------------------- */
  /* Privilege and capability handling                                 */
  /* Cases:                                                            */
  /* 1. Running not as root or suid root; no special capabilities.     */
  /*    Action: none                                                   */
  /*                                                                   */
  /* 2. Running logged in as root (euid=0; ruid=0); Not using libcap.  */
  /*    Action: none                                                   */
  /*                                                                   */
  /* 3. Running logged in as root (euid=0; ruid=0). Using libcap.      */
  /*    Action:                                                        */
  /*      - Near start of program: Enable NET_RAW and NET_ADMIN        */
  /*        capabilities; Drop all other capabilities;                 */
  /*      - If not -w  (ie: doing -S or -D, etc) run to completion;    */
  /*        else: after  pcap_open_live() in capture_loop_open_input() */
  /*         drop all capabilities (NET_RAW and NET_ADMIN);            */
  /*         (Note: this means that the process, although logged in    */
  /*          as root, does not have various permissions such as the   */
  /*          ability to bypass file access permissions).              */
  /*      XXX: Should we just leave capabilities alone in this case    */
  /*          so that user gets expected effect that root can do       */
  /*          anything ??                                              */
  /*                                                                   */
  /* 4. Running as suid root (euid=0, ruid=n); Not using libcap.       */
  /*    Action:                                                        */
  /*      - If not -w  (ie: doing -S or -D, etc) run to completion;    */
  /*        else: after  pcap_open_live() in capture_loop_open_input() */
  /*         drop suid root (set euid=ruid).(ie: keep suid until after */
  /*         pcap_open_live).                                          */
  /*                                                                   */
  /* 5. Running as suid root (euid=0, ruid=n); Using libcap.           */
  /*    Action:                                                        */
  /*      - Near start of program: Enable NET_RAW and NET_ADMIN        */
  /*        capabilities; Drop all other capabilities;                 */
  /*        Drop suid privileges (euid=ruid);                          */
  /*      - If not -w  (ie: doing -S or -D, etc) run to completion;    */
  /*        else: after  pcap_open_live() in capture_loop_open_input() */
  /*         drop all capabilities (NET_RAW and NET_ADMIN).            */
  /*                                                                   */
  /*      XXX: For some Linux versions/distros with capabilities       */
  /*        a 'normal' process with any capabilities cannot be         */
  /*        'killed' (signaled) from another (same uid) non-privileged */
  /*        process.                                                   */
  /*        For example: If (non-suid) Wireshark forks a               */
  /*        child suid dumpcap which acts as described here (case 5),  */
  /*        Wireshark will be unable to kill (signal) the child        */
  /*        dumpcap process until the capabilities have been dropped   */
  /*        (after pcap_open_live()).                                  */
  /*        This behaviour will apparently be changed in the kernel    */
  /*        to allow the kill (signal) in this case.                   */
  /*        See the following for details:                             */
  /*           http://www.mail-archive.com/  [wrapped]                 */
  /*             linux-security-module@vger.kernel.org/msg02913.html   */
  /*                                                                   */
  /*        It is therefore conceivable that if dumpcap somehow hangs  */
  /*        in pcap_open_live or before that wireshark will not        */
  /*        be able to stop dumpcap using a signal (USR1, TERM, etc).  */
  /*        In this case, exiting wireshark will kill the child        */
  /*        dumpcap process.                                           */
  /*                                                                   */
  /* 6. Not root or suid root; Running with NET_RAW & NET_ADMIN        */
  /*     capabilities; Using libcap.  Note: capset cmd (which see)     */
  /*     used to assign capabilities to file.                          */
  /*    Action:                                                        */
  /*      - If not -w  (ie: doing -S or -D, etc) run to completion;    */
  /*        else: after  pcap_open_live() in capture_loop_open_input() */
  /*         drop all capabilities (NET_RAW and NET_ADMIN)             */
  /*                                                                   */
  /* ToDo: -S (stats) should drop privileges/capabilities when no      */
  /*       longer required (similar to capture).                        */
  /*                                                                   */
  /* ----------------------------------------------------------------- */

  get_credential_info();

#ifdef HAVE_LIBCAP
  /* If 'started with special privileges' (and using libcap)  */
  /*   Set to keep only NET_RAW and NET_ADMIN capabilities;   */
  /*   Set euid/egid = ruid/rgid to remove suid privileges    */
  relinquish_privs_except_capture();
#endif

  /* Set the initial values in the capture options. This might be overwritten
     by the command line parameters. */
  capture_opts_init(&global_capture_opts, NULL);

  /* Default to capturing the entire packet. */
  global_capture_opts.snaplen             = WTAP_MAX_PACKET_SIZE;

  /* We always save to a file - if no file was specified, we save to a
     temporary file. */
  global_capture_opts.saving_to_file      = TRUE;
  global_capture_opts.has_ring_num_files  = TRUE;

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
      case 'n':        /* Use pcapng format */
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
        status = capture_opts_add_opt(&global_capture_opts, opt, optarg, &start_capture);
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
          sig_pipe_name = g_strdup_printf(SIGNAL_PIPE_FORMAT, optarg);
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
    if (global_capture_opts.multi_files_on) {
      cmdarg_err("Ring buffer requested, but a capture isn't being done.");
      exit_main(1);
    }
  } else {
    /* No - was the ring buffer option specified and, if so, does it make
       sense? */
    if (global_capture_opts.multi_files_on) {
      /* Ring buffer works only under certain conditions:
	 a) ring buffer does not work with temporary files;
	 b) it makes no sense to enable the ring buffer if the maximum
	    file size is set to "infinite". */
      if (global_capture_opts.save_file == NULL) {
	cmdarg_err("Ring buffer requested, but capture isn't being saved to a permanent file.");
	global_capture_opts.multi_files_on = FALSE;
      }
      if (!global_capture_opts.has_autostop_filesize && !global_capture_opts.has_file_duration) {
	cmdarg_err("Ring buffer requested, but no maximum capture file size or duration were specified.");
/* XXX - this must be redesigned as the conditions changed */
/*	global_capture_opts.multi_files_on = FALSE;*/
      }
    }
  }

  if (capture_opts_trim_iface(&global_capture_opts, NULL) == FALSE) {
    /* cmdarg_err() already called .... */
    exit_main(1);
  }

  /* Let the user know what interface was chosen. */
  /* get_interface_descriptive_name() is not available! */
  g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "Interface: %s\n", global_capture_opts.iface);

  if (list_interfaces) {
    status = capture_opts_list_interfaces(machine_readable);
    exit_main(status);
  } else if (list_link_layer_types) {
    status = capture_opts_list_link_layer_types(&global_capture_opts, machine_readable);
    exit_main(status);
  } else if (print_statistics) {
    status = print_statistics_loop(machine_readable);
    exit_main(status);
  }

  capture_opts_trim_snaplen(&global_capture_opts, MIN_PACKET_SIZE);
  capture_opts_trim_ring_num_files(&global_capture_opts);

  /* Now start the capture. */

  if(capture_loop_start(&global_capture_opts, &stats_known, &stats) == TRUE) {
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
  struct tm  *today;
  const char *level;
  gchar      *msg;

  /* ignore log message, if log_level isn't interesting */
  if( !(log_level & G_LOG_LEVEL_MASK & ~(G_LOG_LEVEL_DEBUG|G_LOG_LEVEL_INFO))) {
#if !defined(DEBUG_DUMPCAP) && !defined(DEBUG_CHILD_DUMPCAP)
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

  /* Generate the output message                                  */
  if(log_level & G_LOG_LEVEL_MESSAGE) {
    /* normal user messages without additional infos */
    msg =  g_strdup_printf("%s\n", message);
  } else {
    /* info/debug messages with additional infos */
    msg = g_strdup_printf("%02u:%02u:%02u %8s %s %s\n",
            today->tm_hour, today->tm_min, today->tm_sec,
            log_domain != NULL ? log_domain : "",
            level, message);
  }

  /* DEBUG & INFO msgs (if we're debugging today)                 */
#if defined(DEBUG_DUMPCAP) || defined(DEBUG_CHILD_DUMPCAP)
  if( !(log_level & G_LOG_LEVEL_MASK & ~(G_LOG_LEVEL_DEBUG|G_LOG_LEVEL_INFO))) {
#ifdef DEBUG_DUMPCAP
    fprintf(stderr, "%s", msg);
    fflush(stderr);
#endif
#ifdef DEBUG_CHILD_DUMPCAP
    fprintf(debug_log, "%s", msg);
    fflush(debug_log);
#endif
    g_free(msg);
    return;
  }
#endif

  /* ERROR, CRITICAL, WARNING, MESSAGE messages goto stderr or    */
  /*  to parent especially formatted if dumpcap running as child. */
  if (capture_child) {
    sync_pipe_errmsg_to_parent(2, msg, "");
  } else {
    fprintf(stderr, "%s", msg);
    fflush(stderr);
  }
  g_free(msg);
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
report_packet_drops(guint32 drops)
{
    char tmp[SP_DECISIZE+1+1];

    g_snprintf(tmp, sizeof(tmp), "%u", drops);

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
static gboolean
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
