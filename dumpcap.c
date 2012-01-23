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

#include <stdio.h>
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

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if defined(__APPLE__) && defined(__LP64__)
#include <sys/utsname.h>
#endif

#include <signal.h>
#include <errno.h>

#ifndef HAVE_GETOPT
#include "wsutil/wsgetopt.h"
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_LIBCAP
# include <sys/prctl.h>
# include <sys/capability.h>
#endif

#include "ringbuffer.h"
#include "clopts_common.h"
#include "console_io.h"
#include "cmdarg_err.h"
#include "version_info.h"

#include "capture-pcap-util.h"
#ifdef _WIN32
#include "capture-wpcap.h"
#endif /* _WIN32 */

#include "pcapio.h"

#ifdef _WIN32
#include "capture-wpcap.h"
#include <wsutil/unicode-utils.h>
#endif

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#endif

#ifdef NEED_INET_V6DEFS_H
# include "wsutil/inet_v6defs.h"
#endif

#include <wsutil/privileges.h>

#include "sync_pipe.h"

#include "capture_opts.h"
#include "capture_ifinfo.h"
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

#ifdef _WIN32
#ifdef DEBUG_DUMPCAP
#include <conio.h>          /* _getch() */
#endif
#endif

#ifdef DEBUG_CHILD_DUMPCAP
FILE *debug_log;   /* for logging debug messages to  */
                   /*  a file if DEBUG_CHILD_DUMPCAP */
                   /*  is defined                    */
#endif

static GAsyncQueue *pcap_queue;
static gint64 pcap_queue_bytes;
static gint64 pcap_queue_packets;
static gint64 pcap_queue_byte_limit = 1024 * 1024;
static gint64 pcap_queue_packet_limit = 1000;

static gboolean capture_child = FALSE; /* FALSE: standalone call, TRUE: this is an Wireshark capture child */
#ifdef _WIN32
static gchar *sig_pipe_name = NULL;
static HANDLE sig_pipe_handle = NULL;
static gboolean signal_pipe_check_running(void);
#endif

#ifdef SIGINFO
static gboolean infodelay;      /* if TRUE, don't print capture info in SIGINFO handler */
static gboolean infoprint;      /* if TRUE, print capture info after clearing infodelay */
#endif /* SIGINFO */

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
 * On UN*X, we catch SIGINT as a "stop capturing" signal, and, in
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
 * However, we don't want to do that on BSD (because "select()" doesn't work
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
 * On Windows, we can't send a SIGINT to stop capturing, so none of this
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

typedef struct _pcap_options {
    guint32        received;
    guint32        dropped;
    pcap_t         *pcap_h;
#ifdef MUST_DO_SELECT
    int            pcap_fd;               /* pcap file descriptor */
#endif
    gboolean       pcap_err;
    guint          interface_id;
    GThread        *tid;
    int            snaplen;
    int            linktype;
    /* capture pipe (unix only "input file") */
    gboolean       from_cap_pipe;         /* TRUE if we are capturing data from a capture pipe */
    struct pcap_hdr cap_pipe_hdr;         /* Pcap header when capturing from a pipe */
    struct pcaprec_modified_hdr cap_pipe_rechdr;  /* Pcap record header when capturing from a pipe */
#ifdef _WIN32
    HANDLE         cap_pipe_h;            /* The handle of the capture pipe */
#else
    int            cap_pipe_fd;           /* the file descriptor of the capture pipe */
#endif
    gboolean       cap_pipe_modified;     /* TRUE if data in the pipe uses modified pcap headers */
    gboolean       cap_pipe_byte_swapped; /* TRUE if data in the pipe is byte swapped */
#if defined(_WIN32)
    char *         cap_pipe_buf;          /* Pointer to the data buffer we read into */
#endif
    int            cap_pipe_bytes_to_read;/* Used by cap_pipe_dispatch */
    int            cap_pipe_bytes_read;   /* Used by cap_pipe_dispatch */
    enum {
        STATE_EXPECT_REC_HDR,
        STATE_READ_REC_HDR,
        STATE_EXPECT_DATA,
        STATE_READ_DATA
    } cap_pipe_state;
    enum { PIPOK, PIPEOF, PIPERR, PIPNEXIST } cap_pipe_err;
#if defined(_WIN32)
    GMutex *cap_pipe_read_mtx;
    GAsyncQueue *cap_pipe_pending_q, *cap_pipe_done_q;
#endif
} pcap_options;

typedef struct _loop_data {
    /* common */
    gboolean       go;                    /* TRUE as long as we're supposed to keep capturing */
    int            err;                   /* if non-zero, error seen while capturing */
    gint           packet_count;          /* Number of packets we have already captured */
    gint           packet_max;            /* Number of packets we're supposed to capture - 0 means infinite */
    gint           inpkts_to_sync_pipe;   /* Packets not already send out to the sync_pipe */
#ifdef SIGINFO
    gboolean       report_packet_count;   /* Set by SIGINFO handler; print packet count */
#endif
    GArray         *pcaps;
    /* output file(s) */
    FILE          *pdh;
    int            save_file_fd;
    long           bytes_written;
    guint32        autostop_files;
} loop_data;

typedef struct _pcap_queue_element {
    pcap_options       *pcap_opts;
    struct pcap_pkthdr phdr;
    u_char             *pd;
} pcap_queue_element;

/*
 * Standard secondary message for unexpected errors.
 */
static const char please_report[] =
    "Please report this to the Wireshark developers.\n"
    "(This is not a crash; please do not report it as such.)";

/*
 * This needs to be static, so that the SIGINT handler can clear the "go"
 * flag.
 */
static loop_data   global_ld;


/*
 * Timeout, in milliseconds, for reads from the stream of captured packets
 * from a capture device.
 *
 * A bug in Mac OS X 10.6 and 10.6.1 causes calls to pcap_open_live(), in
 * 64-bit applications, with sub-second timeouts not to work.  The bug is
 * fixed in 10.6.2, re-broken in 10.6.3, and again fixed in 10.6.5.
 */
#if defined(__APPLE__) && defined(__LP64__)
static gboolean need_timeout_workaround;

#define CAP_READ_TIMEOUT        (need_timeout_workaround ? 1000 : 250)
#else
#define CAP_READ_TIMEOUT        250
#endif

/*
 * Timeout, in microseconds, for reads from the stream of captured packets
 * from a pipe.  Pipes don't have the same problem that BPF devices do
 * in OS X 10.6, 10.6.1, 10.6.3, and 10.6.4, so we always use a timeout
 * of 250ms, i.e. the same value as CAP_READ_TIMEOUT when not on one
 * of the offending versions of Snow Leopard.
 *
 * On Windows this value is converted to milliseconds and passed to
 * WaitForSingleObject. If it's less than 1000 WaitForSingleObject
 * will return immediately.
 */
#if defined(_WIN32)
#define PIPE_READ_TIMEOUT   100000
#else
#define PIPE_READ_TIMEOUT   250000
#endif

#define WRITER_THREAD_TIMEOUT 100000 /* usecs */

static void
console_log_handler(const char *log_domain, GLogLevelFlags log_level,
                    const char *message, gpointer user_data _U_);

/* capture related options */
static capture_options global_capture_opts;
static gboolean quiet = FALSE;
static gboolean use_threads = FALSE;

static void capture_loop_write_packet_cb(u_char *pcap_opts_p, const struct pcap_pkthdr *phdr,
                                         const u_char *pd);
static void capture_loop_queue_packet_cb(u_char *pcap_opts_p, const struct pcap_pkthdr *phdr,
                                         const u_char *pd);
static void capture_loop_get_errmsg(char *errmsg, int errmsglen, const char *fname,
                                    int err, gboolean is_close);

static void WS_MSVC_NORETURN exit_main(int err) G_GNUC_NORETURN;

static void report_new_capture_file(const char *filename);
static void report_packet_count(int packet_count);
static void report_packet_drops(guint32 received, guint32 drops, gchar *name);
static void report_capture_error(const char *error_msg, const char *secondary_error_msg);
static void report_cfilter_error(capture_options *capture_opts, guint i, const char *errmsg);

#define MSG_MAX_LENGTH 4096

static void
print_usage(gboolean print_ver)
{
    FILE *output;

    if (print_ver) {
        output = stdout;
        fprintf(output,
                "Dumpcap " VERSION "%s\n"
                "Capture network packets and dump them into a pcapng file.\n"
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
#ifdef HAVE_PCAP_CREATE
    fprintf(output, "  -I                       capture in monitor mode, if available\n");
#endif
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
    fprintf(output, "  -B <buffer size>         size of kernel buffer (def: 1MB)\n");
#endif
    fprintf(output, "  -y <link type>           link layer type (def: first appropriate)\n");
    fprintf(output, "  -D                       print list of interfaces and exit\n");
    fprintf(output, "  -L                       print list of link-layer types of iface and exit\n");
#ifdef HAVE_BPF_IMAGE
    fprintf(output, "  -d                       print generated BPF code for capture filter\n");
#endif
    fprintf(output, "  -S                       print statistics for each interface once per second\n");
    fprintf(output, "  -M                       for -D, -L, and -S, produce machine-readable output\n");
    fprintf(output, "\n");
#ifdef HAVE_PCAP_REMOTE
    fprintf(output, "RPCAP options:\n");
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
    fprintf(output, "  -g                       enable group read access on the output file(s)\n");
    fprintf(output, "  -b <ringbuffer opt.> ... duration:NUM - switch to next file after NUM secs\n");
    fprintf(output, "                           filesize:NUM - switch to next file after NUM KB\n");
    fprintf(output, "                              files:NUM - ringbuffer: replace after NUM files\n");
    fprintf(output, "  -n                       use pcapng format instead of pcap (default)\n");
    fprintf(output, "  -P                       use libpcap format instead of pcapng\n");
    fprintf(output, "\n");
    fprintf(output, "Miscellaneous:\n");
    fprintf(output, "  -t                       use a separate thread per interface\n");
    fprintf(output, "  -q                       don't report packet capture counts\n");
    fprintf(output, "  -v                       print version information and exit\n");
    fprintf(output, "  -h                       display this help and exit\n");
    fprintf(output, "\n");
    fprintf(output, "Example: dumpcap -i eth0 -a duration:60 -w output.pcapng\n");
    fprintf(output, "\"Capture network packets from interface eth0 until 60s passed into output.pcapng\"\n");
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
 * Print to the standard error.  This is a command-line tool, so there's
 * no need to pop up a console.
 */
void
vfprintf_stderr(const char *fmt, va_list ap)
{
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

#ifdef HAVE_LIBCAP
static void
#if 0 /* Set to enable capability debugging */
/* see 'man cap_to_text()' for explanation of output                         */
/* '='   means 'all= '  ie: no capabilities                                  */
/* '=ip' means 'all=ip' ie: all capabilities are permissible and inheritable */
/* ....                                                                      */
print_caps(const char *pfx) {
    cap_t caps = cap_get_proc();
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
          "%s: EUID: %d  Capabilities: %s", pfx,
          geteuid(), cap_to_text(caps, NULL));
    cap_free(caps);
#else
print_caps(const char *pfx _U_) {
#endif
}

static void
relinquish_all_capabilities(void)
{
    /* Drop any and all capabilities this process may have.            */
    /* Allowed whether or not process has any privileges.              */
    cap_t caps = cap_init();    /* all capabilities initialized to off */
    print_caps("Pre-clear");
    if (cap_set_proc(caps)) {
        cmdarg_err("cap_set_proc() fail return: %s", g_strerror(errno));
    }
    print_caps("Post-clear");
    cap_free(caps);
}
#endif

static pcap_t *
open_capture_device(interface_options *interface_opts,
                    char (*open_err_str)[PCAP_ERRBUF_SIZE])
{
    pcap_t *pcap_h;
#ifdef HAVE_PCAP_CREATE
    int         err;
#endif
#if defined(HAVE_PCAP_OPEN) && defined(HAVE_PCAP_REMOTE)
    struct pcap_rmtauth auth;
#endif

    /* Open the network interface to capture from it.
       Some versions of libpcap may put warnings into the error buffer
       if they succeed; to tell if that's happened, we have to clear
       the error buffer, and check if it's still a null string.  */
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "Entering open_capture_device().");
    (*open_err_str)[0] = '\0';
#if defined(HAVE_PCAP_OPEN) && defined(HAVE_PCAP_REMOTE)
    /*
     * If we're opening a remote device, use pcap_open(); that's currently
     * the only open routine that supports remote devices.
     */
    if (strncmp (interface_opts->name, "rpcap://", 8) == 0) {
        auth.type = interface_opts->auth_type == CAPTURE_AUTH_PWD ?
            RPCAP_RMTAUTH_PWD : RPCAP_RMTAUTH_NULL;
        auth.username = interface_opts->auth_username;
        auth.password = interface_opts->auth_password;

        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
              "Calling pcap_open() using name %s, snaplen %d, promisc_mode %d, datatx_udp %d, nocap_rpcap %d.",
              interface_opts->name, interface_opts->snaplen, interface_opts->promisc_mode,
              interface_opts->datatx_udp, interface_opts->nocap_rpcap);
        pcap_h = pcap_open(interface_opts->name, interface_opts->snaplen,
                           /* flags */
                           (interface_opts->promisc_mode ? PCAP_OPENFLAG_PROMISCUOUS : 0) |
                           (interface_opts->datatx_udp ? PCAP_OPENFLAG_DATATX_UDP : 0) |
                           (interface_opts->nocap_rpcap ? PCAP_OPENFLAG_NOCAPTURE_RPCAP : 0),
                           CAP_READ_TIMEOUT, &auth, *open_err_str);
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
              "pcap_open() returned %p.", (void *)pcap_h);
    } else
#endif
    {
        /*
         * If we're not opening a remote device, use pcap_create() and
         * pcap_activate() if we have them, so that we can set the buffer
         * size, otherwise use pcap_open_live().
         */
#ifdef HAVE_PCAP_CREATE
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
              "Calling pcap_create() using %s.", interface_opts->name);
        pcap_h = pcap_create(interface_opts->name, *open_err_str);
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
              "pcap_create() returned %p.", (void *)pcap_h);
        if (pcap_h != NULL) {
            g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
                  "Calling pcap_set_snaplen() with snaplen %d.", interface_opts->snaplen);
            pcap_set_snaplen(pcap_h, interface_opts->snaplen);
            g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
                  "Calling pcap_set_snaplen() with promisc_mode %d.", interface_opts->promisc_mode);
            pcap_set_promisc(pcap_h, interface_opts->promisc_mode);
            pcap_set_timeout(pcap_h, CAP_READ_TIMEOUT);

            g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
                  "buffersize %d.", interface_opts->buffer_size);
            if (interface_opts->buffer_size > 1) {
                pcap_set_buffer_size(pcap_h, interface_opts->buffer_size * 1024 * 1024);
            }
            g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
                  "monitor_mode %d.", interface_opts->monitor_mode);
            if (interface_opts->monitor_mode)
                pcap_set_rfmon(pcap_h, 1);
            err = pcap_activate(pcap_h);
            g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
                  "pcap_activate() returned %d.", err);
            if (err < 0) {
                /* Failed to activate, set to NULL */
                if (err == PCAP_ERROR)
                    g_strlcpy(*open_err_str, pcap_geterr(pcap_h), sizeof *open_err_str);
                else
                    g_strlcpy(*open_err_str, pcap_statustostr(err), sizeof *open_err_str);
                pcap_close(pcap_h);
                pcap_h = NULL;
            }
        }
#else
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
              "pcap_open_live() calling using name %s, snaplen %d, promisc_mode %d.",
              interface_opts->name, interface_opts->snaplen, interface_opts->promisc_mode);
        pcap_h = pcap_open_live(interface_opts->name, interface_opts->snaplen,
                                interface_opts->promisc_mode, CAP_READ_TIMEOUT,
                                *open_err_str);
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
              "pcap_open_live() returned %p.", (void *)pcap_h);
#endif
    }
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "open_capture_device %s : %s", pcap_h ? "SUCCESS" : "FAILURE", interface_opts->name);
    return pcap_h;
}

static void
get_capture_device_open_failure_messages(const char *open_err_str,
                                         const char *iface
#ifndef _WIN32
                                                           _U_
#endif
                                         ,
                                         char *errmsg, size_t errmsg_len,
                                         char *secondary_errmsg,
                                         size_t secondary_errmsg_len)
{
    const char *libpcap_warn;
    static const char ppamsg[] = "can't find PPA for ";

    /* If we got a "can't find PPA for X" message, warn the user (who
       is running dumcap on HP-UX) that they don't have a version of
       libpcap that properly handles HP-UX (libpcap 0.6.x and later
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
#ifdef _WIN32
    if (!has_wpcap) {
      g_snprintf(secondary_errmsg, (gulong) secondary_errmsg_len,
                 "\n"
                 "In order to capture packets, WinPcap must be installed; see\n"
                 "\n"
                 "        http://www.winpcap.org/\n"
                 "\n"
                 "or the mirror at\n"
                 "\n"
                 "        http://www.mirrors.wiretapped.net/security/packet-capture/winpcap/\n"
                 "\n"
                 "or the mirror at\n"
                 "\n"
                 "        http://winpcap.cs.pu.edu.tw/\n"
                 "\n"
                 "for a downloadable version of WinPcap and for instructions on how to install\n"
                 "WinPcap.");
    } else {
      g_snprintf(secondary_errmsg, (gulong) secondary_errmsg_len,
                 "\n"
                 "Please check that \"%s\" is the proper interface.\n"
                 "\n"
                 "\n"
                 "Help can be found at:\n"
                 "\n"
                 "       http://wiki.wireshark.org/WinPcap\n"
                 "       http://wiki.wireshark.org/CaptureSetup\n",
                 iface);
    }
#else
    g_snprintf(secondary_errmsg, (gulong) secondary_errmsg_len,
               "Please check to make sure you have sufficient permissions, and that you have "
               "the proper interface or pipe specified.%s", libpcap_warn);
#endif /* _WIN32 */
}

/* Set the data link type on a pcap. */
static gboolean
set_pcap_linktype(pcap_t *pcap_h, int linktype,
#ifdef HAVE_PCAP_SET_DATALINK
                  char *name _U_,
#else
                  char *name,
#endif
                  char *errmsg, size_t errmsg_len,
                  char *secondary_errmsg, size_t secondary_errmsg_len)
{
    char *set_linktype_err_str;

    if (linktype == -1)
        return TRUE; /* just use the default */
#ifdef HAVE_PCAP_SET_DATALINK
    if (pcap_set_datalink(pcap_h, linktype) == 0)
        return TRUE; /* no error */
    set_linktype_err_str = pcap_geterr(pcap_h);
#else
    /* Let them set it to the type it is; reject any other request. */
    if (get_pcap_linktype(pcap_h, name) == linktype)
        return TRUE; /* no error */
    set_linktype_err_str =
        "That DLT isn't one of the DLTs supported by this device";
#endif
    g_snprintf(errmsg, (gulong) errmsg_len, "Unable to set data link type (%s).",
               set_linktype_err_str);
    /*
     * If the error isn't "XXX is not one of the DLTs supported by this device",
     * tell the user to tell the Wireshark developers about it.
     */
    if (strstr(set_linktype_err_str, "is not one of the DLTs supported by this device") == NULL)
        g_snprintf(secondary_errmsg, (gulong) secondary_errmsg_len, please_report);
    else
        secondary_errmsg[0] = '\0';
    return FALSE;
}

static gboolean
compile_capture_filter(const char *iface, pcap_t *pcap_h,
                       struct bpf_program *fcode, const char *cfilter)
{
    bpf_u_int32 netnum, netmask;
    gchar       lookup_net_err_str[PCAP_ERRBUF_SIZE];

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

    /*
     * Sigh.  Older versions of libpcap don't properly declare the
     * third argument to pcap_compile() as a const pointer.  Cast
     * away the warning.
     */
    if (pcap_compile(pcap_h, fcode, (char *)cfilter, 1, netmask) < 0)
        return FALSE;
    return TRUE;
}

#ifdef HAVE_BPF_IMAGE
static gboolean
show_filter_code(capture_options *capture_opts)
{
    interface_options interface_opts;
    pcap_t *pcap_h;
    gchar open_err_str[PCAP_ERRBUF_SIZE];
    char errmsg[MSG_MAX_LENGTH+1];
    char secondary_errmsg[MSG_MAX_LENGTH+1];
    struct bpf_program fcode;
    struct bpf_insn *insn;
    u_int i;
    guint j;

    for (j = 0; j < capture_opts->ifaces->len; j++) {
        interface_opts = g_array_index(capture_opts->ifaces, interface_options, j);
        pcap_h = open_capture_device(&interface_opts, &open_err_str);
        if (pcap_h == NULL) {
            /* Open failed; get messages */
            get_capture_device_open_failure_messages(open_err_str,
                                                     interface_opts.name,
                                                     errmsg, sizeof errmsg,
                                                     secondary_errmsg,
                                                     sizeof secondary_errmsg);
            /* And report them */
            report_capture_error(errmsg, secondary_errmsg);
            return FALSE;
        }

        /* Set the link-layer type. */
        if (!set_pcap_linktype(pcap_h, interface_opts.linktype, interface_opts.name,
                               errmsg, sizeof errmsg,
                               secondary_errmsg, sizeof secondary_errmsg)) {
            pcap_close(pcap_h);
            report_capture_error(errmsg, secondary_errmsg);
            return FALSE;
        }

        /* OK, try to compile the capture filter. */
        if (!compile_capture_filter(interface_opts.name, pcap_h, &fcode,
                                    interface_opts.cfilter)) {
            pcap_close(pcap_h);
            report_cfilter_error(capture_opts, j, errmsg);
            return FALSE;
        }
        pcap_close(pcap_h);

        /* Now print the filter code. */
        insn = fcode.bf_insns;

        for (i = 0; i < fcode.bf_len; insn++, i++)
            printf("%s\n", bpf_image(insn, i));
    }
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
    if (capture_child) {
        /* Let our parent know we succeeded. */
        pipe_write_block(2, SP_SUCCESS, NULL);
    }
    return TRUE;
}
#endif

/*
 * capture_interface_list() is expected to do the right thing to get
 * a list of interfaces.
 *
 * In most of the programs in the Wireshark suite, "the right thing"
 * is to run dumpcap and ask it for the list, because dumpcap may
 * be the only program in the suite with enough privileges to get
 * the list.
 *
 * In dumpcap itself, however, we obviously can't run dumpcap to
 * ask for the list.  Therefore, our capture_interface_list() should
 * just call get_interface_list().
 */
GList *
capture_interface_list(int *err, char **err_str)
{
    return get_interface_list(err, err_str);
}

/*
 * Get the data-link type for a libpcap device.
 * This works around AIX 5.x's non-standard and incompatible-with-the-
 * rest-of-the-universe libpcap.
 */
static int
get_pcap_linktype(pcap_t *pch, const char *devname
#ifndef _AIX
        _U_
#endif
)
{
    int linktype;
#ifdef _AIX
    const char *ifacename;
#endif

    linktype = pcap_datalink(pch);
#ifdef _AIX

    /*
     * The libpcap that comes with AIX 5.x uses RFC 1573 ifType values
     * rather than DLT_ values for link-layer types; the ifType values
     * for LAN devices are:
     *
     *  Ethernet        6
     *  802.3           7
     *  Token Ring      9
     *  FDDI            15
     *
     * and the ifType value for a loopback device is 24.
     *
     * The AIX names for LAN devices begin with:
     *
     *  Ethernet                en
     *  802.3                   et
     *  Token Ring              tr
     *  FDDI                    fi
     *
     * and the AIX names for loopback devices begin with "lo".
     *
     * (The difference between "Ethernet" and "802.3" is presumably
     * whether packets have an Ethernet header, with a packet type,
     * or an 802.3 header, with a packet length, followed by an 802.2
     * header and possibly a SNAP header.)
     *
     * If the device name matches "linktype" interpreted as an ifType
     * value, rather than as a DLT_ value, we will assume this is AIX's
     * non-standard, incompatible libpcap, rather than a standard libpcap,
     * and will map the link-layer type to the standard DLT_ value for
     * that link-layer type, as that's what the rest of Wireshark expects.
     *
     * (This means the capture files won't be readable by a tcpdump
     * linked with AIX's non-standard libpcap, but so it goes.  They
     * *will* be readable by standard versions of tcpdump, Wireshark,
     * and so on.)
     *
     * XXX - if we conclude we're using AIX libpcap, should we also
     * set a flag to cause us to assume the time stamps are in
     * seconds-and-nanoseconds form, and to convert them to
     * seconds-and-microseconds form before processing them and
     * writing them out?
     */

    /*
     * Find the last component of the device name, which is the
     * interface name.
     */
    ifacename = strchr(devname, '/');
    if (ifacename == NULL)
        ifacename = devname;

    /* See if it matches any of the LAN device names. */
    if (strncmp(ifacename, "en", 2) == 0) {
        if (linktype == 6) {
            /*
             * That's the RFC 1573 value for Ethernet; map it to DLT_EN10MB.
             */
            linktype = 1;
        }
    } else if (strncmp(ifacename, "et", 2) == 0) {
        if (linktype == 7) {
            /*
             * That's the RFC 1573 value for 802.3; map it to DLT_EN10MB.
             * (libpcap, tcpdump, Wireshark, etc. don't care if it's Ethernet
             * or 802.3.)
             */
            linktype = 1;
        }
    } else if (strncmp(ifacename, "tr", 2) == 0) {
        if (linktype == 9) {
            /*
             * That's the RFC 1573 value for 802.5 (Token Ring); map it to
             * DLT_IEEE802, which is what's used for Token Ring.
             */
            linktype = 6;
        }
    } else if (strncmp(ifacename, "fi", 2) == 0) {
        if (linktype == 15) {
            /*
             * That's the RFC 1573 value for FDDI; map it to DLT_FDDI.
             */
            linktype = 10;
        }
    } else if (strncmp(ifacename, "lo", 2) == 0) {
        if (linktype == 24) {
            /*
             * That's the RFC 1573 value for "software loopback" devices; map it
             * to DLT_NULL, which is what's used for loopback devices on BSD.
             */
            linktype = 0;
        }
    }
#endif

    return linktype;
}

static data_link_info_t *
create_data_link_info(int dlt)
{
    data_link_info_t *data_link_info;
    const char *text;

    data_link_info = (data_link_info_t *)g_malloc(sizeof (data_link_info_t));
    data_link_info->dlt = dlt;
    text = pcap_datalink_val_to_name(dlt);
    if (text != NULL)
        data_link_info->name = g_strdup(text);
    else
        data_link_info->name = g_strdup_printf("DLT %d", dlt);
    text = pcap_datalink_val_to_description(dlt);
    if (text != NULL)
        data_link_info->description = g_strdup(text);
    else
        data_link_info->description = NULL;
    return data_link_info;
}

/*
 * Get the capabilities of a network device.
 */
static if_capabilities_t *
get_if_capabilities(const char *devname, gboolean monitor_mode
#ifndef HAVE_PCAP_CREATE
        _U_
#endif
, char **err_str)
{
    if_capabilities_t *caps;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pch;
#ifdef HAVE_PCAP_CREATE
    int status;
#endif
    int deflt;
#ifdef HAVE_PCAP_LIST_DATALINKS
    int *linktypes;
    int i, nlt;
#endif
    data_link_info_t *data_link_info;

    /*
     * Allocate the interface capabilities structure.
     */
    caps = g_malloc(sizeof *caps);

#ifdef HAVE_PCAP_OPEN
    pch = pcap_open(devname, MIN_PACKET_SIZE, 0, 0, NULL, errbuf);
    caps->can_set_rfmon = FALSE;
    if (pch == NULL) {
        if (err_str != NULL)
            *err_str = g_strdup(errbuf);
        g_free(caps);
        return NULL;
    }
#elif defined(HAVE_PCAP_CREATE)
    pch = pcap_create(devname, errbuf);
    if (pch == NULL) {
        if (err_str != NULL)
            *err_str = g_strdup(errbuf);
        g_free(caps);
        return NULL;
    }
    status = pcap_can_set_rfmon(pch);
    if (status < 0) {
        /* Error. */
        if (status == PCAP_ERROR)
            *err_str = g_strdup_printf("pcap_can_set_rfmon() failed: %s",
                                       pcap_geterr(pch));
        else
            *err_str = g_strdup(pcap_statustostr(status));
        pcap_close(pch);
        g_free(caps);
        return NULL;
    }
    if (status == 0)
        caps->can_set_rfmon = FALSE;
    else if (status == 1) {
        caps->can_set_rfmon = TRUE;
        if (monitor_mode)
            pcap_set_rfmon(pch, 1);
    } else {
        if (err_str != NULL) {
            *err_str = g_strdup_printf("pcap_can_set_rfmon() returned %d",
                                       status);
        }
        pcap_close(pch);
        g_free(caps);
        return NULL;
    }

    status = pcap_activate(pch);
    if (status < 0) {
        /* Error.  We ignore warnings (status > 0). */
        if (err_str != NULL) {
            if (status == PCAP_ERROR)
                *err_str = g_strdup_printf("pcap_activate() failed: %s",
                                           pcap_geterr(pch));
            else
                *err_str = g_strdup(pcap_statustostr(status));
        }
        pcap_close(pch);
        g_free(caps);
        return NULL;
    }
#else
    pch = pcap_open_live(devname, MIN_PACKET_SIZE, 0, 0, errbuf);
    caps->can_set_rfmon = FALSE;
    if (pch == NULL) {
        if (err_str != NULL)
            *err_str = g_strdup(errbuf);
        g_free(caps);
        return NULL;
    }
#endif
    deflt = get_pcap_linktype(pch, devname);
#ifdef HAVE_PCAP_LIST_DATALINKS
    nlt = pcap_list_datalinks(pch, &linktypes);
    if (nlt == 0 || linktypes == NULL) {
        pcap_close(pch);
        if (err_str != NULL)
            *err_str = NULL; /* an empty list doesn't mean an error */
        return NULL;
    }
    caps->data_link_types = NULL;
    for (i = 0; i < nlt; i++) {
        data_link_info = create_data_link_info(linktypes[i]);

        /*
         * XXX - for 802.11, make the most detailed 802.11
         * version the default, rather than the one the
         * device has as the default?
         */
        if (linktypes[i] == deflt)
            caps->data_link_types = g_list_prepend(caps->data_link_types,
                                                   data_link_info);
        else
            caps->data_link_types = g_list_append(caps->data_link_types,
                                                  data_link_info);
    }
#ifdef HAVE_PCAP_FREE_DATALINKS
    pcap_free_datalinks(linktypes);
#else
    /*
     * In Windows, there's no guarantee that if you have a library
     * built with one version of the MSVC++ run-time library, and
     * it returns a pointer to allocated data, you can free that
     * data from a program linked with another version of the
     * MSVC++ run-time library.
     *
     * This is not an issue on UN*X.
     *
     * See the mail threads starting at
     *
     *    http://www.winpcap.org/pipermail/winpcap-users/2006-September/001421.html
     *
     * and
     *
     *    http://www.winpcap.org/pipermail/winpcap-users/2008-May/002498.html
     */
#ifndef _WIN32
#define xx_free free  /* hack so checkAPIs doesn't complain */
    xx_free(linktypes);
#endif /* _WIN32 */
#endif /* HAVE_PCAP_FREE_DATALINKS */
#else /* HAVE_PCAP_LIST_DATALINKS */

    data_link_info = create_data_link_info(deflt);
    caps->data_link_types = g_list_append(caps->data_link_types,
                                          data_link_info);
#endif /* HAVE_PCAP_LIST_DATALINKS */

    pcap_close(pch);

    if (err_str != NULL)
        *err_str = NULL;
    return caps;
}

#define ADDRSTRLEN 46 /* Covers IPv4 & IPv6 */
static void
print_machine_readable_interfaces(GList *if_list)
{
    int         i;
    GList       *if_entry;
    if_info_t   *if_info;
    GSList      *addr;
    if_addr_t   *if_addr;
    char        addr_str[ADDRSTRLEN];

    if (capture_child) {
        /* Let our parent know we succeeded. */
        pipe_write_block(2, SP_SUCCESS, NULL);
    }

    i = 1;  /* Interface id number */
    for (if_entry = g_list_first(if_list); if_entry != NULL;
         if_entry = g_list_next(if_entry)) {
        if_info = (if_info_t *)if_entry->data;
        printf("%d. %s", i++, if_info->name);

        /*
         * Print the contents of the if_entry struct in a parseable format.
         * Each if_entry element is tab-separated.  Addresses are comma-
         * separated.
         */
        /* XXX - Make sure our description doesn't contain a tab */
        if (if_info->description != NULL)
            printf("\t%s\t", if_info->description);
        else
            printf("\t\t");

        for(addr = g_slist_nth(if_info->addrs, 0); addr != NULL;
                    addr = g_slist_next(addr)) {
            if (addr != g_slist_nth(if_info->addrs, 0))
                printf(",");

            if_addr = (if_addr_t *)addr->data;
            switch(if_addr->ifat_type) {
            case IF_AT_IPv4:
                if (inet_ntop(AF_INET, &if_addr->addr.ip4_addr, addr_str,
                              ADDRSTRLEN)) {
                    printf("%s", addr_str);
                } else {
                    printf("<unknown IPv4>");
                }
                break;
            case IF_AT_IPv6:
                if (inet_ntop(AF_INET6, &if_addr->addr.ip6_addr,
                              addr_str, ADDRSTRLEN)) {
                    printf("%s", addr_str);
                } else {
                    printf("<unknown IPv6>");
                }
                break;
            default:
                printf("<type unknown %u>", if_addr->ifat_type);
            }
        }

        if (if_info->loopback)
            printf("\tloopback");
        else
            printf("\tnetwork");

        printf("\n");
    }
}

/*
 * If you change the machine-readable output format of this function,
 * you MUST update capture_ifinfo.c:capture_get_if_capabilities() accordingly!
 */
static void
print_machine_readable_if_capabilities(if_capabilities_t *caps)
{
    GList *lt_entry;
    data_link_info_t *data_link_info;
    const gchar *desc_str;

    if (capture_child) {
        /* Let our parent know we succeeded. */
        pipe_write_block(2, SP_SUCCESS, NULL);
    }

    if (caps->can_set_rfmon)
        printf("1\n");
    else
        printf("0\n");
    for (lt_entry = caps->data_link_types; lt_entry != NULL;
         lt_entry = g_list_next(lt_entry)) {
      data_link_info = (data_link_info_t *)lt_entry->data;
      if (data_link_info->description != NULL)
        desc_str = data_link_info->description;
      else
        desc_str = "(not supported)";
      printf("%d\t%s\t%s\n", data_link_info->dlt, data_link_info->name,
             desc_str);
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
        case DONT_HAVE_PCAP:
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
        if_info = (if_info_t *)if_entry->data;
#ifdef HAVE_PCAP_OPEN
        pch = pcap_open(if_info->name, MIN_PACKET_SIZE, 0, 0, NULL, errbuf);
#else
        pch = pcap_open_live(if_info->name, MIN_PACKET_SIZE, 0, 0, errbuf);
#endif

        if (pch) {
            if_stat = (if_stat_t *)g_malloc(sizeof(if_stat_t));
            if_stat->name = g_strdup(if_info->name);
            if_stat->pch = pch;
            stat_list = g_list_append(stat_list, if_stat);
        }
    }

    if (!stat_list) {
        cmdarg_err("There are no interfaces on which a capture can be done");
        return 2;
    }

    if (capture_child) {
        /* Let our parent know we succeeded. */
        pipe_write_block(2, SP_SUCCESS, NULL);
    }

    if (!machine_readable) {
        printf("%-15s  %10s  %10s\n", "Interface", "Received",
            "Dropped");
    }

    global_ld.go = TRUE;
    while (global_ld.go) {
        for (stat_entry = g_list_first(stat_list); stat_entry != NULL; stat_entry = g_list_next(stat_entry)) {
            if_stat = (if_stat_t *)stat_entry->data;
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
        if_stat = (if_stat_t *)stat_entry->data;
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
capture_cleanup_handler(DWORD dwCtrlType)
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
capture_cleanup_handler(int signum _U_)
{
    /* On UN*X, we cleanly shut down the capture on SIGINT, SIGHUP, and
       SIGTERM.  We assume that if the user wanted it to keep running
       after they logged out, they'd have nohupped it. */

    /* Note: don't call g_log() in the signal handler: if we happened to be in
     * g_log() in process context when the signal came in, g_log will detect
     * the "recursion" and abort.
     */

    capture_loop_stop();
}
#endif


static void
report_capture_count(gboolean reportit)
{
    /* Don't print this if we're a capture child. */
    if (!capture_child && reportit) {
        fprintf(stderr, "\rPackets captured: %u\n", global_ld.packet_count);
        /* stderr could be line buffered */
        fflush(stderr);
    }
}


#ifdef SIGINFO
static void
report_counts_for_siginfo(void)
{
    report_capture_count(quiet);
    infoprint = FALSE; /* we just reported it */
}

static void
report_counts_siginfo(int signum _U_)
{
    int sav_errno = errno;

    /* If we've been told to delay printing, just set a flag asking
       that we print counts (if we're supposed to), otherwise print
       the count of packets captured (if we're supposed to). */
    if (infodelay)
        infoprint = TRUE;
    else
        report_counts_for_siginfo();
    errno = sav_errno;
}
#endif /* SIGINFO */

static void
exit_main(int status)
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
            cmdarg_err("prctl() fail return: %s", g_strerror(errno));
        }

        cap_set_flag(caps, CAP_PERMITTED,   cl_len, cap_list, CAP_SET);
        cap_set_flag(caps, CAP_INHERITABLE, cl_len, cap_list, CAP_SET);

        if (cap_set_proc(caps)) {
            cmdarg_err("cap_set_proc() fail return: %s", g_strerror(errno));
        }
        print_caps("Pre drop, post set");

        relinquish_special_privs_perm();

        print_caps("Post drop, pre set");
        cap_set_flag(caps, CAP_EFFECTIVE,   cl_len, cap_list, CAP_SET);
        if (cap_set_proc(caps)) {
            cmdarg_err("cap_set_proc() fail return: %s", g_strerror(errno));
        }
        print_caps("Post drop, post set");

        cap_free(caps);
    }
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

#if defined(_WIN32)
/*
 * Thread function that reads from a pipe and pushes the data
 * to the main application thread.
 */
/*
 * XXX Right now we use async queues for basic signaling. The main thread
 * sets cap_pipe_buf and cap_bytes_to_read, then pushes an item onto
 * cap_pipe_pending_q which triggers a read in the cap_pipe_read thread.
 * Iff the read is successful cap_pipe_read pushes an item onto
 * cap_pipe_done_q, otherwise an error is signaled. No data is passed in
 * the queues themselves (yet).
 *
 * We might want to move some of the cap_pipe_dispatch logic here so that
 * we can let cap_pipe_read run independently, queuing up multiple reads
 * for the main thread (and possibly get rid of cap_pipe_read_mtx).
 */
static void *cap_pipe_read(void *arg)
{
    pcap_options *pcap_opts;
    int bytes_read;
#ifdef _WIN32
    BOOL res;
    DWORD b, last_err;
#else /* _WIN32 */
    int b;
#endif /* _WIN32 */

    pcap_opts = (pcap_options *)arg;
    while (pcap_opts->cap_pipe_err == PIPOK) {
        g_async_queue_pop(pcap_opts->cap_pipe_pending_q); /* Wait for our cue (ahem) from the main thread */
        g_mutex_lock(pcap_opts->cap_pipe_read_mtx);
        bytes_read = 0;
        while (bytes_read < (int) pcap_opts->cap_pipe_bytes_to_read) {
#ifdef _WIN32
            /* If we try to use read() on a named pipe on Windows with partial
             * data it appears to return EOF.
             */
            res = ReadFile(pcap_opts->cap_pipe_h, pcap_opts->cap_pipe_buf+bytes_read,
                           pcap_opts->cap_pipe_bytes_to_read - bytes_read,
                           &b, NULL);

            bytes_read += b;
            if (!res) {
                last_err = GetLastError();
                if (last_err == ERROR_MORE_DATA) {
                    continue;
                } else if (last_err == ERROR_HANDLE_EOF || last_err == ERROR_BROKEN_PIPE || last_err == ERROR_PIPE_NOT_CONNECTED) {
                    pcap_opts->cap_pipe_err = PIPEOF;
                    bytes_read = 0;
                    break;
                }
                pcap_opts->cap_pipe_err = PIPERR;
                bytes_read = -1;
                break;
            } else if (b == 0 && pcap_opts->cap_pipe_bytes_to_read > 0) {
                pcap_opts->cap_pipe_err = PIPEOF;
                bytes_read = 0;
                break;
            }
#else /* _WIN32 */
            b = read(pcap_opts->cap_pipe_fd, pcap_opts->cap_pipe_buf+bytes_read,
                     pcap_opts->cap_pipe_bytes_to_read - bytes_read);
            if (b <= 0) {
                if (b == 0) {
                    pcap_opts->cap_pipe_err = PIPEOF;
                    bytes_read = 0;
                    break;
                } else {
                    pcap_opts->cap_pipe_err = PIPERR;
                    bytes_read = -1;
                    break;
                }
            } else {
                bytes_read += b;
            }
#endif /*_WIN32 */
        }
        pcap_opts->cap_pipe_bytes_read = bytes_read;
        if (pcap_opts->cap_pipe_bytes_read >= pcap_opts->cap_pipe_bytes_to_read) {
            g_async_queue_push(pcap_opts->cap_pipe_done_q, pcap_opts->cap_pipe_buf); /* Any non-NULL value will do */
        }
        g_mutex_unlock(pcap_opts->cap_pipe_read_mtx);
    }
    return NULL;
}
#endif

#if !defined(_WIN32) || defined(MUST_DO_SELECT)
/* Provide select() functionality for a single file descriptor
 * on UNIX/POSIX. Windows uses cap_pipe_read via a thread.
 *
 * Returns the same values as select.
 */
static int
cap_pipe_select(int pipe_fd)
{
    fd_set      rfds;
    struct timeval timeout;

    FD_ZERO(&rfds);
    FD_SET(pipe_fd, &rfds);

    timeout.tv_sec = PIPE_READ_TIMEOUT / 1000000;
    timeout.tv_usec = PIPE_READ_TIMEOUT % 1000000;

    return select(pipe_fd+1, &rfds, NULL, NULL, &timeout);
}
#endif


/* Mimic pcap_open_live() for pipe captures

 * We check if "pipename" is "-" (stdin), a AF_UNIX socket, or a FIFO,
 * open it, and read the header.
 *
 * N.B. : we can't read the libpcap formats used in RedHat 6.1 or SuSE 6.3
 * because we can't seek on pipes (see wiretap/libpcap.c for details) */
static void
cap_pipe_open_live(char *pipename,
                   pcap_options *pcap_opts,
                   struct pcap_hdr *hdr,
                   char *errmsg, int errmsgl)
{
#ifndef _WIN32
    ws_statb64   pipe_stat;
    struct sockaddr_un sa;
    int          b;
    int          fd;
#else /* _WIN32 */
#if 1
    char *pncopy, *pos;
    wchar_t *err_str;
#endif
#endif
#ifndef _WIN32
    int          sel_ret;
    unsigned int bytes_read;
#endif
    guint32       magic = 0;

#ifndef _WIN32
    pcap_opts->cap_pipe_fd = -1;
#else
    pcap_opts->cap_pipe_h = INVALID_HANDLE_VALUE;
#endif
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "cap_pipe_open_live: %s", pipename);

    /*
     * XXX - this blocks until a pcap per-file header has been written to
     * the pipe, so it could block indefinitely.
     */
    if (strcmp(pipename, "-") == 0) {
#ifndef _WIN32
        fd = 0; /* read from stdin */
#else /* _WIN32 */
        pcap_opts->cap_pipe_h = GetStdHandle(STD_INPUT_HANDLE);
#endif  /* _WIN32 */
    } else {
#ifndef _WIN32
        if (ws_stat64(pipename, &pipe_stat) < 0) {
            if (errno == ENOENT || errno == ENOTDIR)
                pcap_opts->cap_pipe_err = PIPNEXIST;
            else {
                g_snprintf(errmsg, errmsgl,
                           "The capture session could not be initiated "
                           "due to error getting information on pipe/socket: %s", g_strerror(errno));
                pcap_opts->cap_pipe_err = PIPERR;
            }
            return;
        }
        if (S_ISFIFO(pipe_stat.st_mode)) {
            fd = ws_open(pipename, O_RDONLY | O_NONBLOCK, 0000 /* no creation so don't matter */);
            if (fd == -1) {
                g_snprintf(errmsg, errmsgl,
                           "The capture session could not be initiated "
                           "due to error on pipe open: %s", g_strerror(errno));
                pcap_opts->cap_pipe_err = PIPERR;
                return;
            }
        } else if (S_ISSOCK(pipe_stat.st_mode)) {
            fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (fd == -1) {
                g_snprintf(errmsg, errmsgl,
                           "The capture session could not be initiated "
                           "due to error on socket create: %s", g_strerror(errno));
                pcap_opts->cap_pipe_err = PIPERR;
                return;
            }
            sa.sun_family = AF_UNIX;
            /*
             * The Single UNIX Specification says:
             *
             *   The size of sun_path has intentionally been left undefined.
             *   This is because different implementations use different sizes.
             *   For example, 4.3 BSD uses a size of 108, and 4.4 BSD uses a size
             *   of 104. Since most implementations originate from BSD versions,
             *   the size is typically in the range 92 to 108.
             *
             *   Applications should not assume a particular length for sun_path
             *   or assume that it can hold {_POSIX_PATH_MAX} bytes (256).
             *
             * It also says
             *
             *   The <sys/un.h> header shall define the sockaddr_un structure,
             *   which shall include at least the following members:
             *
             *   sa_family_t  sun_family  Address family.
             *   char         sun_path[]  Socket pathname.
             *
             * so we assume that it's an array, with a specified size,
             * and that the size reflects the maximum path length.
             */
            if (g_strlcpy(sa.sun_path, pipename, sizeof sa.sun_path) > sizeof sa.sun_path) {
                /* Path name too long */
                g_snprintf(errmsg, errmsgl,
                           "The capture session coud not be initiated "
                           "due to error on socket connect: Path name too long");
                pcap_opts->cap_pipe_err = PIPERR;
                return;
            }
            b = connect(fd, (struct sockaddr *)&sa, sizeof sa);
            if (b == -1) {
                g_snprintf(errmsg, errmsgl,
                           "The capture session coud not be initiated "
                           "due to error on socket connect: %s", g_strerror(errno));
                pcap_opts->cap_pipe_err = PIPERR;
                return;
            }
        } else {
            if (S_ISCHR(pipe_stat.st_mode)) {
                /*
                 * Assume the user specified an interface on a system where
                 * interfaces are in /dev.  Pretend we haven't seen it.
                 */
                pcap_opts->cap_pipe_err = PIPNEXIST;
            } else
            {
                g_snprintf(errmsg, errmsgl,
                           "The capture session could not be initiated because\n"
                           "\"%s\" is neither an interface nor a socket nor a pipe", pipename);
                pcap_opts->cap_pipe_err = PIPERR;
            }
            return;
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
            pcap_opts->cap_pipe_err = PIPNEXIST;
            return;
        }

        /* Wait for the pipe to appear */
        while (1) {
            pcap_opts->cap_pipe_h = CreateFile(utf_8to16(pipename), GENERIC_READ, 0, NULL,
                                               OPEN_EXISTING, 0, NULL);

            if (pcap_opts->cap_pipe_h != INVALID_HANDLE_VALUE)
                break;

            if (GetLastError() != ERROR_PIPE_BUSY) {
                FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
                              NULL, GetLastError(), 0, (LPTSTR) &err_str, 0, NULL);
                g_snprintf(errmsg, errmsgl,
                           "The capture session on \"%s\" could not be started "
                           "due to error on pipe open: %s (error %d)",
                           pipename, utf_16to8(err_str), GetLastError());
                LocalFree(err_str);
                pcap_opts->cap_pipe_err = PIPERR;
                return;
            }

            if (!WaitNamedPipe(utf_8to16(pipename), 30 * 1000)) {
                FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
                              NULL, GetLastError(), 0, (LPTSTR) &err_str, 0, NULL);
                g_snprintf(errmsg, errmsgl,
                           "The capture session on \"%s\" timed out during "
                           "pipe open: %s (error %d)",
                           pipename, utf_16to8(err_str), GetLastError());
                LocalFree(err_str);
                pcap_opts->cap_pipe_err = PIPERR;
                return;
            }
        }
#endif /* _WIN32 */
    }

    pcap_opts->from_cap_pipe = TRUE;

#ifndef _WIN32
    /* read the pcap header */
    bytes_read = 0;
    while (bytes_read < sizeof magic) {
        sel_ret = cap_pipe_select(fd);
        if (sel_ret < 0) {
            g_snprintf(errmsg, errmsgl,
                       "Unexpected error from select: %s", g_strerror(errno));
            goto error;
        } else if (sel_ret > 0) {
            b = read(fd, ((char *)&magic)+bytes_read, sizeof magic-bytes_read);
            if (b <= 0) {
                if (b == 0)
                    g_snprintf(errmsg, errmsgl, "End of file on pipe magic during open");
                else
                    g_snprintf(errmsg, errmsgl, "Error on pipe magic during open: %s",
                               g_strerror(errno));
                goto error;
            }
            bytes_read += b;
        }
    }
#else
    g_thread_create(&cap_pipe_read, pcap_opts, FALSE, NULL);

    pcap_opts->cap_pipe_buf = (char *) &magic;
    pcap_opts->cap_pipe_bytes_read = 0;
    pcap_opts->cap_pipe_bytes_to_read = sizeof(magic);
    /* We don't have to worry about cap_pipe_read_mtx here */
    g_async_queue_push(pcap_opts->cap_pipe_pending_q, pcap_opts->cap_pipe_buf);
    g_async_queue_pop(pcap_opts->cap_pipe_done_q);
    if (pcap_opts->cap_pipe_bytes_read <= 0) {
        if (pcap_opts->cap_pipe_bytes_read == 0)
            g_snprintf(errmsg, errmsgl, "End of file on pipe magic during open");
        else
            g_snprintf(errmsg, errmsgl, "Error on pipe magic during open: %s",
                       g_strerror(errno));
        goto error;
    }

#endif

    switch (magic) {
    case PCAP_MAGIC:
        /* Host that wrote it has our byte order, and was running
           a program using either standard or ss990417 libpcap. */
        pcap_opts->cap_pipe_byte_swapped = FALSE;
        pcap_opts->cap_pipe_modified = FALSE;
        break;
    case PCAP_MODIFIED_MAGIC:
        /* Host that wrote it has our byte order, but was running
           a program using either ss990915 or ss991029 libpcap. */
        pcap_opts->cap_pipe_byte_swapped = FALSE;
        pcap_opts->cap_pipe_modified = TRUE;
        break;
    case PCAP_SWAPPED_MAGIC:
        /* Host that wrote it has a byte order opposite to ours,
           and was running a program using either standard or
           ss990417 libpcap. */
        pcap_opts->cap_pipe_byte_swapped = TRUE;
        pcap_opts->cap_pipe_modified = FALSE;
        break;
    case PCAP_SWAPPED_MODIFIED_MAGIC:
        /* Host that wrote it out has a byte order opposite to
           ours, and was running a program using either ss990915
           or ss991029 libpcap. */
        pcap_opts->cap_pipe_byte_swapped = TRUE;
        pcap_opts->cap_pipe_modified = TRUE;
        break;
    default:
        /* Not a "libpcap" type we know about. */
        g_snprintf(errmsg, errmsgl, "Unrecognized libpcap format");
        goto error;
    }

#ifndef _WIN32
    /* Read the rest of the header */
    bytes_read = 0;
    while (bytes_read < sizeof(struct pcap_hdr)) {
        sel_ret = cap_pipe_select(fd);
        if (sel_ret < 0) {
            g_snprintf(errmsg, errmsgl,
                       "Unexpected error from select: %s", g_strerror(errno));
            goto error;
        } else if (sel_ret > 0) {
            b = read(fd, ((char *)hdr)+bytes_read,
                     sizeof(struct pcap_hdr) - bytes_read);
            if (b <= 0) {
                if (b == 0)
                    g_snprintf(errmsg, errmsgl, "End of file on pipe header during open");
                else
                    g_snprintf(errmsg, errmsgl, "Error on pipe header during open: %s",
                               g_strerror(errno));
                goto error;
            }
            bytes_read += b;
        }
    }
#else
    pcap_opts->cap_pipe_buf = (char *) hdr;
    pcap_opts->cap_pipe_bytes_read = 0;
    pcap_opts->cap_pipe_bytes_to_read = sizeof(struct pcap_hdr);
    g_async_queue_push(pcap_opts->cap_pipe_pending_q, pcap_opts->cap_pipe_buf);
    g_async_queue_pop(pcap_opts->cap_pipe_done_q);
    if (pcap_opts->cap_pipe_bytes_read <= 0) {
        if (pcap_opts->cap_pipe_bytes_read == 0)
            g_snprintf(errmsg, errmsgl, "End of file on pipe header during open");
        else
            g_snprintf(errmsg, errmsgl, "Error on pipe header header during open: %s",
                       g_strerror(errno));
        goto error;
    }
#endif

    if (pcap_opts->cap_pipe_byte_swapped) {
        /* Byte-swap the header fields about which we care. */
        hdr->version_major = BSWAP16(hdr->version_major);
        hdr->version_minor = BSWAP16(hdr->version_minor);
        hdr->snaplen = BSWAP32(hdr->snaplen);
        hdr->network = BSWAP32(hdr->network);
    }
    pcap_opts->linktype = hdr->network;

    if (hdr->version_major < 2) {
        g_snprintf(errmsg, errmsgl, "Unable to read old libpcap format");
        goto error;
    }

    pcap_opts->cap_pipe_state = STATE_EXPECT_REC_HDR;
    pcap_opts->cap_pipe_err = PIPOK;
#ifndef _WIN32
    pcap_opts->cap_pipe_fd = fd;
#endif
    return;

error:
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "cap_pipe_open_live: error %s", errmsg);
    pcap_opts->cap_pipe_err = PIPERR;
#ifndef _WIN32
    ws_close(fd);
    pcap_opts->cap_pipe_fd = -1;
#endif
    return;

}


/* We read one record from the pipe, take care of byte order in the record
 * header, write the record to the capture file, and update capture statistics. */
static int
cap_pipe_dispatch(loop_data *ld, pcap_options *pcap_opts, guchar *data, char *errmsg, int errmsgl)
{
    struct pcap_pkthdr phdr;
    enum { PD_REC_HDR_READ, PD_DATA_READ, PD_PIPE_EOF, PD_PIPE_ERR,
           PD_ERR } result;
#ifdef _WIN32
    GTimeVal wait_time;
    gpointer q_status;
#else
    int b;
#endif
#ifdef _WIN32
    wchar_t *err_str;
#endif

#ifdef LOG_CAPTURE_VERBOSE
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "cap_pipe_dispatch");
#endif

    switch (pcap_opts->cap_pipe_state) {

    case STATE_EXPECT_REC_HDR:
#ifdef _WIN32
        if (g_mutex_trylock(pcap_opts->cap_pipe_read_mtx)) {
#endif

            pcap_opts->cap_pipe_state = STATE_READ_REC_HDR;
            pcap_opts->cap_pipe_bytes_to_read = pcap_opts->cap_pipe_modified ?
                sizeof(struct pcaprec_modified_hdr) : sizeof(struct pcaprec_hdr);
            pcap_opts->cap_pipe_bytes_read = 0;

#ifdef _WIN32
            pcap_opts->cap_pipe_buf = (char *) &pcap_opts->cap_pipe_rechdr;
            g_async_queue_push(pcap_opts->cap_pipe_pending_q, pcap_opts->cap_pipe_buf);
            g_mutex_unlock(pcap_opts->cap_pipe_read_mtx);
        }
#endif
        /* Fall through */

    case STATE_READ_REC_HDR:
#ifndef _WIN32
        b = read(pcap_opts->cap_pipe_fd, ((char *)&pcap_opts->cap_pipe_rechdr)+pcap_opts->cap_pipe_bytes_read,
                 pcap_opts->cap_pipe_bytes_to_read - pcap_opts->cap_pipe_bytes_read);
        if (b <= 0) {
            if (b == 0)
                result = PD_PIPE_EOF;
            else
                result = PD_PIPE_ERR;
            break;
        }
        pcap_opts->cap_pipe_bytes_read += b;
#else
        g_get_current_time(&wait_time);
        g_time_val_add(&wait_time, PIPE_READ_TIMEOUT);
        q_status = g_async_queue_timed_pop(pcap_opts->cap_pipe_done_q, &wait_time);
        if (pcap_opts->cap_pipe_err == PIPEOF) {
            result = PD_PIPE_EOF;
            break;
        } else if (pcap_opts->cap_pipe_err == PIPERR) {
            result = PD_PIPE_ERR;
            break;
        }
        if (!q_status) {
            return 0;
        }
#endif
        if ((pcap_opts->cap_pipe_bytes_read) < pcap_opts->cap_pipe_bytes_to_read)
            return 0;
        result = PD_REC_HDR_READ;
        break;

    case STATE_EXPECT_DATA:
#ifdef _WIN32
        if (g_mutex_trylock(pcap_opts->cap_pipe_read_mtx)) {
#endif

            pcap_opts->cap_pipe_state = STATE_READ_DATA;
            pcap_opts->cap_pipe_bytes_to_read = pcap_opts->cap_pipe_rechdr.hdr.incl_len;
            pcap_opts->cap_pipe_bytes_read = 0;

#ifdef _WIN32
            pcap_opts->cap_pipe_buf = (char *) data;
            g_async_queue_push(pcap_opts->cap_pipe_pending_q, pcap_opts->cap_pipe_buf);
            g_mutex_unlock(pcap_opts->cap_pipe_read_mtx);
        }
#endif
        /* Fall through */

    case STATE_READ_DATA:
#ifndef _WIN32
        b = read(pcap_opts->cap_pipe_fd, data+pcap_opts->cap_pipe_bytes_read,
                 pcap_opts->cap_pipe_bytes_to_read - pcap_opts->cap_pipe_bytes_read);
        if (b <= 0) {
            if (b == 0)
                result = PD_PIPE_EOF;
            else
                result = PD_PIPE_ERR;
            break;
        }
        pcap_opts->cap_pipe_bytes_read += b;
#else
        g_get_current_time(&wait_time);
        g_time_val_add(&wait_time, PIPE_READ_TIMEOUT);
        q_status = g_async_queue_timed_pop(pcap_opts->cap_pipe_done_q, &wait_time);
        if (pcap_opts->cap_pipe_err == PIPEOF) {
            result = PD_PIPE_EOF;
            break;
        } else if (pcap_opts->cap_pipe_err == PIPERR) {
            result = PD_PIPE_ERR;
            break;
        }
        if (!q_status) {
            return 0;
        }
#endif
        if ((pcap_opts->cap_pipe_bytes_read) < pcap_opts->cap_pipe_bytes_to_read)
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
        cap_pipe_adjust_header(pcap_opts->cap_pipe_byte_swapped, &pcap_opts->cap_pipe_hdr,
                               &pcap_opts->cap_pipe_rechdr.hdr);
        if (pcap_opts->cap_pipe_rechdr.hdr.incl_len > WTAP_MAX_PACKET_SIZE) {
            g_snprintf(errmsg, errmsgl, "Frame %u too long (%d bytes)",
                       ld->packet_count+1, pcap_opts->cap_pipe_rechdr.hdr.incl_len);
            break;
        }

        if (pcap_opts->cap_pipe_rechdr.hdr.incl_len) {
            pcap_opts->cap_pipe_state = STATE_EXPECT_DATA;
            return 0;
        }
        /* no data to read? fall through */

    case PD_DATA_READ:
        /* Fill in a "struct pcap_pkthdr", and process the packet. */
        phdr.ts.tv_sec = pcap_opts->cap_pipe_rechdr.hdr.ts_sec;
        phdr.ts.tv_usec = pcap_opts->cap_pipe_rechdr.hdr.ts_usec;
        phdr.caplen = pcap_opts->cap_pipe_rechdr.hdr.incl_len;
        phdr.len = pcap_opts->cap_pipe_rechdr.hdr.orig_len;

        if (use_threads) {
            capture_loop_queue_packet_cb((u_char *)pcap_opts, &phdr, data);
        } else {
            capture_loop_write_packet_cb((u_char *)pcap_opts, &phdr, data);
        }
        pcap_opts->cap_pipe_state = STATE_EXPECT_REC_HDR;
        return 1;

    case PD_PIPE_EOF:
        pcap_opts->cap_pipe_err = PIPEOF;
        return -1;

    case PD_PIPE_ERR:
#ifdef _WIN32
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
                      NULL, GetLastError(), 0, (LPTSTR) &err_str, 0, NULL);
        g_snprintf(errmsg, errmsgl,
                   "Error reading from pipe: %s (error %d)",
                   utf_16to8(err_str), GetLastError());
        LocalFree(err_str);
#else
        g_snprintf(errmsg, errmsgl, "Error reading from pipe: %s",
                   g_strerror(errno));
#endif
        /* Fall through */
    case PD_ERR:
        break;
    }

    pcap_opts->cap_pipe_err = PIPERR;
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
    gchar             open_err_str[PCAP_ERRBUF_SIZE];
    gchar             *sync_msg_str;
    interface_options interface_opts;
    pcap_options      *pcap_opts;
    guint             i;
#ifdef _WIN32
    int         err;
    gchar      *sync_secondary_msg_str;
    WORD        wVersionRequested;
    WSADATA     wsaData;
#endif

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
    if ((use_threads == FALSE) &&
        (capture_opts->ifaces->len > 1)) {
        g_snprintf(errmsg, (gulong) errmsg_len,
                   "Using threads is required for capturing on mulitple interfaces!");
        return FALSE;
    }

    for (i = 0; i < capture_opts->ifaces->len; i++) {
        interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
        pcap_opts = (pcap_options *)g_malloc(sizeof (pcap_options));
        if (pcap_opts == NULL) {
            g_snprintf(errmsg, (gulong) errmsg_len,
                   "Could not allocate memory.");
            return FALSE;
        }
        pcap_opts->received = 0;
        pcap_opts->dropped = 0;
        pcap_opts->pcap_h = NULL;
#ifdef MUST_DO_SELECT
        pcap_opts->pcap_fd = -1;
#endif
        pcap_opts->pcap_err = FALSE;
        pcap_opts->interface_id = i;
        pcap_opts->tid = NULL;
        pcap_opts->snaplen = 0;
        pcap_opts->linktype = -1;
        pcap_opts->from_cap_pipe = FALSE;
        memset(&pcap_opts->cap_pipe_hdr, 0, sizeof(struct pcap_hdr));
        memset(&pcap_opts->cap_pipe_rechdr, 0, sizeof(struct pcaprec_modified_hdr));
#ifdef _WIN32
        pcap_opts->cap_pipe_h = INVALID_HANDLE_VALUE;
#else
        pcap_opts->cap_pipe_fd = -1;
#endif
        pcap_opts->cap_pipe_modified = FALSE;
        pcap_opts->cap_pipe_byte_swapped = FALSE;
#ifdef _WIN32
        pcap_opts->cap_pipe_buf = NULL;
#endif
        pcap_opts->cap_pipe_bytes_to_read = 0;
        pcap_opts->cap_pipe_bytes_read = 0;
        pcap_opts->cap_pipe_state = 0;
        pcap_opts->cap_pipe_err = PIPOK;
#ifdef _WIN32
#if GLIB_CHECK_VERSION(2,31,0)
        pcap_opts->cap_pipe_read_mtx = g_malloc(sizeof(GMutex));
        g_mutex_init(pcap_opts->cap_pipe_read_mtx);
#else
        pcap_opts->cap_pipe_read_mtx = g_mutex_new();
#endif
        pcap_opts->cap_pipe_pending_q = g_async_queue_new();
        pcap_opts->cap_pipe_done_q = g_async_queue_new();
#endif
        g_array_append_val(ld->pcaps, pcap_opts);

        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_open_input : %s", interface_opts.name);
        pcap_opts->pcap_h = open_capture_device(&interface_opts, &open_err_str);

        if (pcap_opts->pcap_h != NULL) {
            /* we've opened "iface" as a network device */
#ifdef _WIN32
            /* try to set the capture buffer size */
            if (interface_opts.buffer_size > 1 &&
                pcap_setbuff(pcap_opts->pcap_h, interface_opts.buffer_size * 1024 * 1024) != 0) {
                sync_secondary_msg_str = g_strdup_printf(
                    "The capture buffer size of %dMB seems to be too high for your machine,\n"
                    "the default of 1MB will be used.\n"
                    "\n"
                    "Nonetheless, the capture is started.\n",
                    interface_opts.buffer_size);
                report_capture_error("Couldn't set the capture buffer size!",
                                     sync_secondary_msg_str);
                g_free(sync_secondary_msg_str);
            }
#endif

#if defined(HAVE_PCAP_SETSAMPLING)
            if (interface_opts.sampling_method != CAPTURE_SAMP_NONE) {
                struct pcap_samp *samp;

                if ((samp = pcap_setsampling(pcap_opts->pcap_h)) != NULL) {
                    switch (interface_opts.sampling_method) {
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
                            interface_opts.sampling_method);
                        report_capture_error("Couldn't set the capture "
                                             "sampling", sync_msg_str);
                        g_free(sync_msg_str);
                    }
                    samp->value = interface_opts.sampling_param;
                } else {
                    report_capture_error("Couldn't set the capture sampling",
                                         "Cannot get packet sampling data structure");
                }
            }
#endif

            /* setting the data link type only works on real interfaces */
            if (!set_pcap_linktype(pcap_opts->pcap_h, interface_opts.linktype, interface_opts.name,
                                   errmsg, errmsg_len,
                                   secondary_errmsg, secondary_errmsg_len)) {
                return FALSE;
            }
            pcap_opts->linktype = get_pcap_linktype(pcap_opts->pcap_h, interface_opts.name);
        } else {
            /* We couldn't open "iface" as a network device. */
            /* Try to open it as a pipe */
            cap_pipe_open_live(interface_opts.name, pcap_opts, &pcap_opts->cap_pipe_hdr, errmsg, (int) errmsg_len);

#ifndef _WIN32
            if (pcap_opts->cap_pipe_fd == -1) {
#else
            if (pcap_opts->cap_pipe_h == INVALID_HANDLE_VALUE) {
#endif
                if (pcap_opts->cap_pipe_err == PIPNEXIST) {
                    /* Pipe doesn't exist, so output message for interface */
                    get_capture_device_open_failure_messages(open_err_str,
                                                             interface_opts.name,
                                                             errmsg,
                                                             errmsg_len,
                                                             secondary_errmsg,
                                                             secondary_errmsg_len);
                }
                /*
                 * Else pipe (or file) does exist and cap_pipe_open_live() has
                 * filled in errmsg
                 */
                return FALSE;
            } else {
                /* cap_pipe_open_live() succeeded; don't want
                   error message from pcap_open_live() */
                open_err_str[0] = '\0';
            }
        }

/* XXX - will this work for tshark? */
#ifdef MUST_DO_SELECT
        if (!pcap_opts->from_cap_pipe) {
#ifdef HAVE_PCAP_GET_SELECTABLE_FD
            pcap_opts->pcap_fd = pcap_get_selectable_fd(pcap_opts->pcap_h);
#else
            pcap_opts->pcap_fd = pcap_fileno(pcap_opts->pcap_h);
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
        capture_opts->ifaces = g_array_remove_index(capture_opts->ifaces, i);
        g_array_insert_val(capture_opts->ifaces, i, interface_opts);
    }

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
    return TRUE;
}

/* close the capture input file (pcap or capture pipe) */
static void capture_loop_close_input(loop_data *ld)
{
    guint i;
    pcap_options *pcap_opts;

    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_close_input");

    for (i = 0; i < ld->pcaps->len; i++) {
        pcap_opts = g_array_index(ld->pcaps, pcap_options *, i);
        /* if open, close the capture pipe "input file" */
#ifndef _WIN32
        if (pcap_opts->cap_pipe_fd >= 0) {
            g_assert(pcap_opts->from_cap_pipe);
            ws_close(pcap_opts->cap_pipe_fd);
            pcap_opts->cap_pipe_fd = -1;
        }
#else
        if (pcap_opts->cap_pipe_h != INVALID_HANDLE_VALUE) {
            CloseHandle(pcap_opts->cap_pipe_h);
            pcap_opts->cap_pipe_h = INVALID_HANDLE_VALUE;
        }
#endif
        /* if open, close the pcap "input file" */
        if (pcap_opts->pcap_h != NULL) {
            g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_close_input: closing %p", (void *)pcap_opts->pcap_h);
            pcap_close(pcap_opts->pcap_h);
            pcap_opts->pcap_h = NULL;
        }
    }

    ld->go = FALSE;

#ifdef _WIN32
    /* Shut down windows sockets */
    WSACleanup();
#endif
}


/* init the capture filter */
static initfilter_status_t
capture_loop_init_filter(pcap_t *pcap_h, gboolean from_cap_pipe,
                         const gchar * name, const gchar * cfilter)
{
    struct bpf_program fcode;

    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_init_filter: %s", cfilter);

    /* capture filters only work on real interfaces */
    if (cfilter && !from_cap_pipe) {
        /* A capture filter was specified; set it up. */
        if (!compile_capture_filter(name, pcap_h, &fcode, cfilter)) {
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
capture_loop_init_output(capture_options *capture_opts, loop_data *ld, char *errmsg, int errmsg_len)
{
    int err;
    guint i;
    pcap_options *pcap_opts;
    interface_options interface_opts;
    gboolean successful;

    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_init_output");

    if ((capture_opts->use_pcapng == FALSE) &&
        (capture_opts->ifaces->len > 1)) {
        g_snprintf(errmsg, errmsg_len,
                   "Using PCAPNG is required for capturing on mulitple interfaces! Use the -n option.");
        return FALSE;
    }

    /* Set up to write to the capture file. */
    if (capture_opts->multi_files_on) {
        ld->pdh = ringbuf_init_libpcap_fdopen(&err);
    } else {
        ld->pdh = libpcap_fdopen(ld->save_file_fd, &err);
    }
    if (ld->pdh) {
        if (capture_opts->use_pcapng) {
            char appname[100];

            g_snprintf(appname, sizeof(appname), "Dumpcap " VERSION "%s", wireshark_svnversion);
            successful = libpcap_write_session_header_block(ld->pdh, appname, &ld->bytes_written, &err);
            for (i = 0; successful && (i < capture_opts->ifaces->len); i++) {
                interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
                pcap_opts = g_array_index(ld->pcaps, pcap_options *, i);
                if (pcap_opts->from_cap_pipe) {
                    pcap_opts->snaplen = pcap_opts->cap_pipe_hdr.snaplen;
                } else {
                    pcap_opts->snaplen = pcap_snapshot(pcap_opts->pcap_h);
                }
                successful = libpcap_write_interface_description_block(ld->pdh,
                                                                       interface_opts.name,
                                                                       interface_opts.cfilter?interface_opts.cfilter:"",
                                                                       pcap_opts->linktype,
                                                                       pcap_opts->snaplen,
                                                                       &ld->bytes_written,
                                                                       &err);
            }
        } else {
            pcap_opts = g_array_index(ld->pcaps, pcap_options *, 0);
            if (pcap_opts->from_cap_pipe) {
                pcap_opts->snaplen = pcap_opts->cap_pipe_hdr.snaplen;
            } else {
                pcap_opts->snaplen = pcap_snapshot(pcap_opts->pcap_h);
            }
            successful = libpcap_write_file_header(ld->pdh, pcap_opts->linktype, pcap_opts->snaplen,
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
                           capture_opts->save_file, g_strerror(err));
            }
            break;
        }

        return FALSE;
    }

    return TRUE;
}

static gboolean
capture_loop_close_output(capture_options *capture_opts, loop_data *ld, int *err_close)
{

    unsigned int i;
    pcap_options *pcap_opts;

    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_close_output");

    if (capture_opts->multi_files_on) {
        return ringbuf_libpcap_dump_close(&capture_opts->save_file, err_close);
    } else {
        if (capture_opts->use_pcapng) {
            for (i = 0; i < global_ld.pcaps->len; i++) {
                pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, i);
                if (!pcap_opts->from_cap_pipe) {
                    libpcap_write_interface_statistics_block(ld->pdh, i, pcap_opts->pcap_h, &ld->bytes_written, err_close);
                }
            }
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
capture_loop_dispatch(loop_data *ld,
                      char *errmsg, int errmsg_len, pcap_options *pcap_opts)
{
    int       inpkts;
    gint      packet_count_before;
    guchar    pcap_data[WTAP_MAX_PACKET_SIZE];
#ifndef _WIN32
    int       sel_ret;
#endif

    packet_count_before = ld->packet_count;
    if (pcap_opts->from_cap_pipe) {
        /* dispatch from capture pipe */
#ifdef LOG_CAPTURE_VERBOSE
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_dispatch: from capture pipe");
#endif
#ifndef _WIN32
        sel_ret = cap_pipe_select(pcap_opts->cap_pipe_fd);
        if (sel_ret <= 0) {
            if (sel_ret < 0 && errno != EINTR) {
                g_snprintf(errmsg, errmsg_len,
                           "Unexpected error from select: %s", g_strerror(errno));
                report_capture_error(errmsg, please_report);
                ld->go = FALSE;
            }
        } else {
            /*
             * "select()" says we can read from the pipe without blocking
             */
#endif
            inpkts = cap_pipe_dispatch(ld, pcap_opts, pcap_data, errmsg, errmsg_len);
            if (inpkts < 0) {
                ld->go = FALSE;
            }
#ifndef _WIN32
        }
#endif
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
        if (pcap_opts->pcap_fd != -1) {
            sel_ret = cap_pipe_select(pcap_opts->pcap_fd);
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
                if (use_threads) {
                    inpkts = pcap_dispatch(pcap_opts->pcap_h, 1, capture_loop_queue_packet_cb, (u_char *)pcap_opts);
                } else {
                    inpkts = pcap_dispatch(pcap_opts->pcap_h, 1, capture_loop_write_packet_cb, (u_char *)pcap_opts);
                }
                if (inpkts < 0) {
                    if (inpkts == -1) {
                        /* Error, rather than pcap_breakloop(). */
                        pcap_opts->pcap_err = TRUE;
                    }
                    ld->go = FALSE; /* error or pcap_breakloop() - stop capturing */
                }
            } else {
                if (sel_ret < 0 && errno != EINTR) {
                    g_snprintf(errmsg, errmsg_len,
                               "Unexpected error from select: %s", g_strerror(errno));
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
            if (use_threads) {
                inpkts = pcap_dispatch(pcap_opts->pcap_h, 1, capture_loop_queue_packet_cb, (u_char *)pcap_opts);
            } else {
                inpkts = pcap_dispatch(pcap_opts->pcap_h, 1, capture_loop_write_packet_cb, (u_char *)pcap_opts);
            }
#else
            if (use_threads) {
                inpkts = pcap_dispatch(pcap_opts->pcap_h, -1, capture_loop_queue_packet_cb, (u_char *)pcap_opts);
            } else {
                inpkts = pcap_dispatch(pcap_opts->pcap_h, -1, capture_loop_write_packet_cb, (u_char *)pcap_opts);
            }
#endif
            if (inpkts < 0) {
                if (inpkts == -1) {
                    /* Error, rather than pcap_breakloop(). */
                    pcap_opts->pcap_err = TRUE;
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
                      (in = pcap_next_ex(pcap_opts->pcap_h, &pkt_header, &pkt_data)) == 1) {
                    if (use_threads) {
                        capture_loop_queue_packet_cb((u_char *)pcap_opts, pkt_header, pkt_data);
                    } else {
                        capture_loop_write_packet_cb((u_char *)pcap_opts, pkt_header, pkt_data);
                    }
                }

                if(in < 0) {
                    pcap_opts->pcap_err = TRUE;
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

#ifdef _WIN32
/* Isolate the Universally Unique Identifier from the interface.  Basically, we
 * want to grab only the characters between the '{' and '}' delimiters.
 *
 * Returns a GString that must be freed with g_string_free(). */
static GString *
isolate_uuid(const char *iface)
{
    gchar *ptr;
    GString *gstr;

    ptr = strchr(iface, '{');
    if (ptr == NULL)
        return g_string_new(iface);
    gstr = g_string_new(ptr + 1);

    ptr = strchr(gstr->str, '}');
    if (ptr == NULL)
        return gstr;

    gstr = g_string_truncate(gstr, ptr - gstr->str);
    return gstr;
}
#endif

/* open the output file (temporary/specified name/ringbuffer/named pipe/stdout) */
/* Returns TRUE if the file opened successfully, FALSE otherwise. */
static gboolean
capture_loop_open_output(capture_options *capture_opts, int *save_file_fd,
                         char *errmsg, int errmsg_len)
{
    char *tmpname;
    gchar *capfile_name;
    gchar *prefix;
    gboolean is_tempfile;

    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "capture_loop_open_output: %s",
          (capture_opts->save_file) ? capture_opts->save_file : "(not specified)");

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
                                             (capture_opts->has_ring_num_files) ? capture_opts->ring_num_files : 0,
                                             capture_opts->group_read_access);

                /* we need the ringbuf name */
                if(*save_file_fd != -1) {
                    g_free(capfile_name);
                    capfile_name = g_strdup(ringbuf_current_filename());
                }
            } else {
                /* Try to open/create the specified file for use as a capture buffer. */
                *save_file_fd = ws_open(capfile_name, O_RDWR|O_BINARY|O_TRUNC|O_CREAT,
                                        (capture_opts->group_read_access) ? 0640 : 0600);
            }
        }
        is_tempfile = FALSE;
    } else {
        /* Choose a random name for the temporary capture buffer */
        if (global_capture_opts.ifaces->len > 1) {
            prefix = g_strdup_printf("wireshark_%d_interfaces", global_capture_opts.ifaces->len);
        } else {
            gchar *basename;
#ifdef _WIN32
            GString *iface;
            iface = isolate_uuid(g_array_index(global_capture_opts.ifaces, interface_options, 0).name);
            basename = g_path_get_basename(iface->str);
            g_string_free(iface, TRUE);
#else
            basename = g_path_get_basename(g_array_index(global_capture_opts.ifaces, interface_options, 0).name);
#endif
            prefix = g_strconcat("wireshark_", basename, NULL);
            g_free(basename);
        }
        *save_file_fd = create_tempfile(&tmpname, prefix);
        g_free(prefix);
        capfile_name = g_strdup(tmpname);
        is_tempfile = TRUE;
    }

    /* did we fail to open the output file? */
    if (*save_file_fd == -1) {
        if (is_tempfile) {
            g_snprintf(errmsg, errmsg_len,
                       "The temporary file to which the capture would be saved (\"%s\") "
                       "could not be opened: %s.", capfile_name, g_strerror(errno));
        } else {
            if (capture_opts->multi_files_on) {
                ringbuf_error_cleanup();
            }

            g_snprintf(errmsg, errmsg_len,
                       "The file to which the capture would be saved (\"%s\") "
                       "could not be opened: %s.", capfile_name,
                       g_strerror(errno));
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

    return TRUE;
}


/* Do the work of handling either the file size or file duration capture
   conditions being reached, and switching files or stopping. */
static gboolean
do_file_switch_or_stop(capture_options *capture_opts,
                       condition *cnd_autostop_files,
                       condition *cnd_autostop_size,
                       condition *cnd_file_duration)
{
    guint i;
    pcap_options *pcap_opts;
    interface_options interface_opts;
    gboolean successful;

    if (capture_opts->multi_files_on) {
        if (cnd_autostop_files != NULL &&
            cnd_eval(cnd_autostop_files, ++global_ld.autostop_files)) {
            /* no files left: stop here */
            global_ld.go = FALSE;
            return FALSE;
        }

        /* Switch to the next ringbuffer file */
        if (ringbuf_switch_file(&global_ld.pdh, &capture_opts->save_file,
                                &global_ld.save_file_fd, &global_ld.err)) {

            /* File switch succeeded: reset the conditions */
            global_ld.bytes_written = 0;
            if (capture_opts->use_pcapng) {
                char appname[100];

                g_snprintf(appname, sizeof(appname), "Dumpcap " VERSION "%s", wireshark_svnversion);
                successful = libpcap_write_session_header_block(global_ld.pdh, appname, &(global_ld.bytes_written), &global_ld.err);
                for (i = 0; successful && (i < capture_opts->ifaces->len); i++) {
                    interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
                    pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, i);
                    successful = libpcap_write_interface_description_block(global_ld.pdh,
                                                                           interface_opts.name,
                                                                           interface_opts.cfilter?interface_opts.cfilter:"",
                                                                           pcap_opts->linktype,
                                                                           pcap_opts->snaplen,
                                                                           &(global_ld.bytes_written),
                                                                           &global_ld.err);
                }
            } else {
                pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, 0);
                successful = libpcap_write_file_header(global_ld.pdh, pcap_opts->linktype, pcap_opts->snaplen,
                                                       &global_ld.bytes_written, &global_ld.err);
            }
            if (!successful) {
                fclose(global_ld.pdh);
                global_ld.pdh = NULL;
                global_ld.go = FALSE;
                return FALSE;
            }
            if (cnd_autostop_size)
                cnd_reset(cnd_autostop_size);
            if (cnd_file_duration)
                cnd_reset(cnd_file_duration);
            libpcap_dump_flush(global_ld.pdh, NULL);
            if (!quiet)
                report_packet_count(global_ld.inpkts_to_sync_pipe);
            global_ld.inpkts_to_sync_pipe = 0;
            report_new_capture_file(capture_opts->save_file);
        } else {
            /* File switch failed: stop here */
            global_ld.go = FALSE;
            return FALSE;
        }
    } else {
        /* single file, stop now */
        global_ld.go = FALSE;
        return FALSE;
    }
    return TRUE;
}

static void *
pcap_read_handler(void* arg)
{
    pcap_options *pcap_opts;
    char errmsg[MSG_MAX_LENGTH+1];

    pcap_opts = (pcap_options *)arg;

    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Started thread for interface %d.",
          pcap_opts->interface_id);

    while (global_ld.go) {
        /* dispatch incoming packets */
        capture_loop_dispatch(&global_ld, errmsg, sizeof(errmsg), pcap_opts);
    }
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Stopped thread for interface %d.",
          pcap_opts->interface_id);
    g_thread_exit(NULL);
    return (NULL);
}

/* Do the low-level work of a capture.
   Returns TRUE if it succeeds, FALSE otherwise. */
static gboolean
capture_loop_start(capture_options *capture_opts, gboolean *stats_known, struct pcap_stat *stats)
{
#ifdef WIN32
    DWORD upd_time, cur_time;   /* GetTickCount() returns a "DWORD" (which is 'unsigned long') */
#else
    struct timeval upd_time, cur_time;
#endif
    int         err_close;
    int         inpkts;
    condition  *cnd_file_duration = NULL;
    condition  *cnd_autostop_files = NULL;
    condition  *cnd_autostop_size = NULL;
    condition  *cnd_autostop_duration = NULL;
    gboolean    write_ok;
    gboolean    close_ok;
    gboolean    cfilter_error = FALSE;
    char        errmsg[MSG_MAX_LENGTH+1];
    char        secondary_errmsg[MSG_MAX_LENGTH+1];
    pcap_options *pcap_opts;
    interface_options interface_opts;
    guint i, error_index = 0;

    *errmsg           = '\0';
    *secondary_errmsg = '\0';

    /* init the loop data */
    global_ld.go                  = TRUE;
    global_ld.packet_count        = 0;
#ifdef SIGINFO
    global_ld.report_packet_count = FALSE;
#endif
    if (capture_opts->has_autostop_packets)
        global_ld.packet_max      = capture_opts->autostop_packets;
    else
        global_ld.packet_max      = 0;        /* no limit */
    global_ld.inpkts_to_sync_pipe = 0;
    global_ld.err                 = 0;  /* no error seen yet */
    global_ld.pdh                 = NULL;
    global_ld.autostop_files      = 0;
    global_ld.save_file_fd        = -1;

    /* We haven't yet gotten the capture statistics. */
    *stats_known      = FALSE;

    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Capture loop starting ...");
    capture_opts_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, capture_opts);

    /* open the "input file" from network interface or capture pipe */
    if (!capture_loop_open_input(capture_opts, &global_ld, errmsg, sizeof(errmsg),
                                 secondary_errmsg, sizeof(secondary_errmsg))) {
        goto error;
    }
    for (i = 0; i < capture_opts->ifaces->len; i++) {
        pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, i);
        interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
        /* init the input filter from the network interface (capture pipe will do nothing) */
        /*
         * When remote capturing WinPCap crashes when the capture filter
         * is NULL. This might be a bug in WPCap. Therefore we provide an emtpy
         * string.
         */
        switch (capture_loop_init_filter(pcap_opts->pcap_h, pcap_opts->from_cap_pipe,
                                         interface_opts.name,
                                         interface_opts.cfilter?interface_opts.cfilter:"")) {

        case INITFILTER_NO_ERROR:
            break;

        case INITFILTER_BAD_FILTER:
            cfilter_error = TRUE;
            error_index = i;
            g_snprintf(errmsg, sizeof(errmsg), "%s", pcap_geterr(pcap_opts->pcap_h));
            goto error;

        case INITFILTER_OTHER_ERROR:
            g_snprintf(errmsg, sizeof(errmsg), "Can't install filter (%s).",
                       pcap_geterr(pcap_opts->pcap_h));
            g_snprintf(secondary_errmsg, sizeof(secondary_errmsg), "%s", please_report);
            goto error;
        }
    }

    /* If we're supposed to write to a capture file, open it for output
       (temporary/specified name/ringbuffer) */
    if (capture_opts->saving_to_file) {
        if (!capture_loop_open_output(capture_opts, &global_ld.save_file_fd,
                                      errmsg, sizeof(errmsg))) {
            goto error;
        }

        /* set up to write to the already-opened capture output file/files */
        if (!capture_loop_init_output(capture_opts, &global_ld, errmsg,
                                      sizeof(errmsg))) {
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
#ifdef WIN32
    upd_time = GetTickCount();
#else
    gettimeofday(&upd_time, NULL);
#endif

    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Capture loop running!");

    /* WOW, everything is prepared! */
    /* please fasten your seat belts, we will enter now the actual capture loop */
    if (use_threads) {
        pcap_queue = g_async_queue_new();
        pcap_queue_bytes = 0;
        pcap_queue_packets = 0;
        for (i = 0; i < global_ld.pcaps->len; i++) {
            pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, i);
#if GLIB_CHECK_VERSION(2,31,0)
            /* XXX - Add an interface name here? */
            pcap_opts->tid = g_thread_new("Capture read", pcap_read_handler, pcap_opts);
#else
            pcap_opts->tid = g_thread_create(pcap_read_handler, pcap_opts, TRUE, NULL);
#endif
        }
    }
    while (global_ld.go) {
        /* dispatch incoming packets */
        if (use_threads) {
            GTimeVal write_thread_time;
            pcap_queue_element *queue_element;

            g_get_current_time(&write_thread_time);
            g_time_val_add(&write_thread_time, WRITER_THREAD_TIMEOUT);
            g_async_queue_lock(pcap_queue);
            queue_element = g_async_queue_timed_pop_unlocked(pcap_queue, &write_thread_time);
            if (queue_element) {
                pcap_queue_bytes -= queue_element->phdr.caplen;
                pcap_queue_packets -= 1;
            }
            g_async_queue_unlock(pcap_queue);
            if (queue_element) {
                g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO,
                      "Dequeued a packet of length %d captured on interface %d.",
                      queue_element->phdr.caplen, queue_element->pcap_opts->interface_id);

                capture_loop_write_packet_cb((u_char *) queue_element->pcap_opts,
                                             &queue_element->phdr,
                                             queue_element->pd);
                g_free(queue_element->pd);
                g_free(queue_element);
                inpkts = 1;
            } else {
                inpkts = 0;
            }
        } else {
            pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, 0);
            inpkts = capture_loop_dispatch(&global_ld, errmsg,
                                           sizeof(errmsg), pcap_opts);
        }
#ifdef SIGINFO
        /* Were we asked to print packet counts by the SIGINFO handler? */
        if (global_ld.report_packet_count) {
            fprintf(stderr, "%u packet%s captured\n", global_ld.packet_count,
                    plurality(global_ld.packet_count, "", "s"));
            global_ld.report_packet_count = FALSE;
        }
#endif

#ifdef _WIN32
        /* any news from our parent (signal pipe)? -> just stop the capture */
        if (!signal_pipe_check_running()) {
            global_ld.go = FALSE;
        }
#endif

        if (inpkts > 0) {
            global_ld.inpkts_to_sync_pipe += inpkts;

            /* check capture size condition */
            if (cnd_autostop_size != NULL &&
                cnd_eval(cnd_autostop_size, (guint32)global_ld.bytes_written)) {
                /* Capture size limit reached, do we have another file? */
                if (!do_file_switch_or_stop(capture_opts, cnd_autostop_files,
                                            cnd_autostop_size, cnd_file_duration))
                    continue;
            } /* cnd_autostop_size */
            if (capture_opts->output_to_pipe) {
                libpcap_dump_flush(global_ld.pdh, NULL);
            }
        } /* inpkts */

        /* Only update once every 500ms so as not to overload slow displays.
         * This also prevents too much context-switching between the dumpcap
         * and wireshark processes.
         */
#define DUMPCAP_UPD_TIME 500

#ifdef WIN32
        cur_time = GetTickCount();  /* Note: wraps to 0 if sys runs for 49.7 days */
        if ((cur_time - upd_time) > DUMPCAP_UPD_TIME) { /* wrap just causes an extra update */
#else
        gettimeofday(&cur_time, NULL);
        if ((cur_time.tv_sec * 1000000 + cur_time.tv_usec) >
            (upd_time.tv_sec * 1000000 + upd_time.tv_usec + DUMPCAP_UPD_TIME*1000)) {
#endif

            upd_time = cur_time;

#if 0
            if (pcap_stats(pch, stats) >= 0) {
                *stats_known = TRUE;
            }
#endif
            /* Let the parent process know. */
            if (global_ld.inpkts_to_sync_pipe) {
                /* do sync here */
                libpcap_dump_flush(global_ld.pdh, NULL);

                /* Send our parent a message saying we've written out
                   "global_ld.inpkts_to_sync_pipe" packets to the capture file. */
                if (!quiet)
                    report_packet_count(global_ld.inpkts_to_sync_pipe);

                global_ld.inpkts_to_sync_pipe = 0;
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
                if (!do_file_switch_or_stop(capture_opts, cnd_autostop_files,
                                            cnd_autostop_size, cnd_file_duration))
                    continue;
            } /* cnd_file_duration */
        }
    }

    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Capture loop stopping ...");
    if (use_threads) {
        pcap_queue_element *queue_element;

        for (i = 0; i < global_ld.pcaps->len; i++) {
            pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, i);
            g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Waiting for thread of interface %u...",
                  pcap_opts->interface_id);
            g_thread_join(pcap_opts->tid);
            g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO, "Thread of interface %u terminated.",
                  pcap_opts->interface_id);
        }
        while (1) {
            g_async_queue_lock(pcap_queue);
            queue_element = g_async_queue_try_pop_unlocked(pcap_queue);
            if (queue_element) {
                pcap_queue_bytes -= queue_element->phdr.caplen;
                pcap_queue_packets -= 1;
            }
            g_async_queue_unlock(pcap_queue);
            if (queue_element == NULL) {
                break;
            }
            g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO,
                  "Dequeued a packet of length %d captured on interface %d.",
                  queue_element->phdr.caplen, queue_element->pcap_opts->interface_id);
            capture_loop_write_packet_cb((u_char *)queue_element->pcap_opts,
                                         &queue_element->phdr,
                                         queue_element->pd);
            g_free(queue_element->pd);
            g_free(queue_element);
            global_ld.inpkts_to_sync_pipe += 1;
            if (capture_opts->output_to_pipe) {
                libpcap_dump_flush(global_ld.pdh, NULL);
            }
        }
    }


    /* delete stop conditions */
    if (cnd_file_duration != NULL)
        cnd_delete(cnd_file_duration);
    if (cnd_autostop_files != NULL)
        cnd_delete(cnd_autostop_files);
    if (cnd_autostop_size != NULL)
        cnd_delete(cnd_autostop_size);
    if (cnd_autostop_duration != NULL)
        cnd_delete(cnd_autostop_duration);

    /* did we have a pcap (input) error? */
    for (i = 0; i < capture_opts->ifaces->len; i++) {
        pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, i);
        if (pcap_opts->pcap_err) {
            /* On Linux, if an interface goes down while you're capturing on it,
               you'll get a "recvfrom: Network is down" or
               "The interface went down" error (ENETDOWN).
               (At least you will if g_strerror() doesn't show a local translation
               of the error.)

               On FreeBSD and OS X, if a network adapter disappears while
               you're capturing on it, you'll get a "read: Device not configured"
               error (ENXIO).  (See previous parenthetical note.)

               On OpenBSD, you get "read: I/O error" (EIO) in the same case.

               These should *not* be reported to the Wireshark developers. */
            char *cap_err_str;

            cap_err_str = pcap_geterr(pcap_opts->pcap_h);
            if (strcmp(cap_err_str, "recvfrom: Network is down") == 0 ||
                strcmp(cap_err_str, "The interface went down") == 0 ||
                strcmp(cap_err_str, "read: Device not configured") == 0 ||
                strcmp(cap_err_str, "read: I/O error") == 0 ||
                strcmp(cap_err_str, "read error: PacketReceivePacket failed") == 0) {
                report_capture_error("The network adapter on which the capture was being done "
                                     "is no longer running; the capture has stopped.",
                                     "");
            } else {
                g_snprintf(errmsg, sizeof(errmsg), "Error while capturing packets: %s",
                           cap_err_str);
                report_capture_error(errmsg, please_report);
            }
            break;
        } else if (pcap_opts->from_cap_pipe && pcap_opts->cap_pipe_err == PIPERR) {
            report_capture_error(errmsg, "");
            break;
        }
    }
    /* did we have an output error while capturing? */
    if (global_ld.err == 0) {
        write_ok = TRUE;
    } else {
        capture_loop_get_errmsg(errmsg, sizeof(errmsg), capture_opts->save_file,
                                global_ld.err, FALSE);
        report_capture_error(errmsg, please_report);
        write_ok = FALSE;
    }

    if (capture_opts->saving_to_file) {
        /* close the output file */
        close_ok = capture_loop_close_output(capture_opts, &global_ld, &err_close);
    } else
        close_ok = TRUE;

    /* there might be packets not yet notified to the parent */
    /* (do this after closing the file, so all packets are already flushed) */
    if(global_ld.inpkts_to_sync_pipe) {
        if (!quiet)
            report_packet_count(global_ld.inpkts_to_sync_pipe);
        global_ld.inpkts_to_sync_pipe = 0;
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

    report_capture_count(TRUE);

    /* get packet drop statistics from pcap */
    for (i = 0; i < capture_opts->ifaces->len; i++) {
        guint32 received;
        guint32 dropped;

        pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, i);
        interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
        received = pcap_opts->received;
        dropped = pcap_opts->dropped;
        if (pcap_opts->pcap_h != NULL) {
            g_assert(!pcap_opts->from_cap_pipe);
            /* Get the capture statistics, so we know how many packets were dropped. */
            if (pcap_stats(pcap_opts->pcap_h, stats) >= 0) {
                *stats_known = TRUE;
                /* Let the parent process know. */
                dropped += stats->ps_drop;
            } else {
                g_snprintf(errmsg, sizeof(errmsg),
                           "Can't get packet-drop statistics: %s",
                           pcap_geterr(pcap_opts->pcap_h));
                report_capture_error(errmsg, please_report);
            }
        }
        report_packet_drops(received, dropped, interface_opts.name);
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
        if (global_ld.save_file_fd != -1) {
            ws_close(global_ld.save_file_fd);
        }

        /* We couldn't even start the capture, so get rid of the capture
           file. */
        if (capture_opts->save_file != NULL) {
            ws_unlink(capture_opts->save_file);
            g_free(capture_opts->save_file);
        }
    }
    capture_opts->save_file = NULL;
    if (cfilter_error)
        report_cfilter_error(capture_opts, error_index, errmsg);
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
    guint i;
    pcap_options *pcap_opts;

    for (i = 0; i < global_ld.pcaps->len; i++) {
        pcap_opts = g_array_index(global_ld.pcaps, pcap_options *, i);
        if (pcap_opts->pcap_h != NULL)
            pcap_breakloop(pcap_opts->pcap_h);
    }
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

    default:
        if (is_close) {
            g_snprintf(errmsg, errmsglen,
                       "The file to which the capture was being saved\n"
                       "(\"%s\") could not be closed: %s.",
                       fname, g_strerror(err));
        } else {
            g_snprintf(errmsg, errmsglen,
                       "An error occurred while writing to the file"
                       " to which the capture was being saved\n"
                       "(\"%s\"): %s.",
                       fname, g_strerror(err));
        }
        break;
    }
}


/* one packet was captured, process it */
static void
capture_loop_write_packet_cb(u_char *pcap_opts_p, const struct pcap_pkthdr *phdr,
                             const u_char *pd)
{
    pcap_options *pcap_opts = (pcap_options *) (void *) pcap_opts_p;
    int err;

    /* We may be called multiple times from pcap_dispatch(); if we've set
       the "stop capturing" flag, ignore this packet, as we're not
       supposed to be saving any more packets. */
    if (!global_ld.go)
        return;

    if (global_ld.pdh) {
        gboolean successful;

        /* We're supposed to write the packet to a file; do so.
           If this fails, set "ld->go" to FALSE, to stop the capture, and set
           "ld->err" to the error. */
        if (global_capture_opts.use_pcapng) {
            successful = libpcap_write_enhanced_packet_block(global_ld.pdh, phdr, pcap_opts->interface_id, pd, &global_ld.bytes_written, &err);
        } else {
            successful = libpcap_write_packet(global_ld.pdh, phdr, pd, &global_ld.bytes_written, &err);
        }
        if (!successful) {
            global_ld.go = FALSE;
            global_ld.err = err;
        } else {
            g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO,
                  "Wrote a packet of length %d captured on interface %u.",
                   phdr->caplen, pcap_opts->interface_id);
            global_ld.packet_count++;
            pcap_opts->received++;
            /* if the user told us to stop after x packets, do we already have enough? */
            if ((global_ld.packet_max > 0) && (global_ld.packet_count >= global_ld.packet_max)) {
                global_ld.go = FALSE;
            }
        }
    }
}

/* one packet was captured, queue it */
static void
capture_loop_queue_packet_cb(u_char *pcap_opts_p, const struct pcap_pkthdr *phdr,
                             const u_char *pd)
{
    pcap_options *pcap_opts = (pcap_options *) (void *) pcap_opts_p;
    pcap_queue_element *queue_element;
    gboolean limit_reached;

    /* We may be called multiple times from pcap_dispatch(); if we've set
       the "stop capturing" flag, ignore this packet, as we're not
       supposed to be saving any more packets. */
    if (!global_ld.go)
        return;

    queue_element = (pcap_queue_element *)g_malloc(sizeof(pcap_queue_element));
    if (queue_element == NULL) {
       pcap_opts->dropped++;
       return;
    }
    queue_element->pcap_opts = pcap_opts;
    queue_element->phdr = *phdr;
    queue_element->pd = (u_char *)g_malloc(phdr->caplen);
    if (queue_element->pd == NULL) {
        pcap_opts->dropped++;
        g_free(queue_element);
        return;
    }
    memcpy(queue_element->pd, pd, phdr->caplen);
    g_async_queue_lock(pcap_queue);
    if (((pcap_queue_byte_limit > 0) && (pcap_queue_bytes < pcap_queue_byte_limit)) &&
        ((pcap_queue_packet_limit > 0) && (pcap_queue_packets < pcap_queue_packet_limit))) {
        limit_reached = FALSE;
        g_async_queue_push_unlocked(pcap_queue, queue_element);
        pcap_queue_bytes += phdr->caplen;
        pcap_queue_packets += 1;
    } else {
        limit_reached = TRUE;
    }
    g_async_queue_unlock(pcap_queue);
    if (limit_reached) {
        pcap_opts->dropped++;
        g_free(queue_element->pd);
        g_free(queue_element);
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO,
              "Dropped a packet of length %d captured on interface %u.",
              phdr->caplen, pcap_opts->interface_id);
    } else {
        pcap_opts->received++;
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO,
              "Queued a packet of length %d captured on interface %u.",
              phdr->caplen, pcap_opts->interface_id);
    }
    /* I don't want to hold the mutex over the debug output. So the
       output may be wrong */
    g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_INFO,
          "Queue size is now %" G_GINT64_MODIFIER "d bytes (%" G_GINT64_MODIFIER "d packets)",
          pcap_queue_bytes, pcap_queue_packets);
}

/* And now our feature presentation... [ fade to music ] */
int
main(int argc, char *argv[])
{
    int                  opt;
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
#ifdef HAVE_BPF_IMAGE
    gboolean             print_bpf_code = FALSE;
#endif
    gboolean             machine_readable = FALSE;
    gboolean             print_statistics = FALSE;
    int                  status, run_once_args = 0;
    gint                 i;
    guint                j;
#if defined(__APPLE__) && defined(__LP64__)
    struct utsname       osinfo;
#endif
    GString             *str;

#ifdef _WIN32
    arg_list_utf_16to8(argc, argv);
#endif /* _WIN32 */

#ifdef _WIN32
    /*
     * Initialize our DLL search path. MUST be called before LoadLibrary
     * or g_module_open.
     */
    ws_init_dll_search_path();
#endif

#ifdef HAVE_PCAP_REMOTE
#define OPTSTRING_A "A:"
#define OPTSTRING_r "r"
#define OPTSTRING_u "u"
#else
#define OPTSTRING_A ""
#define OPTSTRING_r ""
#define OPTSTRING_u ""
#endif

#ifdef HAVE_PCAP_SETSAMPLING
#define OPTSTRING_m "m:"
#else
#define OPTSTRING_m ""
#endif

#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
#define OPTSTRING_B "B:"
#else
#define OPTSTRING_B ""
#endif  /* _WIN32 or HAVE_PCAP_CREATE */

#ifdef HAVE_PCAP_CREATE
#define OPTSTRING_I "I"
#else
#define OPTSTRING_I ""
#endif

#ifdef HAVE_BPF_IMAGE
#define OPTSTRING_d "d"
#else
#define OPTSTRING_d ""
#endif

#define OPTSTRING "a:" OPTSTRING_A "b:" OPTSTRING_B "c:" OPTSTRING_d "Df:ghi:" OPTSTRING_I "L" OPTSTRING_m "MnpPq" OPTSTRING_r "Ss:t" OPTSTRING_u "vw:y:Z:"

#ifdef DEBUG_CHILD_DUMPCAP
    if ((debug_log = ws_fopen("dumpcap_debug_log.tmp","w")) == NULL) {
        fprintf (stderr, "Unable to open debug log file !\n");
        exit (1);
    }
#endif

#if defined(__APPLE__) && defined(__LP64__)
    /*
     * Is this Mac OS X 10.6.0, 10.6.1, 10.6.3, or 10.6.4?  If so, we need
     * a bug workaround - timeouts less than 1 second don't work with libpcap
     * in 64-bit code.  (The bug was introduced in 10.6, fixed in 10.6.2,
     * re-introduced in 10.6.3, not fixed in 10.6.4, and fixed in 10.6.5.
     * The problem is extremely unlikely to be reintroduced in a future
     * release.)
     */
    if (uname(&osinfo) == 0) {
        /*
         * Mac OS X 10.x uses Darwin {x+4}.0.0.  Mac OS X 10.x.y uses Darwin
         * {x+4}.y.0 (except that 10.6.1 appears to have a uname version
         * number of 10.0.0, not 10.1.0 - go figure).
         */
        if (strcmp(osinfo.release, "10.0.0") == 0 ||    /* 10.6, 10.6.1 */
            strcmp(osinfo.release, "10.3.0") == 0 ||    /* 10.6.3 */
            strcmp(osinfo.release, "10.4.0") == 0)              /* 10.6.4 */
            need_timeout_workaround = TRUE;
    }
#endif

    /*
     * Determine if dumpcap is being requested to run in a special
     * capture_child mode by going thru the command line args to see if
     * a -Z is present. (-Z is a hidden option).
     *
     * The primary result of running in capture_child mode is that
     * all messages sent out on stderr are in a special type/len/string
     * format to allow message processing by type.  These messages include
     * error messages if dumpcap fails to start the operation it was
     * requested to do, as well as various "status" messages which are sent
     * when an actual capture is in progress, and a "success" message sent
     * if dumpcap was requested to perform an operation other than a
     * capture.
     *
     * Capture_child mode would normally be requested by a parent process
     * which invokes dumpcap and obtains dumpcap stderr output via a pipe
     * to which dumpcap stderr has been redirected.  It might also have
     * another pipe to obtain dumpcap stdout output; for operations other
     * than a capture, that information is formatted specially for easier
     * parsing by the parent process.
     *
     * Capture_child mode needs to be determined immediately upon
     * startup so that any messages generated by dumpcap in this mode
     * (eg: during initialization) will be formatted properly.
     */

    for (i=1; i<argc; i++) {
        if (strcmp("-Z", argv[i]) == 0) {
            capture_child = TRUE;
            machine_readable = TRUE;  /* request machine-readable output */
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

    /* Initialize the pcaps list */
    global_ld.pcaps = g_array_new(FALSE, FALSE, sizeof(pcap_options *));

#if !GLIB_CHECK_VERSION(2,31,0)
    /* Initialize the thread system */
    g_thread_init(NULL);
#endif

#ifdef _WIN32
    /* Load wpcap if possible. Do this before collecting the run-time version information */
    load_wpcap();

    /* ... and also load the packet.dll from wpcap */
    /* XXX - currently not required, may change later. */
    /*wpcap_packet_load();*/

    /* Start windows sockets */
    WSAStartup( MAKEWORD( 1, 1 ), &wsaData );

    /* Set handler for Ctrl+C key */
    SetConsoleCtrlHandler(capture_cleanup_handler, TRUE);
#else
    /* Catch SIGINT and SIGTERM and, if we get either of them, clean up
       and exit. */
    action.sa_handler = capture_cleanup_handler;
    /*
     * Arrange that system calls not get restarted, because when
     * our signal handler returns we don't want to restart
     * a call that was waiting for packets to arrive.
     */
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGPIPE, &action, NULL);
    sigaction(SIGHUP, NULL, &oldaction);
    if (oldaction.sa_handler == SIG_DFL)
        sigaction(SIGHUP, &action, NULL);

#ifdef SIGINFO
    /* Catch SIGINFO and, if we get it and we're capturing in
       quiet mode, report the number of packets we've captured. */
    action.sa_handler = report_counts_siginfo;
    action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINFO, &action, NULL);
#endif /* SIGINFO */
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
    /*        be able to stop dumpcap using a signal (INT, TERM, etc).   */
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
    /*       longer required (similar to capture).                       */
    /*                                                                   */
    /* ----------------------------------------------------------------- */

    init_process_policies();

#ifdef HAVE_LIBCAP
    /* If 'started with special privileges' (and using libcap)  */
    /*   Set to keep only NET_RAW and NET_ADMIN capabilities;   */
    /*   Set euid/egid = ruid/rgid to remove suid privileges    */
    relinquish_privs_except_capture();
#endif

    /* Set the initial values in the capture options. This might be overwritten
       by the command line parameters. */
    capture_opts_init(&global_capture_opts, NULL);

    /* We always save to a file - if no file was specified, we save to a
       temporary file. */
    global_capture_opts.saving_to_file      = TRUE;
    global_capture_opts.has_ring_num_files  = TRUE;

    /* Now get our args */
    while ((opt = getopt(argc, argv, OPTSTRING)) != -1) {
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
            get_compiled_version_info(comp_info_str, NULL, NULL);

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
        case 'P':        /* Use pcap format */
        case 's':        /* Set the snapshot (capture) length */
        case 'w':        /* Write to capture file x */
        case 'g':        /* enable group read accesson file(s) */
        case 'y':        /* Set the pcap data link type */
#ifdef HAVE_PCAP_REMOTE
        case 'u':        /* Use UDP for data transfer */
        case 'r':        /* Capture own RPCAP traffic too */
        case 'A':        /* Authentication */
#endif
#ifdef HAVE_PCAP_SETSAMPLING
        case 'm':        /* Sampling */
#endif
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
        case 'B':        /* Buffer size */
#endif /* _WIN32 or HAVE_PCAP_CREATE */
#ifdef HAVE_PCAP_CREATE
        case 'I':        /* Monitor mode */
#endif
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

        case 'q':        /* Quiet */
            quiet = TRUE;
            break;
        case 't':
            use_threads = TRUE;
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
#ifdef HAVE_BPF_IMAGE
        case 'd':        /* Print BPF code for capture filter and exit */
            print_bpf_code = TRUE;
            run_once_args++;
            break;
#endif
        case 'S':        /* Print interface statistics once a second */
            print_statistics = TRUE;
            run_once_args++;
            break;
        case 'M':        /* For -D, -L, and -S, print machine-readable output */
            machine_readable = TRUE;
            break;
        default:
            cmdarg_err("Invalid Option: %s", argv[optind-1]);
            /* FALLTHROUGH */
        case '?':        /* Bad flag - print usage message */
            arg_error = TRUE;
            break;
        }
    }
    if (!arg_error) {
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
    }

    if (arg_error) {
        print_usage(FALSE);
        exit_main(1);
    }

    if (run_once_args > 1) {
        cmdarg_err("Only one of -D, -L, or -S may be supplied.");
        exit_main(1);
    } else if (run_once_args == 1) {
        /* We're supposed to print some information, rather than
           to capture traffic; did they specify a ring buffer option? */
        if (global_capture_opts.multi_files_on) {
            cmdarg_err("Ring buffer requested, but a capture isn't being done.");
            exit_main(1);
        }
    } else {
        /* We're supposed to capture traffic; */
        /* Are we capturing on multiple interface? If so, use threads and pcapng. */
        if (global_capture_opts.ifaces->len > 1) {
            use_threads = TRUE;
            global_capture_opts.use_pcapng = TRUE;
        }
        /* Was the ring buffer option specified and, if so, does it make sense? */
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
#if 0
                /* XXX - this must be redesigned as the conditions changed */
                global_capture_opts.multi_files_on = FALSE;
#endif
            }
        }
    }

    /*
     * "-D" requires no interface to be selected; it's supposed to list
     * all interfaces.
     */
    if (list_interfaces) {
        /* Get the list of interfaces */
        GList       *if_list;
        int         err;
        gchar       *err_str;

        if_list = capture_interface_list(&err, &err_str);
        if (if_list == NULL) {
            switch (err) {
            case CANT_GET_INTERFACE_LIST:
            case DONT_HAVE_PCAP:
                cmdarg_err("%s", err_str);
                g_free(err_str);
                exit_main(2);
                break;

            case NO_INTERFACES_FOUND:
                /*
                 * If we're being run by another program, just give them
                 * an empty list of interfaces, don't report this as
                 * an error; that lets them decide whether to report
                 * this as an error or not.
                 */
                if (!machine_readable) {
                    cmdarg_err("There are no interfaces on which a capture can be done");
                    exit_main(2);
                }
                break;
            }
        }

        if (machine_readable)      /* tab-separated values to stdout */
            print_machine_readable_interfaces(if_list);
        else
            capture_opts_print_interfaces(if_list);
        free_interface_list(if_list);
        exit_main(0);
    }

    /*
     * "-S" requires no interface to be selected; it gives statistics
     * for all interfaces.
     */
    if (print_statistics) {
        status = print_statistics_loop(machine_readable);
        exit_main(status);
    }

    /*
     * "-L", "-d", and capturing act on a particular interface, so we have to
     * have an interface; if none was specified, pick a default.
     */
    if (capture_opts_trim_iface(&global_capture_opts, NULL) == FALSE) {
        /* cmdarg_err() already called .... */
        exit_main(1);
    }

    /* Let the user know what interfaces were chosen. */
    /* get_interface_descriptive_name() is not available! */
    if (capture_child) {
        for (j = 0; j < global_capture_opts.ifaces->len; j++) {
            interface_options interface_opts;

            interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, j);
            g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "Interface: %s\n",
                  interface_opts.name);
        }
    } else {
        str = g_string_new("");
#ifdef _WIN32
        if (global_capture_opts.ifaces->len < 2) {
#else
        if (global_capture_opts.ifaces->len < 4) {
#endif
            for (j = 0; j < global_capture_opts.ifaces->len; j++) {
                interface_options interface_opts;

                interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, j);
                if (j > 0) {
                    if (global_capture_opts.ifaces->len > 2) {
                        g_string_append_printf(str, ",");
                    }
                    g_string_append_printf(str, " ");
                    if (j == global_capture_opts.ifaces->len - 1) {
                        g_string_append_printf(str, "and ");
                    }
                }
                g_string_append_printf(str, "%s", interface_opts.name);
            }
        } else {
            g_string_append_printf(str, "%u interfaces", global_capture_opts.ifaces->len);
        }
        fprintf(stderr, "Capturing on %s\n", str->str);
        g_string_free(str, TRUE);
    }

    if (list_link_layer_types) {
        /* Get the list of link-layer types for the capture device. */
        if_capabilities_t *caps;
        gchar *err_str;
        guint i;

        for (i = 0; i < global_capture_opts.ifaces->len; i++) {
            interface_options interface_opts;

            interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, i);
            caps = get_if_capabilities(interface_opts.name,
                                       interface_opts.monitor_mode, &err_str);
            if (caps == NULL) {
                cmdarg_err("The capabilities of the capture device \"%s\" could not be obtained (%s).\n"
                           "Please check to make sure you have sufficient permissions, and that\n"
                           "you have the proper interface or pipe specified.", interface_opts.name, err_str);
                g_free(err_str);
                exit_main(2);
            }
            if (caps->data_link_types == NULL) {
                cmdarg_err("The capture device \"%s\" has no data link types.", interface_opts.name);
                exit_main(2);
            }
            if (machine_readable)      /* tab-separated values to stdout */
                /* XXX: We need to change the format and adopt consumers */
                print_machine_readable_if_capabilities(caps);
            else
                /* XXX: We might want to print also the interface name */
                capture_opts_print_if_capabilities(caps, interface_opts.name,
                                                   interface_opts.monitor_mode);
            free_if_capabilities(caps);
        }
        exit_main(0);
    }

    /* We're supposed to do a capture, or print the BPF code for a filter.
       Process the snapshot length, as that affects the generated BPF code. */
    capture_opts_trim_snaplen(&global_capture_opts, MIN_PACKET_SIZE);

#ifdef HAVE_BPF_IMAGE
    if (print_bpf_code) {
        show_filter_code(&global_capture_opts);
        exit_main(0);
    }
#endif

    /* We're supposed to do a capture.  Process the ring buffer arguments. */
    capture_opts_trim_ring_num_files(&global_capture_opts);

    /* Now start the capture. */

    if(capture_loop_start(&global_capture_opts, &stats_known, &stats) == TRUE) {
        /* capture ok */
        exit_main(0);
    } else {
        /* capture failed */
        exit_main(1);
    }
    return 0; /* never here, make compiler happy */
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


static void
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

static void
report_new_capture_file(const char *filename)
{
    if(capture_child) {
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "File: %s", filename);
        pipe_write_block(2, SP_FILE, filename);
    } else {
#ifdef SIGINFO
        /*
         * Prevent a SIGINFO handler from writing to the standard error
         * while we're doing so; instead, have it just set a flag telling
         * us to print that information when we're done.
         */
        infodelay = TRUE;
#endif /* SIGINFO */
        fprintf(stderr, "File: %s\n", filename);
        /* stderr could be line buffered */
        fflush(stderr);

#ifdef SIGINFO
        /*
         * Allow SIGINFO handlers to write.
         */
        infodelay = FALSE;

        /*
         * If a SIGINFO handler asked us to write out capture counts, do so.
         */
        if (infoprint)
          report_counts_for_siginfo();
#endif /* SIGINFO */
    }
}

static void
report_cfilter_error(capture_options *capture_opts, guint i, const char *errmsg)
{
    interface_options interface_opts;
    char tmp[MSG_MAX_LENGTH+1+6];

    if (i < capture_opts->ifaces->len) {
        if (capture_child) {
            g_snprintf(tmp, sizeof(tmp), "%u:%s", i, errmsg);
            g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG, "Capture filter error: %s", errmsg);
            pipe_write_block(2, SP_BAD_FILTER, tmp);
        } else {
            /*
             * clopts_step_invalid_capfilter in test/suite-clopts.sh MUST match
             * the error message below.
             */
            interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);
            cmdarg_err(
              "Invalid capture filter: \"%s\" for interface %s!\n"
              "\n"
              "That string isn't a valid capture filter (%s).\n"
              "See the User's Guide for a description of the capture filter syntax.",
              interface_opts.cfilter, interface_opts.name, errmsg);
        }
    }
}

static void
report_capture_error(const char *error_msg, const char *secondary_error_msg)
{
    if(capture_child) {
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
            "Primary Error: %s", error_msg);
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
            "Secondary Error: %s", secondary_error_msg);
        sync_pipe_errmsg_to_parent(2, error_msg, secondary_error_msg);
    } else {
        cmdarg_err("%s", error_msg);
        if (secondary_error_msg[0] != '\0')
          cmdarg_err_cont("%s", secondary_error_msg);
    }
}

static void
report_packet_drops(guint32 received, guint32 drops, gchar *name)
{
    char tmp[SP_DECISIZE+1+1];

    g_snprintf(tmp, sizeof(tmp), "%u", drops);

    if(capture_child) {
        g_log(LOG_DOMAIN_CAPTURE_CHILD, G_LOG_LEVEL_DEBUG,
            "Packets received/dropped on interface %s: %u/%u",
            name, received, drops);
        /* XXX: Need to provide interface id, changes to consumers required. */
        pipe_write_block(2, SP_DROPS, tmp);
    } else {
        fprintf(stderr,
            "Packets received/dropped on interface %s: %u/%u (%.1f%%)\n",
            name, received, drops,
            received ? 100.0 * received / (received + drops) : 0.0);
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

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
