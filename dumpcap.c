/* dumpcap.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#define WS_LOG_DOMAIN LOG_DOMAIN_CAPCHILD

#include <stdio.h>
#include <stdlib.h> /* for exit() */
#include <glib.h>

#include <string.h>

#include <ws_exit_codes.h>

#include <sys/types.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <wsutil/ws_getopt.h>

#if defined(__APPLE__) && defined(__LP64__)
#include <sys/utsname.h>
#endif

#include <signal.h>
#include <errno.h>

#include <wsutil/array.h>
#include <wsutil/cmdarg_err.h>
#include <wsutil/strtoi.h>
#include <cli_main.h>
#include <wsutil/version_info.h>

#include <wsutil/socket.h>
#include <wsutil/wslog.h>
#include <wsutil/file_util.h>

#ifdef HAVE_LIBCAP
# include <sys/prctl.h>
# include <sys/capability.h>
#endif

#include "ringbuffer.h"

#include "capture/capture_ifinfo.h"
#include "capture/capture-pcap-util.h"
#include "capture/capture-pcap-util-int.h"
#ifdef _WIN32
#include "capture/capture-wpcap.h"
#endif /* _WIN32 */

#include "writecap/pcapio.h"

#ifndef _WIN32
#include <sys/un.h>
#endif

#include <wsutil/clopts_common.h>
#include <wsutil/privileges.h>

#include "sync_pipe.h"

#include "capture_opts.h"
#include <capture/capture_session.h>
#include <capture/capture_sync.h>

#include "wsutil/tempfile.h"
#include "wsutil/file_util.h"
#include "wsutil/cpu_info.h"
#include "wsutil/os_version_info.h"
#include "wsutil/str_util.h"
#include "wsutil/inet_addr.h"
#include "wsutil/time_util.h"
#include "wsutil/please_report_bug.h"
#include "wsutil/glib-compat.h"
#include <wsutil/json_dumper.h>
#include <wsutil/ws_assert.h>

#include "capture/ws80211_utils.h"

#include "extcap.h"

/*
 * Get information about libpcap format from "wiretap/libpcap.h".
 * Get information about pcapng format from "wiretap/pcapng_module.h".
 * XXX - can we just use pcap_open_offline() to read the pipe?
 */
#include "wiretap/libpcap.h"
#include "wiretap/pcapng_module.h"
#include "wiretap/pcapng.h"

/*
 * Define these for extra logging. Note that when dumpcap is spawned as
 * a child process, logs are sent to the parent via the sync pipe.
 * The parent will pass along the Capchild domain log level settings,
 * so "--log-debug Capchild" or "--log-level debug" can be used to get
 * debugging from dumpcap sent to the parent.
 */
//#define DEBUG_DUMPCAP       /* Waits for keypress on quitting on Windows */
//#define DEBUG_CHILD_DUMPCAP /* Writes logs to file */

#ifdef _WIN32
#include "wsutil/win32-utils.h"
#ifdef DEBUG_DUMPCAP
#include <conio.h>          /* _getch() */
#endif
#endif

#ifdef DEBUG_CHILD_DUMPCAP
FILE *debug_log;   /* for logging debug messages to  */
                   /*  a file if DEBUG_CHILD_DUMPCAP */
                   /*  is defined                    */
#include <stdarg.h> /* va_copy */
#endif

static GAsyncQueue *pcap_queue;
static int64_t pcap_queue_bytes;
static int64_t pcap_queue_packets;
static int64_t pcap_queue_byte_limit;
static int64_t pcap_queue_packet_limit;

static bool capture_child; /* false: standalone call, true: this is an Wireshark capture child */
static const char *report_capture_filename; /* capture child file name */
#ifdef _WIN32
static char *sig_pipe_name;
static HANDLE sig_pipe_handle;
static bool signal_pipe_check_running(void);
#endif
static int sync_pipe_fd = 2;

#ifdef ENABLE_ASAN
/* This has public visibility so that if compiled with shared libasan (the
 * gcc default) function interposition occurs.
 */
WS_DLL_PUBLIC int
__lsan_is_turned_off(void)
{
    /* If we're in capture child mode, don't run a LSan report and
     * send it to stderr, because it isn't properly formatted for
     * the sync pipe.
     * We could, if debugging variables are set, send the reports
     * elsewhere instead, by calling __sanitizer_set_report_path()
     * or __sanitizer_set_report_fd()
     */
    if (capture_child) {
        return 1;
    }
#ifdef HAVE_LIBCAP
    /* LSan dies with a fatal error without explanation if it can't ptrace.
     * Normally, the "dumpable" attribute (which also controls ptracing)
     * is set to 1 (SUID_DUMP_USER, process is dumpable.) However, it is
     * reset to the current value in /proc/sys/fs/suid_dumpable in the
     * following circumstances: euid/egid changes, fsuid/fsgid changes,
     * execve of a setuid or setgid program that changes the euid or egid,
     * execve of a program with capabilities exceeding those already
     * permitted for the process.
     *
     * Unless we're running as root, one of those applies to dumpcap.
     *
     * The default value of /proc/sys/fs/suid_dumpable is 0, SUID_DUMP_DISABLE.
     * In such a case, LeakSanitizer temporarily sets the value to 1 to
     * allow ptracing, and then sets it back to 0.
     *
     * Another possible value, used by Ubuntu, Fedora, etc., is 2,
     * which creates dumps readable by root only. For security reasons,
     * unprivileged programs are not allowed to change the value to 2.
     * (See https://nvd.nist.gov/vuln/detail/CVE-2006-2451 )
     *
     * LSan does not check for the value 2 and change dumpable to 1 in that
     * case, possibly because if it did it could not change it back to 2
     * and would have to either leave the process dumpable or change it to 0.
     *
     * The usual way to control the family of sanitizers is through environment
     * variables. However, complicating things, changing the dumpable attribute
     * to 0 or 2 changes the ownership of files in /proc/[pid] (including
     * /proc/self ) to root:root, in particular /proc/[pid]/environ, and so
     * ASAN_OPTIONS=detect_leaks=0 has no effect. (Unless the process has
     * CAP_SYS_PTRACE, which allows tracing of any process, but that's also
     * a security risk and we'll have dropped that with other privileges.)
     *
     * So if prctl(PR_GET_DUMPABLE) returns 2, we know that the process will
     * die with a fatal error if it attempts to run LSan, so don't.
     *
     * See proc(5), prctl(2), ptrace(2), and
     * https://github.com/google/sanitizers/issues/1306
     * https://github.com/llvm/llvm-project/issues/55944
     */
    if (prctl(PR_GET_DUMPABLE) == 2) {
        ws_debug("Not running LeakSanitizer because /proc/sys/fs/suid_dumpable is 2");
        return 1;
    }
#endif
    return 0;
}

WS_DLL_PUBLIC const char*
__asan_default_options(void)
{
    /* By default don't override our exit code if there's a leak or error.
     * We particularly don't want to do this if running as a capture child,
     * because capture/capture_sync doesn't expect the ASan exit codes.
     */
    return "exitcode=0";
}
#endif

#ifdef SIGINFO
static bool infodelay;      /* if true, don't print capture info in SIGINFO handler */
static bool infoprint;      /* if true, print capture info after clearing infodelay */
#endif /* SIGINFO */

/** Stop a low-level capture (stops the capture child). */
static void capture_loop_stop(void);
/** Close a pipe, or socket if \a from_socket is true */
static void cap_pipe_close(int pipe_fd, bool from_socket);

#if defined (__linux__)
/* whatever the deal with pcap_breakloop, linux doesn't support timeouts
 * in pcap_dispatch(); on the other hand, select() works just fine there.
 * Hence we use a select for that come what may.
 *
 * XXX - with TPACKET_V1 and TPACKET_V2, it currently uses select()
 * internally, and, with TPACKET_V3, once that's supported, it'll
 * support timeouts, at least as I understand the way the code works.
 */
#define MUST_DO_SELECT
#endif

/** init the capture filter */
typedef enum {
    INITFILTER_NO_ERROR,
    INITFILTER_BAD_FILTER,
    INITFILTER_OTHER_ERROR
} initfilter_status_t;

typedef enum {
    STATE_EXPECT_REC_HDR,
    STATE_READ_REC_HDR,
    STATE_EXPECT_DATA,
    STATE_READ_DATA
} cap_pipe_state_t;

typedef enum {
    PIPOK,
    PIPEOF,
    PIPERR,
    PIPNEXIST
} cap_pipe_err_t;

typedef struct _pcap_pipe_info {
    bool                         byte_swapped; /**< true if data in the pipe is byte swapped. */
    struct pcap_hdr              hdr;          /**< Pcap header when capturing from a pipe */
    struct pcaprec_modified_hdr  rechdr;       /**< Pcap record header when capturing from a pipe */
} pcap_pipe_info_t;

typedef struct _pcapng_pipe_info {
    pcapng_block_header_t bh;                  /**< Pcapng general block header when capturing from a pipe */
    GArray *src_iface_to_global;               /**< Int array mapping local IDB numbers to global_ld.interface_data */
} pcapng_pipe_info_t;

struct _loop_data; /* forward declaration so we can use it in the cap_pipe_dispatch function pointer */

/*
 * A source of packets from which we're capturing.
 */
typedef struct _capture_src {
    uint32_t                     received;
    uint32_t                     dropped;
    uint32_t                     flushed;
    pcap_t                      *pcap_h;
#ifdef MUST_DO_SELECT
    int                          pcap_fd;                /**< pcap file descriptor */
#endif
    bool                         pcap_err;
    unsigned                     interface_id;
    unsigned                     idb_id;                 /**< If from_pcapng is false, the output IDB interface ID. Otherwise the mapping in src_iface_to_global is used. */
    GThread                     *tid;
    int                          snaplen;
    int                          linktype;
    bool                         ts_nsec;                /**< true if we're using nanosecond precision. */
                                                         /**< capture pipe (unix only "input file") */
    bool                         from_cap_pipe;          /**< true if we are capturing data from a capture pipe */
    bool                         from_cap_socket;        /**< true if we're capturing from socket */
    bool                         from_pcapng;            /**< true if we're capturing from pcapng format */
    union {
        pcap_pipe_info_t         pcap;                   /**< Pcap info when capturing from a pipe */
        pcapng_pipe_info_t       pcapng;                 /**< Pcapng info when capturing from a pipe */
    } cap_pipe_info;
#ifdef _WIN32
    HANDLE                       cap_pipe_h;             /**< The handle of the capture pipe */
#endif
    int                          cap_pipe_fd;            /**< the file descriptor of the capture pipe */
    bool                         cap_pipe_modified;      /**< true if data in the pipe uses modified pcap headers */
    char *                       cap_pipe_databuf;       /**< Pointer to the data buffer we've allocated */
    size_t                       cap_pipe_databuf_size;  /**< Current size of the data buffer */
    unsigned                     cap_pipe_max_pkt_size;  /**< Maximum packet size allowed */
#if defined(_WIN32)
    char *                       cap_pipe_buf;           /**< Pointer to the buffer we read into */
    DWORD                        cap_pipe_bytes_to_read; /**< Used by cap_pipe_dispatch */
    DWORD                        cap_pipe_bytes_read;    /**< Used by cap_pipe_dispatch */
#else
    size_t                       cap_pipe_bytes_to_read; /**< Used by cap_pipe_dispatch */
    size_t                       cap_pipe_bytes_read;    /**< Used by cap_pipe_dispatch */
#endif
    int (*cap_pipe_dispatch)(struct _loop_data *, struct _capture_src *, char *, size_t);
    cap_pipe_state_t cap_pipe_state;
    cap_pipe_err_t cap_pipe_err;

#if defined(_WIN32)
    GMutex                      *cap_pipe_read_mtx;
    GAsyncQueue                 *cap_pipe_pending_q, *cap_pipe_done_q;
#endif
} capture_src;

typedef struct _saved_idb {
    bool deleted;
    unsigned interface_id; /* capture_src->interface_id for the associated SHB */
    uint8_t *idb;        /* If non-NULL, IDB read from capture_src. This is an interface specified on the command line otherwise. */
    unsigned idb_len;
} saved_idb_t;

/*
 * Global capture loop state.
 */
typedef struct _loop_data {
    /* common */
    bool      go;                  /**< true as long as we're supposed to keep capturing */
    int       err;                 /**< if non-zero, error seen while capturing */
    int       packets_captured;    /**< Number of packets we have already captured */
    unsigned  inpkts_to_sync_pipe; /**< Packets not already send out to the sync_pipe */
#ifdef SIGINFO
    bool      report_packet_count; /**< Set by SIGINFO handler; print packet count */
#endif
    GArray   *pcaps;               /**< Array of capture_src's on which we're capturing */
    bool      pcapng_passthrough;  /**< We have one source and it's pcapng. Pass its SHB and IDBs through. */
    uint8_t  *saved_shb;           /**< SHB to write when we have one pcapng input */
    GArray   *saved_idbs;          /**< Array of saved_idb_t, written when we have a new section or output file. */
    GRWLock   saved_shb_idb_lock;  /**< Saved IDB RW mutex */
    /* output file(s) */
    FILE     *pdh;
    int       save_file_fd;
    char     *io_buffer;           /**< Our IO buffer if we increase the size from the standard size */
    uint64_t  bytes_written;       /**< Bytes written for the current file. */
    /* autostop conditions */
    int       packets_written;     /**< Packets written for the current file. */
    int       file_count;
    /* ring buffer conditions */
    GTimer  *file_duration_timer;
    time_t   next_interval_time;
    int      interval_s;
} loop_data;

typedef struct _pcap_queue_element {
    capture_src        *pcap_src;
    union {
        struct pcap_pkthdr  phdr;
        pcapng_block_header_t  bh;
    } u;
    uint8_t             *pd;
} pcap_queue_element;

/*
 * This needs to be static, so that the SIGINT handler can clear the "go"
 * flag and for saved_shb_idb_lock.
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
static bool need_timeout_workaround;

#define CAP_READ_TIMEOUT        (need_timeout_workaround ? 1000 : 250)
#else
#define CAP_READ_TIMEOUT        250
#endif

/*
 * Timeout, in microseconds, for reads from the stream of captured packets
 * from a pipe.  Pipes don't have the same problem that BPF devices do
 * in Mac OS X 10.6, 10.6.1, 10.6.3, and 10.6.4, so we always use a timeout
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
dumpcap_log_writer(const char *domain, enum ws_log_level level,
                                   const char *file, long line, const char *func,
                                   const char *fatal_msg, ws_log_manifest_t *mft,
                                   const char *user_format, va_list user_ap,
                                   void *user_data);

/* capture related options */
static capture_options global_capture_opts;
static GPtrArray *capture_comments;
static bool quiet;
static bool really_quiet;
static bool use_threads;
static uint64_t start_time;

static void capture_loop_write_packet_cb(uint8_t *pcap_src_p, const struct pcap_pkthdr *phdr,
                                         const uint8_t *pd);
static void capture_loop_queue_packet_cb(uint8_t *pcap_src_p, const struct pcap_pkthdr *phdr,
                                         const uint8_t *pd);
static void capture_loop_write_pcapng_cb(capture_src *pcap_src, const pcapng_block_header_t *bh, uint8_t *pd);
static void capture_loop_queue_pcapng_cb(capture_src *pcap_src, const pcapng_block_header_t *bh, uint8_t *pd);
static void capture_loop_get_errmsg(char *errmsg, size_t errmsglen,
                                    char *secondary_errmsg,
                                    size_t secondary_errmsglen,
                                    const char *fname, int err,
                                    bool is_close);

WS_NORETURN static void exit_main(int err);

static void report_new_capture_file(const char *filename);
static void report_packet_count(unsigned int packet_count);
static void report_packet_drops(uint32_t received, uint32_t pcap_drops, uint32_t drops, uint32_t flushed, uint32_t ps_ifdrop, char *name);
static void report_capture_error(const char *error_msg, const char *secondary_error_msg);
static void report_cfilter_error(capture_options *capture_opts, unsigned i, const char *errmsg);

#define MSG_MAX_LENGTH 4096

static void
print_usage(FILE *output)
{
    fprintf(output, "\nUsage: dumpcap [options] ...\n");
    fprintf(output, "\n");
    fprintf(output, "Capture interface:\n");
    fprintf(output, "  -i <interface>, --interface <interface>\n");
    fprintf(output, "                           name or idx of interface (def: first non-loopback),\n"
#ifdef HAVE_PCAP_REMOTE
                    "                           or for remote capturing, use one of these formats:\n"
                    "                               rpcap://<host>/<interface>\n"
#else
                    "                           or for remote capturing, use this format:\n"
#endif
                    "                               TCP@<host>:<port>\n");
    fprintf(output, "  --ifname <name>          name to use in the capture file for a pipe from which\n");
    fprintf(output, "                           we're capturing\n");
    fprintf(output, "  --ifdescr <description>\n");
    fprintf(output, "                           description to use in the capture file for a pipe\n");
    fprintf(output, "                           from which we're capturing\n");
    fprintf(output, "  -f <capture filter>      packet filter in libpcap filter syntax\n");
    fprintf(output, "  -s <snaplen>, --snapshot-length <snaplen>\n");
#ifdef HAVE_PCAP_CREATE
    fprintf(output, "                           packet snapshot length (def: appropriate maximum)\n");
#else
    fprintf(output, "                           packet snapshot length (def: %u)\n", WTAP_MAX_PACKET_SIZE_STANDARD);
#endif
    fprintf(output, "  -p, --no-promiscuous-mode\n");
    fprintf(output, "                           don't capture in promiscuous mode\n");
#ifdef HAVE_PCAP_CREATE
    fprintf(output, "  -I, --monitor-mode       capture in monitor mode, if available\n");
#endif
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
    fprintf(output, "  -B <buffer size>, --buffer-size <buffer size>\n");
    fprintf(output, "                           size of kernel buffer in MiB (def: %dMiB)\n", DEFAULT_CAPTURE_BUFFER_SIZE);
#endif
    fprintf(output, "  -y <link type>, --linktype <link type>\n");
    fprintf(output, "                           link layer type (def: first appropriate)\n");
    fprintf(output, "  --time-stamp-type <type> timestamp method for interface\n");
    fprintf(output, "  -D, --list-interfaces    print list of interfaces and exit\n");
    fprintf(output, "  -L, --list-data-link-types\n");
    fprintf(output, "                           print list of link-layer types of iface and exit\n");
    fprintf(output, "  --list-time-stamp-types  print list of timestamp types for iface and exit\n");
    fprintf(output, "  --update-interval        interval between updates with new packets (def: %dms)\n", DEFAULT_UPDATE_INTERVAL);
    fprintf(output, "  -d                       print generated BPF code for capture filter\n");
    fprintf(output, "  -k <freq>,[<type>],[<center_freq1>],[<center_freq2>]\n");
    fprintf(output, "                           set channel on wifi interface\n");
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
    fprintf(output, "  -a <autostop cond.> ..., --autostop <autostop cond.> ...\n");
    fprintf(output, "                           duration:NUM - stop after NUM seconds\n");
    fprintf(output, "                           filesize:NUM - stop this file after NUM kB\n");
    fprintf(output, "                              files:NUM - stop after NUM files\n");
    fprintf(output, "                            packets:NUM - stop after NUM packets\n");
    /*fprintf(output, "\n");*/
    fprintf(output, "Output (files):\n");
    fprintf(output, "  -w <filename>            name of file to save (def: tempfile)\n");
    fprintf(output, "  -g                       enable group read access on the output file(s)\n");
    fprintf(output, "  -b <ringbuffer opt.> ..., --ring-buffer <ringbuffer opt.>\n");
    fprintf(output, "                           duration:NUM - switch to next file after NUM secs\n");
    fprintf(output, "                           filesize:NUM - switch to next file after NUM kB\n");
    fprintf(output, "                              files:NUM - ringbuffer: replace after NUM files\n");
    fprintf(output, "                            packets:NUM - ringbuffer: replace after NUM packets\n");
    fprintf(output, "                           interval:NUM - switch to next file when the time is\n");
    fprintf(output, "                                          an exact multiple of NUM secs\n");
    fprintf(output, "                          printname:FILE - print filename to FILE when written\n");
    fprintf(output, "                                           (can use 'stdout' or 'stderr')\n");
    fprintf(output, "  -n                       use pcapng format instead of pcap (default)\n");
    fprintf(output, "  -P                       use libpcap format instead of pcapng\n");
    fprintf(output, "  --capture-comment <comment>\n");
    fprintf(output, "                           add a capture comment to the output file\n");
    fprintf(output, "                           (only for pcapng)\n");
    fprintf(output, "  --temp-dir <directory>   write temporary files to this directory\n");
    fprintf(output, "                           (default: %s)\n", g_get_tmp_dir());
    fprintf(output, "\n");

    ws_log_print_usage(output);
    fprintf(output, "\n");

    fprintf(output, "Miscellaneous:\n");
    fprintf(output, "  -N <packet_limit>        maximum number of packets buffered within dumpcap\n");
    fprintf(output, "  -C <byte_limit>          maximum number of bytes used for buffering packets\n");
    fprintf(output, "                           within dumpcap\n");
    fprintf(output, "  -t                       use a separate thread per interface\n");
    fprintf(output, "  -q                       don't report packet capture counts\n");
    fprintf(output, "  -v, --version            print version information and exit\n");
    fprintf(output, "  -h, --help               display this help and exit\n");
    fprintf(output, "\n");
#ifdef __linux__
    fprintf(output, "Dumpcap can benefit from an enabled BPF JIT compiler if available.\n");
    fprintf(output, "You might want to enable it by executing:\n");
    fprintf(output, " \"echo 1 > /proc/sys/net/core/bpf_jit_enable\"\n");
    fprintf(output, "Note that this can make your system less secure!\n");
    fprintf(output, "\n");
#endif
    fprintf(output, "Example: dumpcap -i eth0 -a duration:60 -w output.pcapng\n");
    fprintf(output, "\"Capture packets from interface eth0 until 60s passed into output.pcapng\"\n");
    fprintf(output, "\n");
    fprintf(output, "Use Ctrl-C to stop capturing at any time.\n");
}

/*
 * Report an error in command-line arguments.
 * If we're a capture child, send a message back to the parent, otherwise
 * just print it.
 */
static void
dumpcap_cmdarg_err(const char *fmt, va_list ap)
{
    if (capture_child) {
        char *msg;
        /* Generate a 'special format' message back to parent */
        msg = ws_strdup_vprintf(fmt, ap);
        sync_pipe_write_errmsgs_to_parent(sync_pipe_fd, msg, "");
        g_free(msg);
    } else {
        fprintf(stderr, "dumpcap: ");
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
    }
}

/*
 * Report additional information for an error in command-line arguments.
 * If we're a capture child, send a message back to the parent, otherwise
 * just print it.
 */
static void
dumpcap_cmdarg_err_cont(const char *fmt, va_list ap)
{
    if (capture_child) {
        char *msg;
        msg = ws_strdup_vprintf(fmt, ap);
        sync_pipe_write_errmsgs_to_parent(sync_pipe_fd, msg, "");
        g_free(msg);
    } else {
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
    }
}

#ifdef HAVE_LIBCAP
static void
/* see 'man cap_to_text()' for explanation of output                         */
/* '='   means 'all= '  ie: no capabilities                                  */
/* '=ip' means 'all=ip' ie: all capabilities are permissible and inheritable */
/* ....                                                                      */
print_caps(const char *pfx) {
    if (ws_log_msg_is_active(WS_LOG_DOMAIN, LOG_LEVEL_NOISY)) {
        cap_t caps = cap_get_proc();
        char *caps_text = cap_to_text(caps, NULL);
        ws_noisy("%s: EUID: %d  Capabilities: %s", pfx, geteuid(), caps_text);
        cap_free(caps_text);
        cap_free(caps);
    }
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

static void
get_capture_device_open_failure_messages(cap_device_open_status open_status,
                                         const char *open_status_str,
                                         const char *iface,
                                         char *errmsg, size_t errmsg_len,
                                         char *secondary_errmsg,
                                         size_t secondary_errmsg_len)
{
    switch (open_status) {

    case CAP_DEVICE_OPEN_ERROR_NO_SUCH_DEVICE:
        snprintf(errmsg, errmsg_len,
                 "There is no device named \"%s\".\n(%s)",
                 iface, open_status_str);
        break;

    case CAP_DEVICE_OPEN_ERROR_RFMON_NOTSUP:
        snprintf(errmsg, errmsg_len,
                 "Capturing in monitor mode is not supported on device \"%s\".\n(%s)",
                 iface, open_status_str);
        break;

    case CAP_DEVICE_OPEN_ERROR_PERM_DENIED:
        snprintf(errmsg, errmsg_len,
                 "You do not have permission to capture on device \"%s\".\n(%s)",
                 iface, open_status_str);
        break;

    case CAP_DEVICE_OPEN_ERROR_IFACE_NOT_UP:
        snprintf(errmsg, errmsg_len,
                 "Device \"%s\" is not up.\n(%s)",
                 iface, open_status_str);
        break;

    case CAP_DEVICE_OPEN_ERROR_PROMISC_PERM_DENIED:
        snprintf(errmsg, errmsg_len,
                 "You do not have permission to capture in promiscuous mode on device \"%s\".\n(%s)",
                 iface, open_status_str);
        break;

    case CAP_DEVICE_OPEN_ERROR_OTHER:
    default:
        snprintf(errmsg, errmsg_len,
                 "The capture session could not be initiated on capture device \"%s\".\n(%s)",
                 iface, open_status_str);
        break;
    }
    snprintf(secondary_errmsg, secondary_errmsg_len, "%s",
               get_pcap_failure_secondary_error_message(open_status, open_status_str));
}

static bool
compile_capture_filter(const char *iface, pcap_t *pcap_h,
                       struct bpf_program *fcode, const char *cfilter)
{
    bpf_u_int32 netnum, netmask;
    char        lookup_net_err_str[PCAP_ERRBUF_SIZE];

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
DIAG_OFF(cast-qual)
    if (pcap_compile(pcap_h, fcode, (char *)cfilter, 1, netmask) < 0)
        return false;
DIAG_ON(cast-qual)
    return true;
}

static bool
show_filter_code(capture_options *capture_opts)
{
    interface_options *interface_opts;
    pcap_t *pcap_h;
    cap_device_open_status open_status;
    char open_status_str[PCAP_ERRBUF_SIZE];
    char errmsg[MSG_MAX_LENGTH+1];
    char secondary_errmsg[MSG_MAX_LENGTH+1];
    struct bpf_program fcode;
    struct bpf_insn *insn;
    u_int i;
    unsigned j;

    for (j = 0; j < capture_opts->ifaces->len; j++) {
        interface_opts = &g_array_index(capture_opts->ifaces, interface_options, j);
        pcap_h = open_capture_device(capture_opts, interface_opts,
            CAP_READ_TIMEOUT, &open_status, &open_status_str);
        if (pcap_h == NULL) {
            /* Open failed; get messages */
            get_capture_device_open_failure_messages(open_status, open_status_str,
                                                     interface_opts->name,
                                                     errmsg, sizeof errmsg,
                                                     secondary_errmsg,
                                                     sizeof secondary_errmsg);
            /* And report them */
            report_capture_error(errmsg, secondary_errmsg);
            return false;
        }

        /* Set the link-layer type. */
        if (!set_pcap_datalink(pcap_h, interface_opts->linktype, interface_opts->name,
                               errmsg, sizeof errmsg,
                               secondary_errmsg, sizeof secondary_errmsg)) {
            pcap_close(pcap_h);
            report_capture_error(errmsg, secondary_errmsg);
            return false;
        }

        /* OK, try to compile the capture filter. */
        if (!compile_capture_filter(interface_opts->name, pcap_h, &fcode,
                                    interface_opts->cfilter)) {
            snprintf(errmsg, sizeof(errmsg), "%s", pcap_geterr(pcap_h));
            pcap_close(pcap_h);
            report_cfilter_error(capture_opts, j, errmsg);
            return false;
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
        sync_pipe_write_string_msg(sync_pipe_fd, SP_SUCCESS, NULL);
    }
    return true;
}

static void
print_machine_readable_if_capabilities(json_dumper *dumper, if_capabilities_t *caps, int queries);

/*
 * Output a machine readable list of the interfaces
 * This list is retrieved by the sync_interface_list_open() function
 * The actual output of this function can be viewed with the command "dumpcap -D -Z none"
 */
static int
print_machine_readable_interfaces(GList *if_list, int caps_queries, bool print_statistics)
{
    GList       *if_entry;
    if_info_t   *if_info;
    GSList      *addr;
    if_addr_t   *if_addr;
    char        addr_str[WS_INET6_ADDRSTRLEN];
    int         status;

    json_dumper dumper = {
        .output_string = g_string_new(NULL),
        .flags = JSON_DUMPER_FLAGS_NO_DEBUG,
        // Don't abort on failure
    };
    json_dumper_begin_array(&dumper);

    /*
     * Print the contents of the if_entry struct in a parseable format (JSON)
     */
    for (if_entry = g_list_first(if_list); if_entry != NULL;
         if_entry = g_list_next(if_entry)) {
        if_info = (if_info_t *)if_entry->data;

        json_dumper_begin_object(&dumper);
        json_dumper_set_member_name(&dumper, if_info->name);

        json_dumper_begin_object(&dumper);

        json_dumper_set_member_name(&dumper, "friendly_name");
        json_dumper_value_string(&dumper, if_info->friendly_name);

        json_dumper_set_member_name(&dumper, "vendor_description");
        json_dumper_value_string(&dumper, if_info->vendor_description);

        json_dumper_set_member_name(&dumper, "type");
        json_dumper_value_anyf(&dumper, "%i", if_info->type);

        json_dumper_set_member_name(&dumper, "addrs");

        json_dumper_begin_array(&dumper);
        for (addr = g_slist_nth(if_info->addrs, 0); addr != NULL;
                    addr = g_slist_next(addr)) {

            if_addr = (if_addr_t *)addr->data;
            switch(if_addr->ifat_type) {
            case IF_AT_IPv4:
                json_dumper_value_string(&dumper, ws_inet_ntop4(&if_addr->addr.ip4_addr, addr_str, sizeof(addr_str)));
                break;
            case IF_AT_IPv6:
                json_dumper_value_string(&dumper, ws_inet_ntop6(&if_addr->addr.ip6_addr, addr_str, sizeof(addr_str)));
                break;
            default:
                json_dumper_value_anyf(&dumper, "<type unknown %i>", if_addr->ifat_type);
            }
        }
        json_dumper_end_array(&dumper);

        json_dumper_set_member_name(&dumper, "loopback");
        json_dumper_value_anyf(&dumper, "%s", if_info->loopback ? "true" : "false");

        json_dumper_set_member_name(&dumper, "extcap");
        json_dumper_value_string(&dumper, if_info->extcap);

        if (if_info->caps && caps_queries) {
            json_dumper_set_member_name(&dumper, "caps");
            json_dumper_begin_object(&dumper);
            print_machine_readable_if_capabilities(&dumper, if_info->caps, caps_queries);
            json_dumper_end_object(&dumper);
        }
        json_dumper_end_object(&dumper);
        json_dumper_end_object(&dumper);
    }
    json_dumper_end_array(&dumper);
    if (json_dumper_finish(&dumper)) {
        status = 0;
        if (capture_child) {
            if (print_statistics) {
                sync_pipe_write_string_msg(sync_pipe_fd, SP_IFACE_LIST, dumper.output_string->str);
            } else {
                /* Let our parent know we succeeded. */
                sync_pipe_write_string_msg(sync_pipe_fd, SP_SUCCESS, NULL);
                printf("%s", dumper.output_string->str);
            }
        } else {
            printf("%s", dumper.output_string->str);
        }
    } else {
        status = 2;
        if (capture_child) {
            sync_pipe_write_errmsgs_to_parent(sync_pipe_fd, "Unexpected JSON error", "");
        } else {
            cmdarg_err("Unexpected JSON error");
        }
    }
    g_string_free(dumper.output_string, TRUE);
    return status;
}

/*
 * If you change the machine-readable output format of this function,
 * you MUST update capture_ifinfo.c:capture_get_if_capabilities() accordingly!
 */
static void
print_machine_readable_if_capabilities(json_dumper *dumper, if_capabilities_t *caps, int queries)
{
    GList *lt_entry, *ts_entry;
    const char *desc_str;

    json_dumper_set_member_name(dumper, "status");
    json_dumper_value_anyf(dumper, "%i", caps->status);
    if (caps->primary_msg) {
        json_dumper_set_member_name(dumper, "primary_msg");
        json_dumper_value_string(dumper, caps->primary_msg);
    }

    if (queries & CAPS_QUERY_LINK_TYPES) {
        json_dumper_set_member_name(dumper, "rfmon");
        json_dumper_value_anyf(dumper, "%s", caps->can_set_rfmon ? "true" : "false");
        json_dumper_set_member_name(dumper, "data_link_types");
        json_dumper_begin_array(dumper);
        for (lt_entry = caps->data_link_types; lt_entry != NULL;
             lt_entry = g_list_next(lt_entry)) {
          data_link_info_t *data_link_info = (data_link_info_t *)lt_entry->data;
          if (data_link_info->description != NULL)
            desc_str = data_link_info->description;
          else
            desc_str = "(not supported)";
          json_dumper_begin_object(dumper);
          json_dumper_set_member_name(dumper, "dlt");
          json_dumper_value_anyf(dumper, "%d", data_link_info->dlt);
          json_dumper_set_member_name(dumper, "name");
          json_dumper_value_string(dumper, data_link_info->name);
          json_dumper_set_member_name(dumper, "description");
          json_dumper_value_string(dumper, desc_str);
          json_dumper_end_object(dumper);
        }
        json_dumper_end_array(dumper);

        json_dumper_set_member_name(dumper, "data_link_types_rfmon");
        json_dumper_begin_array(dumper);
        for (lt_entry = caps->data_link_types_rfmon; lt_entry != NULL;
             lt_entry = g_list_next(lt_entry)) {
          data_link_info_t *data_link_info = (data_link_info_t *)lt_entry->data;
          if (data_link_info->description != NULL)
            desc_str = data_link_info->description;
          else
            desc_str = "(not supported)";
          json_dumper_begin_object(dumper);
          json_dumper_set_member_name(dumper, "dlt");
          json_dumper_value_anyf(dumper, "%d", data_link_info->dlt);
          json_dumper_set_member_name(dumper, "name");
          json_dumper_value_string(dumper, data_link_info->name);
          json_dumper_set_member_name(dumper, "description");
          json_dumper_value_string(dumper, desc_str);
          json_dumper_end_object(dumper);
        }
        json_dumper_end_array(dumper);
    }
    if (queries & CAPS_QUERY_TIMESTAMP_TYPES) {
        json_dumper_set_member_name(dumper, "timestamp_types");
        json_dumper_begin_array(dumper);
        for (ts_entry = caps->timestamp_types; ts_entry != NULL;
             ts_entry = g_list_next(ts_entry)) {
          timestamp_info_t *timestamp = (timestamp_info_t *)ts_entry->data;
          if (timestamp->description != NULL)
            desc_str = timestamp->description;
          else
            desc_str = "(none)";
          json_dumper_begin_object(dumper);
          json_dumper_set_member_name(dumper, "name");
          json_dumper_value_string(dumper, timestamp->name);
          json_dumper_set_member_name(dumper, "description");
          json_dumper_value_string(dumper, desc_str);
          json_dumper_end_object(dumper);
        }
        json_dumper_end_array(dumper);
    }
}

typedef struct {
    char *name;
    pcap_t *pch;
} if_stat_t;

/* Print the number of packets captured for each interface until we're killed. */
static int
print_statistics_loop(bool machine_readable)
{
    GList       *if_list, *if_entry, *stat_list = NULL, *stat_entry;
    if_info_t   *if_info;
    if_stat_t   *if_stat;
    int         err;
    char        *err_str;
    pcap_t      *pch;
    char        errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_stat ps;

    if_list = get_interface_list(&err, &err_str);
    if (if_list == NULL) {
        if (err == 0) {
            cmdarg_err("There are no interfaces on which a capture can be done");
            err = WS_EXIT_NO_INTERFACES;
        }
        else {
            cmdarg_err("%s", err_str);
            g_free(err_str);
        }
        return err;
    }

    for (if_entry = g_list_first(if_list); if_entry != NULL; if_entry = g_list_next(if_entry)) {
        if_info = (if_info_t *)if_entry->data;

#ifdef __linux__
        /* On Linux nf* interfaces don't collect stats properly and don't allows multiple
         * connections. We avoid collecting stats on them.
         */
        if (!strncmp(if_info->name, "nf", 2)) {
            ws_debug("Skipping interface %s for stats", if_info->name);
            continue;
        }
#endif

#ifdef HAVE_PCAP_OPEN
	/*
	 * If we're opening a remote device, use pcap_open(); that's currently
	 * the only open routine that supports remote devices.
	 */
        if (strncmp(if_info->name, "rpcap://", 8) == 0)
            pch = pcap_open(if_info->name, MIN_PACKET_SIZE, 0, 0, NULL, errbuf);
        else
#endif
        pch = pcap_open_live(if_info->name, MIN_PACKET_SIZE, 0, 0, errbuf);

        if (pch) {
            if_stat = g_new(if_stat_t, 1);
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
        sync_pipe_write_string_msg(sync_pipe_fd, SP_SUCCESS, NULL);
    }

    if (!machine_readable) {
        printf("%-15s  %10s  %10s\n", "Interface", "Received",
            "Dropped");
    }

    global_ld.go = true;
    while (global_ld.go) {
        for (stat_entry = g_list_first(stat_list); stat_entry != NULL; stat_entry = g_list_next(stat_entry)) {
            if_stat = (if_stat_t *)stat_entry->data;
            /* XXX - what if this fails? */
            if (pcap_stats(if_stat->pch, &ps) == 0) {
                if (!machine_readable) {
                    printf("%-15s  %10u  %10u\n", if_stat->name,
                           ps.ps_recv, ps.ps_drop);
                } else {
                    printf("%s\t%u\t%u\n", if_stat->name,
                           ps.ps_recv, ps.ps_drop);
                    fflush(stdout);
                }
            }
        }
#ifdef _WIN32
        /* If we have a dummy signal pipe check it */
        if (!signal_pipe_check_running()) {
            global_ld.go = false;
        }
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

    ws_info("Console: Control signal");
    ws_debug("Console: Control signal, CtrlType: %lu", dwCtrlType);

    /* Keep capture running if we're a service and a user logs off */
    if (capture_child || (dwCtrlType != CTRL_LOGOFF_EVENT)) {
        capture_loop_stop();
        return true;
    } else {
        return false;
    }
}
#else
static void
capture_cleanup_handler(int signum _U_)
{
    /* On UN*X, we cleanly shut down the capture on SIGINT, SIGHUP, and
       SIGTERM.  We assume that if the user wanted it to keep running
       after they logged out, they'd have nohupped it. */

    capture_loop_stop();
}
#endif


static void
report_capture_count(bool reportit)
{
    /* Don't print this if we're a capture child. */
    if (!capture_child && reportit) {
        fprintf(stderr, "\rPackets captured: %d\n", global_ld.packets_captured);
        /* stderr could be line buffered */
        fflush(stderr);
    }
}


#ifdef SIGINFO
static void
report_counts_for_siginfo(void)
{
    report_capture_count(quiet);
    infoprint = false; /* we just reported it */
}

static void
report_counts_siginfo(int signum _U_)
{
    int sav_errno = errno;

    /* If we've been told to delay printing, just set a flag asking
       that we print counts (if we're supposed to), otherwise print
       the count of packets captured (if we're supposed to). */
    if (infodelay)
        infoprint = true;
    else
        report_counts_for_siginfo();
    errno = sav_errno;
}
#endif /* SIGINFO */

static void
exit_main(int status)
{
    ws_cleanup_sockets();

#ifdef _WIN32
    /* can be helpful for debugging */
#ifdef DEBUG_DUMPCAP
    printf("Press any key\n");
    _getch();
#endif

#endif /* _WIN32 */

    if (ringbuf_is_initialized()) {
        /* save_file is managed by ringbuffer, be sure to release the memory and
         * avoid capture_opts_cleanup from double-freeing 'save_file'. */
        ringbuf_free();
        global_capture_opts.save_file = NULL;
    }

    capture_opts_cleanup(&global_capture_opts);
    exit(status);
}

#ifdef HAVE_LIBCAP
/*
 * If we were linked with libcap (not related to libpcap), make sure we have
 * CAP_NET_ADMIN and CAP_NET_RAW, then relinquish our permissions.
 * (See comment in main() for details)
 */
static void
relinquish_privs_except_capture(void)
{
    /*
     * Drop any capabilities other than NET_ADMIN and NET_RAW:
     *
     * CAP_NET_ADMIN: Promiscuous mode and a truckload of other
     *                stuff we don't need (and shouldn't have).
     * CAP_NET_RAW:   Packet capture (raw sockets).
     *
     * If 'started_with_special_privs' (ie: suid) then drop our
     * suid privileges.
     */

    cap_t current_caps = cap_get_proc();
    print_caps("Pre set");

    cap_t caps = cap_init();    /* all capabilities initialized to off */

    /*
     * We can only set capabilities that are in the permitted set.
     * If the real or effective user ID is 0 (root), then the file
     * inherited and permitted sets are ignored, and our permitted
     * set should be all ones - unless the effective ID is 0, the
     * real ID is not zero, and the binary has file capabilities,
     * in which case the permitted set is only that of the file.
     * (E.g., set-user-ID-root + file capabilities.)
     *
     * If one or more of the euid, ruid, and saved set user ID are
     * all zero and all change to nonzero, then all capabilities are
     * cleared from the permitted, effective, and ambient sets.
     * PR_SET_KEEPCAPS causes the permitted set to be retained, so
     * we can relinquish our changed user ID.
     *
     * All capabilities are always cleared from the effective set
     * when the euid is changed from 0 to nonzero.
     *
     * See capabilities(7).
     */
    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
        cmdarg_err("prctl() fail return: %s", g_strerror(errno));
    }

    if (started_with_special_privs()) {
        relinquish_special_privs_perm();
    }

    /*
     * If cap_set_proc() fails, it leaves the capabilities unchanged.
     * So the only way to guarantee that we've dropped all other
     * capabilities is to ensure that cap_set_proc() succeeds.
     * One option might be to exit if cap_set_proc() fails - but some
     * captures will work with CAP_NET_RAW but not CAP_NET_ADMIN.
     */

    cap_value_t cap_list[1] = { CAP_NET_ADMIN };
    int cl_len = array_length(cap_list);
    cap_flag_value_t value;

    cap_get_flag(current_caps, cap_list[0], CAP_PERMITTED, &value);

    if (value != CAP_SET) {
        // XXX - Should we warn here? Some captures will still work.
    }
    cap_set_flag(caps, CAP_PERMITTED, cl_len, cap_list, value);
    // XXX - Do we really need CAP_INHERITABLE?
    cap_set_flag(caps, CAP_INHERITABLE, cl_len, cap_list, value);
    cap_set_flag(caps, CAP_EFFECTIVE, cl_len, cap_list, value);

    cap_list[0] = CAP_NET_RAW;
    cap_get_flag(current_caps, cap_list[0], CAP_PERMITTED, &value);

    if (value != CAP_SET) {
        // XXX - Should we warn here?
    }
    cap_set_flag(caps, CAP_PERMITTED, cl_len, cap_list, value);
    // XXX - Do we really need CAP_INHERITABLE?
    cap_set_flag(caps, CAP_INHERITABLE, cl_len, cap_list, value);
    cap_set_flag(caps, CAP_EFFECTIVE, cl_len, cap_list, value);

    if (cap_set_proc(caps)) {
        /*
         * This shouldn't happen, we're only trying to set capabilities
         * already in the permitted set.
         */
        cmdarg_err("cap_set_proc() fail return: %s", g_strerror(errno));
    }

    print_caps("Post set");

    cap_free(current_caps);
    cap_free(caps);
}

#endif /* HAVE_LIBCAP */

/* Map DLT_ values, as returned by pcap_datalink(), to LINKTYPE_ values,
   as are written to capture files.

   Most of the time, a DLT_ value and the corresponding LINKYPE_ value
   are the same, but there are some cases, where a numeric value as
   a DLT_ doesn't uniquely identify a particular link-layer header type,
   where they differ, so that the values in files *do* identify
   particular link-layer header types. */

/* LINKTYPE_ values that don't match corresponding DLT_ values on
    all platforms. */
#define LINKTYPE_ATM_RFC1483	100
#define LINKTYPE_RAW		101
#define LINKTYPE_SLIP_BSDOS	102
#define LINKTYPE_PPP_BSDOS	103
#define LINKTYPE_C_HDLC		104
#define LINKTYPE_IEEE802_11	105
#define LINKTYPE_ATM_CLIP	106
#define LINKTYPE_FRELAY		107
#define LINKTYPE_LOOP		108
#define LINKTYPE_ENC		109
#define LINKTYPE_NETBSD_HDLC	112
#define LINKTYPE_PFSYNC		246
#define LINKTYPE_PKTAP		258

static int
dlt_to_linktype(int dlt)
{
	/* DLT_NULL through DLT_FDDI have the same numeric value on
	   all platforms, so the corresponding LINKTYPE_s have the
	   same numeric values. */
	if (dlt >= DLT_NULL && dlt <= DLT_FDDI)
		return (dlt);

#if defined(DLT_PFSYNC) && DLT_PFSYNC != LINKTYPE_PFSYNC
	/* DLT_PFSYNC has a value on several platforms that's in the
	   non-matching range, a value on FreeBSD that's in the high
	   matching range and that's *not* equal to LINKTYPE_PFSYNC,
	   and has a value on the rmaining platforms that's equal
	   to LINKTYPE_PFSYNC, which is in the high matching range.

	   Map it to LINKTYPE_PFSYNC if it's not equal to LINKTYPE_PFSYNC. */
	if (dlt == DLT_PFSYNC)
		return (LINKTYPE_PFSYNC);
#endif

	/* DLT_PKTAP is defined as DLT_USER2 - which is in the high
	   matching range - on Darwin because Apple used DLT_USER2
	   on systems that users ran, not just as an internal thing.

	   We map it to LINKTYPE_PKTAP if it's not equal to LINKTYPE_PKTAP
	   so that DLT_PKTAP captures from Apple machines can be read by
	   software that either doesn't handle DLT_USER2 or that handles it
	   as something other than Apple PKTAP. */
#if defined(DLT_PKTAP) && DLT_PKTAP != LINKTYPE_PKTAP
	if (dlt == DLT_PKTAP)
		return (LINKTYPE_PKTAP);
#endif

	/* For all other DLT_s with values beyond 104, the value
	   of the corresponding LINKTYPE_ is the same. */
	if (dlt >= 104)
		return (dlt);

	/* These DLT_ values have different values on different
	   platforms, so we assigned them LINKTYPE_ values just
	   below the lower bound of the high matchig range;
	   those values should never be equal to any DLT_
	   values, so that should avoid collisions.

	   That way, for example, "raw IP" packets will have
	   LINKTYPE_RAW as the code in all savefiles for
	   which the code that writes them maps to that
	   value, regardless of the platform on which they
	   were written, so they should be readable on all
	   platforms without having to determine on which
	   platform they were written.

	   We map the DLT_ values on this platform, whatever
	   it might be, to the corresponding LINKTYPE_ values. */
#ifdef DLT_ATM_RFC1483
	if (dlt == DLT_ATM_RFC1483)
		return (LINKTYPE_ATM_RFC1483);
#endif
#ifdef DLT_RAW
	if (dlt == DLT_RAW)
		return (LINKTYPE_RAW);
#endif
#ifdef DLT_SLIP_BSDOS
	if (dlt == DLT_SLIP_BSDOS)
		return (LINKTYPE_SLIP_BSDOS);
#endif
#ifdef DLT_PPP_BSDOS
	if (dlt == DLT_PPP_BSDOS)
		return (LINKTYPE_PPP_BSDOS);
#endif

	/* These DLT_ values were originally defined on some platform,
	   and weren't defined on other platforms.

	   At least some of those values, on at least one platform,
	   collide with the values of other DLT_s on other platforms,
	   e.g. DLT_LOOP, so we don't just define them, on all
	   platforms, as having the same value as on the original
	   platform.

	   Therefore, we assigned new LINKTYPE_ values to them, and,
	   on the platforms where they weren't originally defined,
	   define the DLT_s to have the same value as the corresponding
	   LINKTYPE_.

	   This means that, for capture files with the original
	   platform's DLT_ value rather than the LINKTYPE_ value
	   as a link-layer type, we will recognize those types
	   on that platform, but not on other platforms. */
#ifdef DLT_FR
	/* BSD/OS Frame Relay */
	if (dlt == DLT_FR)
		return (LINKTYPE_FRELAY);
#endif
#if defined(DLT_HDLC) && DLT_HDLC != LINKTYPE_NETBSD_HDLC
	/* NetBSD HDLC */
	if (dlt == DLT_HDLC)
		return (LINKTYPE_NETBSD_HDLC);
#endif
#if defined(DLT_C_HDLC) && DLT_C_HDLC != LINKTYPE_C_HDLC
	/* BSD/OS Cisco HDLC */
	if (dlt == DLT_C_HDLC)
		return (LINKTYPE_C_HDLC);
#endif
#if defined(DLT_LOOP) && DLT_LOOP != LINKTYPE_LOOP
	/* OpenBSD DLT_LOOP */
	if (dlt == DLT_LOOP)
		return (LINKTYPE_LOOP);
#endif
#if defined(DLT_ENC) && DLT_ENC != LINKTYPE_ENC
	/* OpenBSD DLT_ENC */
	if (dlt == DLT_ENC)
		return (LINKTYPE_ENC);
#endif

	/* These DLT_ values are not on all platforms, but, so far,
	   there don't appear to be any platforms that define
	   other DLT_s with those values; we map them to
	   different LINKTYPE_ values anyway, just in case. */
#ifdef DLT_ATM_CLIP
	/* Linux ATM Classical IP */
	if (dlt == DLT_ATM_CLIP)
		return (LINKTYPE_ATM_CLIP);
#endif

	/* Treat all other DLT_s as having the same value as the
	   corresponding LINKTYPE_. */
	return (dlt);
}

/* Take care of byte order in the libpcap headers read from pipes.
 * (function taken from wiretap/libpcap.c) */
static void
cap_pipe_adjust_pcap_header(bool byte_swapped, struct pcap_hdr *hdr, struct pcaprec_hdr *rechdr)
{
    if (byte_swapped) {
        /* Byte-swap the record header fields. */
        rechdr->ts_sec = GUINT32_SWAP_LE_BE(rechdr->ts_sec);
        rechdr->ts_usec = GUINT32_SWAP_LE_BE(rechdr->ts_usec);
        rechdr->incl_len = GUINT32_SWAP_LE_BE(rechdr->incl_len);
        rechdr->orig_len = GUINT32_SWAP_LE_BE(rechdr->orig_len);
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
        uint32_t temp;

        temp = rechdr->orig_len;
        rechdr->orig_len = rechdr->incl_len;
        rechdr->incl_len = temp;
    }
}

/* Wrapper: distinguish between recv/read if we're reading on Windows,
 * or just read().
 */
static ssize_t
cap_pipe_read(int pipe_fd, char *buf, size_t sz, bool from_socket _U_)
{
#ifdef _WIN32
    if (from_socket) {
        return recv(pipe_fd, buf, (int)sz, 0);
    } else {
        return -1;
    }
#else
    return ws_read(pipe_fd, buf, sz);
#endif
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
 * we can let cap_thread_read run independently, queuing up multiple reads
 * for the main thread (and possibly get rid of cap_pipe_read_mtx).
 */
static void *cap_thread_read(void *arg)
{
    capture_src *pcap_src;
#ifdef _WIN32
    BOOL res;
    DWORD last_err, bytes_read;
#else /* _WIN32 */
    size_t bytes_read;
#endif /* _WIN32 */

    pcap_src = (capture_src *)arg;
    while (pcap_src->cap_pipe_err == PIPOK) {
        g_async_queue_pop(pcap_src->cap_pipe_pending_q); /* Wait for our cue (ahem) from the main thread */
        g_mutex_lock(pcap_src->cap_pipe_read_mtx);
        bytes_read = 0;
        while (bytes_read < pcap_src->cap_pipe_bytes_to_read) {
           if ((pcap_src->from_cap_socket)
#ifndef _WIN32
              || 1
#endif
              )
           {
               ssize_t b;
               b = cap_pipe_read(pcap_src->cap_pipe_fd, pcap_src->cap_pipe_buf+bytes_read,
                        pcap_src->cap_pipe_bytes_to_read - bytes_read, pcap_src->from_cap_socket);
               if (b <= 0) {
                   if (b == 0) {
                       pcap_src->cap_pipe_err = PIPEOF;
                       bytes_read = 0;
                       break;
                   } else {
                       pcap_src->cap_pipe_err = PIPERR;
                       bytes_read = -1;
                       break;
                   }
               } else {
                   bytes_read += (DWORD)b;
               }
           }
#ifdef _WIN32
           else
           {
               /* If we try to use read() on a named pipe on Windows with partial
                * data it appears to return EOF.
                */
               DWORD b;
               res = ReadFile(pcap_src->cap_pipe_h, pcap_src->cap_pipe_buf+bytes_read,
                              pcap_src->cap_pipe_bytes_to_read - bytes_read,
                              &b, NULL);

               bytes_read += b;
               if (!res) {
                   last_err = GetLastError();
                   if (last_err == ERROR_MORE_DATA) {
                       continue;
                   } else if (last_err == ERROR_HANDLE_EOF || last_err == ERROR_BROKEN_PIPE || last_err == ERROR_PIPE_NOT_CONNECTED) {
                       pcap_src->cap_pipe_err = PIPEOF;
                       bytes_read = 0;
                       break;
                   }
                   pcap_src->cap_pipe_err = PIPERR;
                   bytes_read = -1;
                   break;
               } else if (b == 0 && pcap_src->cap_pipe_bytes_to_read > 0) {
                   pcap_src->cap_pipe_err = PIPEOF;
                   bytes_read = 0;
                   break;
               }
           }
#endif /*_WIN32 */
        }
        pcap_src->cap_pipe_bytes_read = bytes_read;
        if (pcap_src->cap_pipe_bytes_read >= pcap_src->cap_pipe_bytes_to_read) {
            g_async_queue_push(pcap_src->cap_pipe_done_q, pcap_src->cap_pipe_buf); /* Any non-NULL value will do */
        }
        g_mutex_unlock(pcap_src->cap_pipe_read_mtx);
    }
    /* Post to queue if we didn't read enough data as the main thread waits for the message */
    g_mutex_lock(pcap_src->cap_pipe_read_mtx);
    if (pcap_src->cap_pipe_bytes_read < pcap_src->cap_pipe_bytes_to_read) {
        /* There's still more of the record to read. */
        g_async_queue_push(pcap_src->cap_pipe_done_q, pcap_src->cap_pipe_buf); /* Any non-NULL value will do */
    }
    g_mutex_unlock(pcap_src->cap_pipe_read_mtx);
    return NULL;
}

/*
 * Do a blocking read from a pipe within the main thread, by pushing
 * the read onto the pipe queue and then popping it off that queue;
 * the pipe will block until the pushed read completes.
 *
 * We do it with another thread because we can't use select() on
 * pipes on Windows, as we can on UN*Xes, we can only use it on
 * sockets.
 */
void
pipe_read_sync(capture_src *pcap_src, void *buf, DWORD nbytes)
{
    pcap_src->cap_pipe_buf = (char *) buf;
    pcap_src->cap_pipe_bytes_read = 0;
    pcap_src->cap_pipe_bytes_to_read = nbytes;
    /* We don't have to worry about cap_pipe_read_mtx here */
    g_async_queue_push(pcap_src->cap_pipe_pending_q, pcap_src->cap_pipe_buf);
    g_async_queue_pop(pcap_src->cap_pipe_done_q);
}
#endif

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

#define DEF_TCP_PORT 19000

static int
cap_open_socket(char *pipename, capture_src *pcap_src, char *errmsg, size_t errmsgl)
{
    struct sockaddr_storage sa;
    socklen_t sa_len;
    int fd;

    /* Skip the initial "TCP@" in the pipename. */
    if (ws_socket_ptoa(&sa, pipename + 4, DEF_TCP_PORT) < 0) {
        snprintf(errmsg, errmsgl,
                "The capture session could not be initiated because"
                "\"%s\" is not a valid socket specification", pipename);
        pcap_src->cap_pipe_err = PIPERR;
        return -1;
    }

    if ((fd = (int)socket(sa.ss_family, SOCK_STREAM, 0)) < 0) {
        snprintf(errmsg, errmsgl,
            "The capture session could not be initiated because"
            " the socket couldn't be created due to the socket error: \n"
#ifdef _WIN32
            "         %s", win32strerror(WSAGetLastError()));
#else
            "         %d: %s", errno, g_strerror(errno));
#endif
        pcap_src->cap_pipe_err = PIPERR;
        return -1;
    }

    if (sa.ss_family == AF_INET6)
        sa_len = sizeof(struct sockaddr_in6);
    else
        sa_len = sizeof(struct sockaddr_in);
    if (connect(fd, (struct sockaddr *)&sa, sa_len) < 0) {
        snprintf(errmsg, errmsgl,
            "The capture session could not be initiated because"
            " the socket couldn't be connected due to the socket error: \n"
#ifdef _WIN32
            "         %s", win32strerror(WSAGetLastError()));
#else
            "         %d: %s", errno, g_strerror(errno));
#endif
        pcap_src->cap_pipe_err = PIPERR;

        cap_pipe_close(fd, true);
        return -1;
    }

    pcap_src->from_cap_socket = true;
    return fd;
}

/* Wrapper: distinguish between closesocket on Windows; use ws_close
 * otherwise.
 */
static void
cap_pipe_close(int pipe_fd, bool from_socket)
{
#ifdef _WIN32
    if (from_socket) {
        closesocket(pipe_fd);
    }
#else
    (void) from_socket; /* Mark unused, similar to Q_UNUSED */
    ws_close(pipe_fd);
#endif
}

/** Read bytes from a capture source, which is assumed to be a pipe or
 * socket.
 *
 * Returns -1, or the number of bytes read similar to read(2).
 * Sets pcap_src->cap_pipe_err on error or EOF.
 */
static ssize_t
cap_pipe_read_data_bytes(capture_src *pcap_src, char *errmsg, size_t errmsgl)
{
    int sel_ret;
    int fd = pcap_src->cap_pipe_fd;
#ifdef _WIN32
    DWORD sz, bytes_read = 0;
#else /* _WIN32 */
    ssize_t sz, bytes_read = 0;
#endif /* _WIN32 */
    ssize_t b;

#ifdef LOG_CAPTURE_VERBOSE
    ws_debug("cap_pipe_read_data_bytes read %lu of %lu",
          pcap_src->cap_pipe_bytes_read, pcap_src->cap_pipe_bytes_to_read);
#endif
    sz = pcap_src->cap_pipe_bytes_to_read - pcap_src->cap_pipe_bytes_read;
    while (bytes_read < sz) {
        if (fd == -1) {
            snprintf(errmsg, errmsgl, "Invalid file descriptor.");
            pcap_src->cap_pipe_err = PIPNEXIST;
            return -1;
        }

        sel_ret = cap_pipe_select(fd);
        if (sel_ret < 0) {
            snprintf(errmsg, errmsgl,
                       "Unexpected error from select: %s.", g_strerror(errno));
            pcap_src->cap_pipe_err = PIPERR;
            return -1;
        } else if (sel_ret > 0) {
            b = cap_pipe_read(fd, pcap_src->cap_pipe_databuf+pcap_src->cap_pipe_bytes_read+bytes_read,
                              sz-bytes_read, pcap_src->from_cap_socket);
            if (b <= 0) {
                if (b == 0) {
                    snprintf(errmsg, errmsgl,
                               "End of file reading from pipe or socket.");
                    pcap_src->cap_pipe_err = PIPEOF;
                } else {
#ifdef _WIN32
                    /*
                     * On Windows, we only do this for sockets.
                     */
                    DWORD lastError = WSAGetLastError();
                    errno = lastError;
                    snprintf(errmsg, errmsgl,
                               "Error reading from pipe or socket: %s.",
                               win32strerror(lastError));
#else
                    snprintf(errmsg, errmsgl,
                               "Error reading from pipe or socket: %s.",
                               g_strerror(errno));
#endif
                    pcap_src->cap_pipe_err = PIPERR;
                }
                return -1;
            }
#ifdef _WIN32
            bytes_read += (DWORD)b;
#else
            bytes_read += b;
#endif
        }
    }
    pcap_src->cap_pipe_bytes_read += bytes_read;
#ifdef LOG_CAPTURE_VERBOSE
    ws_debug("cap_pipe_read_data_bytes read %lu of %lu",
          pcap_src->cap_pipe_bytes_read, pcap_src->cap_pipe_bytes_to_read);
#endif
    return bytes_read;
}

/* Some forward declarations for breaking up cap_pipe_open_live for pcap and pcapng formats */
static void pcap_pipe_open_live(int fd, capture_src *pcap_src,
                                struct pcap_hdr *hdr,
                                char *errmsg, size_t errmsgl,
                                char *secondary_errmsg, size_t secondary_errmsgl);
static void pcapng_pipe_open_live(int fd, capture_src *pcap_src,
                                  char *errmsg, size_t errmsgl);
static int pcapng_pipe_dispatch(loop_data *ld, capture_src *pcap_src,
                                char *errmsg, size_t errmsgl);

/* For problems that are probably Not Our Fault. */
static char not_our_bug[] =
    "Please report this to the developers of the program writing to the pipe.";

/* Mimic pcap_open_live() for pipe captures

 * We check if "pipename" is "-" (stdin), a AF_UNIX socket, or a FIFO,
 * open it, and read the header.
 *
 * N.B. : we can't read the libpcap formats used in RedHat 6.1 or SuSE 6.3
 * because we can't seek on pipes (see wiretap/libpcap.c for details) */
static void
cap_pipe_open_live(char *pipename,
                   capture_src *pcap_src,
                   void *hdr,
                   char *errmsg, size_t errmsgl,
                   char *secondary_errmsg, size_t secondary_errmsgl)
{
#ifndef _WIN32
    ws_statb64         pipe_stat;
    struct sockaddr_un sa;
#else /* _WIN32 */
    guintptr extcap_pipe_handle;
#endif
    bool extcap_pipe = false;
    ssize_t  b;
    int      fd = -1, sel_ret;
    size_t   bytes_read;
    uint32_t magic = 0;
    pcap_src->cap_pipe_fd = -1;
#ifdef _WIN32
    pcap_src->cap_pipe_h = INVALID_HANDLE_VALUE;
#endif

    ws_debug("cap_pipe_open_live: %s", pipename);

    /*
     * XXX - this blocks until a pcap per-file header has been written to
     * the pipe, so it could block indefinitely.
     */
    if (strcmp(pipename, "-") == 0) {
#ifndef _WIN32
        fd = 0; /* read from stdin */
#else /* _WIN32 */
        pcap_src->cap_pipe_h = GetStdHandle(STD_INPUT_HANDLE);
#endif  /* _WIN32 */
    } else if (!strncmp(pipename, "TCP@", 4)) {
       if ((fd = cap_open_socket(pipename, pcap_src, errmsg, errmsgl)) < 0) {
          return;
       }
    } else {
#ifndef _WIN32
        if ( g_strrstr(pipename, EXTCAP_PIPE_PREFIX) != NULL )
            extcap_pipe = true;

        if (ws_stat64(pipename, &pipe_stat) < 0) {
            if (errno == ENOENT || errno == ENOTDIR)
                pcap_src->cap_pipe_err = PIPNEXIST;
            else {
                snprintf(errmsg, errmsgl,
                           "The capture session could not be initiated "
                           "due to error getting information on pipe or socket: %s.", g_strerror(errno));
                pcap_src->cap_pipe_err = PIPERR;
            }
            return;
        }
        if (S_ISFIFO(pipe_stat.st_mode)) {
            fd = ws_open(pipename, O_RDONLY | O_NONBLOCK, 0000 /* no creation so don't matter */);
            if (fd == -1) {
                snprintf(errmsg, errmsgl,
                           "The capture session could not be initiated "
                           "due to error on pipe open: %s.", g_strerror(errno));
                pcap_src->cap_pipe_err = PIPERR;
                return;
            }
        } else if (S_ISSOCK(pipe_stat.st_mode)) {
            fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (fd == -1) {
                snprintf(errmsg, errmsgl,
                           "The capture session could not be initiated "
                           "due to error on socket create: %s.", g_strerror(errno));
                pcap_src->cap_pipe_err = PIPERR;
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
                snprintf(errmsg, errmsgl,
                           "The capture session could not be initiated "
                           "due to error on socket connect: Path name too long.");
                pcap_src->cap_pipe_err = PIPERR;
                ws_close(fd);
                return;
            }
            b = connect(fd, (struct sockaddr *)&sa, sizeof sa);
            if (b == -1) {
                snprintf(errmsg, errmsgl,
                           "The capture session could not be initiated "
                           "due to error on socket connect: %s.", g_strerror(errno));
                pcap_src->cap_pipe_err = PIPERR;
                ws_close(fd);
                return;
            }
        } else {
            if (S_ISCHR(pipe_stat.st_mode)) {
                /*
                 * Assume the user specified an interface on a system where
                 * interfaces are in /dev.  Pretend we haven't seen it.
                 */
                pcap_src->cap_pipe_err = PIPNEXIST;
            } else {
                snprintf(errmsg, errmsgl,
                           "The capture session could not be initiated because\n"
                           "\"%s\" is neither an interface nor a socket nor a pipe.", pipename);
                pcap_src->cap_pipe_err = PIPERR;
            }
            return;
        }

#else /* _WIN32 */
        if (sscanf(pipename, EXTCAP_PIPE_PREFIX "%" SCNuPTR, &extcap_pipe_handle) == 1)
        {
            /* The client is already connected to extcap pipe.
             * We have inherited the handle from parent process.
             */
            extcap_pipe = true;
            pcap_src->cap_pipe_h = (HANDLE)extcap_pipe_handle;
        }
        else
        {
            if (!win32_is_pipe_name(pipename)) {
                snprintf(errmsg, errmsgl,
                    "The capture session could not be initiated because\n"
                    "\"%s\" is neither an interface nor a pipe.", pipename);
                pcap_src->cap_pipe_err = PIPNEXIST;
                return;
            }

            /* Wait for the pipe to appear */
            while (1) {
                pcap_src->cap_pipe_h = CreateFile(utf_8to16(pipename), GENERIC_READ, 0, NULL,
                        OPEN_EXISTING, 0, NULL);

                if (pcap_src->cap_pipe_h != INVALID_HANDLE_VALUE)
                    break;

                if (GetLastError() != ERROR_PIPE_BUSY) {
                    snprintf(errmsg, errmsgl,
                        "The capture session on \"%s\" could not be started "
                        "due to error on pipe open: %s.",
                        pipename, win32strerror(GetLastError()));
                    pcap_src->cap_pipe_err = PIPERR;
                    return;
                }

                if (!WaitNamedPipe(utf_8to16(pipename), 30 * 1000)) {
                    snprintf(errmsg, errmsgl,
                        "The capture session on \"%s\" timed out during "
                        "pipe open: %s.",
                        pipename, win32strerror(GetLastError()));
                    pcap_src->cap_pipe_err = PIPERR;
                    return;
                }
            }
        }
#endif /* _WIN32 */
    }

    pcap_src->from_cap_pipe = true;

    /*
     * We start with a 2KB buffer for packet data, which should be
     * large enough for most regular network packets.  We increase it,
     * up to the maximum size we allow, as necessary.
     */
    pcap_src->cap_pipe_databuf = (char*)g_malloc(2048);
    pcap_src->cap_pipe_databuf_size = 2048;

    /*
     * Read the first 4 bytes of data from the pipe.
     *
     * If a pcap file is being written to it, that will be
     * the pcap magic number.
     *
     * If a pcapng file is being written to it, that will be
     * the block type of the initial SHB.
     */
#ifdef _WIN32
    /*
     * On UN*X, we can use select() on pipes or sockets.
     *
     * On Windows, we can only use it on sockets; to do non-blocking
     * reads from pipes, we currently do reads in a separate thread
     * and use GLib asynchronous queues from the main thread to start
     * read operations and to wait for them to complete.
     */
    if (pcap_src->from_cap_socket)
#endif
    {
        bytes_read = 0;
        while (bytes_read < sizeof magic) {
            sel_ret = cap_pipe_select(fd);
            if (sel_ret < 0) {
                snprintf(errmsg, errmsgl,
                           "Unexpected error from select: %s.",
                           g_strerror(errno));
                goto error;
            } else if (sel_ret > 0) {
                b = cap_pipe_read(fd, ((char *)&magic)+bytes_read,
                                  sizeof magic-bytes_read,
                                  pcap_src->from_cap_socket);
                /* jump messaging, if extcap had an error, stderr will provide the correct message */
                if (extcap_pipe && b <= 0)
                    goto error;

                if (b <= 0) {
                    if (b == 0)
                        snprintf(errmsg, errmsgl,
                                   "End of file on pipe magic during open.");
                    else
                        snprintf(errmsg, errmsgl,
                                   "Error on pipe magic during open: %s.",
                                   g_strerror(errno));
                    goto error;
                }
                bytes_read += b;
            }
        }
    }
#ifdef _WIN32
    else {
        /* Create a thread to read from this pipe */
        g_thread_new("cap_pipe_open_live", &cap_thread_read, pcap_src);

        pipe_read_sync(pcap_src, &magic, sizeof(magic));
        /* jump messaging, if extcap had an error, stderr will provide the correct message */
        if (pcap_src->cap_pipe_bytes_read <= 0 && extcap_pipe)
            goto error;

        if (pcap_src->cap_pipe_bytes_read <= 0) {
            if (pcap_src->cap_pipe_bytes_read == 0)
                snprintf(errmsg, errmsgl,
                           "End of file on pipe magic during open.");
            else
                snprintf(errmsg, errmsgl,
                           "Error on pipe magic during open: %s.",
                           g_strerror(errno));
            goto error;
        }
    }
#endif

    switch (magic) {
    case PCAP_MAGIC:
    case PCAP_NSEC_MAGIC:
        /* This is a pcap file.
           The host that wrote it has our byte order, and was running
           a program using either standard or ss990417 libpcap. */
        pcap_src->cap_pipe_info.pcap.byte_swapped = false;
        pcap_src->cap_pipe_modified = false;
        pcap_src->ts_nsec = magic == PCAP_NSEC_MAGIC;
        break;
    case PCAP_MODIFIED_MAGIC:
        /* This is a pcap file.
           The host that wrote it has our byte order, but was running
           a program using either ss990915 or ss991029 libpcap. */
        pcap_src->cap_pipe_info.pcap.byte_swapped = false;
        pcap_src->cap_pipe_modified = true;
        break;
    case PCAP_SWAPPED_MAGIC:
    case PCAP_SWAPPED_NSEC_MAGIC:
        /* This is a pcap file.
           The host that wrote it has a byte order opposite to ours,
           and was running a program using either standard or
           ss990417 libpcap. */
        pcap_src->cap_pipe_info.pcap.byte_swapped = true;
        pcap_src->cap_pipe_modified = false;
        pcap_src->ts_nsec = magic == PCAP_SWAPPED_NSEC_MAGIC;
        break;
    case PCAP_SWAPPED_MODIFIED_MAGIC:
        /* This is a pcap file.
           The host that wrote it out has a byte order opposite to
           ours, and was running a program using either ss990915
           or ss991029 libpcap. */
        pcap_src->cap_pipe_info.pcap.byte_swapped = true;
        pcap_src->cap_pipe_modified = true;
        break;
    case BLOCK_TYPE_SHB:
        /* This is a pcapng file. */
        pcap_src->from_pcapng = true;
        pcap_src->cap_pipe_dispatch = pcapng_pipe_dispatch;
        pcap_src->cap_pipe_info.pcapng.src_iface_to_global = g_array_new(FALSE, FALSE, sizeof(uint32_t));
        global_capture_opts.use_pcapng = true;      /* we can only output in pcapng format */
        break;
    default:
        /* Not a pcapng file, and either not a pcap type we know about
           or not a pcap file, either. */
        snprintf(errmsg, errmsgl,
                   "File type is neither a supported pcap nor pcapng format. (magic = 0x%08x)", magic);
        snprintf(secondary_errmsg, secondary_errmsgl, "%s",
                   not_our_bug);
        goto error;
    }

    if (pcap_src->from_pcapng)
        pcapng_pipe_open_live(fd, pcap_src, errmsg, errmsgl);
    else
        pcap_pipe_open_live(fd, pcap_src, (struct pcap_hdr *) hdr, errmsg, errmsgl,
                            secondary_errmsg, secondary_errmsgl);

    return;

error:
    ws_debug("cap_pipe_open_live: error %s", errmsg);
    pcap_src->cap_pipe_err = PIPERR;
    cap_pipe_close(fd, pcap_src->from_cap_socket);
    pcap_src->cap_pipe_fd = -1;
#ifdef _WIN32
    pcap_src->cap_pipe_h = INVALID_HANDLE_VALUE;
#endif
}

/*
 * Read the part of the pcap file header that follows the magic
 * number (we've already read the magic number).
 */
static void
pcap_pipe_open_live(int fd,
                    capture_src *pcap_src,
                    struct pcap_hdr *hdr,
                    char *errmsg, size_t errmsgl,
                    char *secondary_errmsg, size_t secondary_errmsgl)
{
    size_t   bytes_read;
    ssize_t  b;
    int      sel_ret;

    /*
     * We're reading from a pcap file.  We've already read the magic
     * number; read the rest of the header.
     *
     * (Note that struct pcap_hdr is a structure for the part of a
     * pcap file header *following the magic number*; it does not
     * include the magic number itself.)
     */
#ifdef _WIN32
    if (pcap_src->from_cap_socket)
#endif
    {
        /* Keep reading until we get the rest of the header. */
        bytes_read = 0;
        while (bytes_read < sizeof(struct pcap_hdr)) {
            sel_ret = cap_pipe_select(fd);
            if (sel_ret < 0) {
                snprintf(errmsg, errmsgl,
                           "Unexpected error from select: %s.",
                           g_strerror(errno));
                goto error;
            } else if (sel_ret > 0) {
                b = cap_pipe_read(fd, ((char *)hdr)+bytes_read,
                                  sizeof(struct pcap_hdr) - bytes_read,
                                  pcap_src->from_cap_socket);
                if (b <= 0) {
                    if (b == 0)
                        snprintf(errmsg, errmsgl,
                                   "End of file on pipe header during open.");
                    else
                        snprintf(errmsg, errmsgl,
                                   "Error on pipe header during open: %s.",
                                   g_strerror(errno));
                    snprintf(secondary_errmsg, secondary_errmsgl,
                               "%s", not_our_bug);
                    goto error;
                }
                bytes_read += b;
            }
        }
    }
#ifdef _WIN32
    else {
        pipe_read_sync(pcap_src, hdr, sizeof(struct pcap_hdr));
        if (pcap_src->cap_pipe_bytes_read <= 0) {
            if (pcap_src->cap_pipe_bytes_read == 0)
                snprintf(errmsg, errmsgl,
                           "End of file on pipe header during open.");
            else
                snprintf(errmsg, errmsgl,
                           "Error on pipe header header during open: %s.",
                           g_strerror(errno));
            snprintf(secondary_errmsg, secondary_errmsgl, "%s",
                       not_our_bug);
            goto error;
        }
    }
#endif

    if (pcap_src->cap_pipe_info.pcap.byte_swapped) {
        /* Byte-swap the header fields about which we care. */
        hdr->version_major = GUINT16_SWAP_LE_BE(hdr->version_major);
        hdr->version_minor = GUINT16_SWAP_LE_BE(hdr->version_minor);
        hdr->snaplen = GUINT32_SWAP_LE_BE(hdr->snaplen);
        hdr->network = GUINT32_SWAP_LE_BE(hdr->network);
    }
    /*
     * The link-layer header type field of the pcap header is
     * probably a LINKTYPE_ value, as the vast majority of
     * LINKTYPE_ values and their corresponding DLT_ values
     * are the same.
     *
     * However, in case the file was written by a program
     * that used a DLT_ value, rather than a LINKTYPE_ value,
     * in one of the cases where the two differ, use dlt_to_linktype()
     * to map to a LINKTYPE_ value, just as we use it to map
     * the result of pcap_datalink() to a LINKTYPE_ value.
     */
    pcap_src->linktype = dlt_to_linktype(hdr->network);
    /* Pick the appropriate maximum packet size for the link type */
    switch (pcap_src->linktype) {

    case 231: /* DLT_DBUS */
        pcap_src->cap_pipe_max_pkt_size = WTAP_MAX_PACKET_SIZE_DBUS;
        break;

    case 279: /* DLT_EBHSCR */
        pcap_src->cap_pipe_max_pkt_size = WTAP_MAX_PACKET_SIZE_EBHSCR;
        break;

    case 249: /* DLT_USBPCAP */
        pcap_src->cap_pipe_max_pkt_size = WTAP_MAX_PACKET_SIZE_USBPCAP;
        break;

    default:
        pcap_src->cap_pipe_max_pkt_size = WTAP_MAX_PACKET_SIZE_STANDARD;
        break;
    }

    if (hdr->version_major < 2) {
        snprintf(errmsg, errmsgl,
                   "The old pcap format version %d.%d is not supported.",
                   hdr->version_major, hdr->version_minor);
        snprintf(secondary_errmsg, secondary_errmsgl, "%s",
                   not_our_bug);
        goto error;
    }

    pcap_src->cap_pipe_fd = fd;
    return;

error:
    ws_debug("pcap_pipe_open_live: error %s", errmsg);
    pcap_src->cap_pipe_err = PIPERR;
    cap_pipe_close(fd, pcap_src->from_cap_socket);
    pcap_src->cap_pipe_fd = -1;
#ifdef _WIN32
    pcap_src->cap_pipe_h = INVALID_HANDLE_VALUE;
#endif
}

/*
 * Synchronously read the fixed portion of the pcapng section header block
 * (we've already read the pcapng block header).
 */
static int
pcapng_read_shb(capture_src *pcap_src,
                char *errmsg,
                size_t errmsgl)
{
    pcapng_section_header_block_t shb;

#ifdef _WIN32
    if (pcap_src->from_cap_socket)
#endif
    {
        pcap_src->cap_pipe_bytes_to_read = sizeof(pcapng_block_header_t) + sizeof(pcapng_section_header_block_t);
        if (cap_pipe_read_data_bytes(pcap_src, errmsg, errmsgl) < 0) {
            return -1;
        }
    }
#ifdef _WIN32
    else {
        pipe_read_sync(pcap_src, pcap_src->cap_pipe_databuf + sizeof(pcapng_block_header_t),
            sizeof(pcapng_section_header_block_t));
        if (pcap_src->cap_pipe_bytes_read <= 0) {
            if (pcap_src->cap_pipe_bytes_read == 0)
                snprintf(errmsg, errmsgl,
                           "End of file reading from pipe or socket.");
            else
                snprintf(errmsg, errmsgl,
                           "Error reading from pipe or socket: %s.",
                           g_strerror(errno));
            return -1;
        }
        /* Continuing with STATE_EXPECT_DATA requires reading into cap_pipe_databuf at offset cap_pipe_bytes_read */
        pcap_src->cap_pipe_bytes_read = sizeof(pcapng_block_header_t) + sizeof(pcapng_section_header_block_t);
    }
#endif
    memcpy(&shb, pcap_src->cap_pipe_databuf + sizeof(pcapng_block_header_t), sizeof(pcapng_section_header_block_t));
    switch (shb.magic)
    {
    case PCAPNG_MAGIC:
        ws_debug("pcapng SHB MAGIC");
        break;
    case PCAPNG_SWAPPED_MAGIC:
        ws_debug("pcapng SHB SWAPPED MAGIC");
        /*
         * pcapng sources can contain all sorts of block types.
         * Rather than add a bunch of complexity to this code (which is
         * often privileged), punt and tell the user to swap bytes
         * elsewhere.
         *
         * XXX - punting means that the Wireshark test suite must be
         * modified to:
         *
         *  1) have both little-endian and big-endian versions of
         *     all pcapng files piped to dumpcap;
         *
         *  2) pipe the appropriate file to dumpcap, depending on
         *     the byte order of the host on which the tests are
         *     being run;
         *
         * as per comments in bug 15772 and 15754.
         *
         * Are we *really* certain that the complexity added would be
         * significant enough to make adding it a security risk?  And
         * why would this code even be running with any elevated
         * privileges if you're capturing from a pipe?  We should not
         * only have given up all additional privileges if we're reading
         * from a pipe, we should give them up in such a fashion that
         * we can't reclaim them.
         */
#if G_BYTE_ORDER == G_BIG_ENDIAN
#define OUR_ENDIAN "big"
#define IFACE_ENDIAN "little"
#else
#define OUR_ENDIAN "little"
#define IFACE_ENDIAN "big"
#endif
        snprintf(errmsg, errmsgl,
                   "Interface %u is " IFACE_ENDIAN " endian but we're " OUR_ENDIAN " endian.",
                   pcap_src->interface_id);
        return -1;
    default:
        /* Not a pcapng type we know about, or not pcapng at all. */
        snprintf(errmsg, errmsgl,
                   "Unrecognized pcapng format or not pcapng data.");
        return -1;
    }

    pcap_src->cap_pipe_max_pkt_size = WTAP_MAX_PACKET_SIZE_STANDARD;

    /* Setup state to capture any options following the section header block */
    pcap_src->cap_pipe_state = STATE_EXPECT_DATA;

    return 0;
}

/*
 * Save IDB blocks for playback whenever we change output files, and
 * fix LINKTYPE_ values that are really platform-dependent DLT_ values.
 * Rewrite EPB and ISB interface IDs.
 */
static bool
pcapng_adjust_block(capture_src *pcap_src, const pcapng_block_header_t *bh, uint8_t *pd)
{
    switch(bh->block_type) {
    case BLOCK_TYPE_SHB:
    {
        if (global_ld.pcapng_passthrough) {
            /*
             * We have a single pcapng input. We pass the SHB through when
             * writing a single output file and for the first ring buffer
             * file. We need to save it for the second and subsequent ring
             * buffer files.
             */
            g_free(global_ld.saved_shb);
            global_ld.saved_shb = (uint8_t *) g_memdup2(pd, bh->block_total_length);

            /*
             * We're dealing with one section at a time, so we can (and must)
             * get rid of our old IDBs.
             */
            for (unsigned i = 0; i < global_ld.saved_idbs->len; i++) {
                saved_idb_t *idb_source = &g_array_index(global_ld.saved_idbs, saved_idb_t, i);
                g_free(idb_source->idb);
            }
            g_array_set_size(global_ld.saved_idbs, 0);
        } else {
            /*
             * We have a new SHB from this capture source. We need to keep
             * global_ld.saved_idbs intact, so we mark IDBs we previously
             * collected from this source as deleted.
             */
            for (unsigned i = 0; i < pcap_src->cap_pipe_info.pcapng.src_iface_to_global->len; i++) {
                uint32_t iface_id = g_array_index(pcap_src->cap_pipe_info.pcapng.src_iface_to_global, uint32_t, i);
                saved_idb_t *idb_source = &g_array_index(global_ld.saved_idbs, saved_idb_t, iface_id);
                ws_assert(idb_source->interface_id == pcap_src->interface_id);
                g_free(idb_source->idb);
                memset(idb_source, 0, sizeof(saved_idb_t));
                idb_source->deleted = true;
                ws_debug("%s: deleted pcapng IDB %u", G_STRFUNC, iface_id);
            }
        }
        g_array_set_size(pcap_src->cap_pipe_info.pcapng.src_iface_to_global, 0);
    }
        break;
    case BLOCK_TYPE_IDB:
    {
        /*
         * Always gather IDBs. We can remove them or mark them as deleted
         * when we get a new SHB.
         */
        saved_idb_t idb_source = { 0 };
        idb_source.interface_id = pcap_src->interface_id;
        idb_source.idb_len = bh->block_total_length;
        idb_source.idb = (uint8_t *) g_memdup2(pd, idb_source.idb_len);
        g_array_append_val(global_ld.saved_idbs, idb_source);
        uint32_t iface_id = global_ld.saved_idbs->len - 1;
        g_array_append_val(pcap_src->cap_pipe_info.pcapng.src_iface_to_global, iface_id);
        ws_debug("%s: mapped pcapng IDB %u -> %u from source %u",
              G_STRFUNC, pcap_src->cap_pipe_info.pcapng.src_iface_to_global->len - 1, iface_id, pcap_src->interface_id);
    }
        break;
    case BLOCK_TYPE_EPB:
    case BLOCK_TYPE_ISB:
    {
        if (global_ld.pcapng_passthrough) {
            /* Our input and output interface IDs are the same. */
            break;
        }
        /* The interface ID is the first 32-bit field after the BH for both EPBs and ISBs. */
        uint32_t iface_id;
        memcpy(&iface_id, pd + sizeof(pcapng_block_header_t), 4);
        if (iface_id < pcap_src->cap_pipe_info.pcapng.src_iface_to_global->len) {
            memcpy(pd + sizeof(pcapng_block_header_t),
                   &g_array_index(pcap_src->cap_pipe_info.pcapng.src_iface_to_global, uint32_t, iface_id), 4);
        } else {
            ws_debug("%s: pcapng EPB or ISB interface id %u > max %u", G_STRFUNC, iface_id, pcap_src->cap_pipe_info.pcapng.src_iface_to_global->len);
            return false;
        }
    }
        break;
    default:
        break;
    }

    return true;
}

/*
 * Return true if the block contains packet, event, or log data. Return false otherwise.
 */
static bool is_data_block(uint32_t block_type)
{
    // Any block types that lead to calling wtap_read_packet_bytes in
    // wiretap/pcapng.c should be listed here.
    switch (block_type) {
        case BLOCK_TYPE_PB:
        case BLOCK_TYPE_EPB:
        case BLOCK_TYPE_SPB:
        case BLOCK_TYPE_SYSTEMD_JOURNAL_EXPORT:
        case BLOCK_TYPE_SYSDIG_EVENT:
        case BLOCK_TYPE_SYSDIG_EVENT_V2:
        case BLOCK_TYPE_SYSDIG_EVENT_V2_LARGE:
            return true;
        default:
            break;
    }
    return false;
}

/*
 * Read the part of the initial pcapng SHB following the block type
 * (we've already read the block type).
 */
static void
pcapng_pipe_open_live(int fd,
                      capture_src *pcap_src,
                      char *errmsg,
                      size_t errmsgl)
{
    uint32_t type = BLOCK_TYPE_SHB;
    pcapng_block_header_t *bh = &pcap_src->cap_pipe_info.pcapng.bh;

    ws_debug("pcapng_pipe_open_live: fd %d", fd);

    /*
     * A pcapng block begins with the block type followed by the block
     * total length; we've already read the block type, now read the
     * block length.
     */
#ifdef _WIN32
    /*
     * On UN*X, we can use select() on pipes or sockets.
     *
     * On Windows, we can only use it on sockets; to do non-blocking
     * reads from pipes, we currently do reads in a separate thread
     * and use GLib asynchronous queues from the main thread to start
     * read operations and to wait for them to complete.
     */
    if (pcap_src->from_cap_socket)
#endif
    {
        memcpy(pcap_src->cap_pipe_databuf, &type, sizeof(uint32_t));
        pcap_src->cap_pipe_bytes_read = sizeof(uint32_t);
        pcap_src->cap_pipe_bytes_to_read = sizeof(pcapng_block_header_t);
        pcap_src->cap_pipe_fd = fd;
        if (cap_pipe_read_data_bytes(pcap_src, errmsg, errmsgl) < 0) {
            goto error;
        }
        memcpy(bh, pcap_src->cap_pipe_databuf, sizeof(pcapng_block_header_t));
    }
#ifdef _WIN32
    else {
        g_thread_new("cap_pipe_open_live", &cap_thread_read, pcap_src);

        bh->block_type = type;
        pipe_read_sync(pcap_src, &bh->block_total_length,
            sizeof(bh->block_total_length));
        if (pcap_src->cap_pipe_bytes_read <= 0) {
            if (pcap_src->cap_pipe_bytes_read == 0)
                snprintf(errmsg, errmsgl,
                           "End of file reading from pipe or socket.");
            else
                snprintf(errmsg, errmsgl,
                           "Error reading from pipe or socket: %s.",
                           g_strerror(errno));
            goto error;
        }
        pcap_src->cap_pipe_bytes_read = sizeof(pcapng_block_header_t);
        memcpy(pcap_src->cap_pipe_databuf, bh, sizeof(pcapng_block_header_t));
        pcap_src->cap_pipe_fd = fd;
    }
#endif
    if ((bh->block_total_length & 0x03) != 0) {
        snprintf(errmsg, errmsgl,
                   "block_total_length read from pipe is %u, which is not a multiple of 4.",
                   bh->block_total_length);
        goto error;
    }
    if (pcapng_read_shb(pcap_src, errmsg, errmsgl)) {
        goto error;
    }

    return;

error:
    ws_debug("pcapng_pipe_open_live: error %s", errmsg);
    pcap_src->cap_pipe_err = PIPERR;
    cap_pipe_close(fd, pcap_src->from_cap_socket);
    pcap_src->cap_pipe_fd = -1;
#ifdef _WIN32
    pcap_src->cap_pipe_h = INVALID_HANDLE_VALUE;
#endif
}

/* We read one record from the pipe, take care of byte order in the record
 * header, write the record to the capture file, and update capture statistics. */
static int
pcap_pipe_dispatch(loop_data *ld, capture_src *pcap_src, char *errmsg, size_t errmsgl)
{
    struct pcap_pkthdr  phdr;
    enum { PD_REC_HDR_READ, PD_DATA_READ, PD_PIPE_EOF, PD_PIPE_ERR,
           PD_ERR } result;
#ifdef _WIN32
    void *    q_status;
#endif
    ssize_t   b;
    unsigned new_bufsize;
    pcap_pipe_info_t *pcap_info = &pcap_src->cap_pipe_info.pcap;

#ifdef LOG_CAPTURE_VERBOSE
    ws_debug("pcap_pipe_dispatch");
#endif

    switch (pcap_src->cap_pipe_state) {

    case STATE_EXPECT_REC_HDR:
#ifdef _WIN32
        if (g_mutex_trylock(pcap_src->cap_pipe_read_mtx)) {
#endif

            pcap_src->cap_pipe_state = STATE_READ_REC_HDR;
            pcap_src->cap_pipe_bytes_to_read = pcap_src->cap_pipe_modified ?
                sizeof(struct pcaprec_modified_hdr) : sizeof(struct pcaprec_hdr);
            pcap_src->cap_pipe_bytes_read = 0;

#ifdef _WIN32
            pcap_src->cap_pipe_buf = (char *) &pcap_info->rechdr;
            g_async_queue_push(pcap_src->cap_pipe_pending_q, pcap_src->cap_pipe_buf);
            g_mutex_unlock(pcap_src->cap_pipe_read_mtx);
        }
#endif
        /* Fall through */

    case STATE_READ_REC_HDR:
#ifdef _WIN32
        if (pcap_src->from_cap_socket)
#endif
        {
            b = cap_pipe_read(pcap_src->cap_pipe_fd, ((char *)&pcap_info->rechdr)+pcap_src->cap_pipe_bytes_read,
                 pcap_src->cap_pipe_bytes_to_read - pcap_src->cap_pipe_bytes_read, pcap_src->from_cap_socket);
            if (b <= 0) {
                if (b == 0)
                    result = PD_PIPE_EOF;
                else
                    result = PD_PIPE_ERR;
                break;
            }
#ifdef _WIN32
            pcap_src->cap_pipe_bytes_read += (DWORD)b;
#else
            pcap_src->cap_pipe_bytes_read += b;
#endif
        }
#ifdef _WIN32
        else {
            q_status = g_async_queue_timeout_pop(pcap_src->cap_pipe_done_q, PIPE_READ_TIMEOUT);
            if (pcap_src->cap_pipe_err == PIPEOF) {
                result = PD_PIPE_EOF;
                break;
            } else if (pcap_src->cap_pipe_err == PIPERR) {
                result = PD_PIPE_ERR;
                break;
            }
            if (!q_status) {
                return 0;
            }
        }
#endif
        if (pcap_src->cap_pipe_bytes_read < pcap_src->cap_pipe_bytes_to_read) {
            /* There's still more of the pcap packet header to read. */
            return 0;
        }
        result = PD_REC_HDR_READ;
        break;

    case STATE_EXPECT_DATA:
#ifdef _WIN32
        if (g_mutex_trylock(pcap_src->cap_pipe_read_mtx)) {
#endif

            pcap_src->cap_pipe_state = STATE_READ_DATA;
            pcap_src->cap_pipe_bytes_to_read = pcap_info->rechdr.hdr.incl_len;
            pcap_src->cap_pipe_bytes_read = 0;

#ifdef _WIN32
            pcap_src->cap_pipe_buf = pcap_src->cap_pipe_databuf;
            g_async_queue_push(pcap_src->cap_pipe_pending_q, pcap_src->cap_pipe_buf);
            g_mutex_unlock(pcap_src->cap_pipe_read_mtx);
        }
#endif
        /* Fall through */

    case STATE_READ_DATA:
#ifdef _WIN32
        if (pcap_src->from_cap_socket)
#endif
        {
            b = cap_pipe_read(pcap_src->cap_pipe_fd,
                              pcap_src->cap_pipe_databuf+pcap_src->cap_pipe_bytes_read,
                              pcap_src->cap_pipe_bytes_to_read - pcap_src->cap_pipe_bytes_read,
                              pcap_src->from_cap_socket);
            if (b <= 0) {
                if (b == 0)
                    result = PD_PIPE_EOF;
                else
                    result = PD_PIPE_ERR;
                break;
            }
#ifdef _WIN32
            pcap_src->cap_pipe_bytes_read += (DWORD)b;
#else
            pcap_src->cap_pipe_bytes_read += b;
#endif
        }
#ifdef _WIN32
        else {

            q_status = g_async_queue_timeout_pop(pcap_src->cap_pipe_done_q, PIPE_READ_TIMEOUT);
            if (pcap_src->cap_pipe_err == PIPEOF) {
                result = PD_PIPE_EOF;
                break;
            } else if (pcap_src->cap_pipe_err == PIPERR) {
                result = PD_PIPE_ERR;
                break;
            }
            if (!q_status) {
                return 0;
            }
        }
#endif /* _WIN32 */
        if (pcap_src->cap_pipe_bytes_read < pcap_src->cap_pipe_bytes_to_read) {
            /* There's still more of the pcap packet data to read. */
            return 0;
        }
        result = PD_DATA_READ;
        break;

    default:
        snprintf(errmsg, errmsgl,
                   "pcap_pipe_dispatch: invalid state");
        result = PD_ERR;

    } /* switch (pcap_src->cap_pipe_state) */

    /*
     * We've now read as much data as we were expecting, so process it.
     */
    switch (result) {

    case PD_REC_HDR_READ:
        /*
         * We've read the packet header, so we know the captured length,
         * and thus the number of packet data bytes. Take care of byte order.
         */
        cap_pipe_adjust_pcap_header(pcap_src->cap_pipe_info.pcap.byte_swapped, &pcap_info->hdr,
                               &pcap_info->rechdr.hdr);
        if (pcap_info->rechdr.hdr.incl_len > pcap_src->cap_pipe_max_pkt_size) {
            /*
             * The record contains more data than the advertised/allowed in the
             * pcap header, do not try to read more data (do not change to
             * STATE_EXPECT_DATA) as that would not fit in the buffer and
             * instead stop with an error.
             */
            snprintf(errmsg, errmsgl, "Frame %u too long (%d bytes)",
                       ld->packets_captured+1, pcap_info->rechdr.hdr.incl_len);
            break;
        }

        if (pcap_info->rechdr.hdr.incl_len > pcap_src->cap_pipe_databuf_size) {
            /*
             * Grow the buffer to the packet size, rounded up to a power of
             * 2.
             */
            new_bufsize = pcap_info->rechdr.hdr.incl_len;
            /*
             * https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
             */
            new_bufsize--;
            new_bufsize |= new_bufsize >> 1;
            new_bufsize |= new_bufsize >> 2;
            new_bufsize |= new_bufsize >> 4;
            new_bufsize |= new_bufsize >> 8;
            new_bufsize |= new_bufsize >> 16;
            new_bufsize++;
            pcap_src->cap_pipe_databuf = (char*)g_realloc(pcap_src->cap_pipe_databuf, new_bufsize);
            pcap_src->cap_pipe_databuf_size = new_bufsize;
        }

        if (pcap_info->rechdr.hdr.incl_len) {
            /*
             * The record has some data following the header, try
             * to read it next time.
             */
            pcap_src->cap_pipe_state = STATE_EXPECT_DATA;
            return 0;
        }

        /*
         * No data following the record header? Then no more data needs to be
         * read and we will fallthrough and emit an empty packet.
         */
        /* FALLTHROUGH */

    case PD_DATA_READ:
        /*
         * We've read the full contents of the packet record.
         * Fill in a "struct pcap_pkthdr", and process the packet.
         */
        phdr.ts.tv_sec = pcap_info->rechdr.hdr.ts_sec;
        phdr.ts.tv_usec = pcap_info->rechdr.hdr.ts_usec;
        phdr.caplen = pcap_info->rechdr.hdr.incl_len;
        phdr.len = pcap_info->rechdr.hdr.orig_len;

        if (use_threads) {
            capture_loop_queue_packet_cb((uint8_t *)pcap_src, &phdr, pcap_src->cap_pipe_databuf);
        } else {
            capture_loop_write_packet_cb((uint8_t *)pcap_src, &phdr, pcap_src->cap_pipe_databuf);
        }

        /*
         * Now we want to read the next packet's header.
         */
        pcap_src->cap_pipe_state = STATE_EXPECT_REC_HDR;
        return 1;

    case PD_PIPE_EOF:
        pcap_src->cap_pipe_err = PIPEOF;
        return -1;

    case PD_PIPE_ERR:
        snprintf(errmsg, errmsgl, "Error reading from pipe: %s",
#ifdef _WIN32
                   win32strerror(GetLastError()));
#else
                   g_strerror(errno));
#endif
        /* Fall through */
    case PD_ERR:
        break;
    }

    pcap_src->cap_pipe_err = PIPERR;
    /* Return here rather than inside the switch to prevent GCC warning */
    return -1;
}

static int
pcapng_pipe_dispatch(loop_data *ld, capture_src *pcap_src, char *errmsg, size_t errmsgl)
{
    enum { PD_REC_HDR_READ, PD_DATA_READ, PD_PIPE_EOF, PD_PIPE_ERR,
           PD_ERR } result;
#ifdef _WIN32
    void *    q_status;
#endif
    unsigned new_bufsize;
    pcapng_block_header_t *bh = &pcap_src->cap_pipe_info.pcapng.bh;

#ifdef LOG_CAPTURE_VERBOSE
    ws_debug("pcapng_pipe_dispatch");
#endif

    switch (pcap_src->cap_pipe_state) {

    case STATE_EXPECT_REC_HDR:
#ifdef LOG_CAPTURE_VERBOSE
        ws_debug("pcapng_pipe_dispatch STATE_EXPECT_REC_HDR");
#endif
#ifdef _WIN32
        if (g_mutex_trylock(pcap_src->cap_pipe_read_mtx)) {
#endif

            pcap_src->cap_pipe_state = STATE_READ_REC_HDR;
            pcap_src->cap_pipe_bytes_to_read = sizeof(pcapng_block_header_t);
            pcap_src->cap_pipe_bytes_read = 0;

#ifdef _WIN32
            if (!pcap_src->from_cap_socket) {
                pcap_src->cap_pipe_buf = pcap_src->cap_pipe_databuf;
                g_async_queue_push(pcap_src->cap_pipe_pending_q, pcap_src->cap_pipe_buf);
            }
            g_mutex_unlock(pcap_src->cap_pipe_read_mtx);
        }
#endif
        /* Fall through */

    case STATE_READ_REC_HDR:
#ifdef LOG_CAPTURE_VERBOSE
        ws_debug("pcapng_pipe_dispatch STATE_READ_REC_HDR");
#endif
#ifdef _WIN32
        if (pcap_src->from_cap_socket) {
#endif
            if (cap_pipe_read_data_bytes(pcap_src, errmsg, errmsgl) < 0) {
                return -1;
            }
#ifdef _WIN32
        } else {
            q_status = g_async_queue_timeout_pop(pcap_src->cap_pipe_done_q, PIPE_READ_TIMEOUT);
            if (pcap_src->cap_pipe_err == PIPEOF) {
                result = PD_PIPE_EOF;
                break;
            } else if (pcap_src->cap_pipe_err == PIPERR) {
                result = PD_PIPE_ERR;
                break;
            }
            if (!q_status) {
                return 0;
            }
        }
#endif
        if (pcap_src->cap_pipe_bytes_read < pcap_src->cap_pipe_bytes_to_read) {
            /* There's still more of the pcapng block header to read. */
            return 0;
        }
        memcpy(bh, pcap_src->cap_pipe_databuf, sizeof(pcapng_block_header_t));
        result = PD_REC_HDR_READ;
        break;

    case STATE_EXPECT_DATA:
#ifdef LOG_CAPTURE_VERBOSE
        ws_debug("pcapng_pipe_dispatch STATE_EXPECT_DATA");
#endif
#ifdef _WIN32
        if (g_mutex_trylock(pcap_src->cap_pipe_read_mtx)) {
#endif
            pcap_src->cap_pipe_state = STATE_READ_DATA;
            pcap_src->cap_pipe_bytes_to_read = bh->block_total_length;

#ifdef _WIN32
            if (!pcap_src->from_cap_socket) {
                pcap_src->cap_pipe_bytes_to_read -= pcap_src->cap_pipe_bytes_read;
                pcap_src->cap_pipe_buf = pcap_src->cap_pipe_databuf + pcap_src->cap_pipe_bytes_read;
                pcap_src->cap_pipe_bytes_read = 0;
                g_async_queue_push(pcap_src->cap_pipe_pending_q, pcap_src->cap_pipe_buf);
            }
            g_mutex_unlock(pcap_src->cap_pipe_read_mtx);
        }
#endif
        /* Fall through */

    case STATE_READ_DATA:
#ifdef LOG_CAPTURE_VERBOSE
        ws_debug("pcapng_pipe_dispatch STATE_READ_DATA");
#endif
#ifdef _WIN32
        if (pcap_src->from_cap_socket) {
#endif
            if (cap_pipe_read_data_bytes(pcap_src, errmsg, errmsgl) < 0) {
                return -1;
            }
#ifdef _WIN32
        } else {

            q_status = g_async_queue_timeout_pop(pcap_src->cap_pipe_done_q, PIPE_READ_TIMEOUT);
            if (pcap_src->cap_pipe_err == PIPEOF) {
                result = PD_PIPE_EOF;
                break;
            } else if (pcap_src->cap_pipe_err == PIPERR) {
                result = PD_PIPE_ERR;
                break;
            }
            if (!q_status) {
                return 0;
            }
        }
#endif /* _WIN32 */
        if (pcap_src->cap_pipe_bytes_read < pcap_src->cap_pipe_bytes_to_read) {
            /* There's still more of the pcap block contents to read. */
            return 0;
        }
        result = PD_DATA_READ;
        break;

    default:
        snprintf(errmsg, errmsgl,
                   "pcapng_pipe_dispatch: invalid state");
        result = PD_ERR;

    } /* switch (pcap_src->cap_pipe_state) */

    /*
     * We've now read as much data as we were expecting, so process it.
     */
    switch (result) {

    case PD_REC_HDR_READ:
        /*
         * We've read the pcapng block header, so we know the block type
         * and length.
         */
        if (bh->block_type == BLOCK_TYPE_SHB) {
            /*
             * We need to read the fixed portion of the SHB before to
             * get the endianness before we can interpret the block length.
             * (The block type of the SHB is byte-order-independent, so that
             * an SHB can be recognized before we know the endianness of
             * the section.)
             *
             * Continue the read process.
             */
            pcapng_read_shb(pcap_src, errmsg, errmsgl);
            return 1;
        }

        if ((bh->block_total_length & 0x03) != 0) {
            snprintf(errmsg, errmsgl,
                       "Total length of pcapng block read from pipe is %u, which is not a multiple of 4.",
                       bh->block_total_length);
            break;
        }
        if (is_data_block(bh->block_type) && bh->block_total_length > pcap_src->cap_pipe_max_pkt_size) {
            /*
            * The record contains more data than the advertised/allowed in the
            * pcapng header, do not try to read more data (do not change to
            * STATE_EXPECT_DATA) as that would not fit in the buffer and
            * instead stop with an error.
            */
            snprintf(errmsg, errmsgl, "Block %u type 0x%08x too long (%d bytes)",
                    ld->packets_captured+1, bh->block_type, bh->block_total_length);
            break;
        }

        if (bh->block_total_length > pcap_src->cap_pipe_databuf_size) {
            /*
            * Grow the buffer to the packet size, rounded up to a power of
            * 2.
            */
            new_bufsize = bh->block_total_length;
            /*
            * https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
            */
            new_bufsize--;
            new_bufsize |= new_bufsize >> 1;
            new_bufsize |= new_bufsize >> 2;
            new_bufsize |= new_bufsize >> 4;
            new_bufsize |= new_bufsize >> 8;
            new_bufsize |= new_bufsize >> 16;
            new_bufsize++;
            pcap_src->cap_pipe_databuf = (unsigned char*)g_realloc(pcap_src->cap_pipe_databuf, new_bufsize);
            pcap_src->cap_pipe_databuf_size = new_bufsize;
        }

        /* The record always has at least the block total length following the header */
        if (bh->block_total_length < sizeof(pcapng_block_header_t)+sizeof(uint32_t)) {
            snprintf(errmsg, errmsgl,
                       "malformed pcapng block_total_length < minimum");
            pcap_src->cap_pipe_err = PIPEOF;
            return -1;
        }

        /*
         * Now we want to read the block contents.
         */
        pcap_src->cap_pipe_state = STATE_EXPECT_DATA;
        return 0;

    case PD_DATA_READ:
        /*
         * We've read the full contents of the block.
         * Process the block.
         */
        if (use_threads) {
            capture_loop_queue_pcapng_cb(pcap_src, bh, pcap_src->cap_pipe_databuf);
        } else {
            capture_loop_write_pcapng_cb(pcap_src, bh, pcap_src->cap_pipe_databuf);
        }

        /*
         * Now we want to read the next block's header.
         */
        pcap_src->cap_pipe_state = STATE_EXPECT_REC_HDR;
        return 1;

    case PD_PIPE_EOF:
        pcap_src->cap_pipe_err = PIPEOF;
        return -1;

    case PD_PIPE_ERR:
        snprintf(errmsg, errmsgl, "Error reading from pipe: %s",
#ifdef _WIN32
                   win32strerror(GetLastError()));
#else
                   g_strerror(errno));
#endif
        /* Fall through */
    case PD_ERR:
        break;
    }

    pcap_src->cap_pipe_err = PIPERR;
    /* Return here rather than inside the switch to prevent GCC warning */
    return -1;
}

/** Open the capture input sources; each one is either a pcap device,
 *  a capture pipe, or a capture socket.
 *  Returns true if it succeeds, false otherwise. */
static bool
capture_loop_open_input(capture_options *capture_opts, loop_data *ld,
                        char *errmsg, size_t errmsg_len,
                        char *secondary_errmsg, size_t secondary_errmsg_len)
{
    cap_device_open_status open_status;
    char                open_status_str[PCAP_ERRBUF_SIZE];
    char               *sync_msg_str;
    interface_options  *interface_opts;
    capture_src        *pcap_src;
    unsigned            i;

    if ((use_threads == false) &&
        (capture_opts->ifaces->len > 1)) {
        snprintf(errmsg, errmsg_len,
                   "Using threads is required for capturing on multiple interfaces.");
        return false;
    }

    int pcapng_src_count = 0;
    for (i = 0; i < capture_opts->ifaces->len; i++) {
        interface_opts = &g_array_index(capture_opts->ifaces, interface_options, i);
        pcap_src = g_new0(capture_src, 1);
        if (pcap_src == NULL) {
            snprintf(errmsg, errmsg_len,
                   "Could not allocate memory.");
            return false;
        }

#ifdef MUST_DO_SELECT
        pcap_src->pcap_fd = -1;
#endif
        pcap_src->interface_id = i;
        pcap_src->linktype = -1;
#ifdef _WIN32
        pcap_src->cap_pipe_h = INVALID_HANDLE_VALUE;
#endif
        pcap_src->cap_pipe_fd = -1;
        pcap_src->cap_pipe_dispatch = pcap_pipe_dispatch;
        pcap_src->cap_pipe_state = STATE_EXPECT_REC_HDR;
        pcap_src->cap_pipe_err = PIPOK;
#ifdef _WIN32
        pcap_src->cap_pipe_read_mtx = g_new(GMutex, 1);
        g_mutex_init(pcap_src->cap_pipe_read_mtx);
        pcap_src->cap_pipe_pending_q = g_async_queue_new();
        pcap_src->cap_pipe_done_q = g_async_queue_new();
#endif
        g_array_append_val(ld->pcaps, pcap_src);

        ws_debug("capture_loop_open_input : %s", interface_opts->name);
        pcap_src->pcap_h = open_capture_device(capture_opts, interface_opts,
            CAP_READ_TIMEOUT, &open_status, &open_status_str);

        if (pcap_src->pcap_h != NULL) {
            /* we've opened "iface" as a network device */

#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
            /* Find out if we're getting nanosecond-precision time stamps */
            pcap_src->ts_nsec = have_high_resolution_timestamp(pcap_src->pcap_h);
#endif

#if defined(HAVE_PCAP_SETSAMPLING)
            if (interface_opts->sampling_method != CAPTURE_SAMP_NONE) {
                struct pcap_samp *samp;

                if ((samp = pcap_setsampling(pcap_src->pcap_h)) != NULL) {
                    switch (interface_opts->sampling_method) {
                    case CAPTURE_SAMP_BY_COUNT:
                        samp->method = PCAP_SAMP_1_EVERY_N;
                        break;

                    case CAPTURE_SAMP_BY_TIMER:
                        samp->method = PCAP_SAMP_FIRST_AFTER_N_MS;
                        break;

                    default:
                        sync_msg_str = ws_strdup_printf(
                            "Unknown sampling method %d specified,\n"
                            "continue without packet sampling",
                            interface_opts->sampling_method);
                        report_capture_error("Couldn't set the capture "
                                             "sampling", sync_msg_str);
                        g_free(sync_msg_str);
                    }
                    samp->value = interface_opts->sampling_param;
                } else {
                    report_capture_error("Couldn't set the capture sampling",
                                         "Cannot get packet sampling data structure");
                }
            }
#endif

            /* setting the data link type only works on real interfaces */
            if (!set_pcap_datalink(pcap_src->pcap_h, interface_opts->linktype,
                                   interface_opts->name,
                                   errmsg, errmsg_len,
                                   secondary_errmsg, secondary_errmsg_len)) {
                return false;
            }
            pcap_src->linktype = dlt_to_linktype(get_pcap_datalink(pcap_src->pcap_h, interface_opts->name));
        } else {
            /* We couldn't open "iface" as a network device. */
            /* Try to open it as a pipe */
            bool pipe_err = false;
            cap_pipe_open_live(interface_opts->name, pcap_src,
                               &pcap_src->cap_pipe_info.pcap.hdr,
                               errmsg, errmsg_len,
                               secondary_errmsg, secondary_errmsg_len);

#ifdef _WIN32
            if (pcap_src->from_cap_socket) {
#endif
                if (pcap_src->cap_pipe_fd == -1) {
                    pipe_err = true;
                }
#ifdef _WIN32
            } else {
                if (pcap_src->cap_pipe_h == INVALID_HANDLE_VALUE) {
                    pipe_err = true;
                }
            }
#endif

            if (pipe_err) {
                if (pcap_src->cap_pipe_err == PIPNEXIST) {
                    /*
                     * We tried opening as an interface, and that failed,
                     * so we tried to open it as a pipe, but the pipe
                     * doesn't exist.  Report the error message for
                     * the interface.
                     */
                    get_capture_device_open_failure_messages(open_status,
                                                             open_status_str,
                                                             interface_opts->name,
                                                             errmsg,
                                                             errmsg_len,
                                                             secondary_errmsg,
                                                             secondary_errmsg_len);
                }
                /*
                 * Else pipe (or file) does exist and cap_pipe_open_live() has
                 * filled in errmsg
                 */
                return false;
            } else {
                /*
                 * We tried opening as an interface, and that failed,
                 * so we tried to open it as a pipe, and that succeeded.
                 */
                open_status = CAP_DEVICE_OPEN_NO_ERR;
            }
        }

/* XXX - will this work for tshark? */
#ifdef MUST_DO_SELECT
        if (!pcap_src->from_cap_pipe) {
            pcap_src->pcap_fd = pcap_get_selectable_fd(pcap_src->pcap_h);
        }
#endif

        /* Is "open_status" something other than CAP_DEVICE_OPEN_NO_ERR?
           If so, "open_capture_device()" returned a warning; print it,
           but keep capturing. */
        if (open_status != CAP_DEVICE_OPEN_NO_ERR) {
            sync_msg_str = ws_strdup_printf("%s.", open_status_str);
            report_capture_error(sync_msg_str, "");
            g_free(sync_msg_str);
        }
        if (pcap_src->from_pcapng) {
            /*
             * We will use the IDBs from the source (but rewrite the
             * interface IDs if there's more than one source.)
             */
            pcapng_src_count++;
        } else {
            /*
             * Add our pcapng interface entry.
             */
            saved_idb_t idb_source = { 0 };
            idb_source.interface_id = i;
            g_rw_lock_writer_lock (&ld->saved_shb_idb_lock);
            pcap_src->idb_id = global_ld.saved_idbs->len;
            g_array_append_val(global_ld.saved_idbs, idb_source);
            g_rw_lock_writer_unlock (&ld->saved_shb_idb_lock);
            ws_debug("%s: saved capture_opts %u to IDB %u",
                  G_STRFUNC, i, pcap_src->idb_id);
        }
    }

    /*
     * Are we capturing from one source that is providing pcapng
     * information?
     */
    if (capture_opts->ifaces->len == 1 && pcapng_src_count == 1) {
        /*
         * Yes; pass through SHBs and IDBs from the source, rather
         * than generating our own.
         */
        ld->pcapng_passthrough = true;
        g_rw_lock_writer_lock (&ld->saved_shb_idb_lock);
        ws_assert(global_ld.saved_idbs->len == 0);
        ws_debug("%s: Pass through SHBs and IDBs directly", G_STRFUNC);
        g_rw_lock_writer_unlock (&ld->saved_shb_idb_lock);
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
    return true;
}

/* close the capture input file (pcap or capture pipe) */
static void capture_loop_close_input(loop_data *ld)
{
    unsigned     i;
    capture_src *pcap_src;

    ws_debug("capture_loop_close_input");

    for (i = 0; i < ld->pcaps->len; i++) {
        pcap_src = g_array_index(ld->pcaps, capture_src *, i);
        /* Pipe, or capture device? */
        if (pcap_src->from_cap_pipe) {
            /* Pipe. If open, close the capture pipe "input file". */
            if (pcap_src->cap_pipe_fd >= 0) {
                cap_pipe_close(pcap_src->cap_pipe_fd, pcap_src->from_cap_socket);
                pcap_src->cap_pipe_fd = -1;
            }
#ifdef _WIN32
            if (pcap_src->cap_pipe_h != INVALID_HANDLE_VALUE) {
                CloseHandle(pcap_src->cap_pipe_h);
                pcap_src->cap_pipe_h = INVALID_HANDLE_VALUE;
            }
#endif
            if (pcap_src->cap_pipe_databuf != NULL) {
                /* Free the buffer. */
                g_free(pcap_src->cap_pipe_databuf);
                pcap_src->cap_pipe_databuf = NULL;
            }
            if (pcap_src->from_pcapng) {
                g_array_free(pcap_src->cap_pipe_info.pcapng.src_iface_to_global, TRUE);
                pcap_src->cap_pipe_info.pcapng.src_iface_to_global = NULL;
            }
        } else {
            /* Capture device.  If open, close the pcap_t. */
            if (pcap_src->pcap_h != NULL) {
                ws_debug("capture_loop_close_input: closing %p", (void *)pcap_src->pcap_h);
                pcap_close(pcap_src->pcap_h);
                pcap_src->pcap_h = NULL;
            }
        }
    }

    ld->go = false;
}


/* init the capture filter */
static initfilter_status_t
capture_loop_init_filter(pcap_t *pcap_h, bool from_cap_pipe,
                         const char * name, const char * cfilter)
{
    struct bpf_program fcode;

    ws_debug("capture_loop_init_filter: %s", cfilter);

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

/*
 * Write the dumpcap pcapng SHB and IDBs if needed.
 * Called from capture_loop_init_output and do_file_switch_or_stop.
 */
static bool
capture_loop_init_pcapng_output(capture_options *capture_opts, loop_data *ld,
                                int *err)
{
    g_rw_lock_reader_lock (&ld->saved_shb_idb_lock);

    if (ld->pcapng_passthrough && !ld->saved_shb) {
        /* We have a single pcapng capture interface and this is the first or only output file. */
        ws_debug("%s: skipping dumpcap SHB and IDBs in favor of source", G_STRFUNC);
        g_rw_lock_reader_unlock (&ld->saved_shb_idb_lock);
        return true;
    }

    bool successful = true;
    GString *os_info_str = g_string_new("");

    *err = 0;
    get_os_version_info(os_info_str);

    if (ld->saved_shb) {
        /* We have a single pcapng capture interface and multiple output files. */

        pcapng_block_header_t bh;

        memcpy(&bh, ld->saved_shb, sizeof(pcapng_block_header_t));

        successful = pcapng_write_block(ld->pdh, ld->saved_shb, bh.block_total_length, &ld->bytes_written, err);

        ws_debug("%s: wrote saved passthrough SHB %d", G_STRFUNC, successful);
    } else {
        GString *cpu_info_str = g_string_new("");
        get_cpu_info(cpu_info_str);

        successful = pcapng_write_section_header_block(ld->pdh,
                                                       capture_comments,   /* Comments */
                                                       cpu_info_str->str,           /* HW */
                                                       os_info_str->str,            /* OS */
                                                       get_appname_and_version(),
                                                       -1,                          /* section_length */
                                                       &ld->bytes_written,
                                                       err);
        ws_debug("%s: wrote dumpcap SHB %d", G_STRFUNC, successful);
        g_string_free(cpu_info_str, TRUE);
    }

    for (unsigned i = 0; successful && (i < ld->saved_idbs->len); i++) {
        saved_idb_t idb_source = g_array_index(ld->saved_idbs, saved_idb_t, i);
        if (idb_source.deleted) {
            /*
             * Our interface is out of scope. Suppose we're writing multiple
             * files and a source switches sections. We currently write dummy
             * IDBs like so:
             *
             * File 1: IDB0, IDB1, IDB2
             * [ The source of IDBs 1 and 2 writes an SHB with two new IDBs ]
             * [ We switch output files ]
             * File 2: IDB0, dummy IDB, dummy IDB, IDB3, IDB4
             *
             * It might make more sense to write the original data so that
             * so that our IDB lists are more consistent across files.
             */
            successful = pcapng_write_interface_description_block(global_ld.pdh,
                                                                  "Interface went out of scope",    /* OPT_COMMENT       1 */
                                                                  "dummy",                          /* IDB_NAME          2 */
                                                                  "Dumpcap dummy interface",        /* IDB_DESCRIPTION   3 */
                                                                  NULL,                             /* IDB_FILTER       11 */
                                                                  os_info_str->str,                 /* IDB_OS           12 */
                                                                  NULL,                             /* IDB_HARDWARE     15 */
                                                                  -1,
                                                                  0,
                                                                  &(global_ld.bytes_written),
                                                                  0,                                /* IDB_IF_SPEED      8 */
                                                                  6,                                /* IDB_TSRESOL       9 */
                                                                  &global_ld.err);
            ws_debug("%s: skipping deleted pcapng IDB %u", G_STRFUNC, i);
        } else if (idb_source.idb && idb_source.idb_len) {
            successful = pcapng_write_block(global_ld.pdh, idb_source.idb, idb_source.idb_len, &ld->bytes_written, err);
            ws_debug("%s: wrote pcapng IDB %d", G_STRFUNC, successful);
        } else if (idb_source.interface_id < capture_opts->ifaces->len) {
            unsigned if_id = idb_source.interface_id;
            interface_options *interface_opts = &g_array_index(capture_opts->ifaces, interface_options, if_id);
            capture_src *pcap_src = g_array_index(ld->pcaps, capture_src *, if_id);
            if (pcap_src->from_cap_pipe) {
                pcap_src->snaplen = pcap_src->cap_pipe_info.pcap.hdr.snaplen;
            } else {
                pcap_src->snaplen = pcap_snapshot(pcap_src->pcap_h);
            }
            successful = pcapng_write_interface_description_block(global_ld.pdh,
                                                                   NULL,                       /* OPT_COMMENT       1 */
                                                                  (interface_opts->ifname != NULL) ? interface_opts->ifname : interface_opts->name, /* IDB_NAME          2 */
                                                                  interface_opts->descr,      /* IDB_DESCRIPTION   3 */
                                                                  interface_opts->cfilter,    /* IDB_FILTER       11 */
                                                                  os_info_str->str,           /* IDB_OS           12 */
                                                                  interface_opts->hardware,   /* IDB_HARDWARE     15 */
                                                                  pcap_src->linktype,
                                                                  pcap_src->snaplen,
                                                                  &(global_ld.bytes_written),
                                                                  0,                          /* IDB_IF_SPEED      8 */
                                                                  pcap_src->ts_nsec ? 9 : 6,  /* IDB_TSRESOL       9 */
                                                                  &global_ld.err);
            ws_debug("%s: wrote capture_opts IDB %d: %d", G_STRFUNC, if_id, successful);
        }
    }
    g_rw_lock_reader_unlock (&ld->saved_shb_idb_lock);

    g_string_free(os_info_str, TRUE);

    return successful;
}

/* set up to write to the already-opened capture output file/files */
static bool
capture_loop_init_output(capture_options *capture_opts, loop_data *ld, char *errmsg, int errmsg_len)
{
    int err = 0;

    ws_debug("capture_loop_init_output");

    if ((capture_opts->use_pcapng == false) &&
        (capture_opts->ifaces->len > 1)) {
        snprintf(errmsg, errmsg_len,
                   "Using PCAPNG is required for capturing on multiple interfaces. Use the -n option.");
        return false;
    }

    /* Set up to write to the capture file. */
    if (capture_opts->multi_files_on) {
        ld->pdh = ringbuf_init_libpcap_fdopen(&err);
    } else {
        ld->pdh = ws_fdopen(ld->save_file_fd, "wb");
        if (ld->pdh == NULL) {
            err = errno;
        } else {
            size_t buffsize = IO_BUF_SIZE;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
            ws_statb64 statb;

            if (ws_fstat64(ld->save_file_fd, &statb) == 0) {
                if (statb.st_blksize > IO_BUF_SIZE) {
                    buffsize = statb.st_blksize;
                }
            }
#endif
            /* Increase the size of the IO buffer */
            ld->io_buffer = (char *)g_malloc(buffsize);
            setvbuf(ld->pdh, ld->io_buffer, _IOFBF, buffsize);
            ws_debug("capture_loop_init_output: buffsize %zu", buffsize);
        }
    }
    if (ld->pdh) {
        bool successful;
        if (capture_opts->use_pcapng) {
            successful = capture_loop_init_pcapng_output(capture_opts, ld, &err);
        } else {
            capture_src *pcap_src;
            pcap_src = g_array_index(ld->pcaps, capture_src *, 0);
            if (pcap_src->from_cap_pipe) {
                pcap_src->snaplen = pcap_src->cap_pipe_info.pcap.hdr.snaplen;
            } else {
                pcap_src->snaplen = pcap_snapshot(pcap_src->pcap_h);
            }
            successful = libpcap_write_file_header(ld->pdh, pcap_src->linktype, pcap_src->snaplen,
                                                pcap_src->ts_nsec, &ld->bytes_written, &err);
        }
        if (!successful) {
            fclose(ld->pdh);
            ld->pdh = NULL;
            g_free(ld->io_buffer);
            ld->io_buffer = NULL;
        }
    }

    if (ld->pdh == NULL) {
        /* We couldn't set up to write to the capture file. */
        /* XXX - use cf_open_error_message from tshark instead? */
        if (err < 0) {
            snprintf(errmsg, errmsg_len,
                       "The file to which the capture would be"
                       " saved (\"%s\") could not be opened: Error %d.",
                       capture_opts->save_file, err);
        } else {
            snprintf(errmsg, errmsg_len,
                       "The file to which the capture would be"
                       " saved (\"%s\") could not be opened: %s.",
                       capture_opts->save_file, g_strerror(err));
        }
        return false;
    }

    return true;
}

static bool
capture_loop_close_output(capture_options *capture_opts, loop_data *ld, int *err_close)
{

    unsigned int i;
    capture_src *pcap_src;
    uint64_t     end_time = create_timestamp();
    bool success;

    ws_debug("capture_loop_close_output");

    if (capture_opts->multi_files_on) {
        return ringbuf_libpcap_dump_close(&capture_opts->save_file, err_close);
    } else {
        if (capture_opts->use_pcapng) {
            for (i = 0; i < global_ld.pcaps->len; i++) {
                pcap_src = g_array_index(global_ld.pcaps, capture_src *, i);
                if (!pcap_src->from_cap_pipe) {
                    uint64_t isb_ifrecv, isb_ifdrop;
                    struct pcap_stat stats;

                    if (pcap_stats(pcap_src->pcap_h, &stats) >= 0) {
                        isb_ifrecv = pcap_src->received;
                        isb_ifdrop = stats.ps_drop + pcap_src->dropped + pcap_src->flushed;
                   } else {
                        isb_ifrecv = UINT64_MAX;
                        isb_ifdrop = UINT64_MAX;
                    }
                    pcapng_write_interface_statistics_block(ld->pdh,
                                                            i,
                                                            &ld->bytes_written,
                                                            "Counters provided by dumpcap",
                                                            start_time,
                                                            end_time,
                                                            isb_ifrecv,
                                                            isb_ifdrop,
                                                            err_close);
                }
            }
        }
        if (fclose(ld->pdh) == EOF) {
            if (err_close != NULL) {
                *err_close = errno;
            }
            success = false;
        } else {
            success = true;
        }
        g_free(ld->io_buffer);
        ld->io_buffer = NULL;
        return success;
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
                      char *errmsg, int errmsg_len, capture_src *pcap_src)
{
    int    inpkts = 0;
    int    packet_count_before;
    int    sel_ret;

    packet_count_before = ld->packets_captured;
    if (pcap_src->from_cap_pipe) {
        /* dispatch from capture pipe */
#ifdef LOG_CAPTURE_VERBOSE
        ws_debug("capture_loop_dispatch: from capture pipe");
#endif
#ifdef _WIN32
        if (pcap_src->from_cap_socket) {
#endif
            sel_ret = cap_pipe_select(pcap_src->cap_pipe_fd);
            if (sel_ret <= 0) {
                if (sel_ret < 0 && errno != EINTR) {
                    snprintf(errmsg, errmsg_len,
                            "Unexpected error from select: %s", g_strerror(errno));
                    report_capture_error(errmsg, please_report_bug());
                    ld->go = false;
                }
            }
#ifdef _WIN32
        } else {
            /* Windows does not have select() for pipes. */
            /* Proceed with _dispatch() which waits for cap_pipe_done_q
             * notification from cap_thread_read() when ReadFile() on
             * the pipe has read enough bytes. */
            sel_ret = 1;
        }
#endif
        if (sel_ret > 0) {
            /*
             * "select()" says we can read from the pipe without blocking
             */
            inpkts = pcap_src->cap_pipe_dispatch(ld, pcap_src, errmsg, errmsg_len);
            if (inpkts < 0) {
                ws_debug("%s: src %u pipe reached EOF or err, rcv: %u drop: %u flush: %u",
                      G_STRFUNC, pcap_src->interface_id, pcap_src->received, pcap_src->dropped, pcap_src->flushed);
                ws_assert(pcap_src->cap_pipe_err != PIPOK);
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
        ws_debug("capture_loop_dispatch: from pcap_dispatch with select");
#endif
        if (pcap_src->pcap_fd != -1) {
            sel_ret = cap_pipe_select(pcap_src->pcap_fd);
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
                    inpkts = pcap_dispatch(pcap_src->pcap_h, 1, capture_loop_queue_packet_cb, (uint8_t *)pcap_src);
                } else {
                    inpkts = pcap_dispatch(pcap_src->pcap_h, 1, capture_loop_write_packet_cb, (uint8_t *)pcap_src);
                }
                if (inpkts < 0) {
                    if (inpkts == -1) {
                        /* Error, rather than pcap_breakloop(). */
                        pcap_src->pcap_err = true;
                    }
                    ld->go = false; /* error or pcap_breakloop() - stop capturing */
                }
            } else {
                if (sel_ret < 0 && errno != EINTR) {
                    snprintf(errmsg, errmsg_len,
                               "Unexpected error from select: %s", g_strerror(errno));
                    report_capture_error(errmsg, please_report_bug());
                    ld->go = false;
                }
            }
        }
        else
#endif /* MUST_DO_SELECT */
        {
            /* dispatch from pcap without select */
#if 1
#ifdef LOG_CAPTURE_VERBOSE
            ws_debug("capture_loop_dispatch: from pcap_dispatch");
#endif
#ifdef _WIN32
            /*
             * On Windows, we don't support asynchronously telling a process to
             * stop capturing; instead, we check for an indication on a pipe
             * after processing packets.  We therefore process only one packet
             * at a time, so that we can check the pipe after every packet.
             */
            if (use_threads) {
                inpkts = pcap_dispatch(pcap_src->pcap_h, 1, capture_loop_queue_packet_cb, (uint8_t *)pcap_src);
            } else {
                inpkts = pcap_dispatch(pcap_src->pcap_h, 1, capture_loop_write_packet_cb, (uint8_t *)pcap_src);
            }
#else
            if (use_threads) {
                inpkts = pcap_dispatch(pcap_src->pcap_h, -1, capture_loop_queue_packet_cb, (uint8_t *)pcap_src);
            } else {
                inpkts = pcap_dispatch(pcap_src->pcap_h, -1, capture_loop_write_packet_cb, (uint8_t *)pcap_src);
            }
#endif
            if (inpkts < 0) {
                if (inpkts == -1) {
                    /* Error, rather than pcap_breakloop(). */
                    pcap_src->pcap_err = true;
                }
                ld->go = false; /* error or pcap_breakloop() - stop capturing */
            }
#else /* pcap_next_ex */
#ifdef LOG_CAPTURE_VERBOSE
            ws_debug("capture_loop_dispatch: from pcap_next_ex");
#endif
            /* XXX - this is currently unused, as there is some confusion with pcap_next_ex() vs. pcap_dispatch() */

            /*
             * WinPcap's remote capturing feature doesn't work with pcap_dispatch(),
             * see https://gitlab.com/wireshark/wireshark/-/wikis/CaptureSetup/WinPcapRemote
             * This should be fixed in the WinPcap 4.0 alpha release.
             *
             * For reference, an example remote interface:
             * rpcap://[1.2.3.4]/\Device\NPF_{39993D68-7C9B-4439-A329-F2D888DA7C5C}
             */

            /* emulate dispatch from pcap */
            {
                int in;
                struct pcap_pkthdr *pkt_header;
                uint8_t *pkt_data;

                in = 0;
                while(ld->go &&
                      (in = pcap_next_ex(pcap_src->pcap_h, &pkt_header, &pkt_data)) == 1) {
                    if (use_threads) {
                        capture_loop_queue_packet_cb((uint8_t *)pcap_src, pkt_header, pkt_data);
                    } else {
                        capture_loop_write_packet_cb((uint8_t *)pcap_src, pkt_header, pkt_data);
                    }
                }

                if (in < 0) {
                    pcap_src->pcap_err = true;
                    ld->go = false;
                }
            }
#endif /* pcap_next_ex */
        }
    }

#ifdef LOG_CAPTURE_VERBOSE
    ws_debug("capture_loop_dispatch: %d new packet%s", inpkts, plurality(inpkts, "", "s"));
#endif

    return ld->packets_captured - packet_count_before;
}

#ifdef _WIN32
/* Isolate the Universally Unique Identifier from the interface.  Basically, we
 * want to grab only the characters between the '{' and '}' delimiters.
 *
 * Returns a GString that must be freed with g_string_free(). */
static GString *
isolate_uuid(const char *iface)
{
    char    *ptr;
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
/* Returns true if the file opened successfully, false otherwise. */
static bool
capture_loop_open_output(capture_options *capture_opts, int *save_file_fd,
                         char *errmsg, int errmsg_len)
{
    char     *capfile_name = NULL;
    char     *prefix, *suffix;
    bool      is_tempfile;
    GError   *err_tempfile = NULL;

    ws_debug("capture_loop_open_output: %s",
          (capture_opts->save_file) ? capture_opts->save_file : "(not specified)");

    if (capture_opts->save_file != NULL) {
        /* We return to the caller while the capture is in progress.
         * Therefore we need to take a copy of save_file in
         * case the caller destroys it after we return.
         */
        capfile_name = g_strdup(capture_opts->save_file);

        if (capture_opts->output_to_pipe == true) { /* either "-" or named pipe */
            if (capture_opts->multi_files_on) {
                /* ringbuffer is enabled; that doesn't work with standard output or a named pipe */
                snprintf(errmsg, errmsg_len,
                           "Ring buffer requested, but capture is being written to standard output or to a named pipe.");
                g_free(capfile_name);
                return false;
            }
            if (strcmp(capfile_name, "-") == 0) {
                /* write to stdout */
                *save_file_fd = 1;
#ifdef _WIN32
                /* set output pipe to binary mode to avoid Windows text-mode processing (eg: for CR/LF)  */
                _setmode(1, O_BINARY);
#endif
            } else {
                /* Try to open the specified FIFO for use as a capture buffer.
                   Do *not* create it if it doesn't exist.  There's nothing
                   to truncate. If we need to read it, We Have A Problem. */
                *save_file_fd = ws_open(capfile_name, O_WRONLY|O_BINARY, 0);
            }
        } /* if (...output_to_pipe ... */

        else {
            if (capture_opts->multi_files_on) {
                /* ringbuffer is enabled */
                *save_file_fd = ringbuf_init(capfile_name,
                                             (capture_opts->has_ring_num_files) ? capture_opts->ring_num_files : 0,
                                             capture_opts->group_read_access,
                                             capture_opts->compress_type,
                                             capture_opts->has_nametimenum);

                /* capfile_name is unused as the ringbuffer provides its own filename. */
                if (*save_file_fd != -1) {
                    g_free(capfile_name);
                    capfile_name = NULL;
                }
                if (capture_opts->print_file_names) {
                    if (!ringbuf_set_print_name(capture_opts->print_name_to, NULL)) {
                        snprintf(errmsg, errmsg_len, "Could not write filenames to %s: %s.\n",
                                   capture_opts->print_name_to,
                                   g_strerror(errno));
                        g_free(capfile_name);
                        ringbuf_error_cleanup();
                        return false;
                    }
                }
            } else {
                /* Try to open/create the specified file for use as a capture buffer. */
                *save_file_fd = ws_open(capfile_name, O_WRONLY|O_BINARY|O_TRUNC|O_CREAT,
                                        (capture_opts->group_read_access) ? 0640 : 0600);
            }
        }
        is_tempfile = false;
    } else {
        /* Choose a random name for the temporary capture buffer */
        if (global_capture_opts.ifaces->len > 1) {
            /*
             * More than one interface; just use the number of interfaces
             * to generate the temporary file name prefix.
             */
            prefix = ws_strdup_printf("wireshark_%d_interfaces", global_capture_opts.ifaces->len);
        } else {
            /*
             * One interface; use its description, if it has one, to generate
             * the temporary file name, otherwise use its name.
             */
            char *basename;
            const interface_options *interface_opts;

            interface_opts = &g_array_index(global_capture_opts.ifaces, interface_options, 0);

            /*
             * Do we have a description?
             */
            if (interface_opts->descr) {
                /*
                 * Yes - use it.
                 *
                 * Strip off any stuff we shouldn't use in the file name,
                 * by getting the last component of what would be a file
                 * name.
                 */
                basename = g_path_get_basename(interface_opts->descr);
            } else {
                /*
                 * No - use the name.
                 *
                 * Strip off any stuff we shouldn't use in the file name,
                 * by getting the last component of what would be a file
                 * name.
                 */
                basename = g_path_get_basename(interface_opts->name);
#ifdef _WIN32
                /*
                 * This is Windows, where we might have an ugly GUID-based
                 * interface name.
                 *
                 * If it's an ugly GUID-based name, use the generic portion
                 * of the interface GUID to form the basis of the filename.
                 */
                if (strncmp("NPF_{", basename, 5) == 0) {
                    /*
                     * We have a GUID-based name; extract the GUID digits
                     * as the basis of the filename.
                     */
                    GString *iface;
                    iface = isolate_uuid(basename);
                    g_free(basename);
                    basename = g_strdup(iface->str);
                    g_string_free(iface, TRUE);
                }
#endif
            }
            /* generate the temp file name prefix */
            prefix = g_strconcat("wireshark_", basename, NULL);
            g_free(basename);
        }

        /* Generate the appropriate suffix. */
        if (capture_opts->use_pcapng) {
            suffix = ".pcapng";
        } else {
            suffix = ".pcap";
        }
        *save_file_fd = create_tempfile(capture_opts->temp_dir, &capfile_name, prefix, suffix, &err_tempfile);
        g_free(prefix);
        is_tempfile = true;
    }

    /* did we fail to open the output file? */
    if (*save_file_fd == -1) {
        if (is_tempfile) {
            snprintf(errmsg, errmsg_len,
                       "The temporary file to which the capture would be saved "
                       "could not be opened: %s.", err_tempfile->message);
            g_error_free(err_tempfile);
        } else {
            if (capture_opts->multi_files_on) {
                /* Ensures that the ringbuffer is not used. This ensures that
                 * !ringbuf_is_initialized() is equivalent to
                 * capture_opts->save_file not being part of ringbuffer. */
                ringbuf_error_cleanup();
            }

            snprintf(errmsg, errmsg_len,
                       "The file to which the capture would be saved (\"%s\") "
                       "could not be opened: %s.", capfile_name,
                       g_strerror(errno));
        }
        g_free(capfile_name);
        return false;
    }

    g_free(capture_opts->save_file);
    if (!is_tempfile && capture_opts->multi_files_on) {
        /* In ringbuffer mode, save_file points to a filename from ringbuffer.c.
         * capfile_name was already freed before. */
        capture_opts->save_file = (char *)ringbuf_current_filename();
    } else {
        /* capture_opts_cleanup will g_free(capture_opts->save_file). */
        capture_opts->save_file = capfile_name;
    }

    return true;
}

static time_t get_next_time_interval(int interval_s) {
    time_t next_time = time(NULL);
    next_time -= next_time % interval_s;
    next_time += interval_s;
    return next_time;
}

/* Do the work of handling either the file size or file duration capture
   conditions being reached, and switching files or stopping. */
static bool
do_file_switch_or_stop(capture_options *capture_opts)
{
    bool              successful;

    if (capture_opts->multi_files_on) {
        if (capture_opts->has_autostop_files &&
            ++global_ld.file_count >= capture_opts->autostop_files) {
            /* no files left: stop here */
            global_ld.go = false;
            return false;
        }

        /* Switch to the next ringbuffer file */
        if (ringbuf_switch_file(&global_ld.pdh, &capture_opts->save_file,
                                &global_ld.save_file_fd, &global_ld.err)) {

            /* File switch succeeded: reset the conditions */
            global_ld.bytes_written = 0;
            global_ld.packets_written = 0;
            if (capture_opts->use_pcapng) {
                successful = capture_loop_init_pcapng_output(capture_opts, &global_ld, &global_ld.err);
            } else {
                capture_src *pcap_src;
                pcap_src = g_array_index(global_ld.pcaps, capture_src *, 0);
                successful = libpcap_write_file_header(global_ld.pdh, pcap_src->linktype, pcap_src->snaplen,
                                                       pcap_src->ts_nsec, &global_ld.bytes_written, &global_ld.err);
            }

            if (!successful) {
                fclose(global_ld.pdh);
                global_ld.pdh = NULL;
                global_ld.go = false;
                g_free(global_ld.io_buffer);
                global_ld.io_buffer = NULL;
                return false;
            }
            if (global_ld.file_duration_timer) {
                g_timer_reset(global_ld.file_duration_timer);
            }
            if (global_ld.next_interval_time) {
                global_ld.next_interval_time = get_next_time_interval(global_ld.interval_s);
            }
            fflush(global_ld.pdh);
            if (global_ld.inpkts_to_sync_pipe) {
                if (!quiet)
                    report_packet_count(global_ld.inpkts_to_sync_pipe);
                global_ld.inpkts_to_sync_pipe = 0;
            }
            report_new_capture_file(capture_opts->save_file);
        } else {
            /* File switch failed: stop here */
            global_ld.go = false;
            return false;
        }
    } else {
        /* single file, stop now */
        global_ld.go = false;
        return false;
    }
    return true;
}

static void *
pcap_read_handler(void* arg)
{
    capture_src *pcap_src = (capture_src *)arg;
    char         errmsg[MSG_MAX_LENGTH+1];

    ws_info("Started thread for interface %d.", pcap_src->interface_id);

    /* If this is a pipe input it might finish early. */
    while (global_ld.go && pcap_src->cap_pipe_err == PIPOK) {
        /* dispatch incoming packets */
        capture_loop_dispatch(&global_ld, errmsg, sizeof(errmsg), pcap_src);
    }

    ws_info("Stopped thread for interface %d.", pcap_src->interface_id);
    g_thread_exit(NULL);
    return (NULL);
}

/* Try to pop an item off the packet queue and if it exists, write it */
static bool
capture_loop_dequeue_packet(void) {
    pcap_queue_element *queue_element;

    g_async_queue_lock(pcap_queue);
    queue_element = (pcap_queue_element *)g_async_queue_timeout_pop_unlocked(pcap_queue, WRITER_THREAD_TIMEOUT);
    if (queue_element) {
        if (queue_element->pcap_src->from_pcapng) {
            pcap_queue_bytes -= queue_element->u.bh.block_total_length;
        } else {
            pcap_queue_bytes -= queue_element->u.phdr.caplen;
        }
        pcap_queue_packets -= 1;
    }
    g_async_queue_unlock(pcap_queue);
    if (queue_element) {
        if (queue_element->pcap_src->from_pcapng) {
            ws_info("Dequeued a block of type 0x%08x of length %d captured on interface %d.",
                  queue_element->u.bh.block_type, queue_element->u.bh.block_total_length,
                  queue_element->pcap_src->interface_id);

            capture_loop_write_pcapng_cb(queue_element->pcap_src,
                                        &queue_element->u.bh,
                                        queue_element->pd);
        } else {
            ws_info("Dequeued a packet of length %d captured on interface %d.",
                queue_element->u.phdr.caplen, queue_element->pcap_src->interface_id);

            capture_loop_write_packet_cb((uint8_t *) queue_element->pcap_src,
                                        &queue_element->u.phdr,
                                        queue_element->pd);
        }
        g_free(queue_element->pd);
        g_free(queue_element);
        return true;
    }
    return false;
}

/*
 * Note: this code will never be run on any OS other than Windows.
 *
 * We keep the arguments in case there's something in the future
 * that needs to be reported as an NPCAP bug.
 */
static char *
handle_npcap_bug(char *adapter_name _U_, char *cap_err_str _U_)
{
    bool have_npcap = false;

#ifdef _WIN32
    have_npcap = caplibs_have_npcap();
#endif

    if (!have_npcap) {
        /*
         * We're not using Npcap, so don't recomment a user
         * file a bug against Npcap.
         */
        return g_strdup("");
    }

    return ws_strdup_printf("If you have not removed that adapter, this "
                          "is probably a known issue in Npcap resulting from "
                          "the behavior of the Windows networking stack. "
                          "Work is being done in Npcap to improve the "
                          "handling of this issue; it does not need to "
                          "be reported as a Wireshark or Npcap bug.");
}

/* Do the low-level work of a capture.
   Returns true if it succeeds, false otherwise. */
static bool
capture_loop_start(capture_options *capture_opts, bool *stats_known, struct pcap_stat *stats)
{
#ifdef _WIN32
    ULONGLONG         upd_time, cur_time; /* GetTickCount64() returns a "ULONGLONG" */
#else
    struct timeval    upd_time, cur_time;
#endif
    int               err_close;
    int               inpkts;
    GTimer           *autostop_duration_timer = NULL;
    bool              write_ok;
    bool              close_ok;
    bool              cfilter_error         = false;
    char              errmsg[MSG_MAX_LENGTH+1];
    char              secondary_errmsg[MSG_MAX_LENGTH+1];
    capture_src      *pcap_src;
    interface_options *interface_opts;
    unsigned          i, error_index        = 0;

    *errmsg           = '\0';
    *secondary_errmsg = '\0';

    /* init the loop data */
    global_ld.go                  = true;
    global_ld.packets_captured    = 0;
#ifdef SIGINFO
    global_ld.report_packet_count = false;
#endif
    global_ld.inpkts_to_sync_pipe = 0;
    global_ld.err                 = 0;  /* no error seen yet */
    global_ld.pdh                 = NULL;
    global_ld.save_file_fd        = -1;
    global_ld.io_buffer           = NULL;
    global_ld.file_count          = 0;
    global_ld.file_duration_timer = NULL;
    global_ld.next_interval_time  = 0;
    global_ld.interval_s          = 0;

    /* We haven't yet gotten the capture statistics. */
    *stats_known      = false;

    ws_info("Capture loop starting ...");
    capture_opts_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_DEBUG, capture_opts);

    /* open the "input file" from network interface or capture pipe */
    if (!capture_loop_open_input(capture_opts, &global_ld, errmsg, sizeof(errmsg),
                                 secondary_errmsg, sizeof(secondary_errmsg))) {
        goto error;
    }
    for (i = 0; i < capture_opts->ifaces->len; i++) {
        pcap_src = g_array_index(global_ld.pcaps, capture_src *, i);
        interface_opts = &g_array_index(capture_opts->ifaces, interface_options, i);
        /* init the input filter from the network interface (capture pipe will do nothing) */
        /*
         * When remote capturing WinPCap crashes when the capture filter
         * is NULL. This might be a bug in WPCap. Therefore we provide an empty
         * string.
         */
        switch (capture_loop_init_filter(pcap_src->pcap_h, pcap_src->from_cap_pipe,
                                         interface_opts->name,
                                         interface_opts->cfilter?interface_opts->cfilter:"")) {

        case INITFILTER_NO_ERROR:
            break;

        case INITFILTER_BAD_FILTER:
            cfilter_error = true;
            error_index = i;
            snprintf(errmsg, sizeof(errmsg), "%s", pcap_geterr(pcap_src->pcap_h));
            goto error;

        case INITFILTER_OTHER_ERROR:
            snprintf(errmsg, sizeof(errmsg), "Can't install filter (%s).",
                       pcap_geterr(pcap_src->pcap_h));
            snprintf(secondary_errmsg, sizeof(secondary_errmsg), "%s", please_report_bug());
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
        fflush(global_ld.pdh);
        report_new_capture_file(capture_opts->save_file);
    }

    if (capture_opts->has_file_interval) {
        global_ld.interval_s = capture_opts->file_interval;
        global_ld.next_interval_time = get_next_time_interval(global_ld.interval_s);
    }
    /* create stop conditions */
    if (capture_opts->has_autostop_filesize) {
        if (capture_opts->autostop_filesize > UINT32_C(2000000000)) {
            capture_opts->autostop_filesize = UINT32_C(2000000000);
        }
    }
    if (capture_opts->has_autostop_duration) {
        autostop_duration_timer = g_timer_new();
    }

    if (capture_opts->multi_files_on) {
        if (capture_opts->has_file_duration) {
            global_ld.file_duration_timer = g_timer_new();
        }
    }

    /* init the time values */
#ifdef _WIN32
    upd_time = GetTickCount64();
#else
    gettimeofday(&upd_time, NULL);
#endif
    start_time = create_timestamp();
    ws_info("Capture loop running.");
    capture_opts_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_DEBUG, capture_opts);

    /* WOW, everything is prepared! */
    /* please fasten your seat belts, we will enter now the actual capture loop */
    if (use_threads) {
        pcap_queue = g_async_queue_new();
        pcap_queue_bytes = 0;
        pcap_queue_packets = 0;
        for (i = 0; i < global_ld.pcaps->len; i++) {
            pcap_src = g_array_index(global_ld.pcaps, capture_src *, i);
            /* XXX - Add an interface name here? */
            pcap_src->tid = g_thread_new("Capture read", pcap_read_handler, pcap_src);
        }
    }
    while (global_ld.go) {
        /* dispatch incoming packets */
        if (use_threads) {
            bool dequeued = capture_loop_dequeue_packet();

            if (dequeued) {
                inpkts = 1;
            } else {
                inpkts = 0;
            }
        } else {
            pcap_src = g_array_index(global_ld.pcaps, capture_src *, 0);
            inpkts = capture_loop_dispatch(&global_ld, errmsg,
                                           sizeof(errmsg), pcap_src);
        }
        if (inpkts == 0) {
            /* Stop capturing if all of our sources are pipes and none of them are open. */
            bool open_interfaces = false;
            for (i = 0; i < global_ld.pcaps->len; i++) {
                pcap_src = g_array_index(global_ld.pcaps, capture_src *, i);
                if (pcap_src->cap_pipe_err == PIPOK) {
                    /* True for both non-pipes and open pipes. */
                    open_interfaces = true;
                }
            }
            if (!open_interfaces) {
                global_ld.go = false;
            }
        }
#ifdef SIGINFO
        /* Were we asked to print packet counts by the SIGINFO handler? */
        if (global_ld.report_packet_count) {
            fprintf(stderr, "%u packet%s captured\n", global_ld.packets_captured,
                    plurality(global_ld.packets_captured, "", "s"));
            global_ld.report_packet_count = false;
        }
#endif

#ifdef _WIN32
        /* any news from our parent (signal pipe)? -> just stop the capture */
        if (!signal_pipe_check_running()) {
            global_ld.go = false;
        }
#endif

        if (inpkts > 0) {
            if (capture_opts->output_to_pipe) {
                fflush(global_ld.pdh);
            }
        } /* inpkts */

        /* Only update after an interval so as not to overload slow displays.
         * This also prevents too much context-switching between the dumpcap
         * and wireshark processes.
         * XXX: Should we send updates sooner if there have been lots of
         * packets we haven't notified the parent about, such as on fast links?
         */
#ifdef _WIN32
        cur_time = GetTickCount64();
        if ((cur_time - upd_time) > capture_opts->update_interval)
#else
        gettimeofday(&cur_time, NULL);
        if (((uint64_t)cur_time.tv_sec * 1000000 + cur_time.tv_usec) >
            ((uint64_t)upd_time.tv_sec * 1000000 + upd_time.tv_usec + capture_opts->update_interval*1000))
#endif
        {

            upd_time = cur_time;

#if 0
            if (pcap_stats(pch, stats) >= 0) {
                *stats_known = true;
            }
#endif
            /* Let the parent process know. */
            if (global_ld.inpkts_to_sync_pipe) {
                /* do sync here */
                fflush(global_ld.pdh);

                /* Send our parent a message saying we've written out
                   "global_ld.inpkts_to_sync_pipe" packets to the capture file. */
                if (!quiet)
                    report_packet_count(global_ld.inpkts_to_sync_pipe);

                global_ld.inpkts_to_sync_pipe = 0;
            }

            /* check capture duration condition */
            if (autostop_duration_timer != NULL && g_timer_elapsed(autostop_duration_timer, NULL) >= capture_opts->autostop_duration) {
                /* The maximum capture time has elapsed; stop the capture. */
                global_ld.go = false;
                continue;
            }

            /* check capture file duration condition */
            if (global_ld.file_duration_timer != NULL && g_timer_elapsed(global_ld.file_duration_timer, NULL) >= capture_opts->file_duration) {
                /* duration limit reached, do we have another file? */
                if (!do_file_switch_or_stop(capture_opts))
                    continue;
            } /* cnd_file_duration */

            /* check capture file interval condition */
            if (global_ld.interval_s && time(NULL) >= global_ld.next_interval_time) {
                /* end of interval reached, do we have another file? */
                if (!do_file_switch_or_stop(capture_opts))
                    continue;
            } /* cnd_file_interval */
        }
    }

    ws_info("Capture loop stopping ...");
    if (use_threads) {

        for (i = 0; i < global_ld.pcaps->len; i++) {
            pcap_src = g_array_index(global_ld.pcaps, capture_src *, i);
            ws_info("Waiting for thread of interface %u...", pcap_src->interface_id);
            g_thread_join(pcap_src->tid);
            ws_info("Thread of interface %u terminated.", pcap_src->interface_id);
        }
        while (1) {
            bool dequeued = capture_loop_dequeue_packet();
            if (!dequeued) {
                break;
            }
            if (capture_opts->output_to_pipe) {
                fflush(global_ld.pdh);
            }
        }
    }


    /* delete stop conditions */
    if (global_ld.file_duration_timer != NULL)
        g_timer_destroy(global_ld.file_duration_timer);
    if (autostop_duration_timer != NULL)
        g_timer_destroy(autostop_duration_timer);

    /* did we have a pcap (input) error? */
    for (i = 0; i < capture_opts->ifaces->len; i++) {
        pcap_src = g_array_index(global_ld.pcaps, capture_src *, i);
        if (pcap_src->pcap_err) {
            /* On Linux, if an interface goes down while you're capturing on it,
               you'll get "recvfrom: Network is down".
               (At least you will if g_strerror() doesn't show a local translation
               of the error.)

               Newer versions of libpcap maps that to just
               "The interface went down".

               On FreeBSD, DragonFly BSD, and macOS, if a network adapter
               disappears while you're capturing on it, you'll get
               "read: Device not configured" error (ENXIO).  (See previous
               parenthetical note.)

               On OpenBSD, you get "read: I/O error" (EIO) in the same case.

               With WinPcap and Npcap, you'll get
               "read error: PacketReceivePacket failed" or
               "PacketReceivePacket error: The device has been removed. (1617)".

               Newer versions of libpcap map some or all of those to just
               "The interface disappeared" or something beginning with
               "The interface disappeared".

               These should *not* be reported to the Wireshark developers,
               although, with Npcap, "The interface disappeared" messages
               should perhaps be reported to the Npcap developers, at least
               until errors of that sort that shouldn't happen are fixed,
               if that's possible. */
            char *cap_err_str;
            char *primary_msg;
            char *secondary_msg;

            interface_opts = &g_array_index(capture_opts->ifaces, interface_options, i);
            cap_err_str = pcap_geterr(pcap_src->pcap_h);
            if (strcmp(cap_err_str, "The interface went down") == 0 ||
                strcmp(cap_err_str, "recvfrom: Network is down") == 0) {
                primary_msg = ws_strdup_printf("The network adapter \"%s\" "
                                              "is no longer running; the "
                                              "capture has stopped.",
                                              interface_opts->display_name);
                secondary_msg = g_strdup("");
            } else if (strcmp(cap_err_str, "The interface disappeared") == 0 ||
                       strcmp(cap_err_str, "read: Device not configured") == 0 ||
                       strcmp(cap_err_str, "read: I/O error") == 0 ||
                       strcmp(cap_err_str, "read error: PacketReceivePacket failed") == 0) {
                primary_msg = ws_strdup_printf("The network adapter \"%s\" "
                                              "is no longer attached; the "
                                              "capture has stopped.",
                                              interface_opts->display_name);
                secondary_msg = g_strdup("");
            } else if (g_str_has_prefix(cap_err_str, "The interface disappeared ")) {
                /*
                 * Npcap, if it picks up a recent commit to libpcap, will
                 * report an error *beginning* with "The interface
                 * disappeared", with the name of the Windows status code,
                 * and the corresponding NT status code, after it.
                 *
                 * Those should be reported as Npcap issues.
                 */
                primary_msg = ws_strdup_printf("The network adapter \"%s\" "
                                              "is no longer attached; the "
                                              "capture has stopped.",
                                              interface_opts->display_name);
                secondary_msg = handle_npcap_bug(interface_opts->display_name,
                                                 cap_err_str);
            } else if (g_str_has_prefix(cap_err_str, "PacketReceivePacket error:") &&
                       g_str_has_suffix(cap_err_str, "(1617)")) {
                /*
                 * "PacketReceivePacket error: {message in arbitrary language} (1617)",
                 * which is ERROR_DEVICE_REMOVED.
                 *
                 * Current libpcap/Npcap treat ERROR_GEN_FAILURE as
                 * "the device is no longer attached"; users are also
                 * getting ERROR_DEVICE_REMOVED.
                 *
                 * For now, some users appear to be getg ERROR_DEVICE_REMOVED
                 * in cases where the device *wasn't* removed, so tell
                 * them to report this as an Npcap issue; I seem to
                 * remember some discussion between Daniel and somebody
                 * at Microsoft about the Windows 10 network stack setup/
                 * teardown code being modified to try to prevent those
                 * sort of problems popping up, but I can't find that
                 * discussion.
                 */
                primary_msg = ws_strdup_printf("The network adapter \"%s\" "
                                              "is no longer attached; the "
                                              "capture has stopped.",
                                              interface_opts->display_name);
                secondary_msg = handle_npcap_bug(interface_opts->display_name,
                                                 "The interface disappeared (error code ERROR_DEVICE_REMOVED/STATUS_DEVICE_REMOVED)");
            } else if (strcmp(cap_err_str, "The other host terminated the connection.") == 0 ||
                       g_str_has_prefix(cap_err_str, "Is the server properly installed?")) {
                /*
                 * Networking error for a remote capture.
                 */
                primary_msg = g_strdup(cap_err_str);
                secondary_msg = g_strdup("This may be a problem with the "
                                         "remote host on which you are "
                                         "capturing packets.");
            } else {
                primary_msg = ws_strdup_printf("Error while capturing packets: %s",
                                              cap_err_str);
                secondary_msg = g_strdup(please_report_bug());
            }
            report_capture_error(primary_msg, secondary_msg);
            g_free(primary_msg);
            g_free(secondary_msg);
            break;
        } else if (pcap_src->from_cap_pipe && pcap_src->cap_pipe_err == PIPERR) {
            report_capture_error(errmsg, "");
            break;
        }
    }
    /* did we have an output error while capturing? */
    if (global_ld.err == 0) {
        write_ok = true;
    } else {
        capture_loop_get_errmsg(errmsg, sizeof(errmsg), secondary_errmsg,
                                sizeof(secondary_errmsg),
                                capture_opts->save_file, global_ld.err, false);
        report_capture_error(errmsg, secondary_errmsg);
        write_ok = false;
    }

    if (capture_opts->saving_to_file) {
        /* close the output file */
        close_ok = capture_loop_close_output(capture_opts, &global_ld, &err_close);
    } else
        close_ok = true;

    /* there might be packets not yet notified to the parent */
    /* (do this after closing the file, so all packets are already flushed) */
    if (global_ld.inpkts_to_sync_pipe) {
        if (!quiet)
            report_packet_count(global_ld.inpkts_to_sync_pipe);
        global_ld.inpkts_to_sync_pipe = 0;
    }

    /* If we've displayed a message about a write error, there's no point
       in displaying another message about an error on close. */
    if (!close_ok && write_ok) {
        capture_loop_get_errmsg(errmsg, sizeof(errmsg), secondary_errmsg,
                                sizeof(secondary_errmsg),
                                capture_opts->save_file, err_close, true);
        report_capture_error(errmsg, secondary_errmsg);
    }

    /*
     * XXX We exhibit different behaviour between normal mode and sync mode
     * when the pipe is stdin and not already at EOF.  If we're a child, the
     * parent's stdin isn't closed, so if the user starts another capture,
     * cap_pipe_open_live() will very likely not see the expected magic bytes and
     * will say "Unrecognized libpcap format".  On the other hand, in normal
     * mode, cap_pipe_open_live() will say "End of file on pipe during open".
     */

    report_capture_count(!really_quiet);

    /* get packet drop statistics from pcap */
    for (i = 0; i < capture_opts->ifaces->len; i++) {
        uint32_t received;
        uint32_t pcap_dropped = 0;

        pcap_src = g_array_index(global_ld.pcaps, capture_src *, i);
        interface_opts = &g_array_index(capture_opts->ifaces, interface_options, i);
        received = pcap_src->received;
        if (pcap_src->pcap_h != NULL) {
            ws_assert(!pcap_src->from_cap_pipe);
            /* Get the capture statistics, so we know how many packets were dropped. */
            if (pcap_stats(pcap_src->pcap_h, stats) >= 0) {
                *stats_known = true;
                /* Let the parent process know. */
                pcap_dropped += stats->ps_drop;
            } else {
                snprintf(errmsg, sizeof(errmsg),
                           "Can't get packet-drop statistics: %s",
                           pcap_geterr(pcap_src->pcap_h));
                report_capture_error(errmsg, please_report_bug());
            }
        }
        report_packet_drops(received, pcap_dropped, pcap_src->dropped, pcap_src->flushed, stats->ps_ifdrop, interface_opts->display_name);
    }

    /* close the input file (pcap or capture pipe) */
    capture_loop_close_input(&global_ld);

    ws_info("Capture loop stopped.");

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
        }
    }
    if (cfilter_error)
        report_cfilter_error(capture_opts, error_index, errmsg);
    else
        report_capture_error(errmsg, secondary_errmsg);

    /* close the input file (pcap or cap_pipe) */
    capture_loop_close_input(&global_ld);

    ws_info("Capture loop stopped with error");

    return false;
}


static void
capture_loop_stop(void)
{
    unsigned     i;
    capture_src *pcap_src;

    for (i = 0; i < global_ld.pcaps->len; i++) {
        pcap_src = g_array_index(global_ld.pcaps, capture_src *, i);
        if (pcap_src->pcap_h != NULL)
            pcap_breakloop(pcap_src->pcap_h);
    }
    global_ld.go = false;
}


static void
capture_loop_get_errmsg(char *errmsg, size_t errmsglen, char *secondary_errmsg,
                        size_t secondary_errmsglen, const char *fname,
                        int err, bool is_close)
{
    static const char find_space[] =
        "You will need to free up space on that file system"
        " or put the capture file on a different file system.";

    switch (err) {

    case ENOSPC:
        snprintf(errmsg, errmsglen,
                   "Not all the packets could be written to the file"
                   " to which the capture was being saved\n"
                   "(\"%s\") because there is no space left on the file system\n"
                   "on which that file resides.",
                   fname);
        snprintf(secondary_errmsg, secondary_errmsglen, "%s", find_space);
        break;

#ifdef EDQUOT
    case EDQUOT:
        snprintf(errmsg, errmsglen,
                   "Not all the packets could be written to the file"
                   " to which the capture was being saved\n"
                   "(\"%s\") because you are too close to, or over,"
                   " your disk quota\n"
                   "on the file system on which that file resides.",
                   fname);
        snprintf(secondary_errmsg, secondary_errmsglen, "%s", find_space);
        break;
#endif

    default:
        if (is_close) {
            snprintf(errmsg, errmsglen,
                       "The file to which the capture was being saved\n"
                       "(\"%s\") could not be closed: %s.",
                       fname, g_strerror(err));
        } else {
            snprintf(errmsg, errmsglen,
                       "An error occurred while writing to the file"
                       " to which the capture was being saved\n"
                       "(\"%s\"): %s.",
                       fname, g_strerror(err));
        }
        snprintf(secondary_errmsg, secondary_errmsglen,
                   "%s", please_report_bug());
        break;
    }
}

/*
 * We wrote one packet. Update some statistics and check if we've met any
 * autostop or ring buffer conditions.
 */
static void
capture_loop_wrote_one_packet(capture_src *pcap_src) {
    global_ld.packets_captured++;
    global_ld.packets_written++;
    global_ld.inpkts_to_sync_pipe++;

    if (!use_threads) {
        pcap_src->received++;
    }

    /* check -c NUM */
    if (global_capture_opts.has_autostop_packets && global_ld.packets_captured >= global_capture_opts.autostop_packets) {
        fflush(global_ld.pdh);
        global_ld.go = false;
        return;
    }
    /* check -a packets:NUM (treat like -c NUM) */
    if (global_capture_opts.has_autostop_written_packets && global_ld.packets_captured >= global_capture_opts.autostop_written_packets) {
        fflush(global_ld.pdh);
        global_ld.go = false;
        return;
    }
    /* check -b packets:NUM */
    if (global_capture_opts.has_file_packets && global_ld.packets_written >= global_capture_opts.file_packets) {
        do_file_switch_or_stop(&global_capture_opts);
        return;
    }
    /* check -a filesize:NUM */
    if (global_capture_opts.has_autostop_filesize &&
        global_capture_opts.autostop_filesize > 0 &&
        global_ld.bytes_written / 1000 >= global_capture_opts.autostop_filesize) {
        /* Capture size limit reached, do we have another file? */
        do_file_switch_or_stop(&global_capture_opts);
        return;
    }
}

/* one pcapng block was captured, process it */
static void
capture_loop_write_pcapng_cb(capture_src *pcap_src, const pcapng_block_header_t *bh, uint8_t *pd)
{
    int          err;

    /*
     * This should never be called if we're not writing pcapng.
     */
    ws_assert(global_capture_opts.use_pcapng);

    /* We may be called multiple times from pcap_dispatch(); if we've set
       the "stop capturing" flag, ignore this packet, as we're not
       supposed to be saving any more packets. */
    if (!global_ld.go) {
        pcap_src->flushed++;
        return;
    }

    if (!pcapng_adjust_block(pcap_src, bh, pd)) {
        ws_info("%s failed to adjust pcapng block.", G_STRFUNC);
        ws_assert_not_reached();
        return;
    }

    if (bh->block_type == BLOCK_TYPE_SHB && !global_ld.pcapng_passthrough) {
        /*
         * capture_loop_init_pcapng_output should've handled this. We need
         * to write ISBs when they're initially read so we shouldn't skip
         * them here.
         */
        return;
    }

    if (global_ld.pdh) {
        bool successful;

        /* We're supposed to write the packet to a file; do so.
           If this fails, set "ld->go" to false, to stop the capture, and set
           "ld->err" to the error. */
        successful = pcapng_write_block(global_ld.pdh,
                                       pd,
                                       bh->block_total_length,
                                       &global_ld.bytes_written, &err);

        fflush(global_ld.pdh);
        if (!successful) {
            global_ld.go = false;
            global_ld.err = err;
            pcap_src->dropped++;
        } else if (is_data_block(bh->block_type)) {
            /* Count packets for block types that should be dissected, i.e. ones that show up in the packet list. */
            ws_debug("Wrote a pcapng block type 0x%04x of length %d captured on interface %u.",
                   bh->block_type, bh->block_total_length, pcap_src->interface_id);
            capture_loop_wrote_one_packet(pcap_src);
        } else if (bh->block_type == BLOCK_TYPE_SHB && report_capture_filename) {
            ws_debug("Sending SP_FILE on first SHB");
            /* SHB is now ready for capture parent to read on SP_FILE message */
            sync_pipe_write_string_msg(sync_pipe_fd, SP_FILE, report_capture_filename);
            report_capture_filename = NULL;
        }
    }
}

/* one pcap packet was captured, process it */
static void
capture_loop_write_packet_cb(uint8_t *pcap_src_p, const struct pcap_pkthdr *phdr,
                             const uint8_t *pd)
{
    capture_src *pcap_src = (capture_src *) (void *) pcap_src_p;
    int          err;
    unsigned     ts_mul    = pcap_src->ts_nsec ? 1000000000 : 1000000;

    ws_debug("capture_loop_write_packet_cb");

    /* We may be called multiple times from pcap_dispatch(); if we've set
       the "stop capturing" flag, ignore this packet, as we're not
       supposed to be saving any more packets. */
    if (!global_ld.go) {
        pcap_src->flushed++;
        return;
    }

    if (global_ld.pdh) {
        bool successful;

        /* We're supposed to write the packet to a file; do so.
           If this fails, set "ld->go" to false, to stop the capture, and set
           "ld->err" to the error. */
        if (global_capture_opts.use_pcapng) {
            successful = pcapng_write_enhanced_packet_block(global_ld.pdh,
                                                            NULL,
                                                            phdr->ts.tv_sec, (int32_t)phdr->ts.tv_usec,
                                                            phdr->caplen, phdr->len,
                                                            pcap_src->idb_id,
                                                            ts_mul,
                                                            pd, 0,
                                                            &global_ld.bytes_written, &err);
        } else {
            successful = libpcap_write_packet(global_ld.pdh,
                                              phdr->ts.tv_sec, (int32_t)phdr->ts.tv_usec,
                                              phdr->caplen, phdr->len,
                                              pd,
                                              &global_ld.bytes_written, &err);
        }
        if (!successful) {
            global_ld.go = false;
            global_ld.err = err;
            pcap_src->dropped++;
        } else {
            ws_debug("Wrote a pcap packet of length %d captured on interface %u.",
                   phdr->caplen, pcap_src->interface_id);
            capture_loop_wrote_one_packet(pcap_src);
        }
    }
}

/* one packet was captured, queue it */
static void
capture_loop_queue_packet_cb(uint8_t *pcap_src_p, const struct pcap_pkthdr *phdr,
                             const uint8_t *pd)
{
    capture_src        *pcap_src = (capture_src *) (void *) pcap_src_p;
    pcap_queue_element *queue_element;
    bool                limit_reached;

    /* We may be called multiple times from pcap_dispatch(); if we've set
       the "stop capturing" flag, ignore this packet, as we're not
       supposed to be saving any more packets. */
    if (!global_ld.go) {
        pcap_src->flushed++;
        return;
    }

    queue_element = g_new(pcap_queue_element, 1);
    if (queue_element == NULL) {
       pcap_src->dropped++;
       return;
    }
    queue_element->pcap_src = pcap_src;
    queue_element->u.phdr = *phdr;
    queue_element->pd = (uint8_t *)g_malloc(phdr->caplen);
    if (queue_element->pd == NULL) {
        pcap_src->dropped++;
        g_free(queue_element);
        return;
    }
    memcpy(queue_element->pd, pd, phdr->caplen);
    g_async_queue_lock(pcap_queue);
    if (((pcap_queue_byte_limit == 0) || (pcap_queue_bytes < pcap_queue_byte_limit)) &&
        ((pcap_queue_packet_limit == 0) || (pcap_queue_packets < pcap_queue_packet_limit))) {
        limit_reached = false;
        g_async_queue_push_unlocked(pcap_queue, queue_element);
        pcap_queue_bytes += phdr->caplen;
        pcap_queue_packets += 1;
    } else {
        limit_reached = true;
    }
    g_async_queue_unlock(pcap_queue);
    if (limit_reached) {
        pcap_src->dropped++;
        g_free(queue_element->pd);
        g_free(queue_element);
        ws_info("Dropped a packet of length %d captured on interface %u.",
              phdr->caplen, pcap_src->interface_id);
    } else {
        pcap_src->received++;
        ws_info("Queued a packet of length %d captured on interface %u.",
              phdr->caplen, pcap_src->interface_id);
    }
    /* I don't want to hold the mutex over the debug output. So the
       output may be wrong */
    ws_info("Queue size is now %" PRId64 " bytes (%" PRId64 " packets)",
          pcap_queue_bytes, pcap_queue_packets);
}

/* one pcapng block was captured, queue it */
static void
capture_loop_queue_pcapng_cb(capture_src *pcap_src, const pcapng_block_header_t *bh, uint8_t *pd)
{
    pcap_queue_element *queue_element;
    bool                limit_reached;

    /* We may be called multiple times from pcap_dispatch(); if we've set
       the "stop capturing" flag, ignore this packet, as we're not
       supposed to be saving any more packets. */
    if (!global_ld.go) {
        pcap_src->flushed++;
        return;
    }

    queue_element = g_new(pcap_queue_element, 1);
    if (queue_element == NULL) {
       pcap_src->dropped++;
       return;
    }
    queue_element->pcap_src = pcap_src;
    queue_element->u.bh = *bh;
    queue_element->pd = (uint8_t *)g_malloc(bh->block_total_length);
    if (queue_element->pd == NULL) {
        pcap_src->dropped++;
        g_free(queue_element);
        return;
    }
    memcpy(queue_element->pd, pd, bh->block_total_length);
    g_async_queue_lock(pcap_queue);
    if (((pcap_queue_byte_limit == 0) || (pcap_queue_bytes < pcap_queue_byte_limit)) &&
        ((pcap_queue_packet_limit == 0) || (pcap_queue_packets < pcap_queue_packet_limit))) {
        limit_reached = false;
        g_async_queue_push_unlocked(pcap_queue, queue_element);
        pcap_queue_bytes += bh->block_total_length;
        pcap_queue_packets += 1;
    } else {
        limit_reached = true;
    }
    g_async_queue_unlock(pcap_queue);
    if (limit_reached) {
        pcap_src->dropped++;
        g_free(queue_element->pd);
        g_free(queue_element);
        ws_info("Dropped a packet of length %d captured on interface %u.",
              bh->block_total_length, pcap_src->interface_id);
    } else {
        pcap_src->received++;
        ws_info("Queued a block of type 0x%08x of length %d captured on interface %u.",
              bh->block_type, bh->block_total_length, pcap_src->interface_id);
    }
    /* I don't want to hold the mutex over the debug output. So the
       output may be wrong */
    ws_info("Queue size is now %" PRId64 " bytes (%" PRId64 " packets)",
          pcap_queue_bytes, pcap_queue_packets);
}

static int
set_80211_channel(const char *iface, const char *opt)
{
    uint32_t freq = 0;
    int type = -1;
    uint32_t center_freq1 = 0;
    uint32_t center_freq2 = 0;
    int args;
    int ret = 0;
    char **options = NULL;

    options = g_strsplit_set(opt, ",", 4);
    for (args = 0; options[args]; args++)
        ;

    ret = ws80211_init();
    if (ret != WS80211_INIT_OK) {
        if (ret == WS80211_INIT_NOT_SUPPORTED)
            cmdarg_err("Setting 802.11 channels is not supported on this platform");
        else
            cmdarg_err("Failed to init ws80211: %s", g_strerror(abs(ret)));
        ret = 2;
        goto out;
    }

    if (options[0])
        freq = get_nonzero_guint32(options[0], "802.11 channel frequency");

    if (args >= 1 && options[1]) {
        type = ws80211_str_to_chan_type(options[1]);
        if (type == -1) {
            cmdarg_err("\"%s\" is not a valid 802.11 channel type", options[1]);
            ret = EINVAL;
            goto out;
        }
    }

    if (args >= 2 && options[2])
        center_freq1 = get_nonzero_guint32(options[2], "VHT center frequency");

    if (args >= 3 && options[3])
        center_freq2 = get_nonzero_guint32(options[3], "VHT center frequency 2");

    ret = ws80211_set_freq(iface, freq, type, center_freq1, center_freq2);

    if (ret) {
        cmdarg_err("%d: Failed to set channel: %s\n", abs(ret), g_strerror(abs(ret)));
        ret = 2;
        goto out;
    }

    if (capture_child)
        sync_pipe_write_string_msg(sync_pipe_fd, SP_SUCCESS, NULL);

out:
    g_strfreev(options);
    return ret;
}

static void
gather_dumpcap_compiled_info(feature_list l)
{
    /* Capture libraries */
    gather_caplibs_compile_info(l);
}

static void
gather_dumpcap_runtime_info(feature_list l)
{
    /* Capture libraries */
    gather_caplibs_runtime_info(l);
}

#define LONGOPT_IFNAME             LONGOPT_BASE_APPLICATION+1
#define LONGOPT_IFDESCR            LONGOPT_BASE_APPLICATION+2
#define LONGOPT_CAPTURE_COMMENT    LONGOPT_BASE_APPLICATION+3
#ifdef _WIN32
#define LONGOPT_SIGNAL_PIPE        LONGOPT_BASE_APPLICATION+4
#endif

/* And now our feature presentation... [ fade to music ] */
int
main(int argc, char *argv[])
{
    char             *err_msg;
    int               opt;
    static const struct ws_option long_options[] = {
        {"help", ws_no_argument, NULL, 'h'},
        {"version", ws_no_argument, NULL, 'v'},
        LONGOPT_CAPTURE_COMMON
        {"ifname", ws_required_argument, NULL, LONGOPT_IFNAME},
        {"ifdescr", ws_required_argument, NULL, LONGOPT_IFDESCR},
        {"capture-comment", ws_required_argument, NULL, LONGOPT_CAPTURE_COMMENT},
#ifdef _WIN32
        {"signal-pipe", ws_required_argument, NULL, LONGOPT_SIGNAL_PIPE},
#endif
        {0, 0, 0, 0 }
    };

    bool              arg_error             = false;

#ifndef _WIN32
    struct sigaction  action, oldaction;
#endif

    bool              stats_known;
    struct pcap_stat  stats = {0};
    bool              list_interfaces       = false;
    int               caps_queries          = 0;
    bool              print_bpf_code        = false;
    bool              set_chan              = false;
    char             *set_chan_arg          = NULL;
    bool              machine_readable      = false;
    bool              print_statistics      = false;
    int               status, run_once_args = 0;
    int               i;
    unsigned          j;
#if defined(__APPLE__) && defined(__LP64__)
    struct utsname    osinfo;
#endif
    GString          *str;

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
            capture_child    = true;
            machine_readable = true;  /* request machine-readable output */
            i++;
            if (i >= argc) {
                exit_main(1);
            }

            if (strcmp(argv[i], SIGNAL_PIPE_CTRL_ID_NONE) != 0) {
                // get_positive_int calls cmdarg_err
                if (!ws_strtoi(argv[i], NULL, &sync_pipe_fd) || sync_pipe_fd <= 0) {
                    exit_main(1);
                }
#ifdef _WIN32
                /* On UN*X the fd is the same when we fork + exec.
                 * On Windows the HANDLE value is the same for inherited
                 * handles in the child process and the parent, although
                 * not necessarily the fd value from _open_osfhandle.
                 * https://learn.microsoft.com/en-us/windows/win32/procthread/inheritance
                 * Also, "64-bit versions of Windows use 32-bit handles for
                 * interoperability... only the lower 32 bits are significant,
                 * so it is safe to truncate... or sign-extend the handle."
                 * https://learn.microsoft.com/en-us/windows/win32/winprog64/interprocess-communication
                 */
                /* set output pipe to binary mode, avoid ugly text conversions */
                sync_pipe_fd = _open_osfhandle( (intptr_t) sync_pipe_fd, _O_BINARY);
#endif
            }
        }
    }

    cmdarg_err_init(dumpcap_cmdarg_err, dumpcap_cmdarg_err_cont);

    /* Initialize log handler early so we can have proper logging during startup. */
    ws_log_init_with_writer("dumpcap", dumpcap_log_writer, vcmdarg_err);

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, vcmdarg_err, 1);

#if DEBUG_CHILD_DUMPCAP
    /* Assume that if we're specially compiled with dumpcap debugging
     * then we want maximum debugging.
     */
    if (capture_child) {
        ws_log_set_level(LOG_LEVEL_NOISY);
    }

    if ((debug_log = ws_fopen("dumpcap_debug_log.tmp","w")) == NULL) {
        fprintf (stderr, "Unable to open debug log file .\n");
        exit (1);
    }
#endif

    ws_noisy("Finished log init and parsing command line log arguments");

#ifdef _WIN32
    create_app_running_mutex();

    /*
     * Initialize our DLL search path. MUST be called before LoadLibrary
     * or g_module_open.
     */
    ws_init_dll_search_path();

    /* Load wpcap if possible. Do this before collecting the run-time version information */
    load_wpcap();
#endif

    /* Initialize the version information. */
    ws_init_version_info("Dumpcap", gather_dumpcap_compiled_info,
                         gather_dumpcap_runtime_info);

#ifdef HAVE_PCAP_REMOTE
#define OPTSTRING_r "r"
#define OPTSTRING_u "u"
#else
#define OPTSTRING_r
#define OPTSTRING_u
#endif

#ifdef HAVE_PCAP_SETSAMPLING
#define OPTSTRING_m "m:"
#else
#define OPTSTRING_m
#endif

#define OPTSTRING OPTSTRING_CAPTURE_COMMON "C:dghk:" OPTSTRING_m "MN:nPqQ" OPTSTRING_r "St" OPTSTRING_u "vw:Z:"

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
         * {Mac} OS X/macOS 10.x uses Darwin {x+4}.0.0; 10.x.y uses Darwin
         * {x+4}.y.0 (except that 10.6.1 appears to have a uname version
         * number of 10.0.0, not 10.1.0 - go figure).
         */
        if (strcmp(osinfo.release, "10.0.0") == 0 ||    /* 10.6, 10.6.1 */
            strcmp(osinfo.release, "10.3.0") == 0 ||    /* 10.6.3 */
            strcmp(osinfo.release, "10.4.0") == 0)              /* 10.6.4 */
            need_timeout_workaround = true;
    }
#endif

    /* Initialize the pcaps list and IDBs */
    global_ld.pcaps = g_array_new(FALSE, FALSE, sizeof(capture_src *));
    global_ld.pcapng_passthrough = false;
    global_ld.saved_shb = NULL;
    global_ld.saved_idbs = g_array_new(FALSE, TRUE, sizeof(saved_idb_t));

    err_msg = ws_init_sockets();
    if (err_msg != NULL)
    {
        ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR,
                          "ERROR: %s", err_msg);
        g_free(err_msg);
        ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_ERROR,
                          "%s", please_report_bug());
        exit_main(1);
    }

#ifdef _WIN32
    /* Set handler for Ctrl+C key */
    SetConsoleCtrlHandler(capture_cleanup_handler, true);
#else
    /* Catch SIGINT and SIGTERM and, if we get either of them, clean up
       and exit.  Do the same with SIGPIPE, in case, for example,
       we're writing to our standard output and it's a pipe.
       Do the same with SIGHUP if it's not being ignored (if we're
       being run under nohup, it might be ignored, in which case we
       should leave it ignored).

       XXX - apparently, Coverity complained that part of action
       wasn't initialized.  Perhaps it's running on Linux, where
       struct sigaction has an ignored "sa_restorer" element and
       where "sa_handler" and "sa_sigaction" might not be two
       members of a union. */
    memset(&action, 0, sizeof(action));
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
    /*           https://www.mail-archive.com/  [wrapped]                */
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
    capture_opts_init(&global_capture_opts, get_interface_list);
    /* We always save to a file - if no file was specified, we save to a
       temporary file. */
    global_capture_opts.saving_to_file      = true;
    global_capture_opts.has_ring_num_files  = true;

    /* Pass on capture_child mode for capture_opts */
    global_capture_opts.capture_child = capture_child;

    /* Now get our args */
    while ((opt = ws_getopt_long(argc, argv, OPTSTRING, long_options, NULL)) != -1) {
        switch (opt) {
        case 'h':        /* Print help and exit */
            show_help_header("Capture network packets and dump them into a pcapng or pcap file.");
            print_usage(stdout);
            exit_main(0);
            break;
        case 'v':        /* Show version and exit */
            show_version();
            exit_main(0);
            break;
        /*** capture option specific ***/
        case 'a':        /* autostop criteria */
        case 'b':        /* Ringbuffer option */
        case 'c':        /* Capture x packets */
        case 'f':        /* capture filter */
        case 'F':        /* capture file type */
        case 'g':        /* enable group read access on file(s) */
        case 'i':        /* Use interface x */
        case LONGOPT_SET_TSTAMP_TYPE: /* Set capture timestamp type */
        case 'n':        /* Use pcapng format */
        case 'p':        /* Don't capture in promiscuous mode */
        case 'P':        /* Use pcap format */
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
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
        case 'B':        /* Buffer size */
#endif
#ifdef HAVE_PCAP_CREATE
        case 'I':        /* Monitor mode */
#endif
        case LONGOPT_COMPRESS_TYPE:        /* compress type */
        case LONGOPT_CAPTURE_TMPDIR:       /* capture temp directory */
        case LONGOPT_UPDATE_INTERVAL:      /* sync pipe update interval */
            status = capture_opts_add_opt(&global_capture_opts, opt, ws_optarg);
            if (status != 0) {
                exit_main(status);
            }
            break;
            /*** hidden option: Wireshark child mode (using binary output messages) ***/
        case LONGOPT_IFNAME:
            if (global_capture_opts.ifaces->len > 0) {
                interface_options *interface_opts;

                interface_opts = &g_array_index(global_capture_opts.ifaces, interface_options, global_capture_opts.ifaces->len - 1);
                interface_opts->ifname = g_strdup(ws_optarg);
            } else {
                cmdarg_err("--ifname must be specified after a -i option");
                exit_main(1);
            }
            break;
        case LONGOPT_IFDESCR:
            if (global_capture_opts.ifaces->len > 0) {
                interface_options *interface_opts;

                interface_opts = &g_array_index(global_capture_opts.ifaces, interface_options, global_capture_opts.ifaces->len - 1);
                interface_opts->descr = g_strdup(ws_optarg);
            } else {
                cmdarg_err("--ifdescr must be specified after a -i option");
                exit_main(1);
            }
            break;
        case LONGOPT_CAPTURE_COMMENT:  /* capture comment */
            if (capture_comments == NULL) {
                capture_comments = g_ptr_array_new_with_free_func(g_free);
            }
            g_ptr_array_add(capture_comments, g_strdup(ws_optarg));
            break;
        case 'Z':
            capture_child = true;
            /*
             * Handled above
             */
            break;
#ifdef _WIN32
        case LONGOPT_SIGNAL_PIPE:
            if (!capture_child) {
                /* We have already checked for -Z at the very beginning. */
                cmdarg_err("--signal-pipe may only be specified with -Z");
                exit_main(1);
            }
            /*
             * ws_optarg = the control ID, aka the PPID, currently used for the
             * signal pipe name.
             */
            if (strcmp(ws_optarg, SIGNAL_PIPE_CTRL_ID_NONE) != 0) {
                sig_pipe_name = ws_strdup_printf(SIGNAL_PIPE_FORMAT, ws_optarg);
                sig_pipe_handle = CreateFile(utf_8to16(sig_pipe_name),
                                             GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

                if (sig_pipe_handle == INVALID_HANDLE_VALUE) {
                    ws_info("Signal pipe: Unable to open %s.  Dead parent?",
                          sig_pipe_name);
                    exit_main(1);
                }
            }
            break;
#endif
        case 'q':        /* Quiet */
            quiet = true;
            break;
        case 'Q':        /* Really quiet */
            quiet = true;
            really_quiet = true;
            break;
        case 't':
            use_threads = true;
            break;
            /*** all non capture option specific ***/
        case 'D':        /* Print a list of capture devices and exit */
            if (!list_interfaces && !caps_queries & !print_statistics) {
                run_once_args++;
            }
            list_interfaces = true;
            break;
        case 'L':        /* Print list of link-layer types and exit */
            if (!list_interfaces && !caps_queries & !print_statistics) {
                run_once_args++;
            }
            caps_queries |= CAPS_QUERY_LINK_TYPES;
            break;
        case LONGOPT_LIST_TSTAMP_TYPES:
            if (!list_interfaces && !caps_queries & !print_statistics) {
                run_once_args++;
            }
            caps_queries |= CAPS_QUERY_TIMESTAMP_TYPES;
            break;
        case 'd':        /* Print BPF code for capture filter and exit */
            if (!print_bpf_code) {
                print_bpf_code = true;
                run_once_args++;
            }
            break;
        case 'S':        /* Print interface statistics once a second */
            if (!list_interfaces && !caps_queries & !print_statistics) {
                run_once_args++;
            }
            print_statistics = true;
            break;
        case 'k':        /* Set wireless channel */
            if (!set_chan) {
                set_chan = true;
                set_chan_arg = ws_optarg;
                run_once_args++;
            } else {
                cmdarg_err("Only one -k flag may be specified");
                arg_error = true;
            }
            break;
        case 'M':        /* For -D, -L, and -S, print machine-readable output */
            machine_readable = true;
            break;
        case 'C':
            pcap_queue_byte_limit = get_positive_int(ws_optarg, "byte_limit");
            break;
        case 'N':
            pcap_queue_packet_limit = get_positive_int(ws_optarg, "packet_limit");
            break;
        default:
            cmdarg_err("Invalid Option: %s", argv[ws_optind-1]);
            /* FALLTHROUGH */
        case '?':        /* Bad flag - print usage message */
            arg_error = true;
            break;
        }
    }
    if (!arg_error) {
        argc -= ws_optind;
        argv += ws_optind;
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
            arg_error = true;
        }
    }

    if ((pcap_queue_byte_limit > 0) || (pcap_queue_packet_limit > 0)) {
        use_threads = true;
    }
    if ((pcap_queue_byte_limit == 0) && (pcap_queue_packet_limit == 0)) {
        /* Use some default if the user hasn't specified some */
        /* XXX: Are these defaults good enough? */
        pcap_queue_byte_limit = 1000 * 1000;
        pcap_queue_packet_limit = 1000;
    }
    if (arg_error) {
        if (ws_optopt == 'F') {
            capture_opts_list_file_types();
            exit_main(1);
        }
        print_usage(stderr);
        exit_main(1);
    }

    if (run_once_args > 1) {
        cmdarg_err("Only one of -D, -L, -d, -k or -S may be supplied.");
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
            use_threads = true;
            global_capture_opts.use_pcapng = true;
        }

        if (capture_comments &&
            (!global_capture_opts.use_pcapng || global_capture_opts.multi_files_on)) {
            /* XXX - for ringbuffer, should we apply the comments to each file? */
            cmdarg_err("Capture comments can only be set if we capture into a single pcapng file.");
            exit_main(1);
        }

        /* Was the ring buffer option specified and, if so, does it make sense? */
        if (global_capture_opts.multi_files_on) {
            /* Ring buffer works only under certain conditions:
               a) ring buffer does not work with temporary files;
               b) it makes no sense to enable the ring buffer if the maximum
               file size is set to "infinite". */
            if (global_capture_opts.save_file == NULL) {
                cmdarg_err("Ring buffer requested, but capture isn't being saved to a permanent file.");
                global_capture_opts.multi_files_on = false;
            }
            if (!global_capture_opts.has_autostop_filesize &&
                !global_capture_opts.has_file_duration &&
                !global_capture_opts.has_file_interval &&
                !global_capture_opts.has_file_packets) {
                cmdarg_err("Ring buffer requested, but no maximum capture file size, duration "
                           "interval, or packets were specified.");
#if 0
                /* XXX - this must be redesigned as the conditions changed */
                global_capture_opts.multi_files_on = false;
#endif
            }
            if (global_capture_opts.has_file_duration && global_capture_opts.has_file_interval) {
                cmdarg_err("Ring buffer file duration and interval can't be used at the same time.");
                exit_main(1);
            }
        }
    }

    /*
     * "-D" requires no interface to be selected; it's supposed to list
     * all interfaces.
     */
    if (list_interfaces) {
        /* Get the list of interfaces */
        GList *if_list;
        int    err;
        char *err_str;

        if_list = get_interface_list(&err, &err_str);
        if (if_list == NULL) {
            if (err == 0) {
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
            } else {
                cmdarg_err("%s", err_str);
                g_free(err_str);
                exit_main(2);
            }
        }

        if (!machine_readable) {
            status = 0;
            capture_opts_print_interfaces(if_list);
        }

        if (caps_queries) {
            if_info_t *if_info;
            interface_options *interface_opts;
            cap_device_open_status open_status;
            char *open_status_str;
            for (GList *if_entry = if_list; if_entry != NULL; if_entry = g_list_next(if_entry)) {
                if_info = (if_info_t *)if_entry->data;

                interface_opts = interface_opts_from_if_info(&global_capture_opts, if_info);

                if_info->caps = get_if_capabilities(interface_opts, &open_status, &open_status_str);

                if (!machine_readable) {
                    if (if_info->caps == NULL) {
                        cmdarg_err("The capabilities of the capture device "
                                    "\"%s\" could not be obtained (%s).\n%s",
                                    interface_opts->name, open_status_str,
                                    get_pcap_failure_secondary_error_message(open_status, open_status_str));
                        g_free(open_status_str);
                        /* Break after one error, as when printing selected
                         * interface capabilities. (XXX: We could print all
                         * the primary status strings, and only the unique
                         * set of secondary messages / suggestions; printing
                         * the same long secondary error is a lot.)
                         */
                        interface_opts_free(interface_opts);
                        g_free(interface_opts);
                        break;
                    } else {
                        status = capture_opts_print_if_capabilities(if_info->caps, interface_opts, caps_queries);
                        if (status != 0) {
                            interface_opts_free(interface_opts);
                            g_free(interface_opts);
                            break;
                        }
                    }
                } else {
                    if (if_info->caps == NULL) {
                        if_info->caps = g_new0(if_capabilities_t, 1);
                        if_info->caps->primary_msg = open_status_str;
                        if_info->caps->secondary_msg = g_strdup(get_pcap_failure_secondary_error_message(open_status, open_status_str));
                    }
                    if_info->caps->status = open_status;
                }

                interface_opts_free(interface_opts);
                g_free(interface_opts);
            }
        }

        if (machine_readable) {
            status = print_machine_readable_interfaces(if_list, caps_queries, print_statistics);
        }
        free_interface_list(if_list);
        if (!print_statistics) {
            exit_main(status);
        }
    }

    /*
     * "-S" requires no interface to be selected; it gives statistics
     * for all interfaces.
     */
    if (print_statistics) {
        status = print_statistics_loop(machine_readable);
        exit_main(status);
    }

    if (set_chan) {
        interface_options *interface_opts;

        if (global_capture_opts.ifaces->len != 1) {
            cmdarg_err("Need one interface");
            exit_main(2);
        }

        interface_opts = &g_array_index(global_capture_opts.ifaces, interface_options, 0);
        status = set_80211_channel(interface_opts->name, set_chan_arg);
        exit_main(status);
    }

    /*
     * "-L", "-d", and capturing act on a particular interface, so we have to
     * have an interface; if none was specified, pick a default.
     */
    status = capture_opts_default_iface_if_necessary(&global_capture_opts, NULL);
    if (status != 0) {
        /* cmdarg_err() already called .... */
        exit_main(status);
    }

    if (caps_queries) {
        /* Get the list of link-layer and/or timestamp types for the capture device. */
        if_capabilities_t *caps;
        cap_device_open_status open_status;
        char *open_status_str;
        unsigned  ii;

        if (machine_readable) {
            json_dumper dumper = {
                .output_file = stdout,
                .flags = JSON_DUMPER_FLAGS_NO_DEBUG,
                // Don't abort on failure
            };
            json_dumper_begin_array(&dumper);
            for (ii = 0; ii < global_capture_opts.ifaces->len; ii++) {
                interface_options *interface_opts;

                interface_opts = &g_array_index(global_capture_opts.ifaces, interface_options, ii);

                json_dumper_begin_object(&dumper);
                json_dumper_set_member_name(&dumper, interface_opts->name);

                json_dumper_begin_object(&dumper);

                open_status = CAP_DEVICE_OPEN_NO_ERR;
                caps = get_if_capabilities(interface_opts, &open_status, &open_status_str);
                if (caps == NULL) {
                    json_dumper_set_member_name(&dumper, "status");
                    json_dumper_value_anyf(&dumper, "%i", open_status);
                    json_dumper_set_member_name(&dumper, "primary_msg");
                    json_dumper_value_string(&dumper, open_status_str);
                    g_free(open_status_str);
                } else {
                    caps->status = open_status;
                    print_machine_readable_if_capabilities(&dumper, caps, caps_queries);
                    free_if_capabilities(caps);
                }
                json_dumper_end_object(&dumper);
                json_dumper_end_object(&dumper);
            }
            json_dumper_end_array(&dumper);
            if (json_dumper_finish(&dumper)) {
                status = 0;
                if (capture_child) {
                    /* Let our parent know we succeeded. */
                    sync_pipe_write_string_msg(sync_pipe_fd, SP_SUCCESS, NULL);
                }
            } else {
                status = 2;
                if (capture_child) {
                    sync_pipe_write_errmsgs_to_parent(sync_pipe_fd, "Unexpected JSON error", "");
                }
            }
        } else {
            for (ii = 0; ii < global_capture_opts.ifaces->len; ii++) {
                interface_options *interface_opts;

                interface_opts = &g_array_index(global_capture_opts.ifaces, interface_options, ii);

                caps = get_if_capabilities(interface_opts, &open_status, &open_status_str);
                if (caps == NULL) {
                    if (capture_child) {
                        char *error_msg = ws_strdup_printf("The capabilities of the capture device "
                                                    "\"%s\" could not be obtained (%s)",
                                                    interface_opts->name, open_status_str);
                        sync_pipe_write_errmsgs_to_parent(sync_pipe_fd, error_msg,
                                get_pcap_failure_secondary_error_message(open_status, open_status_str));
                        g_free(error_msg);
                    }
                    else {
                        cmdarg_err("The capabilities of the capture device "
                                    "\"%s\" could not be obtained (%s).\n%s",
                                    interface_opts->name, open_status_str,
                                    get_pcap_failure_secondary_error_message(open_status, open_status_str));
                    }
                    g_free(open_status_str);
                    exit_main(2);
                }

                /* XXX: We might want to print also the interface name */
                status = capture_opts_print_if_capabilities(caps,
                                                            interface_opts,
                                                            caps_queries);
                free_if_capabilities(caps);
                if (status != 0)
                    break;
            }
        }
        exit_main(status);
    }

#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
    for (j = 0; j < global_capture_opts.ifaces->len; j++) {
        interface_options *interface_opts;

        interface_opts = &g_array_index(global_capture_opts.ifaces, interface_options, j);
        if (interface_opts->timestamp_type) {
            interface_opts->timestamp_type_id = pcap_tstamp_type_name_to_val(interface_opts->timestamp_type);
            if (interface_opts->timestamp_type_id < 0) {
                cmdarg_err("Invalid argument to option: --time-stamp-type=%s", interface_opts->timestamp_type);
                exit_main(1);
            }
        }
    }
#endif

    /* We're supposed to do a capture, or print the BPF code for a filter. */

    /* Let the user know what interfaces were chosen. */
    if (capture_child) {
        for (j = 0; j < global_capture_opts.ifaces->len; j++) {
            interface_options *interface_opts;

            interface_opts = &g_array_index(global_capture_opts.ifaces, interface_options, j);
            ws_debug("Interface: %s\n", interface_opts->name);
        }
    } else {
        str = g_string_new("");
#ifdef _WIN32
        if (global_capture_opts.ifaces->len < 2)
#else
        if (global_capture_opts.ifaces->len < 4)
#endif
        {
            for (j = 0; j < global_capture_opts.ifaces->len; j++) {
                interface_options *interface_opts;

                interface_opts = &g_array_index(global_capture_opts.ifaces, interface_options, j);
                if (j > 0) {
                    if (global_capture_opts.ifaces->len > 2) {
                        g_string_append_printf(str, ",");
                    }
                    g_string_append_printf(str, " ");
                    if (j == global_capture_opts.ifaces->len - 1) {
                        g_string_append_printf(str, "and ");
                    }
                }
                if (interface_opts->ifname != NULL) {
                    /*
                     * Re-generate the display name based on the strins
                     * we were handed.
                     */
                    g_free(interface_opts->display_name);
                    if (interface_opts->descr != NULL) {
#ifdef _WIN32
                        interface_opts->display_name = ws_strdup_printf("%s",
                            interface_opts->descr);
#else
                        interface_opts->display_name = ws_strdup_printf("%s: %s",
                            interface_opts->descr, interface_opts->ifname);
#endif
                    } else {
                        interface_opts->display_name = ws_strdup_printf("%s",
                            interface_opts->ifname);
                    }
                }
                g_string_append_printf(str, "'%s'", interface_opts->display_name);
            }
        } else {
            g_string_append_printf(str, "%u interfaces", global_capture_opts.ifaces->len);
        }
        if (!really_quiet)
            fprintf(stderr, "Capturing on %s\n", str->str);
        g_string_free(str, TRUE);
    }

    /* Process the snapshot length, as that affects the generated BPF code. */
    capture_opts_trim_snaplen(&global_capture_opts, MIN_PACKET_SIZE);

    if (print_bpf_code) {
        show_filter_code(&global_capture_opts);
        exit_main(0);
    }

    /* We're supposed to do a capture.  Process the ring buffer arguments. */
    capture_opts_trim_ring_num_files(&global_capture_opts);

    /* flush stderr prior to starting the main capture loop */
    fflush(stderr);

    /* Now start the capture. */
    if (capture_loop_start(&global_capture_opts, &stats_known, &stats) == true) {
        /* capture ok */
        exit_main(0);
    } else {
        /* capture failed */
        exit_main(1);
    }
    return 0; /* never here, make compiler happy */
}

static void
dumpcap_log_writer(const char *domain, enum ws_log_level level,
                                    const char *file, long line, const char *func,
                                    const char *fatal_msg _U_,
                                    ws_log_manifest_t *mft,
                                    const char *user_format, va_list user_ap,
                                    void *user_data _U_)
{
    if (ws_log_msg_is_active(domain, level)) {
        /* log messages go to stderr or    */
        /* to parent especially formatted if dumpcap running as child. */
#ifdef DEBUG_CHILD_DUMPCAP
        va_list user_ap_copy;
        va_copy(user_ap_copy, user_ap);
#endif
        if (capture_child) {
            /* Format the log mesage as the numeric level, followed
             * by a colon and then a string matching the standard log
             * string. In the future perhaps we serialize file, line,
             * and func (which can be NULL) instead.
             */
            GString *msg = g_string_new(NULL);
            g_string_append_printf(msg, "%u:", level);
            if (file != NULL) {
                g_string_append_printf(msg, "%s", file);
                if (line >= 0) {
                    g_string_append_printf(msg, ":%ld", line);
                }
            }
            g_string_append(msg, " --");
            if (func != NULL) {
                g_string_append_printf(msg, " %s():", func);
            }
            g_string_append_c(msg, ' ');
            g_string_append_vprintf(msg, user_format, user_ap);

            sync_pipe_write_string_msg(sync_pipe_fd, SP_LOG_MSG, msg->str);
            g_string_free(msg, TRUE);
        } else {
            ws_log_console_writer(domain, level, file, line, func, mft, user_format, user_ap);
        }
#ifdef DEBUG_CHILD_DUMPCAP
        ws_log_file_writer(debug_log, domain, level, file, line, func, mft, user_format, user_ap_copy);
        va_end(user_ap_copy);
#endif
    }
}


/****************************************************************************************************************/
/* indication report routines */


static void
report_packet_count(unsigned int packet_count)
{
    static unsigned int count = 0;

    if (capture_child) {
        ws_debug("Packets: %u", packet_count);
        sync_pipe_write_uint_msg(sync_pipe_fd, SP_PACKET_COUNT, packet_count);
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
    if (capture_child) {
        ws_debug("File: %s", filename);
        if (global_ld.pcapng_passthrough) {
            /* Save filename for sending SP_FILE to capture parent after SHB is passed-through */
            ws_debug("Delaying SP_FILE until first SHB");
            report_capture_filename = filename;
        } else {
            sync_pipe_write_string_msg(sync_pipe_fd, SP_FILE, filename);
        }
    } else {
#ifdef SIGINFO
        /*
         * Prevent a SIGINFO handler from writing to the standard error
         * while we're doing so; instead, have it just set a flag telling
         * us to print that information when we're done.
         */
        infodelay = true;
#endif /* SIGINFO */
        if (!really_quiet) {
            fprintf(stderr, "File: %s\n", filename);
            /* stderr could be line buffered */
            fflush(stderr);
        }

#ifdef SIGINFO
        /*
         * Allow SIGINFO handlers to write.
         */
        infodelay = false;

        /*
         * If a SIGINFO handler asked us to write out capture counts, do so.
         */
        if (infoprint)
          report_counts_for_siginfo();
#endif /* SIGINFO */
    }
}

static void
report_cfilter_error(capture_options *capture_opts, unsigned i, const char *errmsg)
{
    interface_options *interface_opts;
    char tmp[MSG_MAX_LENGTH+1+6];

    if (i < capture_opts->ifaces->len) {
        if (capture_child) {
            snprintf(tmp, sizeof(tmp), "%u:%s", i, errmsg);
            ws_debug("Capture filter error: %s", errmsg);
            sync_pipe_write_string_msg(sync_pipe_fd, SP_BAD_FILTER, tmp);
        } else {
            /*
             * clopts_step_invalid_capfilter in test/suite-clopts.sh MUST match
             * the error message below.
             */
            interface_opts = &g_array_index(capture_opts->ifaces, interface_options, i);
            cmdarg_err(
              "Invalid capture filter \"%s\" for interface '%s'.\n"
              "\n"
              "That string isn't a valid capture filter (%s).\n"
              "See the User's Guide for a description of the capture filter syntax.",
              interface_opts->cfilter, interface_opts->name, errmsg);
        }
    }
}

static void
report_capture_error(const char *error_msg, const char *secondary_error_msg)
{
    if (capture_child) {
        ws_debug("Primary Error: %s", error_msg);
        ws_debug("Secondary Error: %s", secondary_error_msg);
        sync_pipe_write_errmsgs_to_parent(sync_pipe_fd, error_msg, secondary_error_msg);
    } else {
        cmdarg_err("%s", error_msg);
        if (secondary_error_msg[0] != '\0')
          cmdarg_err_cont("%s", secondary_error_msg);
    }
}

static void
report_packet_drops(uint32_t received, uint32_t pcap_drops, uint32_t drops, uint32_t flushed, uint32_t ps_ifdrop, char *name)
{
    uint32_t total_drops = pcap_drops + drops + flushed;

    if (capture_child) {
        char* tmp = ws_strdup_printf("%u:%s", total_drops, name);

        ws_debug("Packets received/dropped on interface '%s': %u/%u (pcap:%u/dumpcap:%u/flushed:%u/ps_ifdrop:%u)",
            name, received, total_drops, pcap_drops, drops, flushed, ps_ifdrop);
        sync_pipe_write_string_msg(sync_pipe_fd, SP_DROPS, tmp);
        g_free(tmp);
    } else {
        if (!really_quiet) {
            fprintf(stderr,
                "Packets received/dropped on interface '%s': %u/%u (pcap:%u/dumpcap:%u/flushed:%u/ps_ifdrop:%u) (%.1f%%)\n",
                name, received, total_drops, pcap_drops, drops, flushed, ps_ifdrop,
                received ? 100.0 * received / (received + total_drops) : 0.0);
            /* stderr could be line buffered */
            fflush(stderr);
        }
    }
}


/************************************************************************************************/
/* signal_pipe handling */


#ifdef _WIN32
static bool
signal_pipe_check_running(void)
{
    /* any news from our parent? -> just stop the capture */
    DWORD    avail = 0;
    bool result;

    /* if we are running standalone, no check required */
    if (!capture_child) {
        return true;
    }

    if (!sig_pipe_name || !sig_pipe_handle) {
        /* This shouldn't happen */
        ws_info("Signal pipe: No name or handle");
        return false;
    }

    /*
     * XXX - We should have the process ID of the parent (from the "-Z" flag)
     * at this point.  Should we check to see if the parent is still alive,
     * e.g. by using OpenProcess?
     */

    result = PeekNamedPipe(sig_pipe_handle, NULL, 0, NULL, &avail, NULL);

    if (!result || avail > 0) {
        /* peek failed or some bytes really available */
        /* (if not piping from stdin this would fail) */
        ws_info("Signal pipe: Stop capture: %s", sig_pipe_name);
        ws_debug("Signal pipe: %s (%p) result: %u avail: %lu", sig_pipe_name,
            sig_pipe_handle, result, avail);
        return false;
    } else {
        /* pipe ok and no bytes available */
        return true;
    }
}
#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
