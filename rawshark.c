/* rawshark.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Rawshark - Raw field extractor by Gerald Combs <gerald@wireshark.org>
 * and Loris Degioanni <loris.degioanni@cacetech.com>
 * Based on TShark, by Gilbert Ramirez <gram@alumni.rice.edu> and Guy Harris
 * <guy@alum.mit.edu>.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Rawshark does the following:
 * - Opens a specified file or named pipe
 * - Applies a specfied DLT or "decode as" encapsulation
 * - Reads frames prepended with a libpcap packet header.
 * - Prints a status line, followed by fields from a specified list.
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <limits.h>

#ifndef _WIN32
#include <sys/time.h>
#include <sys/resource.h>
#endif

#include <errno.h>

#include <wsutil/ws_getopt.h>

#include <glib.h>
#include <epan/epan.h>

#include <ui/cmdarg_err.h>
#include <ui/exit_codes.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/socket.h>
#include <wsutil/plugins.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <wsutil/please_report_bug.h>
#include <wsutil/wslog.h>
#include <ui/clopts_common.h>

#ifdef _WIN32
#include <wsutil/unicode-utils.h>
#endif

#include "globals.h"
#include <epan/packet.h>
#include <epan/ftypes/ftypes.h>
#include "file.h"
#include "frame_tvbuff.h"
#include <epan/disabled_protos.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/print.h>
#include <epan/addr_resolv.h>
#ifdef HAVE_LIBPCAP
#include "ui/capture_ui_utils.h"
#endif
#include "ui/util.h"
#include "ui/dissect_opts.h"
#include "ui/failure_message.h"
#include <epan/epan_dissect.h>
#include <epan/stat_tap_ui.h>
#include <epan/timestamp.h>
#include "epan/column-utils.h"
#include "epan/proto.h"
#include <epan/tap.h>

#include <wiretap/wtap.h>
#include <wiretap/libpcap.h>
#include <wiretap/pcap-encap.h>

#include <cli_main.h>
#include <ui/version_info.h>

#include "capture/capture-pcap-util.h"

#ifdef HAVE_LIBPCAP
#include <setjmp.h>
#ifdef _WIN32
#include "capture/capture-wpcap.h"
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */

#if 0
/*
 * This is the template for the decode as option; it is shared between the
 * various functions that output the usage for this parameter.
 */
static const gchar decode_as_arg_template[] = "<layer_type>==<selector>,<decode_as_protocol>";
#endif

/* Additional exit codes */
#define INVALID_DFILTER 2
#define FORMAT_ERROR    2

capture_file cfile;

static guint32 cum_bytes;
static frame_data ref_frame;
static frame_data prev_dis_frame;
static frame_data prev_cap_frame;

/*
 * The way the packet decode is to be written.
 */
typedef enum {
    WRITE_TEXT, /* summary or detail text */
    WRITE_XML   /* PDML or PSML */
    /* Add CSV and the like here */
} output_action_e;

static gboolean line_buffered;
static print_format_e print_format = PR_FMT_TEXT;

static gboolean want_pcap_pkthdr;

cf_status_t raw_cf_open(capture_file *cf, const char *fname);
static gboolean load_cap_file(capture_file *cf);
static gboolean process_packet(capture_file *cf, epan_dissect_t *edt, gint64 offset,
                               wtap_rec *rec, Buffer *buf);
static void show_print_file_io_error(int err);

static void rawshark_cmdarg_err(const char *fmt, va_list ap);
static void rawshark_cmdarg_err_cont(const char *fmt, va_list ap);
static void protocolinfo_init(char *field);
static gboolean parse_field_string_format(char *format);

typedef enum {
    SF_NONE,    /* No format (placeholder) */
    SF_NAME,    /* %D Field name / description */
    SF_NUMVAL,  /* %N Numeric value */
    SF_STRVAL   /* %S String value */
} string_fmt_e;

typedef struct string_fmt_s {
    gchar *plain;
    string_fmt_e format;    /* Valid if plain is NULL */
} string_fmt_t;

int n_rfilters;
int n_rfcodes;
dfilter_t *rfcodes[64];
int n_rfieldfilters;
dfilter_t *rfieldfcodes[64];
int fd;
int encap;
GPtrArray *string_fmts;

static void
print_usage(FILE *output)
{
    fprintf(output, "\n");
    fprintf(output, "Usage: rawshark [options] ...\n");
    fprintf(output, "\n");

    fprintf(output, "Input file:\n");
    fprintf(output, "  -r <infile>              set the pipe or file name to read from\n");

    fprintf(output, "\n");
    fprintf(output, "Processing:\n");
    fprintf(output, "  -d <encap:linktype>|<proto:protoname>\n");
    fprintf(output, "                           packet encapsulation or protocol\n");
    fprintf(output, "  -F <field>               field to display\n");
#ifndef _WIN32
    fprintf(output, "  -m                       virtual memory limit, in bytes\n");
#endif
    fprintf(output, "  -n                       disable all name resolution (def: all enabled)\n");
    fprintf(output, "  -N <name resolve flags>  enable specific name resolution(s): \"mnNtdv\"\n");
    fprintf(output, "  -p                       use the system's packet header format\n");
    fprintf(output, "                           (which may have 64-bit timestamps)\n");
    fprintf(output, "  -R <read filter>         packet filter in Wireshark display filter syntax\n");
    fprintf(output, "  -s                       skip PCAP header on input\n");

    fprintf(output, "\n");
    fprintf(output, "Output:\n");
    fprintf(output, "  -l                       flush output after each packet\n");
    fprintf(output, "  -S                       format string for fields\n");
    fprintf(output, "                           (%%D - name, %%S - stringval, %%N numval)\n");
    fprintf(output, "  -t ad|a|r|d|dd|e         output format of time stamps (def: r: rel. to first)\n");
    fprintf(output, "\n");

    ws_log_print_usage(output);
    fprintf(output, "\n");

    fprintf(output, "\n");
    fprintf(output, "Miscellaneous:\n");
    fprintf(output, "  -h                       display this help and exit\n");
    fprintf(output, "  -o <name>:<value> ...    override preference setting\n");
    fprintf(output, "  -v                       display version info and exit\n");
}

/**
 * Open a pipe for raw input.  This is a stripped-down version of
 * pcap_loop.c:cap_pipe_open_live().
 * We check if "pipe_name" is "-" (stdin) or a FIFO, and open it.
 * @param pipe_name The name of the pipe or FIFO.
 * @return A POSIX file descriptor on success, or -1 on failure.
 */
static int
raw_pipe_open(const char *pipe_name)
{
#ifndef _WIN32
    ws_statb64 pipe_stat;
#else
    char *pncopy, *pos = NULL;
    DWORD err;
    wchar_t *err_str;
    HANDLE hPipe = NULL;
#endif
    int          rfd;

    ws_log(LOG_DOMAIN_CAPCHILD, LOG_LEVEL_DEBUG, "open_raw_pipe: %s", pipe_name);

    /*
     * XXX Rawshark blocks until we return
     */
    if (strcmp(pipe_name, "-") == 0) {
        rfd = 0; /* read from stdin */
#ifdef _WIN32
        /*
         * This is needed to set the stdin pipe into binary mode, otherwise
         * CR/LF are mangled...
         */
        _setmode(0, _O_BINARY);
#endif  /* _WIN32 */
    } else {
#ifndef _WIN32
        if (ws_stat64(pipe_name, &pipe_stat) < 0) {
            fprintf(stderr, "rawshark: The pipe %s could not be checked: %s\n",
                    pipe_name, g_strerror(errno));
            return -1;
        }
        if (! S_ISFIFO(pipe_stat.st_mode)) {
            if (S_ISCHR(pipe_stat.st_mode)) {
                /*
                 * Assume the user specified an interface on a system where
                 * interfaces are in /dev.  Pretend we haven't seen it.
                 */
            } else
            {
                fprintf(stderr, "rawshark: \"%s\" is neither an interface nor a pipe\n",
                        pipe_name);
            }
            return -1;
        }
        rfd = ws_open(pipe_name, O_RDONLY | O_NONBLOCK, 0000 /* no creation so don't matter */);
        if (rfd == -1) {
            fprintf(stderr, "rawshark: \"%s\" could not be opened: %s\n",
                    pipe_name, g_strerror(errno));
            return -1;
        }
#else /* _WIN32 */
#define PIPE_STR "\\pipe\\"
        /* Under Windows, named pipes _must_ have the form
         * "\\<server>\pipe\<pipe_name>".  <server> may be "." for localhost.
         */
        pncopy = g_strdup(pipe_name);
        if (strstr(pncopy, "\\\\") == pncopy) {
            pos = strchr(pncopy + 3, '\\');
            if (pos && g_ascii_strncasecmp(pos, PIPE_STR, strlen(PIPE_STR)) != 0)
                pos = NULL;
        }

        g_free(pncopy);

        if (!pos) {
            fprintf(stderr, "rawshark: \"%s\" is neither an interface nor a pipe\n",
                    pipe_name);
            return -1;
        }

        /* Wait for the pipe to appear */
        while (1) {
            hPipe = CreateFile(utf_8to16(pipe_name), GENERIC_READ, 0, NULL,
                               OPEN_EXISTING, 0, NULL);

            if (hPipe != INVALID_HANDLE_VALUE)
                break;

            err = GetLastError();
            if (err != ERROR_PIPE_BUSY) {
                FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
                              NULL, err, 0, (LPTSTR) &err_str, 0, NULL);
                fprintf(stderr, "rawshark: \"%s\" could not be opened: %s (error %lu)\n",
                        pipe_name, utf_16to8(err_str), err);
                LocalFree(err_str);
                return -1;
            }

            if (!WaitNamedPipe(utf_8to16(pipe_name), 30 * 1000)) {
                err = GetLastError();
                FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
                              NULL, err, 0, (LPTSTR) &err_str, 0, NULL);
                fprintf(stderr, "rawshark: \"%s\" could not be waited for: %s (error %lu)\n",
                        pipe_name, utf_16to8(err_str), err);
                LocalFree(err_str);
                return -1;
            }
        }

        rfd = _open_osfhandle((intptr_t) hPipe, _O_RDONLY);
        if (rfd == -1) {
            fprintf(stderr, "rawshark: \"%s\" could not be opened: %s\n",
                    pipe_name, g_strerror(errno));
            return -1;
        }
#endif /* _WIN32 */
    }

    return rfd;
}

/**
 * Parse a link-type argument of the form "encap:<pcap linktype>" or
 * "proto:<proto name>".  "Pcap linktype" must be a name conforming to
 * pcap_datalink_name_to_val() or an integer; the integer should be
 * a LINKTYPE_ value supported by Wiretap.  "Proto name" must be
 * a protocol name, e.g. "http".
 */
static gboolean
set_link_type(const char *lt_arg) {
    char *spec_ptr = strchr(lt_arg, ':');
    char *p;
    int dlt_val;
    long val;
    dissector_handle_t dhandle;
    GString *pref_str;
    char *errmsg = NULL;

    if (!spec_ptr)
        return FALSE;

    spec_ptr++;

    if (strncmp(lt_arg, "encap:", strlen("encap:")) == 0) {
        dlt_val = linktype_name_to_val(spec_ptr);
        if (dlt_val == -1) {
            errno = 0;
            val = strtol(spec_ptr, &p, 10);
            if (p == spec_ptr || *p != '\0' || errno != 0 || val > INT_MAX) {
                return FALSE;
            }
            dlt_val = (int)val;
        }
        /*
         * In those cases where a given link-layer header type
         * has different LINKTYPE_ and DLT_ values, linktype_name_to_val()
         * will return the OS's DLT_ value for that link-layer header
         * type, not its OS-independent LINKTYPE_ value.
         *
         * On a given OS, wtap_pcap_encap_to_wtap_encap() should
         * be able to map either LINKTYPE_ values or DLT_ values
         * for the OS to the appropriate Wiretap encapsulation.
         */
        encap = wtap_pcap_encap_to_wtap_encap(dlt_val);
        if (encap == WTAP_ENCAP_UNKNOWN) {
            return FALSE;
        }
        return TRUE;
    } else if (strncmp(lt_arg, "proto:", strlen("proto:")) == 0) {
        dhandle = find_dissector(spec_ptr);
        if (dhandle) {
            encap = WTAP_ENCAP_USER0;
            pref_str = g_string_new("uat:user_dlts:");
            /* This must match the format used in the user_dlts file */
            g_string_append_printf(pref_str,
                                   "\"User 0 (DLT=147)\",\"%s\",\"0\",\"\",\"0\",\"\"",
                                   spec_ptr);
            if (prefs_set_pref(pref_str->str, &errmsg) != PREFS_SET_OK) {
                g_string_free(pref_str, TRUE);
                g_free(errmsg);
                return FALSE;
            }
            g_string_free(pref_str, TRUE);
            return TRUE;
        }
    }
    return FALSE;
}

int
main(int argc, char *argv[])
{
    char                *err_msg;
    int                  opt, i;

#ifndef _WIN32
    struct rlimit limit;
#endif  /* !_WIN32 */

    gchar               *pipe_name = NULL;
    gchar               *rfilters[64];
    e_prefs             *prefs_p;
    char                 badopt;
    GPtrArray           *disp_fields = g_ptr_array_new();
    guint                fc;
    gboolean             skip_pcap_header = FALSE;
    int                  ret = EXIT_SUCCESS;
    static const struct ws_option long_options[] = {
      {"help", ws_no_argument, NULL, 'h'},
      {"version", ws_no_argument, NULL, 'v'},
      {0, 0, 0, 0 }
    };

#define OPTSTRING_INIT "d:F:hlm:nN:o:pr:R:sS:t:v"

    static const char    optstring[] = OPTSTRING_INIT;
    static const struct report_message_routines rawshark_report_routines = {
      failure_message,
      failure_message,
      open_failure_message,
      read_failure_message,
      write_failure_message,
      cfile_open_failure_message,
      cfile_dump_open_failure_message,
      cfile_read_failure_message,
      cfile_write_failure_message,
      cfile_close_failure_message
    };

    /*
     * Set the C-language locale to the native environment and set the
     * code page to UTF-8 on Windows.
     */
#ifdef _WIN32
    setlocale(LC_ALL, ".UTF-8");
#else
    setlocale(LC_ALL, "");
#endif

    cmdarg_err_init(rawshark_cmdarg_err, rawshark_cmdarg_err_cont);

    /* Initialize log handler early so we can have proper logging during startup. */
    ws_log_init("rawshark", vcmdarg_err);

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, vcmdarg_err, INVALID_OPTION);

    /* Initialize the version information. */
    ws_init_version_info("Rawshark",
                         epan_gather_compile_info,
                         NULL);

#ifdef _WIN32
    create_app_running_mutex();
#endif /* _WIN32 */

    /*
     * Get credential information for later use.
     */
    init_process_policies();

    /*
     * Clear the filters arrays
     */
    memset(rfilters, 0, sizeof(rfilters));
    memset(rfcodes, 0, sizeof(rfcodes));
    n_rfilters = 0;
    n_rfcodes = 0;

    /*
     * Initialize our string format
     */
    string_fmts = g_ptr_array_new();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    err_msg = configuration_init(argv[0], NULL);
    if (err_msg != NULL) {
        fprintf(stderr, "rawshark: Can't get pathname of rawshark program: %s.\n",
                err_msg);
    }

    init_report_message("rawshark", &rawshark_report_routines);

    timestamp_set_type(TS_RELATIVE);
    timestamp_set_precision(TS_PREC_AUTO);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

    /*
     * XXX - is this necessary, given that we're not reading a
     * regular capture file, we're reading rawshark's packet
     * stream format?
     *
     * If it is, note that libwiretap must be initialized before
     * libwireshark is, so that dissection-time handlers for
     * file-type-dependent blocks can register using the file
     * type/subtype value for the file type.
     */
    wtap_init(FALSE);

    /* Register all dissectors; we must do this before checking for the
       "-G" flag, as the "-G" flag dumps information registered by the
       dissectors, and we must do it before we read the preferences, in
       case any dissectors register preferences. */
    if (!epan_init(NULL, NULL, TRUE)) {
        ret = INIT_FAILED;
        goto clean_exit;
    }

    /* Load libwireshark settings from the current profile. */
    prefs_p = epan_load_settings();

#ifdef _WIN32
    ws_init_dll_search_path();
    /* Load Wpcap, if possible */
    load_wpcap();
#endif

    cap_file_init(&cfile);

    /* Print format defaults to this. */
    print_format = PR_FMT_TEXT;

    /* Initialize our encapsulation type */
    encap = WTAP_ENCAP_UNKNOWN;

    /* Now get our args */
    /* XXX - We should probably have an option to dump libpcap link types */
    while ((opt = ws_getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        switch (opt) {
            case 'd':        /* Payload type */
                if (!set_link_type(ws_optarg)) {
                    cmdarg_err("Invalid link type or protocol \"%s\"", ws_optarg);
                    ret = INVALID_OPTION;
                    goto clean_exit;
                }
                break;
            case 'F':        /* Read field to display */
                g_ptr_array_add(disp_fields, g_strdup(ws_optarg));
                break;
            case 'h':        /* Print help and exit */
                show_help_header("Dump and analyze network traffic.");
                print_usage(stdout);
                goto clean_exit;
                break;
            case 'l':        /* "Line-buffer" standard output */
                /* This isn't line-buffering, strictly speaking, it's just
                   flushing the standard output after the information for
                   each packet is printed; however, that should be good
                   enough for all the purposes to which "-l" is put (and
                   is probably actually better for "-V", as it does fewer
                   writes).

                   See the comment in "process_packet()" for an explanation of
                   why we do that, and why we don't just use "setvbuf()" to
                   make the standard output line-buffered (short version: in
                   Windows, "line-buffered" is the same as "fully-buffered",
                   and the output buffer is only flushed when it fills up). */
                line_buffered = TRUE;
                break;
#ifndef _WIN32
            case 'm':
                limit.rlim_cur = get_positive_int(ws_optarg, "memory limit");
                limit.rlim_max = get_positive_int(ws_optarg, "memory limit");

                if(setrlimit(RLIMIT_AS, &limit) != 0) {
                    cmdarg_err("setrlimit() returned error");
                    ret = INVALID_OPTION;
                    goto clean_exit;
                }
                break;
#endif
            case 'n':        /* No name resolution */
                disable_name_resolution();
                break;
            case 'N':        /* Select what types of addresses/port #s to resolve */
                badopt = string_to_name_resolve(ws_optarg, &gbl_resolv_flags);
                if (badopt != '\0') {
                    cmdarg_err("-N specifies unknown resolving option '%c'; valid options are 'd', m', 'n', 'N', and 't'",
                               badopt);
                    ret = INVALID_OPTION;
                    goto clean_exit;
                }
                break;
            case 'o':        /* Override preference from command line */
            {
                char *errmsg = NULL;

                switch (prefs_set_pref(ws_optarg, &errmsg)) {

                    case PREFS_SET_OK:
                        break;

                    case PREFS_SET_SYNTAX_ERR:
                        cmdarg_err("Invalid -o flag \"%s\"%s%s", ws_optarg,
                                errmsg ? ": " : "", errmsg ? errmsg : "");
                        g_free(errmsg);
                        ret = INVALID_OPTION;
                        goto clean_exit;
                        break;

                    case PREFS_SET_NO_SUCH_PREF:
                        cmdarg_err("-o flag \"%s\" specifies unknown preference", ws_optarg);
                        ret = INVALID_OPTION;
                        goto clean_exit;
                        break;

                    case PREFS_SET_OBSOLETE:
                        cmdarg_err("-o flag \"%s\" specifies obsolete preference", ws_optarg);
                        ret = INVALID_OPTION;
                        goto clean_exit;
                        break;
                }
                break;
            }
            case 'p':        /* Expect pcap_pkthdr packet headers, which may have 64-bit timestamps */
                want_pcap_pkthdr = TRUE;
                break;
            case 'r':        /* Read capture file xxx */
                pipe_name = g_strdup(ws_optarg);
                break;
            case 'R':        /* Read file filter */
                if(n_rfilters < (int) sizeof(rfilters) / (int) sizeof(rfilters[0])) {
                    rfilters[n_rfilters++] = ws_optarg;
                }
                else {
                    cmdarg_err("Too many display filters");
                    ret = INVALID_OPTION;
                    goto clean_exit;
                }
                break;
            case 's':        /* Skip PCAP header */
                skip_pcap_header = TRUE;
                break;
            case 'S':        /* Print string representations */
                if (!parse_field_string_format(ws_optarg)) {
                    cmdarg_err("Invalid field string format");
                    ret = INVALID_OPTION;
                    goto clean_exit;
                }
                break;
            case 't':        /* Time stamp type */
                if (strcmp(ws_optarg, "r") == 0)
                    timestamp_set_type(TS_RELATIVE);
                else if (strcmp(ws_optarg, "a") == 0)
                    timestamp_set_type(TS_ABSOLUTE);
                else if (strcmp(ws_optarg, "ad") == 0)
                    timestamp_set_type(TS_ABSOLUTE_WITH_YMD);
                else if (strcmp(ws_optarg, "adoy") == 0)
                    timestamp_set_type(TS_ABSOLUTE_WITH_YDOY);
                else if (strcmp(ws_optarg, "d") == 0)
                    timestamp_set_type(TS_DELTA);
                else if (strcmp(ws_optarg, "dd") == 0)
                    timestamp_set_type(TS_DELTA_DIS);
                else if (strcmp(ws_optarg, "e") == 0)
                    timestamp_set_type(TS_EPOCH);
                else if (strcmp(ws_optarg, "u") == 0)
                    timestamp_set_type(TS_UTC);
                else if (strcmp(ws_optarg, "ud") == 0)
                    timestamp_set_type(TS_UTC_WITH_YMD);
                else if (strcmp(ws_optarg, "udoy") == 0)
                    timestamp_set_type(TS_UTC_WITH_YDOY);
                else {
                    cmdarg_err("Invalid time stamp type \"%s\"",
                               ws_optarg);
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
                    ret = INVALID_OPTION;
                    goto clean_exit;
                }
                break;
            case 'v':        /* Show version and exit */
            {
                show_version();
                goto clean_exit;
            }
            default:
            case '?':        /* Bad flag - print usage message */
                print_usage(stderr);
                ret = INVALID_OPTION;
                goto clean_exit;
        }
    }

    /* Notify all registered modules that have had any of their preferences
       changed either from one of the preferences file or from the command
       line that their preferences have changed.
       Initialize preferences before display filters, otherwise modules
       like MATE won't work. */
    prefs_apply_all();

    /* Initialize our display fields */
    for (fc = 0; fc < disp_fields->len; fc++) {
        protocolinfo_init((char *)g_ptr_array_index(disp_fields, fc));
    }
    g_ptr_array_free(disp_fields, TRUE);
    printf("\n");
    fflush(stdout);

    /* If no capture filter or read filter has been specified, and there are
       still command-line arguments, treat them as the tokens of a capture
       filter (if no "-r" flag was specified) or a read filter (if a "-r"
       flag was specified. */
    if (ws_optind < argc) {
        if (pipe_name != NULL) {
            if (n_rfilters != 0) {
                cmdarg_err("Read filters were specified both with \"-R\" "
                           "and with additional command-line arguments");
                ret = INVALID_OPTION;
                goto clean_exit;
            }
            rfilters[n_rfilters] = get_args_as_string(argc, argv, ws_optind);
        }
    }

    /* Make sure we got a dissector handle for our payload. */
    if (encap == WTAP_ENCAP_UNKNOWN) {
        cmdarg_err("No valid payload dissector specified.");
        ret = INVALID_OPTION;
        goto clean_exit;
    }

    err_msg = ws_init_sockets();
    if (err_msg != NULL)
    {
        cmdarg_err("%s", err_msg);
        g_free(err_msg);
        cmdarg_err_cont("%s", please_report_bug());
        ret = INIT_FAILED;
        goto clean_exit;
    }

    /*
     * Enabled and disabled protocols and heuristic dissectors as per
     * command-line options.
     */
    setup_enabled_and_disabled_protocols();

    /* Build the column format array */
    build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

    if (n_rfilters != 0) {
        for (i = 0; i < n_rfilters; i++) {
            if (!dfilter_compile(rfilters[i], &rfcodes[n_rfcodes], &err_msg)) {
                cmdarg_err("%s", err_msg);
                g_free(err_msg);
                ret = INVALID_DFILTER;
                goto clean_exit;
            }
            n_rfcodes++;
        }
    }

    if (pipe_name) {
        /*
         * We're reading a pipe (or capture file).
         */

        /*
         * Immediately relinquish any special privileges we have; we must not
         * be allowed to read any capture files the user running Rawshark
         * can't open.
         */
        relinquish_special_privs_perm();

        if (raw_cf_open(&cfile, pipe_name) != CF_OK) {
            ret = OPEN_ERROR;
            goto clean_exit;
        }

        /* Do we need to PCAP header and magic? */
        if (skip_pcap_header) {
            unsigned int bytes_left = (unsigned int) sizeof(struct pcap_hdr) + sizeof(guint32);
            gchar buf[sizeof(struct pcap_hdr) + sizeof(guint32)];
            while (bytes_left != 0) {
                ssize_t bytes = ws_read(fd, buf, bytes_left);
                if (bytes <= 0) {
                    cmdarg_err("Not enough bytes for pcap header.");
                    ret =  FORMAT_ERROR;
                    goto clean_exit;
                }
                bytes_left -= (unsigned int)bytes;
            }
        }

        /* Process the packets in the file */
        if (!load_cap_file(&cfile)) {
            ret = OPEN_ERROR;
            goto clean_exit;
        }
    } else {
        /* If you want to capture live packets, use TShark. */
        cmdarg_err("Input file or pipe name not specified.");
        ret = OPEN_ERROR;
        goto clean_exit;
    }

clean_exit:
    g_free(pipe_name);
    epan_free(cfile.epan);
    epan_cleanup();
    wtap_cleanup();
    return ret;
}

/**
 * Read data from a raw pipe.  The "raw" data consists of a libpcap
 * packet header followed by the payload.
 * @param buf [IN] A POSIX file descriptor.  Because that's _exactly_ the sort
 *           of thing you want to use in Windows.
 * @param err [OUT] Error indicator.  Uses wiretap values.
 * @param err_info [OUT] Error message.
 * @param data_offset [OUT] data offset in the pipe.
 * @return TRUE on success, FALSE on failure.
 */
static gboolean
raw_pipe_read(wtap_rec *rec, Buffer *buf, int *err, gchar **err_info, gint64 *data_offset) {
    struct pcap_pkthdr mem_hdr;
    struct pcaprec_hdr disk_hdr;
    ssize_t bytes_read = 0;
    unsigned int bytes_needed = (unsigned int) sizeof(disk_hdr);
    guchar *ptr = (guchar*) &disk_hdr;

    *err = 0;

    if (want_pcap_pkthdr) {
        bytes_needed = sizeof(mem_hdr);
        ptr = (guchar*) &mem_hdr;
    }

    /*
     * Newer versions of the VC runtime do parameter validation. If stdin
     * has been closed, calls to _read, _get_osfhandle, et al will trigger
     * the invalid parameter handler and crash.
     * We could alternatively use ReadFile or set an invalid parameter
     * handler.
     * We could also tell callers not to close stdin prematurely.
     */
#ifdef _WIN32
    DWORD ghi_flags;
    if (fd == 0 && GetHandleInformation(GetStdHandle(STD_INPUT_HANDLE), &ghi_flags) == 0) {
        *err = 0;
        *err_info = NULL;
        return FALSE;
    }
#endif

    /* Copied from capture_loop.c */
    while (bytes_needed > 0) {
        bytes_read = ws_read(fd, ptr, bytes_needed);
        if (bytes_read == 0) {
            *err = 0;
            *err_info = NULL;
            return FALSE;
        } else if (bytes_read < 0) {
            *err = errno;
            *err_info = NULL;
            return FALSE;
        }
        bytes_needed -= (unsigned int)bytes_read;
        *data_offset += bytes_read;
        ptr += bytes_read;
    }

    rec->rec_type = REC_TYPE_PACKET;
    rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
    if (want_pcap_pkthdr) {
        rec->ts.secs = mem_hdr.ts.tv_sec;
        rec->ts.nsecs = (gint32)mem_hdr.ts.tv_usec * 1000;
        rec->rec_header.packet_header.caplen = mem_hdr.caplen;
        rec->rec_header.packet_header.len = mem_hdr.len;
    } else {
        rec->ts.secs = disk_hdr.ts_sec;
        rec->ts.nsecs = disk_hdr.ts_usec * 1000;
        rec->rec_header.packet_header.caplen = disk_hdr.incl_len;
        rec->rec_header.packet_header.len = disk_hdr.orig_len;
    }
    bytes_needed = rec->rec_header.packet_header.caplen;

    rec->rec_header.packet_header.pkt_encap = encap;

#if 0
    printf("mem_hdr: %lu disk_hdr: %lu\n", sizeof(mem_hdr), sizeof(disk_hdr));
    printf("tv_sec: %d (%04x)\n", (unsigned int) rec->ts.secs, (unsigned int) rec->ts.secs);
    printf("tv_nsec: %d (%04x)\n", rec->ts.nsecs, rec->ts.nsecs);
    printf("caplen: %d (%04x)\n", rec->rec_header.packet_header.caplen, rec->rec_header.packet_header.caplen);
    printf("len: %d (%04x)\n", rec->rec_header.packet_header.len, rec->rec_header.packet_header.len);
#endif
    if (bytes_needed > WTAP_MAX_PACKET_SIZE_STANDARD) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("Bad packet length: %lu",
                   (unsigned long) bytes_needed);
        return FALSE;
    }

    ws_buffer_assure_space(buf, bytes_needed);
    ptr = ws_buffer_start_ptr(buf);
    while (bytes_needed > 0) {
        bytes_read = ws_read(fd, ptr, bytes_needed);
        if (bytes_read == 0) {
            *err = WTAP_ERR_SHORT_READ;
            *err_info = NULL;
            return FALSE;
        } else if (bytes_read < 0) {
            *err = errno;
            *err_info = NULL;
            return FALSE;
        }
        bytes_needed -= (unsigned int)bytes_read;
        *data_offset += bytes_read;
        ptr += bytes_read;
    }
    return TRUE;
}

static gboolean
load_cap_file(capture_file *cf)
{
    int          err;
    gchar       *err_info = NULL;
    gint64       data_offset = 0;

    wtap_rec     rec;
    Buffer       buf;
    epan_dissect_t edt;

    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514);

    epan_dissect_init(&edt, cf->epan, TRUE, FALSE);

    while (raw_pipe_read(&rec, &buf, &err, &err_info, &data_offset)) {
        process_packet(cf, &edt, data_offset, &rec, &buf);
    }

    epan_dissect_cleanup(&edt);

    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);
    if (err != 0) {
        /* Print a message noting that the read failed somewhere along the line. */
        cfile_read_failure_message(cf->filename, err, err_info);
        return FALSE;
    }

    return TRUE;
}

static gboolean
process_packet(capture_file *cf, epan_dissect_t *edt, gint64 offset,
               wtap_rec *rec, Buffer *buf)
{
    frame_data fdata;
    gboolean passed;
    int i;

    if(rec->rec_header.packet_header.len == 0)
    {
        /* The user sends an empty packet when he wants to get output from us even if we don't currently have
           packets to process. We spit out a line with the timestamp and the text "void"
        */
        printf("%lu %" PRIu64 " %d void -\n", (unsigned long int)cf->count,
               (guint64)rec->ts.secs, rec->ts.nsecs);

        fflush(stdout);

        return FALSE;
    }

    /* Count this packet. */
    cf->count++;

    /* If we're going to print packet information, or we're going to
       run a read filter, or we're going to process taps, set up to
       do a dissection and do so. */
    frame_data_init(&fdata, cf->count, rec, offset, cum_bytes);

    passed = TRUE;

    /* If we're running a read filter, prime the epan_dissect_t with that
       filter. */
    if (n_rfilters > 0) {
        for(i = 0; i < n_rfcodes; i++) {
            epan_dissect_prime_with_dfilter(edt, rfcodes[i]);
        }
    }

    printf("%lu", (unsigned long int) cf->count);

    frame_data_set_before_dissect(&fdata, &cf->elapsed_time,
                                  &cf->provider.ref, cf->provider.prev_dis);

    if (cf->provider.ref == &fdata) {
       ref_frame = fdata;
       cf->provider.ref = &ref_frame;
    }

    /* We only need the columns if we're printing packet info but we're
     *not* verbose; in verbose mode, we print the protocol tree, not
     the protocol summary. */
    epan_dissect_run_with_taps(edt, cf->cd_t, rec,
                               frame_tvbuff_new_buffer(&cf->provider, &fdata, buf),
                               &fdata, &cf->cinfo);

    frame_data_set_after_dissect(&fdata, &cum_bytes);
    prev_dis_frame = fdata;
    cf->provider.prev_dis = &prev_dis_frame;

    prev_cap_frame = fdata;
    cf->provider.prev_cap = &prev_cap_frame;

    for(i = 0; i < n_rfilters; i++) {
        /* Run the read filter if we have one. */
        if (rfcodes[i])
            passed = dfilter_apply_edt(rfcodes[i], edt);
        else
            passed = TRUE;

        /* Print a one-line summary */
        printf(" %d", passed ? 1 : 0);
    }

    printf(" -\n");

    /* The ANSI C standard does not appear to *require* that a line-buffered
       stream be flushed to the host environment whenever a newline is
       written, it just says that, on such a stream, characters "are
       intended to be transmitted to or from the host environment as a
       block when a new-line character is encountered".

       The Visual C++ 6.0 C implementation doesn't do what is intended;
       even if you set a stream to be line-buffered, it still doesn't
       flush the buffer at the end of every line.

       So, if the "-l" flag was specified, we flush the standard output
       at the end of a packet.  This will do the right thing if we're
       printing packet summary lines, and, as we print the entire protocol
       tree for a single packet without waiting for anything to happen,
       it should be as good as line-buffered mode if we're printing
       protocol trees.  (The whole reason for the "-l" flag in either
       tcpdump or Rawshark is to allow the output of a live capture to
       be piped to a program or script and to have that script see the
       information for the packet as soon as it's printed, rather than
       having to wait until a standard I/O buffer fills up. */
    if (line_buffered)
        fflush(stdout);

    if (ferror(stdout)) {
        show_print_file_io_error(errno);
        exit(2);
    }

    epan_dissect_reset(edt);
    frame_data_destroy(&fdata);

    return passed;
}

/****************************************************************************************
 * FIELD EXTRACTION ROUTINES
 ****************************************************************************************/
typedef struct _pci_t {
    char *filter;
    int hf_index;
    int cmd_line_index;
} pci_t;

static const char* ftenum_to_string(header_field_info *hfi)
{
    const char* str;
    if (!hfi) {
        return "n.a.";
    }

    if (string_fmts->len > 0 && hfi->strings) {
        return "FT_STRING";
    }

    str = ftype_name(hfi->type);
    if (str == NULL) {
        str = "n.a.";
    }

    return str;
}

static void field_display_to_string(header_field_info *hfi, char* buf, int size)
{
    if (hfi->type != FT_BOOLEAN)
    {
        (void) g_strlcpy(buf, proto_field_display_to_string(hfi->display), size);
    }
    else
    {
        snprintf(buf, size, "(Bit count: %d)", hfi->display);
    }
}

/*
 * Copied from various parts of proto.c
 */
#define FIELD_STR_INIT_LEN 256
#define cVALS(x) (const value_string*)(x)
static gboolean print_field_value(field_info *finfo, int cmd_line_index)
{
    header_field_info   *hfinfo;
    char                *fs_buf;
    char                *fs_ptr = NULL;
    static GString     *label_s = NULL;
    size_t              fs_len;
    guint              i;
    string_fmt_t       *sf;
    guint32            uvalue;
    gint32             svalue;
    guint64            uvalue64;
    gint64             svalue64;
    const true_false_string *tfstring = &tfs_true_false;

    hfinfo = finfo->hfinfo;

    if (!label_s) {
        label_s = g_string_new("");
    }

    fs_buf = fvalue_to_string_repr(NULL, &finfo->value,
                          FTREPR_DFILTER, finfo->hfinfo->display);
    if (fs_buf != NULL) {
        /*
         * this field has an associated value,
         * e.g: ip.hdr_len
         */
        fs_len = strlen(fs_buf);
        fs_ptr = fs_buf;

        /* String types are quoted. Remove them. */
        if (IS_FT_STRING(fvalue_type_ftenum(&finfo->value)) && fs_len > 2) {
            fs_buf[fs_len - 1] = '\0';
            fs_ptr++;
        }
    }

    if (string_fmts->len > 0 && finfo->hfinfo->strings) {
        g_string_truncate(label_s, 0);
        for (i = 0; i < string_fmts->len; i++) {
            sf = (string_fmt_t *)g_ptr_array_index(string_fmts, i);
            if (sf->plain) {
                g_string_append(label_s, sf->plain);
            } else {
                switch (sf->format) {
                    case SF_NAME:
                        g_string_append(label_s, hfinfo->name);
                        break;
                    case SF_NUMVAL:
                        g_string_append(label_s, fs_ptr);
                        break;
                    case SF_STRVAL:
                        switch(hfinfo->type) {
                            case FT_BOOLEAN:
                                uvalue64 = fvalue_get_uinteger64(&finfo->value);
                                tfstring = (const true_false_string*) hfinfo->strings;
                                g_string_append(label_s, tfs_get_string(!!uvalue64, tfstring));
                                break;
                            case FT_INT8:
                            case FT_INT16:
                            case FT_INT24:
                            case FT_INT32:
                                DISSECTOR_ASSERT(!hfinfo->bitmask);
                                svalue = fvalue_get_sinteger(&finfo->value);
                                if (hfinfo->display & BASE_RANGE_STRING) {
                                    g_string_append(label_s, rval_to_str_const(svalue, (const range_string *) hfinfo->strings, "Unknown"));
                                } else if (hfinfo->display & BASE_EXT_STRING) {
                                    g_string_append(label_s, val_to_str_ext_const(svalue, (value_string_ext *) hfinfo->strings, "Unknown"));
                                } else {
                                    g_string_append(label_s, val_to_str_const(svalue, cVALS(hfinfo->strings), "Unknown"));
                                }
                                break;
                            case FT_INT40: /* XXX: Shouldn't these be as smart as FT_INT{8,16,24,32}? */
                            case FT_INT48:
                            case FT_INT56:
                            case FT_INT64:
                                DISSECTOR_ASSERT(!hfinfo->bitmask);
                                svalue64 = fvalue_get_sinteger64(&finfo->value);
                                if (hfinfo->display & BASE_VAL64_STRING) {
                                    g_string_append(label_s, val64_to_str_const(svalue64, (const val64_string *)(hfinfo->strings), "Unknown"));
                                }
                                break;
                            case FT_UINT8:
                            case FT_UINT16:
                            case FT_UINT24:
                            case FT_UINT32:
                                DISSECTOR_ASSERT(!hfinfo->bitmask);
                                uvalue = fvalue_get_uinteger(&finfo->value);
                                if (!hfinfo->bitmask && hfinfo->display & BASE_RANGE_STRING) {
                                    g_string_append(label_s, rval_to_str_const(uvalue, (const range_string *) hfinfo->strings, "Unknown"));
                                } else if (hfinfo->display & BASE_EXT_STRING) {
                                    g_string_append(label_s, val_to_str_ext_const(uvalue, (value_string_ext *) hfinfo->strings, "Unknown"));
                                } else {
                                    g_string_append(label_s, val_to_str_const(uvalue, cVALS(hfinfo->strings), "Unknown"));
                                }
                                break;
                            case FT_UINT40: /* XXX: Shouldn't these be as smart as FT_INT{8,16,24,32}? */
                            case FT_UINT48:
                            case FT_UINT56:
                            case FT_UINT64:
                                DISSECTOR_ASSERT(!hfinfo->bitmask);
                                uvalue64 = fvalue_get_uinteger64(&finfo->value);
                                if (hfinfo->display & BASE_VAL64_STRING) {
                                    g_string_append(label_s, val64_to_str_const(uvalue64, (const val64_string *)(hfinfo->strings), "Unknown"));
                                }
                                break;
                            default:
                                break;
                        }
                        break;
                    default:
                        break;
                }
            }
        }
        printf(" %d=\"%s\"", cmd_line_index, label_s->str);
        wmem_free(NULL, fs_buf);
        return TRUE;
    }

    if(fs_buf)
    {
        printf(" %d=\"%s\"", cmd_line_index, fs_ptr);
        wmem_free(NULL, fs_buf);
        return TRUE;
    }

    /*
     * This field doesn't have an associated value,
     * e.g. http
     * We return n.a.
     */
    printf(" %d=\"n.a.\"", cmd_line_index);
    return TRUE;
}

static tap_packet_status
protocolinfo_packet(void *prs, packet_info *pinfo _U_, epan_dissect_t *edt, const void *dummy _U_, tap_flags_t flags _U_)
{
    pci_t *rs=(pci_t *)prs;
    GPtrArray *gp;
    guint i;

    gp=proto_get_finfo_ptr_array(edt->tree, rs->hf_index);
    if(!gp){
        printf(" n.a.");
        return TAP_PACKET_DONT_REDRAW;
    }

    /*
     * Print each occurrence of the field
     */
    for (i = 0; i < gp->len; i++) {
        print_field_value((field_info *)gp->pdata[i], rs->cmd_line_index);
    }

    return TAP_PACKET_DONT_REDRAW;
}

int g_cmd_line_index = 0;

/*
 * field must be persistent - we don't g_strdup() it below
 */
static void
protocolinfo_init(char *field)
{
    pci_t *rs;
    header_field_info *hfi;
    GString *error_string;
    char hfibuf[100];

    hfi=proto_registrar_get_byname(field);
    if(!hfi){
        fprintf(stderr, "rawshark: Field \"%s\" doesn't exist.\n", field);
        exit(1);
    }

    field_display_to_string(hfi, hfibuf, sizeof(hfibuf));
    printf("%d %s %s - ",
            g_cmd_line_index,
            ftenum_to_string(hfi),
            hfibuf);

    rs=g_new(pci_t, 1);
    rs->hf_index=hfi->id;
    rs->filter=field;
    rs->cmd_line_index = g_cmd_line_index++;

    error_string=register_tap_listener("frame", rs, rs->filter, TL_REQUIRES_PROTO_TREE, NULL, protocolinfo_packet, NULL, NULL);
    if(error_string){
        /* error, we failed to attach to the tap. complain and clean up */
        fprintf(stderr, "rawshark: Couldn't register field extraction tap: %s\n",
                error_string->str);
        g_string_free(error_string, TRUE);
        if(rs->filter){
            g_free(rs->filter);
        }
        g_free(rs);

        exit(1);
    }
}

/*
 * Given a format string, split it into a GPtrArray of string_fmt_t structs
 * and fill in string_fmt_parts.
 */

static void
add_string_fmt(string_fmt_e format, gchar *plain) {
    string_fmt_t *sf = g_new(string_fmt_t, 1);

    sf->format = format;
    sf->plain = g_strdup(plain);

    g_ptr_array_add(string_fmts, sf);
}

static gboolean
parse_field_string_format(gchar *format) {
    size_t len;
    size_t pos = 0;

    if (!format) {
        return FALSE;
    }

    GString *plain_s = g_string_new("");

    len = strlen(format);
    g_ptr_array_set_size(string_fmts, 0);

    while (pos < len) {
        if (format[pos] == '%') {
            if (pos >= (len-1)) { /* There should always be a following specifier character */
                return FALSE;
            }
            pos++;
            if (plain_s->len > 0) {
                add_string_fmt(SF_NONE, plain_s->str);
                g_string_truncate(plain_s, 0);
            }
            switch (format[pos]) {
                case 'D':
                    add_string_fmt(SF_NAME, NULL);
                    break;
                case 'N':
                    add_string_fmt(SF_NUMVAL, NULL);
                    break;
                case 'S':
                    add_string_fmt(SF_STRVAL, NULL);
                    break;
                case '%':
                    g_string_append_c(plain_s, '%');
                    break;
                default: /* Invalid format */
                    return FALSE;
            }
        } else {
            g_string_append_c(plain_s, format[pos]);
        }
        pos++;
    }

    if (plain_s->len > 0) {
        add_string_fmt(SF_NONE, plain_s->str);
    }
    g_string_free(plain_s, TRUE);

    return TRUE;
}
/****************************************************************************************
 * END OF FIELD EXTRACTION ROUTINES
 ****************************************************************************************/

static void
show_print_file_io_error(int err)
{
    switch (err) {

        case ENOSPC:
            cmdarg_err("Not all the packets could be printed because there is "
                       "no space left on the file system.");
            break;

#ifdef EDQUOT
        case EDQUOT:
            cmdarg_err("Not all the packets could be printed because you are "
                       "too close to, or over your disk quota.");
            break;
#endif

        default:
            cmdarg_err("An error occurred while printing packets: %s.",
                       g_strerror(err));
            break;
    }
}

static const nstime_t *
raw_get_frame_ts(struct packet_provider_data *prov, guint32 frame_num)
{
    if (prov->ref && prov->ref->num == frame_num)
        return &prov->ref->abs_ts;

    if (prov->prev_dis && prov->prev_dis->num == frame_num)
        return &prov->prev_dis->abs_ts;

    if (prov->prev_cap && prov->prev_cap->num == frame_num)
        return &prov->prev_cap->abs_ts;

    return NULL;
}

static epan_t *
raw_epan_new(capture_file *cf)
{
    static const struct packet_provider_funcs funcs = {
        raw_get_frame_ts,
        cap_file_provider_get_interface_name,
        cap_file_provider_get_interface_description,
        NULL,
    };

    return epan_new(&cf->provider, &funcs);
}

cf_status_t
raw_cf_open(capture_file *cf, const char *fname)
{
    if ((fd = raw_pipe_open(fname)) < 0)
        return CF_ERROR;

    /* The open succeeded.  Fill in the information for this file. */

    /* Create new epan session for dissection. */
    epan_free(cf->epan);
    cf->epan = raw_epan_new(cf);

    cf->provider.wth = NULL;
    cf->f_datalen = 0; /* not used, but set it anyway */

    /* Set the file name because we need it to set the follow stream filter.
       XXX - is that still true?  We need it for other reasons, though,
       in any case. */
    cf->filename = g_strdup(fname);

    /* Indicate whether it's a permanent or temporary file. */
    cf->is_tempfile = FALSE;

    /* No user changes yet. */
    cf->unsaved_changes = FALSE;

    cf->cd_t      = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;
    cf->open_type = WTAP_TYPE_AUTO;
    cf->count     = 0;
    cf->drops_known = FALSE;
    cf->drops     = 0;
    cf->snap      = 0;
    nstime_set_zero(&cf->elapsed_time);
    cf->provider.ref = NULL;
    cf->provider.prev_dis = NULL;
    cf->provider.prev_cap = NULL;

    return CF_OK;
}

/*
 * Report an error in command-line arguments.
 */
static void
rawshark_cmdarg_err(const char *fmt, va_list ap)
{
    fprintf(stderr, "rawshark: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
rawshark_cmdarg_err_cont(const char *fmt, va_list ap)
{
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
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
