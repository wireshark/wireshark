/* tfshark.c
 *
 * Text-mode variant of Fileshark, based off of TShark,
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#define WS_LOG_DOMAIN  LOG_DOMAIN_MAIN

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <limits.h>

#include <wsutil/ws_getopt.h>

#include <errno.h>

#include <glib.h>

#include <epan/exceptions.h>
#include <epan/epan.h>

#include <ui/clopts_common.h>
#include <ui/cmdarg_err.h>
#include <ui/exit_codes.h>
#include <ui/urls.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>
#include <cli_main.h>
#include <ui/version_info.h>

#include "globals.h"
#include <epan/timestamp.h>
#include <epan/packet.h>
#ifdef HAVE_LUA
#include <epan/wslua/init_wslua.h>
#endif
#include "file.h"
#include "frame_tvbuff.h"
#include <epan/disabled_protos.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/print.h>
#include <epan/addr_resolv.h>
#include "ui/util.h"
#include "ui/decode_as_utils.h"
#include "ui/dissect_opts.h"
#include "ui/failure_message.h"
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/ex-opt.h>
#include "extcap.h"

#include <wiretap/wtap-int.h>
#include <wiretap/file_wrappers.h>

#include <epan/funnel.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

/* Additional exit codes */
#define NO_FILE_SPECIFIED 1

capture_file cfile;

static guint32 cum_bytes;
static frame_data ref_frame;
static frame_data prev_dis_frame;
static frame_data prev_cap_frame;

static gboolean prefs_loaded = FALSE;

static gboolean perform_two_pass_analysis;

/*
 * The way the packet decode is to be written.
 */
typedef enum {
    WRITE_TEXT,   /* summary or detail text */
    WRITE_XML,    /* PDML or PSML */
    WRITE_FIELDS  /* User defined list of fields */
    /* Add CSV and the like here */
} output_action_e;

static output_action_e output_action;
static gboolean do_dissection;     /* TRUE if we have to dissect each packet */
static gboolean print_packet_info; /* TRUE if we're to print packet information */
static gint print_summary = -1;    /* TRUE if we're to print packet summary information */
static gboolean print_details;     /* TRUE if we're to print packet details information */
static gboolean print_hex;         /* TRUE if we're to print hex/ascci information */
static gboolean line_buffered;
static gboolean really_quiet = FALSE;

static print_format_e print_format = PR_FMT_TEXT;
static print_stream_t *print_stream;

static output_fields_t* output_fields  = NULL;

/* The line separator used between packets, changeable via the -S option */
static const char *separator = "";

static gboolean process_file(capture_file *, int, gint64);
static gboolean process_packet_single_pass(capture_file *cf,
        epan_dissect_t *edt, gint64 offset, wtap_rec *rec,
        const guchar *pd, guint tap_flags);
static void show_print_file_io_error(int err);
static gboolean write_preamble(capture_file *cf);
static gboolean print_packet(capture_file *cf, epan_dissect_t *edt);
static gboolean write_finale(void);
static const char *cf_open_error_message(int err, gchar *err_info,
        gboolean for_writing, int file_type);

static void tfshark_cmdarg_err(const char *msg_format, va_list ap);
static void tfshark_cmdarg_err_cont(const char *msg_format, va_list ap);

static GHashTable *output_only_tables = NULL;

#if 0
struct string_elem {
    const char *sstr;   /* The short string */
    const char *lstr;   /* The long string */
};

static gint
string_compare(gconstpointer a, gconstpointer b)
{
    return strcmp(((const struct string_elem *)a)->sstr,
            ((const struct string_elem *)b)->sstr);
}

static void
string_elem_print(gpointer data, gpointer not_used _U_)
{
    fprintf(stderr, "    %s - %s\n",
            ((struct string_elem *)data)->sstr,
            ((struct string_elem *)data)->lstr);
}
#endif

static void
print_usage(FILE *output)
{
    fprintf(output, "\n");
    fprintf(output, "Usage: tfshark [options] ...\n");
    fprintf(output, "\n");

    /*fprintf(output, "\n");*/
    fprintf(output, "Input file:\n");
    fprintf(output, "  -r <infile>              set the filename to read from (no pipes or stdin)\n");

    fprintf(output, "\n");
    fprintf(output, "Processing:\n");
    fprintf(output, "  -2                       perform a two-pass analysis\n");
    fprintf(output, "  -R <read filter>         packet Read filter in Wireshark display filter syntax\n");
    fprintf(output, "                           (requires -2)\n");
    fprintf(output, "  -Y <display filter>      packet displaY filter in Wireshark display filter\n");
    fprintf(output, "                           syntax\n");
    fprintf(output, "  -d %s ...\n", DECODE_AS_ARG_TEMPLATE);
    fprintf(output, "                           \"Decode As\", see the man page for details\n");
    fprintf(output, "                           Example: tcp.port==8888,http\n");

    /*fprintf(output, "\n");*/
    fprintf(output, "Output:\n");
    fprintf(output, "  -C <config profile>      start with specified configuration profile\n");
    fprintf(output, "  -V                       add output of packet tree        (Packet Details)\n");
    fprintf(output, "  -O <protocols>           Only show packet details of these protocols, comma\n");
    fprintf(output, "                           separated\n");
    fprintf(output, "  -S <separator>           the line separator to print between packets\n");
    fprintf(output, "  -x                       add output of hex and ASCII dump (Packet Bytes)\n");
    fprintf(output, "  -T pdml|ps|psml|text|fields\n");
    fprintf(output, "                           format of text output (def: text)\n");
    fprintf(output, "  -e <field>               field to print if -Tfields selected (e.g. tcp.port,\n");
    fprintf(output, "                           _ws.col.Info)\n");
    fprintf(output, "                           this option can be repeated to print multiple fields\n");
    fprintf(output, "  -E<fieldsoption>=<value> set options for output when -Tfields selected:\n");
    fprintf(output, "     header=y|n            switch headers on and off\n");
    fprintf(output, "     separator=/t|/s|<char> select tab, space, printable character as separator\n");
    fprintf(output, "     occurrence=f|l|a      print first, last or all occurrences of each field\n");
    fprintf(output, "     aggregator=,|/s|<char> select comma, space, printable character as\n");
    fprintf(output, "                           aggregator\n");
    fprintf(output, "     quote=d|s|n           select double, single, no quotes for values\n");
    fprintf(output, "  -t a|ad|d|dd|e|r|u|ud    output format of time stamps (def: r: rel. to first)\n");
    fprintf(output, "  -u s|hms                 output format of seconds (def: s: seconds)\n");
    fprintf(output, "  -l                       flush standard output after each packet\n");
    fprintf(output, "  -q                       be more quiet on stdout (e.g. when using statistics)\n");
    fprintf(output, "  -Q                       only log true errors to stderr (quieter than -q)\n");
    fprintf(output, "  -X <key>:<value>         eXtension options, see the man page for details\n");
    fprintf(output, "  -z <statistics>          various statistics, see the man page for details\n");
    fprintf(output, "\n");

    ws_log_print_usage(output);
    fprintf(output, "\n");

    fprintf(output, "Miscellaneous:\n");
    fprintf(output, "  -h                       display this help and exit\n");
    fprintf(output, "  -v                       display version info and exit\n");
    fprintf(output, "  -o <name>:<value> ...    override preference setting\n");
    fprintf(output, "  -K <keytab>              keytab file to use for kerberos decryption\n");
    fprintf(output, "  -G [report]              dump one of several available reports and exit\n");
    fprintf(output, "                           default report=\"fields\"\n");
    fprintf(output, "                           use \"-G ?\" for more help\n");
}

static void
glossary_option_help(void)
{
    FILE *output;

    output = stdout;

    fprintf(output, "%s\n", get_appname_and_version());

    fprintf(output, "\n");
    fprintf(output, "Usage: tfshark -G [report]\n");
    fprintf(output, "\n");
    fprintf(output, "Glossary table reports:\n");
    fprintf(output, "  -G column-formats        dump column format codes and exit\n");
    fprintf(output, "  -G decodes               dump \"layer type\"/\"decode as\" associations and exit\n");
    fprintf(output, "  -G dissector-tables      dump dissector table names, types, and properties\n");
    fprintf(output, "  -G fields                dump fields glossary and exit\n");
    fprintf(output, "  -G ftypes                dump field type basic and descriptive names\n");
    fprintf(output, "  -G heuristic-decodes     dump heuristic dissector tables\n");
    fprintf(output, "  -G plugins               dump installed plugins and exit\n");
    fprintf(output, "  -G protocols             dump protocols in registration database and exit\n");
    fprintf(output, "  -G values                dump value, range, true/false strings and exit\n");
    fprintf(output, "\n");
    fprintf(output, "Preference reports:\n");
    fprintf(output, "  -G currentprefs          dump current preferences and exit\n");
    fprintf(output, "  -G defaultprefs          dump default preferences and exit\n");
    fprintf(output, "\n");
}

static void
print_current_user(void)
{
    gchar *cur_user, *cur_group;

    if (started_with_special_privs()) {
        cur_user = get_cur_username();
        cur_group = get_cur_groupname();
        fprintf(stderr, "Running as user \"%s\" and group \"%s\".",
                cur_user, cur_group);
        g_free(cur_user);
        g_free(cur_group);
        if (running_with_special_privs()) {
            fprintf(stderr, " This could be dangerous.");
        }
        fprintf(stderr, "\n");
    }
}

int
main(int argc, char *argv[])
{
    char                *configuration_init_error;
    int                  opt;
    static const struct ws_option long_options[] = {
        {"help", ws_no_argument, NULL, 'h'},
        {"version", ws_no_argument, NULL, 'v'},
        {0, 0, 0, 0 }
    };
    gboolean             arg_error = FALSE;

    int                  err;
    volatile gboolean    success;
    volatile int         exit_status = 0;
    gboolean             quiet = FALSE;
    gchar               *volatile cf_name = NULL;
    gchar               *rfilter = NULL;
    gchar               *dfilter = NULL;
    dfilter_t           *rfcode = NULL;
    dfilter_t           *dfcode = NULL;
    gchar               *err_msg;
    e_prefs             *prefs_p;
    gchar               *output_only = NULL;

    /*
     * The leading + ensures that getopt_long() does not permute the argv[]
     * entries.
     *
     * We have to make sure that the first getopt_long() preserves the content
     * of argv[] for the subsequent getopt_long() call.
     *
     * We use getopt_long() in both cases to ensure that we're using a routine
     * whose permutation behavior we can control in the same fashion on all
     * platforms, and so that, if we ever need to process a long argument before
     * doing further initialization, we can do so.
     *
     * Glibc and Solaris libc document that a leading + disables permutation
     * of options, regardless of whether POSIXLY_CORRECT is set or not; *BSD
     * and macOS don't document it, but do so anyway.
     *
     * We do *not* use a leading - because the behavior of a leading - is
     * platform-dependent.
     */
#define OPTSTRING "+2C:d:e:E:hK:lo:O:qQr:R:S:t:T:u:vVxX:Y:z:"

    static const char    optstring[] = OPTSTRING;
    static const struct report_message_routines tfshark_report_routines = {
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

    cmdarg_err_init(tfshark_cmdarg_err, tfshark_cmdarg_err_cont);

    /* Initialize log handler early so we can have proper logging during startup. */
    ws_log_init("tfshark", vcmdarg_err);

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, vcmdarg_err, INVALID_OPTION);

#ifdef _WIN32
    create_app_running_mutex();
#endif /* _WIN32 */

    /*
     * Get credential information for later use, and drop privileges
     * before doing anything else.
     * Let the user know if anything happened.
     */
    init_process_policies();
    relinquish_special_privs_perm();
    print_current_user();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    configuration_init_error = configuration_init(argv[0], NULL);
    if (configuration_init_error != NULL) {
        fprintf(stderr,
                "tfshark: Can't get pathname of directory containing the tfshark program: %s.\n",
                configuration_init_error);
        g_free(configuration_init_error);
    }

    initialize_funnel_ops();

    /* Initialize the version information. */
    ws_init_version_info("TFShark",
                         epan_gather_compile_info,
                         epan_gather_runtime_info);
    /*
     * In order to have the -X opts assigned before the wslua machine starts
     * we need to call getopts before epan_init() gets called.
     *
     * In order to handle, for example, -o options, we also need to call it
     * *after* epan_init() gets called, so that the dissectors have had a
     * chance to register their preferences.
     *
     * XXX - can we do this all with one getopt_long() call, saving the
     * arguments we can't handle until after initializing libwireshark,
     * and then process them after initializing libwireshark?
     */
    ws_opterr = 0;

    while ((opt = ws_getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        switch (opt) {
            case 'C':        /* Configuration Profile */
                if (profile_exists (ws_optarg, FALSE)) {
                    set_profile_name (ws_optarg);
                } else if (profile_exists (ws_optarg, TRUE)) {
                    char  *pf_dir_path, *pf_dir_path2, *pf_filename;
                    /* Copy from global profile */
                    if (create_persconffile_profile(ws_optarg, &pf_dir_path) == -1) {
                        cmdarg_err("Can't create directory\n\"%s\":\n%s.",
                            pf_dir_path, g_strerror(errno));

                        g_free(pf_dir_path);
                        exit_status = INVALID_FILE;
                        goto clean_exit;
                    }
                    if (copy_persconffile_profile(ws_optarg, ws_optarg, TRUE, &pf_filename,
                            &pf_dir_path, &pf_dir_path2) == -1) {
                        cmdarg_err("Can't copy file \"%s\" in directory\n\"%s\" to\n\"%s\":\n%s.",
                            pf_filename, pf_dir_path2, pf_dir_path, g_strerror(errno));

                        g_free(pf_filename);
                        g_free(pf_dir_path);
                        g_free(pf_dir_path2);
                        exit_status = INVALID_FILE;
                        goto clean_exit;
                    }
                    set_profile_name (ws_optarg);
                } else {
                    cmdarg_err("Configuration Profile \"%s\" does not exist", ws_optarg);
                    return 1;
                }
                break;
            case 'O':        /* Only output these protocols */
                output_only = g_strdup(ws_optarg);
                /* FALLTHROUGH */
            case 'V':        /* Verbose */
                print_details = TRUE;
                print_packet_info = TRUE;
                break;
            case 'x':        /* Print packet data in hex (and ASCII) */
                print_hex = TRUE;
                /*  The user asked for hex output, so let's ensure they get it,
                 *  even if they're writing to a file.
                 */
                print_packet_info = TRUE;
                break;
            case 'X':
                ex_opt_add(ws_optarg);
                break;
            default:
                break;
        }
    }

    /*
     * Print packet summary information is the default, unless either -V or -x
     * were specified.  Note that this is new behavior, which
     * allows for the possibility of printing only hex/ascii output without
     * necessarily requiring that either the summary or details be printed too.
     */
    if (print_summary == -1)
        print_summary = (print_details || print_hex) ? FALSE : TRUE;

    init_report_message("tfshark", &tfshark_report_routines);

    timestamp_set_type(TS_RELATIVE);
    timestamp_set_precision(TS_PREC_AUTO);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

    /*
     * Libwiretap must be initialized before libwireshark is, so that
     * dissection-time handlers for file-type-dependent blocks can
     * register using the file type/subtype value for the file type.
     *
     * XXX - TFShark shouldn't use libwiretap, as it's a file dissector
     * and should read all files as raw bytes and then try to dissect them.
     * It needs to handle file types its own way, because we would want
     * to support dissecting file-type-specific blocks when dissecting
     * capture files, but that mechanism should support plugins for
     * other files, too, if *their* formats are extensible.
     */
    wtap_init(TRUE);

    /* Register all dissectors; we must do this before checking for the
       "-G" flag, as the "-G" flag dumps information registered by the
       dissectors, and we must do it before we read the preferences, in
       case any dissectors register preferences. */
    if (!epan_init(NULL, NULL, TRUE)) {
        exit_status = INIT_FAILED;
        goto clean_exit;
    }

    /* Register all tap listeners; we do this before we parse the arguments,
       as the "-z" argument can specify a registered tap. */

    /* we register the plugin taps before the other taps because
       stats_tree taps plugins will be registered as tap listeners
       by stats_tree_stat.c and need to registered before that */

    /* XXX Disable tap registration for now until we can get tfshark set up with
     * its own set of taps and the necessary registration function etc.
     register_all_tap_listeners();
     */

    /* If invoked with the "-G" flag, we dump out information based on
       the argument to the "-G" flag; if no argument is specified,
       for backwards compatibility we dump out a glossary of display
       filter symbols.

       XXX - we do this here, for now, to support "-G" with no arguments.
       If none of our build or other processes uses "-G" with no arguments,
       we can just process it with the other arguments. */
    if (argc >= 2 && strcmp(argv[1], "-G") == 0) {
        proto_initialize_all_prefixes();

        if (argc == 2)
            proto_registrar_dump_fields();
        else {
            if (strcmp(argv[2], "column-formats") == 0)
                column_dump_column_formats();
            else if (strcmp(argv[2], "currentprefs") == 0) {
                epan_load_settings();
                write_prefs(NULL);
            }
            else if (strcmp(argv[2], "decodes") == 0)
                dissector_dump_decodes();
            else if (strcmp(argv[2], "defaultprefs") == 0)
                write_prefs(NULL);
            else if (strcmp(argv[2], "dissector-tables") == 0)
                dissector_dump_dissector_tables();
            else if (strcmp(argv[2], "fields") == 0)
                proto_registrar_dump_fields();
            else if (strcmp(argv[2], "ftypes") == 0)
                proto_registrar_dump_ftypes();
            else if (strcmp(argv[2], "heuristic-decodes") == 0)
                dissector_dump_heur_decodes();
            else if (strcmp(argv[2], "plugins") == 0) {
#ifdef HAVE_PLUGINS
                plugins_dump_all();
#endif
#ifdef HAVE_LUA
                wslua_plugins_dump_all();
#endif
            }
            else if (strcmp(argv[2], "protocols") == 0)
                proto_registrar_dump_protocols();
            else if (strcmp(argv[2], "values") == 0)
                proto_registrar_dump_values();
            else if (strcmp(argv[2], "?") == 0)
                glossary_option_help();
            else if (strcmp(argv[2], "-?") == 0)
                glossary_option_help();
            else {
                cmdarg_err("Invalid \"%s\" option for -G flag, enter -G ? for more help.", argv[2]);
                exit_status = INVALID_OPTION;
                goto clean_exit;
            }
        }
        goto clean_exit;
    }

    /* Load libwireshark settings from the current profile. */
    prefs_p = epan_load_settings();
    prefs_loaded = TRUE;

    cap_file_init(&cfile);

    /* Print format defaults to this. */
    print_format = PR_FMT_TEXT;

    output_fields = output_fields_new();

    /*
     * To reset the options parser, set ws_optreset to 1 and set ws_optind to 1.
     *
     * Also reset ws_opterr to 1, so that error messages are printed by
     * getopt_long().
     */
    ws_optreset = 1;
    ws_optind = 1;
    ws_opterr = 1;

    /* Now get our args */
    while ((opt = ws_getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        switch (opt) {
            case '2':        /* Perform two pass analysis */
                perform_two_pass_analysis = TRUE;
                break;
            case 'C':
                /* already processed; just ignore it now */
                break;
            case 'e':
                /* Field entry */
                output_fields_add(output_fields, ws_optarg);
                break;
            case 'E':
                /* Field option */
                if (!output_fields_set_option(output_fields, ws_optarg)) {
                    cmdarg_err("\"%s\" is not a valid field output option=value pair.", ws_optarg);
                    output_fields_list_options(stderr);
                    exit_status = INVALID_OPTION;
                    goto clean_exit;
                }
                break;

            case 'h':        /* Print help and exit */
                show_help_header("Analyze file structure.");
                print_usage(stdout);
                goto clean_exit;
                break;
            case 'l':        /* "Line-buffer" standard output */
                /* The ANSI C standard does not appear to *require* that a
                   line-buffered stream be flushed to the host environment
                   whenever a newline is written, it just says that, on such a
                   stream, characters "are intended to be transmitted to or
                   from the host environment as a block when a new-line
                   character is encountered".

                   The Visual C++ 6.0 C implementation doesn't do what is
                   intended; even if you set a stream to be line-buffered, it
                   still doesn't flush the buffer at the end of every line.

                   The whole reason for the "-l" flag in either tcpdump or
                   TShark is to allow the output of a live capture to be piped
                   to a program or script and to have that script see the
                   information for the packet as soon as it's printed, rather
                   than having to wait until a standard I/O buffer fills up.

                   So, if the "-l" flag is specified, we flush the standard
                   output at the end of a packet.  This will do the right thing
                   if we're printing packet summary lines, and, as we print the
                   entire protocol tree for a single packet without waiting for
                   anything to happen, it should be as good as line-buffered
                   mode if we're printing protocol trees - arguably even
                   better, as it may do fewer writes. */
                line_buffered = TRUE;
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
                            exit_status = INVALID_OPTION;
                            goto clean_exit;
                            break;

                        case PREFS_SET_NO_SUCH_PREF:
                            cmdarg_err("-o flag \"%s\" specifies unknown preference", ws_optarg);
                            exit_status = INVALID_OPTION;
                            goto clean_exit;
                            break;

                        case PREFS_SET_OBSOLETE:
                            cmdarg_err("-o flag \"%s\" specifies obsolete preference", ws_optarg);
                            exit_status = INVALID_OPTION;
                            goto clean_exit;
                            break;
                    }
                    break;
                }
            case 'q':        /* Quiet */
                quiet = TRUE;
                break;
            case 'Q':        /* Really quiet */
                quiet = TRUE;
                really_quiet = TRUE;
                break;
            case 'r':        /* Read capture file x */
                cf_name = g_strdup(ws_optarg);
                break;
            case 'R':        /* Read file filter */
                rfilter = ws_optarg;
                break;
            case 'S':        /* Set the line Separator to be printed between packets */
                separator = g_strdup(ws_optarg);
                break;
            case 'T':        /* printing Type */
                if (strcmp(ws_optarg, "text") == 0) {
                    output_action = WRITE_TEXT;
                    print_format = PR_FMT_TEXT;
                } else if (strcmp(ws_optarg, "ps") == 0) {
                    output_action = WRITE_TEXT;
                    print_format = PR_FMT_PS;
                } else if (strcmp(ws_optarg, "pdml") == 0) {
                    output_action = WRITE_XML;
                    print_details = TRUE;   /* Need details */
                    print_summary = FALSE;  /* Don't allow summary */
                } else if (strcmp(ws_optarg, "psml") == 0) {
                    output_action = WRITE_XML;
                    print_details = FALSE;  /* Don't allow details */
                    print_summary = TRUE;   /* Need summary */
                } else if (strcmp(ws_optarg, "fields") == 0) {
                    output_action = WRITE_FIELDS;
                    print_details = TRUE;   /* Need full tree info */
                    print_summary = FALSE;  /* Don't allow summary */
                } else {
                    cmdarg_err("Invalid -T parameter \"%s\"; it must be one of:", ws_optarg);                   /* x */
                    cmdarg_err_cont("\t\"fields\" The values of fields specified with the -e option, in a form\n"
                                    "\t         specified by the -E option.\n"
                                    "\t\"pdml\"   Packet Details Markup Language, an XML-based format for the\n"
                                    "\t         details of a decoded packet. This information is equivalent to\n"
                                    "\t         the packet details printed with the -V flag.\n"
                                    "\t\"ps\"     PostScript for a human-readable one-line summary of each of\n"
                                    "\t         the packets, or a multi-line view of the details of each of\n"
                                    "\t         the packets, depending on whether the -V flag was specified.\n"
                                    "\t\"psml\"   Packet Summary Markup Language, an XML-based format for the\n"
                                    "\t         summary information of a decoded packet. This information is\n"
                                    "\t         equivalent to the information shown in the one-line summary\n"
                                    "\t         printed by default.\n"
                                    "\t\"text\"   Text of a human-readable one-line summary of each of the\n"
                                    "\t         packets, or a multi-line view of the details of each of the\n"
                                    "\t         packets, depending on whether the -V flag was specified.\n"
                                    "\t         This is the default.");
                    exit_status = INVALID_OPTION;
                    goto clean_exit;
                }
                break;
            case 'v':         /* Show version and exit */
                show_version();
                goto clean_exit;
            case 'O':        /* Only output these protocols */
                /* already processed; just ignore it now */
                break;
            case 'V':        /* Verbose */
                /* already processed; just ignore it now */
                break;
            case 'x':        /* Print packet data in hex (and ASCII) */
                /* already processed; just ignore it now */
                break;
            case 'X':
                /* already processed; just ignore it now */
                break;
            case 'Y':
                dfilter = ws_optarg;
                break;
            case 'z':
                /* We won't call the init function for the stat this soon
                   as it would disallow MATE's fields (which are registered
                   by the preferences set callback) from being used as
                   part of a tap filter.  Instead, we just add the argument
                   to a list of stat arguments. */
                if (strcmp("help", ws_optarg) == 0) {
                    fprintf(stderr, "tfshark: The available statistics for the \"-z\" option are:\n");
                    list_stat_cmd_args();
                    goto clean_exit;
                }
                if (!process_stat_cmd_arg(ws_optarg)) {
                    cmdarg_err("Invalid -z argument \"%s\"; it must be one of:", ws_optarg);
                    list_stat_cmd_args();
                    exit_status = INVALID_OPTION;
                    goto clean_exit;
                }
                break;
            case 'd':        /* Decode as rule */
            case 'K':        /* Kerberos keytab file */
            case 't':        /* Time stamp type */
            case 'u':        /* Seconds type */
            case LONGOPT_DISABLE_PROTOCOL: /* disable dissection of protocol */
            case LONGOPT_ENABLE_HEURISTIC: /* enable heuristic dissection of protocol */
            case LONGOPT_DISABLE_HEURISTIC: /* disable heuristic dissection of protocol */
            case LONGOPT_ENABLE_PROTOCOL: /* enable dissection of protocol (that is disabled by default) */
                if (!dissect_opts_handle_opt(opt, ws_optarg)) {
                    exit_status = INVALID_OPTION;
                    goto clean_exit;
                }
                break;
            default:
            case '?':        /* Bad flag - print usage message */
                print_usage(stderr);
                exit_status = INVALID_OPTION;
                goto clean_exit;
                break;
        }
    }

    /* If we specified output fields, but not the output field type... */
    if (WRITE_FIELDS != output_action && 0 != output_fields_num_fields(output_fields)) {
        cmdarg_err("Output fields were specified with \"-e\", "
                "but \"-Tfields\" was not specified.");
        return 1;
    } else if (WRITE_FIELDS == output_action && 0 == output_fields_num_fields(output_fields)) {
        cmdarg_err("\"-Tfields\" was specified, but no fields were "
                "specified with \"-e\".");

        exit_status = INVALID_OPTION;
        goto clean_exit;
    }

    /* We require a -r flag specifying a file to read. */
    if (cf_name == NULL) {
        cmdarg_err("A file to read must be specified with \"-r\".");
        exit_status = NO_FILE_SPECIFIED;
        goto clean_exit;
    }

    /* If no display filter has been specified, and there are still command-
       line arguments, treat them as the tokens of a display filter. */
    if (ws_optind < argc) {
        if (dfilter != NULL) {
            cmdarg_err("Display filters were specified both with \"-Y\" "
                    "and with additional command-line arguments.");
            exit_status = INVALID_OPTION;
            goto clean_exit;
        }
        dfilter = get_args_as_string(argc, argv, ws_optind);
    }

    /* if "-q" wasn't specified, we should print packet information */
    if (!quiet)
        print_packet_info = TRUE;

    if (arg_error) {
        print_usage(stderr);
        exit_status = INVALID_OPTION;
        goto clean_exit;
    }

    if (print_hex) {
        if (output_action != WRITE_TEXT) {
            cmdarg_err("Raw packet hex data can only be printed as text or PostScript");
            exit_status = INVALID_OPTION;
            goto clean_exit;
        }
    }

    if (output_only != NULL) {
        char *ps;

        if (!print_details) {
            cmdarg_err("-O requires -V");
            exit_status = INVALID_OPTION;
            goto clean_exit;
        }

        output_only_tables = g_hash_table_new (g_str_hash, g_str_equal);
        for (ps = strtok (output_only, ","); ps; ps = strtok (NULL, ",")) {
            g_hash_table_insert(output_only_tables, (gpointer)ps, (gpointer)ps);
        }
    }

    if (rfilter != NULL && !perform_two_pass_analysis) {
        cmdarg_err("-R without -2 is deprecated. For single-pass filtering use -Y.");
        exit_status = INVALID_OPTION;
        goto clean_exit;
    }

    /* Notify all registered modules that have had any of their preferences
       changed either from one of the preferences file or from the command
       line that their preferences have changed. */
    prefs_apply_all();

    /*
     * Enabled and disabled protocols and heuristic dissectors as per
     * command-line options.
     */
    if (!setup_enabled_and_disabled_protocols()) {
        exit_status = INVALID_OPTION;
        goto clean_exit;
    }

    /* Build the column format array */
    build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

    if (rfilter != NULL) {
        if (!dfilter_compile(rfilter, &rfcode, &err_msg)) {
            cmdarg_err("%s", err_msg);
            g_free(err_msg);
            exit_status = INVALID_FILTER;
            goto clean_exit;
        }
    }
    cfile.rfcode = rfcode;

    if (dfilter != NULL) {
        if (!dfilter_compile(dfilter, &dfcode, &err_msg)) {
            cmdarg_err("%s", err_msg);
            g_free(err_msg);
            exit_status = INVALID_FILTER;
            goto clean_exit;
        }
    }
    cfile.dfcode = dfcode;

    if (print_packet_info) {
        /* If we're printing as text or PostScript, we have
           to create a print stream. */
        if (output_action == WRITE_TEXT) {
            switch (print_format) {

                case PR_FMT_TEXT:
                    print_stream = print_stream_text_stdio_new(stdout);
                    break;

                case PR_FMT_PS:
                    print_stream = print_stream_ps_stdio_new(stdout);
                    break;

                default:
                    ws_assert_not_reached();
            }
        }
    }

    /* We have to dissect each packet if:

       we're printing information about each packet;

       we're using a read filter on the packets;

       we're using a display filter on the packets;

       we're using any taps that need dissection. */
    do_dissection = print_packet_info || rfcode || dfcode || tap_listeners_require_dissection();

    /*
     * Read the file.
     */

    /* TODO: if tfshark is ever changed to give the user a choice of which
       open_routine reader to use, then the following needs to change. */
    if (cf_open(&cfile, cf_name, WTAP_TYPE_AUTO, FALSE, &err) != CF_OK) {
        exit_status = OPEN_ERROR;
        goto clean_exit;
    }

    /* Start statistics taps; we do so after successfully opening the
       capture file, so we know we have something to compute stats
       on, and after registering all dissectors, so that MATE will
       have registered its field array so we can have a tap filter
       with one of MATE's late-registered fields as part of the
       filter. */
    start_requested_stats();

    /* Process the packets in the file */
    TRY {
        /* XXX - for now there is only 1 packet */
        success = process_file(&cfile, 1, 0);
    }
    CATCH(OutOfMemoryError) {
        fprintf(stderr,
                "Out Of Memory.\n"
                "\n"
                "Sorry, but TFShark has to terminate now.\n"
                "\n"
                "Some infos / workarounds can be found at:\n"
                WS_WIKI_URL("KnownBugs/OutOfMemory") "\n");
        success = FALSE;
    }
    ENDTRY;

    if (!success) {
        /* We still dump out the results of taps, etc., as we might have
           read some packets; however, we exit with an error status. */
        exit_status = 2;
    }

    g_free(cf_name);

    if (cfile.provider.frames != NULL) {
        free_frame_data_sequence(cfile.provider.frames);
        cfile.provider.frames = NULL;
    }

    draw_tap_listeners(TRUE);
    funnel_dump_all_text_windows();

clean_exit:
    destroy_print_stream(print_stream);
    epan_free(cfile.epan);
    epan_cleanup();
    extcap_cleanup();

    output_fields_free(output_fields);
    output_fields = NULL;

    col_cleanup(&cfile.cinfo);
    wtap_cleanup();
    return exit_status;
}

static const nstime_t *
tfshark_get_frame_ts(struct packet_provider_data *prov, guint32 frame_num)
{
    if (prov->ref && prov->ref->num == frame_num)
        return &prov->ref->abs_ts;

    if (prov->prev_dis && prov->prev_dis->num == frame_num)
        return &prov->prev_dis->abs_ts;

    if (prov->prev_cap && prov->prev_cap->num == frame_num)
        return &prov->prev_cap->abs_ts;

    if (prov->frames) {
        frame_data *fd = frame_data_sequence_find(prov->frames, frame_num);

        return (fd) ? &fd->abs_ts : NULL;
    }

    return NULL;
}

static const char *
no_interface_name(struct packet_provider_data *prov _U_, guint32 interface_id _U_)
{
    return "";
}

static epan_t *
tfshark_epan_new(capture_file *cf)
{
    static const struct packet_provider_funcs funcs = {
        tfshark_get_frame_ts,
        no_interface_name,
        NULL,
        NULL,
    };

    return epan_new(&cf->provider, &funcs);
}

static gboolean
process_packet_first_pass(capture_file *cf, epan_dissect_t *edt,
        gint64 offset, wtap_rec *rec,
        const guchar *pd)
{
    frame_data     fdlocal;
    guint32        framenum;
    gboolean       passed;

    /* The frame number of this packet is one more than the count of
       frames in this packet. */
    framenum = cf->count + 1;

    /* If we're not running a display filter and we're not printing any
       packet information, we don't need to do a dissection. This means
       that all packets can be marked as 'passed'. */
    passed = TRUE;

    frame_data_init(&fdlocal, framenum, rec, offset, cum_bytes);

    /* If we're going to print packet information, or we're going to
       run a read filter, or display filter, or we're going to process taps, set up to
       do a dissection and do so. */
    if (edt) {
        /* If we're running a read filter, prime the epan_dissect_t with that
           filter. */
        if (cf->rfcode)
            epan_dissect_prime_with_dfilter(edt, cf->rfcode);

        /* This is the first pass, so prime the epan_dissect_t with the
           hfids postdissectors want on the first pass. */
        prime_epan_dissect_with_postdissector_wanted_hfids(edt);

        frame_data_set_before_dissect(&fdlocal, &cf->elapsed_time,
                &cf->provider.ref, cf->provider.prev_dis);
        if (cf->provider.ref == &fdlocal) {
            ref_frame = fdlocal;
            cf->provider.ref = &ref_frame;
        }

        epan_dissect_file_run(edt, rec,
                file_tvbuff_new(&cf->provider, &fdlocal, pd),
                &fdlocal, NULL);

        /* Run the read filter if we have one. */
        if (cf->rfcode)
            passed = dfilter_apply_edt(cf->rfcode, edt);
    }

    if (passed) {
        frame_data_set_after_dissect(&fdlocal, &cum_bytes);
        cf->provider.prev_cap = cf->provider.prev_dis = frame_data_sequence_add(cf->provider.frames, &fdlocal);

        /* If we're not doing dissection then there won't be any dependent frames.
         * More importantly, edt.pi.dependent_frames won't be initialized because
         * epan hasn't been initialized.
         */
        if (edt) {
            g_slist_foreach(edt->pi.dependent_frames, find_and_mark_frame_depended_upon, cf->provider.frames);
        }

        cf->count++;
    } else {
        /* if we don't add it to the frame_data_sequence, clean it up right now
         * to avoid leaks */
        frame_data_destroy(&fdlocal);
    }

    if (edt)
        epan_dissect_reset(edt);

    return passed;
}

static gboolean
process_packet_second_pass(capture_file *cf, epan_dissect_t *edt,
        frame_data *fdata, wtap_rec *rec,
        Buffer *buf, guint tap_flags)
{
    column_info    *cinfo;
    gboolean        passed;

    /* If we're not running a display filter and we're not printing any
       packet information, we don't need to do a dissection. This means
       that all packets can be marked as 'passed'. */
    passed = TRUE;

    /* If we're going to print packet information, or we're going to
       run a read filter, or we're going to process taps, set up to
       do a dissection and do so. */
    if (edt) {

        /* If we're running a display filter, prime the epan_dissect_t with that
           filter. */
        if (cf->dfcode)
            epan_dissect_prime_with_dfilter(edt, cf->dfcode);

        /* This is the first and only pass, so prime the epan_dissect_t
           with the hfids postdissectors want on the first pass. */
        prime_epan_dissect_with_postdissector_wanted_hfids(edt);

        col_custom_prime_edt(edt, &cf->cinfo);

        /* We only need the columns if either
           1) some tap needs the columns
           or
           2) we're printing packet info but we're *not* verbose; in verbose
           mode, we print the protocol tree, not the protocol summary.
           */
        if ((tap_flags & TL_REQUIRES_COLUMNS) || (print_packet_info && print_summary))
            cinfo = &cf->cinfo;
        else
            cinfo = NULL;

        frame_data_set_before_dissect(fdata, &cf->elapsed_time,
                &cf->provider.ref, cf->provider.prev_dis);
        if (cf->provider.ref == fdata) {
            ref_frame = *fdata;
            cf->provider.ref = &ref_frame;
        }

        epan_dissect_file_run_with_taps(edt, rec,
                file_tvbuff_new_buffer(&cf->provider, fdata, buf), fdata, cinfo);

        /* Run the read/display filter if we have one. */
        if (cf->dfcode)
            passed = dfilter_apply_edt(cf->dfcode, edt);
    }

    if (passed) {
        frame_data_set_after_dissect(fdata, &cum_bytes);
        /* Process this packet. */
        if (print_packet_info) {
            /* We're printing packet information; print the information for
               this packet. */
            print_packet(cf, edt);

            /* If we're doing "line-buffering", flush the standard output
               after every packet.  See the comment above, for the "-l"
               option, for an explanation of why we do that. */
            if (line_buffered)
                fflush(stdout);

            if (ferror(stdout)) {
                show_print_file_io_error(errno);
                return FALSE;
            }
        }
        cf->provider.prev_dis = fdata;
    }
    cf->provider.prev_cap = fdata;

    if (edt) {
        epan_dissect_reset(edt);
    }
    return passed || fdata->dependent_of_displayed;
}

static gboolean
local_wtap_read(capture_file *cf, wtap_rec *file_rec _U_, int *err, gchar **err_info _U_, gint64 *data_offset _U_, guint8** data_buffer)
{
    /* int bytes_read; */
    gint64 packet_size = wtap_file_size(cf->provider.wth, err);

    *data_buffer = (guint8*)g_malloc((gsize)packet_size);
    /* bytes_read =*/ file_read(*data_buffer, (unsigned int)packet_size, cf->provider.wth->fh);

#if 0 /* no more filetap */
    if (bytes_read < 0) {
        *err = file_error(cf->provider.wth->fh, err_info);
        if (*err == 0)
            *err = FTAP_ERR_SHORT_READ;
        return FALSE;
    } else if (bytes_read == 0) {
        /* Done with file, no error */
        return FALSE;
    }


    /* XXX - SET FRAME SIZE EQUAL TO TOTAL FILE SIZE */
    file_rec->rec_header.packet_header.caplen = (guint32)packet_size;
    file_rec->rec_header.packet_header.len = (guint32)packet_size;

    /*
     * Set the packet encapsulation to the file's encapsulation
     * value; if that's not WTAP_ENCAP_PER_PACKET, it's the
     * right answer (and means that the read routine for this
     * capture file type doesn't have to set it), and if it
     * *is* WTAP_ENCAP_PER_PACKET, the caller needs to set it
     * anyway.
     */
    wth->rec.rec_header.packet_header.pkt_encap = wth->file_encap;

    if (!wth->subtype_read(wth, err, err_info, data_offset)) {
        /*
         * If we didn't get an error indication, we read
         * the last packet.  See if there's any deferred
         * error, as might, for example, occur if we're
         * reading a compressed file, and we got an error
         * reading compressed data from the file, but
         * got enough compressed data to decompress the
         * last packet of the file.
         */
        if (*err == 0)
            *err = file_error(wth->fh, err_info);
        return FALSE;    /* failure */
    }

    /*
     * It makes no sense for the captured data length to be bigger
     * than the actual data length.
     */
    if (wth->rec.rec_header.packet_header.caplen > wth->rec.rec_header.packet_header.len)
        wth->rec.rec_header.packet_header.caplen = wth->rec.rec_header.packet_header.len;

    /*
     * Make sure that it's not WTAP_ENCAP_PER_PACKET, as that
     * probably means the file has that encapsulation type
     * but the read routine didn't set this packet's
     * encapsulation type.
     */
    ws_assert(wth->rec.rec_header.packet_header.pkt_encap != WTAP_ENCAP_PER_PACKET);
#endif

    return TRUE; /* success */
}

static gboolean
process_file(capture_file *cf, int max_packet_count, gint64 max_byte_count)
{
    guint32      framenum;
    int          err;
    gchar       *err_info = NULL;
    gint64       data_offset = 0;
    gboolean     filtering_tap_listeners;
    guint        tap_flags;
    Buffer       buf;
    epan_dissect_t *edt = NULL;
    wtap_rec     file_rec;
    guint8* raw_data;

    if (print_packet_info) {
        if (!write_preamble(cf)) {
            err = errno;
            show_print_file_io_error(err);
            goto out;
        }
    }

    /* Do we have any tap listeners with filters? */
    filtering_tap_listeners = have_filtering_tap_listeners();

    /* Get the union of the flags for all tap listeners. */
    tap_flags = union_of_tap_listener_flags();

    wtap_rec_init(&file_rec);

    /* XXX - TEMPORARY HACK TO ELF DISSECTOR */
    file_rec.rec_header.packet_header.pkt_encap = 1234;

    if (perform_two_pass_analysis) {
        frame_data *fdata;

        /* Allocate a frame_data_sequence for all the frames. */
        cf->provider.frames = new_frame_data_sequence();

        if (do_dissection) {
            gboolean create_proto_tree;

            /*
             * Determine whether we need to create a protocol tree.
             * We do if:
             *
             *    we're going to apply a read filter;
             *
             *    a postdissector wants field values or protocols
             *    on the first pass.
             */
            create_proto_tree =
                (cf->rfcode != NULL || postdissectors_want_hfids());

            /* We're not going to display the protocol tree on this pass,
               so it's not going to be "visible". */
            edt = epan_dissect_new(cf->epan, create_proto_tree, FALSE);
        }
        while (local_wtap_read(cf, &file_rec, &err, &err_info, &data_offset, &raw_data)) {
            if (process_packet_first_pass(cf, edt, data_offset, &file_rec, raw_data)) {

                /* Stop reading if we have the maximum number of packets;
                 * When the -c option has not been used, max_packet_count
                 * starts at 0, which practically means, never stop reading.
                 * (unless we roll over max_packet_count ?)
                 */
                if ( (--max_packet_count == 0) || (max_byte_count != 0 && data_offset >= max_byte_count)) {
                    err = 0; /* This is not an error */
                    break;
                }
            }
        }

        if (edt) {
            epan_dissect_free(edt);
            edt = NULL;
        }

#if 0
        /* Close the sequential I/O side, to free up memory it requires. */
        wtap_sequential_close(cf->provider.wth);
#endif

        /* Allow the protocol dissectors to free up memory that they
         * don't need after the sequential run-through of the packets. */
        postseq_cleanup_all_protocols();

        cf->provider.prev_dis = NULL;
        cf->provider.prev_cap = NULL;
        ws_buffer_init(&buf, 1514);

        if (do_dissection) {
            gboolean create_proto_tree;

            /*
             * Determine whether we need to create a protocol tree.
             * We do if:
             *
             *    we're going to apply a display filter;
             *
             *    we're going to print the protocol tree;
             *
             *    one of the tap listeners requires a protocol tree;
             *
             *    we have custom columns (which require field values, which
             *    currently requires that we build a protocol tree).
             */
            create_proto_tree =
                (cf->dfcode || print_details || filtering_tap_listeners ||
                 (tap_flags & TL_REQUIRES_PROTO_TREE) || have_custom_cols(&cf->cinfo));

            /* The protocol tree will be "visible", i.e., printed, only if we're
               printing packet details, which is true if we're printing stuff
               ("print_packet_info" is true) and we're in verbose mode
               ("packet_details" is true). */
            edt = epan_dissect_new(cf->epan, create_proto_tree, print_packet_info && print_details);
        }

        for (framenum = 1; err == 0 && framenum <= cf->count; framenum++) {
            fdata = frame_data_sequence_find(cf->provider.frames, framenum);
#if 0
            if (wtap_seek_read(cf->provider.wth, fdata->file_off,
                        &buf, fdata->cap_len, &err, &err_info)) {
                process_packet_second_pass(cf, edt, fdata, &cf->rec, &buf, tap_flags);
            }
#else
            if (!process_packet_second_pass(cf, edt, fdata, &cf->rec, &buf,
                        tap_flags))
                return FALSE;
#endif
        }

        if (edt) {
            epan_dissect_free(edt);
            edt = NULL;
        }

        ws_buffer_free(&buf);
    }
    else {
        framenum = 0;

        if (do_dissection) {
            gboolean create_proto_tree;

            /*
             * Determine whether we need to create a protocol tree.
             * We do if:
             *
             *    we're going to apply a read filter;
             *
             *    we're going to apply a display filter;
             *
             *    we're going to print the protocol tree;
             *
             *    one of the tap listeners is going to apply a filter;
             *
             *    one of the tap listeners requires a protocol tree;
             *
             *    a postdissector wants field values or protocols
             *    on the first pass;
             *
             *    we have custom columns (which require field values, which
             *    currently requires that we build a protocol tree).
             */
            create_proto_tree =
                (cf->rfcode || cf->dfcode || print_details || filtering_tap_listeners ||
                 (tap_flags & TL_REQUIRES_PROTO_TREE) || postdissectors_want_hfids() ||
                 have_custom_cols(&cf->cinfo));

            /* The protocol tree will be "visible", i.e., printed, only if we're
               printing packet details, which is true if we're printing stuff
               ("print_packet_info" is true) and we're in verbose mode
               ("packet_details" is true). */
            edt = epan_dissect_new(cf->epan, create_proto_tree, print_packet_info && print_details);
        }

        while (local_wtap_read(cf, &file_rec, &err, &err_info, &data_offset, &raw_data)) {

            framenum++;

            if (!process_packet_single_pass(cf, edt, data_offset,
                        &file_rec/*wtap_get_rec(cf->provider.wth)*/,
                        raw_data, tap_flags))
                return FALSE;

            /* Stop reading if we have the maximum number of packets;
             * When the -c option has not been used, max_packet_count
             * starts at 0, which practically means, never stop reading.
             * (unless we roll over max_packet_count ?)
             */
            if ( (--max_packet_count == 0) || (max_byte_count != 0 && data_offset >= max_byte_count)) {
                err = 0; /* This is not an error */
                break;
            }
        }

        if (edt) {
            epan_dissect_free(edt);
            edt = NULL;
        }
    }

    wtap_rec_cleanup(&file_rec);

    if (err != 0) {
        /*
         * Print a message noting that the read failed somewhere along the line.
         *
         * If we're printing packet data, and the standard output and error are
         * going to the same place, flush the standard output, so everything
         * buffered up is written, and then print a newline to the standard error
         * before printing the error message, to separate it from the packet
         * data.  (Alas, that only works on UN*X; st_dev is meaningless, and
         * the _fstat() documentation at Microsoft doesn't indicate whether
         * st_ino is even supported.)
         */
#ifndef _WIN32
        if (print_packet_info) {
            ws_statb64 stat_stdout, stat_stderr;

            if (ws_fstat64(1, &stat_stdout) == 0 && ws_fstat64(2, &stat_stderr) == 0) {
                if (stat_stdout.st_dev == stat_stderr.st_dev &&
                        stat_stdout.st_ino == stat_stderr.st_ino) {
                    fflush(stdout);
                    fprintf(stderr, "\n");
                }
            }
        }
#endif
#if 0
        switch (err) {

            case FTAP_ERR_UNSUPPORTED:
                cmdarg_err("The file \"%s\" contains record data that TFShark doesn't support.\n(%s)",
                        cf->filename, err_info);
                g_free(err_info);
                break;

            case FTAP_ERR_UNSUPPORTED_ENCAP:
                cmdarg_err("The file \"%s\" has a packet with a network type that TFShark doesn't support.\n(%s)",
                        cf->filename, err_info);
                g_free(err_info);
                break;

            case FTAP_ERR_CANT_READ:
                cmdarg_err("An attempt to read from the file \"%s\" failed for some unknown reason.",
                        cf->filename);
                break;

            case FTAP_ERR_SHORT_READ:
                cmdarg_err("The file \"%s\" appears to have been cut short in the middle of a packet.",
                        cf->filename);
                break;

            case FTAP_ERR_BAD_FILE:
                cmdarg_err("The file \"%s\" appears to be damaged or corrupt.\n(%s)",
                        cf->filename, err_info);
                g_free(err_info);
                break;

            case FTAP_ERR_DECOMPRESS:
                cmdarg_err("The compressed file \"%s\" appears to be damaged or corrupt.\n"
                        "(%s)", cf->filename, err_info);
                break;

            default:
                cmdarg_err("An error occurred while reading the file \"%s\": %s.",
                        cf->filename, ftap_strerror(err));
                break;
        }
#endif
    } else {
        if (print_packet_info) {
            if (!write_finale()) {
                err = errno;
                show_print_file_io_error(err);
            }
        }
    }

out:
    wtap_close(cf->provider.wth);
    cf->provider.wth = NULL;

    return (err != 0);
}

static gboolean
process_packet_single_pass(capture_file *cf, epan_dissect_t *edt, gint64 offset,
        wtap_rec *rec, const guchar *pd,
        guint tap_flags)
{
    frame_data      fdata;
    column_info    *cinfo;
    gboolean        passed;

    /* Count this packet. */
    cf->count++;

    /* If we're not running a display filter and we're not printing any
       packet information, we don't need to do a dissection. This means
       that all packets can be marked as 'passed'. */
    passed = TRUE;

    frame_data_init(&fdata, cf->count, rec, offset, cum_bytes);

    /* If we're going to print packet information, or we're going to
       run a read filter, or we're going to process taps, set up to
       do a dissection and do so. */
    if (edt) {
        /* If we're running a filter, prime the epan_dissect_t with that
           filter. */
        if (cf->dfcode)
            epan_dissect_prime_with_dfilter(edt, cf->dfcode);

        col_custom_prime_edt(edt, &cf->cinfo);

        /* We only need the columns if either
           1) some tap needs the columns
           or
           2) we're printing packet info but we're *not* verbose; in verbose
           mode, we print the protocol tree, not the protocol summary.
           or
           3) there is a column mapped as an individual field */
        if ((tap_flags & TL_REQUIRES_COLUMNS) || (print_packet_info && print_summary) || output_fields_has_cols(output_fields))
            cinfo = &cf->cinfo;
        else
            cinfo = NULL;

        frame_data_set_before_dissect(&fdata, &cf->elapsed_time,
                &cf->provider.ref, cf->provider.prev_dis);
        if (cf->provider.ref == &fdata) {
            ref_frame = fdata;
            cf->provider.ref = &ref_frame;
        }

        epan_dissect_file_run_with_taps(edt, rec,
                frame_tvbuff_new(&cf->provider, &fdata, pd),
                &fdata, cinfo);

        /* Run the filter if we have it. */
        if (cf->dfcode)
            passed = dfilter_apply_edt(cf->dfcode, edt);
    }

    if (passed) {
        frame_data_set_after_dissect(&fdata, &cum_bytes);

        /* Process this packet. */
        if (print_packet_info) {
            /* We're printing packet information; print the information for
               this packet. */
            print_packet(cf, edt);

            /* If we're doing "line-buffering", flush the standard output
               after every packet.  See the comment above, for the "-l"
               option, for an explanation of why we do that. */
            if (line_buffered)
                fflush(stdout);

            if (ferror(stdout)) {
                show_print_file_io_error(errno);
                return FALSE;
            }
        }

        /* this must be set after print_packet() [bug #8160] */
        prev_dis_frame = fdata;
        cf->provider.prev_dis = &prev_dis_frame;
    }

    prev_cap_frame = fdata;
    cf->provider.prev_cap = &prev_cap_frame;

    if (edt) {
        epan_dissect_reset(edt);
        frame_data_destroy(&fdata);
    }
    return passed;
}

static gboolean
write_preamble(capture_file *cf)
{
    switch (output_action) {

        case WRITE_TEXT:
            return print_preamble(print_stream, cf->filename, get_ws_vcs_version_info());

        case WRITE_XML:
            if (print_details)
                write_pdml_preamble(stdout, cf->filename);
            else
                write_psml_preamble(&cf->cinfo, stdout);
            return !ferror(stdout);

        case WRITE_FIELDS:
            write_fields_preamble(output_fields, stdout);
            return !ferror(stdout);

        default:
            ws_assert_not_reached();
            return FALSE;
    }
}

static char *
get_line_buf(size_t len)
{
    static char   *line_bufp    = NULL;
    static size_t  line_buf_len = 256;
    size_t         new_line_buf_len;

    for (new_line_buf_len = line_buf_len; len > new_line_buf_len;
            new_line_buf_len *= 2)
        ;
    if (line_bufp == NULL) {
        line_buf_len = new_line_buf_len;
        line_bufp = (char *)g_malloc(line_buf_len + 1);
    } else {
        if (new_line_buf_len > line_buf_len) {
            line_buf_len = new_line_buf_len;
            line_bufp = (char *)g_realloc(line_bufp, line_buf_len + 1);
        }
    }
    return line_bufp;
}

static inline void
put_string(char *dest, const char *str, size_t str_len)
{
    memcpy(dest, str, str_len);
    dest[str_len] = '\0';
}

static inline void
put_spaces_string(char *dest, const char *str, size_t str_len, size_t str_with_spaces)
{
    size_t i;

    for (i = str_len; i < str_with_spaces; i++)
        *dest++ = ' ';

    put_string(dest, str, str_len);
}

static inline void
put_string_spaces(char *dest, const char *str, size_t str_len, size_t str_with_spaces)
{
    size_t i;

    memcpy(dest, str, str_len);
    for (i = str_len; i < str_with_spaces; i++)
        dest[i] = ' ';

    dest[str_with_spaces] = '\0';
}

static gboolean
print_columns(capture_file *cf)
{
    char   *line_bufp;
    int     i;
    size_t  buf_offset;
    size_t  column_len;
    size_t  col_len;
    col_item_t* col_item;

    line_bufp = get_line_buf(256);
    buf_offset = 0;
    *line_bufp = '\0';
    for (i = 0; i < cf->cinfo.num_cols; i++) {
        col_item = &cf->cinfo.columns[i];
        /* Skip columns not marked as visible. */
        if (!get_column_visible(i))
            continue;
        const gchar* col_text = get_column_text(&cf->cinfo, i);
        switch (col_item->col_fmt) {
            case COL_NUMBER:
                column_len = col_len = strlen(col_text);
                if (column_len < 3)
                    column_len = 3;
                line_bufp = get_line_buf(buf_offset + column_len);
                put_spaces_string(line_bufp + buf_offset, col_text, col_len, column_len);
                break;

            case COL_CLS_TIME:
            case COL_REL_TIME:
            case COL_ABS_TIME:
            case COL_ABS_YMD_TIME:  /* XXX - wider */
            case COL_ABS_YDOY_TIME: /* XXX - wider */
            case COL_UTC_TIME:
            case COL_UTC_YMD_TIME:  /* XXX - wider */
            case COL_UTC_YDOY_TIME: /* XXX - wider */
                column_len = col_len = strlen(col_text);
                if (column_len < 10)
                    column_len = 10;
                line_bufp = get_line_buf(buf_offset + column_len);
                put_spaces_string(line_bufp + buf_offset, col_text, col_len, column_len);
                break;

            case COL_DEF_SRC:
            case COL_RES_SRC:
            case COL_UNRES_SRC:
            case COL_DEF_DL_SRC:
            case COL_RES_DL_SRC:
            case COL_UNRES_DL_SRC:
            case COL_DEF_NET_SRC:
            case COL_RES_NET_SRC:
            case COL_UNRES_NET_SRC:
                column_len = col_len = strlen(col_text);
                if (column_len < 12)
                    column_len = 12;
                line_bufp = get_line_buf(buf_offset + column_len);
                put_spaces_string(line_bufp + buf_offset, col_text, col_len, column_len);
                break;

            case COL_DEF_DST:
            case COL_RES_DST:
            case COL_UNRES_DST:
            case COL_DEF_DL_DST:
            case COL_RES_DL_DST:
            case COL_UNRES_DL_DST:
            case COL_DEF_NET_DST:
            case COL_RES_NET_DST:
            case COL_UNRES_NET_DST:
                column_len = col_len = strlen(col_text);
                if (column_len < 12)
                    column_len = 12;
                line_bufp = get_line_buf(buf_offset + column_len);
                put_string_spaces(line_bufp + buf_offset, col_text, col_len, column_len);
                break;

            default:
                column_len = strlen(col_text);
                line_bufp = get_line_buf(buf_offset + column_len);
                put_string(line_bufp + buf_offset, col_text, column_len);
                break;
        }
        buf_offset += column_len;
        if (i != cf->cinfo.num_cols - 1) {
            /*
             * This isn't the last column, so we need to print a
             * separator between this column and the next.
             *
             * If we printed a network source and are printing a
             * network destination of the same type next, separate
             * them with " -> "; if we printed a network destination
             * and are printing a network source of the same type
             * next, separate them with " <- "; otherwise separate them
             * with a space.
             *
             * We add enough space to the buffer for " <- " or " -> ",
             * even if we're only adding " ".
             */
            line_bufp = get_line_buf(buf_offset + 4);
            switch (col_item->col_fmt) {

                case COL_DEF_SRC:
                case COL_RES_SRC:
                case COL_UNRES_SRC:
                    switch (cf->cinfo.columns[i+1].col_fmt) {

                        case COL_DEF_DST:
                        case COL_RES_DST:
                        case COL_UNRES_DST:
                            put_string(line_bufp + buf_offset, " -> ", 4);
                            buf_offset += 4;
                            break;

                        default:
                            put_string(line_bufp + buf_offset, " ", 1);
                            buf_offset += 1;
                            break;
                    }
                    break;

                case COL_DEF_DL_SRC:
                case COL_RES_DL_SRC:
                case COL_UNRES_DL_SRC:
                    switch (cf->cinfo.columns[i+1].col_fmt) {

                        case COL_DEF_DL_DST:
                        case COL_RES_DL_DST:
                        case COL_UNRES_DL_DST:
                            put_string(line_bufp + buf_offset, " -> ", 4);
                            buf_offset += 4;
                            break;

                        default:
                            put_string(line_bufp + buf_offset, " ", 1);
                            buf_offset += 1;
                            break;
                    }
                    break;

                case COL_DEF_NET_SRC:
                case COL_RES_NET_SRC:
                case COL_UNRES_NET_SRC:
                    switch (cf->cinfo.columns[i+1].col_fmt) {

                        case COL_DEF_NET_DST:
                        case COL_RES_NET_DST:
                        case COL_UNRES_NET_DST:
                            put_string(line_bufp + buf_offset, " -> ", 4);
                            buf_offset += 4;
                            break;

                        default:
                            put_string(line_bufp + buf_offset, " ", 1);
                            buf_offset += 1;
                            break;
                    }
                    break;

                case COL_DEF_DST:
                case COL_RES_DST:
                case COL_UNRES_DST:
                    switch (cf->cinfo.columns[i+1].col_fmt) {

                        case COL_DEF_SRC:
                        case COL_RES_SRC:
                        case COL_UNRES_SRC:
                            put_string(line_bufp + buf_offset, " <- ", 4);
                            buf_offset += 4;
                            break;

                        default:
                            put_string(line_bufp + buf_offset, " ", 1);
                            buf_offset += 1;
                            break;
                    }
                    break;

                case COL_DEF_DL_DST:
                case COL_RES_DL_DST:
                case COL_UNRES_DL_DST:
                    switch (cf->cinfo.columns[i+1].col_fmt) {

                        case COL_DEF_DL_SRC:
                        case COL_RES_DL_SRC:
                        case COL_UNRES_DL_SRC:
                            put_string(line_bufp + buf_offset, " <- ", 4);
                            buf_offset += 4;
                            break;

                        default:
                            put_string(line_bufp + buf_offset, " ", 1);
                            buf_offset += 1;
                            break;
                    }
                    break;

                case COL_DEF_NET_DST:
                case COL_RES_NET_DST:
                case COL_UNRES_NET_DST:
                    switch (cf->cinfo.columns[i+1].col_fmt) {

                        case COL_DEF_NET_SRC:
                        case COL_RES_NET_SRC:
                        case COL_UNRES_NET_SRC:
                            put_string(line_bufp + buf_offset, " <- ", 4);
                            buf_offset += 4;
                            break;

                        default:
                            put_string(line_bufp + buf_offset, " ", 1);
                            buf_offset += 1;
                            break;
                    }
                    break;

                default:
                    put_string(line_bufp + buf_offset, " ", 1);
                    buf_offset += 1;
                    break;
            }
        }
    }
    return print_line(print_stream, 0, line_bufp);
}

static gboolean
print_packet(capture_file *cf, epan_dissect_t *edt)
{
    if (print_summary || output_fields_has_cols(output_fields)) {
        /* Just fill in the columns. */
        epan_dissect_fill_in_columns(edt, FALSE, TRUE);

        if (print_summary) {
            /* Now print them. */
            switch (output_action) {

                case WRITE_TEXT:
                    if (!print_columns(cf))
                        return FALSE;
                    break;

                case WRITE_XML:
                    write_psml_columns(edt, stdout, FALSE);
                    return !ferror(stdout);
                case WRITE_FIELDS: /*No non-verbose "fields" format */
                    ws_assert_not_reached();
                    break;
            }
        }
    }
    if (print_details) {
        /* Print the information in the protocol tree. */
        switch (output_action) {

            case WRITE_TEXT:
                if (!proto_tree_print(print_details ? print_dissections_expanded : print_dissections_none,
                            print_hex, edt, output_only_tables, print_stream))
                    return FALSE;
                if (!print_hex) {
                    if (!print_line(print_stream, 0, separator))
                        return FALSE;
                }
                break;

            case WRITE_XML:
                write_pdml_proto_tree(NULL, NULL, PF_NONE, edt, &cf->cinfo, stdout, FALSE);
                printf("\n");
                return !ferror(stdout);
            case WRITE_FIELDS:
                write_fields_proto_tree(output_fields, edt, &cf->cinfo, stdout);
                printf("\n");
                return !ferror(stdout);
        }
    }
    if (print_hex) {
        if (print_summary || print_details) {
            if (!print_line(print_stream, 0, ""))
                return FALSE;
        }
        if (!print_hex_data(print_stream, edt, HEXDUMP_SOURCE_MULTI | HEXDUMP_ASCII_INCLUDE))
            return FALSE;
        if (!print_line(print_stream, 0, separator))
            return FALSE;
    }
    return TRUE;
}

static gboolean
write_finale(void)
{
    switch (output_action) {

        case WRITE_TEXT:
            return print_finale(print_stream);

        case WRITE_XML:
            if (print_details)
                write_pdml_finale(stdout);
            else
                write_psml_finale(stdout);
            return !ferror(stdout);

        case WRITE_FIELDS:
            write_fields_finale(output_fields, stdout);
            return !ferror(stdout);

        default:
            ws_assert_not_reached();
            return FALSE;
    }
}

cf_status_t
cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
    gchar *err_info;
    char   err_msg[2048+1];

    /* The open isn't implemented yet.  Fill in the information for this file. */

    /* Create new epan session for dissection. */
    epan_free(cf->epan);
    cf->epan = tfshark_epan_new(cf);

    cf->provider.wth = NULL; /**** XXX - DOESN'T WORK RIGHT NOW!!!! */
    cf->f_datalen = 0; /* not used, but set it anyway */

    /* Set the file name because we need it to set the follow stream filter.
       XXX - is that still true?  We need it for other reasons, though,
       in any case. */
    cf->filename = g_strdup(fname);

    /* Indicate whether it's a permanent or temporary file. */
    cf->is_tempfile = is_tempfile;

    /* No user changes yet. */
    cf->unsaved_changes = FALSE;

    cf->cd_t      = 0; /**** XXX - DOESN'T WORK RIGHT NOW!!!! */
    cf->open_type = type;
    cf->count     = 0;
    cf->drops_known = FALSE;
    cf->drops     = 0;
    cf->snap      = 0; /**** XXX - DOESN'T WORK RIGHT NOW!!!! */
    nstime_set_zero(&cf->elapsed_time);
    cf->provider.ref = NULL;
    cf->provider.prev_dis = NULL;
    cf->provider.prev_cap = NULL;

    cf->state = FILE_READ_IN_PROGRESS;

    return CF_OK;

/* fail: */
    snprintf(err_msg, sizeof err_msg,
            cf_open_error_message(*err, err_info, FALSE, cf->cd_t), fname);
    cmdarg_err("%s", err_msg);
    return CF_ERROR;
}

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

static const char *
cf_open_error_message(int err, gchar *err_info _U_, gboolean for_writing,
        int file_type _U_)
{
    const char *errmsg;
    /* static char errmsg_errno[1024+1]; */

#if 0
    if (err < 0) {
        /* Wiretap error. */
        switch (err) {

            case FTAP_ERR_NOT_REGULAR_FILE:
                errmsg = "The file \"%s\" is a \"special file\" or socket or other non-regular file.";
                break;

            case FTAP_ERR_RANDOM_OPEN_PIPE:
                /* Seen only when opening a capture file for reading. */
                errmsg = "The file \"%s\" is a pipe or FIFO; TFShark can't read pipe or FIFO files in two-pass mode.";
                break;

            case FTAP_ERR_FILE_UNKNOWN_FORMAT:
                /* Seen only when opening a capture file for reading. */
                errmsg = "The file \"%s\" isn't a capture file in a format TFShark understands.";
                break;

            case FTAP_ERR_UNSUPPORTED:
                /* Seen only when opening a capture file for reading. */
                snprintf(errmsg_errno, sizeof(errmsg_errno),
                        "The file \"%%s\" isn't a capture file in a format TFShark understands.\n"
                        "(%s)", err_info);
                g_free(err_info);
                errmsg = errmsg_errno;
                break;

            case FTAP_ERR_CANT_WRITE_TO_PIPE:
                /* Seen only when opening a capture file for writing. */
                snprintf(errmsg_errno, sizeof(errmsg_errno),
                        "The file \"%%s\" is a pipe, and \"%s\" capture files can't be "
                        "written to a pipe.", ftap_file_type_subtype_short_string(file_type));
                errmsg = errmsg_errno;
                break;

            case FTAP_ERR_UNSUPPORTED_FILE_TYPE:
                /* Seen only when opening a capture file for writing. */
                errmsg = "TFShark doesn't support writing capture files in that format.";
                break;

            case FTAP_ERR_UNSUPPORTED_ENCAP:
                if (for_writing) {
                    snprintf(errmsg_errno, sizeof(errmsg_errno),
                            "TFShark can't save this capture as a \"%s\" file.",
                            ftap_file_type_subtype_short_string(file_type));
                } else {
                    snprintf(errmsg_errno, sizeof(errmsg_errno),
                            "The file \"%%s\" is a capture for a network type that TFShark doesn't support.\n"
                            "(%s)", err_info);
                    g_free(err_info);
                }
                errmsg = errmsg_errno;
                break;

            case FTAP_ERR_ENCAP_PER_RECORD_UNSUPPORTED:
                if (for_writing) {
                    snprintf(errmsg_errno, sizeof(errmsg_errno),
                            "TFShark can't save this capture as a \"%s\" file.",
                            ftap_file_type_subtype_short_string(file_type));
                    errmsg = errmsg_errno;
                } else
                    errmsg = "The file \"%s\" is a capture for a network type that TFShark doesn't support.";
                break;

            case FTAP_ERR_BAD_FILE:
                /* Seen only when opening a capture file for reading. */
                snprintf(errmsg_errno, sizeof(errmsg_errno),
                        "The file \"%%s\" appears to be damaged or corrupt.\n"
                        "(%s)", err_info);
                g_free(err_info);
                errmsg = errmsg_errno;
                break;

            case FTAP_ERR_CANT_OPEN:
                if (for_writing)
                    errmsg = "The file \"%s\" could not be created for some unknown reason.";
                else
                    errmsg = "The file \"%s\" could not be opened for some unknown reason.";
                break;

            case FTAP_ERR_SHORT_READ:
                errmsg = "The file \"%s\" appears to have been cut short"
                    " in the middle of a packet or other data.";
                break;

            case FTAP_ERR_SHORT_WRITE:
                errmsg = "A full header couldn't be written to the file \"%s\".";
                break;

            case FTAP_ERR_COMPRESSION_NOT_SUPPORTED:
                errmsg = "This file type cannot be written as a compressed file.";
                break;

            case FTAP_ERR_DECOMPRESS:
                /* Seen only when opening a capture file for reading. */
                snprintf(errmsg_errno, sizeof(errmsg_errno),
                        "The compressed file \"%%s\" appears to be damaged or corrupt.\n"
                        "(%s)", err_info);
                g_free(err_info);
                errmsg = errmsg_errno;
                break;

            default:
                snprintf(errmsg_errno, sizeof(errmsg_errno),
                        "The file \"%%s\" could not be %s: %s.",
                        for_writing ? "created" : "opened",
                        ftap_strerror(err));
                errmsg = errmsg_errno;
                break;
        }
    } else
#endif
        errmsg = file_open_error_message(err, for_writing);
    return errmsg;
}

/*
 * Report an error in command-line arguments.
 */
static void
tfshark_cmdarg_err(const char *msg_format, va_list ap)
{
    fprintf(stderr, "tfshark: ");
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
tfshark_cmdarg_err_cont(const char *msg_format, va_list ap)
{
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}
