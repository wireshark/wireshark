/* commandline.c
 * Common command line handling between GUIs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <wsutil/ws_getopt.h>

#include <ui/version_info.h>

#include <ui/clopts_common.h>
#include <ui/cmdarg_err.h>
#include <ui/exit_codes.h>
#include <wsutil/filesystem.h>
#include <wsutil/ws_assert.h>

#include <epan/ex-opt.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/stat_tap_ui.h>

#include "capture_opts.h"
#include "persfilepath_opt.h"
#include "preference_utils.h"
#include "console.h"
#include "recent.h"
#include "decode_as_utils.h"

#include "../file.h"

#include "ui/dissect_opts.h"

#include "ui/commandline.h"

commandline_param_info_t global_commandline_info;

capture_options global_capture_opts;

void
commandline_print_usage(gboolean for_help_option) {
    FILE *output;

#ifdef _WIN32
    create_console();
#endif

    if (for_help_option) {
        show_help_header("Interactively dump and analyze network traffic.");
        output = stdout;
    } else {
        output = stderr;
    }
    fprintf(output, "\n");
    fprintf(output, "Usage: wireshark [options] ... [ <infile> ]\n");
    fprintf(output, "\n");

#ifdef HAVE_LIBPCAP
    fprintf(output, "Capture interface:\n");
    fprintf(output, "  -i <interface>, --interface <interface>\n");
    fprintf(output, "                           name or idx of interface (def: first non-loopback)\n");
    fprintf(output, "  -f <capture filter>      packet filter in libpcap filter syntax\n");
    fprintf(output, "  -s <snaplen>, --snapshot-length <snaplen>\n");
#ifdef HAVE_PCAP_CREATE
    fprintf(output, "                           packet snapshot length (def: appropriate maximum)\n");
#else
    fprintf(output, "                           packet snapshot length (def: %u)\n", WTAP_MAX_PACKET_SIZE_STANDARD);
#endif
    fprintf(output, "  -p, --no-promiscuous-mode\n");
    fprintf(output, "                           don't capture in promiscuous mode\n");
    fprintf(output, "  -k                       start capturing immediately (def: do nothing)\n");
    fprintf(output, "  -S                       update packet display when new packets are captured\n");
    fprintf(output, "  -l                       turn on automatic scrolling while -S is in use\n");
#ifdef HAVE_PCAP_CREATE
    fprintf(output, "  -I, --monitor-mode       capture in monitor mode, if available\n");
#endif
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
    fprintf(output, "  -B <buffer size>, --buffer-size <buffer size>\n");
    fprintf(output, "                           size of kernel buffer (def: %dMB)\n", DEFAULT_CAPTURE_BUFFER_SIZE);
#endif
    fprintf(output, "  -y <link type>, --linktype <link type>\n");
    fprintf(output, "                           link layer type (def: first appropriate)\n");
    fprintf(output, "  --time-stamp-type <type> timestamp method for interface\n");
    fprintf(output, "  -D, --list-interfaces    print list of interfaces and exit\n");
    fprintf(output, "  -L, --list-data-link-types\n");
    fprintf(output, "                           print list of link-layer types of iface and exit\n");
    fprintf(output, "  --list-time-stamp-types  print list of timestamp types for iface and exit\n");
    fprintf(output, "\n");
    fprintf(output, "Capture stop conditions:\n");
    fprintf(output, "  -c <packet count>        stop after n packets (def: infinite)\n");
    fprintf(output, "  -a <autostop cond.> ..., --autostop <autostop cond.> ...\n");
    fprintf(output, "                           duration:NUM - stop after NUM seconds\n");
    fprintf(output, "                           filesize:NUM - stop this file after NUM KB\n");
    fprintf(output, "                              files:NUM - stop after NUM files\n");
    fprintf(output, "                            packets:NUM - stop after NUM packets\n");
    /*fprintf(output, "\n");*/
    fprintf(output, "Capture output:\n");
    fprintf(output, "  -b <ringbuffer opt.> ..., --ring-buffer <ringbuffer opt.>\n");
    fprintf(output, "                           duration:NUM - switch to next file after NUM secs\n");
    fprintf(output, "                           filesize:NUM - switch to next file after NUM KB\n");
    fprintf(output, "                              files:NUM - ringbuffer: replace after NUM files\n");
    fprintf(output, "                            packets:NUM - switch to next file after NUM packets\n");
    fprintf(output, "                           interval:NUM - switch to next file when the time is\n");
    fprintf(output, "                                          an exact multiple of NUM secs\n");
#endif  /* HAVE_LIBPCAP */
#ifdef HAVE_PCAP_REMOTE
    fprintf(output, "RPCAP options:\n");
    fprintf(output, "  -A <user>:<password>     use RPCAP password authentication\n");
#endif
    /*fprintf(output, "\n");*/
    fprintf(output, "Input file:\n");
    fprintf(output, "  -r <infile>, --read-file <infile>\n");
    fprintf(output, "                           set the filename to read from (no pipes or stdin!)\n");

    fprintf(output, "\n");
    fprintf(output, "Processing:\n");
    fprintf(output, "  -R <read filter>, --read-filter <read filter>\n");
    fprintf(output, "                           packet filter in Wireshark display filter syntax\n");
    fprintf(output, "  -n                       disable all name resolutions (def: all enabled)\n");
    fprintf(output, "  -N <name resolve flags>  enable specific name resolution(s): \"mnNtdv\"\n");
    fprintf(output, "  -d %s ...\n", DECODE_AS_ARG_TEMPLATE);
    fprintf(output, "                           \"Decode As\", see the man page for details\n");
    fprintf(output, "                           Example: tcp.port==8888,http\n");
    fprintf(output, "  --enable-protocol <proto_name>\n");
    fprintf(output, "                           enable dissection of proto_name\n");
    fprintf(output, "  --disable-protocol <proto_name>\n");
    fprintf(output, "                           disable dissection of proto_name\n");
    fprintf(output, "  --enable-heuristic <short_name>\n");
    fprintf(output, "                           enable dissection of heuristic protocol\n");
    fprintf(output, "  --disable-heuristic <short_name>\n");
    fprintf(output, "                           disable dissection of heuristic protocol\n");

    fprintf(output, "\n");
    fprintf(output, "User interface:\n");
    fprintf(output, "  -C <config profile>      start with specified configuration profile\n");
    fprintf(output, "  -H                       hide the capture info dialog during packet capture\n");
    fprintf(output, "  -Y <display filter>, --display-filter <display filter>\n");
    fprintf(output, "                           start with the given display filter\n");
    fprintf(output, "  -g <packet number>       go to specified packet number after \"-r\"\n");
    fprintf(output, "  -J <jump filter>         jump to the first packet matching the (display)\n");
    fprintf(output, "                           filter\n");
    fprintf(output, "  -j                       search backwards for a matching packet after \"-J\"\n");
    fprintf(output, "  -t a|ad|adoy|d|dd|e|r|u|ud|udoy\n");
    fprintf(output, "                           format of time stamps (def: r: rel. to first)\n");
    fprintf(output, "  -u s|hms                 output format of seconds (def: s: seconds)\n");
    fprintf(output, "  -X <key>:<value>         eXtension options, see man page for details\n");
    fprintf(output, "  -z <statistics>          show various statistics, see man page for details\n");

    fprintf(output, "\n");
    fprintf(output, "Output:\n");
    fprintf(output, "  -w <outfile|->           set the output filename (or '-' for stdout)\n");
#ifdef HAVE_LIBPCAP
    fprintf(output, "  --capture-comment <comment>\n");
    fprintf(output, "                           add a capture file comment, if supported\n");
#endif
    fprintf(output, "  --temp-dir <directory>   write temporary files to this directory\n");
    fprintf(output, "                           (default: %s)\n", g_get_tmp_dir());
    fprintf(output, "\n");

    ws_log_print_usage(output);

    fprintf(output, "\n");
    fprintf(output, "Miscellaneous:\n");
    fprintf(output, "  -h, --help               display this help and exit\n");
    fprintf(output, "  -v, --version            display version info and exit\n");
    fprintf(output, "  -P <key>:<path>          persconf:path - personal configuration files\n");
    fprintf(output, "                           persdata:path - personal data files\n");
    fprintf(output, "  -o <name>:<value> ...    override preference or recent setting\n");
    fprintf(output, "  -K <keytab>              keytab file to use for kerberos decryption\n");
#ifndef _WIN32
    fprintf(output, "  --display <X display>    X display to use\n");
#endif
    fprintf(output, "  --fullscreen             start Wireshark in full screen\n");

#ifdef _WIN32
    destroy_console();
#endif
}

#define LONGOPT_FULL_SCREEN     LONGOPT_BASE_GUI+1
#define LONGOPT_CAPTURE_COMMENT LONGOPT_BASE_GUI+2

#define OPTSTRING OPTSTRING_CAPTURE_COMMON OPTSTRING_DISSECT_COMMON "C:g:HhjJ:klm:o:P:r:R:Svw:X:Y:z:"
static const struct ws_option long_options[] = {
        {"help", ws_no_argument, NULL, 'h'},
        {"read-file", ws_required_argument, NULL, 'r' },
        {"read-filter", ws_required_argument, NULL, 'R' },
        {"display-filter", ws_required_argument, NULL, 'Y' },
        {"version", ws_no_argument, NULL, 'v'},
        {"fullscreen", ws_no_argument, NULL, LONGOPT_FULL_SCREEN },
        {"capture-comment", ws_required_argument, NULL, LONGOPT_CAPTURE_COMMENT},
        LONGOPT_CAPTURE_COMMON
        LONGOPT_DISSECT_COMMON
        {0, 0, 0, 0 }
    };
static const char optstring[] = OPTSTRING;

#ifndef HAVE_LIBPCAP
static void print_no_capture_support_error(void)
{
    cmdarg_err("This version of Wireshark was not built with support for capturing packets.");
}
#endif

void commandline_early_options(int argc, char *argv[])
{
    int opt;
#ifdef HAVE_LIBPCAP
    int err;
    GList *if_list;
    gchar *err_str;
#else
    gboolean capture_option_specified;
#endif

    /*
     * In order to have the -X opts assigned before the wslua machine starts
     * we need to call getopt_long before epan_init() gets called.
     *
     * In addition, we process "console only" parameters (ones where we
     * send output to the console and exit) here, so we don't start GUI
     * if we're only showing command-line help or version information.
     *
     * XXX - this pre-scan is done before we start GUI, so we haven't
     * run "GUI init function" on the arguments.  That means that GUI-specific
     * arguments have not been removed from the argument list; those arguments
     * begin with "--", and will be treated as an error by getopt_long().
     *
     * We thus ignore errors - *and* set "ws_opterr" to 0 to suppress the
     * error messages.
     *
     * In order to handle, for example, -o options, we also need to call it
     * *after* epan_init() gets called, so that the dissectors have had a
     * chance to register their preferences, so we have another getopt_long()
     * call later.
     *
     * XXX - can we do this all with one getopt_long() call, saving the
     * arguments we can't handle until after initializing libwireshark,
     * and then process them after initializing libwireshark?
     *
     * Note that we don't want to initialize libwireshark until after the
     * GUI is up, as that can take a while, and we want a window of some
     * sort up to show progress while that's happening.
     */
    ws_opterr = 0;

#ifndef HAVE_LIBPCAP
    capture_option_specified = FALSE;
#endif
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
                        exit(INVALID_FILE);
                    }
                    if (copy_persconffile_profile(ws_optarg, ws_optarg, TRUE, &pf_filename,
                            &pf_dir_path, &pf_dir_path2) == -1) {
                        cmdarg_err("Can't copy file \"%s\" in directory\n\"%s\" to\n\"%s\":\n%s.",
                            pf_filename, pf_dir_path2, pf_dir_path, g_strerror(errno));

                        g_free(pf_filename);
                        g_free(pf_dir_path);
                        g_free(pf_dir_path2);
                        exit(INVALID_FILE);
                    }
                    set_profile_name (ws_optarg);
                } else {
                    cmdarg_err("Configuration Profile \"%s\" does not exist", ws_optarg);
                    exit(1);
                }
                break;
            case 'D':        /* Print a list of capture devices and exit */
#ifdef HAVE_LIBPCAP
                if_list = capture_interface_list(&err, &err_str, NULL);
                if (if_list == NULL) {
                    if (err == 0)
                        cmdarg_err("There are no interfaces on which a capture can be done");
                    else {
                        cmdarg_err("%s", err_str);
                        g_free(err_str);
                    }
                    exit(INVALID_INTERFACE);
                }
#ifdef _WIN32
                create_console();
#endif /* _WIN32 */
                capture_opts_print_interfaces(if_list);
                free_interface_list(if_list);
#ifdef _WIN32
                destroy_console();
#endif /* _WIN32 */
                exit(EXIT_SUCCESS);
#else /* HAVE_LIBPCAP */
                capture_option_specified = TRUE;
#endif /* HAVE_LIBPCAP */
                break;
            case 'h':        /* Print help and exit */
                commandline_print_usage(TRUE);
                exit(EXIT_SUCCESS);
                break;
#ifdef _WIN32
            case 'i':
                if (strcmp(ws_optarg, "-") == 0)
                    set_stdin_capture(TRUE);
                break;
#endif
            case 'P':        /* Personal file directory path settings - change these before the Preferences and alike are processed */
                if (!persfilepath_opt(opt, ws_optarg)) {
                    cmdarg_err("-P flag \"%s\" failed (hint: is it quoted and existing?)", ws_optarg);
                    exit(EXIT_SUCCESS);
                }
                break;
            case 'v':        /* Show version and exit */
#ifdef _WIN32
                create_console();
#endif
                show_version();
#ifdef _WIN32
                destroy_console();
#endif
                exit(EXIT_SUCCESS);
                break;
            case 'X':
                /*
                 *  Extension command line options have to be processed before
                 *  we call epan_init() as they are supposed to be used by dissectors
                 *  or taps very early in the registration process.
                 */
                ex_opt_add(ws_optarg);
                break;
            case '?':        /* Ignore errors - the "real" scan will catch them. */
                break;
        }
    }

#ifndef HAVE_LUA
    if (ex_opt_count("lua_script") > 0) {
        cmdarg_err("This version of Wireshark was not built with support for Lua scripting.");
        exit(1);
    }
#endif

#ifndef HAVE_LIBPCAP
    if (capture_option_specified) {
        print_no_capture_support_error();
        commandline_print_usage(FALSE);
        exit(EXIT_SUCCESS);
    }
#endif
}

void commandline_other_options(int argc, char *argv[], gboolean opt_reset)
{
    int opt;
    gboolean arg_error = FALSE;
#ifdef HAVE_LIBPCAP
    const char *list_option_supplied = NULL;
    int status;
#else
    gboolean capture_option_specified;
#endif

    /*
     * To reset the options parser, set ws_optreset to 1 and set ws_optind to 1.
     *
     * Also reset ws_opterr to 1, so that error messages are printed by
     * getopt_long().
     *
     * XXX - if we want to control all the command-line option errors, so
     * that we can display them where we choose (e.g., in a window), we'd
     * want to leave ws_opterr as 0, and produce our own messages using ws_optopt.
     * We'd have to check the value of ws_optopt to see if it's a valid option
     * letter, in which case *presumably* the error is "this option requires
     * an argument but none was specified", or not a valid option letter,
     * in which case *presumably* the error is "this option isn't valid".
     * Some versions of getopt() let you supply a option string beginning
     * with ':', which means that getopt() will return ':' rather than '?'
     * for "this option requires an argument but none was specified", but
     * not all do.  But we're now using getopt_long() - what does it do?
     */
    if (opt_reset) {
        ws_optreset = 1;
        ws_optind = 1;
        ws_opterr = 1;
    }

    /* Initialize with default values */
    dissect_opts_init();
    global_commandline_info.jump_backwards = SD_FORWARD;
    global_commandline_info.go_to_packet = 0;
    global_commandline_info.jfilter = NULL;
    global_commandline_info.cf_name = NULL;
    global_commandline_info.rfilter = NULL;
    global_commandline_info.dfilter = NULL;
#ifdef HAVE_LIBPCAP
    global_commandline_info.start_capture = FALSE;
    global_commandline_info.list_link_layer_types = FALSE;
    global_commandline_info.list_timestamp_types = FALSE;
    global_commandline_info.quit_after_cap = getenv("WIRESHARK_QUIT_AFTER_CAPTURE") ? TRUE : FALSE;
    global_commandline_info.capture_comments = NULL;
#endif
    global_commandline_info.full_screen = FALSE;
    global_commandline_info.user_opts = NULL;

    while ((opt = ws_getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        switch (opt) {
            /*** capture option specific ***/
            case 'a':        /* autostop criteria */
            case 'b':        /* Ringbuffer option */
            case 'c':        /* Capture xxx packets */
            case 'f':        /* capture filter */
            case 'H':        /* Hide capture info dialog box */
            case 'p':        /* Don't capture in promiscuous mode */
            case 'i':        /* Use interface x */
            case LONGOPT_SET_TSTAMP_TYPE: /* Set capture timestamp type */
            case LONGOPT_CAPTURE_TMPDIR: /* capture temp directory */
#ifdef HAVE_PCAP_CREATE
            case 'I':        /* Capture in monitor mode, if available */
#endif
#ifdef HAVE_PCAP_REMOTE
            case 'A':        /* Authentication */
#endif
            case 's':        /* Set the snapshot (capture) length */
            case 'S':        /* "Sync" mode: used for following file ala tail -f */
            case 'w':        /* Write to capture file xxx */
            case 'y':        /* Set the pcap data link type */
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
            case 'B':        /* Buffer size */
#endif
#ifdef HAVE_LIBPCAP
                status = capture_opts_add_opt(&global_capture_opts, opt, ws_optarg);
                if(status != 0) {
                    exit_application(status);
                }
#else
                capture_option_specified = TRUE;
                arg_error = TRUE;
#endif
                break;

            /*** all non capture option specific ***/
            case 'C':
                /* Configuration profile settings were already processed just ignore them this time*/
                break;
            case 'j':        /* Search backwards for a matching packet from filter in option J */
                global_commandline_info.jump_backwards = SD_BACKWARD;
                break;
            case 'g':        /* Go to packet with the given packet number */
                global_commandline_info.go_to_packet = get_nonzero_guint32(ws_optarg, "go to packet");
                break;
            case 'J':        /* Jump to the first packet which matches the filter criteria */
                global_commandline_info.jfilter = ws_optarg;
                break;
            case 'k':        /* Start capture immediately */
#ifdef HAVE_LIBPCAP
                global_commandline_info.start_capture = TRUE;
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
                global_commandline_info.list_link_layer_types = TRUE;
                list_option_supplied = "-L";
#else
                capture_option_specified = TRUE;
                arg_error = TRUE;
#endif
                break;
            case LONGOPT_LIST_TSTAMP_TYPES:
#ifdef HAVE_LIBPCAP
                global_commandline_info.list_timestamp_types = TRUE;
                list_option_supplied = "--list-time-stamp-types";
#else
                capture_option_specified = TRUE;
                arg_error = TRUE;
#endif
                break;
            case 'o':        /* Override preference from command line */
            {
                char *errmsg = NULL;

                switch (prefs_set_pref(ws_optarg, &errmsg)) {
                    case PREFS_SET_OK:
                        global_commandline_info.user_opts =
                                g_slist_prepend(global_commandline_info.user_opts,
                                        g_strdup(ws_optarg));
                        break;
                    case PREFS_SET_SYNTAX_ERR:
                        cmdarg_err("Invalid -o flag \"%s\"%s%s", ws_optarg,
                                errmsg ? ": " : "", errmsg ? errmsg : "");
                        g_free(errmsg);
                        exit_application(1);
                        break;
                    case PREFS_SET_NO_SUCH_PREF:
                    /* not a preference, might be a recent setting */
                        switch (recent_set_arg(ws_optarg)) {
                            case PREFS_SET_OK:
                                break;
                            case PREFS_SET_SYNTAX_ERR:
                                /* shouldn't happen, checked already above */
                                cmdarg_err("Invalid -o flag \"%s\"", ws_optarg);
                                exit_application(1);
                                break;
                            case PREFS_SET_NO_SUCH_PREF:
                            case PREFS_SET_OBSOLETE:
                                cmdarg_err("-o flag \"%s\" specifies unknown preference/recent value",
                                           ws_optarg);
                                exit_application(1);
                                break;
                            default:
                                ws_assert_not_reached();
                        }
                        break;
                    case PREFS_SET_OBSOLETE:
                        cmdarg_err("-o flag \"%s\" specifies obsolete preference",
                                   ws_optarg);
                        exit_application(1);
                        break;
                    default:
                        ws_assert_not_reached();
                }
                break;
            }
            case 'P':
                /* Path settings were already processed just ignore them this time*/
                break;
            case 'r':        /* Read capture file xxx */
                /* We may set "last_open_dir" to "cf_name", and if we change
                 "last_open_dir" later, we free the old value, so we have to
                 set "cf_name" to something that's been allocated. */
                global_commandline_info.cf_name = g_strdup(ws_optarg);
                break;
            case 'R':        /* Read file filter */
                global_commandline_info.rfilter = ws_optarg;
                break;
            case 'X':
                /* ext ops were already processed just ignore them this time*/
                break;
            case 'Y':
                global_commandline_info.dfilter = ws_optarg;
                break;
            case 'z':
                /* We won't call the init function for the stat this soon
                 as it would disallow MATE's fields (which are registered
                 by the preferences set callback) from being used as
                 part of a tap filter.  Instead, we just add the argument
                 to a list of stat arguments. */
                if (strcmp("help", ws_optarg) == 0) {
                  fprintf(stderr, "wireshark: The available statistics for the \"-z\" option are:\n");
                  list_stat_cmd_args();
                  exit_application(0);
                }
                if (!process_stat_cmd_arg(ws_optarg)) {
                    cmdarg_err("Invalid -z argument.");
                    cmdarg_err_cont("  -z argument must be one of :");
                    list_stat_cmd_args();
                    exit_application(1);
                }
                break;
            case 'd':        /* Decode as rule */
            case 'K':        /* Kerberos keytab file */
            case 'n':        /* No name resolution */
            case 'N':        /* Select what types of addresses/port #s to resolve */
            case 't':        /* time stamp type */
            case 'u':        /* Seconds type */
            case LONGOPT_DISABLE_PROTOCOL: /* disable dissection of protocol */
            case LONGOPT_ENABLE_HEURISTIC: /* enable heuristic dissection of protocol */
            case LONGOPT_DISABLE_HEURISTIC: /* disable heuristic dissection of protocol */
            case LONGOPT_ENABLE_PROTOCOL: /* enable dissection of protocol (that is disabled by default) */
                if (!dissect_opts_handle_opt(opt, ws_optarg))
                   exit_application(1);
                break;
            case LONGOPT_FULL_SCREEN:
                global_commandline_info.full_screen = TRUE;
                break;
#ifdef HAVE_LIBPCAP
            case LONGOPT_CAPTURE_COMMENT:  /* capture comment */
                if (global_commandline_info.capture_comments == NULL) {
                    global_commandline_info.capture_comments = g_ptr_array_new_with_free_func(g_free);
                }
                g_ptr_array_add(global_commandline_info.capture_comments, g_strdup(ws_optarg));
#else
                capture_option_specified = TRUE;
                arg_error = TRUE;
#endif
                break;
            default:
            case '?':        /* Bad flag - print usage message */
                arg_error = TRUE;
                break;
            }
    }

    /* Since we prepended each option when processing `-o`, reverse the list
     * in case the order of options becomes meaningful.
     */
    global_commandline_info.user_opts = g_slist_reverse(global_commandline_info.user_opts);

    if (!arg_error) {
        argc -= ws_optind;
        argv += ws_optind;
        if (argc >= 1) {
            if (global_commandline_info.cf_name != NULL) {
                /*
                 * Input file name specified with "-r" *and* specified as a regular
                 * command-line argument.
                 */
                cmdarg_err("File name specified both with -r and regular argument");
                arg_error = TRUE;
            } else {
                /*
                 * Input file name not specified with "-r", and a command-line argument
                 * was specified; treat it as the input file name.
                 *
                 * Yes, this is different from tshark, where non-flag command-line
                 * arguments are a filter, but this works better on GUI desktops
                 * where a command can be specified to be run to open a particular
                 * file - yes, you could have "-r" as the last part of the command,
                 * but that's a bit ugly.
                 */
                global_commandline_info.cf_name = g_strdup(argv[0]);
            }
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
    }

    if (arg_error) {
#ifndef HAVE_LIBPCAP
        if (capture_option_specified) {
            print_no_capture_support_error();
        }
#endif
        commandline_print_usage(FALSE);
        exit_application(1);
    }

#ifdef HAVE_LIBPCAP
    if (global_commandline_info.start_capture && list_option_supplied) {
        /* Specifying *both* is bogus. */
        cmdarg_err("You can't specify both %s and a live capture.", list_option_supplied);
        exit_application(1);
    }

    if (list_option_supplied) {
        /* We're supposed to list the link-layer types for an interface;
           did the user also specify a capture file to be read? */
        if (global_commandline_info.cf_name) {
            /* Yes - that's bogus. */
            cmdarg_err("You can't specify %s and a capture file to be read.", list_option_supplied);
            exit_application(1);
        }
        /* No - did they specify a ring buffer option? */
        if (global_capture_opts.multi_files_on) {
            cmdarg_err("Ring buffer requested, but a capture isn't being done.");
            exit_application(1);
        }
    } else {
        /* We're supposed to do a live capture; did the user also specify
           a capture file to be read? */
        if (global_commandline_info.start_capture && global_commandline_info.cf_name) {
            /* Yes - that's bogus. */
            cmdarg_err("You can't specify both a live capture and a capture file to be read.");
            exit_application(1);
        }

        /* No - was the ring buffer option specified and, if so, does it make
           sense? */
        if (global_capture_opts.multi_files_on) {
            /* Ring buffer works only under certain conditions:
             a) ring buffer does not work with temporary files;
             b) real_time_mode and multi_files_on are mutually exclusive -
             real_time_mode takes precedence;
             c) it makes no sense to enable the ring buffer if the maximum
             file size is set to "infinite". */
            if (global_capture_opts.save_file == NULL) {
                cmdarg_err("Ring buffer requested, but capture isn't being saved to a permanent file.");
                global_capture_opts.multi_files_on = FALSE;
            }
            if (!global_capture_opts.has_autostop_filesize &&
                !global_capture_opts.has_file_duration &&
                !global_capture_opts.has_file_interval &&
                !global_capture_opts.has_file_packets) {
                cmdarg_err("Ring buffer requested, but no maximum capture file size, duration, interval or packets were specified.");
                /* XXX - this must be redesigned as the conditions changed */
            }
        }
    }
#endif
}

/* Local function used by commandline_options_drop */
static int cl_find_custom(gconstpointer elem_data, gconstpointer search_data) {
    return memcmp(elem_data, search_data, strlen((char *)search_data));
}

/* Drop any options the user specified on the command line with `-o`
 * that have the given module and preference names
 */
void commandline_options_drop(const char *module_name, const char *pref_name) {
    GSList *elem;
    char *opt_prefix;

    if (global_commandline_info.user_opts == NULL) return;

    opt_prefix = ws_strdup_printf("%s.%s:", module_name, pref_name);

    while (NULL != (elem = g_slist_find_custom(global_commandline_info.user_opts,
                        (gconstpointer)opt_prefix, cl_find_custom))) {
        global_commandline_info.user_opts =
                g_slist_remove_link(global_commandline_info.user_opts, elem);
        g_free(elem->data);
        g_slist_free_1(elem);
    }
    g_free(opt_prefix);
}

/* Reapply any options the user specified on the command line with `-o`
 * Called in the Qt UI when reloading Lua plugins
 * For https://gitlab.com/wireshark/wireshark/-/issues/12331
 */
void commandline_options_reapply(void) {
    char *errmsg = NULL;
    GSList *entry = NULL;

    for (entry = global_commandline_info.user_opts; entry != NULL; entry = g_slist_next(entry)) {
        /* Although these options are from the user-supplied command line,
         * they were checked for validity before we added them to user_opts,
         * so we don't check them again here. In the worst case, a pref is
         * specified for a lua plugin which has been edited after Wireshark
         * started and has had that pref removed; not worth exiting over.
         * See #12331
         */
        prefs_set_pref((char *)entry->data, &errmsg);
        if (errmsg != NULL) {
            g_free(errmsg);
            errmsg = NULL;
        }
    }
}

/* Free memory used to hold user-specified command line options */
void commandline_options_free(void) {
    g_slist_free_full(global_commandline_info.user_opts, g_free);
}
