/* commandline.c
 * Common command line handling between GUIs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifndef HAVE_GETOPT_LONG
#include "wsutil/wsgetopt.h"
#endif

#include <ws_version_info.h>

#include <wsutil/clopts_common.h>
#include <wsutil/cmdarg_err.h>
#include <wsutil/filesystem.h>

#include <epan/ex-opt.h>
#include <epan/addr_resolv.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/timestamp.h>
#include <epan/stat_tap_ui.h>

#include "capture_opts.h"
#include "persfilepath_opt.h"
#include "preference_utils.h"
#include "console.h"
#include "recent.h"
#include "decode_as_utils.h"

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
#include <epan/asn1.h>
#include <epan/dissectors/packet-kerberos.h>
#endif

#include "../file.h"

#include "ui/commandline.h"

commandline_param_info_t global_commandline_info;

#if defined(HAVE_LIBPCAP) || defined(HAVE_EXTCAP)
capture_options global_capture_opts;
#endif

void
commandline_print_usage(gboolean for_help_option) {
    FILE *output;

#ifdef _WIN32
    create_console();
#endif

    if (for_help_option) {
        output = stdout;
        fprintf(output, "Wireshark %s\n"
            "Interactively dump and analyze network traffic.\n"
            "See https://www.wireshark.org for more information.\n",
            get_ws_vcs_version_info());
    } else {
        output = stderr;
    }
    fprintf(output, "\n");
    fprintf(output, "Usage: wireshark [options] ... [ <infile> ]\n");
    fprintf(output, "\n");

#ifdef HAVE_LIBPCAP
    fprintf(output, "Capture interface:\n");
    fprintf(output, "  -i <interface>           name or idx of interface (def: first non-loopback)\n");
    fprintf(output, "  -f <capture filter>      packet filter in libpcap filter syntax\n");
    fprintf(output, "  -s <snaplen>             packet snapshot length (def: 65535)\n");
    fprintf(output, "  -p                       don't capture in promiscuous mode\n");
    fprintf(output, "  -k                       start capturing immediately (def: do nothing)\n");
    fprintf(output, "  -S                       update packet display when new packets are captured\n");
    fprintf(output, "  -l                       turn on automatic scrolling while -S is in use\n");
#ifdef HAVE_PCAP_CREATE
    fprintf(output, "  -I                       capture in monitor mode, if available\n");
#endif
#ifdef CAN_SET_CAPTURE_BUFFER_SIZE
    fprintf(output, "  -B <buffer size>         size of kernel buffer (def: %dMB)\n", DEFAULT_CAPTURE_BUFFER_SIZE);
#endif
    fprintf(output, "  -y <link type>           link layer type (def: first appropriate)\n");
    fprintf(output, "  -D                       print list of interfaces and exit\n");
    fprintf(output, "  -L                       print list of link-layer types of iface and exit\n");
    fprintf(output, "\n");
    fprintf(output, "Capture stop conditions:\n");
    fprintf(output, "  -c <packet count>        stop after n packets (def: infinite)\n");
    fprintf(output, "  -a <autostop cond.> ...  duration:NUM - stop after NUM seconds\n");
    fprintf(output, "                           filesize:NUM - stop this file after NUM KB\n");
    fprintf(output, "                              files:NUM - stop after NUM files\n");
    /*fprintf(output, "\n");*/
    fprintf(output, "Capture output:\n");
    fprintf(output, "  -b <ringbuffer opt.> ... duration:NUM - switch to next file after NUM secs\n");
    fprintf(output, "                           filesize:NUM - switch to next file after NUM KB\n");
    fprintf(output, "                              files:NUM - ringbuffer: replace after NUM files\n");
#endif  /* HAVE_LIBPCAP */
#ifdef HAVE_PCAP_REMOTE
    fprintf(output, "RPCAP options:\n");
    fprintf(output, "  -A <user>:<password>     use RPCAP password authentication\n");
#endif
    /*fprintf(output, "\n");*/
    fprintf(output, "Input file:\n");
    fprintf(output, "  -r <infile>              set the filename to read from (no pipes or stdin!)\n");

    fprintf(output, "\n");
    fprintf(output, "Processing:\n");
    fprintf(output, "  -R <read filter>         packet filter in Wireshark display filter syntax\n");
    fprintf(output, "  -n                       disable all name resolutions (def: all enabled)\n");
    fprintf(output, "  -N <name resolve flags>  enable specific name resolution(s): \"mnNtd\"\n");
    fprintf(output, "  -d %s ...\n", DECODE_AS_ARG_TEMPLATE);
    fprintf(output, "                           \"Decode As\", see the man page for details\n");
    fprintf(output, "                           Example: tcp.port==8888,http\n");
    fprintf(output, "  --disable-protocol <proto_name>\n");
    fprintf(output, "                           disable dissection of proto_name\n");
    fprintf(output, "  --enable-heuristic <short_name>\n");
    fprintf(output, "                           enable dissection of heuristic protocol\n");
    fprintf(output, "  --disable-heuristic <short_name>\n");
    fprintf(output, "                           disable dissection of heuristic protocol\n");

    fprintf(output, "\n");
    fprintf(output, "User interface:\n");
    fprintf(output, "  -C <config profile>      start with specified configuration profile\n");
    fprintf(output, "  -Y <display filter>      start with the given display filter\n");
    fprintf(output, "  -g <packet number>       go to specified packet number after \"-r\"\n");
    fprintf(output, "  -J <jump filter>         jump to the first packet matching the (display)\n");
    fprintf(output, "                           filter\n");
    fprintf(output, "  -j                       search backwards for a matching packet after \"-J\"\n");
    fprintf(output, "  -m <font>                set the font name used for most text\n");
    fprintf(output, "  -t a|ad|d|dd|e|r|u|ud    output format of time stamps (def: r: rel. to first)\n");
    fprintf(output, "  -u s|hms                 output format of seconds (def: s: seconds)\n");
    fprintf(output, "  -X <key>:<value>         eXtension options, see man page for details\n");
    fprintf(output, "  -z <statistics>          show various statistics, see man page for details\n");

    fprintf(output, "\n");
    fprintf(output, "Output:\n");
    fprintf(output, "  -w <outfile|->           set the output filename (or '-' for stdout)\n");

    fprintf(output, "\n");
    fprintf(output, "Miscellaneous:\n");
    fprintf(output, "  -h                       display this help and exit\n");
    fprintf(output, "  -v                       display version info and exit\n");
    fprintf(output, "  -P <key>:<path>          persconf:path - personal configuration files\n");
    fprintf(output, "                           persdata:path - personal data files\n");
    fprintf(output, "  -o <name>:<value> ...    override preference or recent setting\n");
    fprintf(output, "  -K <keytab>              keytab file to use for kerberos decryption\n");
#ifndef _WIN32
    fprintf(output, "  --display=DISPLAY        X display to use\n");
#endif

#ifdef _WIN32
    destroy_console();
#endif
}

#define OPTSTRING OPTSTRING_CAPTURE_COMMON "C:d:g:Hh" "jJ:kK:lm:nN:o:P:r:R:St:u:vw:X:Y:z:"
static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"read-file", required_argument, NULL, 'r' },
        {"read-filter", required_argument, NULL, 'R' },
        {"display-filter", required_argument, NULL, 'Y' },
        {"version", no_argument, NULL, 'v'},
        LONGOPT_CAPTURE_COMMON
        {0, 0, 0, 0 }
    };
static const char optstring[] = OPTSTRING;

#ifndef HAVE_LIBPCAP
static void print_no_capture_support_error(void)
{
    cmdarg_err("This version of Wireshark was not built with support for capturing packets.");
}
#endif

void commandline_early_options(int argc, char *argv[],
    GString *comp_info_str, GString *runtime_info_str)
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
     * We thus ignore errors - *and* set "opterr" to 0 to suppress the
     * error messages.
     *
     * XXX - should we, instead, first call gtk_parse_args(), without
     * calling gtk_init(), and then call this?
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
    opterr = 0;

#ifndef HAVE_LIBPCAP
    capture_option_specified = FALSE;
#endif
    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        switch (opt) {
            case 'C':        /* Configuration Profile */
                if (profile_exists (optarg, FALSE)) {
                    set_profile_name (optarg);
                } else {
                    cmdarg_err("Configuration Profile \"%s\" does not exist", optarg);
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
                    exit(2);
                }
#ifdef _WIN32
                create_console();
#endif /* _WIN32 */
                capture_opts_print_interfaces(if_list);
                free_interface_list(if_list);
#ifdef _WIN32
                destroy_console();
#endif /* _WIN32 */
                exit(0);
#else /* HAVE_LIBPCAP */
                capture_option_specified = TRUE;
#endif /* HAVE_LIBPCAP */
                break;
            case 'h':        /* Print help and exit */
                commandline_print_usage(TRUE);
                exit(0);
                break;
#ifdef _WIN32
            case 'i':
                if (strcmp(optarg, "-") == 0)
                    set_stdin_capture(TRUE);
                break;
#endif
            case 'P':        /* Personal file directory path settings - change these before the Preferences and alike are processed */
                if (!persfilepath_opt(opt, optarg)) {
                    cmdarg_err("-P flag \"%s\" failed (hint: is it quoted and existing?)", optarg);
                    exit(2);
                }
                break;
            case 'v':        /* Show version and exit */
#ifdef _WIN32
                create_console();
#endif
                show_version("Wireshark", comp_info_str, runtime_info_str);
#ifdef _WIN32
                destroy_console();
#endif
                exit(0);
                break;
            case 'X':
                /*
                 *  Extension command line options have to be processed before
                 *  we call epan_init() as they are supposed to be used by dissectors
                 *  or taps very early in the registration process.
                 */
                ex_opt_add(optarg);
                break;
            case '?':        /* Ignore errors - the "real" scan will catch them. */
                break;
        }
    }

#ifndef HAVE_LIBPCAP
    if (capture_option_specified) {
        print_no_capture_support_error();
        commandline_print_usage(FALSE);
        exit(1);
    }
#endif
}

void commandline_other_options(int argc, char *argv[], gboolean opt_reset)
{
    int opt;
    gboolean arg_error = FALSE;
#ifdef HAVE_LIBPCAP
    int status;
#else
    gboolean capture_option_specified;
#endif
    char badopt;

    /*
     * To reset the options parser, set optreset to 1 on platforms that
     * have optreset (documented in *BSD and OS X, apparently present but
     * not documented in Solaris - the Illumos repository seems to
     * suggest that the first Solaris getopt_long(), at least as of 2004,
     * was based on the NetBSD one, it had optreset) and set optind to 1,
     * and set optind to 0 otherwise (documented as working in the GNU
     * getopt_long().  Setting optind to 0 didn't originally work in the
     * NetBSD one, but that was added later - we don't want to depend on
     * it if we have optreset).
     *
     * Also reset opterr to 1, so that error messages are printed by
     * getopt_long().
     *
     * XXX - if we want to control all the command-line option errors, so
     * that we can display them where we choose (e.g., in a window), we'd
     * want to leave opterr as 0, and produce our own messages using optopt.
     * We'd have to check the value of optopt to see if it's a valid option
     * letter, in which case *presumably* the error is "this option requires
     * an argument but none was specified", or not a valid option letter,
     * in which case *presumably* the error is "this option isn't valid".
     * Some versions of getopt() let you supply a option string beginning
     * with ':', which means that getopt() will return ':' rather than '?'
     * for "this option requires an argument but none was specified", but
     * not all do.  But we're now using getopt_long() - what does it do?
     */
    if (opt_reset) {
#ifdef HAVE_OPTRESET
        optreset = 1;
        optind = 1;
#else
        optind = 0;
#endif
        opterr = 1;
    }

    /* Initialize with default values */
    global_commandline_info.jump_backwards = SD_FORWARD;
    global_commandline_info.go_to_packet = 0;
    global_commandline_info.jfilter = NULL;
    global_commandline_info.cf_name = NULL;
    global_commandline_info.rfilter = NULL;
    global_commandline_info.dfilter = NULL;
    global_commandline_info.time_format = TS_NOT_SET;
#ifdef HAVE_LIBPCAP
    global_commandline_info.start_capture = FALSE;
    global_commandline_info.list_link_layer_types = FALSE;
    global_commandline_info.quit_after_cap = getenv("WIRESHARK_QUIT_AFTER_CAPTURE") ? TRUE : FALSE;
#endif
    global_commandline_info.disable_protocol_slist = NULL;
    global_commandline_info.enable_heur_slist = NULL;
    global_commandline_info.disable_heur_slist = NULL;

    while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
        switch (opt) {
            /*** capture option specific ***/
            case 'a':        /* autostop criteria */
            case 'b':        /* Ringbuffer option */
            case 'c':        /* Capture xxx packets */
            case 'f':        /* capture filter */
            case 'k':        /* Start capture immediately */
            case 'H':        /* Hide capture info dialog box */
            case 'p':        /* Don't capture in promiscuous mode */
            case 'i':        /* Use interface x */
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
                status = capture_opts_add_opt(&global_capture_opts, opt, optarg,
                                              &global_commandline_info.start_capture);
                if(status != 0) {
                    exit(status);
                }
#else
                capture_option_specified = TRUE;
                arg_error = TRUE;
#endif
                break;

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
            case 'K':        /* Kerberos keytab file */
                read_keytab_file(optarg);
                break;
#endif

            /*** all non capture option specific ***/
            case 'C':
                /* Configuration profile settings were already processed just ignore them this time*/
                break;
            case 'd':        /* Decode as rule */
                if (!decode_as_command_option(optarg))
                    exit(1);
                break;
            case 'j':        /* Search backwards for a matching packet from filter in option J */
                global_commandline_info.jump_backwards = SD_BACKWARD;
                break;
            case 'g':        /* Go to packet with the given packet number */
                global_commandline_info.go_to_packet = get_positive_int(optarg, "go to packet");
                break;
            case 'J':        /* Jump to the first packet which matches the filter criteria */
                global_commandline_info.jfilter = optarg;
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
#else
                capture_option_specified = TRUE;
                arg_error = TRUE;
#endif
                break;
            case 'm':        /* Fixed-width font for the display. GTK+ only. */
                g_free(global_commandline_info.prefs_p->gui_gtk2_font_name);
                global_commandline_info.prefs_p->gui_gtk2_font_name = g_strdup(optarg);
                break;
            case 'n':        /* No name resolution */
                disable_name_resolution();
                break;
            case 'N':        /* Select what types of addresses/port #s to resolve */
                badopt = string_to_name_resolve(optarg, &gbl_resolv_flags);
                if (badopt != '\0') {
                    cmdarg_err("-N specifies unknown resolving option '%c'; valid options are 'd', m', 'n', 'N', and 't'",
                               badopt);
                    exit(1);
                }
                break;
            case 'o':        /* Override preference from command line */
                switch (prefs_set_pref(optarg)) {
                    case PREFS_SET_OK:
                        break;
                    case PREFS_SET_SYNTAX_ERR:
                        cmdarg_err("Invalid -o flag \"%s\"", optarg);
                        exit(1);
                        break;
                    case PREFS_SET_NO_SUCH_PREF:
                    /* not a preference, might be a recent setting */
                        switch (recent_set_arg(optarg)) {
                            case PREFS_SET_OK:
                                break;
                            case PREFS_SET_SYNTAX_ERR:
                                /* shouldn't happen, checked already above */
                                cmdarg_err("Invalid -o flag \"%s\"", optarg);
                                exit(1);
                                break;
                            case PREFS_SET_NO_SUCH_PREF:
                            case PREFS_SET_OBSOLETE:
                                cmdarg_err("-o flag \"%s\" specifies unknown preference/recent value",
                                           optarg);
                                exit(1);
                                break;
                            default:
                                g_assert_not_reached();
                        }
                        break;
                    case PREFS_SET_OBSOLETE:
                        cmdarg_err("-o flag \"%s\" specifies obsolete preference",
                                   optarg);
                        exit(1);
                        break;
                    default:
                        g_assert_not_reached();
                }
                break;
            case 'P':
                /* Path settings were already processed just ignore them this time*/
                break;
            case 'r':        /* Read capture file xxx */
                /* We may set "last_open_dir" to "cf_name", and if we change
                 "last_open_dir" later, we free the old value, so we have to
                 set "cf_name" to something that's been allocated. */
                global_commandline_info.cf_name = g_strdup(optarg);
                break;
            case 'R':        /* Read file filter */
                global_commandline_info.rfilter = optarg;
                break;
            case 't':        /* Time stamp type */
                if (strcmp(optarg, "r") == 0)
                    global_commandline_info.time_format = TS_RELATIVE;
                else if (strcmp(optarg, "a") == 0)
                    global_commandline_info.time_format = TS_ABSOLUTE;
                else if (strcmp(optarg, "ad") == 0)
                    global_commandline_info.time_format = TS_ABSOLUTE_WITH_YMD;
                else if (strcmp(optarg, "adoy") == 0)
                    global_commandline_info.time_format = TS_ABSOLUTE_WITH_YDOY;
                else if (strcmp(optarg, "d") == 0)
                    global_commandline_info.time_format = TS_DELTA;
                else if (strcmp(optarg, "dd") == 0)
                    global_commandline_info.time_format = TS_DELTA_DIS;
                else if (strcmp(optarg, "e") == 0)
                    global_commandline_info.time_format = TS_EPOCH;
                else if (strcmp(optarg, "u") == 0)
                    global_commandline_info.time_format = TS_UTC;
                else if (strcmp(optarg, "ud") == 0)
                    global_commandline_info.time_format = TS_UTC_WITH_YMD;
                else if (strcmp(optarg, "udoy") == 0)
                    global_commandline_info.time_format = TS_UTC_WITH_YDOY;
                else {
                    cmdarg_err("Invalid time stamp type \"%s\"", optarg);
                    cmdarg_err_cont("It must be \"a\" for absolute, \"ad\" for absolute with YYYY-MM-DD date,");
                    cmdarg_err_cont("\"adoy\" for absolute with YYYY/DOY date, \"d\" for delta,");
                    cmdarg_err_cont("\"dd\" for delta displayed, \"e\" for epoch, \"r\" for relative,");
                    cmdarg_err_cont("\"u\" for absolute UTC, \"ud\" for absolute UTC with YYYY-MM-DD date,");
                    cmdarg_err_cont("or \"udoy\" for absolute UTC with YYYY/DOY date.");
                    exit(1);
                }
                break;
            case 'u':        /* Seconds type */
                if (strcmp(optarg, "s") == 0)
                    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);
                else if (strcmp(optarg, "hms") == 0)
                    timestamp_set_seconds_type(TS_SECONDS_HOUR_MIN_SEC);
                else {
                    cmdarg_err("Invalid seconds type \"%s\"", optarg);
                    cmdarg_err_cont("It must be \"s\" for seconds or \"hms\" for hours, minutes and seconds.");
                    exit(1);
                }
                break;
            case 'X':
                /* ext ops were already processed just ignore them this time*/
                break;
            case 'Y':
                global_commandline_info.dfilter = optarg;
                break;
            case 'z':
                /* We won't call the init function for the stat this soon
                 as it would disallow MATE's fields (which are registered
                 by the preferences set callback) from being used as
                 part of a tap filter.  Instead, we just add the argument
                 to a list of stat arguments. */
                if (strcmp("help", optarg) == 0) {
                  fprintf(stderr, "wireshark: The available statistics for the \"-z\" option are:\n");
                  list_stat_cmd_args();
                  exit(0);
                }
                if (!process_stat_cmd_arg(optarg)) {
                    cmdarg_err("Invalid -z argument.");
                    cmdarg_err_cont("  -z argument must be one of :");
                    list_stat_cmd_args();
                    exit(1);
                }
                break;
            case LONGOPT_DISABLE_PROTOCOL: /* disable dissection of protocol */
                global_commandline_info.disable_protocol_slist = g_slist_append(global_commandline_info.disable_protocol_slist, optarg);
                break;
            case LONGOPT_ENABLE_HEURISTIC: /* enable heuristic dissection of protocol */
                global_commandline_info.enable_heur_slist = g_slist_append(global_commandline_info.enable_heur_slist, optarg);
                break;
            case LONGOPT_DISABLE_HEURISTIC: /* disable heuristic dissection of protocol */
                global_commandline_info.disable_heur_slist = g_slist_append(global_commandline_info.disable_heur_slist, optarg);
                break;
            default:
            case '?':        /* Bad flag - print usage message */
                arg_error = TRUE;
                break;
            }
    }

    if (!arg_error) {
        argc -= optind;
        argv += optind;
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
#ifndef HAVE_GTKOSXAPPLICATION
                /*
                 * For GTK+ Mac Integration, file name passed as free argument passed
                 * through grag-and-drop and opened twice sometimes causing crashes.
                 * Subject to report to GTK+ MAC.
                 */
                global_commandline_info.cf_name = g_strdup(argv[0]);
#endif
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
        exit(1);
    }

#ifdef HAVE_LIBPCAP
    if (global_commandline_info.start_capture && global_commandline_info.list_link_layer_types) {
        /* Specifying *both* is bogus. */
        cmdarg_err("You can't specify both -L and a live capture.");
        exit(1);
    }

    if (global_commandline_info.list_link_layer_types) {
        /* We're supposed to list the link-layer types for an interface;
           did the user also specify a capture file to be read? */
        if (global_commandline_info.cf_name) {
            /* Yes - that's bogus. */
            cmdarg_err("You can't specify -L and a capture file to be read.");
            exit(1);
        }
        /* No - did they specify a ring buffer option? */
        if (global_capture_opts.multi_files_on) {
            cmdarg_err("Ring buffer requested, but a capture isn't being done.");
            exit(1);
        }
    } else {
        /* We're supposed to do a live capture; did the user also specify
           a capture file to be read? */
        if (global_commandline_info.start_capture && global_commandline_info.cf_name) {
            /* Yes - that's bogus. */
            cmdarg_err("You can't specify both a live capture and a capture file to be read.");
            exit(1);
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
            if (!global_capture_opts.has_autostop_filesize && !global_capture_opts.has_file_duration) {
                cmdarg_err("Ring buffer requested, but no maximum capture file size or duration were specified.");
                /* XXX - this must be redesigned as the conditions changed */
            }
        }
    }
#endif
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
