/* dissect_opts.c
 * Routines for dissection options setting
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include <glib.h>

#include <epan/prefs.h>
#include <epan/timestamp.h>
#include <epan/addr_resolv.h>
#include <epan/disabled_protos.h>

#include "ui/decode_as_utils.h"

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
#include <epan/dissectors/read_keytab_file.h>
#endif

#include <wsutil/clopts_common.h>
#include <wsutil/strtoi.h>
#include <wsutil/cmdarg_err.h>
#include <wsutil/file_util.h>
#include <wsutil/ws_assert.h>

#include "ui/dissect_opts.h"

dissect_options global_dissect_options = {
    .time_format = TS_NOT_SET,
    .time_precision = TS_PREC_NOT_SET
};

bool
dissect_opts_handle_opt(int opt, char *optarg_str_p)
{
    char badopt;
    char *dotp;
    ts_precision tsp;

    switch(opt) {
    case 'd':        /* Decode as rule */
        if (!decode_as_command_option(optarg_str_p))
             return false;
        break;
    case 'K':        /* Kerberos keytab file */
#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
        read_keytab_file(optarg_str_p);
#else
        cmdarg_err("-K specified, but Kerberos keytab file support isn't present");
        return false;
#endif
        break;
    case 'n':        /* No name resolution */
        disable_name_resolution();
        break;
    case 'N':        /* Select what types of addresses/port #s to resolve */
        badopt = string_to_name_resolve(optarg_str_p, &gbl_resolv_flags);
        if (badopt != '\0') {
            cmdarg_err("-N specifies unknown resolving option '%c'; valid options are:",
                       badopt);
            cmdarg_err_cont("\t'd' to enable address resolution from captured DNS packets\n"
                            "\t'g' to enable address geolocation information from MaxMind databases\n"
                            "\t'm' to enable MAC address resolution\n"
                            "\t'n' to enable network address resolution\n"
                            "\t'N' to enable using external resolvers (e.g., DNS)\n"
                            "\t    for network address resolution\n"
                            "\t's' to enable address resolution using SNI information found in captured\n"
                            "\t    handshake packets\n"
                            "\t't' to enable transport-layer port number resolution\n"
                            "\t'v' to enable VLAN IDs to names resolution");
            return false;
        }
        break;
    case 't':        /* Time stamp type */
        tsp = TS_PREC_NOT_SET;
        dotp = strchr(optarg_str_p, '.');
        if (dotp != NULL) {
            if (strcmp(dotp + 1, "") == 0) {
                /* Nothing specified; use appropriate precision for the file. */
                tsp = TS_PREC_AUTO;
            } else {
                /*
                 * Precision must be a number giving the number of
                 * digits of precision.
                 */
                uint32_t val;

                if (!ws_strtou32(dotp + 1, NULL, &val) || val > WS_TSPREC_MAX) {
                    cmdarg_err("Invalid .N time stamp precision \"%s\"; N must be a value between 0 and %u or absent",
                               dotp + 1, WS_TSPREC_MAX);
                    return false;
                }
                tsp = val;
            }
            /* Mask the '.' while checking format. */
            *dotp = '\0';
        }
        if (strcmp(optarg_str_p, "r") == 0)
            global_dissect_options.time_format = TS_RELATIVE;
        else if (strcmp(optarg_str_p, "a") == 0)
            global_dissect_options.time_format = TS_ABSOLUTE;
        else if (strcmp(optarg_str_p, "ad") == 0)
            global_dissect_options.time_format = TS_ABSOLUTE_WITH_YMD;
        else if (strcmp(optarg_str_p, "adoy") == 0)
            global_dissect_options.time_format = TS_ABSOLUTE_WITH_YDOY;
        else if (strcmp(optarg_str_p, "d") == 0)
            global_dissect_options.time_format = TS_DELTA;
        else if (strcmp(optarg_str_p, "dd") == 0)
            global_dissect_options.time_format = TS_DELTA_DIS;
        else if (strcmp(optarg_str_p, "e") == 0)
            global_dissect_options.time_format = TS_EPOCH;
        else if (strcmp(optarg_str_p, "u") == 0)
            global_dissect_options.time_format = TS_UTC;
        else if (strcmp(optarg_str_p, "ud") == 0)
            global_dissect_options.time_format = TS_UTC_WITH_YMD;
        else if (strcmp(optarg_str_p, "udoy") == 0)
            global_dissect_options.time_format = TS_UTC_WITH_YDOY;
        else if (optarg_str_p != dotp) {
            /* If (optarg_str_p == dotp), user only set precision. */
            cmdarg_err("Invalid time stamp type \"%s\"; it must be one of:", optarg_str_p);
            cmdarg_err_cont("\t\"a\"    for absolute\n"
                            "\t\"ad\"   for absolute with YYYY-MM-DD date\n"
                            "\t\"adoy\" for absolute with YYYY/DOY date\n"
                            "\t\"d\"    for delta\n"
                            "\t\"dd\"   for delta displayed\n"
                            "\t\"e\"    for epoch\n"
                            "\t\"r\"    for relative\n"
                            "\t\"u\"    for absolute UTC\n"
                            "\t\"ud\"   for absolute UTC with YYYY-MM-DD date\n"
                            "\t\"udoy\" for absolute UTC with YYYY/DOY date");
            if (dotp)
                *dotp = '.';
            return false;
        }
        if (dotp) {
            *dotp = '.';
            global_dissect_options.time_precision = tsp;
        }
        break;
    case 'u':        /* Seconds type */
        if (strcmp(optarg_str_p, "s") == 0)
            timestamp_set_seconds_type(TS_SECONDS_DEFAULT);
        else if (strcmp(optarg_str_p, "hms") == 0)
            timestamp_set_seconds_type(TS_SECONDS_HOUR_MIN_SEC);
        else {
            cmdarg_err("Invalid seconds type \"%s\"; it must be one of:", optarg_str_p);
            cmdarg_err_cont("\t\"s\"   for seconds\n"
                            "\t\"hms\" for hours, minutes and seconds");
            return false;
        }
        break;
    case LONGOPT_DISABLE_PROTOCOL: /* disable dissection of protocol */
        global_dissect_options.disable_protocol_slist = g_slist_append(global_dissect_options.disable_protocol_slist, optarg_str_p);
        break;
    case LONGOPT_ENABLE_HEURISTIC: /* enable heuristic dissection of protocol */
        global_dissect_options.enable_heur_slist = g_slist_append(global_dissect_options.enable_heur_slist, optarg_str_p);
        break;
    case LONGOPT_DISABLE_HEURISTIC: /* disable heuristic dissection of protocol */
        global_dissect_options.disable_heur_slist = g_slist_append(global_dissect_options.disable_heur_slist, optarg_str_p);
        break;
    case LONGOPT_ENABLE_PROTOCOL: /* enable dissection of protocol (that is disabled by default) */
        global_dissect_options.enable_protocol_slist = g_slist_append(global_dissect_options.enable_protocol_slist, optarg_str_p);
        break;
    case LONGOPT_ONLY_PROTOCOLS: /* enable dissection of these comma separated protocols only */
        proto_disable_all();
        for (char *ps = strtok (optarg_str_p, ","); ps; ps = strtok(NULL, ",")){
          global_dissect_options.enable_protocol_slist = g_slist_append(global_dissect_options.enable_protocol_slist, ps);
        }
        break;
    case LONGOPT_DISABLE_ALL_PROTOCOLS: /* disable dissection of all protocols */
        proto_disable_all();
        break;
    default:
        /* the caller is responsible to send us only the right opt's */
        ws_assert_not_reached();
    }
    return true;
}

typedef bool (proto_set_func)(const char *);

static bool
process_enable_disable_list(GSList *list, proto_set_func callback)
{
    bool success = true;
    bool rv;
    GSList *iter;
    char *c;
    char *proto_name;

    for (iter = list; iter != NULL; iter = g_slist_next(iter)) {
        proto_name = (char *)iter->data;
        c = strchr(proto_name, ',');
        if (c == NULL) {
            rv = callback(proto_name);
            if (!rv) {
                cmdarg_err("No such protocol %s", proto_name);
                success = false;
            }
        }
        else {
            char *start;
            char save;

            start = proto_name;
            while(1) {
                if (c != NULL) {
                    save = *c;
                    *c = '\0';
                }
                rv = callback(start);
                if (!rv) {
                    cmdarg_err("No such protocol %s", start);
                    success = false;
                }
                if (c != NULL) {
                    *c = save;
                    start = (save == ',' ? c+1 : c);
                    c = strchr(start, ',');
                }
                else {
                    break;
                }
            }
        }
    }

    return success;
}

bool
setup_enabled_and_disabled_protocols(void)
{
    bool success = true;

    success = success && process_enable_disable_list(global_dissect_options.disable_protocol_slist,
            proto_disable_proto_by_name);
    success = success && process_enable_disable_list(global_dissect_options.enable_protocol_slist,
            proto_enable_proto_by_name);
    success = success && process_enable_disable_list(global_dissect_options.enable_heur_slist,
            proto_enable_heuristic_by_name);
    success = success && process_enable_disable_list(global_dissect_options.disable_heur_slist,
            proto_disable_heuristic_by_name);
    return success;
}
