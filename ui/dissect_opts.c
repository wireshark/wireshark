/* dissect_opts.c
 * Routines for dissection options setting
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include <errno.h>

#include <glib.h>

#include <epan/timestamp.h>

#include "ui/decode_as_utils.h"

#include <wsutil/clopts_common.h>
#include <wsutil/cmdarg_err.h>
#include <wsutil/file_util.h>

#include "ui/dissect_opts.h"

dissect_options global_dissect_options;

void
dissect_opts_init(void)
{
    global_dissect_options.time_format = TS_NOT_SET;
    global_dissect_options.disable_protocol_slist = NULL;
    global_dissect_options.enable_heur_slist = NULL;
    global_dissect_options.disable_heur_slist = NULL;
}

void
dissect_opts_add_opt(int opt, char *optarg_str_p)
{
    switch(opt) {
    case 'd':        /* Decode as rule */
        if (!decode_as_command_option(optarg_str_p))
             exit(1);
        break;
    case 't':        /* Time stamp type */
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
        else {
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
            exit(1);
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
    default:
        /* the caller is responsible to send us only the right opt's */
        g_assert_not_reached();
    }
}

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
