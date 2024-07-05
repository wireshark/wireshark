/* tap-flow.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This module provides udp and tcp follow stream capabilities to tshark.
 * It is only used by tshark and not wireshark.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include <epan/sequence_analysis.h>
#include <epan/stat_tap_ui.h>
#include <epan/tap.h>

void register_tap_listener_flow(void);

#define STR_FLOW        "flow,"
#define STR_STANDARD    ",standard"
#define STR_NETWORK     ",network"

WS_NORETURN static void flow_exit(const char *strp)
{
    fprintf(stderr, "tshark: flow - %s\n", strp);
    exit(1);
}

static void
flow_draw(void *arg)
{
    seq_analysis_info_t* flow_info = (seq_analysis_info_t*)arg;

    sequence_analysis_get_nodes(flow_info);

    sequence_analysis_dump_to_file(stdout, flow_info, 0);

    //clean up the data
    sequence_analysis_list_free(flow_info);
    sequence_analysis_info_free(flow_info);
}

static bool flow_arg_strncmp(const char **opt_argp, const char *strp)
{
    size_t len = strlen(strp);

    if (strncmp(*opt_argp, strp, len) == 0)
    {
        *opt_argp += len;
        return true;
    }
    return false;
}

static void
flow_arg_mode(const char **opt_argp, seq_analysis_info_t *flow_info)
{
    if (flow_arg_strncmp(opt_argp, STR_STANDARD))
    {
        flow_info->any_addr = 1;
    }
    else if (flow_arg_strncmp(opt_argp, STR_NETWORK))
    {
        flow_info->any_addr = 0;
    }
    else
    {
        flow_exit("Invalid address type.");
    }
}

static void
flow_init(const char *opt_argp, void *userdata)
{
    seq_analysis_info_t *flow_info = g_new0(seq_analysis_info_t, 1);
    GString  *errp;
    register_analysis_t* analysis = (register_analysis_t*)userdata;
    const char *filter=NULL;

    opt_argp += strlen(STR_FLOW);
    opt_argp += strlen(sequence_analysis_get_name(analysis));

    flow_arg_mode(&opt_argp, flow_info);
    if (*opt_argp == ',') {
        filter = opt_argp + 1;
    }

    sequence_analysis_list_free(flow_info);

    errp = register_tap_listener(sequence_analysis_get_tap_listener_name(analysis), flow_info, filter, sequence_analysis_get_tap_flags(analysis),
                                NULL, sequence_analysis_get_packet_func(analysis), flow_draw, NULL);

    if (errp != NULL)
    {
        sequence_analysis_list_free(flow_info);
        sequence_analysis_info_free(flow_info);
        g_string_free(errp, TRUE);
        flow_exit("Error registering tap listener.");
    }
}

static bool
flow_register(const void *key _U_, void *value, void *userdata _U_)
{
    register_analysis_t* analysis = (register_analysis_t*)value;
    stat_tap_ui flow_ui;
    GString *cmd_str = g_string_new(STR_FLOW);
    char *cli_string;

    g_string_append(cmd_str, sequence_analysis_get_name(analysis));
    cli_string = g_string_free(cmd_str, FALSE);

    flow_ui.group = REGISTER_STAT_GROUP_GENERIC;
    flow_ui.title = NULL;   /* construct this from the protocol info? */
    flow_ui.cli_string = cli_string;
    flow_ui.tap_init_cb = flow_init;
    flow_ui.nparams = 0;
    flow_ui.params = NULL;
    register_stat_tap_ui(&flow_ui, analysis);
    g_free(cli_string);
    return false;
}

void
register_tap_listener_flow(void)
{
    sequence_analysis_table_iterate_tables(flow_register, NULL);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
