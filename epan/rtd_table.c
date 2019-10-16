/* rtd_table.c
 * Helper routines common to all RTD taps.
 * Based on srt_table.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include "proto.h"
#include "packet_info.h"
#include "rtd_table.h"

struct register_rtd {
    int proto_id;              /* protocol id (0-indexed) */
    const char* tap_listen_str;      /* string used in register_tap_listener (NULL to use protocol name) */
    tap_packet_cb rtd_func;    /* function to be called for new incoming packets for RTD */
    guint num_tables;
    guint num_timestats;
    const value_string* vs_type;
    rtd_filter_check_cb filter_check;
};

int get_rtd_proto_id(register_rtd_t* rtd)
{
    if (!rtd) {
        return -1;
    }
    return rtd->proto_id;
}

const char* get_rtd_tap_listener_name(register_rtd_t* rtd)
{
    return rtd->tap_listen_str;
}

tap_packet_cb get_rtd_packet_func(register_rtd_t* rtd)
{
    return rtd->rtd_func;
}

guint get_rtd_num_tables(register_rtd_t* rtd) {
    return rtd->num_tables;
}

const value_string* get_rtd_value_string(register_rtd_t* rtd)
{
    return rtd->vs_type;
}

static wmem_tree_t *registered_rtd_tables = NULL;

void
register_rtd_table(const int proto_id, const char* tap_listener, guint num_tables, guint num_timestats, const value_string* vs_type,
                   tap_packet_cb rtd_packet_func, rtd_filter_check_cb filter_check_cb)
{
    register_rtd_t *table;
    DISSECTOR_ASSERT(rtd_packet_func);

    table = wmem_new(wmem_epan_scope(), register_rtd_t);

    table->proto_id      = proto_id;
    if (tap_listener != NULL)
        table->tap_listen_str = tap_listener;
    else
        table->tap_listen_str = proto_get_protocol_filter_name(proto_id);
    table->rtd_func      = rtd_packet_func;
    table->num_tables = num_tables;
    table->num_timestats = num_timestats;
    table->vs_type = vs_type;
    table->filter_check = filter_check_cb;

    if (registered_rtd_tables == NULL)
        registered_rtd_tables = wmem_tree_new(wmem_epan_scope());

    wmem_tree_insert_string(registered_rtd_tables, proto_get_protocol_filter_name(proto_id), table, 0);
}

void free_rtd_table(rtd_stat_table* table)
{
    guint i;

    for (i = 0; i < table->num_rtds; i++)
    {
        g_free(table->time_stats[i].rtd);
    }
    g_free(table->time_stats);
    table->time_stats = NULL;
    table->num_rtds = 0;
}

void reset_rtd_table(rtd_stat_table* table)
{
    guint i = 0;

    for (i = 0; i < table->num_rtds; i++)
        memset(table->time_stats[i].rtd, 0, sizeof(timestat_t)*table->time_stats[i].num_timestat);
}

register_rtd_t* get_rtd_table_by_name(const char* name)
{
    return (register_rtd_t*)wmem_tree_lookup_string(registered_rtd_tables, name, 0);
}

gchar* rtd_table_get_tap_string(register_rtd_t* rtd)
{
    GString *cmd_str = g_string_new(proto_get_protocol_filter_name(rtd->proto_id));
    g_string_append(cmd_str, ",rtd");
    return g_string_free(cmd_str, FALSE);
}

void rtd_table_get_filter(register_rtd_t* rtd, const char *opt_arg, const char **filter, char** err)
{
    gchar* cmd_str = rtd_table_get_tap_string(rtd);
    guint len = (guint) strlen(cmd_str);
    *filter=NULL;
    *err=NULL;

    if (!strncmp(opt_arg, cmd_str, len))
    {
        if (opt_arg[len] == ',')
        {
           *filter = opt_arg + len+1;
        }
	}

    if (rtd->filter_check)
        rtd->filter_check(opt_arg, filter, err);

    g_free(cmd_str);
}

void rtd_table_dissector_init(register_rtd_t* rtd, rtd_stat_table* table, rtd_gui_init_cb gui_callback, void *callback_data)
{
    guint i;

    table->num_rtds = rtd->num_tables;
    table->time_stats = g_new0(rtd_timestat, rtd->num_tables);

    for (i = 0; i < table->num_rtds; i++)
    {
        table->time_stats[i].num_timestat = rtd->num_timestats;
        table->time_stats[i].rtd = g_new0(timestat_t, rtd->num_timestats);
    }

    if (gui_callback)
        gui_callback(table, callback_data);
}

void rtd_table_iterate_tables(wmem_foreach_func func, gpointer user_data)
{
    wmem_tree_foreach(registered_rtd_tables, func, user_data);
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
