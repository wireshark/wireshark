/* srt_table.c
 * Helper routines common to all SRT taps.
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
#include "srt_table.h"
#include <wsutil/ws_assert.h>

struct register_srt {
    int proto_id;              /* protocol id (0-indexed) */
    const char* tap_listen_str;      /* string used in register_tap_listener (NULL to use protocol name) */
    int max_tables;            /* Maximum number of tables expected (used by GUI to determine how to display tables) */
    tap_packet_cb srt_func;    /* function to be called for new incoming packets for SRT */
    srt_init_cb srt_init;      /* function to create dissector SRT tables */
    srt_param_handler_cb param_cb; /* function to parse parameters of optional arguments of tap string */
    void* param_data;          /* Storage for tap parameter data */
};

int get_srt_proto_id(register_srt_t* srt)
{
    if (!srt) {
        return -1;
    }
    return srt->proto_id;
}

const char* get_srt_tap_listener_name(register_srt_t* srt)
{
    return srt->tap_listen_str;
}

int get_srt_max_tables(register_srt_t* srt)
{
    return srt->max_tables;
}

tap_packet_cb get_srt_packet_func(register_srt_t* srt)
{
    return srt->srt_func;
}

void set_srt_table_param_data(register_srt_t* srt, void* data)
{
    srt->param_data = data;
}

void* get_srt_table_param_data(register_srt_t* srt)
{
    return srt->param_data;
}

void
free_srt_table_data(srt_stat_table *rst)
{
    int i;

    for(i=0;i<rst->num_procs;i++){
        g_free(rst->procedures[i].procedure);
        rst->procedures[i].procedure=NULL;
    }
    g_free(rst->filter_string);
    rst->filter_string=NULL;
    g_free(rst->procedures);
    rst->procedures=NULL;
    rst->num_procs=0;
}

void free_srt_table(register_srt_t *srt, GArray* srt_array)
{
    unsigned i = 0;
    srt_stat_table *srt_table;

    for (i = 0; i < srt_array->len; i++)
    {
        srt_table = g_array_index(srt_array, srt_stat_table*, i);

        free_srt_table_data(srt_table);
        g_free(srt_table);
    }

    /* Clear the tables */
    g_array_set_size(srt_array, 0);

    /* Clear out any possible parameter data */
    g_free(srt->param_data);
    srt->param_data = NULL;
}

static void reset_srt_table_data(srt_stat_table *rst)
{
    int i;

    for(i=0;i<rst->num_procs;i++){
        time_stat_init(&rst->procedures[i].stats);
    }
}

void reset_srt_table(GArray* srt_array)
{
    unsigned i = 0;
    srt_stat_table *srt_table;

    for (i = 0; i < srt_array->len; i++)
    {
        srt_table = g_array_index(srt_array, srt_stat_table*, i);

        reset_srt_table_data(srt_table);
    }
}

static wmem_tree_t *registered_srt_tables;

register_srt_t* get_srt_table_by_name(const char* name)
{
    return (register_srt_t*)wmem_tree_lookup_string(registered_srt_tables, name, 0);
}

char* srt_table_get_tap_string(register_srt_t* srt)
{
    GString *cmd_str = g_string_new(proto_get_protocol_filter_name(srt->proto_id));
    g_string_append(cmd_str, ",srt");
    return g_string_free(cmd_str, FALSE);
}

void srt_table_get_filter(register_srt_t* srt, const char *opt_arg, const char **filter, char** err)
{
    char* cmd_str = srt_table_get_tap_string(srt);
    unsigned len = (uint32_t)strlen(cmd_str);
    unsigned pos = len;
    *filter=NULL;
    *err = NULL;

    if(!strncmp(opt_arg, cmd_str, len))
    {
        if (srt->param_cb != NULL)
        {
            pos = srt->param_cb(srt, opt_arg + len, err);
            if (*err != NULL)
                return;

            if (pos > 0)
                pos += len;
        }

        if (opt_arg[pos] == ',')
        {
           *filter = opt_arg + pos+1;
        }
    }

    g_free(cmd_str);
}

void srt_table_dissector_init(register_srt_t* srt, GArray* srt_array)
{
    srt->srt_init(srt, srt_array);
}

void
register_srt_table(const int proto_id, const char* tap_listener, int max_tables, tap_packet_cb srt_packet_func, srt_init_cb init_cb, srt_param_handler_cb param_cb)
{
    register_srt_t *table;
    DISSECTOR_ASSERT(init_cb);
    DISSECTOR_ASSERT(srt_packet_func);

    table = wmem_new(wmem_epan_scope(), register_srt_t);

    table->proto_id      = proto_id;
    if (tap_listener != NULL)
        table->tap_listen_str = tap_listener;
    else
        table->tap_listen_str = proto_get_protocol_filter_name(proto_id);
    table->max_tables    = max_tables;
    table->srt_func      = srt_packet_func;
    table->srt_init      = init_cb;
    table->param_cb      = param_cb;
    table->param_data    = NULL;

    if (registered_srt_tables == NULL)
        registered_srt_tables = wmem_tree_new(wmem_epan_scope());

    wmem_tree_insert_string(registered_srt_tables, proto_get_protocol_filter_name(proto_id), table, 0);
}

void srt_table_iterate_tables(wmem_foreach_func func, void *user_data)
{
    wmem_tree_foreach(registered_srt_tables, func, user_data);
}

srt_stat_table*
init_srt_table(const char *name, const char *short_name, GArray *srt_array, int num_procs, const char* proc_column_name,
                const char *filter_string, void* table_specific_data)
{
    int i;
    srt_stat_table *table = g_new(srt_stat_table, 1);

    table->filter_string = g_strdup(filter_string);

    table->name = name;
    table->short_name = short_name;
    table->proc_column_name = proc_column_name;
    table->num_procs=num_procs;
    table->procedures=g_new(srt_procedure_t, num_procs);
    for(i=0;i<num_procs;i++){
        time_stat_init(&table->procedures[i].stats);
        table->procedures[i].proc_index = 0;
        table->procedures[i].procedure = NULL;
    }

    g_array_insert_val(srt_array, srt_array->len, table);

    table->table_specific_data = table_specific_data;

    return table;
}

void
init_srt_table_row(srt_stat_table *rst, int indx, const char *procedure)
{
    /* we have discovered a new procedure. Extend the table accordingly */
    if(indx>=rst->num_procs){
        int old_num_procs=rst->num_procs;
        int i;

        rst->num_procs=indx+1;
        rst->procedures=(srt_procedure_t *)g_realloc(rst->procedures, sizeof(srt_procedure_t)*(rst->num_procs));
        for(i=old_num_procs;i<rst->num_procs;i++){
            time_stat_init(&rst->procedures[i].stats);
            rst->procedures[i].proc_index = i;
            rst->procedures[i].procedure=NULL;
        }
    }
    rst->procedures[indx].proc_index = indx;
    rst->procedures[indx].procedure=g_strdup(procedure);
}

void
add_srt_table_data(srt_stat_table *rst, int indx, const nstime_t *req_time, packet_info *pinfo)
{
    srt_procedure_t *rp;
    nstime_t t, delta;

    ws_assert(indx >= 0 && indx < rst->num_procs);
    rp=&rst->procedures[indx];

    /* calculate time delta between request and reply */
    t=pinfo->abs_ts;
    nstime_delta(&delta, &t, req_time);

    time_stat_update(&rp->stats, &delta, pinfo);
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
