/* stat_tap_ui.c
 * Routines to register UI information for stats
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>

#include <string.h>

#include <glib.h>

#include <epan/stat_tap_ui.h>

/* structure to keep track of what stats have registered command-line
   arguments.
 */
typedef struct _stat_cmd_arg {
    stat_tap_ui *ui;
    const char *cmd;
    void (*func)(const char *arg, void* userdata);
    void* userdata;
} stat_cmd_arg;

static wmem_list_t *stat_cmd_arg_list=NULL;

/* structure to keep track of what stats have been specified on the
   command line.
 */
typedef struct {
    stat_cmd_arg *sca;
    char *arg;
} stat_requested;
static GSList *stats_requested = NULL;

/* **********************************************************************
 * Function called from stat to register the stat's command-line argument
 * and initialization routine
 * ********************************************************************** */
static gint
search_duplicate(gconstpointer a, gconstpointer b)
{
    return strcmp(((const stat_cmd_arg *)a)->cmd, (const char *)b);
}

static gint
sort_by_name(gconstpointer a, gconstpointer b)
{
    return strcmp(((const stat_cmd_arg *)a)->cmd, ((const stat_cmd_arg *)b)->cmd);
}

void
register_stat_tap_ui(stat_tap_ui *ui, void *userdata)
{
    stat_cmd_arg *newsca;

    if (stat_cmd_arg_list == NULL)
        stat_cmd_arg_list = wmem_list_new(wmem_epan_scope());

    /* Key is already present */
    if (wmem_list_find_custom(stat_cmd_arg_list, ui->cli_string, search_duplicate))
        return;

    newsca = wmem_new(wmem_epan_scope(), stat_cmd_arg);
    newsca->cmd= wmem_strdup(wmem_epan_scope(), ui->cli_string);
    newsca->func=ui->tap_init_cb;
    newsca->userdata=userdata;

    wmem_list_insert_sorted(stat_cmd_arg_list, newsca, sort_by_name);
}

/* **********************************************************************
 * Function called for a stat command-line argument
 * ********************************************************************** */
gboolean
process_stat_cmd_arg(const char *optstr)
{
    wmem_list_frame_t *entry;
    stat_cmd_arg *sca;
    stat_requested *tr;
    char *stat_command = g_strdup(optstr);

    /* Renamed in Wireshark 3.0, backwards compatibility. */
    if (!strncmp(stat_command, "follow,ssl", strlen("follow,ssl"))) {
        memcpy(stat_command + 7, "tls", 3);
    }

    /* The strings "ipx" or "ipv6" must be tested before "ip" to select the
      right tap so the sorting does matter.  And it's also why the list is
      walked backwards */
    for (entry = wmem_list_tail(stat_cmd_arg_list); entry; entry = wmem_list_frame_prev(entry)) {
        sca = (stat_cmd_arg*)wmem_list_frame_data(entry);
        if (!strncmp(sca->cmd, stat_command, strlen(sca->cmd))) {
            tr=(stat_requested *)g_malloc(sizeof (stat_requested));
            tr->sca = sca;
            tr->arg = stat_command;
            stats_requested = g_slist_append(stats_requested, tr);
            return TRUE;
        }
    }
    g_free(stat_command);
    return FALSE;
}

/* **********************************************************************
 * Function to list all possible tap command-line arguments
 * ********************************************************************** */
static void
list_stat_cmd_args_func(gpointer data, gpointer userdata _U_)
{
    fprintf(stderr,"     %s\n", ((stat_cmd_arg*)data)->cmd);
}

void
list_stat_cmd_args(void)
{
    wmem_list_foreach(stat_cmd_arg_list, list_stat_cmd_args_func, NULL);
}

/* **********************************************************************
 * Function to process stats requested with command-line arguments
 * ********************************************************************** */
void
start_requested_stats(void)
{
    stat_requested *sr;

    while(stats_requested){
        sr=(stat_requested *)stats_requested->data;
        (*sr->sca->func)(sr->arg,sr->sca->userdata);
        stats_requested=g_slist_remove(stats_requested, sr);
        g_free(sr->arg);
        g_free(sr);
    }
}

static wmem_tree_t *registered_stat_tables = NULL;

void register_stat_tap_table_ui(stat_tap_table_ui *ui)
{
    if (registered_stat_tables == NULL)
        registered_stat_tables = wmem_tree_new(wmem_epan_scope());

    wmem_tree_insert_string(registered_stat_tables, ui->cli_string, ui, 0);
}

stat_tap_table_ui *stat_tap_by_name(const char *name)
{
    return (stat_tap_table_ui *) wmem_tree_lookup_string(registered_stat_tables, name, 0);
}

void stat_tap_iterate_tables(wmem_foreach_func func, gpointer user_data)
{
    wmem_tree_foreach(registered_stat_tables, func, user_data);
}

void stat_tap_get_filter(stat_tap_table_ui* new_stat, const char *opt_arg, const char **filter, char** err)
{
    guint len = (guint) strlen(new_stat->cli_string);
    *filter=NULL;
    *err=NULL;

    if (!strncmp(opt_arg, new_stat->cli_string, len))
    {
        if (opt_arg[len] == ',')
        {
           *filter = opt_arg + len+1;
        }
    }

    if (new_stat->stat_filter_check_cb)
        new_stat->stat_filter_check_cb(opt_arg, filter, err);
}

stat_tap_table* stat_tap_init_table(const char *name, int num_fields, int num_elements,
                const char *filter_string)
{
    stat_tap_table* new_table = g_new0(stat_tap_table, 1);

    new_table->title = name;
    new_table->num_elements = num_elements;
    new_table->num_fields = num_fields;
    new_table->filter_string = filter_string;
    new_table->elements = g_new0(stat_tap_table_item_type*, num_elements);

    return new_table;
}

void stat_tap_add_table(stat_tap_table_ui* new_stat, stat_tap_table* table)
{
    if (new_stat->tables == NULL)
        new_stat->tables = g_array_new(FALSE, TRUE, sizeof(stat_tap_table*));

    g_array_insert_val(new_stat->tables, new_stat->tables->len, table);
}

void stat_tap_init_table_row(stat_tap_table *stat_table, guint table_index, guint num_fields, const stat_tap_table_item_type* fields)
{
    /* we have discovered a new procedure. Extend the table accordingly */
    if(table_index>=stat_table->num_elements){
        guint old_num_elements=stat_table->num_elements;
        guint i;

        stat_table->num_elements=table_index+1;
        stat_table->elements = (stat_tap_table_item_type**)g_realloc(stat_table->elements, sizeof(stat_tap_table_item_type*)*(stat_table->num_elements));
        for(i=old_num_elements;i<stat_table->num_elements;i++){
            stat_table->elements[i] = g_new0(stat_tap_table_item_type, stat_table->num_fields);
        }
    }
    memcpy(stat_table->elements[table_index], fields, num_fields*sizeof(stat_tap_table_item_type));

}

stat_tap_table_item_type* stat_tap_get_field_data(const stat_tap_table *stat_table, guint table_index, guint field_index)
{
    stat_tap_table_item_type* field_value;
    g_assert(table_index < stat_table->num_elements);

    field_value = stat_table->elements[table_index];

    g_assert(field_index < stat_table->num_fields);

    return &field_value[field_index];
}

void stat_tap_set_field_data(stat_tap_table *stat_table, guint table_index, guint field_index, stat_tap_table_item_type* field_data)
{
    stat_tap_table_item_type* field_value;
    g_assert(table_index < stat_table->num_elements);

    field_value = stat_table->elements[table_index];

    g_assert(field_index < stat_table->num_fields);

    field_value[field_index] = *field_data;
}

void reset_stat_table(stat_tap_table_ui* new_stat)
{
    guint i = 0;
    stat_tap_table *stat_table;

    for (i = 0; i < new_stat->tables->len; i++)
    {
        stat_table = g_array_index(new_stat->tables, stat_tap_table*, i);

        if (new_stat->stat_tap_reset_table_cb)
            new_stat->stat_tap_reset_table_cb(stat_table);
    }
}

void free_stat_tables(stat_tap_table_ui* new_stat)
{
    guint i = 0, element, field_index;
    stat_tap_table *stat_table;
    stat_tap_table_item_type* field_data;

    for (i = 0; i < new_stat->tables->len; i++)
    {
        stat_table = g_array_index(new_stat->tables, stat_tap_table*, i);

        for (element = 0; element < stat_table->num_elements; element++)
        {
            for (field_index = 0; field_index < stat_table->num_fields; field_index++)
            {
                field_data = stat_tap_get_field_data(stat_table, element, field_index);
                /* Give dissector a crack at it */
                /* XXX Should this be per-row instead? */
                if (new_stat->stat_tap_free_table_item_cb)
                    new_stat->stat_tap_free_table_item_cb(stat_table, element, field_index, field_data);
            }
            g_free(stat_table->elements[element]);
        }
        g_free(stat_table->elements);
        g_free(stat_table);
    }
    g_array_set_size(new_stat->tables, 0);
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
