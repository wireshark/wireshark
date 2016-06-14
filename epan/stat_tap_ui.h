/* stat_tap_ui.h
 * Declarations of routines to register UI information for stats
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

#ifndef __STAT_TAP_UI_H__
#define __STAT_TAP_UI_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Parameters for taps.
 */

#include <epan/params.h>
#include <epan/stat_groups.h>
#include <epan/packet_info.h>
#include <epan/tap.h>

typedef enum {
    PARAM_UINT,   /* Unused? */
    PARAM_STRING, /* Unused? */
    PARAM_ENUM,   /* SCSI SRT */
    PARAM_UUID,   /* DCE-RPC. Unused? */
    PARAM_FILTER
} param_type;

typedef struct _tap_param {
    param_type        type;      /* type of parameter */
    const char       *name;      /* name to use in error messages */
    const char       *title;     /* title to use in GUI widgets */
    const enum_val_t *enum_vals; /* values for PARAM_ENUM */
    gboolean          optional;  /* TRUE if the parameter is optional */
} tap_param;

/*
 * UI information for a tap.
 */
typedef void (* stat_tap_init_cb)(const char *, void*);
typedef struct _stat_tap_ui {
    register_stat_group_t  group;      /* group to which statistic belongs */
    const char            *title;      /* title of statistic */
    const char            *cli_string; /* initial part of the "-z" argument for statistic */
    stat_tap_init_cb tap_init_cb;      /* callback to init function of the tap */
    size_t                 nparams;    /* number of parameters */
    tap_param             *params;     /* pointer to table of parameter info */
} stat_tap_ui;

typedef enum {
    TABLE_ITEM_NONE = 0,
    TABLE_ITEM_UINT,
    TABLE_ITEM_INT,
    TABLE_ITEM_STRING,
    TABLE_ITEM_FLOAT,
    TABLE_ITEM_ENUM
} stat_tap_table_item_enum;

typedef struct _stat_tap_table_item_type
{
    stat_tap_table_item_enum type;
    union
    {
        guint uint_value;
        gint  int_value;
        const char* string_value;
        double float_value;
        gint enum_value;
    } value;
    /* Scratch space for the dissector. Alternatively we could also add support
     * for hidden columns. */
    union
    {
        guint uint_value;
        gint  int_value;
        const char* string_value;
        double float_value;
        gint enum_value;
        void* ptr_value;
    } user_data;
} stat_tap_table_item_type;

/* Possible alignments */
typedef enum {
    TAP_ALIGN_LEFT = 0,
    TAP_ALIGN_RIGHT
} tap_alignment_type;

typedef struct _stat_tap_table_item
{
    stat_tap_table_item_enum type;
    tap_alignment_type align;
    const char* column_name;
    const char* field_format; /* printf style formating of field. Currently unused? */

} stat_tap_table_item;


/* Description of a UI table */
typedef struct _stat_tap_table
{
    const char* title;
    const char *filter_string;        /**< append procedure number (%d) to this string to create a display filter */
    guint num_fields;
    guint num_elements;
    stat_tap_table_item_type **elements;

} stat_tap_table;

typedef void (*new_stat_tap_gui_init_cb)(stat_tap_table* stat_table, void* gui_data); /* GTK+ only? */
typedef void (*new_stat_tap_gui_reset_cb)(stat_tap_table* stat_table, void* gui_data); /* GTK+ only? */
typedef void (*new_stat_tap_gui_free_cb)(stat_tap_table* stat_table, void* gui_data); /* GTK+ only? */

/*
 * UI information for a tap with a table-based UI.
 */
typedef struct _stat_tap_table_ui {
    register_stat_group_t  group;      /* group to which statistic belongs */
    const char            *title;      /* title of statistic */
    const char            *tap_name;
    const char            *cli_string; /* initial part of the "-z" argument for statistic */
    void (* stat_tap_init_cb)(struct _stat_tap_table_ui* new_stat, new_stat_tap_gui_init_cb gui_callback, void* gui_data);
    tap_packet_cb packet_func;
    void (* stat_tap_reset_table_cb)(stat_tap_table* table);
    void (* stat_tap_free_table_item_cb)(stat_tap_table* table, guint row, guint column, stat_tap_table_item_type* field_data);
    void (* stat_filter_check_cb)(const char *opt_arg, const char **filter, char** err); /* Dissector chance to reject filter */
    size_t                 nfields;    /* number of fields */
    stat_tap_table_item*   fields;
    size_t                 nparams;    /* number of parameters */
    tap_param             *params;     /* pointer to table of parameter info */
    GArray                *tables;     /* An array of stat_tap_table* */
    guint                  refcount;   /* a reference count for deallocation */
} stat_tap_table_ui;


/** tap data
 */
typedef struct _new_stat_data_t {
    stat_tap_table_ui *stat_tap_data;
    void        *user_data;       /**< "GUI" specifics (if necessary) */
} new_stat_data_t;


/** Register UI information for a tap.
 *
 * @param ui UI information for the tap.
 * @param userdata Additional data for the init routine.
 */
WS_DLL_PUBLIC void register_stat_tap_ui(stat_tap_ui *ui, void *userdata);

WS_DLL_PUBLIC void register_stat_tap_table_ui(stat_tap_table_ui *ui);
WS_DLL_PUBLIC void new_stat_tap_iterate_tables(GFunc func, gpointer user_data);
WS_DLL_PUBLIC void new_stat_tap_get_filter(stat_tap_table_ui* new_stat, const char *opt_arg, const char **filter, char** err);
WS_DLL_PUBLIC stat_tap_table* new_stat_tap_init_table(const char *name, int num_fields, int num_elements,
                const char *filter_string, new_stat_tap_gui_init_cb gui_callback, void* gui_data);
WS_DLL_PUBLIC void new_stat_tap_add_table(stat_tap_table_ui* new_stat, stat_tap_table* table);

WS_DLL_PUBLIC void new_stat_tap_init_table_row(stat_tap_table *stat_table, guint table_index, guint num_fields, const stat_tap_table_item_type* fields);
WS_DLL_PUBLIC stat_tap_table_item_type* new_stat_tap_get_field_data(const stat_tap_table *stat_table, guint table_index, guint field_index);
WS_DLL_PUBLIC void new_stat_tap_set_field_data(stat_tap_table *stat_table, guint table_index, guint field_index, stat_tap_table_item_type* field_data);
WS_DLL_PUBLIC void reset_stat_table(stat_tap_table_ui* new_stat, new_stat_tap_gui_reset_cb gui_callback, void *callback_data);

/** Free all of the tables associated with a stat_tap_table_ui.
 *
 * Frees data created by stat_tap_ui.stat_tap_init_cb.
 * stat_tap_table_ui.stat_tap_free_table_item_cb is called for each index in each
 * row.
 *
 * @param new_stat Parent stat_tap_table_ui struct, provided by the dissector.
 * @param gui_callback Per-table callback, run before rows are removed.
 * Provided by the UI.
 * @param callback_data Data for the per-table callback.
 */
WS_DLL_PUBLIC void free_stat_tables(stat_tap_table_ui* new_stat, new_stat_tap_gui_free_cb gui_callback, void *callback_data);


WS_DLL_PUBLIC gboolean process_stat_cmd_arg(char *optstr);

WS_DLL_PUBLIC void list_stat_cmd_args(void);

WS_DLL_PUBLIC void start_requested_stats(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

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
