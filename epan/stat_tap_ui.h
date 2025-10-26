/** @file
 * Declarations of routines to register UI information for stats
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __STAT_TAP_UI_H__
#define __STAT_TAP_UI_H__

#include "ws_symbol_export.h"

#include <epan/params.h>
#include <epan/stat_groups.h>
#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/wmem_scopes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Parameters for taps.
 */

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
    bool              optional;  /* true if the parameter is optional */
} tap_param;

/*
 * UI information for a tap.
 */
typedef bool (* stat_tap_init_cb)(const char *, void*);
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

/**
 * @brief Represents a single item in a statistics tap table.
 *
 * This structure holds a typed value used in statistical reporting, such as counters,
 * labels, or computed metrics. It also includes a scratchpad area (`user_data`) for
 * dissector-specific temporary storage or extended metadata.
 */
typedef struct _stat_tap_table_item_type
{
    stat_tap_table_item_enum type; /**< Type of the item (e.g., integer, float, string). */

    /**
     * @brief The primary value of the item.
     *
     * The actual field used depends on the `type` member.
     */
    union {
        unsigned uint_value;     /**< Unsigned integer value. */
        int int_value;           /**< Signed integer value. */
        const char* string_value;/**< String value. */
        double float_value;      /**< Floating-point value. */
        int enum_value;          /**< Enumerated value. */
    } value;

    /**
     * @brief Scratch space for dissector use.
     *
     * This union provides temporary storage for dissectors to associate
     * auxiliary data with the item. It can also be used to support hidden columns.
     */
    union {
        unsigned uint_value;     /**< Unsigned integer scratch value. */
        int int_value;           /**< Signed integer scratch value. */
        const char* string_value;/**< String scratch value. */
        double float_value;      /**< Floating-point scratch value. */
        int enum_value;          /**< Enumerated scratch value. */
        void* ptr_value;         /**< Generic pointer for custom data. */
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
    const char* field_format; /* printf style formatting of field. */

} stat_tap_table_item;


/* Description of a UI table */
typedef struct _stat_tap_table
{
    const char* title;
    const char *filter_string;        /**< append procedure number (%d) to this string to create a display filter */
    unsigned num_fields;
    unsigned num_elements;
    stat_tap_table_item_type **elements;

} stat_tap_table;

/*
 * UI information for a tap with a table-based UI.
 */
typedef struct _stat_tap_table_ui {
    register_stat_group_t  group;      /* group to which statistic belongs */
    const char            *title;      /* title of statistic */
    const char            *tap_name;
    const char            *cli_string; /* initial part of the "-z" argument for statistic */
    void (* stat_tap_init_cb)(struct _stat_tap_table_ui* new_stat);
    tap_packet_cb packet_func;
    void (* stat_tap_reset_table_cb)(stat_tap_table* table);
    void (* stat_tap_free_table_item_cb)(stat_tap_table* table, unsigned row, unsigned column, stat_tap_table_item_type* field_data);
    void (* stat_filter_check_cb)(const char *opt_arg, const char **filter, char** err); /* Dissector chance to reject filter */
    size_t                 nfields;    /* number of fields */
    stat_tap_table_item*   fields;
    size_t                 nparams;    /* number of parameters */
    tap_param             *params;     /* pointer to table of parameter info */
    GArray                *tables;     /* An array of stat_tap_table* */
    unsigned               refcount;   /* a reference count for deallocation */
} stat_tap_table_ui;


/** tap data
 */
typedef struct _stat_data_t {
    stat_tap_table_ui *stat_tap_data;
    void        *user_data;       /**< "GUI" specifics (if necessary) */
} stat_data_t;


/** Register UI information for a tap.
 *
 * @param ui UI information for the tap.
 * @param userdata Additional data for the init routine.
 */
WS_DLL_PUBLIC void register_stat_tap_ui(stat_tap_ui *ui, void *userdata);

WS_DLL_PUBLIC void register_stat_tap_table_ui(stat_tap_table_ui *ui);
WS_DLL_PUBLIC void stat_tap_iterate_tables(wmem_foreach_func func, void *user_data);
WS_DLL_PUBLIC void stat_tap_get_filter(stat_tap_table_ui* new_stat, const char *opt_arg, const char **filter, char** err);
WS_DLL_PUBLIC stat_tap_table* stat_tap_init_table(const char *name, int num_fields, int num_elements,
                const char *filter_string);
WS_DLL_PUBLIC void stat_tap_add_table(stat_tap_table_ui* new_stat, stat_tap_table* table);
WS_DLL_PUBLIC stat_tap_table *stat_tap_find_table(stat_tap_table_ui *ui, const char *name);
WS_DLL_PUBLIC void stat_tap_init_table_row(stat_tap_table *stat_table, unsigned table_index, unsigned num_fields, const stat_tap_table_item_type* fields);
WS_DLL_PUBLIC stat_tap_table_item_type* stat_tap_get_field_data(const stat_tap_table *stat_table, unsigned table_index, unsigned field_index);
WS_DLL_PUBLIC void stat_tap_set_field_data(stat_tap_table *stat_table, unsigned table_index, unsigned field_index, stat_tap_table_item_type* field_data);
WS_DLL_PUBLIC void reset_stat_table(stat_tap_table_ui* new_stat);

WS_DLL_PUBLIC stat_tap_table_ui *stat_tap_by_name(const char *name);

/** Free all of the tables associated with a stat_tap_table_ui.
 *
 * Frees data created by stat_tap_ui.stat_tap_init_cb.
 * stat_tap_table_ui.stat_tap_free_table_item_cb is called for each index in each
 * row.
 *
 * @param new_stat Parent stat_tap_table_ui struct, provided by the dissector.
 */
WS_DLL_PUBLIC void free_stat_tables(stat_tap_table_ui* new_stat);


WS_DLL_PUBLIC bool process_stat_cmd_arg(const char *optstr);

WS_DLL_PUBLIC void list_stat_cmd_args(void);

WS_DLL_PUBLIC bool start_requested_stats(void);

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
