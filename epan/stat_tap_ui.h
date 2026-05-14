/** @file
 * Declarations of routines to register UI information for stats
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
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

/** Initialize statistics tap system.
 *
 * @brief Initializes the statistics tap system, setting up necessary data structures.
 */
extern void stat_tap_init(void);

/** Register UI information for a tap.
 *
 * @param ui UI information for the tap.
 * @param userdata Additional data for the init routine.
 */
WS_DLL_PUBLIC void register_stat_tap_ui(stat_tap_ui *ui, void *userdata);

/**
 * @brief Register a table-based statistics tap UI descriptor.
 * @param ui The @c stat_tap_table_ui descriptor to register. The caller
 *           retains ownership; the descriptor must remain valid for the
 *           lifetime of the session.
 */
WS_DLL_PUBLIC void register_stat_tap_table_ui(stat_tap_table_ui *ui);

/**
 * @brief Iterate over all registered table-based statistics tap UIs.
 *
 * @param func      The callback to invoke for each registered descriptor.
 *                  Signature: @c bool func(const void *key, void *value, void *user_data)
 * @param user_data Caller-supplied context pointer passed through to @p func.
 */
WS_DLL_PUBLIC void stat_tap_iterate_tables(wmem_foreach_func func, void *user_data);

/**
 * @brief Parse the display filter from a statistics option argument string.
 *
 * @param new_stat The @c stat_tap_table_ui descriptor for the statistic being
 *                 initialised.
 * @param opt_arg  The raw option argument string (e.g. @c "http,tree,ip.src==1.2.3.4").
 * @param filter   Receives a pointer to the filter substring within @p opt_arg,
 *                 or NULL if no filter was supplied. The pointer aliases
 *                 @p opt_arg and must not be freed separately.
 * @param err      Receives a newly allocated error string if @p opt_arg cannot
 *                 be parsed, or NULL on success. The caller must free any
 *                 non-NULL value with @c g_free().
 */
WS_DLL_PUBLIC void stat_tap_get_filter(stat_tap_table_ui *new_stat, const char *opt_arg,
                                       const char **filter, char **err);

/**
 * @brief Allocate and initialise a @c stat_tap_table.
 *
 * @param name          Human-readable title shown as the table heading.
 * @param num_fields    Number of columns (field descriptors) in the table.
 * @param num_elements  Initial number of rows to pre-allocate.
 * @param filter_string Base display filter prefix to which a procedure
 *                      number can be appended (e.g. @c "rpc.procedure=="),
 *                      or NULL if per-row filters are not needed.
 * @return A newly allocated and initialised @c stat_tap_table. Freed by
 *         the statistics framework when the table is destroyed.
 */
WS_DLL_PUBLIC stat_tap_table *stat_tap_init_table(const char *name, int num_fields,
                                                   int num_elements,
                                                   const char *filter_string);

/**
 * @brief Adds a new table to the statistics tap.
 *
 * @param new_stat Pointer to the statistics tap UI structure.
 * @param table Pointer to the statistics tap table structure.
 */
WS_DLL_PUBLIC void stat_tap_add_table(stat_tap_table_ui* new_stat, stat_tap_table* table);

/**
 * @brief Finds a table by its UI structure and name.
 *
 * @param ui The UI structure containing the tables.
 * @param name The name of the table to find.
 * @return stat_tap_table* Pointer to the found table, or NULL if not found.
 */
WS_DLL_PUBLIC stat_tap_table *stat_tap_find_table(stat_tap_table_ui *ui, const char *name);

/**
 * @brief Initialise a row in a stat_tap_table with field values.
 *
 * @param stat_table  The table whose row is being initialised.
 * @param table_index Zero-based row index within @p stat_table.
 * @param num_fields  Number of column values provided in @p fields. Must
 *                    not exceed the @p num_fields value passed to
 *                    stat_tap_init_table().
 * @param fields      Array of @p num_fields @c stat_tap_table_item_type
 *                    values to copy into the row. The caller retains
 *                    ownership of the array; values are copied into the
 *                    table's internal storage.
 */
WS_DLL_PUBLIC void stat_tap_init_table_row(stat_tap_table *stat_table,
                                           unsigned table_index,
                                           unsigned num_fields,
                                           const stat_tap_table_item_type *fields);

/**
 * @brief Return a pointer to the field value at a given row and column.
 *
 * @param stat_table  The table to query.
 * @param table_index Zero-based row index within @p stat_table.
 * @param field_index Zero-based column index within the row.
 * @return A pointer to the live @c stat_tap_table_item_type for that cell,
 *         or NULL if @p table_index or @p field_index is out of range.
 *         The pointer is valid until the table is freed or reset.
 */
WS_DLL_PUBLIC stat_tap_table_item_type *stat_tap_get_field_data(
                                           const stat_tap_table *stat_table,
                                           unsigned table_index,
                                           unsigned field_index);

/**
 * @brief Set field data for a specific table and field index.
 *
 * @param stat_table Pointer to the stat_tap_table structure.
 * @param table_index Index of the table within the stat_tap_table.
 * @param field_index Index of the field within the specified table.
 * @param field_data Pointer to the new field data to be set.
 */
WS_DLL_PUBLIC void stat_tap_set_field_data(stat_tap_table *stat_table, unsigned table_index, unsigned field_index, stat_tap_table_item_type* field_data);

/**
 * @brief Reset all tables belonging to a statistics tap UI to their initial state.
 * @param new_stat The @c stat_tap_table_ui whose tables should be reset.
 */
WS_DLL_PUBLIC void reset_stat_table(stat_tap_table_ui *new_stat);


/**
 * @brief Look up a registered table-based statistics tap UI by its option name.
 * @param name The @c -z option name to search for (e.g. @c "http,tree").
 * @return The matching @c stat_tap_table_ui descriptor, or NULL if no
 *         registered statistic has that name.
 */
WS_DLL_PUBLIC stat_tap_table_ui *stat_tap_by_name(const char *name);

/**
 * @brief Free all of the tables associated with a stat_tap_table_ui.
 *
 * Frees data created by stat_tap_ui.stat_tap_init_cb.
 * stat_tap_table_ui.stat_tap_free_table_item_cb is called for each index in each
 * row.
 *
 * @param new_stat Parent stat_tap_table_ui struct, provided by the dissector.
 */
WS_DLL_PUBLIC void free_stat_tables(stat_tap_table_ui* new_stat);

/**
 * @brief Processes a command argument for statistics.
 *
 * @param optstr The option string to process.
 * @return true if the command is recognized and processed, false otherwise.
 */
WS_DLL_PUBLIC bool process_stat_cmd_arg(const char *optstr);

/**
 * @brief List command-line arguments for requested statistics.
 *
 * This function iterates through a list of command-line arguments and processes them to request specific statistics.
 */
WS_DLL_PUBLIC void list_stat_cmd_args(void);

/**
 * @brief Start requested statistics.
 *
 * This function processes and initializes all registered statistics taps that have been requested.
 *
 * @return true if all statistics taps were successfully initialized, false otherwise.
 */
WS_DLL_PUBLIC bool start_requested_stats(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

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
