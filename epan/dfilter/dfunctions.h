/** @file
 *
 * Wireshark - Network traffic analyzer
 *
 * Copyright 2006 Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DFUNCTIONS_H
#define DFUNCTIONS_H

#include <glib.h>
#include <epan/ftypes/ftypes.h>
#include <epan/dfilter/syntax-tree.h>
#include <epan/dfilter/dfilter-int.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Functions take any number of arguments and return 1. */

#define dfunc_fail(dfw, node, ...) \
    do { \
        ws_noisy("Semantic check failed here."); \
        dfilter_fail_throw(dfw, DF_ERROR_GENERIC, stnode_location(node), __VA_ARGS__); \
    } while (0)

/* The run-time logic of the dfilter function */
typedef bool (*DFFuncType)(GSList *stack, uint32_t arg_count, df_cell_t *retval);

/* The semantic check for the dfilter function */
typedef ftenum_t (*DFSemCheckType)(dfwork_t *dfw, const char *func_name, ftenum_t lhs_ftype,
                                GSList *param_list, df_loc_t func_loc);

/**
 * @brief Defines a display filter function, holding its name, implementation, arity, and type information.
 */
typedef struct {
    const char*    name;                     /**< The function name as used in display filter expressions. */
    DFFuncType     function;                 /**< Pointer to the function implementation. */
    unsigned       min_nargs;                /**< Minimum number of arguments the function accepts. */
    unsigned       max_nargs;                /**< Maximum number of arguments the function accepts; 0 means no upper limit. */
    ftenum_t       return_ftype;             /**< Return type of the function; FT_NONE if the return type matches the argument type. */
    DFSemCheckType semcheck_param_function;  /**< Semantic check callback used to validate the function's parameters at compile time. */
} df_func_def_t;

/** @brief Check semantic correctness of a parameter in a display filter function.
 *
 * @param dfw The current working state of the display filter evaluation.
 * @param func_name The name of the function being checked.
 * @param logical_ftype The expected type of the parameter.
 * @param param The parameter node to check.
 * @param func_loc Location information for error reporting.
 * @return True if the parameter is semantically correct, False otherwise.
 */
WS_DLL_PUBLIC
ftenum_t
df_semcheck_param(dfwork_t *dfw, const char *func_name, ftenum_t logical_ftype,
                            stnode_t *param, df_loc_t func_loc);

/**
 * @brief Initialize the display filter functions.
 *
 * This function initializes the display filter functions by creating a hash table
 * for registered functions and registering built-in functions.
 */
void df_func_init(void);

/**
 * @brief Register a display filter function.
 *
 * Registers a new display filter function definition with the system.
 *
 * @param func Pointer to the df_func_def_t structure containing the function definition.
 * @return Returns false if the function name already exists.
 */
WS_DLL_PUBLIC
bool df_func_register(df_func_def_t *func);

/**
 * @brief Deregisters a display filter function.
 *
 * @param func Pointer to the function definition record to deregister.
 * @return true if the function was successfully deregistered, false otherwise.
 */
WS_DLL_PUBLIC
bool df_func_deregister(df_func_def_t *func);

/**
 * @brief Lookup a display filter function definition record by name.
 *
 * @param name The name of the function to lookup.
 * @return A pointer to the function definition record if found, otherwise NULL.
 */
WS_DLL_PUBLIC
df_func_def_t* df_func_lookup(const char *name);

/**
 * @brief Returns a pointer to an array of registered display filter function names.
 *
 * @note You must call g_ptr_array_unref() when you are done.
 *
 * @return A GPtrArray containing the names of all registered display filter functions.
 */
WS_DLL_PUBLIC
GPtrArray *df_func_name_list(void);

/**
 * @brief Cleans up resources used by display filter functions.
 *
 * This function destroys the hash table containing registered functions and
 * unrefs the array of registered names, freeing up associated memory.
 */
void df_func_cleanup(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
