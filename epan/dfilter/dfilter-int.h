/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DFILTER_INT_H
#define DFILTER_INT_H

#include "dfilter.h"
#include "syntax-tree.h"

#include <epan/proto.h>
#include <stdio.h>

/**
 * @brief Reference to a display filter field.
 */
typedef struct {
    const header_field_info *hfinfo; /**< Information about the header field. */
    fvalue_t *value;                 /**< The parsed value. */
    int proto_layer_num;             /**< The protocol layer number where the field was found. */
} df_reference_t;

/**
 * @brief A container for a pointer array, typically holding field references.
 */
typedef struct {
    GPtrArray *array; /**< Array of pointers. */
} df_cell_t;

/**
 * @brief Iterator for navigating through a df_cell_t array.
 */
typedef struct {
    GPtrArray *ptr; /**< Pointer to the array being iterated. */
    unsigned idx;   /**< Current index in the array. */
} df_cell_iter_t;

/**
 * @brief The compiled display filter object passed back to the user.
 */
struct epan_dfilter {
    GPtrArray   *insns;                  /**< Array of compiled instructions. */
    unsigned    num_registers;           /**< Number of registers used by the filter. */
    df_cell_t   *registers;              /**< Array of registers storing cell data. */
    int     *interesting_fields;         /**< Array of field IDs that are interesting to the filter. */
    int     num_interesting_fields;      /**< Count of interesting fields. */
    GPtrArray   *deprecated;             /**< Array of deprecated items used in the filter. */
    GSList      *warnings;               /**< List of warnings generated during compilation. */
    char        *expanded_text;          /**< The expanded filter text after macro expansion. */
    GHashTable  *references;             /**< Hash table mapping references. */
    GHashTable  *raw_references;         /**< Hash table mapping raw references. */
    char        *syntax_tree_str;        /**< String representation of the syntax tree. */
    /* Used to pass arguments to functions. List of Lists (list of registers). */
    GSList      *function_stack;         /**< Stack for function arguments. */
    GSList      *set_stack;              /**< Stack for set operations. */
    ftenum_t     ret_type;               /**< The return type of the display filter evaluation. */
};

/**
 * @brief State structure for display filter evaluation or processing.
 */
typedef struct {
    df_error_t *error; /**< Pointer to error information, if an error occurred. */
    /* more fields. */
} dfstate_t;

/**
 * @brief State for the first stage of display filter compilation (parsing).
 */
typedef struct {
    df_error_t  *error;     /**< Must be first struct field. Error state. */
    unsigned    flags;      /**< Parsing flags. */
    stnode_t    *st_root;   /**< The root node of the syntax tree. */
    GPtrArray   *deprecated;/**< Array of deprecated items encountered. */
    stnode_t    *lval;      /**< Left value in the current parsing context. */
    GString     *quoted_string; /**< Currently parsed quoted string. */
    bool        raw_string; /**< Flag indicating if the string is raw. */
    df_loc_t    string_loc; /**< Location of the string in the source text. */
    df_loc_t    location;   /**< Current parsing location. */
} dfsyntax_t;

/**
 * @brief State for the second stage of display filter compilation (semantic check and code generation).
 */
typedef struct {
    df_error_t  *error;     /**< Must be first struct field. Error state. */
    unsigned    flags;      /**< Compilation flags. */
    stnode_t    *st_root;   /**< The root node of the syntax tree. */
    unsigned    field_count;/**< Counter for fields processed. */
    GPtrArray   *insns;     /**< Array of generated instructions. */
    GHashTable  *loaded_fields; /**< Hash table of loaded fields. */
    GHashTable  *loaded_raw_fields; /**< Hash table of loaded raw fields. */
    GHashTable  *loaded_vs_fields;  /**< Hash table of loaded value string fields. */
    GHashTable  *interesting_fields;/**< Hash table of interesting fields. */
    int     next_insn_id;   /**< ID for the next instruction. */
    int     next_register;  /**< ID for the next register. */
    GPtrArray   *deprecated;/**< Array of deprecated items encountered. */
    GHashTable  *references; /**< hfinfo -> pointer to array of references. */
    GHashTable  *raw_references; /**< hfinfo -> pointer to array of references. */
    char        *expanded_text; /**< The expanded filter text. */
    wmem_allocator_t *dfw_scope; /**< Memory pool allocator for the dfwork_t context.
                                      Because we use exceptions for error handling sometimes
                                      cleaning up memory allocations is inconvenient. Memory
                                      allocated from this pool will be freed when the dfwork_t
                                      context is destroyed. */
    GSList      *warnings;   /**< List of warnings generated. */
    ftenum_t     ret_type;   /**< The determined return type of the filter expression. */
} dfwork_t;

/* Constructor/Destructor prototypes for Lemon Parser */

/**
 * @brief Allocator for the display filter.
 */
void *DfilterAlloc(void *(*)(size_t));

/**
 * @brief Deallocator for the display filter.
 */
void DfilterFree(void *, void (*)(void *));

/**
 * @brief Evaluates a token in the Lemon Parser.
 * @param yyp The parser instance.
 * @param yymajor The major token type.
 * @param yyminor The minor token data.
 */
void Dfilter(void *yyp, int yymajor, stnode_t *yyminor, dfsyntax_t *);

/* Return value for error in scanner. */
/**
 * @brief Indicates a scanning failure.
 * Not 0, as 0 means end-of-input.
 */
#define SCAN_FAILED -1

/**
 * @brief Report a failure in a display filter.
 *
 * This function is used to report an error in a display filter. If an error has already been reported, it will not overwrite the existing error.
 *
 * @param state Pointer to the state of the display filter.
 * @param code Error code indicating the type of error.
 * @param err_loc Location information where the error occurred.
 * @param format Format string for the error message.
 * @param args Variable arguments list for the format string.
 */
WS_DLL_PUBLIC
void
dfilter_vfail(void *state, int code, df_loc_t err_loc,
			const char *format, va_list args);

/**
 * @brief Handle a filter failure and log an error message.
 *
 * This function is called when a filter fails to compile or execute, and it logs an error message with the specified code and location.
 *
 * @param state The state of the dfilter.
 * @param code The error code associated with the failure.
 * @param err_loc The location in the filter where the error occurred.
 * @param format A format string for the error message.
 */
WS_DLL_PUBLIC
void
dfilter_fail(void *state, int code, df_loc_t err_loc,
			const char *format, ...) G_GNUC_PRINTF(4, 5);

/**
 * @brief Throw a filter failure with an error message.
 *
 * @param state The state of the filter.
 * @param code The error code.
 * @param err_loc The location of the error.
 * @param format The format string for the error message.
 */
WS_DLL_PUBLIC WS_NORETURN
void
dfilter_fail_throw(void *state, int code, df_loc_t err_loc,
			const char *format, ...) G_GNUC_PRINTF(4, 5);

/**
 * @brief Set the error location for a given dfwork_t object.
 *
 * @param dfw Pointer to the dfwork_t object.
 * @param err_loc The error location to set.
 */
void
dfw_set_error_location(dfwork_t *dfw, df_loc_t err_loc);

/**
 * @brief Adds a deprecated token to an array.
 *
 * @param deprecated Pointer to the GPtrArray where deprecated tokens are stored.
 * @param token The token to add, which will not be added if it already exists in the array.
 */
void
add_deprecated_token(GPtrArray *deprecated, const char *token);

/**
 * @brief Adds a compile warning to the given dfwork_t structure.
 *
 * @param dfw Pointer to the dfwork_t structure where the warning will be stored.
 * @param format Format string for the warning message, followed by variable arguments.
 */
void
add_compile_warning(dfwork_t *dfw, const char *format, ...);

/**
 * @brief Frees memory allocated for deprecated items.
 *
 * @param deprecated Pointer to the GPtrArray containing deprecated items.
 */
void
free_deprecated(GPtrArray *deprecated);

/**
 * @brief Writes a trace prompt to the specified file.
 *
 * @param TraceFILE Pointer to the file where the trace prompt will be written.
 * @param zTracePrompt The trace prompt string to write.
 */
void
DfilterTrace(FILE *TraceFILE, char *zTracePrompt);

/**
 * @brief Resolve an unparsed filter name to a header field info.
 *
 * @param name The name of the filter to resolve.
 * @param deprecated A pointer to a GPtrArray where deprecated tokens will be stored, or NULL if not needed.
 * @return header_field_info* The resolved header field info, or NULL if not found.
 */
header_field_info *
dfilter_resolve_unparsed(const char *name, GPtrArray *deprecated);

/**
 * @brief Creates a fvalue from a literal string.
 *
 * @param dfw The current working state of the display filter.
 * @param ftype The type of the field.
 * @param st The syntax tree node to be replaced with the fvalue.
 * @param allow_partial_value Whether partial values are allowed.
 * @param hfinfo_value_string Information about the value string.
 * @return true if the create syntax node has a (value) string type, false otherwise.
 */
bool
dfilter_fvalue_from_literal(dfwork_t *dfw, ftenum_t ftype, stnode_t *st,
		bool allow_partial_value, header_field_info *hfinfo_value_string);

/**
 * @brief Converts a string to a filter value.
 *
 * @param dfw The current working state of the dfilter.
 * @param ftype The type of the field.
 * @param st The node where the result will be stored.
 * @param hfinfo_value_string Information about the header field.
 */
bool
dfilter_fvalue_from_string(dfwork_t *dfw, ftenum_t ftype, stnode_t *st,
		header_field_info *hfinfo_value_string);

/**
 * @brief Create a new filter value from a character constant.
 *
 * @param dfw The current dfilter work context.
 * @param ftype The type of the field value.
 * @param st The node containing the data to be converted.
 */
void
dfilter_fvalue_from_charconst(dfwork_t *dfw, ftenum_t ftype, stnode_t *st);

/**
 * @brief Create an filter value from a number token.
 *
 * This function converts a number token into an fvalue based on its type and stores it in the dfwork_t structure.
 *
 * @param dfw Pointer to the dfwork_t structure where the fvalue will be stored.
 * @param ftype The desired data type for the fvalue (e.g., FT_INT64, FT_DOUBLE).
 * @param st Pointer to the stnode_t structure containing the number token.
 */
void
dfilter_fvalue_from_number(dfwork_t *dfw, ftenum_t ftype, stnode_t *st);

 /**
  * @brief Retrieves a string representation of a token.
  *
  * @param token The integer value of the token to convert.
  * @return A constant character pointer to the string representation of the token, or NULL if the token is invalid.
  */
const char *tokenstr(int token);

/**
 * @brief Creates a new reference for a field.
 *
 * @param finfo Pointer to the field information.
 * @param raw Flag indicating whether to use raw value.
 * @return df_reference_t* Pointer to the newly created reference.
 */
df_reference_t *
reference_new(const field_info *finfo, bool raw);

/**
 * @brief Frees a reference.
 *
 * @param ref The reference to be freed.
 */
void
reference_free(df_reference_t *ref);

/**
 * @brief Append a fvalue to a df_cell.
 *
 * @param rp Pointer to the df_cell where the fvalue will be appended.
 * @param fv Pointer to the fvalue to append.
 */
WS_DLL_PUBLIC
void
df_cell_append(df_cell_t *rp, fvalue_t *fv);

/**
 * @brief Get a reference to the array in a df_cell_t structure.
 *
 * @param rp Pointer to the df_cell_t structure.
 * @return A pointer to the referenced array, or NULL if the array is not initialized.
 */
WS_DLL_PUBLIC
GPtrArray *
df_cell_ref(df_cell_t *rp);

#define df_cell_ptr(rp) ((rp)->array)

/**
 * @brief Get the size of a df_cell_t.
 *
 * @param rp Pointer to the df_cell_t structure.
 * @return The number of elements in the array, or 0 if the array is NULL.
 */
WS_DLL_PUBLIC
size_t
df_cell_size(const df_cell_t *rp);


/**
 * @brief Retrieves an array of fvalue_t pointers from a df_cell_t.
 *
 * @param rp Pointer to the df_cell_t structure.
 * @return A pointer to an array of fvalue_t pointers, or NULL if the array is empty.
 */
WS_DLL_PUBLIC
fvalue_t **
df_cell_array(const df_cell_t *rp);

/**
 * @brief Checks if a df_cell_t is empty.
 *
 * @param rp Pointer to the df_cell_t structure to check.
 * @return true if the cell is empty, false otherwise.
 */
WS_DLL_PUBLIC
bool
df_cell_is_empty(const df_cell_t *rp);

/**
 * @brief Check if the given cell is null.
 *
 * @param rp Pointer to the df_cell_t structure to check.
 * @return true if the cell's array is NULL, false otherwise.
 */
WS_DLL_PUBLIC
bool
df_cell_is_null(const df_cell_t *rp);

/**
 * @brief Initialize a df_cell_t structure.
 *
 * @param rp Pointer to the df_cell_t structure to initialize.
 * @param free_seg Pass true to free the array contents when the cell is cleared.
 */
WS_DLL_PUBLIC
void
df_cell_init(df_cell_t *rp, bool free_seg);

/**
 * @brief Clear a df_cell_t structure.
 *
 * This function clears the contents of a df_cell_t structure, releasing any resources it holds.
 *
 * @param rp Pointer to the df_cell_t structure to be cleared.
 */
WS_DLL_PUBLIC
void
df_cell_clear(df_cell_t *rp);

/**
 * @brief Initialize an iterator for a cell.
 *
 * @note Cell must not be cleared while iter is alive.
 *
 * @param rp Pointer to the cell to iterate over.
 * @param iter Pointer to the iterator structure to initialize.
 */
WS_DLL_PUBLIC
void
df_cell_iter_init(df_cell_t *rp, df_cell_iter_t *iter);

/**
 * @brief Advances the iterator to the next cell and returns its value.
 *
 * @param iter Pointer to the iterator structure.
 * @return fcell_t* Pointer to the next cell's value, or NULL if there are no more cells.
 */
WS_DLL_PUBLIC
fvalue_t *
df_cell_iter_next(df_cell_iter_t *iter);


#endif
