/** @file
 * Definitions for value_string structures and routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __VALUE_STRING_H__
#define __VALUE_STRING_H__

#include <stdint.h>

#include "ws_symbol_export.h"

#include <wsutil/nstime.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* VALUE TO STRING MATCHING */

/**
 * @brief Mapping between a 32-bit integer value and its string representation.
 *
 * Used to associate a `uint32_t` value with a human-readable string. This is
 * commonly employed in protocol dissectors and diagnostic tools to convert
 * numeric constants into descriptive labels.
 */
typedef struct _value_string {
    uint32_t     value;   /**< Numeric value to match. */
    const char *strptr;   /**< Corresponding string representation. */
} value_string;


#if 0
  /* -----  VALUE_STRING "Helper" macros ----- */

  /* Essentially: Provide the capability to define a list of value_strings once and
     then to expand the list as an enum and/or as a value_string array. */

  /* Usage: */

  /*- define list of value strings -*/
     #define foo_VALUE_STRING_LIST(XXX) \
        XXX( FOO_A, 1, "aaa" ) \
        XXX( FOO_B, 3, "bbb" )

  /*- gen enum -*/
     VALUE_STRING_ENUM(foo);      /* gen's 'enum {FOO_A=1, FOO_B=3};' */

  /*- gen value_string array -*/
     /* local */
     VALUE_STRING_ARRAY(foo);     /* gen's 'static const value_string foo[] = {{1,"aaa"}, {3,"bbb"}}; */

     /* global */
     VALUE_STRING_ARRAY_GLOBAL_DEF(foo); /* gen's 'const value_string foo[] = {{1,"aaa"}, {3,"bbb"}}; */
     VALUE_STRING_ARRAY_GLOBAL_DCL(foo); /* gen's 'const value_string foo[]; */

  /* Alternatively: */
     #define bar_VALUE_STRING_LIST(XXX) \
        XXX( BAR_A, 1) \
        XXX( BAR_B, 3)

     VALUE_STRING_ENUM2(bar);     /* gen's 'enum {BAR_A=1, BAR_B=3};' */
     VALUE_STRING_ARRAY2(bar);    /* gen's 'static const value_string bar[] = {{1,"BAR_A"}, {3,"BAR_B"}}; */
     ...
#endif

/* -- Public -- */
#define VALUE_STRING_ENUM(              array_name) _VS_ENUM_XXX( array_name, _VS_ENUM_ENTRY)
#define VALUE_STRING_ARRAY(             array_name) _VS_ARRAY_SC_XXX(array_name, _VS_ARRAY_ENTRY, static)
#define VALUE_STRING_ARRAY_GLOBAL_DEF(  array_name) _VS_ARRAY_XXX(array_name, _VS_ARRAY_ENTRY)
#define VALUE_STRING_ARRAY_GLOBAL_DCL(  array_name) _VS_ARRAY_SC_TYPE_NAME(array_name, extern)

#define VALUE_STRING_ENUM2(             array_name) _VS_ENUM_XXX( array_name, _VS_ENUM_ENTRY2)
#define VALUE_STRING_ARRAY2(            array_name) _VS_ARRAY_SC_XXX(array_name, _VS_ARRAY_ENTRY2, static)
#define VALUE_STRING_ARRAY2_GLOBAL_DEF( array_name) _VS_ARRAY_XXX(array_name, _VS_ARRAY_ENTRY2)
#define VALUE_STRING_ARRAY2_GLOBAL_DCL( array_name) _VS_ARRAY_SC_TYPE_NAME(array_name, extern)

/* -- Private -- */
#define _VS_ENUM_XXX(array_name, macro) \
enum { \
    array_name##_VALUE_STRING_LIST(macro) \
    _##array_name##_ENUM_DUMMY = 0 \
}

#define _VS_ARRAY_SC_XXX(array_name, macro, sc)  \
    _VS_ARRAY_SC_TYPE_NAME(array_name, sc) = { \
    array_name##_VALUE_STRING_LIST(macro) \
    { 0, NULL } \
}

#define _VS_ARRAY_XXX(array_name, macro)  \
    _VS_ARRAY_TYPE_NAME(array_name) = { \
    array_name##_VALUE_STRING_LIST(macro) \
    { 0, NULL } \
}

#define _VS_ARRAY_SC_TYPE_NAME(array_name, sc) sc const value_string array_name[]
#define _VS_ARRAY_TYPE_NAME(array_name) const value_string array_name[]

#define _VS_ENUM_ENTRY( name, value, string) name = value,
#define _VS_ARRAY_ENTRY(name, value, string) { value, string },

#define _VS_ENUM_ENTRY2( name, value) name = value,
#define _VS_ARRAY_ENTRY2(name, value) { value, #name },
/* ----- ----- */

/**
 * @brief Convert a numeric value to a string using a value-string mapping.
 *
 * Searches the provided `value_string` array `vs` for a matching entry with
 * value `val`. If found, returns the corresponding string. If not found,
 * formats the value using the provided `fmt` string and returns the result.
 * Memory is allocated using the specified `wmem_allocator_t` scope.
 *
 * @param scope  Memory allocator scope for the returned string.
 * @param val    Numeric value to convert.
 * @param vs     Array of value-string mappings.
 * @param fmt    Format string used if `val` is not found in `vs`.
 * @return       A newly allocated string representing the value.
 */
WS_DLL_PUBLIC
char *
val_to_str(wmem_allocator_t *scope, const uint32_t val, const value_string *vs, const char *fmt)
G_GNUC_PRINTF(4, 0);

/**
 * @brief Convert a numeric value to a constant string using a value-string mapping.
 *
 * Searches the provided `value_string` array `vs` for an entry matching `val`.
 * If found, returns the corresponding constant string. If not found, returns
 * the provided `unknown_str`.
 *
 * This function does not allocate memory and is suitable for use in contexts
 * where a constant string is sufficient and memory management must be avoided.
 *
 * @param val          Numeric value to convert.
 * @param vs           Array of value-string mappings.
 * @param unknown_str  Fallback string if `val` is not found in `vs`.
 * @return             A constant string representing the value or `unknown_str`.
 */
WS_DLL_PUBLIC
const char *
val_to_str_const(const uint32_t val, const value_string *vs, const char *unknown_str);

/**
 * @brief Attempt to convert a numeric value to a string using a value-string mapping.
 *
 * Searches the provided `value_string` array `vs` for an entry matching `val`.
 * If found, returns the corresponding string. If not found, returns `NULL`.
 *
 * This function is useful when the caller wants to distinguish between known
 * and unknown values without falling back to a default string.
 *
 * @param val  Numeric value to convert.
 * @param vs   Array of value-string mappings.
 * @return     A constant string if found, or `NULL` if not found.
 */
WS_DLL_PUBLIC
const char *
try_val_to_str(const uint32_t val, const value_string *vs);

/**
 * @brief Attempt to convert a numeric value to a string and retrieve its index.
 *
 * Searches the provided `value_string` array `vs` for an entry matching `val`.
 * If found, returns the corresponding string and sets `*idx` to the index of
 * the matching entry. If not found, returns `NULL` and leaves `*idx` unchanged.
 *
 * This function is useful when both the string representation and its position
 * in the mapping array are needed.
 *
 * @param val   Numeric value to convert.
 * @param vs    Array of value-string mappings.
 * @param idx   Pointer to an integer to receive the index of the match.
 * @return      A constant string if found, or `NULL` if not found.
 */
WS_DLL_PUBLIC
const char *
try_val_to_str_idx(const uint32_t val, const value_string *vs, int *idx);

/* 64-BIT VALUE TO STRING MATCHING */

/**
 * @brief Mapping between a 64-bit integer value and its string representation.
 *
 * Used to associate a `uint64_t` value with a human-readable string. This is
 * useful for converting large numeric constants to descriptive labels in
 * protocol dissectors, debug output, or UI elements.
 */
typedef struct _val64_string {
    uint64_t     value;   /**< Numeric value to match. */
    const char *strptr;   /**< Corresponding string representation. */
} val64_string;

/**
 * @brief Convert a 64-bit value to a string using a value-string mapping.
 *
 * Searches the provided `val64_string` array `vs` for an entry matching `val`.
 * If found, returns the corresponding string. If not found, formats the value
 * using the provided `fmt` string and returns the result. The returned string
 * is allocated using the specified `wmem_allocator_t` scope.
 *
 * @param scope  Memory allocator scope for the returned string.
 * @param val    64-bit value to convert.
 * @param vs     Array of 64-bit value-string mappings.
 * @param fmt    Format string used if `val` is not found in `vs`.
 * @return       A newly allocated string representing the value.
 */
WS_DLL_PUBLIC
const char *
val64_to_str_wmem(wmem_allocator_t* scope, const uint64_t val, const val64_string *vs, const char *fmt)
G_GNUC_PRINTF(4, 0);

/**
 * @brief Convert a 64-bit value to a constant string using a value-string mapping.
 *
 * Searches the provided `val64_string` array `vs` for an entry matching `val`.
 * If found, returns the corresponding constant string. If not found, returns
 * the specified `unknown_str`.
 *
 * This function does not allocate memory and is suitable for use in contexts
 * where a constant string is sufficient and memory management must be avoided.
 *
 * @param val          64-bit value to convert.
 * @param vs           Array of 64-bit value-string mappings.
 * @param unknown_str  Fallback string if `val` is not found in `vs`.
 * @return             A constant string representing the value or `unknown_str`.
 */
WS_DLL_PUBLIC
const char *
val64_to_str_const(const uint64_t val, const val64_string *vs, const char *unknown_str);

/**
 * @brief Attempt to convert a 64-bit value to a string using a value-string mapping.
 *
 * Searches the provided `val64_string` array `vs` for an entry matching `val`.
 * If found, returns the corresponding string. If not found, returns `NULL`.
 *
 * This function is useful when the caller wants to detect unknown values
 * without falling back to a default string or allocating memory.
 *
 * @param val  64-bit value to convert.
 * @param vs   Array of 64-bit value-string mappings.
 * @return     A constant string if found, or `NULL` if not found.
 */
WS_DLL_PUBLIC
const char *
try_val64_to_str(const uint64_t val, const val64_string *vs);

/**
 * @brief Attempt to convert a 64-bit value to a string and retrieve its index.
 *
 * Searches the provided `val64_string` array `vs` for an entry matching `val`.
 * If found, returns the corresponding string and sets `*idx` to the index of
 * the matching entry. If not found, returns `NULL` and leaves `*idx` unchanged.
 *
 * This function is useful when both the string representation and its position
 * in the mapping array are needed for further processing or diagnostics.
 *
 * @param val   64-bit value to convert.
 * @param vs    Array of 64-bit value-string mappings.
 * @param idx   Pointer to an integer to receive the index of the match.
 * @return      A constant string if found, or `NULL` if not found.
 */
WS_DLL_PUBLIC
const char *
try_val64_to_str_idx(const uint64_t val, const val64_string *vs, int *idx);

/* STRING TO VALUE MATCHING */

/**
 * @brief Convert a string to its corresponding numeric value using a value-string mapping.
 *
 * Searches the provided `value_string` array `vs` for an entry whose string matches `val`.
 * If found, returns the associated numeric value. If not found, returns `err_val`.
 *
 * This function is useful for parsing user input or protocol fields that use
 * string representations of enumerated values.
 *
 * @param val      String to convert.
 * @param vs       Array of value-string mappings.
 * @param err_val  Value to return if `val` is not found in `vs`.
 * @return         The numeric value corresponding to `val`, or `err_val` if not found.
 */
WS_DLL_PUBLIC
uint32_t
str_to_val(const char *val, const value_string *vs, const uint32_t err_val);

/**
 * @brief Retrieve the index of a string in a value-string mapping array.
 *
 * Searches the provided `value_string` array `vs` for an entry whose string
 * matches `val`. If found, returns the index of the matching entry. If not
 * found, returns -1.
 *
 * This function is useful when the caller needs the position of a matched
 * string for further processing or lookup.
 *
 * @param val  String to search for.
 * @param vs   Array of value-string mappings.
 * @return     Index of the matching entry, or -1 if not found.
 */
WS_DLL_PUBLIC
int
str_to_val_idx(const char *val, const value_string *vs);

/* EXTENDED VALUE TO STRING MATCHING */

typedef struct _value_string_ext value_string_ext;
typedef const value_string *(*_value_string_match2_t)(const uint32_t, value_string_ext*);

/**
 * @brief Extended metadata for a value_string array.
 *
 * Encapsulates additional information and utilities for working with a
 * `value_string` array, including match logic, bounds, and memory scope.
 * This structure supports enhanced lookup and error reporting functionality.
 */
struct _value_string_ext {
    _value_string_match2_t _vs_match2;     /**< Optional custom match function for advanced lookup. */
    uint32_t               _vs_first_value;/**< First value in the value_string array. */
    unsigned               _vs_num_entries;/**< Number of entries in the array (excluding final {0, NULL}). */
    const value_string    *_vs_p;          /**< Pointer to the value_string array. */
    const char            *_vs_name;       /**< Name of the mapping (used in error messages). */
    wmem_allocator_t      *_scope;         /**< Memory scope used for allocation and cleanup. */
};


#define VALUE_STRING_EXT_VS_P(x)           (x)->_vs_p
#define VALUE_STRING_EXT_VS_NUM_ENTRIES(x) (x)->_vs_num_entries
#define VALUE_STRING_EXT_VS_NAME(x)        (x)->_vs_name

/**
 * @brief Attempt to initialize and retrieve a value-string entry from an extended mapping.
 *
 * Searches the extended value-string structure `vse` for an entry matching `val`.
 * If found, returns a pointer to the corresponding `value_string` entry.
 * If not found, returns `NULL`. This function may also perform internal
 * initialization of the `value_string_ext` structure if needed.
 *
 * @param val  Numeric value to look up.
 * @param vse  Pointer to an extended value-string mapping structure.
 * @return     Pointer to the matching `value_string` entry, or `NULL` if not found.
 */
WS_DLL_PUBLIC
const value_string *
_try_val_to_str_ext_init(const uint32_t val, value_string_ext *vse);
#define VALUE_STRING_EXT_INIT(x) { _try_val_to_str_ext_init, 0, G_N_ELEMENTS(x)-1, x, #x, NULL }

/**
 * @brief Create a new extended value-string mapping structure.
 *
 * Allocates and initializes a `value_string_ext` object using the provided
 * `value_string` array.
 *
 * @param scope              Memory allocator scope for the new structure.
 * @param vs                 Pointer to the value-string array.
 * @param vs_tot_num_entries Total number of entries in the array (excluding the final {0, NULL}).
 * @param vs_name            Descriptive name for the mapping (used in diagnostics).
 * @return                   Pointer to the newly created `value_string_ext` structure.
 */
WS_DLL_PUBLIC
value_string_ext *
value_string_ext_new(wmem_allocator_t* scope, const value_string *vs, unsigned vs_tot_num_entries, const char *vs_name);

/**
 * @brief Free an extended value-string mapping structure.
 *
 * Releases any memory associated with the given `value_string_ext` structure,
 * including its internal scope if applicable. This function should be called
 * when the extended mapping is no longer needed to avoid memory leaks.
 *
 * @param vse  Pointer to the `value_string_ext` structure to be freed.
 */
WS_DLL_PUBLIC
void
value_string_ext_free(value_string_ext *vse);

/**
 * @brief Convert a numeric value to a string using an extended value-string mapping.
 *
 * Searches the extended value-string structure `vse` for an entry matching `val`.
 * If found, returns the corresponding string. If not found, formats the value
 * using the provided `fmt` string. The result is allocated using the specified
 * `wmem_allocator_t` scope.
 *
 * This function is useful for enhanced lookup scenarios where additional metadata
 * or scoped memory management is required.
 *
 * @param scope  Memory allocator scope for the returned string.
 * @param val    Numeric value to convert.
 * @param vse    Pointer to the extended value-string mapping structure.
 * @param fmt    Format string used if `val` is not found in `vse`.
 * @return       A newly allocated string representing the value.
 */
WS_DLL_PUBLIC
char *
val_to_str_ext(wmem_allocator_t *scope, const uint32_t val, value_string_ext *vse, const char *fmt)
G_GNUC_PRINTF(4, 0);

/**
 * @brief Convert a numeric value to a constant string using an extended value-string mapping.
 *
 * Searches the extended value-string structure `vs` for an entry matching `val`.
 * If found, returns the corresponding constant string. If not found, returns
 * the specified `unknown_str`.
 *
 * This function does not allocate memory and is suitable for contexts where
 * a constant string is sufficient and memory management must be avoided.
 *
 * @param val          Numeric value to convert.
 * @param vs           Pointer to the extended value-string mapping structure.
 * @param unknown_str  Fallback string if `val` is not found in `vs`.
 * @return             A constant string representing the value or `unknown_str`.
 */
WS_DLL_PUBLIC
const char *
val_to_str_ext_const(const uint32_t val, value_string_ext *vs, const char *unknown_str);

/**
 * @brief Attempt to convert a numeric value to a string using an extended value-string mapping.
 *
 * Searches the extended value-string structure `vse` for an entry matching `val`.
 * If found, returns the corresponding string. If not found, returns `NULL`.
 *
 * This function is useful when the caller wants to detect unknown values
 * without allocating memory or falling back to a default string.
 *
 * @param val  Numeric value to convert.
 * @param vse  Pointer to the extended value-string mapping structure.
 * @return     A constant string if found, or `NULL` if not found.
 */
WS_DLL_PUBLIC
const char *
try_val_to_str_ext(const uint32_t val, value_string_ext *vse);

/**
 * @brief Attempt to convert a numeric value to a string and retrieve its index from an extended mapping.
 *
 * Searches the extended value-string structure `vse` for an entry matching `val`.
 * If found, returns the corresponding string and sets `*idx` to the index of the
 * matching entry within the original `value_string` array. If not found, returns
 * `NULL` and leaves `*idx` unchanged.
 *
 * This function is useful when both the string representation and its position
 * in the mapping array are needed for diagnostics or further processing.
 *
 * @param val   Numeric value to convert.
 * @param vse   Pointer to the extended value-string mapping structure.
 * @param idx   Pointer to an integer to receive the index of the match.
 * @return      A constant string if found, or `NULL` if not found.
 */
WS_DLL_PUBLIC
const char *
try_val_to_str_idx_ext(const uint32_t val, value_string_ext *vse, int *idx);

/* EXTENDED 64-BIT VALUE TO STRING MATCHING */

typedef struct _val64_string_ext val64_string_ext;
typedef const val64_string *(*_val64_string_match2_t)(const uint64_t, val64_string_ext*);

/**
 * @brief Extended metadata for a 64-bit value-string mapping array.
 *
 * Encapsulates additional information and utilities for working with a
 * `val64_string` array, including match logic, bounds, and memory scope.
 */
struct _val64_string_ext {
    _val64_string_match2_t _vs_match2;     /**< Optional custom match function for advanced lookup. */
    uint64_t               _vs_first_value;/**< First value in the val64_string array. */
    unsigned               _vs_num_entries;/**< Number of entries in the array (excluding final {0, NULL}). */
    const val64_string    *_vs_p;          /**< Pointer to the val64_string array. */
    const char            *_vs_name;       /**< Descriptive name for diagnostics and error messages. */
    wmem_allocator_t      *_scope;         /**< Memory scope used for allocation and cleanup. */
};

#define VAL64_STRING_EXT_VS_P(x)           (x)->_vs_p
#define VAL64_STRING_EXT_VS_NUM_ENTRIES(x) (x)->_vs_num_entries
#define VAL64_STRING_EXT_VS_NAME(x)        (x)->_vs_name

/**
 * @brief Compare two value_string entries by their numeric value.
 *
 * Used primarily for sorting or searching operations on arrays of
 * `value_string` structures. This function compares the `value` fields
 * of the two entries pointed to by `a` and `b`.
 *
 * @param a  Pointer to the first `value_string` entry.
 * @param b  Pointer to the second `value_string` entry.
 * @return   Negative if `a < b`, zero if `a == b`, positive if `a > b`.
 */
WS_DLL_PUBLIC
int
value_str_value_compare(const void* a, const void* b);

/**
 * @brief Attempt to initialize and retrieve a 64-bit value-string entry from an extended mapping.
 *
 * Searches the extended `val64_string_ext` structure `vse` for an entry matching `val`.
 * If found, returns a pointer to the corresponding `val64_string` entry.
 * If not found, returns `NULL`. This function may also perform internal
 * initialization of the `val64_string_ext` structure if required.
 *
 * This is useful for advanced lookup scenarios where metadata and scoped
 * memory management are involved, and where direct access to the matched
 * entry is needed for further processing.
 *
 * @param val  64-bit value to look up.
 * @param vse  Pointer to an extended 64-bit value-string mapping structure.
 * @return     Pointer to the matching `val64_string` entry, or `NULL` if not found.
 */
WS_DLL_PUBLIC
const val64_string *
_try_val64_to_str_ext_init(const uint64_t val, val64_string_ext *vse);
#define VAL64_STRING_EXT_INIT(x) { _try_val64_to_str_ext_init, 0, G_N_ELEMENTS(x)-1, x, #x, NULL }

WS_DLL_PUBLIC
val64_string_ext *
val64_string_ext_new(wmem_allocator_t* scope, const val64_string *vs, unsigned vs_tot_num_entries, const char *vs_name);

WS_DLL_PUBLIC
void
val64_string_ext_free(val64_string_ext *vse);

WS_DLL_PUBLIC
char *
val64_to_str_ext_wmem(wmem_allocator_t *scope, const uint64_t val, val64_string_ext *vse, const char *fmt)
G_GNUC_PRINTF(4, 0);

WS_DLL_PUBLIC
const char *
val64_to_str_ext_const(const uint64_t val, val64_string_ext *vs, const char *unknown_str);

WS_DLL_PUBLIC
const char *
try_val64_to_str_ext(const uint64_t val, val64_string_ext *vse);

WS_DLL_PUBLIC
const char *
try_val64_to_str_idx_ext(const uint64_t val, val64_string_ext *vse, int *idx);

/* STRING TO STRING MATCHING */

typedef struct _string_string {
    const char *value;
    const char *strptr;
} string_string;

WS_DLL_PUBLIC
const char *
str_to_str_wmem(wmem_allocator_t* scope, const char *val, const string_string *vs, const char *fmt)
G_GNUC_PRINTF(4, 0);

WS_DLL_PUBLIC
const char *
try_str_to_str(const char *val, const string_string *vs);

WS_DLL_PUBLIC
const char *
try_str_to_str_idx(const char *val, const string_string *vs, int *idx);

/* RANGE TO STRING MATCHING */

typedef struct _range_string {
    uint64_t     value_min;
    uint64_t     value_max;
    const char *strptr;
} range_string;

WS_DLL_PUBLIC
const char *
rval_to_str_wmem(wmem_allocator_t* scope, const uint32_t val, const range_string *rs, const char *fmt)
G_GNUC_PRINTF(4, 0);

WS_DLL_PUBLIC
const char *
rval_to_str_const(const uint32_t val, const range_string *rs, const char *unknown_str);

WS_DLL_PUBLIC
const char *
try_rval_to_str(const uint32_t val, const range_string *rs);

WS_DLL_PUBLIC
const char *
try_rval_to_str_idx(const uint32_t val, const range_string *rs, int *idx);

WS_DLL_PUBLIC
const char *
try_rval64_to_str(const uint64_t val, const range_string *rs);

WS_DLL_PUBLIC
const char *
try_rval64_to_str_idx(const uint64_t val, const range_string *rs, int *idx);

/* TIME TO STRING MATCHING */

typedef struct _time_value_string {
    nstime_t     value;
    const char *strptr;
} time_value_string;

WS_DLL_PUBLIC
const char *
try_time_val_to_str(const nstime_t *val, const time_value_string *vs);

/* BYTES TO STRING MATCHING */

typedef struct _bytes_string {
  const uint8_t *value;
  const size_t  value_length;
  const char   *strptr;
} bytes_string;

WS_DLL_PUBLIC
const char *
bytesval_to_str_wmem(wmem_allocator_t* scope, const uint8_t *val, const size_t val_len, const bytes_string *bs, const char *fmt)
G_GNUC_PRINTF(5, 0);

WS_DLL_PUBLIC
const char *
try_bytesval_to_str(const uint8_t *val, const size_t val_len, const bytes_string *bs);

WS_DLL_PUBLIC
const char *
bytesprefix_to_str(wmem_allocator_t* scope, const uint8_t *haystack, const size_t haystack_len, const bytes_string *bs, const char *fmt)
G_GNUC_PRINTF(5, 0);

WS_DLL_PUBLIC
const char *
try_bytesprefix_to_str(const uint8_t *haystack, const size_t haystack_len, const bytes_string *bs);

WS_DLL_PUBLIC
void register_external_value_string(const char* name, const value_string* vs);

WS_DLL_PUBLIC
value_string* get_external_value_string(const char* name);

WS_DLL_PUBLIC
void register_external_value_string_ext(const char* name, const value_string_ext* vse);

WS_DLL_PUBLIC
value_string_ext* get_external_value_string_ext(const char* name);

/* MISC (generally do not use) */

WS_DLL_PUBLIC
void value_string_externals_init(void);

WS_DLL_PUBLIC
void value_string_externals_cleanup(void);

WS_DLL_PUBLIC
bool
value_string_ext_validate(const value_string_ext *vse);

WS_DLL_PUBLIC
const char *
value_string_ext_match_type_str(const value_string_ext *vse);

WS_DLL_PUBLIC
bool
val64_string_ext_validate(const val64_string_ext *vse);

WS_DLL_PUBLIC
const char *
val64_string_ext_match_type_str(const val64_string_ext *vse);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __VALUE_STRING_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
