/* value_string.c
 * Routines for value_strings
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_EPAN

#include <stdio.h>
#include <string.h>

#include <epan/wmem_scopes.h>
#include "proto.h"
#include "to_str.h"
#include "value_string.h"
#include <wsutil/ws_assert.h>

#include <wsutil/wslog.h>

/* REGULAR VALUE STRING */

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr on a match.
   Formats val with fmt, and returns the resulting string, on failure. */
const char *
val_to_str(const uint32_t val, const value_string *vs, const char *fmt)
{
    const char *ret;

    DISSECTOR_ASSERT(fmt != NULL);

    ret = try_val_to_str(val, vs);
    if (ret != NULL)
        return ret;

    return wmem_strdup_printf(wmem_packet_scope(), fmt, val);
}

char *
val_to_str_wmem(wmem_allocator_t *scope, const uint32_t val, const value_string *vs, const char *fmt)
{
    const char *ret;

    DISSECTOR_ASSERT(fmt != NULL);

    ret = try_val_to_str(val, vs);
    if (ret != NULL)
        return wmem_strdup(scope, ret);

    return wmem_strdup_printf(scope, fmt, val);
}

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr on a match.
   Returns 'unknown_str', on failure. */
const char *
val_to_str_const(const uint32_t val, const value_string *vs,
        const char *unknown_str)
{
    const char *ret;

    DISSECTOR_ASSERT(unknown_str != NULL);

    ret = try_val_to_str(val, vs);
    if (ret != NULL)
        return ret;

    return unknown_str;
}

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr, and sets "*idx" to the index in
   that table, on a match, and returns NULL, and sets "*idx" to -1,
   on failure. */
const char *
try_val_to_str_idx(const uint32_t val, const value_string *vs, int *idx)
{
    int i = 0;

    DISSECTOR_ASSERT(idx != NULL);

    if(vs) {
        while (vs[i].strptr) {
            if (vs[i].value == val) {
                *idx = i;
                return(vs[i].strptr);
            }
            i++;
        }
    }

    *idx = -1;
    return NULL;
}

/* Like try_val_to_str_idx(), but doesn't return the index. */
const char *
try_val_to_str(const uint32_t val, const value_string *vs)
{
    int ignore_me;
    return try_val_to_str_idx(val, vs, &ignore_me);
}

const char *
char_val_to_str(char val, const value_string *vs, const char *msg)
{
    const char *ret;
    char buf[7];

    DISSECTOR_ASSERT(msg != NULL);

    ret = try_val_to_str(val, vs);
    if (ret != NULL)
        return ret;

    return wmem_strdup_printf(wmem_packet_scope(), "%s: %s",
            msg, hfinfo_char_value_format_display(BASE_HEX, buf, val));
}

/* 64-BIT VALUE STRING */

const char *
val64_to_str(const uint64_t val, const val64_string *vs, const char *fmt)
{
    const char *ret;

    DISSECTOR_ASSERT(fmt != NULL);

    ret = try_val64_to_str(val, vs);
    if (ret != NULL)
        return ret;

    return wmem_strdup_printf(wmem_packet_scope(), fmt, val);
}

const char *
val64_to_str_const(const uint64_t val, const val64_string *vs,
        const char *unknown_str)
{
    const char *ret;

    DISSECTOR_ASSERT(unknown_str != NULL);

    ret = try_val64_to_str(val, vs);
    if (ret != NULL)
        return ret;

    return unknown_str;
}

const char *
try_val64_to_str_idx(const uint64_t val, const val64_string *vs, int *idx)
{
    int i = 0;

    DISSECTOR_ASSERT(idx != NULL);

    if(vs) {
        while (vs[i].strptr) {
            if (vs[i].value == val) {
                *idx = i;
                return(vs[i].strptr);
            }
            i++;
        }
    }

    *idx = -1;
    return NULL;
}

const char *
try_val64_to_str(const uint64_t val, const val64_string *vs)
{
    int ignore_me;
    return try_val64_to_str_idx(val, vs, &ignore_me);
}

/* REVERSE VALUE STRING */

/* We use the same struct as for regular value strings, but we look up strings
 * and return values instead */

/* Like val_to_str except backwards */
uint32_t
str_to_val(const char *val, const value_string *vs, const uint32_t err_val)
{
    int i;

    i = str_to_val_idx(val, vs);

    if (i >= 0) {
        return vs[i].value;
    }

    return err_val;
}

/* Find the index of a string in a value_string, or -1 when not present */
int
str_to_val_idx(const char *val, const value_string *vs)
{
    int i = 0;

    if(vs) {

        while (vs[i].strptr) {

            if (strcmp(vs[i].strptr, val) == 0) {
                return i;
            }

            i++;
        }

    }

    return -1;
}

/* EXTENDED VALUE STRING */

/* Extended value strings allow fast(er) value_string array lookups by
 * using (if possible) direct access or a binary search of the array.
 *
 * If the values in the value_string array are a contiguous range of values
 * from min to max, the value will be used as a direct index into the array.
 *
 * If the values in the array are not contiguous (ie: there are "gaps"),
 * but are in assending order a binary search will be used.
 *
 * If direct access or binary search cannot be used, then a linear search
 * is used and a warning is emitted.
 *
 * Note that the value_string array used with VALUE_STRING_EXT_INIT
 * *must* be terminated with {0, NULL}).
 *
 * Extended value strings are defined at compile time as follows:
 *   static const value_string vs[] = { {value1, "string1"},
 *                                      {value2, "string2"},
 *                                      ...,
 *                                      {0, NULL}};
 *   static value_string_ext vse = VALUE_STRING_EXT_INIT(vs);
 *
 * Extended value strings can be created at runtime by calling
 *   value_string_ext_new(<ptr to value_string array>,
 *                        <total number of entries in the value_string_array>,
 *                        <value_string_name>);
 * Note: The <total number of entries in the value_string_array> should include
 *       the {0, NULL} entry.
 */

/* Create a value_string_ext given a ptr to a value_string array and the total
 * number of entries. Note that the total number of entries should include the
 * required {0, NULL} terminating entry of the array.
 * Returns a pointer to an epan-scoped'd and initialized value_string_ext
 * struct. */
value_string_ext *
value_string_ext_new(const value_string *vs, unsigned vs_tot_num_entries,
        const char *vs_name)
{
    value_string_ext *vse;

    DISSECTOR_ASSERT (vs_name != NULL);
    DISSECTOR_ASSERT (vs_tot_num_entries > 0);
    /* Null-terminated value-string ? */
    DISSECTOR_ASSERT (vs[vs_tot_num_entries-1].strptr == NULL);

    vse                  = wmem_new(wmem_epan_scope(), value_string_ext);
    vse->_vs_p           = vs;
    vse->_vs_num_entries = vs_tot_num_entries - 1;
    /* We set our 'match' function to the init function, which finishes by
     * setting the match function properly and then calling it. This is a
     * simple way to do lazy initialization of extended value strings.
     * The init function also sets up _vs_first_value for us. */
    vse->_vs_first_value = 0;
    vse->_vs_match2      = _try_val_to_str_ext_init;
    vse->_vs_name        = vs_name;

    return vse;
}

void
value_string_ext_free(value_string_ext *vse)
{
    wmem_free(wmem_epan_scope(), vse);
}

/* Like try_val_to_str for extended value strings */
const char *
try_val_to_str_ext(const uint32_t val, value_string_ext *vse)
{
    if (vse) {
        const value_string *vs = vse->_vs_match2(val, vse);

        if (vs) {
            return vs->strptr;
        }
    }

    return NULL;
}

/* Like try_val_to_str_idx for extended value strings */
const char *
try_val_to_str_idx_ext(const uint32_t val, value_string_ext *vse, int *idx)
{
    if (vse) {
        const value_string *vs = vse->_vs_match2(val, vse);
        if (vs) {
            *idx = (int) (vs - vse->_vs_p);
            return vs->strptr;
        }
    }
    *idx = -1;
    return NULL;
}

/* Like val_to_str for extended value strings */
const char *
val_to_str_ext(const uint32_t val, value_string_ext *vse, const char *fmt)
{
    const char *ret;

    DISSECTOR_ASSERT(fmt != NULL);

    ret = try_val_to_str_ext(val, vse);
    if (ret != NULL)
        return ret;

    return wmem_strdup_printf(wmem_packet_scope(), fmt, val);
}

char *
val_to_str_ext_wmem(wmem_allocator_t *scope, const uint32_t val, value_string_ext *vse, const char *fmt)
{
    const char *ret;

    DISSECTOR_ASSERT(fmt != NULL);

    ret = try_val_to_str_ext(val, vse);
    if (ret != NULL)
        return wmem_strdup(scope, ret);

    return wmem_strdup_printf(scope, fmt, val);
}

/* Like val_to_str_const for extended value strings */
const char *
val_to_str_ext_const(const uint32_t val, value_string_ext *vse,
        const char *unknown_str)
{
    const char *ret;

    DISSECTOR_ASSERT(unknown_str != NULL);

    ret = try_val_to_str_ext(val, vse);
    if (ret != NULL)
        return ret;

    return unknown_str;
}

/* Fallback linear matching algorithm for extended value strings */
static const value_string *
_try_val_to_str_linear(const uint32_t val, value_string_ext *vse)
{
    const value_string *vs_p = vse->_vs_p;
    unsigned i;
    for (i=0; i<vse->_vs_num_entries; i++) {
        if (vs_p[i].value == val)
            return &(vs_p[i]);
    }
    return NULL;
}

/* Constant-time matching algorithm for contiguous extended value strings */
static const value_string *
_try_val_to_str_index(const uint32_t val, value_string_ext *vse)
{
    uint32_t i;

    i = val - vse->_vs_first_value;
    if (i < vse->_vs_num_entries) {
        ws_assert (val == vse->_vs_p[i].value);
        return &(vse->_vs_p[i]);
    }
    return NULL;
}

/* Value comparator for sorted extended value strings */
static int
val_to_str_compar(const void *v_needle, const void *v_item)
{
    uint32_t needle = *(const uint32_t *)v_needle;
    uint32_t value = ((const value_string *)v_item)->value;
    return needle > value ? 1 : (needle < value ? -1 : 0);
}

/* log(n)-time matching for sorted extended value strings */
static const value_string *
_try_val_to_str_bsearch(const uint32_t val, value_string_ext *vse)
{
    return bsearch(&val, vse->_vs_p, vse->_vs_num_entries,
                   sizeof vse->_vs_p[0], val_to_str_compar);
}

/* Initializes an extended value string. Behaves like a match function to
 * permit lazy initialization of extended value strings.
 * - Goes through the value_string array to determine the fastest possible
 *   access method.
 * - Verifies that the value_string contains no NULL string pointers.
 * - Verifies that the value_string is terminated by {0, NULL}
 */
const value_string *
_try_val_to_str_ext_init(const uint32_t val, value_string_ext *vse)
{
    const value_string *vs_p           = vse->_vs_p;
    const unsigned      vs_num_entries = vse->_vs_num_entries;

    /* The matching algorithm used:
     * VS_LIN_SEARCH - slow linear search (as in a normal value string)
     * VS_BIN_SEARCH - log(n)-time binary search, the values must be sorted
     * VS_INDEX      - constant-time index lookup, the values must be contiguous
     */
    enum { VS_LIN_SEARCH, VS_BIN_SEARCH, VS_INDEX } type = VS_INDEX;

    /* Note: The value_string 'value' is *unsigned*, but we do a little magic
     * to help with value strings that have negative values.
     *
     * { -3, -2, -1, 0, 1, 2 }
     * will be treated as "ascending ordered" (although it isn't technically),
     * thus allowing constant-time index search
     *
     * { -3, -2, 0, 1, 2 } and { -3, -2, -1, 0, 2 }
     * will both be considered as "out-of-order with gaps", thus falling
     * back to the slow linear search
     *
     * { 0, 1, 2, -3, -2 } and { 0, 2, -3, -2, -1 }
     * will be considered "ascending ordered with gaps" thus allowing
     * a log(n)-time 'binary' search
     *
     * If you're confused, think of how negative values are represented, or
     * google two's complement.
     */

    uint32_t prev_value;
    uint32_t first_value;
    unsigned   i;

    DISSECTOR_ASSERT((vs_p[vs_num_entries].value  == 0) &&
                     (vs_p[vs_num_entries].strptr == NULL));

    vse->_vs_first_value = vs_p[0].value;
    first_value          = vs_p[0].value;
    prev_value           = first_value;

    for (i = 0; i < vs_num_entries; i++) {
        DISSECTOR_ASSERT(vs_p[i].strptr != NULL);
        if ((type == VS_INDEX) && (vs_p[i].value != (i + first_value))) {
            type = VS_BIN_SEARCH;
        }
        /* XXX: Should check for dups ?? */
        if (type == VS_BIN_SEARCH) {
            if (prev_value > vs_p[i].value) {
                ws_warning("Extended value string '%s' forced to fall back to linear search:\n"
                          "  entry %u, value %u [%#x] < previous entry, value %u [%#x]",
                          vse->_vs_name, i, vs_p[i].value, vs_p[i].value, prev_value, prev_value);
                type = VS_LIN_SEARCH;
                break;
            }
            if (first_value > vs_p[i].value) {
                ws_warning("Extended value string '%s' forced to fall back to linear search:\n"
                          "  entry %u, value %u [%#x] < first entry, value %u [%#x]",
                          vse->_vs_name, i, vs_p[i].value, vs_p[i].value, first_value, first_value);
                type = VS_LIN_SEARCH;
                break;
            }
        }

        prev_value = vs_p[i].value;
    }

    switch (type) {
        case VS_LIN_SEARCH:
            vse->_vs_match2 = _try_val_to_str_linear;
            break;
        case VS_BIN_SEARCH:
            vse->_vs_match2 = _try_val_to_str_bsearch;
            break;
        case VS_INDEX:
            vse->_vs_match2 = _try_val_to_str_index;
            break;
        default:
            ws_assert_not_reached();
            break;
    }

    return vse->_vs_match2(val, vse);
}

/* EXTENDED 64-BIT VALUE STRING */

/* Extended value strings allow fast(er) val64_string array lookups by
 * using (if possible) direct access or a binary search of the array.
 *
 * If the values in the val64_string array are a contiguous range of values
 * from min to max, the value will be used as a direct index into the array.
 *
 * If the values in the array are not contiguous (ie: there are "gaps"),
 * but are in assending order a binary search will be used.
 *
 * If direct access or binary search cannot be used, then a linear search
 * is used and a warning is emitted.
 *
 * Note that the val64_string array used with VAL64_STRING_EXT_INIT
 * *must* be terminated with {0, NULL}).
 *
 * Extended value strings are defined at compile time as follows:
 *   static const val64_string vs[] = { {value1, "string1"},
 *                                      {value2, "string2"},
 *                                      ...,
 *                                      {0, NULL}};
 *   static val64_string_ext vse = VAL64_STRING_EXT_INIT(vs);
 *
 * Extended value strings can be created at runtime by calling
 *   val64_string_ext_new(<ptr to val64_string array>,
 *                        <total number of entries in the val64_string_array>,
 *                        <val64_string_name>);
 * Note: The <total number of entries in the val64_string_array> should include
 *       the {0, NULL} entry.
 */

/* Create a val64_string_ext given a ptr to a val64_string array and the total
 * number of entries. Note that the total number of entries should include the
 * required {0, NULL} terminating entry of the array.
 * Returns a pointer to an epan-scoped'd and initialized val64_string_ext
 * struct. */
val64_string_ext *
val64_string_ext_new(const val64_string *vs, unsigned vs_tot_num_entries,
        const char *vs_name)
{
    val64_string_ext *vse;

    DISSECTOR_ASSERT (vs_name != NULL);
    DISSECTOR_ASSERT (vs_tot_num_entries > 0);
    /* Null-terminated value-string ? */
    DISSECTOR_ASSERT (vs[vs_tot_num_entries-1].strptr == NULL);

    vse                  = wmem_new(wmem_epan_scope(), val64_string_ext);
    vse->_vs_p           = vs;
    vse->_vs_num_entries = vs_tot_num_entries - 1;
    /* We set our 'match' function to the init function, which finishes by
     * setting the match function properly and then calling it. This is a
     * simple way to do lazy initialization of extended value strings.
     * The init function also sets up _vs_first_value for us. */
    vse->_vs_first_value = 0;
    vse->_vs_match2      = _try_val64_to_str_ext_init;
    vse->_vs_name        = vs_name;

    return vse;
}

void
val64_string_ext_free(val64_string_ext *vse)
{
    wmem_free(wmem_epan_scope(), vse);
}

/* Like try_val_to_str for extended value strings */
const char *
try_val64_to_str_ext(const uint64_t val, val64_string_ext *vse)
{
    if (vse) {
        const val64_string *vs = vse->_vs_match2(val, vse);

        if (vs) {
            return vs->strptr;
        }
    }

    return NULL;
}

/* Like try_val_to_str_idx for extended value strings */
const char *
try_val64_to_str_idx_ext(const uint64_t val, val64_string_ext *vse, int *idx)
{
    if (vse) {
        const val64_string *vs = vse->_vs_match2(val, vse);
        if (vs) {
            *idx = (int) (vs - vse->_vs_p);
            return vs->strptr;
        }
    }
    *idx = -1;
    return NULL;
}

/* Like val_to_str for extended value strings */
const char *
val64_to_str_ext(const uint64_t val, val64_string_ext *vse, const char *fmt)
{
    const char *ret;

    DISSECTOR_ASSERT(fmt != NULL);

    ret = try_val64_to_str_ext(val, vse);
    if (ret != NULL)
        return ret;

    return wmem_strdup_printf(wmem_packet_scope(), fmt, val);
}

char *
val64_to_str_ext_wmem(wmem_allocator_t *scope, const uint64_t val, val64_string_ext *vse, const char *fmt)
{
    const char *ret;

    DISSECTOR_ASSERT(fmt != NULL);

    ret = try_val64_to_str_ext(val, vse);
    if (ret != NULL)
        return wmem_strdup(scope, ret);

    return wmem_strdup_printf(scope, fmt, val);
}

/* Like val_to_str_const for extended value strings */
const char *
val64_to_str_ext_const(const uint64_t val, val64_string_ext *vse,
        const char *unknown_str)
{
    const char *ret;

    DISSECTOR_ASSERT(unknown_str != NULL);

    ret = try_val64_to_str_ext(val, vse);
    if (ret != NULL)
        return ret;

    return unknown_str;
}

/* Fallback linear matching algorithm for extended value strings */
static const val64_string *
_try_val64_to_str_linear(const uint64_t val, val64_string_ext *vse)
{
    const val64_string *vs_p = vse->_vs_p;
    unsigned i;
    for (i=0; i<vse->_vs_num_entries; i++) {
        if (vs_p[i].value == val)
            return &(vs_p[i]);
    }
    return NULL;
}

/* Constant-time matching algorithm for contiguous extended value strings */
static const val64_string *
_try_val64_to_str_index(const uint64_t val, val64_string_ext *vse)
{
    uint64_t i;

    i = val - vse->_vs_first_value;
    if (i < vse->_vs_num_entries) {
        ws_assert (val == vse->_vs_p[i].value);
        return &(vse->_vs_p[i]);
    }
    return NULL;
}

/* Value comparator for sorted extended value strings */
static int
val64_to_str_compar(const void *v_needle, const void *v_item)
{
    uint64_t needle = *(const uint64_t *)v_needle;
    uint64_t value = ((const val64_string *)v_item)->value;
    return needle > value ? 1 : (needle < value ? -1 : 0);
}

/* log(n)-time matching for sorted extended value strings */
static const val64_string *
_try_val64_to_str_bsearch(const uint64_t val, val64_string_ext *vse)
{
    return bsearch(&val, vse->_vs_p, vse->_vs_num_entries,
                   sizeof vse->_vs_p[0], val64_to_str_compar);
}

/* Initializes an extended value string. Behaves like a match function to
 * permit lazy initialization of extended value strings.
 * - Goes through the val64_string array to determine the fastest possible
 *   access method.
 * - Verifies that the val64_string contains no NULL string pointers.
 * - Verifies that the val64_string is terminated by {0, NULL}
 */
const val64_string *
_try_val64_to_str_ext_init(const uint64_t val, val64_string_ext *vse)
{
    const val64_string *vs_p           = vse->_vs_p;
    const unsigned      vs_num_entries = vse->_vs_num_entries;

    /* The matching algorithm used:
     * VS_LIN_SEARCH - slow linear search (as in a normal value string)
     * VS_BIN_SEARCH - log(n)-time binary search, the values must be sorted
     * VS_INDEX      - constant-time index lookup, the values must be contiguous
     */
    enum { VS_LIN_SEARCH, VS_BIN_SEARCH, VS_INDEX } type = VS_INDEX;

    /* Note: The val64_string 'value' is *unsigned*, but we do a little magic
     * to help with value strings that have negative values.
     *
     * { -3, -2, -1, 0, 1, 2 }
     * will be treated as "ascending ordered" (although it isn't technically),
     * thus allowing constant-time index search
     *
     * { -3, -2, 0, 1, 2 } and { -3, -2, -1, 0, 2 }
     * will both be considered as "out-of-order with gaps", thus falling
     * back to the slow linear search
     *
     * { 0, 1, 2, -3, -2 } and { 0, 2, -3, -2, -1 }
     * will be considered "ascending ordered with gaps" thus allowing
     * a log(n)-time 'binary' search
     *
     * If you're confused, think of how negative values are represented, or
     * google two's complement.
     */

    uint64_t prev_value;
    uint64_t first_value;
    unsigned   i;

    DISSECTOR_ASSERT((vs_p[vs_num_entries].value  == 0) &&
                     (vs_p[vs_num_entries].strptr == NULL));

    vse->_vs_first_value = vs_p[0].value;
    first_value          = vs_p[0].value;
    prev_value           = first_value;

    for (i = 0; i < vs_num_entries; i++) {
        DISSECTOR_ASSERT(vs_p[i].strptr != NULL);
        if ((type == VS_INDEX) && (vs_p[i].value != (i + first_value))) {
            type = VS_BIN_SEARCH;
        }
        /* XXX: Should check for dups ?? */
        if (type == VS_BIN_SEARCH) {
            if (prev_value > vs_p[i].value) {
                ws_warning("Extended value string '%s' forced to fall back to linear search:\n"
                          "  entry %u, value %" PRIu64 " [%#" PRIx64 "] < previous entry, value %" PRIu64 " [%#" PRIx64 "]",
                          vse->_vs_name, i, vs_p[i].value, vs_p[i].value, prev_value, prev_value);
                type = VS_LIN_SEARCH;
                break;
            }
            if (first_value > vs_p[i].value) {
                ws_warning("Extended value string '%s' forced to fall back to linear search:\n"
                          "  entry %u, value %" PRIu64 " [%#" PRIx64 "] < first entry, value %" PRIu64 " [%#" PRIx64 "]",
                          vse->_vs_name, i, vs_p[i].value, vs_p[i].value, first_value, first_value);
                type = VS_LIN_SEARCH;
                break;
            }
        }

        prev_value = vs_p[i].value;
    }

    switch (type) {
        case VS_LIN_SEARCH:
            vse->_vs_match2 = _try_val64_to_str_linear;
            break;
        case VS_BIN_SEARCH:
            vse->_vs_match2 = _try_val64_to_str_bsearch;
            break;
        case VS_INDEX:
            vse->_vs_match2 = _try_val64_to_str_index;
            break;
        default:
            ws_assert_not_reached();
            break;
    }

    return vse->_vs_match2(val, vse);
}

/* STRING TO STRING MATCHING */

/* string_string is like value_string except the values being matched are
 * also strings (instead of unsigned integers) */

/* Like val_to_str except for string_string */
const char *
str_to_str(const char *val, const string_string *vs, const char *fmt)
{
    const char *ret;

    DISSECTOR_ASSERT(fmt != NULL);

    ret = try_str_to_str(val, vs);
    if (ret != NULL)
        return ret;

    return wmem_strdup_printf(wmem_packet_scope(), fmt, val);
}

/* Like try_val_to_str_idx except for string_string */
const char *
try_str_to_str_idx(const char *val, const string_string *vs, int *idx)
{
    int i = 0;

    if(vs) {
        while (vs[i].strptr) {
            if (!strcmp(vs[i].value,val)) {
                *idx = i;
                return(vs[i].strptr);
            }
            i++;
        }
    }

    *idx = -1;
    return NULL;
}

/* Like try_val_to_str except for string_string */
const char *
try_str_to_str(const char *val, const string_string *vs)
{
    int ignore_me;
    return try_str_to_str_idx(val, vs, &ignore_me);
}

/* RANGE TO STRING MATCHING */

/* range_string is like value_string except the values being matched are
 * integer ranges (for example, 0-10, 11-19, etc.) instead of single values. */

/* Like val_to_str except for range_string */
const char *
rval_to_str(const uint32_t val, const range_string *rs, const char *fmt)
{
    const char *ret = NULL;

    DISSECTOR_ASSERT(fmt != NULL);

    ret = try_rval_to_str(val, rs);
    if(ret != NULL)
        return ret;

    return wmem_strdup_printf(wmem_packet_scope(), fmt, val);
}

/* Like val_to_str_const except for range_string */
const char *
rval_to_str_const(const uint32_t val, const range_string *rs,
        const char *unknown_str)
{
    const char *ret = NULL;

    DISSECTOR_ASSERT(unknown_str != NULL);

    ret = try_rval_to_str(val, rs);
    if(ret != NULL)
        return ret;

    return unknown_str;
}

/* Like try_val_to_str_idx except for range_string */
const char *
try_rval_to_str_idx(const uint32_t val, const range_string *rs, int *idx)
{
    int i = 0;

    if(rs) {
        while(rs[i].strptr) {
            if( (val >= rs[i].value_min) && (val <= rs[i].value_max) ) {
                *idx = i;
                return (rs[i].strptr);
            }
            i++;
        }
    }

    *idx = -1;
    return NULL;
}

/* Like try_val_to_str except for range_string */
const char *
try_rval_to_str(const uint32_t val, const range_string *rs)
{
    int ignore_me = 0;
    return try_rval_to_str_idx(val, rs, &ignore_me);
}

/* Like try_val_to_str_idx except for range_string */
const char *
try_rval64_to_str_idx(const uint64_t val, const range_string *rs, int *idx)
{
    int i = 0;

    if(rs) {
        while(rs[i].strptr) {
            if( (val >= rs[i].value_min) && (val <= rs[i].value_max) ) {
                *idx = i;
                return (rs[i].strptr);
            }
            i++;
        }
    }

    *idx = -1;
    return NULL;
}

/* Like try_val64_to_str except for range_string */
const char *
try_rval64_to_str(const uint64_t val, const range_string *rs)
{
    int ignore_me = 0;
    return try_rval64_to_str_idx(val, rs, &ignore_me);
}


/* BYTE BUFFER TO STRING MATCHING */

/* Like val_to_str except for bytes_string */
const char *
bytesval_to_str(const uint8_t *val, const size_t val_len, const bytes_string *bs, const char *fmt)
{
    const char *ret;

    DISSECTOR_ASSERT(fmt != NULL);

    ret = try_bytesval_to_str(val, val_len, bs);
    if (ret != NULL)
        return ret;

    /*
     * XXX should this use bytes_to_str as format parameter for consistency?
     * Though for bytes I guess most of the time you want to show "Unknown"
     * anyway rather than "Unknown (\x13\x37...)"
     */
    return wmem_strdup(wmem_packet_scope(), fmt);
}

/* Like try_val_to_str except for bytes_string */
const char *
try_bytesval_to_str(const uint8_t *val, const size_t val_len, const bytes_string *bs)
{
    unsigned i = 0;

    if (bs) {
        while (bs[i].strptr) {
            if (bs[i].value_length == val_len && !memcmp(bs[i].value, val, val_len)) {
                return bs[i].strptr;
            }
            i++;
        }
    }

    return NULL;
}

/* Like val_to_str, but tries to find a prefix (instead of an exact) match
   of any prefix from the bytes_string array bs against the haystack. */
const char *
bytesprefix_to_str(const uint8_t *haystack, const size_t haystack_len, const bytes_string *bs, const char *fmt)
{
    const char *ret;

    DISSECTOR_ASSERT(fmt != NULL);

    ret = try_bytesprefix_to_str(haystack, haystack_len, bs);
    if (ret != NULL)
        return ret;

    /* XXX See note at bytesval_to_str. */
    return wmem_strdup(wmem_packet_scope(), fmt);
}

/* Like try_val_to_str, but tries to find a prefix (instead of an exact) match
   of any prefix from the bytes_string array bs against the haystack. */
const char *
try_bytesprefix_to_str(const uint8_t *haystack, const size_t haystack_len, const bytes_string *bs)
{
    unsigned i = 0;

    if (bs) {
        while (bs[i].strptr) {
            if (haystack_len >= bs[i].value_length &&
                !memcmp(bs[i].value, haystack, bs[i].value_length)) {
                return bs[i].strptr;
            }
            i++;
        }
    }

    return NULL;
}

/* MISC */

/* Functions for use by proto_registrar_dump_values(), see proto.c */

bool
value_string_ext_validate(const value_string_ext *vse)
{
    if (vse == NULL)
        return false;
#ifndef _WIN32  /* doesn't work on Windows for refs from another DLL ?? */
    if ((vse->_vs_match2 != _try_val_to_str_ext_init) &&
        (vse->_vs_match2 != _try_val_to_str_linear)   &&
        (vse->_vs_match2 != _try_val_to_str_bsearch)  &&
        (vse->_vs_match2 != _try_val_to_str_index))
        return false;
#endif
    return true;
}

const char *
value_string_ext_match_type_str(const value_string_ext *vse)
{
    if (vse->_vs_match2 == _try_val_to_str_ext_init)
        return "[Not Initialized]";
    if (vse->_vs_match2 == _try_val_to_str_linear)
        return "[Linear Search]";
    if (vse->_vs_match2 == _try_val_to_str_bsearch)
        return "[Binary Search]";
    if (vse->_vs_match2 == _try_val_to_str_index)
        return "[Direct (indexed) Access]";
    return "[Invalid]";
}

bool
val64_string_ext_validate(const val64_string_ext *vse)
{
    if (vse == NULL)
        return false;
#ifndef _WIN32  /* doesn't work on Windows for refs from another DLL ?? */
    if ((vse->_vs_match2 != _try_val64_to_str_ext_init) &&
        (vse->_vs_match2 != _try_val64_to_str_linear)   &&
        (vse->_vs_match2 != _try_val64_to_str_bsearch)  &&
        (vse->_vs_match2 != _try_val64_to_str_index))
        return false;
#endif
    return true;
}

const char *
val64_string_ext_match_type_str(const val64_string_ext *vse)
{
    if (vse->_vs_match2 == _try_val64_to_str_ext_init)
        return "[Not Initialized]";
    if (vse->_vs_match2 == _try_val64_to_str_linear)
        return "[Linear Search]";
    if (vse->_vs_match2 == _try_val64_to_str_bsearch)
        return "[Binary Search]";
    if (vse->_vs_match2 == _try_val64_to_str_index)
        return "[Direct (indexed) Access]";
    return "[Invalid]";
}

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
