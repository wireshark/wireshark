/*
 * Wireshark - Network traffic analyzer
 *
 * Copyright 2006 Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_DFILTER

#include <wireshark.h>

#include "dfilter-int.h"
#include "dfunctions.h"
#include "dfilter-plugin.h"
#include "sttype-field.h"
#include "sttype-pointer.h"
#include "semcheck.h"

#include <string.h>

#include <ftypes/ftypes.h>
#include <epan/exceptions.h>
#include <wsutil/ws_assert.h>


static GHashTable *registered_functions;

static GPtrArray *registered_names;

/* Convert an FT_STRING using a callback function */
static bool
string_walk(GSList *stack, uint32_t arg_count _U_, df_cell_t *retval, char(*conv_func)(char))
{
    GPtrArray   *arg1;
    fvalue_t    *arg_fvalue;
    fvalue_t    *new_ft_string;
    const wmem_strbuf_t *src;
    wmem_strbuf_t       *dst;

    ws_assert(arg_count == 1);
    arg1 = stack->data;
    if (arg1 == NULL)
        return false;

    for (unsigned i = 0; i < arg1->len; i++) {
        arg_fvalue = arg1->pdata[i];
        /* XXX - it would be nice to handle FT_TVBUFF, too */
        if (FT_IS_STRING(fvalue_type_ftenum(arg_fvalue))) {
            src = fvalue_get_strbuf(arg_fvalue);
            dst = wmem_strbuf_new_sized(NULL, src->len);
            for (size_t j = 0; j < src->len; j++) {
                    wmem_strbuf_append_c(dst, conv_func(src->str[j]));
            }
            new_ft_string = fvalue_new(FT_STRING);
            fvalue_set_strbuf(new_ft_string, dst);
            df_cell_append(retval, new_ft_string);
        }
    }

    return true;
}

/* dfilter function: lower() */
static bool
df_func_lower(GSList *stack, uint32_t arg_count, df_cell_t *retval)
{
    return string_walk(stack, arg_count, retval, g_ascii_tolower);
}

/* dfilter function: upper() */
static bool
df_func_upper(GSList *stack, uint32_t arg_count, df_cell_t *retval)
{
    return string_walk(stack, arg_count, retval, g_ascii_toupper);
}

/* dfilter function: count() */
static bool
df_func_count(GSList *stack, uint32_t arg_count _U_, df_cell_t *retval)
{
    GPtrArray *arg1;
    fvalue_t *ft_ret;
    uint32_t  num_items;

    ws_assert(arg_count == 1);
    arg1 = stack->data;
    if (arg1 == NULL)
        return false;

    num_items = arg1->len;
    ft_ret = fvalue_new(FT_UINT32);
    fvalue_set_uinteger(ft_ret, num_items);
    df_cell_append(retval, ft_ret);

    return true;
}

/* dfilter function: string() */
static bool
df_func_string(GSList *stack, uint32_t arg_count _U_, df_cell_t *retval)
{
    GPtrArray *arg1;
    fvalue_t *arg_fvalue;
    fvalue_t *new_ft_string;
    char     *s;

    ws_assert(arg_count == 1);
    arg1 = stack->data;
    if (arg1 == NULL)
        return false;

    for (unsigned i = 0; i < arg1->len; i++) {
        arg_fvalue = arg1->pdata[i];
        switch (fvalue_type_ftenum(arg_fvalue))
        {
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
        case FT_UINT40:
        case FT_UINT48:
        case FT_UINT56:
        case FT_UINT64:
        case FT_INT8:
        case FT_INT16:
        case FT_INT32:
        case FT_INT40:
        case FT_INT48:
        case FT_INT56:
        case FT_INT64:
        case FT_IPv4:
        case FT_IPv6:
        case FT_FLOAT:
        case FT_DOUBLE:
        case FT_ETHER:
        case FT_FRAMENUM:
        case FT_AX25:
        case FT_IPXNET:
        case FT_GUID:
        case FT_OID:
        case FT_EUI64:
        case FT_VINES:
        case FT_REL_OID:
        case FT_SYSTEM_ID:
        case FT_FCWWN:
        case FT_IEEE_11073_SFLOAT:
        case FT_IEEE_11073_FLOAT:
            s = fvalue_to_string_repr(NULL, arg_fvalue, FTREPR_DFILTER, BASE_NONE);
            /* Ensure we have an allocated string here */
            if (!s)
                s = wmem_strdup(NULL, "");
            break;
        default:
            return true;
        }

        new_ft_string = fvalue_new(FT_STRING);
        fvalue_set_string(new_ft_string, s);
        wmem_free(NULL, s);
        df_cell_append(retval, new_ft_string);
    }

    return true;
}

/* dfilter functions: dec(), hex(), */
static bool
df_func_base(GSList *stack, uint32_t arg_count _U_, df_cell_t *retval, int base)
{
    GPtrArray *arg1;
    fvalue_t *arg_fvalue;
    fvalue_t *new_ft_string;
    char     *s;

    ws_assert(arg_count == 1);
    arg1 = stack->data;
    if (arg1 == NULL)
        return false;

    for (unsigned i = 0; i < arg1->len; i++) {
        arg_fvalue = arg1->pdata[i];

        if (FT_IS_UINT(fvalue_type_ftenum(arg_fvalue))) {
            s = fvalue_to_string_repr(NULL, arg_fvalue, FTREPR_DFILTER, base);
            /* Ensure we have an allocated string here */
            if (!s)
                s = wmem_strdup(NULL, "");
        } else {
            /* XXX - We have, unfortunately, some field abbreviations which are
             * re-used with incompatible types, some of which support different
             * bases and some which don't.
             */
            s = wmem_strdup(NULL, "");
        }

        new_ft_string = fvalue_new(FT_STRING);
        fvalue_set_string(new_ft_string, s);
        wmem_free(NULL, s);
        df_cell_append(retval, new_ft_string);
    }

    return true;
}

static bool
df_func_hex(GSList *stack, uint32_t arg_count _U_, df_cell_t *retval)
{
    return df_func_base(stack, arg_count, retval, BASE_HEX);
}

static bool
df_func_dec(GSList *stack, uint32_t arg_count _U_, df_cell_t *retval)
{
    return df_func_base(stack, arg_count, retval, BASE_DEC);
}

#if 0
// XXX - BASE_OCT isn't handled by fvalue_to_string_repr; it probably
// should at least for FTREPR_DISPLAY (the filter language doesn't
// support it due to possible notation confusion, I assume.)
// Add that first before offering it.
static bool
df_func_oct(GSList *stack, uint32_t arg_count _U_, df_cell_t *retval)
{
    return df_func_base(stack, arg_count, retval, BASE_OCT);
}
#endif

static bool
df_func_compare(GSList *stack, uint32_t arg_count, df_cell_t *retval,
                    bool (*fv_cmp)(const fvalue_t *a, const fvalue_t *b))
{
    fvalue_t *fv_ret = NULL;
    GSList   *args;
    GPtrArray *arg1;
    fvalue_t *arg_fvalue;
    uint32_t i;

    for (args = stack, i = 0; i < arg_count; args = args->next, i++) {
        arg1 = args->data;
        if (arg1 != NULL) {
            for (unsigned j = 0; j < arg1->len; j++) {
                arg_fvalue = arg1->pdata[j];
                if (fv_ret == NULL || fv_cmp(arg_fvalue, fv_ret)) {
                    fv_ret = arg_fvalue;
                }
            }
        }
    }

    if (fv_ret == NULL)
        return false;

    df_cell_append(retval, fvalue_dup(fv_ret));

    return true;
}

/* Find maximum value. */
static bool
df_func_max(GSList *stack, uint32_t arg_count, df_cell_t *retval)
{
    return df_func_compare(stack, arg_count, retval, fvalue_gt);
}

/* Find minimum value. */
static bool
df_func_min(GSList *stack, uint32_t arg_count, df_cell_t *retval)
{
    return df_func_compare(stack, arg_count, retval, fvalue_lt);
}

static bool
df_func_abs(GSList *stack, uint32_t arg_count _U_, df_cell_t *retval)
{
    GPtrArray *arg1;
    fvalue_t *fv_arg, *new_fv;
    char     *err_msg = NULL;

    ws_assert(arg_count == 1);
    arg1 = stack->data;
    if (arg1 == NULL)
        return false;

    for (unsigned i = 0; i < arg1->len; i++) {
        fv_arg = arg1->pdata[i];
        if (fvalue_is_negative(fv_arg)) {
            new_fv = fvalue_unary_minus(fv_arg, &err_msg);
            if (new_fv == NULL) {
                ws_debug("abs: %s", err_msg);
                g_free(err_msg);
                err_msg = NULL;
            }
        }
        else {
            new_fv = fvalue_dup(fv_arg);
        }
        df_cell_append(retval, new_fv);
    }

    return !df_cell_is_empty(retval);
}

ftenum_t
df_semcheck_param(dfwork_t *dfw, const char *func_name _U_, ftenum_t logical_ftype,
                            stnode_t *param, df_loc_t func_loc _U_)
{
    ftenum_t ftype = FT_NONE;

    resolve_unparsed(dfw, param, false);

    switch (stnode_type_id(param)) {
        case STTYPE_ARITHMETIC:
            ftype = check_arithmetic(dfw, param, logical_ftype);
            break;

        case STTYPE_LITERAL:
            dfilter_fvalue_from_literal(dfw, logical_ftype, param, false, NULL);
            ftype = sttype_pointer_ftenum(param);
            break;

        case STTYPE_STRING:
            dfilter_fvalue_from_string(dfw, logical_ftype, param, NULL);
            ftype = sttype_pointer_ftenum(param);
            break;

        case STTYPE_CHARCONST:
            dfilter_fvalue_from_charconst(dfw, logical_ftype, param);
            ftype = sttype_pointer_ftenum(param);
            break;

        case STTYPE_NUMBER:
            dfilter_fvalue_from_number(dfw, logical_ftype, param);
            ftype = sttype_pointer_ftenum(param);
            break;

        case STTYPE_FUNCTION:
            ftype = check_function(dfw, param, logical_ftype);
            break;

        case STTYPE_FIELD:
            dfw->field_count++;
            /* fall-through */
        case STTYPE_REFERENCE:
            ftype = sttype_field_ftenum(param);
            break;

        case STTYPE_SLICE:
            ftype = check_slice(dfw, param, logical_ftype);
            break;

        case STTYPE_UNPARSED:
        case STTYPE_TEST:
        case STTYPE_FVALUE:
        case STTYPE_PCRE:
        case STTYPE_SET:
        case STTYPE_UNINITIALIZED:
        case STTYPE_NUM_TYPES:
            ASSERT_STTYPE_NOT_REACHED(stnode_type_id(param));
    }

    return ftype;
}

/* For upper() and lower() checks that the parameter passed to
 * it is an FT_STRING */
static ftenum_t
ul_semcheck_is_string(dfwork_t *dfw, const char *func_name, ftenum_t logical_ftype _U_,
                            GSList *param_list, df_loc_t func_loc _U_)
{
    ws_assert(g_slist_length(param_list) == 1);
    stnode_t *param = param_list->data;
    ftenum_t ftype;

    resolve_unparsed(dfw, param, true);

    ftype = df_semcheck_param(dfw, func_name, logical_ftype, param, func_loc);
    if (!FT_IS_STRING(ftype)) {
        dfunc_fail(dfw, param, "Only string type fields can be used as parameter for %s()", func_name);
    }
    return FT_STRING;
}

static ftenum_t
ul_semcheck_is_field(dfwork_t *dfw, const char *func_name, ftenum_t logical_ftype _U_,
                            GSList *param_list, df_loc_t func_loc _U_)
{
    ws_assert(g_slist_length(param_list) == 1);
    stnode_t *param = param_list->data;

    resolve_unparsed(dfw, param, true);

    if (stnode_type_id(param) != STTYPE_FIELD) {
        dfunc_fail(dfw, param, "Only fields can be used as parameter for %s()", func_name);
    }
    df_semcheck_param(dfw, func_name, logical_ftype, param, func_loc);
    return FT_UINT32;
}

static ftenum_t
ul_semcheck_can_length(dfwork_t *dfw, const char *func_name, ftenum_t logical_ftype,
                            GSList *param_list, df_loc_t func_loc)
{
    ws_assert(g_slist_length(param_list) == 1);
    stnode_t *param = param_list->data;
    ftenum_t ftype;

    ftype = df_semcheck_param(dfw, func_name, logical_ftype, param, func_loc);
    if (!ftype_can_length(ftype)) {
        dfunc_fail(dfw, param, "Argument does not support the %s() function", func_name);
    }
    return FT_UINT32;
}

static ftenum_t
ul_semcheck_string(dfwork_t *dfw, const char *func_name, ftenum_t logical_ftype _U_,
                            GSList *param_list, df_loc_t func_loc _U_)
{
    header_field_info *hfinfo;

    ws_assert(g_slist_length(param_list) == 1);
    stnode_t *param = param_list->data;

    resolve_unparsed(dfw, param, true);

    if (stnode_type_id(param) == STTYPE_FIELD) {
        dfw->field_count++;
        hfinfo = sttype_field_hfinfo(param);
        switch (hfinfo->type) {
            case FT_UINT8:
            case FT_UINT16:
            case FT_UINT24:
            case FT_UINT32:
            case FT_UINT40:
            case FT_UINT48:
            case FT_UINT56:
            case FT_UINT64:
            case FT_INT8:
            case FT_INT16:
            case FT_INT32:
            case FT_INT40:
            case FT_INT48:
            case FT_INT56:
            case FT_INT64:
            case FT_IPv4:
            case FT_IPv6:
            case FT_FLOAT:
            case FT_DOUBLE:
            case FT_ETHER:
            case FT_FRAMENUM:
            case FT_AX25:
            case FT_IPXNET:
            case FT_GUID:
            case FT_OID:
            case FT_EUI64:
            case FT_VINES:
            case FT_REL_OID:
            case FT_SYSTEM_ID:
            case FT_FCWWN:
            case FT_IEEE_11073_SFLOAT:
            case FT_IEEE_11073_FLOAT:
                return FT_STRING;
            default:
                break;
        }
        dfunc_fail(dfw, param, "String conversion for field \"%s\" is not supported", hfinfo->abbrev);
    }
    dfunc_fail(dfw, param, "Only fields can be used as parameter for %s()", func_name);
}

static ftenum_t
ul_semcheck_base(dfwork_t *dfw, const char *func_name, ftenum_t logical_ftype _U_,
                            GSList *param_list, df_loc_t func_loc _U_)
{
    header_field_info *hfinfo;

    ws_assert(g_slist_length(param_list) == 1);
    stnode_t *param = param_list->data;

    resolve_unparsed(dfw, param, true);

    if (stnode_type_id(param) == STTYPE_FIELD) {
        dfw->field_count++;
        hfinfo = sttype_field_hfinfo(param);
        /* FT_CHAR also supports BASE_, but for what sort of escaped
         * values to use for non-printable ASCII. BASE_HEX uses hex,
         * all other bases will use octal.
         * That's a little confusing, so don't support it for now.
         * More useful might be to display all possible values as
         * HEX or DEC, i.e. convert to a FT_UINT8 first. */
        if (FT_IS_UINT(hfinfo->type)) {
            return FT_STRING;
        }
        dfunc_fail(dfw, param, "Base conversion for field \"%s\" is not supported", hfinfo->abbrev);
    }
    dfunc_fail(dfw, param, "Only fields can be used as parameter for %s()", func_name);
}

static ftenum_t
ul_semcheck_value_string(dfwork_t *dfw, const char *func_name, ftenum_t logical_ftype _U_,
                            GSList *param_list, df_loc_t func_loc _U_)
{
    header_field_info *hfinfo;

    ws_assert(g_slist_length(param_list) == 1);
    stnode_t *param = param_list->data;

    resolve_unparsed(dfw, param, true);

    if (stnode_type_id(param) == STTYPE_FIELD) {
        dfw->field_count++;
        hfinfo = sttype_field_hfinfo(param);
        if (hfinfo->strings != NULL && hfinfo->type != FT_FRAMENUM && hfinfo->type != FT_PROTOCOL) {
            sttype_field_set_value_string(param, true);
            return FT_STRING;
        }
        dfunc_fail(dfw, param, "Field \"%s\" does not have a value string.",
				hfinfo->abbrev);
    }
    dfunc_fail(dfw, param, "Only fields can be used as parameter for %s()", func_name);
}

/* Check arguments are all the same type and they can be compared. */
static ftenum_t
ul_semcheck_compare(dfwork_t *dfw, const char *func_name, ftenum_t logical_ftype,
                        GSList *param_list, df_loc_t func_loc)
{
    stnode_t *param;
    ftenum_t ftype;
    GSList *l;

    for (l = param_list; l != NULL; l = l->next) {
        param = l->data;
        ftype = df_semcheck_param(dfw, func_name, logical_ftype, param, func_loc);

        if (!compatible_ftypes(ftype, logical_ftype)) {
            dfunc_fail(dfw, param, "Arguments to '%s' must be of compatible type (expected %s, got %s)",
                                        func_name, ftype_pretty_name(logical_ftype), ftype_pretty_name(ftype));
        }
        if (!ftype_can_cmp(ftype)) {
            dfunc_fail(dfw, param, "Argument '%s' to '%s' cannot be ordered",
                                    stnode_todisplay(param), func_name);
        }
    }

    return logical_ftype;
}

static ftenum_t
ul_semcheck_absolute_value(dfwork_t *dfw, const char *func_name, ftenum_t logical_ftype,
                        GSList *param_list, df_loc_t func_loc)
{
    ws_assert(g_slist_length(param_list) == 1);
    stnode_t *param = param_list->data;
    ftenum_t ftype;

    ftype = df_semcheck_param(dfw, func_name, logical_ftype, param, func_loc);
    if (!ftype_can_is_negative(ftype) || !ftype_can_unary_minus(ftype)) {
        dfunc_fail(dfw, param, "Argument cannot be negated");
    }
    return ftype;
}

/* The table of all display-filter functions */
static df_func_def_t
df_functions[] = {
    { "lower",  df_func_lower,  1, 1, FT_STRING, ul_semcheck_is_string },
    { "upper",  df_func_upper,  1, 1, FT_STRING, ul_semcheck_is_string },
    /* Length function is implemented as a DFVM instruction. */
    { "len",    NULL,           1, 1, FT_UINT32, ul_semcheck_can_length },
    { "count",  df_func_count,  1, 1, FT_UINT32, ul_semcheck_is_field },
    { "string", df_func_string, 1, 1, FT_STRING, ul_semcheck_string },
    { "dec",    df_func_dec,    1, 1, FT_STRING, ul_semcheck_base },
    { "hex",    df_func_hex,    1, 1, FT_STRING, ul_semcheck_base },
    //{ "oct",    df_func_oct,    1, 1, FT_STRING, ul_semcheck_base },
    /* VALUE STRING function is implemented as a DFVM instruction. */
    { "vals",   NULL,           1, 1, FT_STRING, ul_semcheck_value_string },
    { "max",    df_func_max,    1, 0, FT_NONE, ul_semcheck_compare },
    { "min",    df_func_min,    1, 0, FT_NONE, ul_semcheck_compare },
    { "abs",    df_func_abs,    1, 1, FT_NONE, ul_semcheck_absolute_value },
    { NULL, NULL, 0, 0, FT_NONE, NULL }
};

/* Returns NULL for success. */
static const char *
check_valid_func_name(const char *name)
{
    if (!g_ascii_isalpha(name[0]) && name[0] != '_') {
        return "first character must be a letter or underscore";
    }
    for (int i = 1; name[i] != '\0'; i++) {
        if (!g_ascii_isalnum(name[0]) && name[0] != '_') {
            return "function names must be alphanumeric plus underscore";
        }
    }
    return NULL;
}

void
df_func_init(void)
{
    df_func_def_t *func;

    registered_functions = g_hash_table_new(g_str_hash, g_str_equal);
    registered_names = g_ptr_array_new();

    /* Register built-in functions. */
    for (func = df_functions; func->name != NULL; func++) {
        df_func_register(func);
    }
}

bool
df_func_register(df_func_def_t *func)
{
    ws_assert(registered_functions);
    ws_assert(registered_names);
    const char *err;
    if ((err = check_valid_func_name(func->name)) != NULL) {
        ws_critical("Function name \"%s\" is invalid: %s",
                    func->name, err);
        return false;
    }
    if (g_hash_table_contains(registered_functions, func->name)) {
        ws_critical("Trying to register display filter function \"%s\" but "
                    "it already exists", func->name);
        return false;
    }

    g_ptr_array_add(registered_names, (gpointer)func->name);
    return g_hash_table_insert(registered_functions, (gpointer)func->name, func);
}

bool
df_func_deregister(df_func_def_t *func)
{
    ws_assert(registered_functions);
    df_func_def_t *value;

    value = g_hash_table_lookup(registered_functions, func->name);
    if (value != func) {
        ws_critical("Trying to deregister display filter function name \"%s\" but "
                    "it doesn't match the existing function", func->name);
        return false;
    }

    g_ptr_array_remove_fast(registered_names, (void *)func->name);
    return g_hash_table_remove(registered_functions, func->name);
}

/* Lookup a display filter function record by name */
df_func_def_t*
df_func_lookup(const char *name)
{
    return g_hash_table_lookup(registered_functions, name);
}

GPtrArray *
df_func_name_list(void)
{
    return g_ptr_array_ref(registered_names);
}

void
df_func_cleanup(void)
{
    g_hash_table_destroy(registered_functions);
    registered_functions = NULL;
    g_ptr_array_unref(registered_names);
    registered_names = NULL;
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
