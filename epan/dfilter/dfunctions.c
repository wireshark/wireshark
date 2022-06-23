/*
 * Wireshark - Network traffic analyzer
 *
 * Copyright 2006 Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include "dfilter-int.h"
#include "dfunctions.h"
#include "sttype-field.h"
#include "semcheck.h"

#include <string.h>

#include <ftypes/ftypes.h>
#include <epan/exceptions.h>
#include <wsutil/ws_assert.h>

#define FAIL(dfw, node, ...) \
	dfilter_fail_throw(dfw, stnode_location(node), __VA_ARGS__)

/* Convert an FT_STRING using a callback function */
static gboolean
string_walk(GSList *args, guint32 arg_count, GSList **retval, gchar(*conv_func)(gchar))
{
    GSList      *arg1;
    fvalue_t    *arg_fvalue;
    fvalue_t    *new_ft_string;
    const wmem_strbuf_t *src;
    wmem_strbuf_t       *dst;

    ws_assert(arg_count == 1);
    arg1 = args->data;
    if (arg1 == NULL)
        return FALSE;

    while (arg1) {
        arg_fvalue = (fvalue_t *)arg1->data;
        /* XXX - it would be nice to handle FT_TVBUFF, too */
        if (IS_FT_STRING(fvalue_type_ftenum(arg_fvalue))) {
            src = fvalue_get_strbuf(arg_fvalue);
            dst = wmem_strbuf_sized_new(NULL, src->len, 0);
            for (size_t i = 0; i < src->len; i++) {
                    wmem_strbuf_append_c(dst, conv_func(src->str[i]));
            }

            new_ft_string = fvalue_new(FT_STRING);
            fvalue_set_strbuf(new_ft_string, dst);
            *retval = g_slist_prepend(*retval, new_ft_string);
        }
        arg1 = arg1->next;
    }

    return TRUE;
}

/* dfilter function: lower() */
static gboolean
df_func_lower(GSList *args, guint32 arg_count, GSList **retval)
{
    return string_walk(args, arg_count, retval, g_ascii_tolower);
}

/* dfilter function: upper() */
static gboolean
df_func_upper(GSList *args, guint32 arg_count, GSList **retval)
{
    return string_walk(args, arg_count, retval, g_ascii_toupper);
}

/* dfilter function: len() */
static gboolean
df_func_len(GSList *args, guint32 arg_count, GSList **retval)
{
    GSList      *arg1;
    fvalue_t    *arg_fvalue;
    fvalue_t    *ft_len;

    ws_assert(arg_count == 1);
    arg1 = args->data;
    if (arg1 == NULL)
        return FALSE;

    while (arg1) {
        arg_fvalue = (fvalue_t *)arg1->data;
        ft_len = fvalue_new(FT_UINT32);
        fvalue_set_uinteger(ft_len, fvalue_length(arg_fvalue));
        *retval = g_slist_prepend(*retval, ft_len);
        arg1 = arg1->next;
    }

    return TRUE;
}

/* dfilter function: count() */
static gboolean
df_func_count(GSList *args, guint32 arg_count, GSList **retval)
{
    GSList   *arg1;
    fvalue_t *ft_ret;
    guint32   num_items;

    ws_assert(arg_count == 1);
    arg1 = args->data;
    if (arg1 == NULL)
        return FALSE;

    num_items = (guint32)g_slist_length(arg1);
    ft_ret = fvalue_new(FT_UINT32);
    fvalue_set_uinteger(ft_ret, num_items);
    *retval = g_slist_prepend(*retval, ft_ret);

    return TRUE;
}

/* dfilter function: string() */
static gboolean
df_func_string(GSList *args, guint32 arg_count, GSList **retval)
{
    GSList   *arg1;
    fvalue_t *arg_fvalue;
    fvalue_t *new_ft_string;
    char     *s;

    ws_assert(arg_count == 1);
    arg1 = args->data;
    if (arg1 == NULL)
        return FALSE;

    while (arg1) {
        arg_fvalue = (fvalue_t *)arg1->data;
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
            return TRUE;
        }

        new_ft_string = fvalue_new(FT_STRING);
        fvalue_set_string(new_ft_string, s);
        wmem_free(NULL, s);
        *retval = g_slist_prepend(*retval, new_ft_string);

        arg1 = arg1->next;
    }

    return TRUE;
}

static gboolean
df_func_compare(GSList *args, guint32 arg_count, GSList **retval,
                    gboolean (*fv_cmp)(const fvalue_t *a, const fvalue_t *b))
{
    fvalue_t *fv_ret = NULL;
    GSList   *l1, *l2;
    guint32 i;

    for (l1 = args, i = 0; i < arg_count; l1 = l1->next, i++) {
        for (l2 = l1->data; l2 != NULL; l2 = l2->next) {
            if (fv_ret == NULL || fv_cmp(l2->data, fv_ret)) {
                fv_ret = l2->data;
            }
        }
    }

    if (fv_ret == NULL)
        return FALSE;

    *retval = g_slist_append(NULL, fvalue_dup(fv_ret));

    return TRUE;
}

/* Find maximum value. */
static gboolean
df_func_max(GSList *args, guint32 arg_count, GSList **retval)
{
    return df_func_compare(args, arg_count, retval, fvalue_gt);
}

/* Find minimum value. */
static gboolean
df_func_min(GSList *args, guint32 arg_count, GSList **retval)
{
    return df_func_compare(args, arg_count, retval, fvalue_lt);
}

static gboolean
df_func_abs(GSList *args, guint32 arg_count, GSList **retval)
{
    GSList   *arg1;
    fvalue_t *fv_arg, *new_fv;
    char     *err_msg = NULL;
    GSList   *result = NULL;

    ws_assert(arg_count == 1);
    arg1 = args->data;
    if (arg1 == NULL)
        return FALSE;

    while (arg1) {
        fv_arg = arg1->data;
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
        result = g_slist_prepend(result, new_fv);
        arg1 = arg1->next;
    }

    if (g_slist_length(result) == 0)
        return FALSE;

    *retval = result;
    return TRUE;
}

/* For upper() and lower() checks that the parameter passed to
 * it is an FT_STRING */
static ftenum_t
ul_semcheck_is_field_string(dfwork_t *dfw, const char *func_name, ftenum_t lhs_ftype _U_,
                            GSList *param_list, stloc_t *func_loc _U_)
{
    header_field_info *hfinfo;

    ws_assert(g_slist_length(param_list) == 1);
    stnode_t *st_node = param_list->data;

    dfw_resolve_unparsed(dfw, st_node);

    if (stnode_type_id(st_node) == STTYPE_FIELD) {
        hfinfo = sttype_field_hfinfo(st_node);
        if (IS_FT_STRING(hfinfo->type)) {
            return FT_STRING;
        }
    }
    FAIL(dfw, st_node, "Only string type fields can be used as parameter for %s()", func_name);
}

static ftenum_t
ul_semcheck_is_field(dfwork_t *dfw, const char *func_name, ftenum_t lhs_ftype _U_,
                            GSList *param_list, stloc_t *func_loc _U_)
{
    ws_assert(g_slist_length(param_list) == 1);
    stnode_t *st_node = param_list->data;

    dfw_resolve_unparsed(dfw, st_node);

    if (stnode_type_id(st_node) == STTYPE_FIELD)
        return FT_UINT32;

    FAIL(dfw, st_node, "Only fields can be used as parameter for %s()", func_name);
}

static ftenum_t
ul_semcheck_string_param(dfwork_t *dfw, const char *func_name, ftenum_t lhs_ftype _U_,
                            GSList *param_list, stloc_t *func_loc _U_)
{
    header_field_info *hfinfo;

    ws_assert(g_slist_length(param_list) == 1);
    stnode_t *st_node = param_list->data;

    dfw_resolve_unparsed(dfw, st_node);

    if (stnode_type_id(st_node) == STTYPE_FIELD) {
        hfinfo = sttype_field_hfinfo(st_node);
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
        FAIL(dfw, st_node, "String conversion for field \"%s\" is not supported", hfinfo->abbrev);
    }
    FAIL(dfw, st_node, "Only fields can be used as parameter for %s()", func_name);
}

/* Check arguments are all the same type and they can be compared. */
static ftenum_t
ul_semcheck_compare(dfwork_t *dfw, const char *func_name, ftenum_t lhs_ftype,
                        GSList *param_list, stloc_t *func_loc _U_)
{
    stnode_t *arg;
    ftenum_t ftype, ft_arg;
    GSList *l;
    fvalue_t *fv;

    arg = param_list->data;
    dfw_resolve_unparsed(dfw, arg);

    if (stnode_type_id(arg) == STTYPE_ARITHMETIC) {
        ftype = check_arithmetic_expr(dfw, arg, lhs_ftype);
    }
    else if (stnode_type_id(arg) == STTYPE_LITERAL && lhs_ftype != FT_NONE) {
        fv = dfilter_fvalue_from_literal(dfw, lhs_ftype, arg, FALSE, NULL);
        stnode_replace(arg, STTYPE_FVALUE, fv);
        ftype = fvalue_type_ftenum(fv);
    }
    else if (stnode_type_id(arg) == STTYPE_FUNCTION) {
        ftype = check_function(dfw, arg, lhs_ftype);
    }
    else {
        ftype = sttype_field_ftenum(arg);
    }

    if (ftype == FT_NONE) {
        FAIL(dfw, arg, "Argument '%s' (FT_NONE) is not valid for %s()",
                                stnode_todisplay(arg), func_name);
    }

    for (l = param_list->next; l != NULL; l = l->next) {
        arg = l->data;
        dfw_resolve_unparsed(dfw, arg);

        if (stnode_type_id(arg) == STTYPE_ARITHMETIC) {
            ft_arg = check_arithmetic_expr(dfw, arg, ftype);
        }
        else if (stnode_type_id(arg) == STTYPE_LITERAL && ftype != FT_NONE) {
            fv = dfilter_fvalue_from_literal(dfw, ftype, arg, FALSE, NULL);
            stnode_replace(arg, STTYPE_FVALUE, fv);
            ft_arg = fvalue_type_ftenum(fv);
        }
        else if (stnode_type_id(arg) == STTYPE_FUNCTION) {
            ft_arg = check_function(dfw, arg, ftype);
        }
        else {
            ft_arg = sttype_field_ftenum(arg);
        }

        if (ft_arg == FT_NONE) {
            FAIL(dfw, arg, "Argument '%s' (FT_NONE) is not valid for %s()",
                                    stnode_todisplay(arg), func_name);
        }
        if (ftype == FT_NONE) {
            ftype = ft_arg;
        }
        if (ft_arg != ftype) {
            FAIL(dfw, arg, "Arguments to '%s' must have the same type (expected %s, got %s)",
                                        func_name, ftype_name(ftype), ftype_name(ft_arg));
        }
        if (!ftype_can_cmp(ft_arg)) {
            FAIL(dfw, arg, "Argument '%s' to '%s' cannot be ordered",
                                    stnode_todisplay(arg), func_name);
        }
    }
    return ftype;
}

static ftenum_t
ul_semcheck_absolute_value(dfwork_t *dfw, const char *func_name, ftenum_t lhs_ftype,
                        GSList *param_list, stloc_t *func_loc _U_)
{
    ws_assert(g_slist_length(param_list) == 1);
    stnode_t *st_node;
    ftenum_t ftype;
    fvalue_t *fv;

    st_node = param_list->data;
    dfw_resolve_unparsed(dfw, st_node);

    if (stnode_type_id(st_node) == STTYPE_ARITHMETIC) {
        ftype = check_arithmetic_expr(dfw, st_node, lhs_ftype);
    }
    else if (stnode_type_id(st_node) == STTYPE_LITERAL && lhs_ftype != FT_NONE) {
        fv = dfilter_fvalue_from_literal(dfw, lhs_ftype, st_node, FALSE, NULL);
        stnode_replace(st_node, STTYPE_FVALUE, fv);
        ftype = fvalue_type_ftenum(fv);
    }
    else if (stnode_type_id(st_node) == STTYPE_FUNCTION) {
        ftype = check_function(dfw, st_node, lhs_ftype);
    }
    else {
        ftype = sttype_field_ftenum(st_node);
    }

    if (ftype == FT_NONE) {
        FAIL(dfw, st_node, "Type %s is not valid for %s",
                        stnode_type_name(st_node), func_name);
    }
    if (!ftype_can_is_negative(ftype)) {
        FAIL(dfw, st_node, "'%s' is not a valid argument to '%s'()",
                        stnode_todisplay(st_node), func_name);
    }
    return ftype;
}

/* The table of all display-filter functions */
static df_func_def_t
df_functions[] = {
    { "lower",  df_func_lower,  1, 1, ul_semcheck_is_field_string },
    { "upper",  df_func_upper,  1, 1, ul_semcheck_is_field_string },
    { "len",    df_func_len,    1, 1, ul_semcheck_is_field },
    { "count",  df_func_count,  1, 1, ul_semcheck_is_field },
    { "string", df_func_string, 1, 1, ul_semcheck_string_param },
    { "max",    df_func_max,    1, 0, ul_semcheck_compare },
    { "min",    df_func_min,    1, 0, ul_semcheck_compare },
    { "abs",    df_func_abs,    1, 1, ul_semcheck_absolute_value },
    { NULL, NULL, 0, 0, NULL }
};

/* Lookup a display filter function record by name */
df_func_def_t*
df_func_lookup(const char *name)
{
    df_func_def_t *func_def;

    func_def = df_functions;
    while (func_def->function != NULL) {
        if (strcmp(func_def->name, name) == 0) {
            return func_def;
        }
        func_def++;
    }
    return NULL;
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
