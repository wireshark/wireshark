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
#include "sttype-pointer.h"

#include <string.h>

#include <ftypes/ftypes.h>
#include <epan/exceptions.h>
#include <wsutil/ws_assert.h>

#define FAIL(dfw, node, ...) \
	dfilter_fail_throw(dfw, stnode_location(node), __VA_ARGS__)

/* Convert an FT_STRING using a callback function */
static gboolean
string_walk(GSList **args, guint32 arg_count, GSList **retval, gchar(*conv_func)(gchar))
{
    GSList      *arg1;
    fvalue_t    *arg_fvalue;
    fvalue_t    *new_ft_string;
    char *s, *c;

    ws_assert(arg_count == 1);
    arg1 = args[0];
    if (arg1 == NULL)
        return FALSE;

    while (arg1) {
        arg_fvalue = (fvalue_t *)arg1->data;
        /* XXX - it would be nice to handle FT_TVBUFF, too */
        if (IS_FT_STRING(fvalue_type_ftenum(arg_fvalue))) {
            s = (char *)wmem_strdup(NULL, (gchar *)fvalue_get(arg_fvalue));
            for (c = s; *c; c++) {
                    *c = conv_func(*c);
            }

            new_ft_string = fvalue_new(FT_STRING);
            fvalue_set_string(new_ft_string, s);
            wmem_free(NULL, s);
            *retval = g_slist_prepend(*retval, new_ft_string);
        }
        arg1 = arg1->next;
    }

    return TRUE;
}

/* dfilter function: lower() */
static gboolean
df_func_lower(GSList **args, guint32 arg_count, GSList **retval)
{
    return string_walk(args, arg_count, retval, g_ascii_tolower);
}

/* dfilter function: upper() */
static gboolean
df_func_upper(GSList **args, guint32 arg_count, GSList **retval)
{
    return string_walk(args, arg_count, retval, g_ascii_toupper);
}

/* dfilter function: len() */
static gboolean
df_func_len(GSList **args, guint32 arg_count, GSList **retval)
{
    GSList      *arg1;
    fvalue_t    *arg_fvalue;
    fvalue_t    *ft_len;

    ws_assert(arg_count == 1);
    arg1 = args[0];
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
df_func_count(GSList **args, guint32 arg_count, GSList **retval)
{
    GSList   *arg1;
    fvalue_t *ft_ret;
    guint32   num_items;

    ws_assert(arg_count == 1);
    arg1 = args[0];
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
df_func_string(GSList **args, guint32 arg_count, GSList **retval)
{
    GSList   *arg1;
    fvalue_t *arg_fvalue;
    fvalue_t *new_ft_string;
    char     *s;

    ws_assert(arg_count == 1);
    arg1 = args[0];
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
df_func_compare(GSList **args, guint32 arg_count, GSList **retval,
                    gboolean (*fv_cmp)(const fvalue_t *a, const fvalue_t *b))
{
    fvalue_t *fv_ret = NULL;
    GSList   *l;
    guint32 i;

    for (i = 0; i < arg_count; i++) {
        for (l = args[i]; l != NULL; l = l->next) {
            if (fv_ret == NULL || fv_cmp(l->data, fv_ret)) {
                fv_ret = l->data;
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
df_func_max(GSList **args, guint32 arg_count, GSList **retval)
{
    return df_func_compare(args, arg_count, retval, fvalue_gt);
}

/* Find minimum value. */
static gboolean
df_func_min(GSList **args, guint32 arg_count, GSList **retval)
{
    return df_func_compare(args, arg_count, retval, fvalue_lt);
}

/* For upper() and lower() checks that the parameter passed to
 * it is an FT_STRING */
static void
ul_semcheck_is_field_string(dfwork_t *dfw, const char *func_name,
                            GSList *param_list, stloc_t *func_loc _U_)
{
    header_field_info *hfinfo;

    ws_assert(g_slist_length(param_list) == 1);
    stnode_t *st_node = param_list->data;

    dfw_resolve_unparsed(dfw, st_node);

    if (stnode_type_id(st_node) == STTYPE_FIELD) {
        hfinfo = stnode_data(st_node);
        if (IS_FT_STRING(hfinfo->type)) {
            return;
        }
    }
    FAIL(dfw, st_node, "Only string type fields can be used as parameter for %s()", func_name);
}

static void
ul_semcheck_is_field(dfwork_t *dfw, const char *func_name,
                            GSList *param_list, stloc_t *func_loc _U_)
{
    ws_assert(g_slist_length(param_list) == 1);
    stnode_t *st_node = param_list->data;

    dfw_resolve_unparsed(dfw, st_node);

    if (stnode_type_id(st_node) == STTYPE_FIELD)
        return;

    FAIL(dfw, st_node, "Only fields can be used as parameter for %s()", func_name);
}

static void
ul_semcheck_string_param(dfwork_t *dfw, const char *func_name,
                            GSList *param_list, stloc_t *func_loc _U_)
{
    header_field_info *hfinfo;

    ws_assert(g_slist_length(param_list) == 1);
    stnode_t *st_node = param_list->data;

    dfw_resolve_unparsed(dfw, st_node);

    if (stnode_type_id(st_node) == STTYPE_FIELD) {
        hfinfo = stnode_data(st_node);
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
                return;
            default:
                break;
        }
        FAIL(dfw, st_node, "String conversion for field \"%s\" is not supported", hfinfo->abbrev);
    }
    FAIL(dfw, st_node, "Only fields can be used as parameter for %s()", func_name);
}

/* Check arguments are all the same type and they can be compared. */
static void
ul_semcheck_compare(dfwork_t *dfw, const char *func_name,
                        GSList *param_list, stloc_t *func_loc)
{
    stnode_t *arg;
    ftenum_t ftype, ft_arg;
    GSList *l;
    const header_field_info *hfinfo;
    fvalue_t *fv;

    /* First argument must be a field not FT_NONE. */
    arg = param_list->data;
    dfw_resolve_unparsed(dfw, arg);
    ftype = sttype_pointer_ftenum(arg);
    if (ftype == FT_NONE) {
        FAIL(dfw, arg, "First argument to %s() must be a field, not %s",
                                        func_name, stnode_type_name(arg));
    }

    for (l = param_list; l != NULL; l = l->next) {
        arg = l->data;
        dfw_resolve_unparsed(dfw, arg);

        switch (stnode_type_id(arg)) {
            case STTYPE_FIELD:
            case STTYPE_REFERENCE:
                hfinfo = stnode_data(arg);
                ft_arg = hfinfo->type;
                break;
            case STTYPE_LITERAL:
                fv = dfilter_fvalue_from_literal(dfw, ftype, arg, FALSE, NULL);
                stnode_replace(arg, STTYPE_FVALUE, fv);
                ft_arg = fvalue_type_ftenum(stnode_data(arg));
                break;
            case STTYPE_FVALUE:
                ft_arg = fvalue_type_ftenum(stnode_data(arg));
                break;
            default:
                FAIL(dfw, arg, "Type %s is not valid for %s",
                                stnode_type_name(arg), func_name);
        }
        if (ft_arg == FT_NONE) {
            dfilter_fail_throw(dfw, func_loc,
                                    "Argument '%s' (FT_NONE) is not valid for %s()",
                                    stnode_todisplay(arg), func_name);
        }
        if (ftype == FT_NONE) {
            ftype = ft_arg;
        }
        if (ft_arg != ftype) {
            dfilter_fail_throw(dfw, func_loc,
                                    "Arguments to '%s' must have the same type",
                                    func_name);
        }
        if (!ftype_can_cmp(ft_arg)) {
            dfilter_fail_throw(dfw, func_loc,
                                    "Argument '%s' to '%s' cannot be ordered",
                                    stnode_todisplay(arg), func_name);
        }
    }
}

/* The table of all display-filter functions */
static df_func_def_t
df_functions[] = {
    { "lower",  df_func_lower,  FT_STRING, 1, 1, ul_semcheck_is_field_string },
    { "upper",  df_func_upper,  FT_STRING, 1, 1, ul_semcheck_is_field_string },
    { "len",    df_func_len,    FT_UINT32, 1, 1, ul_semcheck_is_field },
    { "count",  df_func_count,  FT_UINT32, 1, 1, ul_semcheck_is_field },
    { "string", df_func_string, FT_STRING, 1, 1, ul_semcheck_string_param },
    { "max",    df_func_max,    /*Any*/ 0, 1, 0, ul_semcheck_compare },
    { "min",    df_func_min,    /*Any*/ 0, 1, 0, ul_semcheck_compare },
    { NULL, NULL, FT_NONE, 0, 0, NULL }
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
