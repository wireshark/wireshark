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

#include <string.h>

#include <ftypes/ftypes.h>
#include <epan/exceptions.h>
#include <wsutil/ws_assert.h>

#define FAIL(dfw, ...) \
	dfilter_fail_throw(dfw, TypeError, __VA_ARGS__)

/* Convert an FT_STRING using a callback function */
static gboolean
string_walk(GSList* arg1list, GSList **retval, gchar(*conv_func)(gchar))
{
    GSList      *arg1;
    fvalue_t    *arg_fvalue;
    fvalue_t    *new_ft_string;
    char *s, *c;

    arg1 = arg1list;
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
df_func_lower(GSList* arg1list, GSList *arg2junk _U_, GSList **retval)
{
    return string_walk(arg1list, retval, g_ascii_tolower);
}

/* dfilter function: upper() */
static gboolean
df_func_upper(GSList* arg1list, GSList *arg2junk _U_, GSList **retval)
{
    return string_walk(arg1list, retval, g_ascii_toupper);
}

/* dfilter function: len() */
static gboolean
df_func_len(GSList* arg1list, GSList *arg2junk _U_, GSList **retval)
{
    GSList      *arg1;
    fvalue_t    *arg_fvalue;
    fvalue_t    *ft_len;

    arg1 = arg1list;
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
df_func_count(GSList* arg1list, GSList *arg2junk _U_, GSList **retval)
{
    fvalue_t *ft_ret;
    guint32   num_items;

    num_items = (guint32)g_slist_length(arg1list);

    ft_ret = fvalue_new(FT_UINT32);
    fvalue_set_uinteger(ft_ret, num_items);
    *retval = g_slist_prepend(*retval, ft_ret);

    return TRUE;
}

/* dfilter function: string() */
static gboolean
df_func_string(GSList* arg1list, GSList *arg2junk _U_, GSList **retval)
{
    GSList   *arg1 = arg1list;
    fvalue_t *arg_fvalue;
    fvalue_t *new_ft_string;
    char     *s;

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

/* For upper() and lower() checks that the parameter passed to
 * it is an FT_STRING */
static void
ul_semcheck_is_field_string(dfwork_t *dfw, const char *func_name,
                            int param_num, stnode_t *st_node)
{
    header_field_info *hfinfo;

    ws_assert(param_num == 0);

    if (stnode_type_id(st_node) == STTYPE_FIELD) {
        hfinfo = stnode_data(st_node);
        if (IS_FT_STRING(hfinfo->type)) {
            return;
        }
    }
    FAIL(dfw, "Only string type fields can be used as parameter for %s()", func_name);
}

static void
ul_semcheck_is_field(dfwork_t *dfw, const char *func_name,
                            int param_num, stnode_t *st_node)
{
    ws_assert(param_num == 0);

    if (stnode_type_id(st_node) == STTYPE_FIELD)
        return;

    FAIL(dfw, "Only fields can be used as parameter for %s()", func_name);
}

static void
ul_semcheck_string_param(dfwork_t *dfw, const char *func_name,
                            int param_num, stnode_t *st_node)
{
    header_field_info *hfinfo;

    ws_assert(param_num == 0);

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
        FAIL(dfw, "String conversion for field \"%s\" is not supported", hfinfo->abbrev);
    }
    FAIL(dfw, "Only fields can be used as parameter for %s()", func_name);
}

/* The table of all display-filter functions */
static df_func_def_t
df_functions[] = {
    { "lower",  df_func_lower,  FT_STRING, 1, 1, ul_semcheck_is_field_string },
    { "upper",  df_func_upper,  FT_STRING, 1, 1, ul_semcheck_is_field_string },
    { "len",    df_func_len,    FT_UINT32, 1, 1, ul_semcheck_is_field },
    { "count",  df_func_count,  FT_UINT32, 1, 1, ul_semcheck_is_field },
    { "string", df_func_string, FT_STRING, 1, 1, ul_semcheck_string_param },
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
