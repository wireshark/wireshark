/*
 * Wireshark - Network traffic analyzer
 *
 * Copyright 2006 Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include "dfilter-int.h"
#include "dfunctions.h"

#include <string.h>

#include <ftypes/ftypes-int.h>
#include <ftypes/ftypes.h>
#include <epan/exceptions.h>

/* Convert an FT_STRING using a callback function */
static gboolean
string_walk(GList* arg1list, GList **retval, gchar(*conv_func)(gchar))
{
    GList       *arg1;
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
                    /**c = g_ascii_tolower(*c);*/
                    *c = conv_func(*c);
            }

            new_ft_string = fvalue_new(FT_STRING);
            fvalue_set_string(new_ft_string, s);
            wmem_free(NULL, s);
            *retval = g_list_append(*retval, new_ft_string);
        }
        arg1 = arg1->next;
    }

    return TRUE;
}

/* dfilter function: lower() */
static gboolean
df_func_lower(GList* arg1list, GList *arg2junk _U_, GList **retval)
{
    return string_walk(arg1list, retval, g_ascii_tolower);
}

/* dfilter function: upper() */
static gboolean
df_func_upper(GList* arg1list, GList *arg2junk _U_, GList **retval)
{
    return string_walk(arg1list, retval, g_ascii_toupper);
}

/* dfilter function: len() */
static gboolean
df_func_len(GList* arg1list, GList *arg2junk _U_, GList **retval)
{
    GList       *arg1;
    fvalue_t    *arg_fvalue;
    fvalue_t    *ft_len;

    arg1 = arg1list;
    while (arg1) {
        arg_fvalue = (fvalue_t *)arg1->data;
        /* XXX - it would be nice to handle other types */
        if (IS_FT_STRING(fvalue_type_ftenum(arg_fvalue))) {
            ft_len = fvalue_new(FT_UINT32);
            fvalue_set_uinteger(ft_len, (guint) strlen((char *)fvalue_get(arg_fvalue)));
            *retval = g_list_append(*retval, ft_len);
        }
        arg1 = arg1->next;
    }

    return TRUE;
}

/* dfilter function: size() */
static gboolean
df_func_size(GList* arg1list, GList *arg2junk _U_, GList **retval)
{
    GList       *arg1;
    fvalue_t    *arg_fvalue;
    fvalue_t    *ft_len;

    arg1 = arg1list;
    while (arg1) {
        arg_fvalue = (fvalue_t *)arg1->data;

        ft_len = fvalue_new(FT_UINT32);
        fvalue_set_uinteger(ft_len, fvalue_length(arg_fvalue));
        *retval = g_list_append(*retval, ft_len);

        arg1 = arg1->next;
    }

    return TRUE;
}

/* dfilter function: count() */
static gboolean
df_func_count(GList* arg1list, GList *arg2junk _U_, GList **retval)
{
    fvalue_t *ft_ret;
    guint32   num_items;

    num_items = (guint32)g_list_length(arg1list);

    ft_ret = fvalue_new(FT_UINT32);
    fvalue_set_uinteger(ft_ret, num_items);
    *retval = g_list_append(*retval, ft_ret);

    return TRUE;
}


/* For upper(), lower() and len(), checks that the parameter passed to
 * it is an FT_STRING */
static void
ul_semcheck_params(dfwork_t *dfw, int param_num, stnode_t *st_node)
{
    sttype_id_t type;
    ftenum_t    ftype;
    header_field_info *hfinfo;

    type = stnode_type_id(st_node);

    if (param_num == 0) {
        switch(type) {
            case STTYPE_FIELD:
                hfinfo = (header_field_info *)stnode_data(st_node);
                ftype = hfinfo->type;
                if (!IS_FT_STRING(ftype)) {
                    dfilter_fail(dfw, "Only strings can be used in upper() or lower() or len()");
                    THROW(TypeError);
                }
                break;
            default:
                dfilter_fail(dfw, "Only string-type fields can be used in upper() or lower() or len()");
                THROW(TypeError);
        }
    }
    else {
        g_assert_not_reached();
    }
}

static void
ul_semcheck_field_param(dfwork_t *dfw, int param_num, stnode_t *st_node)
{
    sttype_id_t type;

    type = stnode_type_id(st_node);

    if (param_num == 0) {
        switch(type) {
            case STTYPE_FIELD:
                break;
            default:
                dfilter_fail(dfw, "Only type fields can be used as parameter "
                      "for size() or count()");
                THROW(TypeError);
        }
    }
    else {
        g_assert_not_reached();
    }
}

/* The table of all display-filter functions */
static df_func_def_t
df_functions[] = {
    { "lower", df_func_lower, FT_STRING, 1, 1, ul_semcheck_params },
    { "upper", df_func_upper, FT_STRING, 1, 1, ul_semcheck_params },
    { "len",   df_func_len,   FT_UINT32, 1, 1, ul_semcheck_params },
    { "size",  df_func_size,  FT_UINT32, 1, 1, ul_semcheck_field_param },
    { "count", df_func_count, FT_UINT32, 1, 1, ul_semcheck_field_param },
    { NULL, NULL, FT_NONE, 0, 0, NULL }
};

/* Lookup a display filter function record by name */
df_func_def_t*
df_func_lookup(char *name)
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
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
