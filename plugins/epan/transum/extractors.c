/* extractors.c
* Routines for the TRANSUM response time analyzer post-dissector
* By Paul Offord <paul.offord@advance7.com>
* Copyright 2016 Advance Seven Limited
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
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
#include <epan/prefs.h>
#include <epan/packet.h>
#include "extractors.h"

/*
    This function extracts a field value (e.g. tcp.len) from a tree.  Because a packet may contain
    multiple values for the the field the extracted values are returned in a result_array.  The
    number of array entries is returned in element_count.

    Return is 0 if all went well.  If this function return -1 it is probably because the tree did not
    include the field defined by the field_id.
 */
int extract_uint(proto_tree *tree, int field_id, guint32 *result_array, size_t *element_count)
{
    GPtrArray *finfo_array;

    *element_count = 0;
    if (tree == NULL) {
        return -1;
    }

    finfo_array = proto_get_finfo_ptr_array(tree, field_id);

    if (finfo_array == NULL) {
        return -1;
    }

    *element_count = g_ptr_array_len(finfo_array);

    for (size_t i = 0; i < *element_count && i < MAX_RETURNED_ELEMENTS; i++)
    {
        result_array[i] = fvalue_get_uinteger(&((field_info*)finfo_array->pdata[i])->value);
    }

    return 0;
}

int extract_ui64(proto_tree *tree, int field_id, guint64 *result_array, size_t *element_count)
{
    GPtrArray *finfo_array;

    *element_count = 0;
    if (tree == NULL) {
        return -1;
    }

    finfo_array = proto_get_finfo_ptr_array(tree, field_id);

    if (finfo_array == NULL) {
        return -1;
    }

    *element_count = g_ptr_array_len(finfo_array);

    for (size_t i = 0; i < *element_count && i < MAX_RETURNED_ELEMENTS; i++)
    {
        result_array[i] = fvalue_get_uinteger64(&((field_info*)finfo_array->pdata[i])->value);
    }

    return 0;
}

int extract_si64(proto_tree *tree, int field_id, guint64 *result_array, size_t *element_count)
{
    GPtrArray *finfo_array;

    *element_count = 0;
    if (tree == NULL) {
        return -1;
    }

    finfo_array = proto_get_finfo_ptr_array(tree, field_id);

    if (finfo_array == NULL) {
        return -1;
    }

    *element_count = g_ptr_array_len(finfo_array);

    for (size_t i = 0; i < *element_count && i < MAX_RETURNED_ELEMENTS; i++)
    {
        result_array[i] = fvalue_get_sinteger64(&((field_info*)finfo_array->pdata[i])->value);
    }

    return 0;
}

int extract_bool(proto_tree *tree, int field_id, gboolean *result_array, size_t *element_count)
{
    GPtrArray *finfo_array;

    *element_count = 0;
    if (tree == NULL) {
        return -1;
    }

    finfo_array = proto_get_finfo_ptr_array(tree, field_id);

    if (finfo_array == NULL) {
        return -1;
    }

    *element_count = g_ptr_array_len(finfo_array);

    for (size_t i = 0; i < *element_count && i < MAX_RETURNED_ELEMENTS; i++)
    {
        fvalue_t *fv = &(((field_info*)finfo_array->pdata[i])->value);

        if (fv->value.uinteger)
            result_array[i] = TRUE;
        else
            result_array[i] = FALSE;
    }

    return 0;
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
