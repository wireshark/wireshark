/* packet_list_utils.c
 * Packet list display utilities
 * Copied from gtk/packet_list.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "config.h"


#include "packet_list_utils.h"

#include <epan/column.h>

gboolean
right_justify_column (gint col, capture_file *cf)
{
    header_field_info *hfi;
    gboolean right_justify = FALSE;

    if (!cf) return FALSE;

    switch (cf->cinfo.columns[col].col_fmt) {

        case COL_NUMBER:
        case COL_PACKET_LENGTH:
        case COL_CUMULATIVE_BYTES:
        case COL_DCE_CALL:
        case COL_DSCP_VALUE:
        case COL_UNRES_DST_PORT:
        case COL_UNRES_SRC_PORT:
        case COL_DEF_DST_PORT:
        case COL_DEF_SRC_PORT:
        case COL_DELTA_TIME:
        case COL_DELTA_TIME_DIS:
            right_justify = TRUE;
            break;

        case COL_CUSTOM:
            hfi = proto_registrar_get_byname(cf->cinfo.columns[col].col_custom_fields);
            /* Check if this is a valid field and we have no strings lookup table */
            if ((hfi != NULL) && ((hfi->strings == NULL) || !get_column_resolved(col))) {
                /* Check for bool, framenum and decimal/octal integer types */
                if ((hfi->type == FT_BOOLEAN) || (hfi->type == FT_FRAMENUM) ||
                        (((hfi->display == BASE_DEC) || (hfi->display == BASE_OCT)) &&
                         (IS_FT_INT(hfi->type) || IS_FT_UINT(hfi->type)))) {
                    right_justify = TRUE;
                }
            }
            break;

        default:
            break;
    }

    return right_justify;
}

gboolean
resolve_column (gint col, capture_file *cf)
{
    header_field_info *hfi;
    gboolean resolve = FALSE;
    guint num_fields, *field_idx, ii;

    if (!cf) return FALSE;

    switch (cf->cinfo.columns[col].col_fmt) {

        case COL_CUSTOM:
            num_fields = g_slist_length(cf->cinfo.columns[col].col_custom_fields_ids);
            for (ii = 0; ii < num_fields; ii++) {
                field_idx = (guint *) g_slist_nth_data(cf->cinfo.columns[col].col_custom_fields_ids, ii);
                hfi = proto_registrar_get_nth(*field_idx);

                /* Check if we have an OID or a strings table with integer values */
                if ((hfi->type == FT_OID) || (hfi->type == FT_REL_OID) ||
                    ((hfi->strings != NULL) &&
                     ((hfi->type == FT_BOOLEAN) || (hfi->type == FT_FRAMENUM) ||
                      IS_FT_INT(hfi->type) || IS_FT_UINT(hfi->type))))
                {
                    resolve = TRUE;
                    break;
                }
            }
            break;

        default:
            break;
    }

    return resolve;
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
