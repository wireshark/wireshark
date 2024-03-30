/* packet_list_utils.c
 * Packet list display utilities
 * Copied from gtk/packet_list.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "packet_list_utils.h"

#include <epan/column.h>

bool
right_justify_column (int col, capture_file *cf)
{
    header_field_info *hfi;
    bool right_justify = false;
    unsigned num_fields, ii;
    col_custom_t *col_custom;
    unsigned right_justify_count = 0;

    if (!cf) return false;

    switch (cf->cinfo.columns[col].col_fmt) {

        case COL_NUMBER:
        case COL_PACKET_LENGTH:
        case COL_CUMULATIVE_BYTES:
        case COL_DSCP_VALUE:
        case COL_UNRES_DST_PORT:
        case COL_UNRES_SRC_PORT:
        case COL_DEF_DST_PORT:
        case COL_DEF_SRC_PORT:
        case COL_DELTA_TIME:
        case COL_DELTA_TIME_DIS:
            right_justify = true;
            break;

        case COL_CUSTOM:
            num_fields = g_slist_length(cf->cinfo.columns[col].col_custom_fields_ids);
            for (ii = 0; ii < num_fields; ii++) {
                col_custom = (col_custom_t *) g_slist_nth_data(cf->cinfo.columns[col].col_custom_fields_ids, ii);
                if (col_custom->field_id == 0) {
                    /* XXX - If there were some way to check the compiled dfilter's
                     * expected return type, we could use that.
                     */
                    return false;
                }
                hfi = proto_registrar_get_nth(col_custom->field_id);

                /* Check if this is a valid field and we have no strings lookup table */
                /* XXX - We should check every hfi with the same abbreviation */
                if ((hfi != NULL) && ((hfi->strings == NULL) || !get_column_resolved(col))) {
                    /* Check for bool, framenum, double, float, relative time and decimal/octal integer types */
                    if ((hfi->type == FT_BOOLEAN) || (hfi->type == FT_FRAMENUM) || (hfi->type == FT_DOUBLE) ||
                        (hfi->type == FT_FLOAT) || (hfi->type == FT_RELATIVE_TIME) ||
                        (((FIELD_DISPLAY(hfi->display) == BASE_DEC) || (FIELD_DISPLAY(hfi->display) == BASE_OCT)) &&
                         (FT_IS_INT(hfi->type) || FT_IS_UINT(hfi->type))))
                    {
                        right_justify_count++;
                    }
                }
            }

            if ((num_fields > 0) && (right_justify_count == num_fields)) {
                /* All custom fields must meet the right-justify criteria */
                right_justify = true;
            }
            break;

        default:
            break;
    }

    return right_justify;
}

bool
resolve_column (int col, capture_file *cf)
{
    header_field_info *hfi;
    bool resolve = false;
    unsigned num_fields, ii;
    col_custom_t *col_custom;

    if (!cf) return false;

    switch (cf->cinfo.columns[col].col_fmt) {

        case COL_CUSTOM:
            num_fields = g_slist_length(cf->cinfo.columns[col].col_custom_fields_ids);
            for (ii = 0; ii < num_fields; ii++) {
                col_custom = (col_custom_t *) g_slist_nth_data(cf->cinfo.columns[col].col_custom_fields_ids, ii);
                if (col_custom->field_id == 0) {
                    /* XXX - A "resolved" string might be conceivable for certain
                     * expressions, but would require being able to know which
                     * hfinfo produced each value, if there are multiple hfi with
                     * the same abbreviation.
                     */
                    continue;
                }
                hfi = proto_registrar_get_nth(col_custom->field_id);
                /* XXX - We should check every hfi with the same abbreviation */

                /* Check if we have an OID, a (potentially) resolvable network
                 * address, a Boolean, or a strings table with integer values */
                /* XXX: Should this checkbox be disabled if the Name Resolution
                 * preference for a given type is off?
                 */
                if ((hfi->type == FT_OID) || (hfi->type == FT_REL_OID) || (hfi->type == FT_ETHER) || (hfi->type == FT_IPv4) || (hfi->type == FT_IPv6) || (hfi->type == FT_FCWWN) || (hfi->type == FT_BOOLEAN) ||
                    ((hfi->strings != NULL) &&
                     (FT_IS_INT(hfi->type) || FT_IS_UINT(hfi->type))))
                {
                    resolve = true;
                    break;
                }
            }
            break;

        default:
            break;
    }

    return resolve;
}
