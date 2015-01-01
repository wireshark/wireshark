/* io_graph_item.h
 * Definitions and functions for IO graph items
 *
 * Copied from gtk/io_stat.c, (c) 2002 Ronnie Sahlberg
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


#include <epan/epan_dissect.h>

#include "ui/io_graph_item.h"

int get_io_graph_index(packet_info *pinfo, int interval) {
    nstime_t time_delta;

    /*
     * Find in which interval this is supposed to go and store the interval index as idx
     */
    time_delta = pinfo->rel_ts;
    if (time_delta.nsecs<0) {
        time_delta.secs--;
        time_delta.nsecs += 1000000000;
    }
    if (time_delta.secs<0) {
        return -1;
    }
    return (int) ((time_delta.secs*1000 + time_delta.nsecs/1000000) / interval);
}

GString *check_field_unit(const char *field_name, int *hf_index, io_graph_item_unit_t item_unit)
{
    GString *err_str = NULL;
    if (item_unit >= IOG_ITEM_UNIT_CALC_SUM) {
        header_field_info *hfi;

        const char *item_unit_names[NUM_IOG_ITEM_UNITS] = {
            "Packets",
            "Bytes",
            "Bits",
            "SUM",
            "COUNT FRAMES",
            "COUNT FIELDS",
            "MAX",
            "MIN",
            "AVG",
            "LOAD"
        };

        /* There was no field specified */
        if ((field_name == NULL) || (field_name[0] == 0)) {
            err_str = g_string_new("You didn't specify a field name.");
            return err_str;
        }

        /* The field could not be found */
        hfi = proto_registrar_get_byname(field_name);
        if (hfi == NULL) {
            err_str = g_string_new("");
            g_string_printf(err_str, "There is no field named '%s'.", field_name);
            return err_str;
        }

        if (hf_index) *hf_index = hfi->id;

        /* Check that the type is compatible */
        switch (hfi->type) {
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
        case FT_UINT64:
        case FT_INT8:
        case FT_INT16:
        case FT_INT24:
        case FT_INT32:
        case FT_INT64:
        case FT_FLOAT:
        case FT_DOUBLE:
            /* These values support all calculations except LOAD */
            switch (item_unit) {
            case IOG_ITEM_UNIT_CALC_LOAD:
                err_str = g_string_new("LOAD is only supported for relative-time fields.");
            default:
                break;
            }
            /* These types support all calculations */
            break;
        case FT_RELATIVE_TIME:
            /* This type only supports COUNT, MAX, MIN, AVG */
            switch (item_unit) {
            case IOG_ITEM_UNIT_CALC_SUM:
            case IOG_ITEM_UNIT_CALC_FRAMES:
            case IOG_ITEM_UNIT_CALC_FIELDS:
            case IOG_ITEM_UNIT_CALC_MAX:
            case IOG_ITEM_UNIT_CALC_MIN:
            case IOG_ITEM_UNIT_CALC_AVERAGE:
            case IOG_ITEM_UNIT_CALC_LOAD:
                break;
            default:
                err_str = g_string_new("");
                g_string_printf(err_str, "\"%s\" is a relative-time field. %s calculations are not supported on it.",
                    field_name,
                    item_unit_names[item_unit]);
            }
            break;
        default:
            if ((item_unit != IOG_ITEM_UNIT_CALC_FRAMES) &&
                (item_unit != IOG_ITEM_UNIT_CALC_FIELDS)) {
                err_str = g_string_new("");
                g_string_printf(err_str, "\"%s\" doesn't have integral or float values. %s calculations are not supported on it.",
                    field_name,
                    item_unit_names[item_unit]);
            }
            break;
        }
    }
    return err_str;
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
