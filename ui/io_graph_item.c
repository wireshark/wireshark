/* io_graph_item.h
 * Definitions and functions for I/O graph items
 *
 * Copied from gtk/io_stat.c, (c) 2002 Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
                g_assert(item_unit < NUM_IOG_ITEM_UNITS);
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

// Adapted from get_it_value in gtk/io_stat.c.
double get_io_graph_item(const io_graph_item_t *items_, io_graph_item_unit_t val_units_, int idx, int hf_index_, const capture_file *cap_file, int interval_, int cur_idx_)
{
    double     value = 0;          /* FIXME: loss of precision, visible on the graph for small values */
    int        adv_type;
    const io_graph_item_t *item;
    guint32    interval;

    item = &items_[idx];

    // Basic units
    switch (val_units_) {
    case IOG_ITEM_UNIT_PACKETS:
        return item->frames;
    case IOG_ITEM_UNIT_BYTES:
        return (double) item->bytes;
    case IOG_ITEM_UNIT_BITS:
        return (double) (item->bytes * 8);
    case IOG_ITEM_UNIT_CALC_FRAMES:
        return item->frames;
    case IOG_ITEM_UNIT_CALC_FIELDS:
        return (double) item->fields;
    default:
        /* If it's COUNT_TYPE_ADVANCED but not one of the
         * generic ones we'll get it when we switch on the
         * adv_type below. */
        break;
    }

    if (hf_index_ < 0) {
        return 0;
    }
    // Advanced units
    adv_type = proto_registrar_get_ftype(hf_index_);
    switch (adv_type) {

    case FT_INT8:
    case FT_INT16:
    case FT_INT24:
    case FT_INT32:
    case FT_INT40:
    case FT_INT48:
    case FT_INT56:
    case FT_INT64:
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
    case FT_UINT40:
    case FT_UINT48:
    case FT_UINT56:
    case FT_UINT64:
    case FT_DOUBLE:
        switch (val_units_) {
        case IOG_ITEM_UNIT_CALC_SUM:
            value = item->double_tot;
            break;
        case IOG_ITEM_UNIT_CALC_MAX:
            value = item->double_max;
            break;
        case IOG_ITEM_UNIT_CALC_MIN:
            value = item->double_min;
            break;
        case IOG_ITEM_UNIT_CALC_AVERAGE:
            if (item->fields) {
                value = item->double_tot / item->fields;
            } else {
                value = 0;
            }
            break;
        default:
            break;
        }
        break;

    case FT_FLOAT:
        switch (val_units_) {
        case IOG_ITEM_UNIT_CALC_SUM:
            value = item->float_tot;
            break;
        case IOG_ITEM_UNIT_CALC_MAX:
            value = item->float_max;
            break;
        case IOG_ITEM_UNIT_CALC_MIN:
            value = item->float_min;
            break;
        case IOG_ITEM_UNIT_CALC_AVERAGE:
            if (item->fields) {
                value = (double)item->float_tot / item->fields;
            } else {
                value = 0;
            }
            break;
        default:
            break;
        }
        break;

    case FT_RELATIVE_TIME:
        switch (val_units_) {
        case IOG_ITEM_UNIT_CALC_MAX:
            value = nstime_to_sec(&item->time_max);
            break;
        case IOG_ITEM_UNIT_CALC_MIN:
            value = nstime_to_sec(&item->time_min);
            break;
        case IOG_ITEM_UNIT_CALC_SUM:
            value = nstime_to_sec(&item->time_tot);
            break;
        case IOG_ITEM_UNIT_CALC_AVERAGE:
            if (item->fields) {
                value = nstime_to_sec(&item->time_tot) / item->fields;
            } else {
                value = 0;
            }
            break;
        case IOG_ITEM_UNIT_CALC_LOAD:
            // "LOAD graphs plot the QUEUE-depth of the connection over time"
            // (for response time fields such as smb.time, rpc.time, etc.)
            // This interval is expressed in milliseconds.
            if (idx == cur_idx_ && cap_file) {
                interval = (guint32)(nstime_to_msec(&cap_file->elapsed_time) + 0.5);
                interval -= (interval_ * idx);
            } else {
                interval = interval_;
            }
            value = nstime_to_msec(&item->time_tot) / interval;
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
    return value;
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
