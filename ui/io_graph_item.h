/** @file
 *
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

#ifndef __IO_GRAPH_ITEM_H__
#define __IO_GRAPH_ITEM_H__

#include "cfile.h"
#include <wsutil/ws_assert.h>

#include <epan/epan_dissect.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
    IOG_ITEM_UNIT_FIRST,
    IOG_ITEM_UNIT_PACKETS = IOG_ITEM_UNIT_FIRST,
    IOG_ITEM_UNIT_BYTES,
    IOG_ITEM_UNIT_BITS,
    IOG_ITEM_UNIT_CALC_SUM,
    IOG_ITEM_UNIT_CALC_FRAMES,
    IOG_ITEM_UNIT_CALC_FIELDS,
    IOG_ITEM_UNIT_CALC_MAX,
    IOG_ITEM_UNIT_CALC_MIN,
    IOG_ITEM_UNIT_CALC_AVERAGE,
    IOG_ITEM_UNIT_CALC_THROUGHPUT,
    IOG_ITEM_UNIT_CALC_LOAD,
    IOG_ITEM_UNIT_LAST = IOG_ITEM_UNIT_CALC_LOAD,
    NUM_IOG_ITEM_UNITS
} io_graph_item_unit_t;

typedef struct _io_graph_item_t {
    uint32_t frames;            /* always calculated, will hold number of frames*/
    uint64_t bytes;             /* always calculated, will hold number of bytes*/
    uint64_t fields;
    /* We use a double for totals because of overflow. For min and max,
     * unsigned 64 bit integers larger than 2^53 cannot all be represented
     * in a double, and this is useful for determining the frame with the
     * min or max value, even though for plotting it will be converted to a
     * double.
     */
    union {
        nstime_t time_max;
        double   double_max;
        int64_t  int_max;
        uint64_t uint_max;
    };
    union {
        nstime_t time_min;
        double   double_min;
        int64_t  int_min;
        uint64_t uint_min;
    };
    union {
        nstime_t time_tot;
        double   double_tot;
    };
    uint32_t  first_frame_in_invl;
    uint32_t  min_frame_in_invl;
    uint32_t  max_frame_in_invl;
    uint32_t  last_frame_in_invl;
} io_graph_item_t;

/** Reset (zero) an io_graph_item_t.
 *
 * @param items [in,out] Array containing the items to reset.
 * @param count [in] The number of items in the array.
 */
static inline void
reset_io_graph_items(io_graph_item_t *items, size_t count, int hf_index _U_) {
    io_graph_item_t *item;
    size_t i;

    for (i = 0; i < count; i++) {
        item = &items[i];

        item->frames     = 0;
        item->bytes      = 0;
        item->fields     = 0;
        item->first_frame_in_invl = 0;
        item->min_frame_in_invl = 0;
        item->max_frame_in_invl = 0;
        item->last_frame_in_invl  = 0;

        nstime_set_zero(&item->time_max);
        nstime_set_zero(&item->time_min);
        nstime_set_zero(&item->time_tot);

#if 0
        /* XXX - On C, type punning is explicitly allowed since C99 so
         * setting the nstime_t values to 0 is always sufficient.
         * On C++ that appears technically to be undefined behavior (though
         * I don't know of any compilers for which it doesn't work and I
         * can't get UBSAN to complain about it) and this would be safer.
         */
        if (hf_index > 0) {

            switch (proto_registrar_get_ftype(hf_index)) {

            case FT_INT8:
            case FT_INT16:
            case FT_INT24:
            case FT_INT32:
            case FT_INT40:
            case FT_INT48:
            case FT_INT56:
            case FT_INT64:
                item->int_max = 0;
                item->int_min = 0;
                item->double_tot = 0;
                break;

            case FT_UINT8:
            case FT_UINT16:
            case FT_UINT24:
            case FT_UINT32:
            case FT_UINT40:
            case FT_UINT48:
            case FT_UINT56:
            case FT_UINT64:
                item->uint_max = 0;
                item->uint_min = 0;
                item->double_tot = 0;
                break;

            case FT_DOUBLE:
            case FT_FLOAT:
                item->double_max = 0;
                item->double_min = 0;
                item->double_tot = 0;
                break;

            case FT_RELATIVE_TIME:
                nstime_set_zero(&item->time_max);
                nstime_set_zero(&item->time_min);
                nstime_set_zero(&item->time_tot);
                break;

            default:
                break;
            }
        }
#endif
    }
}

/** Get the interval (array index) for a packet
 *
 * It is up to the caller to determine if the return value is valid.
 *
 * @param [in] pinfo Packet of interest.
 * @param [in] interval Time interval in microseconds
 * @return Array index on success, -1 on failure.
 *
 * @note pinfo->rel_ts, and hence the index, is not affected by ignoring
 * frames, but is affected by time references. (Ignoring frames before
 * a time reference can be useful, though.)
 */
int64_t get_io_graph_index(packet_info *pinfo, int interval);

/** Check field and item unit compatibility
 *
 * @param field_name [in] Header field name to check
 * @param hf_index [out] Assigned the header field index corresponding to field_name if valid.
 *                       Can be NULL.
 * @param item_unit [in] The type of unit to calculate. From IOG_ITEM_UNITS.
 * @return NULL if compatible, otherwise an error string. The string must
 *         be freed by the caller.
 */
GString *check_field_unit(const char *field_name, int *hf_index, io_graph_item_unit_t item_unit);

/** Get the value at the given interval (idx) for the current value unit.
 *
 * @param items [in] Array containing the item to get.
 * @param val_units [in] The type of unit to calculate. From IOG_ITEM_UNITS.
 * @param idx [in] Index of the item to get.
 * @param hf_index [in] Header field index for advanced statistics.
 * @param cap_file [in] Capture file.
 * @param interval [in] Timing interval in ms.
 * @param cur_idx [in] Current index.
 */
double get_io_graph_item(const io_graph_item_t *items, io_graph_item_unit_t val_units, int idx, int hf_index, const capture_file *cap_file, int interval, int cur_idx);

/** Update the values of an io_graph_item_t.
 *
 * Frame and byte counts are always calculated. If edt is non-NULL advanced
 * statistics are calculated using hfindex.
 *
 * @param items [in,out] Array containing the item to update.
 * @param idx [in] Index of the item to update.
 * @param pinfo [in] Packet containing update information.
 * @param edt [in] Dissection information for advanced statistics. May be NULL.
 * @param hf_index [in] Header field index for advanced statistics.
 * @param item_unit [in] The type of unit to calculate. From IOG_ITEM_UNITS.
 * @param interval [in] Timing interval in μs.
 * @return true if the update was successful, otherwise false.
 */
static inline bool
update_io_graph_item(io_graph_item_t *items, int idx, packet_info *pinfo, epan_dissect_t *edt, int hf_index, int item_unit, uint32_t interval) {
    io_graph_item_t *item = &items[idx];

    /* Set the first and last frame num in current interval matching the target field+filter  */
    if (item->first_frame_in_invl == 0) {
        item->first_frame_in_invl = pinfo->num;
    }
    item->last_frame_in_invl = pinfo->num;

    if (edt && hf_index >= 0) {
        GPtrArray *gp;
        unsigned i;

        gp = proto_get_finfo_ptr_array(edt->tree, hf_index);
        if (!gp) {
            return false;
        }

        /* Update the appropriate counters. If fields == 0, this is the first seen
         *  value so set any min/max values accordingly. */
        for (i=0; i < gp->len; i++) {
            int64_t new_int64;
            uint64_t new_uint64;
            float new_float;
            double new_double;
            const nstime_t *new_time;

            switch (proto_registrar_get_ftype(hf_index)) {
            case FT_UINT8:
            case FT_UINT16:
            case FT_UINT24:
            case FT_UINT32:
                new_uint64 = fvalue_get_uinteger(((field_info *)gp->pdata[i])->value);

                if ((new_uint64 > item->uint_max) || (item->fields == 0)) {
                    item->uint_max = new_uint64;
                    item->max_frame_in_invl = pinfo->num;
                }
                if ((new_uint64 < item->uint_min) || (item->fields == 0)) {
                    item->uint_min = new_uint64;
                    item->min_frame_in_invl = pinfo->num;
                }
                item->double_tot += (double)new_uint64;
                item->fields++;
                break;
            case FT_INT8:
            case FT_INT16:
            case FT_INT24:
            case FT_INT32:
                new_int64 = fvalue_get_sinteger(((field_info *)gp->pdata[i])->value);
                if ((new_int64 > item->int_max) || (item->fields == 0)) {
                    item->int_max = new_int64;
                    item->max_frame_in_invl = pinfo->num;
                }
                if ((new_int64 < item->int_min) || (item->fields == 0)) {
                    item->int_min = new_int64;
                    item->min_frame_in_invl = pinfo->num;
                }
                item->double_tot += (double)new_int64;
                item->fields++;
                break;
            case FT_UINT40:
            case FT_UINT48:
            case FT_UINT56:
            case FT_UINT64:
                new_uint64 = fvalue_get_uinteger64(((field_info *)gp->pdata[i])->value);
                if ((new_uint64 > item->uint_max) || (item->fields == 0)) {
                    item->uint_max = new_uint64;
                    item->max_frame_in_invl = pinfo->num;
                }
                if ((new_uint64 < item->uint_min) || (item->fields == 0)) {
                    item->uint_min = new_uint64;
                    item->min_frame_in_invl = pinfo->num;
                }
                item->double_tot += (double)new_uint64;
                item->fields++;
                break;
            case FT_INT40:
            case FT_INT48:
            case FT_INT56:
            case FT_INT64:
                new_int64 = fvalue_get_sinteger64(((field_info *)gp->pdata[i])->value);
                if ((new_int64 > item->int_max) || (item->fields == 0)) {
                    item->int_max = new_int64;
                    item->max_frame_in_invl = pinfo->num;
                }
                if ((new_int64 < item->int_min) || (item->fields == 0)) {
                    item->int_min = new_int64;
                    item->min_frame_in_invl = pinfo->num;
                }
                item->double_tot += (double)new_int64;
                item->fields++;
                break;
            case FT_FLOAT:
                new_float = (float)fvalue_get_floating(((field_info *)gp->pdata[i])->value);
                if ((new_float > item->double_max) || (item->fields == 0)) {
                    item->double_max = new_float;
                    item->max_frame_in_invl = pinfo->num;
                }
                if ((new_float < item->double_min) || (item->fields == 0)) {
                    item->double_min = new_float;
                    item->min_frame_in_invl = pinfo->num;
                }
                item->double_tot += new_float;
                item->fields++;
                break;
            case FT_DOUBLE:
                new_double = fvalue_get_floating(((field_info *)gp->pdata[i])->value);
                if ((new_double > item->double_max) || (item->fields == 0)) {
                    item->double_max = new_double;
                    item->max_frame_in_invl = pinfo->num;
                }
                if ((new_double < item->double_min) || (item->fields == 0)) {
                    item->double_min = new_double;
                    item->min_frame_in_invl = pinfo->num;
                }
                item->double_tot += new_double;
                item->fields++;
                break;
            case FT_RELATIVE_TIME:
                new_time = fvalue_get_time(((field_info *)gp->pdata[i])->value);

                switch (item_unit) {
                case IOG_ITEM_UNIT_CALC_LOAD:
                {
                    uint64_t t, pt; /* time in us */
                    int j;
                    /*
                     * Add the time this call spanned each interval according to
                     * its contribution to that interval.
                     * If the call time is negative (unlikely, requires both an
                     * out of order capture file plus retransmission), ignore.
                     */
                    const nstime_t time_zero = NSTIME_INIT_ZERO;
                    if (nstime_cmp(new_time, &time_zero) < 0) {
                        break;
                    }
                    t = new_time->secs;
                    t = t * 1000000 + new_time->nsecs / 1000;
                    j = idx;
                    /*
                     * Handle current interval
                     * This cannot be negative, because get_io_graph_index
                     * returns an invalid interval if so.
                     */
                    pt = pinfo->rel_ts.secs * 1000000 + pinfo->rel_ts.nsecs / 1000;
                    pt = pt % interval;
                    if (pt > t) {
                        pt = t;
                    }
                    while (t) {
                        io_graph_item_t *load_item;

                        load_item = &items[j];
                        load_item->time_tot.nsecs += (int) (pt * 1000);
                        if (load_item->time_tot.nsecs > 1000000000) {
                            load_item->time_tot.secs++;
                            load_item->time_tot.nsecs -= 1000000000;
                        }
                        load_item->fields++;

                        if (j == 0) {
                            break;
                        }
                        j--;
                        t -= pt;
                        if (t > (uint64_t) interval) {
                            pt = (uint64_t) interval;
                        } else {
                            pt = t;
                        }
                    }
                    break;
                }
                default:
                    if ( (nstime_cmp(new_time, &item->time_max) > 0)
                         || (item->fields == 0)) {
                        item->time_max = *new_time;
                        item->max_frame_in_invl = pinfo->num;
                    }
                    if ( (nstime_cmp(new_time, &item->time_min) < 0)
                         || (item->fields == 0)) {
                        item->time_min = *new_time;
                        item->min_frame_in_invl = pinfo->num;
                    }
                    nstime_add(&item->time_tot, new_time);
                    item->fields++;
                }
                break;
            default:
                if ((item_unit == IOG_ITEM_UNIT_CALC_FRAMES) ||
                    (item_unit == IOG_ITEM_UNIT_CALC_FIELDS)) {
                    /*
                     * It's not an integeresque type, but
                     * all we want to do is count it, so
                     * that's all right.
                     */
                    item->fields++;
                }
                else {
                    /*
                     * "Can't happen"; see the "check that the
                     * type is compatible" check in
                     * filter_callback().
                     */
                    ws_assert_not_reached();
                }
                break;
            }
        }
    }

    item->frames++;
    item->bytes += pinfo->fd->pkt_len;

    return true;
}


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __IO_GRAPH_ITEM_H__ */
