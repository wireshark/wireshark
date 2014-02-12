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

#ifndef __IO_GRAPH_ITEM_H__
#define __IO_GRAPH_ITEM_H__

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
    IOG_ITEM_UNIT_CALC_LOAD,
    IOG_ITEM_UNIT_LAST = IOG_ITEM_UNIT_CALC_LOAD,
    NUM_IOG_ITEM_UNITS
} io_graph_item_unit_t;

typedef struct _io_graph_item_t {
    guint32  frames;            /* always calculated, will hold number of frames*/
    guint64  bytes;             /* always calculated, will hold number of bytes*/
    guint64  fields;
    gint64   int_max;
    gint64   int_min;
    gint64   int_tot;
    /* XXX - Why do we always use 64-bit ints but split floats between
     * gfloat and gdouble?
     */
    gfloat   float_max;
    gfloat   float_min;
    gfloat   float_tot;
    gdouble  double_max;
    gdouble  double_min;
    gdouble  double_tot;
    nstime_t time_max;
    nstime_t time_min;
    nstime_t time_tot;
    guint32  first_frame_in_invl;
    guint32  last_frame_in_invl;
} io_graph_item_t;

/** Reset (zero) an io_graph_item_t.
 *
 * @param items [in,out] Array containing the items to reset.
 * @param count [in] The number of items in the array.
 */
static inline void
reset_io_graph_items(io_graph_item_t *items, int count) {
    io_graph_item_t *item;
    int i;

    for (i = 0; i < count; i++) {
        item = &items[i];

        item->frames     = 0;
        item->bytes      = 0;
        item->fields     = 0;
        item->int_max    = 0;
        item->int_min    = 0;
        item->int_tot    = 0;
        item->float_max  = 0;
        item->float_min  = 0;
        item->float_tot  = 0;
        item->double_max = 0;
        item->double_min = 0;
        item->double_tot = 0;
        nstime_set_zero(&item->time_max);
        nstime_set_zero(&item->time_min);
        nstime_set_zero(&item->time_tot);
        item->first_frame_in_invl = 0;
        item->last_frame_in_invl  = 0;
    }
}

/** Get the interval (array index) for a packet
 *
 * It is up to the caller to determine if the return value is valid.
 *
 * @param [in] pinfo Packet of interest.
 * @param [in] interval Time interval in milliseconds.
 * @return Array index on success, -1 on failure.
 */
int get_io_graph_index(packet_info *pinfo, int interval);

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
 * @param interval [in] Timing interval in ms.
 * @return TRUE if the update was successful, otherwise FALSE.
 */
static inline gboolean
update_io_graph_item(io_graph_item_t *items, int idx, packet_info *pinfo, epan_dissect_t *edt, int hf_index, int item_unit, guint32 interval) {
    io_graph_item_t *item = &items[idx];

    /* Set the first and last frame num in current interval matching the target field+filter  */
    if (item->first_frame_in_invl == 0) {
        item->first_frame_in_invl = pinfo->fd->num;
    }
    item->last_frame_in_invl = pinfo->fd->num;

    if (edt && hf_index >= 0) {
        GPtrArray *gp;
        guint i;

        gp = proto_get_finfo_ptr_array(edt->tree, hf_index);
        if (!gp) {
            return FALSE;
        }

        /* Update the appropriate counters. If fields == 0, this is the first seen
         *  value so set any min/max values accordingly. */
        for (i=0; i < gp->len; i++) {
            int new_int;
            gint64 new_int64;
            float new_float;
            double new_double;
            nstime_t *new_time;

            switch (proto_registrar_get_ftype(hf_index)) {
            case FT_UINT8:
            case FT_UINT16:
            case FT_UINT24:
            case FT_UINT32:
                new_int = fvalue_get_uinteger(&((field_info *)gp->pdata[i])->value);

                if ((new_int > item->int_max) || (item->fields == 0)) {
                    item->int_max = new_int;
                }
                if ((new_int < item->int_min) || (item->fields == 0)) {
                    item->int_min = new_int;
                }
                item->int_tot += new_int;
                item->fields++;
                break;
            case FT_INT8:
            case FT_INT16:
            case FT_INT24:
            case FT_INT32:
                new_int = fvalue_get_sinteger(&((field_info *)gp->pdata[i])->value);
                if ((new_int > item->int_max) || (item->fields == 0)) {
                    item->int_max = new_int;
                }
                if ((new_int < item->int_min) || (item->fields == 0)) {
                    item->int_min = new_int;
                }
                item->int_tot += new_int;
                item->fields++;
                break;
            case FT_UINT64:
            case FT_INT64:
                new_int64 = fvalue_get_integer64(&((field_info *)gp->pdata[i])->value);
                if ((new_int64 > item->int_max) || (item->fields == 0)) {
                    item->int_max = new_int64;
                }
                if ((new_int64 < item->int_min) || (item->fields == 0)) {
                    item->int_min = new_int64;
                }
                item->int_tot += new_int64;
                item->fields++;
                break;
            case FT_FLOAT:
                new_float = (gfloat)fvalue_get_floating(&((field_info *)gp->pdata[i])->value);
                if ((new_float > item->float_max) || (item->fields == 0)) {
                    item->float_max = new_float;
                }
                if ((new_float < item->float_min) || (item->fields == 0)) {
                    item->float_min = new_float;
                }
                item->float_tot += new_float;
                item->fields++;
                break;
            case FT_DOUBLE:
                new_double = fvalue_get_floating(&((field_info *)gp->pdata[i])->value);
                if ((new_double > item->double_max) || (item->fields == 0)) {
                    item->double_max = new_double;
                }
                if ((new_double < item->double_min) || (item->fields == 0)) {
                    item->double_min = new_double;
                }
                item->double_tot += new_double;
                item->fields++;
                break;
            case FT_RELATIVE_TIME:
                new_time = (nstime_t *)fvalue_get(&((field_info *)gp->pdata[i])->value);

                switch (item_unit) {
                    guint64 t, pt; /* time in us */
                    int j;
                case IOG_ITEM_UNIT_CALC_LOAD:
                    /*
                    * Add the time this call spanned each interval according to its contribution
                    * to that interval.
                    */
                    t = new_time->secs;
                    t = t * 1000000 + new_time->nsecs / 1000;
                    j = idx;
                    /*
                     * Handle current interval */
                    pt = pinfo->rel_ts.secs * 1000000 + pinfo->rel_ts.nsecs / 1000;
                    pt = pt % (interval * 1000);
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

                        if (j == 0) {
                            break;
                        }
                        j--;
                        t -= pt;
                        if (t > (guint64) interval * 1000) {
                            pt = (guint64) interval * 1000;
                        } else {
                            pt = t;
                        }
                    }
                    break;
                default:
                    if ( (new_time->secs > item->time_max.secs)
                         || ( (new_time->secs == item->time_max.secs)
                              && (new_time->nsecs > item->time_max.nsecs))
                         || (item->fields == 0)) {
                        item->time_max = *new_time;
                    }
                    if ( (new_time->secs<item->time_min.secs)
                         || ( (new_time->secs == item->time_min.secs)
                              && (new_time->nsecs < item->time_min.nsecs))
                         || (item->fields == 0)) {
                        item->time_min = *new_time;
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
                    g_assert_not_reached();
                }
                break;
            }
        }
    }

    item->frames++;
    item->bytes += pinfo->fd->pkt_len;

    return TRUE;
}


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __IO_GRAPH_ITEM_H__ */

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
