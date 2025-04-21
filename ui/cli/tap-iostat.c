/* tap-iostat.c
 * iostat   2002 Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <locale.h>

#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include "globals.h"
#include <wsutil/ws_assert.h>
#include <wsutil/time_util.h>
#include <wsutil/to_str.h>
#include <wsutil/cmdarg_err.h>

#define CALC_TYPE_FRAMES 0
#define CALC_TYPE_BYTES  1
#define CALC_TYPE_FRAMES_AND_BYTES 2
#define CALC_TYPE_COUNT  3
#define CALC_TYPE_SUM    4
#define CALC_TYPE_MIN    5
#define CALC_TYPE_MAX    6
#define CALC_TYPE_AVG    7
#define CALC_TYPE_LOAD   8

void register_tap_listener_iostat(void);

typedef struct {
    const char *func_name;
    int calc_type;
} calc_type_ent_t;

static calc_type_ent_t calc_type_table[] = {
    { "FRAMES",       CALC_TYPE_FRAMES },
    { "BYTES",        CALC_TYPE_BYTES },
    { "FRAMES BYTES", CALC_TYPE_FRAMES_AND_BYTES },
    { "COUNT",        CALC_TYPE_COUNT },
    { "SUM",          CALC_TYPE_SUM },
    { "MIN",          CALC_TYPE_MIN },
    { "MAX",          CALC_TYPE_MAX },
    { "AVG",          CALC_TYPE_AVG },
    { "LOAD",         CALC_TYPE_LOAD },
    { NULL, 0 }
};

typedef struct _io_stat_t {
    uint64_t interval;     /* The user-specified time interval (us) */
    unsigned invl_prec;      /* Decimal precision of the time interval (1=10s, 2=100s etc) */
    unsigned int num_cols;         /* The number of columns of stats in the table */
    struct _io_stat_item_t *items;  /* Each item is a single cell in the table */
    nstime_t start_time;    /* Time of first frame matching the filter */
    /* The following are all per-column fixed information arrays */
    const char **filters; /* 'io,stat' cmd strings (e.g., "AVG(smb.time)smb.time") */
    uint64_t *max_vals;    /* The max value sans the decimal or nsecs portion in each stat column */
    uint32_t *max_frame;   /* The max frame number displayed in each stat column */
    int *hf_indexes;
    int *calc_type;        /* The statistic type */
} io_stat_t;

typedef struct _io_stat_item_t {
    io_stat_t *parent;
    struct _io_stat_item_t *next;
    struct _io_stat_item_t *prev;
    uint64_t start_time;   /* Time since start of capture (us)*/
    int colnum;           /* Column number of this stat (0 to n) */
    uint32_t frames;
    uint32_t num;          /* The sample size of a given statistic (only needed for AVG) */
    union {    /* The accumulated data for the calculation of that statistic */
        uint64_t counter;
        float float_counter;
        double double_counter;
    };
} io_stat_item_t;

static char *io_decimal_point;

#define NANOSECS_PER_SEC UINT64_C(1000000000)

static uint64_t last_relative_time;

static tap_packet_status
iostat_packet(void *arg, packet_info *pinfo, epan_dissect_t *edt, const void *dummy _U_, tap_flags_t flags _U_)
{
    io_stat_t *parent;
    io_stat_item_t *mit;
    io_stat_item_t *it;
    uint64_t relative_time, rt;
    const nstime_t *new_time;
    GPtrArray *gp;
    unsigned i;
    int ftype;

    mit = (io_stat_item_t *) arg;
    parent = mit->parent;

    /* If this frame's relative time is negative, set its relative time to last_relative_time
       rather than disincluding it from the calculations. */
    if ((pinfo->rel_ts.secs >= 0) && (pinfo->rel_ts.nsecs >= 0)) {
        relative_time = ((uint64_t)pinfo->rel_ts.secs * UINT64_C(1000000)) +
                        ((uint64_t)((pinfo->rel_ts.nsecs+500)/1000));
        last_relative_time = relative_time;
    } else {
        relative_time = last_relative_time;
    }

    if (nstime_is_unset(&mit->parent->start_time)) {
        nstime_delta(&mit->parent->start_time, &pinfo->abs_ts, &pinfo->rel_ts);
    }

    /* The prev item is always the last interval in which we saw packets. */
    it = mit->prev;

    /* If we have moved into a new interval (row), create a new io_stat_item_t struct for every interval
    *  between the last struct and this one. If an item was not found in a previous interval, an empty
    *  struct will be created for it. */
    rt = relative_time;
    while (rt >= it->start_time + parent->interval) {
        it->next = g_new(io_stat_item_t, 1);
        it->next->prev = it;
        it->next->next = NULL;
        it = it->next;
        mit->prev = it;

        it->start_time = it->prev->start_time + parent->interval;
        it->frames = 0;
        it->counter = 0; /* 64-bit, type-punning with double is fine */
        it->num = 0;
        it->colnum = it->prev->colnum;
    }

    /* Store info in the current structure */
    it->frames++;

    switch (parent->calc_type[it->colnum]) {
    case CALC_TYPE_FRAMES:
    case CALC_TYPE_BYTES:
    case CALC_TYPE_FRAMES_AND_BYTES:
        it->counter += pinfo->fd->pkt_len;
        break;
    case CALC_TYPE_COUNT:
        gp = proto_get_finfo_ptr_array(edt->tree, parent->hf_indexes[it->colnum]);
        if (gp) {
            it->counter += gp->len;
        }
        break;
    case CALC_TYPE_SUM:
        gp = proto_get_finfo_ptr_array(edt->tree, parent->hf_indexes[it->colnum]);
        if (gp) {
            uint64_t val;

            for (i=0; i<gp->len; i++) {
                switch (proto_registrar_get_ftype(parent->hf_indexes[it->colnum])) {
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT24:
                case FT_UINT32:
                    it->counter += fvalue_get_uinteger(((field_info *)gp->pdata[i])->value);
                    break;
                case FT_UINT40:
                case FT_UINT48:
                case FT_UINT56:
                case FT_UINT64:
                    it->counter += fvalue_get_uinteger64(((field_info *)gp->pdata[i])->value);
                    break;
                case FT_INT8:
                case FT_INT16:
                case FT_INT24:
                case FT_INT32:
                    it->counter += fvalue_get_sinteger(((field_info *)gp->pdata[i])->value);
                    break;
                case FT_INT40:
                case FT_INT48:
                case FT_INT56:
                case FT_INT64:
                    it->counter += (int64_t)fvalue_get_sinteger64(((field_info *)gp->pdata[i])->value);
                    break;
                case FT_FLOAT:
                    it->float_counter +=
                        (float)fvalue_get_floating(((field_info *)gp->pdata[i])->value);
                    break;
                case FT_DOUBLE:
                    it->double_counter += fvalue_get_floating(((field_info *)gp->pdata[i])->value);
                    break;
                case FT_RELATIVE_TIME:
                    new_time = fvalue_get_time(((field_info *)gp->pdata[i])->value);
                    val = ((uint64_t)new_time->secs * NANOSECS_PER_SEC) + (uint64_t)new_time->nsecs;
                    it->counter  +=  val;
                    break;
                default:
                    /*
                     * "Can't happen"; see the checks
                     * in register_io_tap().
                     */
                    ws_assert_not_reached();
                    break;
                }
            }
        }
        break;
    case CALC_TYPE_MIN:
        gp = proto_get_finfo_ptr_array(edt->tree, parent->hf_indexes[it->colnum]);
        if (gp) {
            uint64_t val;
            float float_val;
            double double_val;

            ftype = proto_registrar_get_ftype(parent->hf_indexes[it->colnum]);
            for (i=0; i<gp->len; i++) {
                switch (ftype) {
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT24:
                case FT_UINT32:
                    val = fvalue_get_uinteger(((field_info *)gp->pdata[i])->value);
                    if ((it->frames == 1 && i == 0) || (val < it->counter)) {
                        it->counter = val;
                    }
                    break;
                case FT_UINT40:
                case FT_UINT48:
                case FT_UINT56:
                case FT_UINT64:
                    val = fvalue_get_uinteger64(((field_info *)gp->pdata[i])->value);
                    if ((it->frames == 1 && i == 0) || (val < it->counter)) {
                        it->counter = val;
                    }
                    break;
                case FT_INT8:
                case FT_INT16:
                case FT_INT24:
                case FT_INT32:
                    val = fvalue_get_sinteger(((field_info *)gp->pdata[i])->value);
                    if ((it->frames == 1 && i == 0) || ((int32_t)val < (int32_t)it->counter)) {
                        it->counter = val;
                    }
                    break;
                case FT_INT40:
                case FT_INT48:
                case FT_INT56:
                case FT_INT64:
                    val = fvalue_get_sinteger64(((field_info *)gp->pdata[i])->value);
                    if ((it->frames == 1 && i == 0) || ((int64_t)val < (int64_t)it->counter)) {
                        it->counter = val;
                    }
                    break;
                case FT_FLOAT:
                    float_val = (float)fvalue_get_floating(((field_info *)gp->pdata[i])->value);
                    if ((it->frames == 1 && i == 0) || (float_val < it->float_counter)) {
                        it->float_counter = float_val;
                    }
                    break;
                case FT_DOUBLE:
                    double_val = fvalue_get_floating(((field_info *)gp->pdata[i])->value);
                    if ((it->frames == 1 && i == 0) || (double_val < it->double_counter)) {
                        it->double_counter = double_val;
                    }
                    break;
                case FT_RELATIVE_TIME:
                    new_time = fvalue_get_time(((field_info *)gp->pdata[i])->value);
                    val = ((uint64_t)new_time->secs * NANOSECS_PER_SEC) + (uint64_t)new_time->nsecs;
                    if ((it->frames == 1 && i == 0) || (val < it->counter)) {
                        it->counter = val;
                    }
                    break;
                default:
                    /*
                     * "Can't happen"; see the checks
                     * in register_io_tap().
                     */
                    ws_assert_not_reached();
                    break;
                }
            }
        }
        break;
    case CALC_TYPE_MAX:
        gp = proto_get_finfo_ptr_array(edt->tree, parent->hf_indexes[it->colnum]);
        if (gp) {
            uint64_t val;
            float float_val;
            double double_val;

            ftype = proto_registrar_get_ftype(parent->hf_indexes[it->colnum]);
            for (i=0; i<gp->len; i++) {
                switch (ftype) {
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT24:
                case FT_UINT32:
                    val = fvalue_get_uinteger(((field_info *)gp->pdata[i])->value);
                    if (val > it->counter)
                        it->counter = val;
                    break;
                case FT_UINT40:
                case FT_UINT48:
                case FT_UINT56:
                case FT_UINT64:
                    val = fvalue_get_uinteger64(((field_info *)gp->pdata[i])->value);
                    if (val > it->counter)
                        it->counter = val;
                    break;
                case FT_INT8:
                case FT_INT16:
                case FT_INT24:
                case FT_INT32:
                    val = fvalue_get_sinteger(((field_info *)gp->pdata[i])->value);
                    if ((int32_t)val > (int32_t)it->counter)
                        it->counter = val;
                    break;
                case FT_INT40:
                case FT_INT48:
                case FT_INT56:
                case FT_INT64:
                    val = fvalue_get_sinteger64(((field_info *)gp->pdata[i])->value);
                    if ((int64_t)val > (int64_t)it->counter)
                        it->counter = val;
                    break;
                case FT_FLOAT:
                    float_val = (float)fvalue_get_floating(((field_info *)gp->pdata[i])->value);
                    if (float_val > it->float_counter)
                        it->float_counter = float_val;
                    break;
                case FT_DOUBLE:
                    double_val = fvalue_get_floating(((field_info *)gp->pdata[i])->value);
                    if (double_val > it->double_counter)
                        it->double_counter = double_val;
                    break;
                case FT_RELATIVE_TIME:
                    new_time = fvalue_get_time(((field_info *)gp->pdata[i])->value);
                    val = ((uint64_t)new_time->secs * NANOSECS_PER_SEC) + (uint64_t)new_time->nsecs;
                    if (val > it->counter)
                        it->counter = val;
                    break;
                default:
                    /*
                     * "Can't happen"; see the checks
                     * in register_io_tap().
                     */
                    ws_assert_not_reached();
                    break;
                }
            }
        }
        break;
    case CALC_TYPE_AVG:
        gp = proto_get_finfo_ptr_array(edt->tree, parent->hf_indexes[it->colnum]);
        if (gp) {
            uint64_t val;

            ftype = proto_registrar_get_ftype(parent->hf_indexes[it->colnum]);
            for (i=0; i<gp->len; i++) {
                it->num++;
                switch (ftype) {
                case FT_UINT8:
                case FT_UINT16:
                case FT_UINT24:
                case FT_UINT32:
                    val = fvalue_get_uinteger(((field_info *)gp->pdata[i])->value);
                    it->counter += val;
                    break;
                case FT_UINT40:
                case FT_UINT48:
                case FT_UINT56:
                case FT_UINT64:
                    val = fvalue_get_uinteger64(((field_info *)gp->pdata[i])->value);
                    it->counter += val;
                    break;
                case FT_INT8:
                case FT_INT16:
                case FT_INT24:
                case FT_INT32:
                    val = fvalue_get_sinteger(((field_info *)gp->pdata[i])->value);
                    it->counter += val;
                    break;
                case FT_INT40:
                case FT_INT48:
                case FT_INT56:
                case FT_INT64:
                    val = fvalue_get_sinteger64(((field_info *)gp->pdata[i])->value);
                    it->counter += val;
                    break;
                case FT_FLOAT:
                    it->float_counter += (float)fvalue_get_floating(((field_info *)gp->pdata[i])->value);
                    break;
                case FT_DOUBLE:
                    it->double_counter += fvalue_get_floating(((field_info *)gp->pdata[i])->value);
                    break;
                case FT_RELATIVE_TIME:
                    new_time = fvalue_get_time(((field_info *)gp->pdata[i])->value);
                    val = ((uint64_t)new_time->secs * NANOSECS_PER_SEC) + (uint64_t)new_time->nsecs;
                    it->counter += val;
                    break;
                default:
                    /*
                     * "Can't happen"; see the checks
                     * in register_io_tap().
                     */
                    ws_assert_not_reached();
                    break;
                }
            }
        }
        break;
    case CALC_TYPE_LOAD:
        gp = proto_get_finfo_ptr_array(edt->tree, parent->hf_indexes[it->colnum]);
        if (gp) {
            ftype = proto_registrar_get_ftype(parent->hf_indexes[it->colnum]);
            if (ftype != FT_RELATIVE_TIME) {
                cmdarg_err("\ntshark: LOAD() is only supported for relative-time fields such as smb.time\n");
                return TAP_PACKET_FAILED;
            }
            for (i=0; i<gp->len; i++) {
                uint64_t val;
                int tival;
                io_stat_item_t *pit;

                new_time = fvalue_get_time(((field_info *)gp->pdata[i])->value);
                val = ((uint64_t)new_time->secs*UINT64_C(1000000)) + (uint64_t)(new_time->nsecs/1000);
                tival = (int)(val % parent->interval);
                it->counter += tival;
                val -= tival;
                pit = it->prev;
                while (val > 0) {
                    if (val < (uint64_t)parent->interval) {
                        pit->counter += val;
                        break;
                    }
                    pit->counter += parent->interval;
                    val -= parent->interval;
                    pit = pit->prev;
                }
            }
        }
        break;
    }
    /* Store the highest value for this item in order to determine the width of each stat column.
    *  For real numbers we only need to know its magnitude (the value to the left of the decimal point
    *  so round it up before storing it as an integer in max_vals. For AVG of RELATIVE_TIME fields,
    *  calc the average, round it to the next second and store the seconds. For all other calc types
    *  of RELATIVE_TIME fields, store the counters without modification.
    *  fields. */
    switch (parent->calc_type[it->colnum]) {
        case CALC_TYPE_FRAMES:
        case CALC_TYPE_FRAMES_AND_BYTES:
            parent->max_frame[it->colnum] =
                MAX(parent->max_frame[it->colnum], it->frames);
            if (parent->calc_type[it->colnum] == CALC_TYPE_FRAMES_AND_BYTES)
                parent->max_vals[it->colnum] =
                    MAX(parent->max_vals[it->colnum], it->counter);
            break;
        case CALC_TYPE_BYTES:
        case CALC_TYPE_COUNT:
        case CALC_TYPE_LOAD:
            parent->max_vals[it->colnum] = MAX(parent->max_vals[it->colnum], it->counter);
            break;
        case CALC_TYPE_SUM:
        case CALC_TYPE_MIN:
        case CALC_TYPE_MAX:
            ftype = proto_registrar_get_ftype(parent->hf_indexes[it->colnum]);
            switch (ftype) {
                case FT_FLOAT:
                    parent->max_vals[it->colnum] =
                        MAX(parent->max_vals[it->colnum], (uint64_t)(it->float_counter+0.5));
                    break;
                case FT_DOUBLE:
                    parent->max_vals[it->colnum] =
                        MAX(parent->max_vals[it->colnum], (uint64_t)(it->double_counter+0.5));
                    break;
                case FT_RELATIVE_TIME:
                    parent->max_vals[it->colnum] =
                        MAX(parent->max_vals[it->colnum], it->counter);
                    break;
                default:
                    /* UINT16-64 and INT8-64 */
                    parent->max_vals[it->colnum] =
                        MAX(parent->max_vals[it->colnum], it->counter);
                    break;
            }
            break;
        case CALC_TYPE_AVG:
            if (it->num == 0) /* avoid division by zero */
               break;
            ftype = proto_registrar_get_ftype(parent->hf_indexes[it->colnum]);
            switch (ftype) {
                case FT_FLOAT:
                    parent->max_vals[it->colnum] =
                        MAX(parent->max_vals[it->colnum], (uint64_t)it->float_counter/it->num);
                    break;
                case FT_DOUBLE:
                    parent->max_vals[it->colnum] =
                        MAX(parent->max_vals[it->colnum], (uint64_t)it->double_counter/it->num);
                    break;
                case FT_RELATIVE_TIME:
                    parent->max_vals[it->colnum] =
                        MAX(parent->max_vals[it->colnum], ((it->counter/(uint64_t)it->num) + UINT64_C(500000000)) / NANOSECS_PER_SEC);
                    break;
                default:
                    /* UINT16-64 and INT8-64 */
                    parent->max_vals[it->colnum] =
                        MAX(parent->max_vals[it->colnum], it->counter/it->num);
                    break;
            }
    }
    return TAP_PACKET_REDRAW;
}

static unsigned int
magnitude (uint64_t val, unsigned int max_w)
{
    unsigned int i, mag = 0;

    for (i=0; i<max_w; i++) {
        mag++;
        if ((val /= 10) == 0)
            break;
    }
    return(mag);
}

/*
*  Print the calc_type_table[] function label centered in the column header.
*/
static void
printcenter (const char *label, int lenval, int numpad)
{
    int lenlab = (int) strlen(label), len;
    const char spaces[] = "      ", *spaces_ptr;

    len = (int) (strlen(spaces)) - (((lenval-lenlab) / 2) + numpad);
    if (len > 0 && len < 6) {
        spaces_ptr = &spaces[len];
        if ((lenval-lenlab)%2 == 0) {
            printf("%s%s%s|", spaces_ptr, label, spaces_ptr);
        } else {
            printf("%s%s%s|", spaces_ptr-1, label, spaces_ptr);
        }
    } else if (len > 0 && len <= 15) {
        printf("%s|", label);
    }
}

typedef struct {
    int fr;  /* Width of this FRAMES column sans padding and border chars */
    int val; /* Width of this non-FRAMES column sans padding and border chars */
} column_width;

static void
fill_abs_time(const nstime_t* the_time, char *time_buf, char *decimal_point, unsigned invl_prec, bool local)
{
    struct tm tm, *tmp;
    char *ptr;
    size_t remaining = NSTIME_ISO8601_BUFSIZE;
    int num_bytes;

    if (local) {
        tmp = ws_localtime_r(&the_time->secs, &tm);
    } else {
        tmp = ws_gmtime_r(&the_time->secs, &tm);
    }

    if (tmp == NULL) {
        snprintf(time_buf, remaining, "XX:XX:XX");
        return;
    }

    ptr = time_buf;
    num_bytes = snprintf(time_buf, NSTIME_ISO8601_BUFSIZE,
        "%02d:%02d:%02d",
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec);
    if (num_bytes < 0) {
        // snprintf failed
        snprintf(time_buf, remaining, "XX:XX:XX");
        return;
    }
    ptr += num_bytes;
    remaining -= num_bytes;
    if (invl_prec != 0) {
        num_bytes = format_fractional_part_nsecs(ptr, remaining,
            (uint32_t)the_time->nsecs, decimal_point, invl_prec);
        ptr += num_bytes;
        remaining -= num_bytes;
    }

    if (!local) {
        if (remaining == 1 && num_bytes > 0) {
            /*
             * If we copied a fractional part but there's only room
             * for the terminating '\0', replace the last digit of
             * the fractional part with the "Z". (Remaining is at
             * least 1, otherwise we would have returned above.)
             */
            ptr--;
            remaining++;
        }
        (void)g_strlcpy(ptr, "Z", remaining);
    }
    return;
}

static void
fill_abs_ydoy_time(const nstime_t* the_time, char *time_buf, char *decimal_point, unsigned invl_prec, bool local)
{
    struct tm tm, *tmp;
    char *ptr;
    size_t remaining = NSTIME_ISO8601_BUFSIZE;
    int num_bytes;

    if (local) {
        tmp = ws_localtime_r(&the_time->secs, &tm);
    } else {
        tmp = ws_gmtime_r(&the_time->secs, &tm);
    }

    if (tmp == NULL) {
        snprintf(time_buf, remaining, "XXXX/XXX XX:XX:XX");
        return;
    }

    ptr = time_buf;
    num_bytes = snprintf(time_buf, NSTIME_ISO8601_BUFSIZE,
        "%04d/%03d %02d:%02d:%02d",
        tmp->tm_year + 1900,
        tmp->tm_yday + 1,
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec);
    if (num_bytes < 0) {
        // snprintf failed
        snprintf(time_buf, remaining, "XXXX/XXX XX:XX:XX");
        return;
    }
    ptr += num_bytes;
    remaining -= num_bytes;
    if (invl_prec != 0) {
        num_bytes = format_fractional_part_nsecs(ptr, remaining,
            (uint32_t)the_time->nsecs, decimal_point, invl_prec);
        ptr += num_bytes;
        remaining -= num_bytes;
    }

    if (!local) {
        if (remaining == 1 && num_bytes > 0) {
            /*
             * If we copied a fractional part but there's only room
             * for the terminating '\0', replace the last digit of
             * the fractional part with the "Z". (Remaining is at
             * least 1, otherwise we would have returned above.)
             */
            ptr--;
            remaining++;
        }
        (void)g_strlcpy(ptr, "Z", remaining);
    }
    return;
}

/* Calc the total width of each row in the stats table and build the printf format string for each
*  column based on its field type, width, and name length.
*  NOTE: The magnitude of all types including float and double are stored in iot->max_vals which
*        is an *integer*. */
static unsigned
iostat_calc_cols_width_and_fmt(io_stat_t *iot, uint64_t interval, column_width* col_w, char**fmts)
{
    unsigned tabrow_w, type, ftype, namelen;
    unsigned fr_mag;    /* The magnitude of the max frame number in this column */
    unsigned val_mag;   /* The magnitude of the max value in this column */
    char *fmt = NULL;

    tabrow_w = 0;
    for (unsigned j=0; j < iot->num_cols; j++) {
        type = iot->calc_type[j];
        if (type == CALC_TYPE_FRAMES_AND_BYTES) {
            namelen = 5;
        } else {
            namelen = (unsigned int)strlen(calc_type_table[type].func_name);
        }
        if (type == CALC_TYPE_FRAMES
         || type == CALC_TYPE_FRAMES_AND_BYTES) {

            fr_mag = magnitude(iot->max_frame[j], 15);
            fr_mag = MAX(6, fr_mag);
            col_w[j].fr = fr_mag;
            tabrow_w += col_w[j].fr + 3;

            if (type == CALC_TYPE_FRAMES) {
                fmt = g_strdup_printf(" %%%uu |", fr_mag);
            } else {
                /* CALC_TYPE_FRAMES_AND_BYTES
                */
                val_mag = magnitude(iot->max_vals[j], 15);
                val_mag = MAX(5, val_mag);
                col_w[j].val = val_mag;
                tabrow_w += (col_w[j].val + 3);
                fmt = g_strdup_printf(" %%%uu | %%%u"PRIu64 " |", fr_mag, val_mag);
            }
            if (fmt)
                fmts[j] = fmt;
            continue;
        }
        switch (type) {
        case CALC_TYPE_BYTES:
        case CALC_TYPE_COUNT:

            val_mag = magnitude(iot->max_vals[j], 15);
            val_mag = MAX(5, val_mag);
            col_w[j].val = val_mag;
            fmt = g_strdup_printf(" %%%u"PRIu64" |", val_mag);
            break;

        default:
            ftype = proto_registrar_get_ftype(iot->hf_indexes[j]);
            switch (ftype) {
                case FT_FLOAT:
                case FT_DOUBLE:
                    val_mag = magnitude(iot->max_vals[j], 15);
                    fmt = g_strdup_printf(" %%%u.6f |", val_mag);
                    col_w[j].val = val_mag + 7;
                    break;
                case FT_RELATIVE_TIME:
                    /* Convert FT_RELATIVE_TIME field to seconds
                    *  CALC_TYPE_LOAD was already converted in iostat_packet() ) */
                    if (type == CALC_TYPE_LOAD) {
                        iot->max_vals[j] /= interval;
                    } else if (type != CALC_TYPE_AVG) {
                        iot->max_vals[j] = (iot->max_vals[j] + UINT64_C(500000000)) / NANOSECS_PER_SEC;
                    }
                    val_mag = magnitude(iot->max_vals[j], 15);
                    fmt = g_strdup_printf(" %%%uu.%%06u |", val_mag);
                    col_w[j].val = val_mag + 7;
                   break;

                default:
                    val_mag = magnitude(iot->max_vals[j], 15);
                    val_mag = MAX(namelen, val_mag);
                    col_w[j].val = val_mag;

                    switch (ftype) {
                    case FT_UINT8:
                    case FT_UINT16:
                    case FT_UINT24:
                    case FT_UINT32:
                    case FT_UINT64:
                        fmt = g_strdup_printf(" %%%u"PRIu64 " |", val_mag);
                        break;
                    case FT_INT8:
                    case FT_INT16:
                    case FT_INT24:
                    case FT_INT32:
                    case FT_INT64:
                        fmt = g_strdup_printf(" %%%u"PRId64 " |", val_mag);
                        break;
                    }
            } /* End of ftype switch */
        } /* End of calc_type switch */
        tabrow_w += col_w[j].val + 3;
        if (fmt)
            fmts[j] = fmt;
    } /* End of for loop (columns) */

    return tabrow_w;
}

static void
iostat_draw_filters(unsigned borderlen, const io_stat_t *iot)
{
    const char *filter;
    size_t len_filt;
    GString *filt_str;

    /* Display the list of filters and their column numbers vertically */
    for (unsigned j=0; j<iot->num_cols; j++) {
        if (j == 0) {
            filt_str = g_string_new("| Col ");
        } else {
            filt_str = g_string_new("|     ");
        };
        g_string_append_printf(filt_str, "%2u: ", j + 1);
        if (!iot->filters[j]) {
            /* An empty (no filter) comma field was specified */
            g_string_append(filt_str, "Frames and bytes");
        } else {
            filter = iot->filters[j];
            len_filt = strlen(filter);
            /* borderlen has been adjusted to try to accommodate the widest
             * filter, but only up to a limit (currently 102 bytes), and so
             * filters wider than that must still wrap. */
            /* 11 is the length of "| Col XX: " plus the trailing "|" */
            size_t max_w = borderlen - 11;

            while (len_filt > max_w) {
                const char *pos;
                size_t len;
                unsigned int next_start;

                /* Find the pos of the last space in filter up to max_w. If a
                 * space is found, copy up to that space; otherwise, wrap the
                 * filter at max_w. */
                pos = g_strrstr_len(filter, max_w, " ");
                if (pos) {
                    len = (size_t)(pos-filter);
                    /* Skip the space when wrapping. */
                    next_start = (unsigned int) len+1;
                } else {
                    len = max_w;
                    next_start = (unsigned int)len;
                }
                g_string_append_len(filt_str, filter, len);
                g_string_append_printf(filt_str, "%*s", (int)(borderlen - filt_str->len), "|");

                puts(filt_str->str);
                g_string_free(filt_str, TRUE);

                filt_str = g_string_new("|         ");
                filter = &filter[next_start];
                len_filt = strlen(filter);
            }

            g_string_append(filt_str, filter);
        }
        g_string_append_printf(filt_str, "%*s", (int)(borderlen - filt_str->len), "|");
        puts(filt_str->str);
        g_string_free(filt_str, TRUE);
    }
}

static void
iostat_draw_header(unsigned borderlen, const io_stat_t *iot, const nstime_t *duration, const nstime_t *interval, ws_tsprec_e invl_prec)
{
    unsigned i;
    char time_buf[NSTIME_ISO8601_BUFSIZE];

    /* Display the top border */
    printf("\n");
    for (i=0; i<borderlen; i++)
        printf("=");

    printf("\n|%-*s|\n", borderlen - 2, " IO Statistics");
    printf("|%-*s|\n", borderlen - 2, "");

    /* For some reason, we print the total duration in microsecond precision
     * here if the interval is in seconds precision, and use the interval
     * precision otherwise.
     */
    ws_tsprec_e dur_prec = (invl_prec == WS_TSPREC_SEC) ? WS_TSPREC_USEC : invl_prec;
    nstime_t dur_rounded;
    nstime_rounded(&dur_rounded, duration, dur_prec);
    int dur_mag = magnitude(duration->secs, 5);
    int dur_w = dur_mag + (invl_prec == 0 ? 0 : invl_prec+1);

    GString *dur_str = g_string_new("| Duration: ");
    display_signed_time(time_buf, NSTIME_ISO8601_BUFSIZE, &dur_rounded, dur_prec);
    g_string_append_printf(dur_str, "%*s secs", dur_w, time_buf);
    g_string_append_printf(dur_str, "%*s", (int)(borderlen - dur_str->len), "|");
    puts(dur_str->str);
    g_string_free(dur_str, TRUE);

    GString *invl_str = g_string_new("| Interval: ");
    display_signed_time(time_buf, NSTIME_ISO8601_BUFSIZE, interval, invl_prec);
    g_string_append_printf(invl_str, "%*s secs", dur_w, time_buf);
    g_string_append_printf(invl_str, "%*s", (int)(borderlen - invl_str->len), "|");
    puts(invl_str->str);
    g_string_free(invl_str, TRUE);

    printf("|%-*s|\n", borderlen - 2, "");

    iostat_draw_filters(borderlen, iot);

    printf("|-");
    for (i=0; i<borderlen-3; i++) {
        printf("-");
    }
    printf("|\n");
}

static void
iostat_draw_header_row(unsigned borderlen, const io_stat_t *iot, const column_width *col_w, unsigned invl_col_w, unsigned tabrow_w)
{
    unsigned j, type, numpad = 1;
    char *filler_s = NULL;

    /* Display spaces above "Interval (s)" label */
    printf("|%*s", invl_col_w - 1, "|");

    /* Display column number headers */
    for (j=0; j < iot->num_cols; j++) {
        int padding;
        if (iot->calc_type[j] == CALC_TYPE_FRAMES_AND_BYTES)
            padding = col_w[j].fr + col_w[j].val + 3;
        else if (iot->calc_type[j] == CALC_TYPE_FRAMES)
            padding = col_w[j].fr;
        else
            padding = col_w[j].val;

        printf("%-2d%*s|", j+1, padding, "");
    }
    if (tabrow_w < borderlen) {
        filler_s = g_strdup_printf("%*s", borderlen - tabrow_w, "|");
        printf("%s", filler_s);
    }
    printf("\n");

    GString *timestamp_str;
    switch (timestamp_get_type()) {
    case TS_ABSOLUTE:
    case TS_UTC:
        timestamp_str = g_string_new("| Time    ");
        break;
    case TS_ABSOLUTE_WITH_YMD:
    case TS_ABSOLUTE_WITH_YDOY:
    case TS_UTC_WITH_YMD:
    case TS_UTC_WITH_YDOY:
        timestamp_str = g_string_new("| Date and time");
        break;
    case TS_RELATIVE:
    case TS_NOT_SET:
        timestamp_str = g_string_new("| Interval");
        break;
    default:
        timestamp_str = g_string_new(NULL);
        break;
    }

    printf("%s%*s", timestamp_str->str, (int)(invl_col_w - timestamp_str->len), "|");
    g_string_free(timestamp_str, TRUE);

    /* Display the stat label in each column */
    for (j=0; j < iot->num_cols; j++) {
        type = iot->calc_type[j];
        if (type == CALC_TYPE_FRAMES) {
            printcenter (calc_type_table[type].func_name, col_w[j].fr, numpad);
        } else if (type == CALC_TYPE_FRAMES_AND_BYTES) {
            printcenter ("Frames", col_w[j].fr, numpad);
            printcenter ("Bytes", col_w[j].val, numpad);
        } else {
            printcenter (calc_type_table[type].func_name, col_w[j].val, numpad);
        }
    }
    if (filler_s) {
        printf("%s", filler_s);
    }
    printf("\n|-");

    for (j=0; j<tabrow_w-3; j++)
        printf("-");
    printf("|");

    if (filler_s) {
        printf("%s", filler_s);
        g_free(filler_s);
    }

    printf("\n");
}

static void
iostat_draw(void *arg)
{
    uint32_t num;
    uint64_t interval, duration, t, invl_end, dv;
    unsigned int i, j, k, num_cols, num_rows, dur_secs, dur_mag,
        invl_mag, invl_prec, tabrow_w, borderlen, invl_col_w, type,
        maxfltr_w, ftype;
    char **fmts, *fmt = NULL;
    static char *invl_fmt, *full_fmt;
    io_stat_item_t *mit, **stat_cols, *item, **item_in_column;
    bool last_row = false;
    io_stat_t *iot;
    column_width *col_w;
    char time_buf[NSTIME_ISO8601_BUFSIZE];

    mit = (io_stat_item_t *)arg;
    iot = mit->parent;
    num_cols = iot->num_cols;
    col_w = g_new(column_width, num_cols);
    fmts = (char **)g_malloc(sizeof(char *) * num_cols);
    duration = ((uint64_t)cfile.elapsed_time.secs * UINT64_C(1000000)) +
                (uint64_t)((cfile.elapsed_time.nsecs + 500) / 1000);

    /* Store the pointer to each stat column */
    stat_cols = (io_stat_item_t **)g_malloc(sizeof(io_stat_item_t *) * num_cols);
    for (j=0; j<num_cols; j++)
        stat_cols[j] = &iot->items[j];

    /* The following prevents gross inaccuracies when the user specifies an interval that is greater
    *  than the capture duration. */
    if (iot->interval > duration || iot->interval == UINT64_MAX) {
        interval = duration;
        iot->interval = UINT64_MAX;
    } else {
        interval = iot->interval;
    }

    /* Calc the capture duration's magnitude (dur_mag) */
    dur_secs  = (unsigned int)(duration/UINT64_C(1000000));
    dur_mag = magnitude((uint64_t)dur_secs, 5);

    /* Calc the interval's magnitude */
    invl_mag = magnitude(interval/UINT64_C(1000000), 5);

    /* Set or get the interval precision */
    if (interval == duration) {
        /*
        * An interval arg of 0 or an interval size exceeding the capture duration was specified.
        * Set the decimal precision of duration based on its magnitude. */
        if (dur_mag >= 2)
            invl_prec = 1;
        else if (dur_mag == 1)
            invl_prec = 3;
        else
            invl_prec = 6;

        borderlen = 30 + dur_mag + (invl_prec == 0 ? 0 : invl_prec+1);
    } else {
        invl_prec = iot->invl_prec;
        borderlen = 25 + MAX(invl_mag,dur_mag) + (invl_prec == 0 ? 0 : invl_prec+1);
    }

    /* Round the duration according to invl_prec */
    dv = 1000000;
    for (i=0; i<invl_prec; i++)
        dv /= 10;
    if ((duration%dv) > 5*(dv/10)) {
        duration += 5*(dv/10);
        duration = (duration/dv) * dv;
        dur_secs  = (unsigned int)(duration/UINT64_C(1000000));
        /*
         * Recalc dur_mag in case rounding has increased its magnitude */
        dur_mag  = magnitude((uint64_t)dur_secs, 5);
    }
    if (iot->interval == UINT64_MAX)
        interval = duration;

    //int dur_w = dur_mag + (invl_prec == 0 ? 0 : invl_prec+1);

    /* Calc the width of the time interval column (incl borders and padding). */
    if (invl_prec == 0) {
        invl_fmt = g_strdup_printf("%%%du", dur_mag);
        invl_col_w = (2*dur_mag) + 8;
    } else {
        invl_fmt = g_strdup_printf("%%%du.%%0%du", dur_mag, invl_prec);
        invl_col_w = (2*dur_mag) + (2*invl_prec) + 10;
    }

    /* Update the width of the time interval column if date is shown */
    switch (timestamp_get_type()) {
    case TS_ABSOLUTE_WITH_YMD:
    case TS_ABSOLUTE_WITH_YDOY:
    case TS_UTC_WITH_YMD:
    case TS_UTC_WITH_YDOY:
        // We don't show more than 6 fractional digits (+Z) currently.
        // NSTIME_ISO8601_BUFSIZE is enough room for 9 frac digits + Z + '\0'
        // That's 4 extra characters, which leaves room for the "|  |".
        invl_col_w = MAX(invl_col_w, NSTIME_ISO8601_BUFSIZE + invl_prec - 6);
        break;

    default:
        // Make it as least as twice as wide as "> Dur|" for the final interval
        invl_col_w = MAX(invl_col_w, 12);
        break;
    }

    /* Calculate the width and format string of all the other columns, and add
     * the total to the interval column width for the entire total. */
    tabrow_w = invl_col_w + iostat_calc_cols_width_and_fmt(iot, interval, col_w, fmts);

    borderlen = MAX(borderlen, tabrow_w);

    /* Calc the max width of the list of filters. */
    maxfltr_w = 0;
    for (j=0; j<num_cols; j++) {
        if (iot->filters[j]) {
            k = (unsigned int) (strlen(iot->filters[j]) + 11);
            maxfltr_w = MAX(maxfltr_w, k);
        } else {
            maxfltr_w = MAX(maxfltr_w, 26);
        }
    }
    /* The stat table is not wrapped (by tshark) but filter is wrapped at the width of the stats table
    *  (which currently = borderlen); however, if the filter width exceeds the table width and the
    *  table width is less than 102 bytes, set borderlen to the lesser of the max filter width and 102.
    *  The filters will wrap at the lesser of borderlen-2 and the last space in the filter.
    *  NOTE: 102 is the typical size of a user window when the font is fixed width (e.g., COURIER 10).
    *  XXX: A pref could be added to change the max width from the default size of 102. */
    if (maxfltr_w > borderlen && borderlen < 102)
            borderlen = MIN(maxfltr_w, 102);

    /* Prevent double right border by adding a space */
    if (borderlen-tabrow_w == 1)
        borderlen++;

    nstime_t invl_time = NSTIME_INIT_SECS_USECS(interval/UINT64_C(1000000), interval%UINT64_C(1000000));
    iostat_draw_header(borderlen, iot, &cfile.elapsed_time, &invl_time, invl_prec);

    iostat_draw_header_row(borderlen, iot, col_w, invl_col_w, tabrow_w);

    t = 0;
    if (invl_prec == 0 && dur_mag == 1)
        full_fmt = g_strconcat("|  ", invl_fmt, " <> ", invl_fmt, "  |", NULL);
    else
        full_fmt = g_strconcat("| ", invl_fmt, " <> ", invl_fmt, " |", NULL);

    if (interval == 0 || duration == 0) {
        num_rows = 0;
    } else {
        num_rows = (unsigned int)(duration/interval) + ((unsigned int)(duration%interval) > 0 ? 1 : 0);
    }

    /* Load item_in_column with the first item in each column */
    item_in_column = (io_stat_item_t **)g_malloc(sizeof(io_stat_item_t *) * num_cols);
    for (j=0; j<num_cols; j++) {
        item_in_column[j] = stat_cols[j];
    }

    /* Display the table values
    *
    * The outer loop is for time interval rows and the inner loop is for stat column items.*/
    for (i=0; i<num_rows; i++) {

        if (i == num_rows-1)
            last_row = true;

        /* Compute the interval for this row */
        if (!last_row) {
            invl_end = t + interval;
        } else {
            invl_end = duration;
        }

        /* Patch for Absolute Time */
        /* XXX - has a Y2.038K problem with 32-bit time_t */
        nstime_t the_time = NSTIME_INIT_SECS_USECS(t / 1000000, t % 1000000);
        nstime_add(&the_time, &iot->start_time);

        /* Display the interval for this row */
        switch (timestamp_get_type()) {
        case TS_ABSOLUTE:
          fill_abs_time(&the_time, time_buf, io_decimal_point, invl_prec, true);
          // invl_col_w includes the "|  |"
          printf("| %-*s |", invl_col_w - 4, time_buf);
          break;

        case TS_ABSOLUTE_WITH_YMD:
          format_nstime_as_iso8601(time_buf, NSTIME_ISO8601_BUFSIZE, &the_time,
            io_decimal_point, true, invl_prec);
          printf("| %-*s |", invl_col_w - 4, time_buf);
          break;

        case TS_ABSOLUTE_WITH_YDOY:
          fill_abs_ydoy_time(&the_time, time_buf, io_decimal_point, invl_prec, true);
          printf("| %-*s |", invl_col_w - 4, time_buf);
          break;

        case TS_UTC:
          fill_abs_time(&the_time, time_buf, io_decimal_point, invl_prec, false);
          printf("| %-*s |", invl_col_w - 4, time_buf);
          break;

        case TS_UTC_WITH_YMD:
          format_nstime_as_iso8601(time_buf, NSTIME_ISO8601_BUFSIZE, &the_time,
            io_decimal_point, false, invl_prec);
          printf("| %-*s |", invl_col_w - 4, time_buf);
          break;

        case TS_UTC_WITH_YDOY:
          fill_abs_ydoy_time(&the_time, time_buf, io_decimal_point, invl_prec, false);
          printf("| %-*s |", invl_col_w - 4, time_buf);
          break;

        case TS_RELATIVE:
        case TS_NOT_SET:
          if (invl_prec == 0) {
              if (last_row) {
                  int maxw;
                  maxw = dur_mag >= 3 ? dur_mag+1 : 3;
                  g_free(full_fmt);
                  full_fmt = g_strdup_printf("| %s%s <> %%-%ds|",
                                            dur_mag == 1 ? " " : "",
                                            invl_fmt, maxw);
                  printf(full_fmt, (uint32_t)(t/UINT64_C(1000000)), "Dur");
              } else {
                  printf(full_fmt, (uint32_t)(t/UINT64_C(1000000)),
                         (uint32_t)(invl_end/UINT64_C(1000000)));
              }
          } else {
              printf(full_fmt, (uint32_t)(t/UINT64_C(1000000)),
                     (uint32_t)(t%UINT64_C(1000000) / dv),
                     (uint32_t)(invl_end/UINT64_C(1000000)),
                     (uint32_t)(invl_end%UINT64_C(1000000) / dv));
          }
          break;
     /* case TS_DELTA:
        case TS_DELTA_DIS:
        case TS_EPOCH:
            are not implemented */
        default:
          break;
        }

        /* Display stat values in each column for this row */
        for (j=0; j<num_cols; j++) {
            fmt = fmts[j];
            item = item_in_column[j];
            type = iot->calc_type[j];

            if (item) {
                switch (type) {
                case CALC_TYPE_FRAMES:
                    printf(fmt, item->frames);
                    break;
                case CALC_TYPE_BYTES:
                case CALC_TYPE_COUNT:
                    printf(fmt, item->counter);
                    break;
                case CALC_TYPE_FRAMES_AND_BYTES:
                    printf(fmt, item->frames, item->counter);
                    break;

                case CALC_TYPE_SUM:
                case CALC_TYPE_MIN:
                case CALC_TYPE_MAX:
                    ftype = proto_registrar_get_ftype(iot->hf_indexes[j]);
                    switch (ftype) {
                    case FT_FLOAT:
                        printf(fmt, item->float_counter);
                        break;
                    case FT_DOUBLE:
                        printf(fmt, item->double_counter);
                        break;
                    case FT_RELATIVE_TIME:
                        item->counter = (item->counter + UINT64_C(500)) / UINT64_C(1000);
                        printf(fmt,
                               (int)(item->counter/UINT64_C(1000000)),
                               (int)(item->counter%UINT64_C(1000000)));
                        break;
                    default:
                        printf(fmt, item->counter);
                        break;
                    }
                    break;

                case CALC_TYPE_AVG:
                    num = item->num;
                    if (num == 0)
                        num = 1;
                    ftype = proto_registrar_get_ftype(iot->hf_indexes[j]);
                    switch (ftype) {
                    case FT_FLOAT:
                        printf(fmt, item->float_counter/num);
                        break;
                    case FT_DOUBLE:
                        printf(fmt, item->double_counter/num);
                        break;
                    case FT_RELATIVE_TIME:
                        item->counter = ((item->counter / (uint64_t)num) + UINT64_C(500)) / UINT64_C(1000);
                        printf(fmt,
                               (int)(item->counter/UINT64_C(1000000)),
                               (int)(item->counter%UINT64_C(1000000)));
                        break;
                    default:
                        printf(fmt, item->counter / (uint64_t)num);
                        break;
                    }
                    break;

                case CALC_TYPE_LOAD:
                    ftype = proto_registrar_get_ftype(iot->hf_indexes[j]);
                    switch (ftype) {
                    case FT_RELATIVE_TIME:
                        if (!last_row) {
                            printf(fmt,
                                (int) (item->counter/interval),
                                   (int)((item->counter%interval)*UINT64_C(1000000) / interval));
                        } else {
                            printf(fmt,
                                   (int) (item->counter/(invl_end-t)),
                                   (int)((item->counter%(invl_end-t))*UINT64_C(1000000) / (invl_end-t)));
                        }
                        break;
                    }
                    break;
                }

                if (last_row) {
                    g_free(fmt);
                } else {
                    item_in_column[j] = item_in_column[j]->next;
                }
            } else {
                printf(fmt, (uint64_t)0, (uint64_t)0);
            }
        }
        if (tabrow_w < borderlen) {
            printf("%*s", borderlen - tabrow_w, "|");
        }
        printf("\n");
        t += interval;

    }
    for (i=0; i<borderlen; i++) {
        printf("=");
    }
    printf("\n");
    g_free(iot->items);
    for (i = 0; i < iot->num_cols; i++) {
        g_free((char*)iot->filters[i]);
    }
    g_free((gpointer)iot->filters);
    g_free(iot->max_vals);
    g_free(iot->max_frame);
    g_free(iot->hf_indexes);
    g_free(iot->calc_type);
    g_free(iot);
    g_free(col_w);
    g_free(invl_fmt);
    g_free(full_fmt);
    g_free(fmts);
    g_free(stat_cols);
    g_free(item_in_column);
}


static bool
register_io_tap(io_stat_t *io, unsigned int i, const char *filter, GString *err)
{
    GString *error_string;
    const char *flt;
    int j;
    size_t namelen;
    const char *p, *parenp;
    char *field;
    header_field_info *hfi;

    io->items[i].prev       = &io->items[i];
    io->items[i].next       = NULL;
    io->items[i].parent     = io;
    io->items[i].start_time = 0;
    io->items[i].frames     = 0;
    io->items[i].counter    = 0;
    io->items[i].num        = 0;

    io->filters[i] = filter;
    flt = filter;

    io->calc_type[i] = CALC_TYPE_FRAMES_AND_BYTES;
    field = NULL;
    hfi = NULL;
    for (j=0; calc_type_table[j].func_name; j++) {
        namelen = strlen(calc_type_table[j].func_name);
        if (filter && strncmp(filter, calc_type_table[j].func_name, namelen) == 0) {
            io->calc_type[i] = calc_type_table[j].calc_type;
            io->items[i].colnum = i;
            if (*(filter+namelen) == '(') {
                p = filter+namelen+1;
                parenp = strchr(p, ')');
                if (!parenp) {
                    cmdarg_err("\ntshark: Closing parenthesis missing from calculated expression.\n");
                    return false;
                }

                if (io->calc_type[i] == CALC_TYPE_FRAMES || io->calc_type[i] == CALC_TYPE_BYTES) {
                    if (parenp != p) {
                        cmdarg_err("\ntshark: %s does not require or allow a field name within the parens.\n",
                            calc_type_table[j].func_name);
                        return false;
                    }
                } else {
                    if (parenp == p) {
                            /* bail out if a field name was not specified */
                            cmdarg_err("\ntshark: You didn't specify a field name for %s(*).\n",
                                calc_type_table[j].func_name);
                            return false;
                    }
                }

                field = (char *)g_malloc(parenp-p+1);
                memcpy(field, p, parenp-p);
                field[parenp-p] = '\0';
                flt = parenp + 1;
                if (io->calc_type[i] == CALC_TYPE_FRAMES || io->calc_type[i] == CALC_TYPE_BYTES)
                    break;
                hfi = proto_registrar_get_byname(field);
                if (!hfi) {
                    cmdarg_err("\ntshark: There is no field named '%s'.\n", field);
                    g_free(field);
                    return false;
                }

                io->hf_indexes[i] = hfi->id;
                break;
            }
        } else {
            if (io->calc_type[i] == CALC_TYPE_FRAMES || io->calc_type[i] == CALC_TYPE_BYTES)
                flt = "";
            io->items[i].colnum = i;
        }
    }
    if (hfi && !(io->calc_type[i] == CALC_TYPE_BYTES ||
                 io->calc_type[i] == CALC_TYPE_FRAMES ||
                 io->calc_type[i] == CALC_TYPE_FRAMES_AND_BYTES)) {
        /* check that the type is compatible */
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
            /* these types support all calculations */
            break;
        case FT_FLOAT:
        case FT_DOUBLE:
            /* these types only support SUM, COUNT, MAX, MIN, AVG */
            switch (io->calc_type[i]) {
            case CALC_TYPE_SUM:
            case CALC_TYPE_COUNT:
            case CALC_TYPE_MAX:
            case CALC_TYPE_MIN:
            case CALC_TYPE_AVG:
                break;
            default:
                cmdarg_err("\ntshark: %s is a float field, so %s(*) calculations are not supported on it.",
                    field,
                    calc_type_table[j].func_name);
                return false;
            }
            break;
        case FT_RELATIVE_TIME:
            /* this type only supports SUM, COUNT, MAX, MIN, AVG, LOAD */
            switch (io->calc_type[i]) {
            case CALC_TYPE_SUM:
            case CALC_TYPE_COUNT:
            case CALC_TYPE_MAX:
            case CALC_TYPE_MIN:
            case CALC_TYPE_AVG:
            case CALC_TYPE_LOAD:
                break;
            default:
                cmdarg_err("\ntshark: %s is a relative-time field, so %s(*) calculations are not supported on it.",
                    field,
                    calc_type_table[j].func_name);
                return false;
            }
            break;
        default:
            /*
             * XXX - support all operations on floating-point
             * numbers?
             */
            if (io->calc_type[i] != CALC_TYPE_COUNT) {
                cmdarg_err("\ntshark: %s doesn't have integral values, so %s(*) "
                    "calculations are not supported on it.\n",
                    field,
                    calc_type_table[j].func_name);
                return false;
            }
            break;
        }
    }
    g_free(field);

    error_string = register_tap_listener("frame", &io->items[i], flt, TL_REQUIRES_PROTO_TREE, NULL,
                                       iostat_packet, i ? NULL : iostat_draw, NULL);
    if (error_string) {
        /* Accumulate errors about all the possible filters tried at the same
         * starting character.
         */
        if (err->len) {
            g_string_append_c(err, '\n');
        }
        g_string_append(err, error_string->str);
        g_string_free(error_string, TRUE);
        return false;
    }

    /* On success, clear old errors (from splitting on internal commas). */
    g_string_truncate(err, 0);
    return true;
}

static bool
iostat_init(const char *opt_arg, void *userdata _U_)
{
    double interval_float;
    uint32_t idx = 0;
    unsigned int i;
    io_stat_t *io;
    const char *filters, *str, *pos;

    io_decimal_point = localeconv()->decimal_point;

    /* XXX - Why can't the last character be a comma? Shouldn't it be
     * fine for the last filter to be empty? Even in the case of locales
     * that use ',' for the decimal separator, there shouldn't be any
     * difference between interpreting a terminating ',' as a decimal
     * point for the interval, and interpreting it as a separator followed
     * by an empty filter.
     */
    if ((*(opt_arg+(strlen(opt_arg)-1)) == ',') ||
        (sscanf(opt_arg, "io,stat,%lf%n", &interval_float, (int *)&idx) != 1) ||
        (idx < 8)) {
        cmdarg_err("\ntshark: invalid \"-z io,stat,<interval>[,<filter>][,<filter>]...\" argument\n");
        return false;
    }

    filters = opt_arg+idx;
    if (*filters) {
        if (*filters != ',') {
            /* For locales that use ',' instead of '.', the comma might
             * have been consumed during the floating point conversion. */
            --filters;
            if (*filters != ',') {
                cmdarg_err("\ntshark: invalid \"-z io,stat,<interval>[,<filter>][,<filter>]...\" argument\n");
                return false;
            }
        }
    }
    /* filters now either starts with ',' or '\0' */

    switch (timestamp_get_type()) {
    case TS_DELTA:
    case TS_DELTA_DIS:
    case TS_EPOCH:
        cmdarg_err("\ntshark: invalid -t operand. io,stat only supports -t <r|a|ad|adoy|u|ud|udoy>\n");
        return false;
    default:
        break;
    }

    io = g_new(io_stat_t, 1);

    /* If interval is 0, calculate statistics over the whole file by setting the interval to
    *  UINT64_MAX */
    if (interval_float == 0) {
        io->interval = UINT64_MAX;
        io->invl_prec = 0;
    } else {
        /* Set interval to the number of us rounded to the nearest integer */
        io->interval = (uint64_t)(interval_float * 1000000.0 + 0.5);
        /*
        * Determine what interval precision the user has specified */
        io->invl_prec = 6;
        for (i=10; i<10000000; i*=10) {
            if (io->interval%i > 0)
                break;
            io->invl_prec--;
        }
        if (io->invl_prec == 0) {
            /* The precision is zero but if the user specified one of more zeros after the decimal point,
               they want that many decimal places shown in the table for all time intervals except
               response time values such as smb.time which always have 6 decimal places of precision.
               This feature is useful in cases where for example the duration is 9.1, you specify an
               interval of 1 and the last interval becomes "9 <> 9". If the interval is instead set to
               1.1, the last interval becomes
               last interval is rounded up to value that is greater than the duration. */
            const char *invl_start = opt_arg+8;
            char *intv_end;
            int invl_len;

            intv_end = g_strstr_len(invl_start, -1, ",");
            invl_len = (int)(intv_end - invl_start);
            invl_start = g_strstr_len(invl_start, invl_len, ".");

            if (invl_start != NULL) {
                invl_len = (int)(intv_end - invl_start - 1);
                if (invl_len)
                    io->invl_prec = MIN(invl_len, 6);
            }
        }
    }
    if (io->interval < 1) {
        cmdarg_err("\ntshark: \"-z\" interval must be >=0.000001 seconds or \"0\" for the entire capture duration.\n");
        return false;
    }

    /* Find how many ',' separated filters we have */
    /* Filter can have internal commas, so this is only an upper bound on the
     * number of filters. In the display filter grammar, commas only appear
     * inside delimiters (quoted strings, slices, sets, and functions), so
     * splitting in the wrong place produces an invalid filter. That is, there
     * can be at most only one valid interpretation (but might be none).
     *
     * XXX - If the grammar changes to allow commas in other places, then there
     * is ambiguity.
     *
     * Perhaps ideally we'd verify the filters before doing allocation.
     */
    io->num_cols = 1;
    nstime_set_unset(&io->start_time);

    if (*filters != '\0') {
        /* Eliminate the first comma. */
        filters++;
        str = filters;
        while ((str = strchr(str, ','))) {
            io->num_cols++;
            str++;
        }
    }

    io->items      = g_new(io_stat_item_t, io->num_cols);
    io->filters    = (const char **)g_malloc(sizeof(char *) * io->num_cols);
    io->max_vals   = g_new(uint64_t, io->num_cols);
    io->max_frame  = g_new(uint32_t, io->num_cols);
    io->hf_indexes = g_new(int, io->num_cols);
    io->calc_type  = g_new(int, io->num_cols);

    for (i=0; i<io->num_cols; i++) {
        io->max_vals[i]  = 0;
        io->max_frame[i] = 0;
    }

    bool success;
    GString *err = g_string_new(NULL);

    /* Register a tap listener for each filter */
    if (filters[0] == '\0') {
        success = register_io_tap(io, 0, NULL, err);
    } else {
        char *filter;
        i = 0;
        str = filters;
        pos = str;
        while ((pos = strchr(pos, ',')) != NULL) {
            if (pos == str) {
                /* Consecutive commas - an empty filter. */
                filter = NULL;
            } else {
                /* Likely a filter. */
                filter = (char *)g_malloc((pos-str)+1);
                (void) g_strlcpy( filter, str, (size_t) ((pos-str)+1));
                filter = g_strstrip(filter);
            }
            success = register_io_tap(io, i, filter, err);
            /* Advance to the next position to look for commas. */
            pos++;
            if (success) {
                /* Also advance the filter start on success. */
                str = pos;
                i++;
            } else {
                g_free(filter);
            }
        }
        /* No more commas, the rest of the string is the last filter. */
        filter = g_strstrip(g_strdup(str));
        if (*filter) {
            success = register_io_tap(io, i, filter, err);
        } else {
            success = register_io_tap(io, i, NULL, err);
        }
        if (success) {
            i++;
        }
        io->num_cols = i;
    }

    if (!success) {
        cmdarg_err("\ntshark: Couldn't register io,stat tap: %s\n",
            err->str);
        g_string_free(err, TRUE);
        g_free(io->items);
        g_free(io);
        return false;
    }
    g_string_free(err, TRUE);
    return true;

}

static stat_tap_ui iostat_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "io,stat",
    iostat_init,
    0,
    NULL
};

void
register_tap_listener_iostat(void)
{
    register_stat_tap_ui(&iostat_ui, NULL);
}
