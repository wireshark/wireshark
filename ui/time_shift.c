/* time_shift.c
 * Routines for "Time Shift" window
 * Submitted by Edwin Groothuis <wireshark@mavetju.org>
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

#include <stdio.h>
#include <string.h>
#include <math.h>


#include "time_shift.h"

#include "ui/ui_util.h"

#ifndef HAVE_FLOORL
#define floorl(x) floor((double)x)
#endif

#define SHIFT_POS               0
#define SHIFT_NEG               1
#define SHIFT_SETTOZERO         1
#define SHIFT_KEEPOFFSET        0

#define CHECK_YEARS(Y)                                  \
    if (*Y < 1970) {                                    \
        return "Years must be larger than 1970";        \
    }
#define CHECK_MONTHS(M)                                 \
    if (*M < 1 || *M > 12) {                            \
        return "Months must be between [1..12]";        \
    }
#define CHECK_DAYS(D)                           \
    if (*D < 1 || *D > 31) {                    \
        return "Days must be between [1..31]";  \
    }
#define CHECK_HOURS(h)                          \
    if (*h < 0 || *h > 23) {                    \
        return "Hours must be between [0..23]"; \
    }
#define CHECK_HOUR(h)                                           \
    if (*h < 0) {                                               \
        return "Negative hours. Have you specified more than "  \
            "one minus character?";                             \
    }
#define CHECK_MINUTE(m)                                 \
    if (*m < 0 || *m > 59) {                            \
        return "Minutes must be between [0..59]";       \
    }
#define CHECK_SECOND(s)                                     \
    if (*s < 0 || *s > 59) {                                \
        return "Seconds must be between [0..59]";           \
    }

static void
modify_time_perform(frame_data *fd, int neg, nstime_t *offset, int settozero)
{
    /* The actual shift */
    if (settozero == SHIFT_SETTOZERO) {
        nstime_subtract(&(fd->abs_ts), &(fd->shift_offset));
        nstime_set_zero(&(fd->shift_offset));
    }

    if (neg == SHIFT_POS) {
        nstime_add(&(fd->abs_ts), offset);
        nstime_add(&(fd->shift_offset), offset);
    } else if (neg == SHIFT_NEG) {
        nstime_subtract(&(fd->abs_ts), offset);
        nstime_subtract(&(fd->shift_offset), offset);
    } else {
        fprintf(stderr, "Modify_time_perform: neg = %d?\n", neg);
    }
}

/*
 * If the line between (OT1, NT1) and (OT2, NT2) is a straight line
 * and (OT3, NT3) is on that line,
 * then (NT2 - NT1) / (OT2 - OT2) = (NT3 - NT1) / (OT3 - OT1) and
 * then (OT3 - OT1) * (NT2 - NT1) / (OT2 - OT2) = (NT3 - NT1) and
 * then NT1 + (OT3 - OT1) * (NT2 - NT1) / (OT2 - OT2) = NT3 and
 * then NT3 = NT1 + (OT3 - OT1) * (NT2 - NT1) / (OT2 - OT2) and
 * thus NT3 = NT1 + (OT3 - OT1) * (NT2 - NT1) / (OT2 - OT1)
 *   or NT3 = NT1 + (OT3 - OT1) * ( deltaNT12 / deltaOT12)
 *
 * All the things you come up when waiting for the train to come...
 */
static void
calcNT3(nstime_t *OT1, nstime_t *OT3, nstime_t *NT1, nstime_t *NT3,
        nstime_t *deltaOT, nstime_t *deltaNT)
{
    long double fnt, fot, f, secs, nsecs;

    fnt = (long double)deltaNT->secs + (deltaNT->nsecs / 1000000000.0L);
    fot = (long double)deltaOT->secs + (deltaOT->nsecs / 1000000000.0L);
    f = fnt / fot;

    nstime_copy(NT3, OT3);
    nstime_subtract(NT3, OT1);

    secs  = f * (long double)NT3->secs;
    nsecs = f * (long double)NT3->nsecs;
    nsecs += (secs - floorl(secs)) * 1000000000.0L;
    while (nsecs > 1000000000L) {
        secs += 1;
        nsecs -= 1000000000L;
    }
    while (nsecs < 0) {
        secs -= 1;
        nsecs += 1000000000L;
    }
    NT3->secs = (time_t)secs;
    NT3->nsecs = (int)nsecs;
    nstime_add(NT3, NT1);
}

const gchar *
time_string_parse(const gchar *time_text, int *year, int *month, int *day, gboolean *negative, int *hour, int *minute, long double *second) {
    const gchar *pts = time_text;

    if (!time_text || !hour || !minute || !second)
        return "Unable to convert time.";

    /* strip whitespace */
    while (g_ascii_isspace(pts[0]))
        ++pts;

    if (year && month && day) {
        /*
         * The following time format is allowed:
         * [YYYY-MM-DD] hh:mm:ss(.decimals)?
         *
         * Since Wireshark doesn't support regular expressions (please prove me
         * wrong :-) we will have to figure it out ourselves in the
         * following order:
         *
         * 1. YYYY-MM-DD hh:mm:ss.decimals
         * 2.            hh:mm:ss.decimals
         *
         */

        /* check for empty string */
        if (pts[0] == '\0')
            return "Time is empty.";

        if (sscanf(pts, "%d-%d-%d %d:%d:%Lf", year, month, day, hour, minute, second) == 6) {
            /* printf("%%d-%%d-%%d %%d:%%d:%%f\n"); */
            CHECK_YEARS(year);
            CHECK_MONTHS(month);
            CHECK_DAYS(day);
            CHECK_HOURS(hour);
            CHECK_MINUTE(minute);
            CHECK_SECOND(second);
        } else if (sscanf(pts, "%d:%d:%Lf", hour, minute, second) == 3) {
            /* printf("%%d:%%d:%%f\n"); */
            *year = *month = *day = 0;
            CHECK_HOUR(hour);
            CHECK_MINUTE(minute);
            CHECK_SECOND(second);
        } else {
            return "Could not parse the time. Expected [YYYY-MM-DD] "
                    "hh:mm:ss[.dec].";
        }
    } else {
        if (!negative)
            return "Unable to convert time.";

        /*
         * The following offset types are allowed:
         * -?((hh:)mm:)ss(.decimals)?
         *
         * Since Wireshark doesn't support regular expressions (please prove me
         * wrong :-) we will have to figure it out ourselves in the
         * following order:
         *
         * 1. hh:mm:ss.decimals
         * 2.    mm:ss.decimals
         * 3.       ss.decimals
         *
         */

        /* check for minus sign */
        *negative = FALSE;
        if (pts[0] == '-') {
            *negative = TRUE;
            pts++;
        }

        /* check for empty string */
        if (pts[0] == '\0')
            return "Time is empty.";

        if (sscanf(pts, "%d:%d:%Lf", hour, minute, second) == 3) {
            /* printf("%%d:%%d:%%d.%%d\n"); */
            CHECK_HOUR(hour);
            CHECK_MINUTE(minute);
            CHECK_SECOND(second);
        } else if (sscanf(pts, "%d:%Lf", minute, second) == 2) {
            /* printf("%%d:%%d.%%d\n"); */
            CHECK_MINUTE(minute);
            CHECK_SECOND(second);
        *hour = 0;
        } else if (sscanf(pts, "%Lf", second) == 1) {
            /* printf("%%d.%%d\n"); */
            CHECK_SECOND(second);
        *hour = *minute = 0;
        } else {
            return "Could not parse the time: Expected [[hh:]mm:]ss.[dec].";
        }
    }

    return NULL;
}

static const gchar *
time_string_to_nstime(const gchar *time_text, nstime_t *packettime, nstime_t *nstime)
{
    int         h, m, Y, M, D;
    long double f;
    struct tm   tm, *tmptm;
    time_t      tt;
    const gchar *err_str;

    if ((err_str = time_string_parse(time_text, &Y, &M, &D, NULL, &h, &m, &f)) != NULL)
        return err_str;

    /* Convert the time entered in an epoch offset */
    tmptm = localtime(&(packettime->secs));
    if (tmptm) {
        tm = *tmptm;
    } else {
        memset (&tm, 0, sizeof (tm));
    }
    if (Y != 0) {
        tm.tm_year = Y - 1900;
        tm.tm_mon = M - 1;
        tm.tm_mday = D;
    }
    tm.tm_hour = h;
    tm.tm_min = m;
    tm.tm_sec = (int)floorl(f);
    tt = mktime(&tm);
    if (tt == -1) {
        return "Mktime went wrong. Is the time valid?";
    }

    nstime->secs = tt;
    f -= tm.tm_sec;
    nstime->nsecs = (int)(f * 1000000000);

    return NULL;
}

const gchar *
time_shift_all(capture_file *cf, const gchar *offset_text)
{
    nstime_t    offset;
    long double offset_float = 0;
    guint32     i;
    frame_data  *fd;
    gboolean    neg;
    int         h, m;
    long double f;
    const gchar *err_str;

    if (!cf || !offset_text)
        return "Nothing to work with.";

    if ((err_str = time_string_parse(offset_text, NULL, NULL, NULL, &neg, &h, &m, &f)) != NULL)
        return err_str;

    offset_float = h * 3600 + m * 60 + f;

    if (offset_float == 0)
        return "Offset is zero.";

    nstime_set_zero(&offset);
    offset.secs = (time_t)floorl(offset_float);
    offset_float -= offset.secs;
    offset.nsecs = (int)(offset_float * 1000000000);

    if (!frame_data_sequence_find(cf->frames, 1))
        return "No frames found."; /* Shouldn't happen */

    for (i = 1; i <= cf->count; i++) {
        if ((fd = frame_data_sequence_find(cf->frames, i)) == NULL)
            continue;   /* Shouldn't happen */
        modify_time_perform(fd, neg ? SHIFT_NEG : SHIFT_POS, &offset, SHIFT_KEEPOFFSET);
    }
    packet_list_queue_draw();

    return NULL;
}

const gchar *
time_shift_settime(capture_file *cf, guint packet_num, const gchar *time_text)
{
    nstime_t    set_time, diff_time, packet_time;
    frame_data  *fd, *packetfd;
    guint32     i;
    const gchar *err_str;

    if (!cf || !time_text)
        return "Nothing to work with.";

    if (packet_num < 1 || packet_num > cf->count)
        return "Packet out of range.";

    /*
     * Get a copy of the real time (abs_ts - shift_offset) do we can find out the
     * difference between the specified time and the original packet
     */
    if ((packetfd = frame_data_sequence_find(cf->frames, packet_num)) == NULL)
        return "No packets found.";
    nstime_delta(&packet_time, &(packetfd->abs_ts), &(packetfd->shift_offset));

    if ((err_str = time_string_to_nstime(time_text, &packet_time, &set_time)) != NULL)
        return err_str;

    /* Calculate difference between packet time and requested time */
    nstime_delta(&diff_time, &set_time, &packet_time);

    /* Up to here nothing is changed */

    if (!frame_data_sequence_find(cf->frames, 1))
        return "No frames found."; /* Shouldn't happen */

    /* Set everything back to the original time */
    for (i = 1; i <= cf->count; i++) {
        if ((fd = frame_data_sequence_find(cf->frames, i)) == NULL)
            continue;   /* Shouldn't happen */
        modify_time_perform(fd, SHIFT_POS, &diff_time, SHIFT_SETTOZERO);
    }

    packet_list_queue_draw();
    return NULL;
}

const gchar *
time_shift_adjtime(capture_file *cf, guint packet1_num, const gchar *time1_text, guint packet2_num, const gchar *time2_text)
{
    nstime_t    nt1, nt2, ot1, ot2, nt3;
    nstime_t    dnt, dot, d3t;
    frame_data  *fd, *packet1fd, *packet2fd;
    guint32     i;
    const gchar *err_str;

    if (!cf || !time1_text || !time2_text)
        return "Nothing to work with.";

    if (packet1_num < 1 || packet1_num > cf->count || packet2_num < 1 || packet2_num > cf->count)
        return "Packet out of range.";

    /*
     * The following time format is allowed:
     * [YYYY-MM-DD] hh:mm:ss(.decimals)?
     *
     * Since Wireshark doesn't support regular expressions (please prove me
     * wrong :-) we will have to figure it out ourselves in the
     * following order:
     *
     * 1. YYYY-MM-DD hh:mm:ss.decimals
     * 2.            hh:mm:ss.decimals
     *
     */

    /*
     * Get a copy of the real time (abs_ts - shift_offset) do we can find out the
     * difference between the specified time and the original packet
     */
    if ((packet1fd = frame_data_sequence_find(cf->frames, packet1_num)) == NULL)
        return "No frames found.";
    nstime_copy(&ot1, &(packet1fd->abs_ts));
    nstime_subtract(&ot1, &(packet1fd->shift_offset));

    if ((err_str = time_string_to_nstime(time1_text, &ot1, &nt1)) != NULL)
        return err_str;

    /*
     * Get a copy of the real time (abs_ts - shift_offset) do we can find out the
     * difference between the specified time and the original packet
     */
    if ((packet2fd = frame_data_sequence_find(cf->frames, packet2_num)) == NULL)
        return "No frames found.";
    nstime_copy(&ot2, &(packet2fd->abs_ts));
    nstime_subtract(&ot2, &(packet2fd->shift_offset));

    if ((err_str = time_string_to_nstime(time2_text, &ot2, &nt2)) != NULL)
        return err_str;

    nstime_copy(&dot, &ot2);
    nstime_subtract(&dot, &ot1);

    nstime_copy(&dnt, &nt2);
    nstime_subtract(&dnt, &nt1);

    /* Up to here nothing is changed */
    if (!frame_data_sequence_find(cf->frames, 1))
        return "No frames found."; /* Shouldn't happen */

    for (i = 1; i <= cf->count; i++) {
        if ((fd = frame_data_sequence_find(cf->frames, i)) == NULL)
            continue;   /* Shouldn't happen */

        /* Set everything back to the original time */
        nstime_subtract(&(fd->abs_ts), &(fd->shift_offset));
        nstime_set_zero(&(fd->shift_offset));

        /* Add the difference to each packet */
        calcNT3(&ot1, &(fd->abs_ts), &nt1, &nt3, &dot, &dnt);

        nstime_copy(&d3t, &nt3);
        nstime_subtract(&d3t, &(fd->abs_ts));

        modify_time_perform(fd, SHIFT_POS, &d3t, SHIFT_SETTOZERO);
    }

    packet_list_queue_draw();
    return NULL;
}

const gchar *
time_shift_undo(capture_file *cf)
{
    guint32     i;
    frame_data  *fd;
    nstime_t    nulltime;

    if (!cf)
        return "Nothing to work with.";

    nulltime.secs = nulltime.nsecs = 0;

    if (!frame_data_sequence_find(cf->frames, 1))
        return "No frames found."; /* Shouldn't happen */

    for (i = 1; i <= cf->count; i++) {
        if ((fd = frame_data_sequence_find(cf->frames, i)) == NULL)
            continue;   /* Shouldn't happen */
        modify_time_perform(fd, SHIFT_NEG, &nulltime, SHIFT_SETTOZERO);
    }
    packet_list_queue_draw();
    return NULL;
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
